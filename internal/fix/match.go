package fix

import (
	"bytes"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/Slymaster/isitfixed/internal/registry"
)

// Status of one artifact with respect to a fix.
type Status string

// Possible statuses.
const (
	Contains     Status = "contains"     // most distinctive lines present
	Lacks        Status = "lacks"        // (almost) none present
	Partial      Status = "partial"      // in between: inconclusive
	Inapplicable Status = "inapplicable" // no fixed file maps into this artifact
)

// Thresholds on the fraction of applicable distinctive lines present.
const (
	ContainsAt = 0.7
	LacksAt    = 0.2
	MinUnits   = 2
)

// Result is the best match of a set of fix commits against one artifact.
// Present counts distinctive lines that are in their post-fix state: added
// lines present, removed lines absent.
type Result struct {
	Status     Status   `json:"status"`
	Present    int      `json:"present"`
	Applicable int      `json:"applicable"`
	Commit     string   `json:"commit,omitempty"`
	Matched    []string `json:"matched,omitempty"`
	Missing    []string `json:"missing,omitempty"`
	LowConf    bool     `json:"low_confidence,omitempty"` // matched compiled classes, not sources
	// OldPresent / OldApplicable count the lines the fix removed that are
	// still present: evidence that the vulnerable code itself is there.
	OldPresent    int `json:"old_present,omitempty"`
	OldApplicable int `json:"old_applicable,omitempty"`
	// GroupApplicable[i] is true when commit group i (see Groups) has
	// distinctive lines in files this artifact ships.
	GroupApplicable []bool `json:"-"`
}

// Fraction returns Present/Applicable.
func (r Result) Fraction() float64 {
	if r.Applicable == 0 {
		return 0
	}
	return float64(r.Present) / float64(r.Applicable)
}

var srcRoots = []string{"src/main/java/", "src/main/kotlin/", "src/main/scala/", "src/main/groovy/", "src/main/resources/"}

// mapFiles maps fix-commit file paths to artifact-relative paths. A repo path
// P maps to artifact path A when P == A or P ends with "/"+A; the longest A
// wins. Mappings whose repository prefix disagrees with the majority are
// dropped, so that a monorepo's other "index.js" does not match.
func mapFiles(repoPaths []string, art *registry.Artifact) map[string]string {
	files := art.Files()
	byBase := map[string][]string{}
	for _, f := range files {
		byBase[path.Base(f)] = append(byBase[path.Base(f)], f)
	}
	type m struct{ p, a, prefix string }
	var ms []m
	for _, p := range repoPaths {
		best := ""
		for _, a := range byBase[path.Base(p)] {
			if (p == a || strings.HasSuffix(p, "/"+a)) && len(a) > len(best) {
				best = a
			}
		}
		if best != "" {
			ms = append(ms, m{p, best, p[:len(p)-len(best)]})
		}
	}
	count := map[string]int{}
	for _, x := range ms {
		count[x.prefix]++
	}
	out := map[string]string{}
	for _, x := range ms {
		keep := true
		for pre, n := range count {
			if pre != x.prefix && n > count[x.prefix] && !isSourceRootPrefix(x.prefix) {
				keep = false
			}
		}
		if keep {
			out[x.p] = x.a
		}
	}
	return out
}

func isSourceRootPrefix(prefix string) bool {
	for _, r := range srcRoots {
		if strings.HasSuffix(prefix, r) || prefix == r {
			return true
		}
	}
	return false
}

// classBase maps a repository .java/.kt path to its class path without
// extension ("io/quarkus/.../HttpSecurityUtils").
func classBase(p string) string {
	ext := path.Ext(p)
	if ext != ".java" && ext != ".kt" {
		return ""
	}
	for _, r := range srcRoots {
		if i := strings.Index(p, r); i >= 0 && (i == 0 || p[i-1] == '/') {
			return strings.TrimSuffix(p[i+len(r):], ext)
		}
	}
	return ""
}

// Match checks one artifact against the fix commits of an advisory.
//
// Commits are first grouped: commits whose distinctive lines largely
// coincide are alternatives (the same fix on different release branches,
// e.g. backports), while disjoint commits are parts of a multi-commit fix.
// Within a group the best-matching commit counts; the artifact contains the
// fix only when every applicable group does, and lacks it only when every
// applicable group does. Anything else is Partial (inconclusive).
//
// seenFiles accumulates the repository paths that mapped into some
// inspected artifact of the package: a file the fix added counts as
// applicable (and absent) in an artifact that lacks it only once it has
// been seen in another version of the same package.
func Match(sets []*Set, art *registry.Artifact, seenFiles map[string]bool) Result {
	var out Result
	groups := 0
	contains, lacks := 0, 0
	gs := Groups(sets)
	out.GroupApplicable = make([]bool, len(gs))
	for gi, g := range gs {
		best := Result{Status: Inapplicable}
		for _, s := range g {
			r := matchOne(s, art, seenFiles)
			if r.Applicable < MinUnits {
				continue
			}
			if best.Status == Inapplicable || r.Fraction() > best.Fraction() {
				best = r
			}
		}
		if best.Status == Inapplicable {
			continue
		}
		out.GroupApplicable[gi] = true
		groups++
		switch best.Status {
		case Contains:
			contains++
		case Lacks:
			lacks++
		}
		if out.Commit == "" {
			out.Commit = best.Commit
		} else {
			out.Commit += "," + best.Commit
		}
		out.Present += best.Present
		out.OldPresent += best.OldPresent
		out.OldApplicable += best.OldApplicable
		out.Applicable += best.Applicable
		out.Matched = append(out.Matched, best.Matched...)
		out.Missing = append(out.Missing, best.Missing...)
		out.LowConf = out.LowConf || best.LowConf
	}
	switch {
	case groups == 0:
		out.Status = Inapplicable
	case contains == groups:
		out.Status = Contains
	case lacks == groups:
		out.Status = Lacks
	default:
		out.Status = Partial
	}
	return out
}

// Groups clusters commits whose distinctive lines overlap (Jaccard ≥ 0.5,
// counting added and removed lines separately).
func Groups(sets []*Set) [][]*Set {
	keys := make([]map[string]bool, len(sets))
	for i, s := range sets {
		keys[i] = map[string]bool{}
		for _, u := range s.Units {
			keys[i][fmt.Sprint(u.Removed, u.Norm)] = true
		}
	}
	parent := make([]int, len(sets))
	for i := range parent {
		parent[i] = i
	}
	var find func(int) int
	find = func(i int) int {
		if parent[i] != i {
			parent[i] = find(parent[i])
		}
		return parent[i]
	}
	for i := range sets {
		for j := i + 1; j < len(sets); j++ {
			inter := 0
			for k := range keys[i] {
				if keys[j][k] {
					inter++
				}
			}
			union := len(keys[i]) + len(keys[j]) - inter
			if union > 0 && float64(inter)/float64(union) >= 0.5 {
				parent[find(j)] = find(i)
			}
		}
	}
	idx := map[int]int{}
	var out [][]*Set
	for i, s := range sets {
		r := find(i)
		k, ok := idx[r]
		if !ok {
			k = len(out)
			idx[r] = k
			out = append(out, nil)
		}
		out[k] = append(out[k], s)
	}
	return out
}

// Superseded drops commits whose added lines are mostly removed again by
// another referenced commit (a later fix-of-the-fix, or the commit that
// introduced the vulnerability), and revert commits, which restore older
// code whose presence says nothing about the fix.
func Superseded(sets []*Set) (kept []*Set, dropped []string) {
	removedBy := make([]map[string]bool, len(sets))
	for i, s := range sets {
		removedBy[i] = map[string]bool{}
		for _, u := range s.Units {
			if u.Removed {
				removedBy[i][u.Norm] = true
			}
		}
	}
	for i, s := range sets {
		if strings.HasPrefix(strings.TrimSpace(s.Commit.Message), "Revert ") {
			dropped = append(dropped, s.Commit.URL+": revert commit")
			continue
		}
		drop := false
		added := 0
		for _, u := range s.Units {
			if !u.Removed {
				added++
			}
		}
		for j := range sets {
			if i == j || added == 0 {
				continue
			}
			n := 0
			for _, u := range s.Units {
				if !u.Removed && removedBy[j][u.Norm] {
					n++
				}
			}
			if 2*n >= added {
				drop = true
				dropped = append(dropped, fmt.Sprintf("%s: its added lines are removed by %s", s.Commit.URL, sets[j].Commit.URL))
				break
			}
		}
		if !drop {
			kept = append(kept, s)
		}
	}
	return kept, dropped
}

func matchOne(s *Set, art *registry.Artifact, seenFiles map[string]bool) Result {
	res := Result{Commit: s.Commit.SHA}
	var paths []string
	for _, u := range s.Units {
		paths = append(paths, u.File)
	}
	norm := map[string]string{}
	if art.Kind == "class" {
		res.LowConf = true
		classes := map[string][]byte{}
		files := art.Files()
		for _, u := range s.Units {
			cb := classBase(u.File)
			if cb == "" || len(u.Tokens) == 0 {
				continue
			}
			data, ok := classes[cb]
			if !ok {
				var buf bytes.Buffer
				for _, f := range files {
					if f == cb+".class" || strings.HasPrefix(f, cb+"$") && strings.HasSuffix(f, ".class") {
						if b, err := art.Read(f); err == nil {
							buf.Write(b)
						}
					}
				}
				data = buf.Bytes()
				classes[cb] = data
				if len(data) > 0 && seenFiles != nil {
					seenFiles[u.File] = true
				}
			}
			if len(data) == 0 && (u.Removed || !(s.Added[u.File] && seenFiles[u.File])) {
				continue
			}
			res.Applicable++
			all := true
			for _, t := range u.Tokens {
				if !bytes.Contains(data, []byte(t)) {
					all = false
					break
				}
			}
			res.countRemoved(u, all)
			if all != u.Removed {
				res.Present++
				res.Matched = append(res.Matched, u.label())
			} else {
				res.Missing = append(res.Missing, u.label())
			}
		}
	} else {
		mapping := mapFiles(dedupe(paths), art)
		for p, a := range mapping {
			if b, err := art.Read(a); err == nil {
				norm[p] = Strip(string(b))
				if seenFiles != nil {
					seenFiles[p] = true
				}
			}
		}
		for _, u := range s.Units {
			content, ok := norm[u.File]
			if !ok && (u.Removed || !(s.Added[u.File] && seenFiles[u.File])) {
				continue
			}
			res.Applicable++
			found := ok && strings.Contains(content, u.Norm)
			res.countRemoved(u, found)
			if found != u.Removed {
				res.Present++
				res.Matched = append(res.Matched, u.label())
			} else {
				res.Missing = append(res.Missing, u.label())
			}
		}
	}
	switch f := res.Fraction(); {
	case res.Applicable < MinUnits:
		res.Status = Inapplicable
	case f >= ContainsAt:
		res.Status = Contains
	case f <= LacksAt:
		res.Status = Lacks
	default:
		res.Status = Partial
	}
	return res
}

func dedupe(s []string) []string {
	m := map[string]bool{}
	var out []string
	for _, x := range s {
		if !m[x] {
			m[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

func (u Unit) label() string {
	if u.Removed {
		return u.File + ": [removed by fix] " + u.Line
	}
	return u.File + ": " + u.Line
}

func (r *Result) countRemoved(u Unit, found bool) {
	if u.Removed {
		r.OldApplicable++
		if found {
			r.OldPresent++
		}
	}
}
