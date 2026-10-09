package fix

import (
	"bytes"
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

// Match checks one artifact against several fix commits and returns the
// best-matching commit's result. seenFiles accumulates the repository paths
// that mapped into some inspected artifact of the package: a file the fix
// added counts as applicable (and absent) in an artifact that lacks it only
// once it has been seen in another version of the same package.
func Match(sets []*Set, art *registry.Artifact, seenFiles map[string]bool) Result {
	best := Result{Status: Inapplicable}
	for _, s := range sets {
		r := matchOne(s, art, seenFiles)
		if r.Applicable < MinUnits {
			continue
		}
		if best.Status == Inapplicable || r.Fraction() > best.Fraction() {
			best = r
		}
	}
	return best
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
			if (ok && strings.Contains(content, u.Norm)) != u.Removed {
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
