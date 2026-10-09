package check

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Slymaster/isitfixed/internal/osv"
	"github.com/Slymaster/isitfixed/internal/versions"
)

const maxAliasRecords = 6

// fetchAliases returns the non-CVE, non-GHSA records that osv.dev links to
// this advisory (e.g. GO-*, RUSTSEC-*, PYSEC-*). osv.dev computes alias
// groups, so the record fetched from the API usually lists more aliases than
// the file itself.
func (e *Engine) fetchAliases(ctx context.Context, v *osv.Vuln) []*osv.Vuln {
	ids := map[string]bool{}
	var order []string
	addIDs := func(xs []string) {
		for _, id := range xs {
			if !ids[id] && id != v.ID {
				ids[id] = true
				order = append(order, id)
			}
		}
	}
	addIDs(v.Aliases)
	if rec, err := e.OSV.Get(ctx, v.ID); err == nil {
		addIDs(rec.Aliases)
	}
	for _, id := range append([]string(nil), order...) {
		if strings.HasPrefix(id, "CVE-") {
			if rec, err := e.OSV.Get(ctx, id); err == nil {
				addIDs(rec.Aliases)
			}
		}
	}
	var out []*osv.Vuln
	for _, id := range order {
		if strings.HasPrefix(id, "CVE-") || strings.HasPrefix(id, "GHSA-") || len(out) >= maxAliasRecords {
			continue
		}
		rec, err := e.OSV.Get(ctx, id)
		if err != nil || rec.Withdrawn != "" {
			continue
		}
		relevant := false
		for _, g := range groupsOf(v) {
			if rec.HasEcosystem(g.Eco) {
				relevant = true
			}
		}
		if relevant {
			out = append(out, rec)
		}
	}
	return out
}

// checkCrossDB implements XDB001: compare which published versions each
// record marks affected, per package, and spot package names spelled
// differently.
func (e *Engine) checkCrossDB(ctx context.Context, a *advisoryCtx) {
	for _, al := range a.aliases {
		other := groupsOf(al)
		byKey := map[string]*group{}
		for _, g := range a.groups {
			byKey[g.key()] = g
		}
		otherKey := map[string]bool{}
		for _, og := range other {
			otherKey[og.key()] = true
		}
		// Packages of this advisory the alias record does not list, but
		// under a similar name: likely a typo on one side.
		for _, mine := range a.groups {
			if otherKey[mine.key()] {
				continue
			}
			for _, og := range other {
				if og.Eco != mine.Eco {
					continue
				}
				msg := ""
				if mine.Eco == versions.Go && goBase(mine.Name) == goBase(og.Name) {
					// Same module, different major-version suffix: only a
					// problem when this advisory's versions do not match
					// its own suffix but match the alias record's.
					ms := majors(mine)
					if len(ms) == 0 || consistent(goSuffix(mine.Name), ms) || !consistent(goSuffix(og.Name), ms) {
						continue
					}
					msg = fmt.Sprintf("this advisory's versions for %s are major version %s, which belong to module %s (as listed by %s)",
						mine.Name, joinInts(ms), og.Name, al.ID)
				} else if strings.HasPrefix(mine.Name, og.Name+"/") || strings.HasPrefix(og.Name, mine.Name+"/") {
					continue // package path vs. its module path
				} else if similarName(mine.Name, og.Name) {
					msg = fmt.Sprintf("%s does not list %s but lists the similarly named %s", al.ID, mine.Name, og.Name)
				} else {
					continue
				}
				f := Finding{Check: XDB001, Severity: Warning, Ecosystem: mine.Eco, Package: mine.Name,
					Message: msg,
					Details: []string{fmt.Sprintf("this advisory's ranges for %s: %s; %s ranges for %s: %s",
						mine.Name, describeAll(mine), al.ID, og.Name, describeAll(og))},
					Evidence: []string{osv.URL(al.ID)}}
				if mine.Pkg == nil {
					f.Details = append(f.Details, mine.Name+" does not exist in the registry (see PKG001)")
				}
				a.add(f)
			}
		}
		for _, og := range other {
			g, ok := byKey[og.key()]
			if !ok {
				continue
			}
			// Ranges built on versions the registry does not have (e.g.
			// git tags that are not Go module versions) cannot be compared.
			if g.Pkg == nil || len(g.Pkg.Releases) == 0 || len(g.missing) > 0 {
				continue
			}
			og.Pkg = g.Pkg
			var onlyMine, onlyOther []string
			for _, r := range g.Pkg.Releases {
				m, o := g.covered(r.Version), og.covered(r.Version)
				switch {
				case m && !o:
					onlyMine = append(onlyMine, r.Version)
				case o && !m:
					onlyOther = append(onlyOther, r.Version)
				}
			}
			if len(onlyMine) == 0 && len(onlyOther) == 0 {
				continue
			}
			f := Finding{Check: XDB001, Severity: Warning, Ecosystem: g.Eco, Package: g.Name,
				Message:  fmt.Sprintf("%s and this advisory disagree on which published versions of %s are affected", al.ID, g.Name),
				Evidence: []string{osv.URL(al.ID), g.Pkg.URL}}
			if len(onlyOther) > 0 {
				f.Details = append(f.Details, fmt.Sprintf("affected only according to %s (%d): %s", al.ID, len(onlyOther), runs(g, onlyOther)))
			}
			if len(onlyMine) > 0 {
				f.Details = append(f.Details, fmt.Sprintf("affected only according to this advisory (%d): %s", len(onlyMine), runs(g, onlyMine)))
			}
			f.Details = append(f.Details, fmt.Sprintf("%s ranges: %s", al.ID, describeAll(og)))
			a.add(f)
		}
	}
}

func describeAll(g *group) string {
	var s []string
	for _, iv := range g.Intervals {
		s = append(s, describe(iv))
	}
	if len(g.Explicit) > 0 {
		s = append(s, fmt.Sprintf("%d explicit versions", len(g.Explicit)))
	}
	return strings.Join(s, " ")
}

// runs renders a subset of published versions as runs of consecutive
// releases: "1.18.0 … 1.18.10, 1.19.0".
func runs(g *group, subset []string) string {
	in := map[string]bool{}
	for _, v := range subset {
		in[v] = true
	}
	var out []string
	var cur []string
	flush := func() {
		switch len(cur) {
		case 0:
		case 1:
			out = append(out, cur[0])
		case 2:
			out = append(out, cur[0], cur[1])
		default:
			out = append(out, cur[0]+" … "+cur[len(cur)-1])
		}
		cur = nil
	}
	for _, r := range g.Pkg.Releases {
		if in[r.Version] {
			cur = append(cur, r.Version)
		} else {
			flush()
		}
	}
	flush()
	if len(out) > 8 {
		out = append(out[:8], fmt.Sprintf("(+%d more runs)", len(out)-8))
	}
	return strings.Join(out, ", ")
}

var majorSuffixRe = regexp.MustCompile(`/v([2-9]|[1-9][0-9]+)$`)

// goSuffix returns the major version implied by a Go module path suffix
// (1 when there is none).
func goSuffix(name string) int {
	if m := majorSuffixRe.FindStringSubmatch(name); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 1
}

func goBase(name string) string { return majorSuffixRe.ReplaceAllString(name, "") }

// majors returns the major versions of a group's range endpoints.
func majors(g *group) []int {
	seen := map[int]bool{}
	var out []int
	for _, iv := range g.Intervals {
		for _, v := range []string{iv.Intro, iv.Fixed, iv.LastAffected} {
			if v == "" || v == "0" || isPseudo(g.Eco, v) {
				continue
			}
			head, _, _ := strings.Cut(v, ".")
			n, err := strconv.Atoi(head)
			if err == nil && !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	sort.Ints(out)
	return out
}

func consistent(suffix int, ms []int) bool {
	for _, m := range ms {
		if suffix >= 2 && m != suffix || suffix < 2 && m > 1 {
			return false
		}
	}
	return true
}

func joinInts(ns []int) string {
	var s []string
	for _, n := range ns {
		s = append(s, strconv.Itoa(n))
	}
	return strings.Join(s, ", ")
}
