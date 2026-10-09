package check

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Slymaster/isitfixed/internal/fix"
	"github.com/Slymaster/isitfixed/internal/osv"
	"github.com/Slymaster/isitfixed/internal/versions"
)

// rngCandidate is a range-shape finding that FIX001 evidence may confirm
// (fix absent from the probed version) or downgrade (fix present).
type rngCandidate struct {
	check     string
	g         *group
	sev       Severity
	message   string
	details   []string
	evidence  []string
	suggested [][]osv.Event
	// uncovered are the versions in question (ascending); probe, the
	// newest of them, is inspected first.
	uncovered []string
	probe     string
	// keep is the interval to rewrite when the fix appears mid-way (RNG001).
	intro string
	// filled by FIX001
	partialFix  bool
	probed      bool
	result      fix.Result
	artURL      string
	earliest    string // earliest uncovered version containing the fix
	earliestURL string
}

func (c *rngCandidate) finding() Finding {
	f := Finding{Check: c.check, Severity: c.sev, Ecosystem: c.g.Eco, Package: c.g.Name,
		Message: c.message, Details: c.details, Evidence: c.evidence, Suggested: c.suggested}
	if !c.probed {
		return f
	}
	switch c.result.Status {
	case fix.Lacks:
		f.Evidence = append(f.Evidence, c.artURL)
		r := c.result
		switch {
		case r.OldApplicable > 0 && 10*r.OldPresent >= 7*r.OldApplicable:
			f.Severity = Warning
			f.Details = append(f.Details, fmt.Sprintf("confirmed by content: %s lacks the fix (%d/%d distinctive lines in their fixed state) and still contains %d/%d lines the fix removed",
				c.probe, r.Present, r.Applicable, r.OldPresent, r.OldApplicable))
		case r.OldApplicable > 0 && 10*r.OldPresent <= 3*r.OldApplicable:
			f.Severity = Info
			f.Suggested = nil
			f.Details = append(f.Details, fmt.Sprintf("%s contains neither the fix nor the code it removed (%d/%d removed lines present), so it was probably never affected",
				c.probe, r.OldPresent, r.OldApplicable))
		default:
			f.Details = append(f.Details, fmt.Sprintf("%s does not contain the fix (%d/%d distinctive lines present); the fix only adds code, so this does not prove the vulnerable code is present",
				c.probe, r.Present, r.Applicable))
		}
	case fix.Contains:
		f.Evidence = append(f.Evidence, c.artURL)
		if c.earliest == "" || c.earliest == c.uncovered[0] {
			f.Severity = Info
			f.Details = append(f.Details, fmt.Sprintf("however %s and every earlier version in question contain the fix (newest: %d/%d distinctive lines present), so these versions are probably not affected",
				orNone(c.earliest), c.result.Present, c.result.Applicable))
			f.Suggested = nil
			break
		}
		f.Severity = Warning
		var lacking []string
		for _, v := range c.uncovered {
			if v == c.earliest {
				break
			}
			lacking = append(lacking, v)
		}
		f.Details = append(f.Details, fmt.Sprintf("confirmed by content: the fix first appears in %s; %d earlier version(s) lack it: %s",
			c.earliest, len(lacking), compact(lacking)))
		if c.earliestURL != "" {
			f.Evidence = append(f.Evidence, c.earliestURL)
		}
		start := c.intro
		if c.check == RNG002 {
			start = c.uncovered[0]
		}
		f.Suggested = [][]osv.Event{{{Introduced: start}, {Fixed: c.earliest}}}
	}
	return f
}

type line struct {
	key      string
	releases []string // ascending
}

// lines groups published versions by release line, ascending.
func lines(g *group) []*line {
	idx := map[string]*line{}
	var out []*line
	for _, r := range g.Pkg.Releases {
		k := versions.Line(g.Eco, r.Version)
		if k == "" {
			continue
		}
		l, ok := idx[k]
		if !ok {
			l = &line{key: k}
			idx[k] = l
			out = append(out, l)
		}
		l.releases = append(l.releases, r.Version)
	}
	// Releases are sorted, so lines appear in order of their first version.
	return out
}

func (l *line) first() string { return l.releases[0] }
func (l *line) last() string  { return l.releases[len(l.releases)-1] }

// rangeCandidates implements RNG001 (stale last_affected) and RNG002
// (uncovered release line between ranges).
func (e *Engine) rangeCandidates(ctx context.Context, a *advisoryCtx, g *group) {
	ls := lines(g)
	if e.on(RNG001) {
		for _, iv := range g.Intervals {
			if iv.LastAffected == "" || g.missing[iv.LastAffected] {
				continue
			}
			lk := versions.Line(g.Eco, iv.LastAffected)
			var later []string
			for _, l := range ls {
				if l.key != lk {
					continue
				}
				for _, v := range l.releases {
					if versions.Compare(g.Eco, v, iv.LastAffected) > 0 && !g.covered(v) {
						later = append(later, v)
					}
				}
			}
			if len(later) == 0 {
				continue
			}
			// Strong signal: a newer line of the same package has a fix, so
			// maintainers patched newer lines and this one probably got none.
			strong := false
			for _, o := range g.Intervals {
				if o.Fixed != "" && versions.Compare(g.Eco, o.Fixed, later[len(later)-1]) > 0 && versions.Line(g.Eco, o.Fixed) != lk {
					strong = true
				}
			}
			sev := Info
			if strong {
				sev = Warning
			}
			newest := later[len(later)-1]
			c := &rngCandidate{check: RNG001, g: g, sev: sev, probe: newest, uncovered: later, intro: iv.Intro,
				message: fmt.Sprintf("range ends with last_affected %s, but %d later %s.x version(s) were published and are not covered by any range: %s",
					iv.LastAffected, len(later), lk, compact(later)),
				evidence:  []string{g.Pkg.URL},
				suggested: [][]osv.Event{{{Introduced: iv.Intro}, {LastAffected: newest}}},
			}
			if strong {
				c.details = append(c.details, "newer release lines have fixed versions; this line looks unpatched, so last_affected should probably be the newest version of the line")
			} else {
				c.details = append(c.details, "if these versions are still vulnerable, last_affected should be extended; if one of them fixed the issue, use a fixed event instead")
			}
			a.rng = append(a.rng, c)
		}
	}
	if !e.on(RNG002) || len(g.Intervals) < 2 {
		return
	}
	// A line is a gap when no version of it is covered, some range ends at
	// or before its first version, and some range starts after its last.
	type gapLine struct {
		l         *line
		end, next string
	}
	var gaps []gapLine
	for _, l := range ls {
		if slicesAny(l.releases, g.covered) {
			continue
		}
		before, end := endsBefore(g, l.first())
		after, next := startsAfter(g, l.last())
		// Go pseudo-versions order before every tagged release, so a range
		// ending at one says nothing about the tagged lines after it.
		if !before || !after || isPseudo(g.Eco, end) || !e.lineBranchedBeforeFix(ctx, g, l, end) {
			continue
		}
		gaps = append(gaps, gapLine{l, end, next.Intro})
	}
	// One finding per run of gap lines between the same two ranges.
	for i := 0; i < len(gaps); {
		j := i
		for j+1 < len(gaps) && gaps[j+1].end == gaps[i].end && gaps[j+1].next == gaps[i].next {
			j++
		}
		run := gaps[i : j+1]
		var keys, vs []string
		for _, x := range run {
			keys = append(keys, x.l.key)
			vs = append(vs, x.l.releases...)
		}
		first, last := run[0].l.first(), run[len(run)-1].l.last()
		sev := Warning
		details := []string{"a line released before the preceding fix and never patched is still vulnerable; if these versions are affected, add a range for them"}
		if mid := midLineIntro(g); mid != "" {
			// "introduced: 14.4.3" means the vulnerable code arrived in a
			// patch release (often a backport), so gaps between ranges may
			// be lines that never had it.
			sev = Info
			details = []string{fmt.Sprintf("a range of this package is introduced mid-line (%s), which suggests the vulnerable code arrived through patch releases; these lines may never have had it", mid)}
		}
		a.rng = append(a.rng, &rngCandidate{check: RNG002, g: g, sev: sev, probe: last, uncovered: vs,
			message: fmt.Sprintf("release line(s) %s (%d versions: %s) lie between affected ranges (after the range ending at %s, before the one introduced at %s) and no version of them is covered",
				strings.Join(keys, ", "), len(vs), compact(vs), run[0].end, run[0].next),
			details:   details,
			evidence:  []string{g.Pkg.URL},
			suggested: [][]osv.Event{{{Introduced: first}, {LastAffected: last}}},
		})
		i = j + 1
	}
}

// midLineIntro returns the first range introduction at a patch release.
func midLineIntro(g *group) string {
	for _, iv := range g.Intervals {
		if iv.Intro != "0" && midLine(g.Eco, iv.Intro) {
			return iv.Intro
		}
	}
	return ""
}

// midLine reports whether v is a patch release (third numeric component
// non-zero), e.g. 14.4.3.
func midLine(eco, v string) bool {
	parts := strings.FieldsFunc(versions.Normalize(eco, v), func(r rune) bool { return r == '.' || r == '-' })
	if len(parts) < 3 {
		return false
	}
	n, err := strconv.Atoi(parts[2])
	return err == nil && n > 0
}

func slicesAny(vs []string, f func(string) bool) bool {
	for _, v := range vs {
		if f(v) {
			return true
		}
	}
	return false
}

// endsBefore reports whether some range ends (fixed or last_affected) at or
// before v, returning the latest such end.
func endsBefore(g *group, v string) (bool, string) {
	best := ""
	for _, iv := range g.Intervals {
		end := iv.end()
		if end == "" {
			continue
		}
		c := versions.Compare(g.Eco, end, v)
		if c < 0 || c == 0 && iv.Fixed != "" {
			if best == "" || versions.Compare(g.Eco, end, best) > 0 {
				best = end
			}
		}
	}
	return best != "", best
}

// startsAfter reports whether some range is introduced after v.
func startsAfter(g *group, v string) (bool, interval) {
	var best *interval
	for i, iv := range g.Intervals {
		if iv.Intro != "0" && versions.Compare(g.Eco, iv.Intro, v) > 0 {
			if best == nil || versions.Compare(g.Eco, iv.Intro, best.Intro) < 0 {
				best = &g.Intervals[i]
			}
		}
	}
	if best == nil {
		return false, interval{}
	}
	return true, *best
}

// lineBranchedBeforeFix filters out lines first published after the
// preceding range's fix: those plausibly inherited the fix. Unknown dates
// keep the line.
func (e *Engine) lineBranchedBeforeFix(ctx context.Context, g *group, l *line, fixed string) bool {
	tl, ok1 := g.Reg.PublishedAt(ctx, g.Name, l.first())
	// An unpublished fixed version is dated by the next published version
	// of its line.
	if r, ok := g.Pkg.Find(fixed); ok {
		fixed = r.Version
	} else {
		for _, r := range g.Pkg.Releases {
			if versions.Compare(g.Eco, r.Version, fixed) > 0 && versions.Line(g.Eco, r.Version) == versions.Line(g.Eco, fixed) {
				fixed = r.Version
				break
			}
		}
	}
	tf, ok2 := g.Reg.PublishedAt(ctx, g.Name, fixed)
	if !ok1 || !ok2 {
		return true
	}
	return tl.Before(tf)
}

var pseudoRe = regexp.MustCompile(`(^|[.-])(0\.)?[0-9]{14}-[0-9a-f]{12}$`)

// isPseudo reports whether v is a Go pseudo-version.
func isPseudo(eco, v string) bool { return eco == versions.Go && pseudoRe.MatchString(v) }

// compact renders a version list briefly: "1.10.1, 1.10.2 … 1.10.20".
func compact(vs []string) string {
	if len(vs) <= 4 {
		return strings.Join(vs, ", ")
	}
	return fmt.Sprintf("%s, %s … %s", vs[0], vs[1], vs[len(vs)-1])
}
