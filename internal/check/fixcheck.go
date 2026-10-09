package check

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/Slymaster/isitfixed/internal/fix"
	"github.com/Slymaster/isitfixed/internal/github"
	"github.com/Slymaster/isitfixed/internal/httpx"
	"github.com/Slymaster/isitfixed/internal/osv"
	"github.com/Slymaster/isitfixed/internal/registry"
	"github.com/Slymaster/isitfixed/internal/versions"
)

// DefaultMaxArtifacts bounds artifact inspections per package.
const DefaultMaxArtifacts = 24

const maxFixRefs = 8

// debug prints the distinctive lines of each fix commit to stderr.
var debug = os.Getenv("ISITFIXED_DEBUG") != ""

type probeRes struct {
	version string
	res     fix.Result
	art     *registry.Artifact
	err     error
}

func (p *probeRes) evidence() string {
	if p.art == nil {
		return ""
	}
	s := p.art.URL
	if p.art.Digest != "" {
		s += " (" + p.art.Digest
		if p.art.Verified {
			s += ", verified"
		} else {
			s += ", as published by the registry"
		}
		s += ")"
	}
	return s
}

func (p *probeRes) summary() string {
	return fmt.Sprintf("%s: %s (%d/%d distinctive lines present)", p.version, p.res.Status, p.res.Present, p.res.Applicable)
}

type prober struct {
	ctx     context.Context
	g       *group
	sets    []*fix.Set
	results map[string]*probeRes
	seen    map[string]bool
	budget  int
	lowConf bool
	// groupSeen[i]: commit group i was applicable to some inspected artifact.
	groupSeen []bool
	// failErr is the first artifact download that failed after retries.
	failErr error
}

// probe inspects one published version (exact release string). It returns
// nil when the download budget is exhausted.
func (p *prober) probe(v string) *probeRes {
	if r, ok := p.results[v]; ok {
		return r
	}
	if p.budget <= 0 {
		return nil
	}
	p.budget--
	r := &probeRes{version: v}
	r.art, r.err = p.g.Reg.Artifact(p.ctx, p.g.Name, v)
	if r.err == nil {
		r.res = fix.Match(p.sets, r.art, p.seen)
		if r.res.LowConf {
			p.lowConf = true
		}
		if p.groupSeen == nil {
			p.groupSeen = make([]bool, len(r.res.GroupApplicable))
		}
		for i, ok := range r.res.GroupApplicable {
			p.groupSeen[i] = p.groupSeen[i] || ok
		}
	} else {
		r.res.Status = fix.Inapplicable
		if httpx.IsFailure(r.err) && p.failErr == nil {
			p.failErr = r.err
		}
	}
	p.results[v] = r
	return r
}

func (p *prober) contains(v string) bool {
	r := p.probe(v)
	return r != nil && r.res.Status == fix.Contains
}

// bisect returns the earliest version of cands (ascending) containing the
// fix, assuming the last one does and that presence is monotonic within a
// release line.
func (p *prober) bisect(cands []string) string {
	lo, hi := 0, len(cands)-1
	for lo < hi {
		mid := (lo + hi) / 2
		r := p.probe(cands[mid])
		if r == nil {
			break
		}
		if r.res.Status == fix.Contains {
			hi = mid
		} else {
			lo = mid + 1
		}
	}
	return cands[hi]
}

// fixRefs collects GitHub commit/PR references from the advisory, from
// alias records (e.g. Go vulndb FIX links) and from --fix-ref.
func (e *Engine) fixRefs(a *advisoryCtx) []github.Ref {
	var urls []string
	for _, r := range a.v.References {
		if r.Type == "FIX" || r.Type == "WEB" || r.Type == "PATCH" {
			urls = append(urls, r.URL)
		}
	}
	for _, al := range a.aliases {
		for _, r := range al.References {
			if r.Type == "FIX" {
				urls = append(urls, r.URL)
			}
		}
	}
	urls = append(urls, e.ExtraFixRefs...)
	seen := map[string]bool{}
	var out []github.Ref
	for _, u := range urls {
		r, ok := github.ParseRef(u)
		if !ok {
			continue
		}
		k := strings.ToLower(r.RepoSlug()) + "@" + r.SHA + fmt.Sprint(r.PR)
		if r.SHA != "" {
			// short and full SHAs of one commit
			for s := range seen {
				if strings.HasPrefix(s, strings.ToLower(r.RepoSlug())+"@"+r.SHA[:7]) {
					k = s
				}
			}
		}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, r)
	}
	if len(out) > maxFixRefs {
		out = out[:maxFixRefs]
	}
	return out
}

// checkFix implements IF005.
func (e *Engine) checkFix(ctx context.Context, a *advisoryCtx, g *group) {
	base := Finding{Check: IF005, Severity: Info, Ecosystem: g.Eco, Package: g.Name}
	info := func(msg string, details ...string) {
		f := base
		f.Message, f.Details = msg, details
		a.add(f)
	}
	refs := e.fixRefs(a)
	if len(refs) == 0 {
		info("unverifiable: no GitHub fix commit or pull request is referenced (pass --fix-ref to supply one)")
		return
	}
	var sets []*fix.Set
	var notes []string
	fetched := 0
	for _, r := range refs {
		c, err := e.GitHub.Resolve(ctx, r)
		if err == nil {
			var s *fix.Set
			if s, err = fix.Extract(ctx, e.GitHub, c); err == nil {
				fetched++
				if len(s.Units) < fix.MinUnits {
					notes = append(notes, fmt.Sprintf("%s: no distinctive added or removed source lines", r.URL))
					continue
				}
				if debug {
					for _, u := range s.Units {
						fmt.Fprintf(os.Stderr, "[debug] %s %s: %s\n", c.SHA[:10], u.File, u.Line)
					}
				}
				sets = append(sets, s)
				continue
			}
		}
		if httpx.IsFailure(err) {
			a.add(failure(IF005, g, "fetching fix commit "+r.URL, err))
			return
		}
		notes = append(notes, fmt.Sprintf("%s: could not be fetched: %v", r.URL, err))
	}
	if fetched == 0 {
		info("unverifiable: none of the referenced fix commits or pull requests could be fetched", notes...)
		return
	}
	sets, dropped := fix.Superseded(sets)
	notes = append(notes, dropped...)
	if len(sets) == 0 {
		info("unverifiable: the referenced fix commits yield no distinctive source lines to look for", notes...)
		return
	}
	budget := e.MaxArtifacts
	if budget <= 0 {
		budget = DefaultMaxArtifacts
	}
	p := &prober{ctx: ctx, g: g, sets: sets, results: map[string]*probeRes{}, seen: map[string]bool{}, budget: budget}
	defer func() {
		if p.failErr != nil {
			a.add(failure(IF005, g, "artifact download", p.failErr))
		}
	}()

	exact := func(v string) (string, bool) {
		r, ok := g.Pkg.Find(v)
		return r.Version, ok
	}
	ls := lines(g)
	type plan struct {
		iv       interval
		fixed    string  // exact release of iv.Fixed, if published
		covLines []*line // lines with versions covered by iv, ascending
		newest   map[string]string
	}
	var plans []*plan
	for _, iv := range g.Intervals {
		pl := &plan{iv: iv, newest: map[string]string{}}
		if iv.Fixed != "" {
			pl.fixed, _ = exact(iv.Fixed)
		}
		for _, l := range ls {
			n := ""
			for _, v := range l.releases {
				if iv.contains(g.Eco, v) {
					n = v
				}
			}
			if n != "" {
				pl.covLines = append(pl.covLines, l)
				pl.newest[l.key] = n
			}
		}
		plans = append(plans, pl)
	}
	// Initial probes: each fixed version, then the newest affected version
	// of the (up to 3) newest lines each range covers.
	for _, pl := range plans {
		if pl.fixed != "" {
			p.probe(pl.fixed)
		}
	}
	for _, pl := range plans {
		for i := len(pl.covLines) - 1; i >= 0 && i >= len(pl.covLines)-3; i-- {
			p.probe(pl.newest[pl.covLines[i].key])
		}
	}
	anchored := func() bool {
		for _, r := range p.results {
			if r.res.Status == fix.Contains {
				return true
			}
		}
		return false
	}
	if !anchored() && len(g.Pkg.Releases) > 0 {
		// Nothing matched yet: try the newest stable release, which should
		// contain the fix if the lines are matchable at all.
		for i := len(g.Pkg.Releases) - 1; i >= 0; i-- {
			if v := g.Pkg.Releases[i].Version; !versions.IsPrerelease(g.Eco, v) {
				p.probe(v)
				break
			}
		}
	}
	if !anchored() {
		var ds []string
		var best *probeRes
		applicable := 0
		for _, v := range g.Pkg.Versions() {
			r, ok := p.results[v]
			if !ok {
				continue
			}
			if r.err != nil {
				ds = append(ds, fmt.Sprintf("%s: %v", r.version, r.err))
				continue
			}
			ds = append(ds, r.summary())
			if r.res.Status != fix.Inapplicable {
				applicable++
			}
			if r.res.Status == fix.Partial && (best == nil || r.res.Fraction() > best.res.Fraction()) {
				best = r
			}
		}
		ds = append(ds, notes...)
		switch {
		case best != nil:
			info(fmt.Sprintf("inconclusive: no inspected version clearly contains the fix (best match %s: %d/%d distinctive lines)",
				best.version, best.res.Present, best.res.Applicable), ds...)
		case applicable == 0:
			info(fmt.Sprintf("unverifiable: the files changed by the fix were not found in any of the %d inspected artifact(s)", len(p.results)), ds...)
		default:
			info(fmt.Sprintf("unverifiable: none of the %d inspected version(s) contains the fix's distinctive lines", len(p.results)), ds...)
		}
		return
	}

	conf := ""
	var verified []string
	for _, pl := range plans {
		iv := pl.iv
		earliest := map[string]string{} // line -> earliest containing version
		// 1. The fixed version must contain the fix.
		if pl.fixed != "" {
			r := p.probe(pl.fixed)
			switch {
			case r == nil || r.err != nil:
			case r.res.Status == fix.Lacks:
				f := base
				f.Severity = Error
				f.Message = fmt.Sprintf("fixed version %s does not contain the fix (%d/%d distinctive lines present)", pl.fixed, r.res.Present, r.res.Applicable)
				f.Details = append(f.Details, sample("missing", r.res.Missing)...)
				f.Evidence = append(f.Evidence, r.evidence())
				f.Evidence = append(f.Evidence, commitURLs(sets)...)
				if e := p.laterInLine(pl.fixed); e != "" {
					f.Details = append(f.Details, "earliest version of the line containing the fix: "+e)
					f.Suggested = [][]osv.Event{{{Introduced: iv.Intro}, {Fixed: e}}}
				}
				a.add(f)
			case r.res.Status == fix.Contains:
				verified = append(verified, r.summary())
			default:
				info(fmt.Sprintf("inconclusive: fixed version %s contains only part of the fix", pl.fixed), r.summary())
			}
		}
		// 2. Affected versions must not contain the fix.
		var bad, pre []string
		var ev []string
		for i := len(pl.covLines) - 1; i >= 0 && i >= len(pl.covLines)-3; i-- {
			l := pl.covLines[i]
			n := pl.newest[l.key]
			r := p.probe(n)
			if r == nil || r.res.Status != fix.Contains {
				if r != nil && r.res.Status == fix.Lacks {
					verified = append(verified, r.summary())
				}
				continue
			}
			var cands []string
			for _, v := range l.releases {
				if iv.contains(g.Eco, v) && versions.Compare(g.Eco, v, n) <= 0 {
					cands = append(cands, v)
				}
			}
			e := p.bisect(cands)
			// Pre-releases of an upcoming fixed release that already carry
			// the fix are expected; report them as info only.
			allPre := true
			for _, v := range cands {
				if versions.Compare(g.Eco, v, e) >= 0 && !versions.IsPrerelease(g.Eco, v) {
					allPre = false
				}
			}
			if allPre {
				pre = append(pre, fmt.Sprintf("%s.x: pre-release %s and later pre-releases already contain the fix", l.key, e))
				continue
			}
			// Present from the very first version the range covers: the
			// referenced commit is more likely the one that introduced the
			// vulnerable feature (advisories often link it) than the fix.
			if e == firstCovered(g, iv) {
				pre = append(pre, fmt.Sprintf("%s.x: the referenced lines are present from %s, the first version the range covers; a referenced commit may be the one that introduced the vulnerability rather than the fix (%s)",
					l.key, e, r.summary()))
				continue
			}
			earliest[l.key] = e
			bad = append([]string{fmt.Sprintf("%s.x: the fix first appears in %s (newest affected version checked: %s)", l.key, e, r.summary())}, bad...)
			ev = append(ev, r.evidence())
			if er := p.results[e]; er != nil && er != r {
				ev = append(ev, er.evidence())
			}
		}
		if len(pre) > 0 {
			info(fmt.Sprintf("range %s: some affected versions contain the referenced lines, but not in a way that shows the range is wrong", describe(iv)), pre...)
		}
		// 3. An unpublished fixed version: find the real one in its line.
		fixedLine := ""
		if iv.Fixed != "" && pl.fixed == "" {
			if e := p.laterInLine(iv.Fixed); e != "" {
				fixedLine = e
				if len(bad) == 0 {
					f := base
					f.Message = fmt.Sprintf("fixed version %s is not published; the earliest later version of its line containing the fix is %s", iv.Fixed, e)
					f.Evidence = []string{p.results[e].evidence()}
					f.Suggested = [][]osv.Event{{{Introduced: iv.Intro}, {Fixed: e}}}
					a.add(f)
				}
			}
		}
		if len(bad) > 0 {
			f := base
			f.Severity = Warning
			f.Message = fmt.Sprintf("range %s includes versions that already contain the fix", describe(iv))
			f.Details = bad
			if fixedLine != "" {
				f.Details = append(f.Details, fmt.Sprintf("fixed version %s is not published; the earliest later %s.x version containing the fix is %s",
					iv.Fixed, versions.Line(g.Eco, iv.Fixed), fixedLine))
			}
			f.Evidence = append(ev, commitURLs(sets)...)
			f.Suggested = split(g, iv, pl.covLines, earliest, fixedLine)
			a.add(f)
		}
	}
	if p.lowConf {
		conf = "low"
	}
	// A fix made of several separate commits, some of which change only
	// files this package does not ship (another module of the project), can
	// only be partly verified here: presence of the visible part does not
	// prove the version is fixed.
	outside := 0
	for _, ok := range p.groupSeen {
		if !ok {
			outside++
		}
	}
	if outside > 0 {
		note := fmt.Sprintf("%d of the %d referenced fix commit groups change only files outside this package's artifacts, so only part of the fix could be checked",
			outside, len(p.groupSeen))
		for i := range a.findings {
			f := &a.findings[i]
			if f.Check == IF005 && f.Package == g.Name && f.Severity == Warning {
				f.Severity = Info
				f.Details = append(f.Details, note)
				f.Suggested = nil
			}
		}
		for _, c := range a.rng {
			if c.g == g {
				c.partialFix = true
			}
		}
	}
	// Feed evidence to range-shape candidates of this package.
	for _, c := range a.rng {
		if c.g != g {
			continue
		}
		v, ok := exact(c.probe)
		if !ok {
			continue
		}
		r := p.probe(v)
		if r == nil || r.err != nil || (r.res.Status != fix.Contains && r.res.Status != fix.Lacks) {
			continue
		}
		if c.partialFix && r.res.Status == fix.Contains {
			continue // a partial fix present proves nothing
		}
		c.probed, c.result, c.artURL = true, r.res, r.evidence()
		if r.res.Status == fix.Contains && len(c.uncovered) > 0 {
			c.earliest = p.bisect(c.uncovered)
			if er := p.results[c.earliest]; er != nil && er != r {
				c.earliestURL = er.evidence()
			}
		}
	}
	if len(verified) > 0 {
		f := base
		f.Message = "fix content checked against published artifacts"
		f.Details = verified
		f.Evidence = commitURLs(sets)
		f.Confidence = conf
		a.add(f)
	}
	if conf != "" {
		for i := range a.findings {
			if a.findings[i].Check == IF005 && a.findings[i].Package == g.Name {
				a.findings[i].Confidence = conf
			}
		}
	}
}

// laterInLine returns the earliest version after v in v's release line that
// contains the fix, or "" if the newest version of the line does not.
func (p *prober) laterInLine(v string) string {
	g := p.g
	var cands []string
	for _, l := range lines(g) {
		if l.key != versions.Line(g.Eco, v) {
			continue
		}
		for _, x := range l.releases {
			if versions.Compare(g.Eco, x, v) > 0 {
				cands = append(cands, x)
			}
		}
	}
	if len(cands) == 0 || !p.contains(cands[len(cands)-1]) {
		return ""
	}
	return p.bisect(cands)
}

// split rewrites one interval so that each release line in which the fix
// was found ends at the earliest version containing it.
func split(g *group, iv interval, covLines []*line, earliest map[string]string, fixedLine string) [][]osv.Event {
	var out [][]osv.Event
	start := iv.Intro
	for i, l := range covLines {
		e, ok := earliest[l.key]
		if !ok {
			continue
		}
		if start != "" && versions.Compare(g.Eco, e, start) > 0 {
			out = append(out, []osv.Event{{Introduced: start}, {Fixed: e}})
		}
		start = ""
		if i+1 < len(covLines) {
			start = covLines[i+1].first()
		}
	}
	if start != "" {
		end := iv.events()[1:]
		if fixedLine != "" {
			end = []osv.Event{{Fixed: fixedLine}}
		}
		out = append(out, append([]osv.Event{{Introduced: start}}, end...))
	}
	return out
}

func describe(iv interval) string {
	switch {
	case iv.Fixed != "":
		return fmt.Sprintf("[%s, %s)", iv.Intro, iv.Fixed)
	case iv.LastAffected != "":
		return fmt.Sprintf("[%s, %s]", iv.Intro, iv.LastAffected)
	}
	return fmt.Sprintf("[%s, ∞)", iv.Intro)
}

func commitURLs(sets []*fix.Set) []string {
	var out []string
	for _, s := range sets {
		out = append(out, s.Commit.URL)
	}
	return out
}

func sample(label string, lines []string) []string {
	var out []string
	for i, l := range lines {
		if i == 3 {
			out = append(out, fmt.Sprintf("… and %d more %s lines", len(lines)-3, label))
			break
		}
		out = append(out, label+": "+l)
	}
	return out
}

// firstCovered returns the lowest published version inside the interval.
func firstCovered(g *group, iv interval) string {
	for _, r := range g.Pkg.Releases {
		if iv.contains(g.Eco, r.Version) {
			return r.Version
		}
	}
	return ""
}
