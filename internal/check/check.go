// Package check implements isitfixed's checks on OSV records.
package check

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/Slymaster/isitfixed/internal/fix"
	"github.com/Slymaster/isitfixed/internal/httpx"
	"github.com/Slymaster/isitfixed/internal/osv"
	"github.com/Slymaster/isitfixed/internal/registry"
	"github.com/Slymaster/isitfixed/internal/versions"
)

// Severity of a finding.
type Severity string

// Severities.
const (
	// Failed means the check could not be completed (network or API
	// failure); the run exits with status 2.
	Failed  Severity = "failed"
	Error   Severity = "error"
	Warning Severity = "warning"
	Info    Severity = "info"
)

func (s Severity) rank() int {
	switch s {
	case Failed:
		return 0
	case Error:
		return 1
	case Warning:
		return 2
	}
	return 3
}

// Check IDs. The IF prefix avoids confusion with osv-linter's rule IDs.
const (
	IF001 = "IF001"
	IF002 = "IF002"
	IF003 = "IF003"
	IF004 = "IF004"
	IF005 = "IF005"
	IF006 = "IF006"
)

// AllChecks lists every check ID.
var AllChecks = []string{IF001, IF002, IF003, IF004, IF005, IF006}

// Slugs are readable names for the check IDs.
var Slugs = map[string]string{
	IF001: "package-missing",
	IF002: "version-missing",
	IF003: "stale-last-affected",
	IF004: "uncovered-release-line",
	IF005: "fix-content",
	IF006: "cross-database",
}

// ParseCheck accepts a check ID ("IF004") or slug ("uncovered-release-line").
func ParseCheck(s string) (string, bool) {
	s = strings.TrimSpace(s)
	for id, slug := range Slugs {
		if strings.EqualFold(s, id) || strings.EqualFold(s, slug) {
			return id, true
		}
	}
	return "", false
}

// Finding is one result.
type Finding struct {
	Advisory  string   `json:"advisory"`
	Check     string   `json:"check"`
	Slug      string   `json:"slug"`
	Severity  Severity `json:"severity"`
	Ecosystem string   `json:"ecosystem,omitempty"`
	Package   string   `json:"package,omitempty"`
	Message   string   `json:"message"`
	Details   []string `json:"details,omitempty"`
	Evidence  []string `json:"evidence,omitempty"`
	// Suggested is a corrected list of ranges' events, when derivable.
	Suggested [][]osv.Event `json:"suggested_events,omitempty"`
	// Confidence is "low" when content matching used compiled classes.
	Confidence string `json:"confidence,omitempty"`
}

// OSVSource fetches OSV records by ID.
type OSVSource interface {
	Get(ctx context.Context, id string) (*osv.Vuln, error)
}

// Engine runs checks.
type Engine struct {
	Registries map[string]registry.Registry
	GitHub     fix.Fetcher // nil disables IF005
	OSV        OSVSource   // nil disables IF006 and alias-based fix discovery
	// ExtraFixRefs are commit/PR URLs supplied by the user (--fix-ref).
	ExtraFixRefs []string
	// MaxArtifacts bounds artifact inspections per package (IF005).
	MaxArtifacts int
	// Enabled restricts checks (nil = all).
	Enabled map[string]bool
}

func (e *Engine) on(id string) bool { return e.Enabled == nil || e.Enabled[id] }

// interval is one introduced→(fixed|last_affected|open) span.
type interval struct {
	Intro, Fixed, LastAffected string
}

func (iv interval) contains(eco, v string) bool {
	if iv.Intro != "0" && versions.Compare(eco, v, iv.Intro) < 0 {
		return false
	}
	switch {
	case iv.Fixed != "":
		return versions.Compare(eco, v, iv.Fixed) < 0
	case iv.LastAffected != "":
		return versions.Compare(eco, v, iv.LastAffected) <= 0
	}
	return true
}

func (iv interval) end() string {
	if iv.Fixed != "" {
		return iv.Fixed
	}
	return iv.LastAffected
}

func (iv interval) events() []osv.Event {
	ev := []osv.Event{{Introduced: iv.Intro}}
	if iv.Fixed != "" {
		ev = append(ev, osv.Event{Fixed: iv.Fixed})
	} else if iv.LastAffected != "" {
		ev = append(ev, osv.Event{LastAffected: iv.LastAffected})
	}
	return ev
}

func evVersion(e osv.Event) string {
	switch {
	case e.Introduced != "":
		return e.Introduced
	case e.Fixed != "":
		return e.Fixed
	case e.LastAffected != "":
		return e.LastAffected
	}
	return e.Limit
}

// intervals converts a range's events (in any order) into spans.
func intervals(eco string, r osv.Range) []interval {
	evs := append([]osv.Event(nil), r.Events...)
	sort.SliceStable(evs, func(i, j int) bool {
		return versions.Compare(eco, evVersion(evs[i]), evVersion(evs[j])) < 0
	})
	var out []interval
	var cur *interval
	for _, e := range evs {
		switch {
		case e.Introduced != "":
			if cur == nil {
				cur = &interval{Intro: versions.Normalize(eco, e.Introduced)}
			}
		case e.Fixed != "" && cur != nil:
			cur.Fixed = versions.Normalize(eco, e.Fixed)
			out = append(out, *cur)
			cur = nil
		case e.LastAffected != "" && cur != nil:
			cur.LastAffected = versions.Normalize(eco, e.LastAffected)
			out = append(out, *cur)
			cur = nil
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}

// group is all affected[] entries of one package in an advisory.
type group struct {
	Eco, Name string
	Intervals []interval
	Explicit  []string
	Pkg       *registry.Package
	Reg       registry.Registry
	missing   map[string]bool // range versions IF002 found unpublished
}

func (g *group) covered(v string) bool {
	for _, iv := range g.Intervals {
		if iv.contains(g.Eco, v) {
			return true
		}
	}
	for _, x := range g.Explicit {
		if versions.Equal(g.Eco, x, v) {
			return true
		}
	}
	return false
}

func (g *group) key() string { return g.Eco + ":" + g.Name }

func groupsOf(v *osv.Vuln) []*group {
	idx := map[string]*group{}
	var out []*group
	for _, a := range v.Affected {
		eco := a.Package.Ecosystem
		if !versions.Supported(eco) || a.Package.Name == "" {
			continue
		}
		k := eco + ":" + a.Package.Name
		g, ok := idx[k]
		if !ok {
			g = &group{Eco: eco, Name: a.Package.Name, missing: map[string]bool{}}
			idx[k] = g
			out = append(out, g)
		}
		for _, r := range a.Ranges {
			if r.Type == "ECOSYSTEM" || r.Type == "SEMVER" {
				g.Intervals = append(g.Intervals, intervals(eco, r)...)
			}
		}
		for _, x := range a.Versions {
			g.Explicit = append(g.Explicit, versions.Normalize(eco, x))
		}
	}
	return out
}

// advisoryCtx carries per-advisory state across checks.
type advisoryCtx struct {
	v        *osv.Vuln
	groups   []*group
	aliases  []*osv.Vuln
	findings []Finding
	// pending range findings that IF005 evidence may confirm or downgrade.
	rng []*rngCandidate
}

func (a *advisoryCtx) add(f Finding) {
	f.Advisory = a.v.ID
	f.Slug = Slugs[f.Check]
	a.findings = append(a.findings, f)
}

// Run checks one advisory.
func (e *Engine) Run(ctx context.Context, v *osv.Vuln) []Finding {
	a := &advisoryCtx{v: v, groups: groupsOf(v)}
	if v.Withdrawn != "" || v.IsMalware() || len(a.groups) == 0 {
		return nil
	}
	for _, g := range a.groups {
		g.Reg = e.Registries[g.Eco]
		if g.Reg == nil {
			continue
		}
		if e.on(IF001) || e.on(IF002) || e.on(IF003) || e.on(IF004) || e.on(IF005) || e.on(IF006) {
			e.checkPackage(ctx, a, g)
		}
	}
	if e.OSV != nil && (e.on(IF006) || e.on(IF005)) {
		var err error
		a.aliases, err = e.fetchAliases(ctx, v)
		if err != nil {
			a.add(failure(IF006, nil, "alias lookup", err))
		}
	}
	for _, g := range a.groups {
		if g.Pkg == nil || g.Pkg.Unpublished {
			continue
		}
		if e.on(IF002) {
			e.checkVersions(ctx, a, g)
		}
		if e.on(IF003) || e.on(IF004) {
			e.rangeCandidates(ctx, a, g)
		}
		if e.on(IF005) && e.GitHub != nil {
			e.checkFix(ctx, a, g)
		}
	}
	for _, c := range a.rng {
		if e.on(c.check) {
			a.add(c.finding())
		}
	}
	if e.on(IF006) && e.OSV != nil {
		e.checkCrossDB(ctx, a)
	}
	sortFindings(a.findings)
	return a.findings
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Advisory != fs[j].Advisory {
			return fs[i].Advisory < fs[j].Advisory
		}
		if fs[i].Severity.rank() != fs[j].Severity.rank() {
			return fs[i].Severity.rank() < fs[j].Severity.rank()
		}
		return fs[i].Check < fs[j].Check
	})
}

func isNotFound(err error) bool { return errors.Is(err, httpx.ErrNotFound) }

// checkPackage implements IF001 and loads registry metadata.
func (e *Engine) checkPackage(ctx context.Context, a *advisoryCtx, g *group) {
	p, err := g.Reg.Lookup(ctx, g.Name)
	if err == nil {
		g.Pkg = p
		if p.Unpublished && e.on(IF001) {
			a.add(Finding{Check: IF001, Severity: Info, Ecosystem: g.Eco, Package: g.Name,
				Message: "package exists but " + p.Note + "; version checks skipped", Evidence: []string{p.URL}})
		}
		return
	}
	if !isNotFound(err) {
		if httpx.IsFailure(err) {
			a.add(failure(IF001, g, "package lookup", err))
		} else if e.on(IF001) {
			a.add(Finding{Check: IF001, Severity: Info, Ecosystem: g.Eco, Package: g.Name,
				Message: "could not look up package: " + err.Error()})
		}
		return
	}
	// The listing is missing; a version page may still exist (incomplete
	// metadata). Only then is the package treated as existing.
	for _, iv := range g.Intervals {
		for _, ver := range []string{iv.Fixed, iv.LastAffected, iv.Intro} {
			if ver == "" || ver == "0" {
				continue
			}
			ok, verr := g.Reg.VersionExists(ctx, g.Name, ver)
			if httpx.IsFailure(verr) {
				a.add(failure(IF001, g, "package lookup", verr))
				return
			}
			if ok {
				if e.on(IF001) {
					a.add(Finding{Check: IF001, Severity: Info, Ecosystem: g.Eco, Package: g.Name,
						Message:  fmt.Sprintf("registry has no version listing for the package, but version %s exists; other checks skipped", ver),
						Evidence: []string{g.Reg.VersionURL(g.Name, ver)}})
				}
				return
			}
		}
	}
	if !e.on(IF001) {
		return
	}
	f := Finding{Check: IF001, Severity: Error, Ecosystem: g.Eco, Package: g.Name,
		Message:  fmt.Sprintf("package %s was not found on %s", g.Name, registryName(g)),
		Evidence: []string{g.Reg.PackageURL(g.Name)}}
	for _, o := range a.groups {
		if o != g && o.Eco == g.Eco && similarName(o.Name, g.Name) {
			f.Details = append(f.Details, fmt.Sprintf("did you mean %s (also named in this advisory)?", o.Name))
		}
	}
	a.add(f)
}

// similarName reports whether two package names plausibly refer to the same
// package (typo, case, duplicated segment).
func similarName(a, b string) bool {
	if a == b {
		return false
	}
	la, lb := strings.ToLower(a), strings.ToLower(b)
	if la == lb || strings.HasPrefix(lb, la) || strings.HasPrefix(la, lb) {
		return true
	}
	return levenshtein(la, lb) <= 3
}

func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			c := 1
			if ra[i-1] == rb[j-1] {
				c = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+c)
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)]
}

func registryName(g *group) string {
	switch r := g.Reg.(type) {
	case *registry.Maven:
		return strings.Join(r.RepoNames(), ", ")
	case *registry.GoProxy:
		return "proxy.golang.org"
	case *registry.Npm:
		return "registry.npmjs.org"
	case *registry.Crates:
		return "crates.io"
	}
	return g.Eco
}

// failure builds a "could not check" result for a lookup that failed after
// retries. It names the host that failed and makes the run exit 2; the
// check itself is not reported as passed or downgraded.
func failure(check string, g *group, what string, err error) Finding {
	host := httpx.FailedHost(err)
	msg := fmt.Sprintf("could not check: %s failed", what)
	if host != "" {
		msg = fmt.Sprintf("could not check: %s on %s failed", what, host)
	}
	f := Finding{Check: check, Severity: Failed, Message: msg, Details: []string{err.Error()}}
	if g != nil {
		f.Ecosystem, f.Package = g.Eco, g.Name
	}
	return f
}
