package check

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/Slymaster/isitfixed/internal/httpx"
	"github.com/Slymaster/isitfixed/internal/registry"
	"github.com/Slymaster/isitfixed/internal/versions"
)

// checkVersions implements IF002: every range version must be published.
// "Published" means equal under ecosystem ordering to a listed version (so
// Maven 2.2.0 matches 2.2.0.RELEASE), or confirmed by a per-version lookup
// (Go pseudo-versions, incomplete Maven metadata).
func (e *Engine) checkVersions(ctx context.Context, a *advisoryCtx, g *group) {
	type ev struct{ kind, ver string }
	seen := map[string]bool{}
	for _, iv := range g.Intervals {
		for _, x := range []ev{{"introduced", iv.Intro}, {"fixed", iv.Fixed}, {"last_affected", iv.LastAffected}} {
			if x.ver == "" || x.ver == "0" || seen[x.kind+x.ver] {
				continue
			}
			if x.kind == "introduced" && g.Eco != versions.Maven && versions.Compare(g.Eco, x.ver, "0.0.0") == 0 {
				continue // "0.0.0" means "0"
			}
			seen[x.kind+x.ver] = true
			if _, ok := g.Pkg.Find(x.ver); ok {
				continue
			}
			ok, err := g.Reg.VersionExists(ctx, g.Name, x.ver)
			if ok {
				continue
			}
			if httpx.IsFailure(err) {
				a.add(failure(IF002, g, fmt.Sprintf("lookup of %s version %s", x.kind, x.ver), err))
				continue
			}
			if err != nil && !isNotFound(err) {
				a.add(Finding{Check: IF002, Severity: Info, Ecosystem: g.Eco, Package: g.Name,
					Message: fmt.Sprintf("could not confirm %s version %s: %v", x.kind, x.ver, err)})
				continue
			}
			g.missing[x.ver] = true
			sev := Warning
			if x.kind == "fixed" {
				sev = Error
			}
			f := Finding{Check: IF002, Severity: sev, Ecosystem: g.Eco, Package: g.Name,
				Message:  fmt.Sprintf("%s version %s is not published for %s", x.kind, x.ver, g.Name),
				Evidence: []string{g.Pkg.URL, g.Reg.VersionURL(g.Name, x.ver)}}
			f.Details = nearest(g, x.ver)
			movedModule := false
			if g.Eco == versions.Go {
				movedModule = e.explainGo(ctx, g, x.ver, &f)
			}
			if f.Severity == Error && !movedModule && !coversAny(g, iv) {
				// The range matches no published version, so the bad
				// endpoint changes nothing for scanners today.
				f.Severity = Warning
				f.Details = append(f.Details, fmt.Sprintf("the range %s currently matches no published version", describe(iv)))
			}
			a.add(f)
		}
	}
}

// nearest describes published versions close to a missing one.
func nearest(g *group, v string) []string {
	var out []string
	var lower, higher string
	for _, r := range g.Pkg.Releases {
		c := versions.Compare(g.Eco, r.Version, v)
		if c < 0 {
			lower = r.Version
		} else if c > 0 && higher == "" {
			higher = r.Version
		}
	}
	if lower != "" || higher != "" {
		out = append(out, fmt.Sprintf("nearest published versions: %s < %s < %s", orNone(lower), v, orNone(higher)))
	}
	return out
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// goModules is implemented by the Go proxy client.
type goModules interface {
	ExactVersion(ctx context.Context, mod, v string) bool
	Origin(ctx context.Context, name string) (repoURL, subdir string)
}

// tagLister is implemented by the GitHub client.
type tagLister interface {
	Tags(ctx context.Context, repo string) ([]string, error)
}

// tagFor finds a git tag naming version v: "v1.2.3", "1.2.3", or a prefixed
// form such as "app/v1.2.3", "lxd-1.2.3" or "version/1.2.3".
func tagFor(tags []string, v string) string {
	for _, t := range tags {
		if t == v || t == "v"+v {
			return t
		}
	}
	for _, t := range tags {
		for _, suf := range []string{"/v" + v, "/" + v, "-v" + v, "-" + v} {
			if strings.HasSuffix(t, suf) {
				return t
			}
		}
	}
	return ""
}

// explainGo refines a missing Go version. Two situations are common:
// the version exists under the module path with the right major-version
// suffix (an actionable mistake in the advisory), or it is only a git tag
// of a repository whose module cannot carry it (major version ≥ 2 without
// a /vN path, a module in a subdirectory, CalVer tags). The latter is a
// widespread convention for applications rather than an error, so it is
// reported as info.
//
// It reports true when the version belongs to another module path.
func (e *Engine) explainGo(ctx context.Context, g *group, ver string, f *Finding) bool {
	gm, ok := g.Reg.(goModules)
	if !ok {
		return false
	}
	major := 0
	if head, _, _ := strings.Cut(ver, "."); head != "" {
		major, _ = strconv.Atoi(head)
	}
	base := goBase(g.Name)
	var alts []string
	if major >= 2 {
		alts = append(alts, fmt.Sprintf("%s/v%d", base, major))
	} else if goSuffix(g.Name) >= 2 {
		alts = append(alts, base)
	}
	for _, alt := range alts {
		if alt != g.Name && gm.ExactVersion(ctx, alt, ver) {
			f.Message = fmt.Sprintf("%s is not a version of module %s; it is published under module %s", ver, g.Name, alt)
			f.Evidence = append(f.Evidence, "https://proxy.golang.org/"+registry.EscapePath(alt)+"/@v/v"+ver+".info")
			return true
		}
	}
	tl, ok := e.GitHub.(tagLister)
	if !ok {
		return false
	}
	repo := ""
	if parts := strings.Split(g.Name, "/"); len(parts) >= 3 && parts[0] == "github.com" {
		repo = parts[1] + "/" + parts[2]
	} else if u, _ := gm.Origin(ctx, g.Name); strings.HasPrefix(u, "https://github.com/") {
		repo = strings.TrimSuffix(strings.TrimPrefix(u, "https://github.com/"), ".git")
	}
	if repo == "" {
		return false
	}
	tags, err := tl.Tags(ctx, repo)
	if err != nil {
		return false
	}
	if t := tagFor(tags, ver); t != "" {
		f.Severity = Info
		f.Message = fmt.Sprintf("%s version %s is a git tag of github.com/%s (%s) but not a version of Go module %s; Go tooling cannot match it",
			kindOf(f.Message), ver, repo, t, g.Name)
		f.Details = []string{"common for applications whose major version is ≥ 2 without a /vN module path, or whose module lives in a subdirectory; not counted as an error"}
		f.Evidence = append(f.Evidence, "https://github.com/"+repo+"/releases/tag/"+t)
	}
	return false
}

func kindOf(msg string) string {
	k, _, _ := strings.Cut(msg, " ")
	return k
}

func coversAny(g *group, iv interval) bool {
	for _, r := range g.Pkg.Releases {
		if iv.contains(g.Eco, r.Version) {
			return true
		}
	}
	return false
}
