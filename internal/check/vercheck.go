package check

import (
	"context"
	"fmt"

	"github.com/Slymaster/isitfixed/internal/versions"
)

// checkVersions implements VER001: every range version must be published.
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
			seen[x.kind+x.ver] = true
			if _, ok := g.Pkg.Find(x.ver); ok {
				continue
			}
			ok, err := g.Reg.VersionExists(ctx, g.Name, x.ver)
			if ok {
				continue
			}
			if err != nil && !isNotFound(err) {
				a.add(Finding{Check: VER001, Severity: Info, Ecosystem: g.Eco, Package: g.Name,
					Message: fmt.Sprintf("could not confirm %s version %s: %v", x.kind, x.ver, err)})
				continue
			}
			g.missing[x.ver] = true
			sev := Warning
			if x.kind == "fixed" {
				sev = Error
			}
			f := Finding{Check: VER001, Severity: sev, Ecosystem: g.Eco, Package: g.Name,
				Message:  fmt.Sprintf("%s version %s is not published for %s", x.kind, x.ver, g.Name),
				Evidence: []string{g.Pkg.URL, g.Reg.VersionURL(g.Name, x.ver)}}
			f.Details = nearest(g, x.ver)
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
