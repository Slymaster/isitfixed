package registry

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/Slymaster/isitfixed/internal/httpx"
	"github.com/Slymaster/isitfixed/internal/versions"
)

// GoProxy reads modules from a GOPROXY (default proxy.golang.org).
type GoProxy struct {
	HTTP *httpx.Client
	Base string
}

func (g *GoProxy) base() string {
	if g.Base != "" {
		return strings.TrimRight(g.Base, "/")
	}
	return "https://proxy.golang.org"
}

// Ecosystem implements Registry.
func (g *GoProxy) Ecosystem() string { return versions.Go }

// EscapePath applies the module proxy case encoding ("A" -> "!a").
func EscapePath(p string) string {
	var b strings.Builder
	for _, r := range p {
		if unicode.IsUpper(r) {
			b.WriteByte('!')
			b.WriteRune(unicode.ToLower(r))
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func (g *GoProxy) modURL(mod string) string { return g.base() + "/" + EscapePath(mod) + "/@v/" }

// moduleCache maps an OSV package name to the module that contains it.
func (g *GoProxy) list(ctx context.Context, mod string) ([]string, error) {
	resp, err := g.HTTP.Get(ctx, httpx.Request{URL: g.modURL(mod) + "list"})
	if err != nil {
		return nil, err
	}
	var out []string
	for _, l := range strings.Split(string(resp.Body), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out, nil
}

// Module resolves an OSV Go package name to its module path. OSV names
// are usually module paths, but may be package paths inside a module.
func (g *GoProxy) Module(ctx context.Context, name string) (string, []string, error) {
	p := name
	for {
		vs, err := g.list(ctx, p)
		if err == nil && (len(vs) > 0 || g.hasLatest(ctx, p)) {
			return p, vs, nil
		}
		if err != nil && err != ErrNotFound {
			return "", nil, err
		}
		i := strings.LastIndexByte(p, '/')
		if i < 0 || strings.Count(p[:i], "/") < 1 {
			return "", nil, ErrNotFound
		}
		p = p[:i]
	}
}

func (g *GoProxy) hasLatest(ctx context.Context, mod string) bool {
	_, err := g.HTTP.Get(ctx, httpx.Request{URL: g.base() + "/" + EscapePath(mod) + "/@latest"})
	return err == nil
}

// Lookup implements Registry.
func (g *GoProxy) Lookup(ctx context.Context, name string) (*Package, error) {
	if name == "stdlib" || name == "toolchain" {
		return nil, fmt.Errorf("go %s is not served by the module proxy", name)
	}
	mod, vs, err := g.Module(ctx, name)
	if err != nil {
		return nil, err
	}
	p := &Package{Ecosystem: versions.Go, Name: name, URL: g.modURL(mod) + "list"}
	if mod != name {
		p.Note = "package inside module " + mod
	}
	seen := map[string]bool{}
	for _, v := range vs {
		n := versions.Normalize(versions.Go, v)
		if !seen[n] {
			seen[n] = true
			p.Releases = append(p.Releases, Release{Version: n})
		}
	}
	sortReleases(versions.Go, p.Releases)
	return p, nil
}

type goInfo struct {
	Version string
	Time    time.Time
	Origin  struct {
		Hash string
		Ref  string
	}
}

func (g *GoProxy) info(ctx context.Context, name, version string) (*goInfo, string, error) {
	mod, _, err := g.Module(ctx, name)
	if err != nil {
		return nil, "", err
	}
	v := "v" + versions.Normalize(versions.Go, version)
	cands := []string{v}
	if !strings.Contains(v, "+") {
		cands = append(cands, v+"+incompatible")
	}
	for _, c := range cands {
		resp, err := g.HTTP.Get(ctx, httpx.Request{URL: g.modURL(mod) + c + ".info", Immutable: true})
		if err == ErrNotFound {
			continue
		}
		if err != nil {
			return nil, mod, err
		}
		var gi goInfo
		if err := json.Unmarshal(resp.Body, &gi); err != nil {
			return nil, mod, err
		}
		return &gi, mod, nil
	}
	return nil, mod, ErrNotFound
}

// VersionURL implements Registry.
func (g *GoProxy) VersionURL(name, version string) string {
	return g.modURL(name) + "v" + versions.Normalize(versions.Go, version) + ".info"
}

// VersionExists implements Registry (resolves pseudo-versions too).
func (g *GoProxy) VersionExists(ctx context.Context, name, version string) (bool, error) {
	_, _, err := g.info(ctx, name, version)
	if err == ErrNotFound {
		return false, nil
	}
	return err == nil, err
}

// PublishedAt implements Registry.
func (g *GoProxy) PublishedAt(ctx context.Context, name, version string) (time.Time, bool) {
	gi, _, err := g.info(ctx, name, version)
	if err != nil {
		return time.Time{}, false
	}
	return gi.Time, !gi.Time.IsZero()
}

// Artifact implements Registry: the module zip, read with ranged requests.
func (g *GoProxy) Artifact(ctx context.Context, name, version string) (*Artifact, error) {
	gi, mod, err := g.info(ctx, name, version)
	if err != nil {
		return nil, err
	}
	u := g.modURL(mod) + gi.Version + ".zip"
	rf, err := g.HTTP.OpenRanged(ctx, u)
	if err != nil {
		return nil, err
	}
	prefix := mod + "@" + gi.Version + "/"
	files, err := zipArtifact(rf, rf.Size(), func(n string) (string, bool) {
		if !strings.HasPrefix(n, prefix) {
			return "", false
		}
		return n[len(prefix):], true
	})
	if err != nil {
		return nil, fmt.Errorf("%s: %w", u, err)
	}
	a := &Artifact{URL: u, Kind: "source", files: files}
	if gi.Origin.Hash != "" {
		a.Digest = "vcs:" + gi.Origin.Hash
	}
	return a, nil
}

// PackageURL implements Registry.
func (g *GoProxy) PackageURL(name string) string { return g.modURL(name) + "list" }

// ExactVersion reports whether module mod itself (not a parent module)
// serves version v.
func (g *GoProxy) ExactVersion(ctx context.Context, mod, v string) bool {
	_, err := g.HTTP.Get(ctx, httpx.Request{URL: g.modURL(mod) + "v" + versions.Normalize(versions.Go, v) + ".info", Immutable: true})
	return err == nil
}

// Origin returns the VCS repository URL and subdirectory of a module, as
// recorded by the proxy for its latest version.
func (g *GoProxy) Origin(ctx context.Context, name string) (repoURL, subdir string) {
	mod, _, err := g.Module(ctx, name)
	if err != nil {
		return "", ""
	}
	resp, err := g.HTTP.Get(ctx, httpx.Request{URL: g.base() + "/" + EscapePath(mod) + "/@latest"})
	if err != nil {
		return "", ""
	}
	var gi struct {
		Origin struct {
			URL    string
			Subdir string
		}
	}
	if json.Unmarshal(resp.Body, &gi) != nil {
		return "", ""
	}
	return gi.Origin.URL, gi.Origin.Subdir
}
