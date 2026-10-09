package check

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Slymaster/isitfixed/internal/github"
	"github.com/Slymaster/isitfixed/internal/httpx"
	"github.com/Slymaster/isitfixed/internal/osv"
	"github.com/Slymaster/isitfixed/internal/registry"
	"github.com/Slymaster/isitfixed/internal/versions"
)

// fakeRegistry is an in-memory registry.
type fakeRegistry struct {
	eco       string
	pkgs      map[string][]string          // name -> versions
	published map[string]time.Time         // version -> time
	files     map[string]map[string]string // version -> artifact files
	kind      string                       // artifact kind
	downloads int
}

func (f *fakeRegistry) Ecosystem() string { return f.eco }

func (f *fakeRegistry) Lookup(_ context.Context, name string) (*registry.Package, error) {
	vs, ok := f.pkgs[name]
	if !ok {
		return nil, registry.ErrNotFound
	}
	p := &registry.Package{Ecosystem: f.eco, Name: name, URL: "https://registry.test/" + name}
	vs = append([]string(nil), vs...)
	versions.Sort(f.eco, vs)
	for _, v := range vs {
		p.Releases = append(p.Releases, registry.Release{Version: v, Published: f.published[v]})
	}
	return p, nil
}

func (f *fakeRegistry) PackageURL(name string) string { return "https://registry.test/" + name }
func (f *fakeRegistry) VersionURL(name, v string) string {
	return "https://registry.test/" + name + "/" + v
}

func (f *fakeRegistry) VersionExists(_ context.Context, name, v string) (bool, error) {
	for _, x := range f.pkgs[name] {
		if versions.Equal(f.eco, x, v) {
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeRegistry) PublishedAt(_ context.Context, _, v string) (time.Time, bool) {
	t, ok := f.published[v]
	return t, ok
}

func (f *fakeRegistry) Artifact(_ context.Context, name, v string) (*registry.Artifact, error) {
	f.downloads++
	files, ok := f.files[v]
	if !ok {
		return nil, registry.ErrNoArtifact
	}
	kind := f.kind
	if kind == "" {
		kind = "source"
	}
	return registry.NewMemArtifact("https://registry.test/"+name+"/"+v+".zip", kind, files), nil
}

// fakeGitHub serves commits and raw files.
type fakeGitHub struct {
	commits map[string]*github.Commit // sha -> commit
	raw     map[string]string         // sha:path -> content
}

func (g *fakeGitHub) Resolve(_ context.Context, r github.Ref) (*github.Commit, error) {
	c, ok := g.commits[r.SHA]
	if !ok {
		return nil, httpx.ErrNotFound
	}
	return c, nil
}

func (g *fakeGitHub) RawFile(_ context.Context, _, sha, path string) ([]byte, error) {
	s, ok := g.raw[sha+":"+path]
	if !ok {
		return nil, httpx.ErrNotFound
	}
	return []byte(s), nil
}

type fakeOSV map[string]*osv.Vuln

func (f fakeOSV) Get(_ context.Context, id string) (*osv.Vuln, error) {
	v, ok := f[id]
	if !ok {
		return nil, httpx.ErrNotFound
	}
	return v, nil
}

func rng(events ...string) osv.Range {
	r := osv.Range{Type: "ECOSYSTEM"}
	for _, e := range events {
		k, v, _ := strings.Cut(e, "=")
		switch k {
		case "i":
			r.Events = append(r.Events, osv.Event{Introduced: v})
		case "f":
			r.Events = append(r.Events, osv.Event{Fixed: v})
		case "la":
			r.Events = append(r.Events, osv.Event{LastAffected: v})
		}
	}
	return r
}

func vuln(id, eco, name string, ranges ...osv.Range) *osv.Vuln {
	v := &osv.Vuln{ID: id}
	for _, r := range ranges {
		v.Affected = append(v.Affected, osv.Affected{Package: osv.Package{Ecosystem: eco, Name: name}, Ranges: []osv.Range{r}})
	}
	return v
}

func only(fs []Finding, check string) []Finding {
	var out []Finding
	for _, f := range fs {
		if f.Check == check {
			out = append(out, f)
		}
	}
	return out
}

func dump(fs []Finding) string {
	var b strings.Builder
	for _, f := range fs {
		fmt.Fprintf(&b, "%s %s %s: %s %v %v\n", f.Severity, f.Check, f.Package, f.Message, f.Details, f.Suggested)
	}
	return b.String()
}

func engine(regs ...*fakeRegistry) *Engine {
	e := &Engine{Registries: map[string]registry.Registry{}}
	for _, r := range regs {
		e.Registries[r.eco] = r
	}
	return e
}

func expectOne(t *testing.T, fs []Finding, check string, sev Severity, contains ...string) Finding {
	t.Helper()
	got := only(fs, check)
	var match []Finding
	for _, f := range got {
		if f.Severity != sev {
			continue
		}
		text := f.Message + " " + strings.Join(f.Details, " ")
		ok := true
		for _, c := range contains {
			if !strings.Contains(text, c) {
				ok = false
			}
		}
		if ok {
			match = append(match, f)
		}
	}
	if len(match) != 1 {
		t.Fatalf("want exactly one %s %s finding containing %q, got:\n%s", sev, check, contains, dump(fs))
	}
	return match[0]
}

// fakeGoRegistry adds the Go-specific lookups used by IF002.
type fakeGoRegistry struct {
	*fakeRegistry
	modules map[string][]string // other module paths -> versions
	origin  string
}

func (f *fakeGoRegistry) ExactVersion(_ context.Context, mod, v string) bool {
	for _, x := range f.modules[mod] {
		if versions.Equal(versions.Go, x, v) {
			return true
		}
	}
	return false
}

func (f *fakeGoRegistry) Origin(context.Context, string) (string, string) { return f.origin, "" }

// fakeTags lists git tags per repository.
type fakeTags struct {
	fakeGitHub
	tags map[string][]string
}

func (f *fakeTags) Tags(_ context.Context, repo string) ([]string, error) { return f.tags[repo], nil }
