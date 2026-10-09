package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Slymaster/isitfixed/internal/check"
	"github.com/Slymaster/isitfixed/internal/httpx"
	"github.com/Slymaster/isitfixed/internal/osv"
	"github.com/Slymaster/isitfixed/internal/registry"
	"github.com/Slymaster/isitfixed/internal/versions"
)

// memRegistry is an offline Maven registry.
type memRegistry struct{ versions []string }

func (m memRegistry) Ecosystem() string { return versions.Maven }
func (m memRegistry) Lookup(_ context.Context, name string) (*registry.Package, error) {
	p := &registry.Package{Ecosystem: versions.Maven, Name: name, URL: "mem://" + name}
	for _, v := range m.versions {
		p.Releases = append(p.Releases, registry.Release{Version: v})
	}
	return p, nil
}
func (m memRegistry) PackageURL(n string) string    { return "mem://" + n }
func (m memRegistry) VersionURL(n, v string) string { return "mem://" + n + "/" + v }
func (m memRegistry) VersionExists(context.Context, string, string) (bool, error) {
	return false, nil
}
func (m memRegistry) PublishedAt(context.Context, string, string) (time.Time, bool) {
	return time.Time{}, false
}
func (m memRegistry) Artifact(context.Context, string, string) (*registry.Artifact, error) {
	return nil, registry.ErrNoArtifact
}

// offline replaces every network client: Maven answers from memory, and
// GitHub/osv.dev are disabled unless a base URL is given.
func offline(t *testing.T, osvBase string, reg registry.Registry) {
	t.Helper()
	testHook = func(e *check.Engine, api *osv.API) {
		e.Registries = map[string]registry.Registry{versions.Maven: reg}
		e.GitHub = nil
		e.OSV = nil
		api.Base = osvBase
		api.HTTP.Backoff = time.Millisecond
	}
	t.Cleanup(func() { testHook = nil })
}

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

const mavenAdvisory = `{"id":"GHSA-test-test-test","affected":[{"package":{"ecosystem":"Maven","name":"g:a"},
 "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"1.0"},{"fixed":"%s"}]}]}]}`

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(append([]string{"check", "--no-cache"}, args...), &out, &errb)
	return code, out.String(), errb.String()
}

func TestExitCodes(t *testing.T) {
	dir := t.TempDir()
	reg := memRegistry{versions: []string{"1.0", "1.0.1", "1.1", "2.0", "2.1"}}
	ok := write(t, dir, "ok.json", strings.Replace(mavenAdvisory, "%s", "1.1", 1))
	bad := write(t, dir, "bad.json", strings.Replace(mavenAdvisory, "%s", "1.0.5", 1))
	stale := write(t, dir, "stale.json", `{"id":"GHSA-stal-stal-stal","affected":[{"package":{"ecosystem":"Maven","name":"g:a"},
 "ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"last_affected":"1.0"}]}]},
 {"package":{"ecosystem":"Maven","name":"g:a"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"2.0"},{"fixed":"2.1"}]}]}]}`)
	malformed := write(t, dir, "malformed.json", `{"id": "GHSA-x",`)
	pypi := write(t, dir, "pypi.json", `{"id":"GHSA-pypi-pypi-pypi","affected":[{"package":{"ecosystem":"PyPI","name":"x"}}]}`)

	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
	defer osvSrv.Close()
	offline(t, osvSrv.URL, reg)

	tests := []struct {
		name   string
		args   []string
		want   int
		output string
	}{
		{"no findings", []string{"--file", ok}, 0, ""},
		{"warnings only", []string{"--file", stale}, 0, "IF003 stale-last-affected"},
		{"error finding", []string{"--file", bad}, 1, "IF002 version-missing"},
		{"malformed file", []string{"--file", malformed}, 2, "invalid JSON"},
		{"missing file", []string{"--file", filepath.Join(dir, "nope.json")}, 2, "no such file"},
		{"unknown ID", []string{"GHSA-0000-0000-0000"}, 2, "not found on osv.dev"},
		{"invalid ID", []string{"../etc/passwd"}, 2, ""},
		{"unsupported ecosystem", []string{"--file", pypi}, 0, "skipped: no package in a supported ecosystem (PyPI)"},
		{"ecosystem filter is case-insensitive", []string{"--ecosystem", "maven", "--file", bad}, 1, "IF002"},
		{"check slugs", []string{"--checks", "version-missing", "--file", bad}, 1, "IF002"},
		{"unknown check", []string{"--checks", "PKG:001", "--file", bad}, 2, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, out, errOut := runCLI(t, tt.args...)
			if code != tt.want {
				t.Errorf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, tt.want, out, errOut)
			}
			if tt.output != "" && !strings.Contains(out+errOut, tt.output) {
				t.Errorf("output lacks %q:\n%s%s", tt.output, out, errOut)
			}
		})
	}
}

func TestExitCodeDirectories(t *testing.T) {
	offline(t, "", memRegistry{versions: []string{"1.0", "1.1"}})
	junk := t.TempDir()
	write(t, junk, "a.json", `{"not":"osv"}`)
	write(t, junk, "b.json", `{broken`)
	code, _, errOut := runCLI(t, "--dir", junk)
	if code != 2 || !strings.Contains(errOut, "skipped 2 file(s)") || !strings.Contains(errOut, "no checkable OSV record") {
		t.Errorf("junk dir: exit %d, stderr %q", code, errOut)
	}
	mixed := t.TempDir()
	write(t, mixed, "a.json", `{"not":"osv"}`)
	write(t, mixed, "ok.json", strings.Replace(mavenAdvisory, "%s", "1.1", 1))
	code, _, errOut = runCLI(t, "--dir", mixed)
	if code != 0 || !strings.Contains(errOut, "skipped 1 file(s)") {
		t.Errorf("mixed dir: exit %d, stderr %q", code, errOut)
	}
}

func TestExitCodeLookupFailure(t *testing.T) {
	// A closed port: every lookup fails after retries. The run must exit 2
	// with a "could not check" result naming Maven Central's host, even
	// with --min-severity error.
	closed := httptest.NewServer(http.NotFoundHandler())
	base := closed.URL
	closed.Close()
	hc := httpx.New("test", "")
	hc.Backoff = time.Millisecond
	reg := &registry.Maven{HTTP: hc, Repos: []string{base + "/central", "http://127.0.0.1:1/mirror"}}
	offline(t, "", reg)
	dir := t.TempDir()
	f := write(t, dir, "a.json", strings.Replace(mavenAdvisory, "%s", "1.1", 1))
	code, out, _ := runCLI(t, "--min-severity", "error", "--file", f)
	host := strings.TrimPrefix(base, "http://")
	if code != 2 || !strings.Contains(out, "FAILED") || !strings.Contains(out, "could not check: package lookup on "+host+" failed") {
		t.Errorf("exit %d, output:\n%s", code, out)
	}
}
