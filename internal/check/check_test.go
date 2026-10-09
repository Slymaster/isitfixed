package check

import (
	"context"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Slymaster/isitfixed/internal/github"
	"github.com/Slymaster/isitfixed/internal/osv"
	"github.com/Slymaster/isitfixed/internal/versions"
)

var ctx = context.Background()

func seq(prefix string, from, to int) []string {
	var out []string
	for i := from; i <= to; i++ {
		out = append(out, prefix+strconv.Itoa(i))
	}
	return out
}

func TestIntervals(t *testing.T) {
	r := rng("i=0", "f=1.17.17", "i=1.18.0", "f=1.18.11", "i=1.19.0")
	got := intervals(versions.Go, r)
	want := []interval{{Intro: "0", Fixed: "1.17.17"}, {Intro: "1.18.0", Fixed: "1.18.11"}, {Intro: "1.19.0"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("intervals = %+v, want %+v", got, want)
	}
	// Events out of order are sorted first.
	got = intervals(versions.Go, rng("f=2.0.1", "i=2.0.0"))
	if len(got) != 1 || got[0].Intro != "2.0.0" || got[0].Fixed != "2.0.1" {
		t.Fatalf("unsorted events: %+v", got)
	}
	iv := interval{Intro: "1.7.0", LastAffected: "1.10.0"}
	for v, want := range map[string]bool{"1.6.9": false, "1.7.0": true, "1.10.0": true, "1.10.1": false} {
		if iv.contains(versions.Go, v) != want {
			t.Errorf("contains(%s) != %v", v, want)
		}
	}
}

func TestPKG001(t *testing.T) {
	reg := &fakeRegistry{eco: versions.Go, pkgs: map[string][]string{"github.com/cilium/cilium": {"1.17.0", "1.18.0"}}}
	v := vuln("GHSA-test", versions.Go, "github.com/cilium/cilium", rng("i=0", "f=1.17.17"))
	v.Affected = append(v.Affected, vuln("", versions.Go, "github.com/cilium/ciliumCilium", rng("i=1.18.0", "f=1.18.11")).Affected...)
	fs := engine(reg).Run(ctx, v)
	expectOne(t, fs, PKG001, Error, "github.com/cilium/ciliumCilium does not exist", "did you mean github.com/cilium/cilium")
	if n := len(only(fs, PKG001)); n != 1 {
		t.Errorf("want only the misspelled package flagged, got %d PKG001 findings", n)
	}
}

func TestVER001(t *testing.T) {
	reg := &fakeRegistry{eco: versions.Maven, pkgs: map[string][]string{
		"org.springframework.cloud:spring-cloud-gateway": {"2.2.0.RELEASE", "2.2.9.RELEASE", "2.2.10.RELEASE", "3.0.0", "3.0.5"},
	}}
	v := vuln("GHSA-2r2v", versions.Maven, "org.springframework.cloud:spring-cloud-gateway",
		rng("i=3.0.0", "f=3.0.5"), rng("i=2.2.0", "f=2.2.10.RELEASE0.5"), rng("i=2.1.0", "la=2.1.9"))
	fs := engine(reg).Run(ctx, v)
	expectOne(t, fs, VER001, Error, "fixed version 2.2.10.RELEASE0.5 is not published", "2.2.10.RELEASE < 2.2.10.RELEASE0.5 < 3.0.0")
	expectOne(t, fs, VER001, Warning, "introduced version 2.1.0")
	expectOne(t, fs, VER001, Warning, "last_affected version 2.1.9")
	for _, f := range only(fs, VER001) {
		if strings.Contains(f.Message, "version 2.2.0 ") {
			t.Errorf("2.2.0 equals 2.2.0.RELEASE under Maven ordering, must not be flagged: %s", f.Message)
		}
	}
}

func TestRNG001(t *testing.T) {
	vs := append(append(seq("1.10.", 0, 20), "1.7.0", "1.9.0"), seq("1.11.", 0, 16)...)
	reg := &fakeRegistry{eco: versions.Go, pkgs: map[string][]string{"github.com/cilium/cilium": vs}}
	v := vuln("GHSA-pg5p", versions.Go, "github.com/cilium/cilium", rng("i=1.7.0", "la=1.10.0"), rng("i=1.11.0", "f=1.11.16"))
	fs := engine(reg).Run(ctx, v)
	f := expectOne(t, fs, RNG001, Warning, "last_affected 1.10.0", "20 later 1.10.x", "1.10.1", "1.10.20")
	want := [][]osv.Event{{{Introduced: "1.7.0"}, {LastAffected: "1.10.20"}}}
	if !reflect.DeepEqual(f.Suggested, want) {
		t.Errorf("suggested = %+v, want %+v", f.Suggested, want)
	}

	// Without a fixed newer line the signal is weak: info only.
	v = vuln("GHSA-weak", versions.Go, "github.com/cilium/cilium", rng("i=1.7.0", "la=1.10.0"))
	expectOne(t, engine(reg).Run(ctx, v), RNG001, Info, "last_affected 1.10.0")

	// last_affected at the newest version: nothing to report.
	v = vuln("GHSA-ok", versions.Go, "github.com/cilium/cilium", rng("i=1.7.0", "la=1.10.20"), rng("i=1.11.0", "f=1.11.16"))
	if fs := only(engine(reg).Run(ctx, v), RNG001); len(fs) != 0 {
		t.Errorf("unexpected: %s", dump(fs))
	}
}

func quarkusRegistry() *fakeRegistry {
	return &fakeRegistry{eco: versions.Maven, pkgs: map[string][]string{"io.quarkus:quarkus-vertx-http": {
		"3.26.0", "3.27.0.CR1", "3.27.0", "3.27.3", "3.27.3.1", "3.27.4",
		"3.28.0.CR1", "3.28.0", "3.28.5", "3.29.0", "3.29.4",
		"3.30.0.CR1", "3.30.0", "3.30.8",
		"3.34.0", "3.34.6", "3.34.7", "3.35.0", "3.35.1", "3.35.2",
	}}, published: map[string]time.Time{}}
}

func TestRNG002(t *testing.T) {
	reg := quarkusRegistry()
	v := vuln("GHSA-rc95", versions.Maven, "io.quarkus:quarkus-vertx-http",
		rng("i=3.21.0", "f=3.27.3.1"), rng("i=3.30.0", "f=3.33.1.1"), rng("i=3.34.0", "f=3.35.2"))
	fs := engine(reg).Run(ctx, v)
	f := expectOne(t, fs, RNG002, Warning, "3.28, 3.29", "3.28.0.CR1")
	if strings.Contains(f.Message, "3.27") && !strings.Contains(f.Message, "3.27.3.1") {
		t.Errorf("partially covered 3.27 must not be flagged: %s", f.Message)
	}
	want := [][]osv.Event{{{Introduced: "3.28.0.CR1"}, {LastAffected: "3.29.4"}}}
	if !reflect.DeepEqual(f.Suggested, want) {
		t.Errorf("suggested = %+v", f.Suggested)
	}

	// A line first published after the preceding fix plausibly inherited it.
	day := func(d int) time.Time { return time.Date(2026, 1, d, 0, 0, 0, 0, time.UTC) }
	reg.published["3.27.3.1"] = day(1)
	reg.published["3.28.0.CR1"] = day(2)
	reg.published["3.29.0"] = day(3)
	if fs := only(engine(reg).Run(ctx, v), RNG002); len(fs) != 0 {
		t.Errorf("lines published after the fix must not be flagged:\n%s", dump(fs))
	}
}

// Fix fixtures: a two-line Go fix in pkg/a.go.
const (
	vulnGo  = "package a\n\nfunc Check(p string) bool {\n\treturn true\n}\n"
	fixedGo = "package a\n\nfunc Check(p string) bool {\n\tif strings.Contains(p, \";\") {\n\t\treturn rejectMatrixParameters(p)\n\t}\n\treturn true\n}\n"
	fixSHA  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

func fixGitHub() *fakeGitHub {
	return &fakeGitHub{
		commits: map[string]*github.Commit{fixSHA: {Repo: "o/r", SHA: fixSHA, Parent: "parent", URL: "https://github.com/o/r/commit/" + fixSHA,
			Files: []github.File{{Path: "pkg/a.go", Status: "modified",
				Patch: "@@ -1,5 +1,8 @@\n func Check(p string) bool {\n+\tif strings.Contains(p, \";\") {\n+\t\treturn rejectMatrixParameters(p)\n+\t}\n \treturn true\n }"}}}},
		raw: map[string]string{"parent:pkg/a.go": vulnGo, fixSHA + ":pkg/a.go": fixedGo},
	}
}

// goFixRegistry publishes vs; versions in fixed contain the fix.
func goFixRegistry(vs []string, fixed ...string) *fakeRegistry {
	reg := &fakeRegistry{eco: versions.Go, pkgs: map[string][]string{"example.com/m": vs}, files: map[string]map[string]string{}}
	isFixed := map[string]bool{}
	for _, f := range fixed {
		isFixed[f] = true
	}
	for _, v := range vs {
		body := vulnGo
		if isFixed[v] {
			body = fixedGo
		}
		reg.files[v] = map[string]string{"pkg/a.go": body, "go.mod": "module example.com/m\n"}
	}
	return reg
}

func fixVuln(ranges ...osv.Range) *osv.Vuln {
	v := vuln("GHSA-fix", versions.Go, "example.com/m", ranges...)
	v.References = []osv.Reference{{Type: "FIX", URL: "https://github.com/o/r/commit/" + fixSHA}}
	return v
}

func TestFIX001Verified(t *testing.T) {
	reg := goFixRegistry([]string{"1.0.0", "1.0.1", "1.0.2"}, "1.0.2")
	e := engine(reg)
	e.GitHub = fixGitHub()
	fs := e.Run(ctx, fixVuln(rng("i=0", "f=1.0.2")))
	expectOne(t, fs, FIX001, Info, "1.0.2: contains (2/2", "1.0.1: lacks (0/2")
	for _, f := range fs {
		if f.Severity != Info {
			t.Errorf("unexpected finding: %s", dump([]Finding{f}))
		}
	}
}

func TestFIX001FixedLacksFix(t *testing.T) {
	reg := goFixRegistry([]string{"1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4"}, "1.0.3", "1.0.4")
	e := engine(reg)
	e.GitHub = fixGitHub()
	fs := e.Run(ctx, fixVuln(rng("i=0", "f=1.0.2")))
	f := expectOne(t, fs, FIX001, Error, "fixed version 1.0.2 does not contain the fix", "earliest version of the line containing the fix: 1.0.3")
	want := [][]osv.Event{{{Introduced: "0"}, {Fixed: "1.0.3"}}}
	if !reflect.DeepEqual(f.Suggested, want) {
		t.Errorf("suggested = %+v", f.Suggested)
	}
}

func TestFIX001RangeIncludesFixedVersions(t *testing.T) {
	vs := seq("1.0.", 0, 9)
	reg := goFixRegistry(vs, seq("1.0.", 4, 9)...)
	e := engine(reg)
	e.GitHub = fixGitHub()
	fs := e.Run(ctx, fixVuln(rng("i=1.0.0", "f=1.0.9")))
	f := expectOne(t, fs, FIX001, Warning, "range [1.0.0, 1.0.9) includes versions that already contain the fix", "the fix first appears in 1.0.4")
	want := [][]osv.Event{{{Introduced: "1.0.0"}, {Fixed: "1.0.4"}}}
	if !reflect.DeepEqual(f.Suggested, want) {
		t.Errorf("suggested = %+v", f.Suggested)
	}
	if reg.downloads > 8 {
		t.Errorf("bisection should bound downloads, got %d", reg.downloads)
	}
}

func TestFIX001BackportAcrossLinesWithUnpublishedFixed(t *testing.T) {
	// Quarkus-like: [3.34.0, 3.35.1.1) where 3.35.1.1 does not exist, the
	// fix was backported to 3.34.7 and released in 3.35.2.
	vs := []string{"3.34.0", "3.34.5", "3.34.6", "3.34.7", "3.35.0", "3.35.1", "3.35.2", "3.35.3"}
	reg := goFixRegistry(vs, "3.34.7", "3.35.2", "3.35.3")
	reg.eco = versions.Maven
	reg.pkgs = map[string][]string{"io.q:http": vs}
	for v, files := range reg.files {
		reg.files[v] = map[string]string{"io/q/a/A.java": strings.ReplaceAll(files["pkg/a.go"], "package a", "package io.q.a;")}
	}
	gh := fixGitHub()
	c := gh.commits[fixSHA]
	c.Files[0].Path = "ext/http/runtime/src/main/java/io/q/a/A.java"
	gh.raw = map[string]string{"parent:" + c.Files[0].Path: vulnGo, fixSHA + ":" + c.Files[0].Path: fixedGo}
	e := engine(reg)
	e.GitHub = gh
	v := vuln("GHSA-rc95", versions.Maven, "io.q:http", rng("i=3.34.0", "f=3.35.1.1"))
	v.References = []osv.Reference{{Type: "WEB", URL: "https://github.com/o/r/commit/" + fixSHA}}
	fs := e.Run(ctx, v)
	expectOne(t, fs, VER001, Error, "fixed version 3.35.1.1 is not published")
	f := expectOne(t, fs, FIX001, Warning, "includes versions that already contain the fix", "3.34.x: the fix first appears in 3.34.7", "earliest later 3.35.x version containing the fix is 3.35.2")
	want := [][]osv.Event{{{Introduced: "3.34.0"}, {Fixed: "3.34.7"}}, {{Introduced: "3.35.0"}, {Fixed: "3.35.2"}}}
	if !reflect.DeepEqual(f.Suggested, want) {
		t.Errorf("suggested = %+v, want %+v", f.Suggested, want)
	}
}

func TestFIX001Unverifiable(t *testing.T) {
	reg := goFixRegistry([]string{"1.0.0", "1.0.1"}, "1.0.1")
	e := engine(reg)
	e.GitHub = fixGitHub()
	// No references.
	v := vuln("GHSA-norefs", versions.Go, "example.com/m", rng("i=0", "f=1.0.1"))
	expectOne(t, e.Run(ctx, v), FIX001, Info, "unverifiable: no GitHub fix commit")
	// The fix touches a file the artifacts do not ship.
	for _, files := range reg.files {
		files["pkg/b.go"] = files["pkg/a.go"]
		delete(files, "pkg/a.go")
	}
	fs := e.Run(ctx, fixVuln(rng("i=0", "f=1.0.1")))
	expectOne(t, fs, FIX001, Info, "unverifiable: the fix's distinctive lines were not found")
	for _, f := range fs {
		if f.Severity != Info {
			t.Errorf("unverifiable fixes must not produce errors or warnings: %s", dump([]Finding{f}))
		}
	}
}

func TestRNG002ConfirmedByContent(t *testing.T) {
	// The 1.18 line is uncovered (its range was attached to a misspelled
	// package); content shows 1.18.0-1.18.10 lack the fix.
	vs := append(append(seq("1.17.", 15, 17), seq("1.18.", 0, 12)...), seq("1.19.", 0, 5)...)
	reg := goFixRegistry(vs, append(append([]string{"1.17.17"}, seq("1.18.", 11, 12)...), "1.19.5")...)
	e := engine(reg)
	e.GitHub = fixGitHub()
	fs := e.Run(ctx, fixVuln(rng("i=0", "f=1.17.17"), rng("i=1.19.0", "f=1.19.5")))
	f := expectOne(t, fs, RNG002, Warning, "release line(s) 1.18", "the fix first appears in 1.18.11")
	want := [][]osv.Event{{{Introduced: "1.18.0"}, {Fixed: "1.18.11"}}}
	if !reflect.DeepEqual(f.Suggested, want) {
		t.Errorf("suggested = %+v", f.Suggested)
	}
}

func TestRNG001ContentDowngrade(t *testing.T) {
	// last_affected 1.0.1 and 1.0.2 contains the fix: consistent, info only.
	reg := goFixRegistry([]string{"1.0.0", "1.0.1", "1.0.2", "1.0.3", "2.0.0", "2.0.1"}, "1.0.2", "1.0.3", "2.0.1")
	e := engine(reg)
	e.GitHub = fixGitHub()
	fs := e.Run(ctx, fixVuln(rng("i=1.0.0", "la=1.0.1"), rng("i=2.0.0", "f=2.0.1")))
	expectOne(t, fs, RNG001, Info, "contain the fix")
}

func TestXDB001(t *testing.T) {
	reg := &fakeRegistry{eco: versions.Go, pkgs: map[string][]string{"github.com/cilium/cilium": append(append(seq("1.17.", 15, 17), seq("1.18.", 0, 11)...), seq("1.19.", 0, 5)...)}}
	ghsa := vuln("GHSA-w7c2", versions.Go, "github.com/cilium/cilium", rng("i=0", "f=1.17.17"), rng("i=1.19.0", "f=1.19.5"))
	ghsa.Affected = append(ghsa.Affected, vuln("", versions.Go, "github.com/cilium/ciliumCilium", rng("i=1.18.0", "f=1.18.11")).Affected...)
	ghsa.Aliases = []string{"CVE-2026-1"}
	goRec := vuln("GO-2026-1", versions.Go, "github.com/cilium/cilium", rng("i=0", "f=1.17.17", "i=1.18.0", "f=1.18.11", "i=1.19.0", "f=1.19.5"))
	e := engine(reg)
	e.OSV = fakeOSV{
		"GHSA-w7c2":  {ID: "GHSA-w7c2", Aliases: []string{"CVE-2026-1", "GO-2026-1"}},
		"CVE-2026-1": {ID: "CVE-2026-1", Aliases: []string{"GHSA-w7c2", "GO-2026-1"}},
		"GO-2026-1":  goRec,
	}
	fs := e.Run(ctx, ghsa)
	expectOne(t, fs, XDB001, Warning, "GO-2026-1 and this advisory disagree", "affected only according to GO-2026-1 (11): 1.18.0 … 1.18.10")
	expectOne(t, fs, XDB001, Warning, "GO-2026-1 does not list github.com/cilium/ciliumCilium but lists the similarly named github.com/cilium/cilium")

	// Agreement: no XDB001.
	ghsa = vuln("GHSA-w7c2", versions.Go, "github.com/cilium/cilium", rng("i=0", "f=1.17.17"), rng("i=1.18.0", "f=1.18.11"), rng("i=1.19.0", "f=1.19.5"))
	if fs := only(e.Run(ctx, ghsa), XDB001); len(fs) != 0 {
		t.Errorf("unexpected:\n%s", dump(fs))
	}
}

func TestSkipsMalwareAndWithdrawn(t *testing.T) {
	reg := &fakeRegistry{eco: versions.Npm, pkgs: map[string][]string{}}
	v := vuln("GHSA-mal", versions.Npm, "evil-pkg", rng("i=0"))
	v.Summary = "Malware in evil-pkg"
	if fs := engine(reg).Run(ctx, v); len(fs) != 0 {
		t.Errorf("malware advisory: %s", dump(fs))
	}
	v = vuln("GHSA-wd", versions.Npm, "gone", rng("i=0", "f=1.0.0"))
	v.Withdrawn = "2024-01-01T00:00:00Z"
	if fs := engine(reg).Run(ctx, v); len(fs) != 0 {
		t.Errorf("withdrawn advisory: %s", dump(fs))
	}
}
