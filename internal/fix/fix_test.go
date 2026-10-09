package fix

import (
	"context"
	"strings"
	"testing"

	"github.com/Slymaster/isitfixed/internal/github"
	"github.com/Slymaster/isitfixed/internal/httpx"
	"github.com/Slymaster/isitfixed/internal/registry"
)

// fakeFetcher serves file contents keyed by "sha:path".
type fakeFetcher map[string]string

func (f fakeFetcher) Resolve(context.Context, github.Ref) (*github.Commit, error) { return nil, nil }

func (f fakeFetcher) RawFile(_ context.Context, _, sha, path string) ([]byte, error) {
	if s, ok := f[sha+":"+path]; ok {
		return []byte(s), nil
	}
	return nil, httpx.ErrNotFound
}

func TestSkippable(t *testing.T) {
	tests := map[string]bool{
		"pkg/envoy/server.go":                       false,
		"pkg/envoy/server_test.go":                  true,
		"src/main/java/io/x/Foo.java":               false,
		"src/test/java/io/x/FooTest.java":           true,
		"extensions/a/runtime/src/main/java/A.java": false,
		"lib/index.js":                              false,
		"lib/index.test.js":                         true,
		"__tests__/a.js":                            true,
		"docs/guide.md":                             true,
		"README.md":                                 true,
		"go.sum":                                    true,
		"package-lock.json":                         true,
		"Cargo.lock":                                true,
		"api/v1/types.pb.go":                        true,
		"pkg/zz_generated.deepcopy.go":              true,
		"dist/app.min.js":                           true,
		"src/lib.rs":                                false,
		"testdata/fixture.go":                       true,
	}
	for p, want := range tests {
		if got := Skippable(p); got != want {
			t.Errorf("Skippable(%q) = %v, want %v", p, got, want)
		}
	}
}

const parentGo = `package envoy

import "log"

func headers(name, value string) {
	if value != "" {
		log.Debugf("HeaderMatches: Adding %s: %s", name, value)
	}
	appendHeader(name, value)
}
`

const postGo = `package envoy

import (
	"log"
	"strings"
)

func headers(name, value string) {
	if value != "" {
		log.Debugf("HeaderMatches: Adding %s", name)
	}
	sanitized := strings.ReplaceAll(value, "\n", "")
	appendHeader(name, sanitized)
}
`

func testCommit() (*github.Commit, fakeFetcher) {
	c := &github.Commit{Repo: "o/r", SHA: "post", Parent: "pre", URL: "https://github.com/o/r/commit/post", Files: []github.File{
		{Path: "pkg/envoy/server.go", Status: "modified", Patch: `@@ -1,9 +1,13 @@
 package envoy

-import "log"
+import (
+	"log"
+	"strings"
+)

 func headers(name, value string) {
 	if value != "" {
-		log.Debugf("HeaderMatches: Adding %s: %s", name, value)
+		log.Debugf("HeaderMatches: Adding %s", name)
 	}
-	appendHeader(name, value)
+	sanitized := strings.ReplaceAll(value, "\n", "")
+	appendHeader(name, sanitized)
+	// make sure we never log values
 }`},
		{Path: "pkg/envoy/server_test.go", Status: "modified", Patch: "+\tassertNoValueLoggedAnywhere(t, logs)\n"},
		{Path: "pkg/envoy/moved.go", Status: "modified", Patch: "-\treturn computeSomethingLong(x)\n"},
		{Path: "pkg/envoy/other.go", Status: "modified", Patch: "+\treturn computeSomethingLong(x)\n"},
	}}
	f := fakeFetcher{
		"pre:pkg/envoy/server.go":  parentGo,
		"post:pkg/envoy/server.go": postGo,
		"pre:pkg/envoy/moved.go":   "x",
		"pre:pkg/envoy/other.go":   "x",
	}
	return c, f
}

func TestExtract(t *testing.T) {
	c, f := testCommit()
	s, _ := Extract(context.Background(), f, c)
	var added, removed []string
	for _, u := range s.Units {
		if u.Removed {
			removed = append(removed, u.Line)
		} else {
			added = append(added, u.Line)
		}
	}
	wantAdded := map[string]bool{
		`sanitized := strings.ReplaceAll(value, "\n", "")`: true,
		`log.Debugf("HeaderMatches: Adding %s", name)`:     true,
		`appendHeader(name, sanitized)`:                    true,
	}
	if len(added) != len(wantAdded) {
		t.Fatalf("added units = %q, want %d lines", added, len(wantAdded))
	}
	for _, a := range added {
		if !wantAdded[a] {
			t.Errorf("unexpected added unit %q (imports, comments, tests and moved lines must be skipped)", a)
		}
	}
	// Removed lines count only when they no longer occur after the fix.
	wantRemoved := map[string]bool{
		`log.Debugf("HeaderMatches: Adding %s: %s", name, value)`: true,
		`appendHeader(name, value)`:                               true,
	}
	for _, r := range removed {
		if !wantRemoved[r] {
			t.Errorf("unexpected removed unit %q", r)
		}
	}
	if len(removed) != len(wantRemoved) {
		t.Errorf("removed units = %q", removed)
	}
}

func goArtifact(body string) *registry.Artifact {
	return registry.NewMemArtifact("mem://zip", "source", map[string]string{
		"pkg/envoy/server.go": body,
		"go.mod":              "module example.com/m\n",
	})
}

func TestMatchStatuses(t *testing.T) {
	c, f := testCommit()
	s, _ := Extract(context.Background(), f, c)
	sets := []*Set{s}

	if r := Match(sets, goArtifact(postGo), map[string]bool{}); r.Status != Contains || r.Present != r.Applicable {
		t.Errorf("post-fix artifact: %+v, want contains with all lines", r)
	}
	if r := Match(sets, goArtifact(parentGo), map[string]bool{}); r.Status != Lacks || r.Present != 0 {
		t.Errorf("pre-fix artifact: %+v, want lacks", r)
	}
	// Re-indented and re-wrapped code still matches.
	reformatted := strings.ReplaceAll(postGo, "\t", "    ")
	reformatted = strings.Replace(reformatted, `strings.ReplaceAll(value, "\n", "")`, "strings.ReplaceAll(\n        value, \"\\n\", \"\")", 1)
	if r := Match(sets, goArtifact(reformatted), map[string]bool{}); r.Status != Contains {
		t.Errorf("reformatted artifact: %+v, want contains", r)
	}
	// Half-applied fix is inconclusive.
	half := strings.Replace(parentGo, `log.Debugf("HeaderMatches: Adding %s: %s", name, value)`, `log.Debugf("HeaderMatches: Adding %s", name)`, 1)
	if r := Match(sets, goArtifact(half), map[string]bool{}); r.Status != Partial {
		t.Errorf("half-fixed artifact: %+v, want partial", r)
	}
	// An artifact without the file is inapplicable, not "lacks".
	other := registry.NewMemArtifact("mem://zip", "source", map[string]string{"main.go": "package main"})
	if r := Match(sets, other, map[string]bool{}); r.Status != Inapplicable {
		t.Errorf("unrelated artifact: %+v, want inapplicable", r)
	}
}

func TestMatchPathMapping(t *testing.T) {
	// Maven sources jar paths are package paths; repo paths carry the module
	// directory and src/main/java prefix.
	c := &github.Commit{Repo: "o/r", SHA: "post", Parent: "pre", Files: []github.File{{
		Path: "extensions/vertx-http/runtime/src/main/java/io/q/HttpSecurityUtils.java", Status: "modified",
		Patch: "+    public static String pathWithoutMatrixParams(String path) {\n+        return stripMatrixParameters(path, ';');\n",
	}}}
	f := fakeFetcher{"pre:extensions/vertx-http/runtime/src/main/java/io/q/HttpSecurityUtils.java": "class HttpSecurityUtils {}"}
	s, _ := Extract(context.Background(), f, c)
	if len(s.Units) != 2 {
		t.Fatalf("units = %+v", s.Units)
	}
	fixed := registry.NewMemArtifact("mem://sources.jar", "source", map[string]string{
		"io/q/HttpSecurityUtils.java": "class HttpSecurityUtils {\n public static String pathWithoutMatrixParams(String path) {\n return stripMatrixParameters(path, ';');\n }\n}",
	})
	if r := Match([]*Set{s}, fixed, nil); r.Status != Contains {
		t.Errorf("sources jar: %+v, want contains", r)
	}
	// Compiled classes: identifiers survive in the constant pool.
	cls := registry.NewMemArtifact("mem://main.jar", "class", map[string]string{
		"io/q/HttpSecurityUtils.class":        "\xca\xfe\xba\xbe...pathWithoutMatrixParams...stripMatrixParameters...",
		"io/q/HttpSecurityUtils$1.class":      "\xca\xfe\xba\xbe",
		"io/q/other/HttpSecurityUtilsX.class": "pathWithoutMatrixParams",
	})
	r := Match([]*Set{s}, cls, nil)
	if r.Status != Contains || !r.LowConf {
		t.Errorf("class jar: %+v, want low-confidence contains", r)
	}
	old := registry.NewMemArtifact("mem://main.jar", "class", map[string]string{"io/q/HttpSecurityUtils.class": "\xca\xfe\xba\xbe...isSecure..."})
	if r := Match([]*Set{s}, old, nil); r.Status != Lacks {
		t.Errorf("old class jar: %+v, want lacks", r)
	}
}

func TestMatchMonorepoPrefix(t *testing.T) {
	// Two files named index.js in different packages: only the majority
	// prefix maps into the artifact.
	files := []string{"packages/a/lib/index.js", "packages/a/lib/util.js", "packages/b/index.js"}
	art := registry.NewMemArtifact("mem://a.tgz", "source", map[string]string{"lib/index.js": "", "lib/util.js": "", "index.js": ""})
	m := mapFiles(files, art)
	if m["packages/a/lib/index.js"] != "lib/index.js" || m["packages/a/lib/util.js"] != "lib/util.js" {
		t.Errorf("mapping = %v", m)
	}
	if _, ok := m["packages/b/index.js"]; ok {
		t.Errorf("packages/b/index.js must not map into package a: %v", m)
	}
}

func TestAddedFileAbsentInOldVersion(t *testing.T) {
	c := &github.Commit{Repo: "o/r", SHA: "post", Parent: "pre", Files: []github.File{{
		Path: "src/sanitize.rs", Status: "added",
		Patch: "+pub fn sanitize_header_value(v: &str) -> String {\n+    v.replace(['\\r', '\\n'], \"\")\n+}\n",
	}}}
	s, _ := Extract(context.Background(), fakeFetcher{}, c)
	seen := map[string]bool{}
	fixed := registry.NewMemArtifact("mem://new.crate", "source", map[string]string{"src/sanitize.rs": "pub fn sanitize_header_value(v: &str) -> String {\n v.replace(['\\r', '\\n'], \"\")\n}"})
	if r := Match([]*Set{s}, fixed, seen); r.Status != Contains {
		t.Fatalf("new version: %+v", r)
	}
	old := registry.NewMemArtifact("mem://old.crate", "source", map[string]string{"src/lib.rs": "fn main() {}"})
	if r := Match([]*Set{s}, old, seen); r.Status != Lacks {
		t.Errorf("old version without the added file: %+v, want lacks", r)
	}
	if r := Match([]*Set{s}, old, map[string]bool{}); r.Status != Inapplicable {
		t.Errorf("added file never seen in any artifact: %+v, want inapplicable", r)
	}
}
