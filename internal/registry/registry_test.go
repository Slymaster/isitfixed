package registry

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Slymaster/isitfixed/internal/httpx"
)

var ctx = context.Background()

func mkzip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func mktgz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func serveBytes(b []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "", time.Date(2021, 11, 9, 0, 0, 0, 0, time.UTC), bytes.NewReader(b))
	}
}

func newClient(t *testing.T) *httpx.Client {
	c := httpx.New("isitfixed-test", t.TempDir())
	c.Backoff = time.Millisecond
	return c
}

func TestGoProxy(t *testing.T) {
	zipBody := mkzip(t, map[string]string{
		"github.com/cilium/cilium@v1.10.20/pkg/envoy/server.go": "package envoy\n",
		"github.com/cilium/cilium@v1.10.20/go.mod":              "module github.com/cilium/cilium\n",
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/github.com/cilium/cilium/@v/list", serveBytes(readTestdata(t, "cilium-list-1.10.txt")))
	mux.HandleFunc("/github.com/cilium/cilium/@v/v1.10.20.info", serveBytes(readTestdata(t, "cilium-v1.10.20.info")))
	mux.HandleFunc("/github.com/cilium/cilium/@v/v1.10.20.zip", serveBytes(zipBody))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	g := &GoProxy{HTTP: newClient(t), Base: srv.URL}

	p, err := g.Lookup(ctx, "github.com/cilium/cilium")
	if err != nil {
		t.Fatal(err)
	}
	vs := p.Versions()
	if vs[0] != "1.10.0-rc0" || vs[len(vs)-1] != "1.10.20" || len(vs) != 24 {
		t.Errorf("versions = %v", vs)
	}
	if _, ok := p.Find("v1.10.20"); !ok {
		t.Error("v-prefixed version not found")
	}
	// Package path inside a module resolves to the module.
	p, err = g.Lookup(ctx, "github.com/cilium/cilium/pkg/envoy")
	if err != nil || !strings.Contains(p.Note, "package inside module github.com/cilium/cilium") {
		t.Errorf("package path: %v %+v", err, p)
	}
	// Case-escaped, nonexistent module.
	if _, err := g.Lookup(ctx, "github.com/cilium/ciliumCilium"); err != ErrNotFound {
		t.Errorf("misspelled module: err = %v, want ErrNotFound", err)
	}
	if EscapePath("github.com/cilium/ciliumCilium") != "github.com/cilium/cilium!cilium" {
		t.Error("EscapePath")
	}
	if tm, ok := g.PublishedAt(ctx, "github.com/cilium/cilium", "1.10.20"); !ok || tm.Year() != 2023 {
		t.Errorf("PublishedAt = %v %v", tm, ok)
	}
	a, err := g.Artifact(ctx, "github.com/cilium/cilium", "1.10.20")
	if err != nil {
		t.Fatal(err)
	}
	if b, err := a.Read("pkg/envoy/server.go"); err != nil || string(b) != "package envoy\n" {
		t.Errorf("zip entry: %q %v (files %v)", b, err, a.Files())
	}
	if a.Digest != "vcs:ad1655800fe2b50eee044e658e1c3bb80a28a97b" {
		t.Errorf("digest = %q", a.Digest)
	}
	if ok, _ := g.VersionExists(ctx, "github.com/cilium/cilium", "1.10.21"); ok {
		t.Error("1.10.21 must not exist")
	}
}

func TestNpm(t *testing.T) {
	tgz := mktgz(t, map[string]string{"package/index.js": "module.exports = leftPad;\n", "package/package.json": "{}"})
	sum := sha1.Sum(tgz)
	var srvURL string
	mux := http.NewServeMux()
	mux.HandleFunc("/left-pad", func(w http.ResponseWriter, r *http.Request) {
		doc := strings.ReplaceAll(string(readTestdata(t, "npm-left-pad.json")), "TARBALL", srvURL+"/tarballs")
		doc = strings.ReplaceAll(doc, "SHASUM-1.3.0", hex.EncodeToString(sum[:]))
		w.Write([]byte(doc))
	})
	mux.HandleFunc("/tarballs/1.3.0", serveBytes(tgz))
	mux.HandleFunc("/tarballs/1.2.0", serveBytes(tgz))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	srvURL = srv.URL
	n := &Npm{HTTP: newClient(t), Base: srv.URL}
	p, err := n.Lookup(ctx, "left-pad")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Versions(); len(got) != 2 || got[1] != "1.3.0" || p.Releases[1].Published.IsZero() {
		t.Errorf("releases = %+v", p.Releases)
	}
	if _, err := n.Lookup(ctx, "@scope/missing"); err != ErrNotFound {
		t.Errorf("missing scoped package: %v", err)
	}
	a, err := n.Artifact(ctx, "left-pad", "1.3.0")
	if err != nil {
		t.Fatal(err)
	}
	if !a.Verified || !strings.HasPrefix(a.Digest, "sha1:") {
		t.Errorf("artifact digest %q verified=%v", a.Digest, a.Verified)
	}
	if _, err := a.Read("index.js"); err != nil {
		t.Errorf("index.js: %v (files %v)", err, a.Files())
	}
	// Shasum mismatch is an error, never silently accepted.
	if _, err := n.Artifact(ctx, "left-pad", "1.2.0"); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("want sha1 mismatch error, got %v", err)
	}
}

func TestMaven(t *testing.T) {
	src := mkzip(t, map[string]string{
		"org/springframework/cloud/gateway/Foo.java": "class Foo {}",
		"META-INF/MANIFEST.MF":                       "x",
	})
	sum := sha1.Sum(src)
	base := "/maven2/org/springframework/cloud/spring-cloud-gateway"
	mux := http.NewServeMux()
	mux.HandleFunc(base+"/maven-metadata.xml", serveBytes(readTestdata(t, "spring-cloud-gateway-maven-metadata.xml")))
	mux.HandleFunc(base+"/2.2.10.RELEASE/spring-cloud-gateway-2.2.10.RELEASE.pom", serveBytes([]byte("<project/>")))
	mux.HandleFunc(base+"/2.2.10.RELEASE/spring-cloud-gateway-2.2.10.RELEASE-sources.jar", serveBytes(src))
	mux.HandleFunc(base+"/2.2.10.RELEASE/spring-cloud-gateway-2.2.10.RELEASE-sources.jar.sha1", serveBytes([]byte(hex.EncodeToString(sum[:]))))
	mux.HandleFunc("/jenkins/org/jenkins-ci/plugins/git/maven-metadata.xml", serveBytes([]byte("<metadata><versioning><versions><version>4.0.0</version></versions></versioning></metadata>")))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	m := &Maven{HTTP: newClient(t), Repos: []string{srv.URL + "/maven2", srv.URL + "/jenkins"}}

	p, err := m.Lookup(ctx, "org.springframework.cloud:spring-cloud-gateway")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.Find("2.2.0"); !ok {
		t.Error("2.2.0 must match 2.2.0.RELEASE")
	}
	if _, ok := p.Find("2.2.10.RELEASE0.5"); ok {
		t.Error("2.2.10.RELEASE0.5 must not match")
	}
	if ok, _ := m.VersionExists(ctx, "org.springframework.cloud:spring-cloud-gateway", "2.2.10.RELEASE"); !ok {
		t.Error("pom HEAD for 2.2.10.RELEASE")
	}
	if tm, ok := m.PublishedAt(ctx, "org.springframework.cloud:spring-cloud-gateway", "2.2.10.RELEASE"); !ok || tm.Year() != 2021 {
		t.Errorf("PublishedAt = %v %v", tm, ok)
	}
	a, err := m.Artifact(ctx, "org.springframework.cloud:spring-cloud-gateway", "2.2.10.RELEASE")
	if err != nil {
		t.Fatal(err)
	}
	if a.Kind != "source" || a.Digest != "sha1:"+hex.EncodeToString(sum[:]) {
		t.Errorf("artifact = %+v", a)
	}
	if fs := a.Files(); len(fs) != 1 || fs[0] != "org/springframework/cloud/gateway/Foo.java" {
		t.Errorf("files = %v (META-INF must be skipped)", fs)
	}
	// pom-only version: no inspectable artifact.
	if _, err := m.Artifact(ctx, "org.springframework.cloud:spring-cloud-gateway", "2.2.9.RELEASE"); err != ErrNoArtifact {
		t.Errorf("pom-only: %v", err)
	}
	// Second repository (Jenkins plugins are not on Maven Central).
	p, err = m.Lookup(ctx, "org.jenkins-ci.plugins:git")
	if err != nil || !strings.Contains(p.Note, "/jenkins") {
		t.Errorf("jenkins lookup: %v %+v", err, p)
	}
	if _, err := m.Lookup(ctx, "not-a-maven-name"); err == nil || err == ErrNotFound {
		t.Errorf("invalid name must be an error distinct from not-found: %v", err)
	}
}

func TestCrates(t *testing.T) {
	crate := mktgz(t, map[string]string{"hyper-1.0.0/src/lib.rs": "pub mod client;\n", "hyper-1.0.0/Cargo.toml": "[package]"})
	sum := sha256.Sum256(crate)
	var gotUA string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/crates/hyper", func(w http.ResponseWriter, r *http.Request) {
		gotUA = r.Header.Get("User-Agent")
		doc := strings.Replace(string(readTestdata(t, "crates-hyper.json")),
			"24590385be94998c5def4cf53d34edc5381144c805126f00efb954d986f9a7b2", hex.EncodeToString(sum[:]), 1)
		w.Write([]byte(doc))
	})
	mux.HandleFunc("/crates/hyper/hyper-1.0.0.crate", serveBytes(crate))
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := &Crates{HTTP: newClient(t), APIBase: srv.URL, StaticBase: srv.URL}
	p, err := c.Lookup(ctx, "hyper")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Versions(); strings.Join(got, " ") != "0.14.27 0.14.28 1.0.0" {
		t.Errorf("versions = %v", got)
	}
	if gotUA != "isitfixed-test" {
		t.Errorf("User-Agent = %q", gotUA)
	}
	a, err := c.Artifact(ctx, "hyper", "1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if !a.Verified {
		t.Error("crate checksum not verified")
	}
	if _, err := a.Read("src/lib.rs"); err != nil {
		t.Errorf("src/lib.rs: %v", err)
	}
	if _, err := c.Lookup(ctx, "no-such-crate"); err != ErrNotFound {
		t.Errorf("missing crate: %v", err)
	}
}
