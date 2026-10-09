package github

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Slymaster/isitfixed/internal/httpx"
)

func TestParseRef(t *testing.T) {
	tests := []struct {
		url  string
		ok   bool
		sha  string
		pr   int
		repo string
	}{
		{"https://github.com/cilium/cilium/commit/7422068aff67ac77c7dcc57aa5b9240c91333deb", true, "7422068aff67ac77c7dcc57aa5b9240c91333deb", 0, "cilium/cilium"},
		{"https://github.com/cilium/cilium/commit/f490339", true, "f490339", 0, "cilium/cilium"},
		{"https://github.com/o/r/commit/ABCDEF1234567.patch", true, "abcdef1234567", 0, "o/r"},
		{"https://github.com/o/r/commits/abcdef1", true, "abcdef1", 0, "o/r"},
		{"https://github.com/o/r/pull/42", true, "", 42, "o/r"},
		{"https://github.com/o/r/pull/42/files", true, "", 42, "o/r"},
		{"https://github.com/o/r/pull/42/commits/abcdef12", true, "abcdef12", 0, "o/r"},
		{"https://github.com/o/r/releases/tag/v1.0.0", false, "", 0, ""},
		{"https://github.com/o/r/security/advisories/GHSA-xxxx-xxxx-xxxx", false, "", 0, ""},
		{"https://gitlab.com/o/r/-/commit/abcdef1", false, "", 0, ""},
	}
	for _, tt := range tests {
		r, ok := ParseRef(tt.url)
		if ok != tt.ok || r.SHA != tt.sha || r.PR != tt.pr || (ok && r.RepoSlug() != tt.repo) {
			t.Errorf("ParseRef(%q) = %+v, %v", tt.url, r, ok)
		}
	}
}

func TestResolve(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/o/r/commits/c0ffee", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("missing token")
		}
		w.Write([]byte(`{"sha":"c0ffee","html_url":"https://github.com/o/r/commit/c0ffee","commit":{"message":"fix"},"parents":[{"sha":"base1"}],"files":[{"filename":"a.go","status":"modified","patch":"+x"}]}`))
	})
	mux.HandleFunc("/repos/o/r/pulls/7", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"merged":true,"merge_commit_sha":"c0ffee","base":{"sha":"base0"},"html_url":"https://github.com/o/r/pull/7"}`))
	})
	mux.HandleFunc("/repos/o/r/pulls/7/files", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"filename":"a.go","status":"modified","patch":"+x"},{"filename":"b.go","status":"added","patch":"+y"}]`))
	})
	mux.HandleFunc("/repos/o/r/pulls/8", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"merged":false}`))
	})
	mux.HandleFunc("/o/r/base1/dir/a%20b.go", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("old")) })
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := &Client{HTTP: httpx.New("ua", ""), Token: "tok", APIBase: srv.URL, RawBase: srv.URL}
	ctx := context.Background()

	cm, err := c.Resolve(ctx, Ref{Owner: "o", Repo: "r", SHA: "c0ffee"})
	if err != nil || cm.Parent != "base1" || len(cm.Files) != 1 || cm.Repo != "o/r" {
		t.Fatalf("commit: %+v %v", cm, err)
	}
	cm, err = c.Resolve(ctx, Ref{Owner: "o", Repo: "r", PR: 7})
	if err != nil || cm.SHA != "c0ffee" || cm.Parent != "base0" || len(cm.Files) != 2 {
		t.Fatalf("PR: %+v %v", cm, err)
	}
	if _, err := c.Resolve(ctx, Ref{Owner: "o", Repo: "r", PR: 8}); err != ErrUnmerged {
		t.Fatalf("unmerged PR: %v", err)
	}
	if b, err := c.RawFile(ctx, "o/r", "base1", "dir/a b.go"); err != nil || string(b) != "old" {
		t.Fatalf("raw: %q %v", b, err)
	}
	if _, err := c.RawFile(ctx, "o/r", "base1", "missing.go"); err != httpx.ErrNotFound {
		t.Fatalf("raw missing: %v", err)
	}
}
