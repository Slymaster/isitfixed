package httpx

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

var ctx = context.Background()

func TestGetCacheRetryAndNotFound(t *testing.T) {
	var hits, fails atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("User-Agent") != "ua-test" {
			t.Errorf("User-Agent = %q", r.Header.Get("User-Agent"))
		}
		switch r.URL.Path {
		case "/flaky":
			if fails.Add(1) < 3 {
				w.WriteHeader(503)
				return
			}
			w.Write([]byte("ok"))
		case "/missing":
			w.WriteHeader(404)
		default:
			w.Write([]byte("body"))
		}
	}))
	defer srv.Close()
	c := New("ua-test", t.TempDir())
	c.Backoff = time.Millisecond

	r, err := c.Get(ctx, Request{URL: srv.URL + "/flaky"})
	if err != nil || string(r.Body) != "ok" {
		t.Fatalf("flaky: %v %v", r, err)
	}
	if _, err := c.Get(ctx, Request{URL: srv.URL + "/missing"}); err != ErrNotFound {
		t.Fatalf("missing: %v", err)
	}
	before := hits.Load()
	c.Get(ctx, Request{URL: srv.URL + "/flaky"})
	if _, err := c.Get(ctx, Request{URL: srv.URL + "/missing"}); err != ErrNotFound {
		t.Fatalf("cached 404: %v", err)
	}
	if hits.Load() != before {
		t.Errorf("expected cache hits, server saw %d more requests", hits.Load()-before)
	}
	// Mutable entries expire.
	c.MetadataTTL = -time.Second
	c.Get(ctx, Request{URL: srv.URL + "/flaky"})
	if hits.Load() == before {
		t.Error("expired entry was not refetched")
	}
	// Immutable entries do not.
	c.MetadataTTL = time.Hour
	c.Get(ctx, Request{URL: srv.URL + "/imm", Immutable: true})
	c.MetadataTTL = -time.Second
	n := hits.Load()
	c.Get(ctx, Request{URL: srv.URL + "/imm", Immutable: true})
	if hits.Load() != n {
		t.Error("immutable entry was refetched")
	}
}

func TestGetGivesUpAfterRetries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	c := New("ua", "")
	c.Backoff = time.Millisecond
	if _, err := c.Get(ctx, Request{URL: srv.URL}); err == nil || err == ErrNotFound {
		t.Fatalf("want error, got %v", err)
	}
}

func TestRanged(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789"), BlockSize/4) // 2.5 blocks
	var requests atomic.Int32
	ranged := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(data))
	}))
	defer ranged.Close()
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write(data) }))
	defer plain.Close()

	for name, u := range map[string]string{"range": ranged.URL, "no-range": plain.URL} {
		t.Run(name, func(t *testing.T) {
			c := New("ua", t.TempDir())
			f, err := c.OpenRanged(ctx, u+"/f.zip")
			if err != nil {
				t.Fatal(err)
			}
			if f.Size() != int64(len(data)) {
				t.Fatalf("size = %d", f.Size())
			}
			got, err := io.ReadAll(io.NewSectionReader(f, 0, f.Size()))
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("content mismatch (%d bytes, err %v)", len(got), err)
			}
			// Unaligned read across a block boundary.
			buf := make([]byte, 20)
			if _, err := f.ReadAt(buf, BlockSize-10); err != nil || string(buf) != string(data[BlockSize-10:BlockSize+10]) {
				t.Fatalf("cross-block read: %q %v", buf, err)
			}
		})
	}
	// Reopening uses cached size and blocks.
	c := New("ua", t.TempDir())
	f, _ := c.OpenRanged(ctx, ranged.URL+"/g.zip")
	io.ReadAll(io.NewSectionReader(f, 0, f.Size()))
	n := requests.Load()
	f2, err := c.OpenRanged(ctx, ranged.URL+"/g.zip")
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(io.NewSectionReader(f2, 0, f2.Size()))
	if requests.Load() != n {
		t.Errorf("cached ranged file refetched %d times", requests.Load()-n)
	}
}
