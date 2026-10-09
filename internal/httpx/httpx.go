// Package httpx is the HTTP layer used by every network client in isitfixed:
// a fixed User-Agent, an on-disk cache, per-host concurrency limits, retries
// with backoff, and ranged reads for large zip archives.
package httpx

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// ErrNotFound is returned for 404/410 responses.
var ErrNotFound = errors.New("not found")

// Client performs cached, polite HTTP requests.
type Client struct {
	UserAgent string
	// CacheDir is the on-disk cache root; empty disables caching.
	CacheDir string
	// MetadataTTL is how long mutable responses (version lists, API
	// objects) are reused from cache.
	MetadataTTL time.Duration
	// PerHost limits concurrent requests per host.
	PerHost int
	// MinInterval enforces a minimum delay between requests to a host
	// (e.g. crates.io asks for at most one request per second).
	MinInterval map[string]time.Duration
	// MaxBody bounds the size of a single response body.
	MaxBody int64
	// Retries is the number of retries after the first attempt.
	Retries int
	// Backoff is the initial retry delay (doubled each retry).
	Backoff time.Duration

	HTTP *http.Client

	mu    sync.Mutex
	sems  map[string]chan struct{}
	last  map[string]time.Time
	pace  map[string]*sync.Mutex
	stats Stats
}

// Stats counts network activity.
type Stats struct {
	Requests  int
	CacheHits int
}

// New returns a client with sensible defaults.
func New(userAgent, cacheDir string) *Client {
	return &Client{
		UserAgent:   userAgent,
		CacheDir:    cacheDir,
		MetadataTTL: 24 * time.Hour,
		PerHost:     4,
		MinInterval: map[string]time.Duration{"crates.io": time.Second},
		MaxBody:     512 << 20,
		Retries:     3,
		Backoff:     time.Second,
		HTTP:        &http.Client{Timeout: 120 * time.Second},
	}
}

// Stats returns a snapshot of request counters.
func (c *Client) Stats() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stats
}

// Request describes a GET.
type Request struct {
	URL    string
	Header map[string]string
	// Immutable responses (content addressed by version or commit) are
	// cached forever; others for MetadataTTL.
	Immutable bool
	// NoCache bypasses the cache.
	NoCache bool
	// MaxBytes overrides Client.MaxBody for this request.
	MaxBytes int64
}

// ErrTooLarge is returned when a response exceeds the size limit.
var ErrTooLarge = errors.New("response too large")

type cacheMeta struct {
	URL    string      `json:"url,omitempty"`
	Status int         `json:"status"`
	Time   time.Time   `json:"time"`
	Header http.Header `json:"header,omitempty"`
}

// Response is a fully-read response.
type Response struct {
	Status int
	Body   []byte
	Header http.Header
	Cached bool
}

func (c *Client) key(u string) string {
	h := sha256.Sum256([]byte(u))
	return hex.EncodeToString(h[:])
}

func (c *Client) cachePath(k string) string {
	return filepath.Join(c.CacheDir, "http", k[:2], k)
}

func (c *Client) readCache(r Request) (*Response, bool) {
	if c.CacheDir == "" || r.NoCache {
		return nil, false
	}
	p := c.cachePath(c.key(r.URL))
	mb, err := os.ReadFile(p + ".meta")
	if err != nil {
		return nil, false
	}
	var m cacheMeta
	if json.Unmarshal(mb, &m) != nil {
		return nil, false
	}
	// Negative and mutable entries expire; immutable 200s never do.
	if !(r.Immutable && m.Status == 200) && time.Since(m.Time) > c.MetadataTTL {
		return nil, false
	}
	body, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	return &Response{Status: m.Status, Body: body, Header: m.Header, Cached: true}, true
}

func (c *Client) writeCache(r Request, resp *Response) {
	if c.CacheDir == "" || r.NoCache {
		return
	}
	p := c.cachePath(c.key(r.URL))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return
	}
	keep := http.Header{}
	for _, h := range []string{"Last-Modified", "Content-Type"} {
		if v := resp.Header.Get(h); v != "" {
			keep.Set(h, v)
		}
	}
	mb, _ := json.Marshal(cacheMeta{URL: r.URL, Status: resp.Status, Time: time.Now(), Header: keep})
	tmp := p + ".tmp" + strconv.Itoa(os.Getpid())
	if os.WriteFile(tmp, resp.Body, 0o644) == nil {
		_ = os.Rename(tmp, p)
	}
	_ = os.WriteFile(p+".meta", mb, 0o644)
}

func (c *Client) acquire(ctx context.Context, host string) (func(), error) {
	c.mu.Lock()
	if c.sems == nil {
		c.sems = map[string]chan struct{}{}
		c.last = map[string]time.Time{}
		c.pace = map[string]*sync.Mutex{}
	}
	s, ok := c.sems[host]
	if !ok {
		n := c.PerHost
		if n <= 0 {
			n = 1
		}
		s = make(chan struct{}, n)
		c.sems[host] = s
		c.pace[host] = &sync.Mutex{}
	}
	pace := c.pace[host]
	c.mu.Unlock()
	select {
	case s <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if iv := c.interval(host); iv > 0 {
		pace.Lock()
		c.mu.Lock()
		wait := time.Until(c.last[host].Add(iv))
		c.mu.Unlock()
		if wait > 0 {
			time.Sleep(wait)
		}
		c.mu.Lock()
		c.last[host] = time.Now()
		c.mu.Unlock()
		pace.Unlock()
	}
	return func() { <-s }, nil
}

func (c *Client) interval(host string) time.Duration {
	for h, d := range c.MinInterval {
		if host == h || len(host) > len(h) && host[len(host)-len(h)-1:] == "."+h {
			return d
		}
	}
	return 0
}

// Get performs a GET. 404/410 return a Response with that status and
// ErrNotFound. Other non-2xx statuses return an error.
func (c *Client) Get(ctx context.Context, r Request) (*Response, error) {
	if resp, ok := c.readCache(r); ok {
		c.mu.Lock()
		c.stats.CacheHits++
		c.mu.Unlock()
		return resp, statusErr(r.URL, resp.Status)
	}
	resp, err := c.doMax(ctx, "GET", r.URL, r.Header, r.MaxBytes)
	if err != nil {
		return nil, err
	}
	if resp.Status == 200 || resp.Status == 404 || resp.Status == 410 {
		c.writeCache(r, resp)
	}
	return resp, statusErr(r.URL, resp.Status)
}

// Head performs a HEAD request (not cached unless the result is cached as a GET).
func (c *Client) Head(ctx context.Context, r Request) (*Response, error) {
	hr := Request{URL: "HEAD " + r.URL, Immutable: r.Immutable}
	if resp, ok := c.readCache(hr); ok {
		return resp, statusErr(r.URL, resp.Status)
	}
	resp, err := c.do(ctx, "HEAD", r.URL, r.Header)
	if err != nil {
		return nil, err
	}
	if resp.Status == 200 || resp.Status == 404 || resp.Status == 410 {
		c.writeCache(hr, resp)
	}
	return resp, statusErr(r.URL, resp.Status)
}

func statusErr(u string, status int) error {
	switch {
	case status >= 200 && status < 300:
		return nil
	case status == 404 || status == 410:
		return ErrNotFound
	default:
		return fmt.Errorf("GET %s: HTTP %d", u, status)
	}
}

// StatusError is returned for unexpected HTTP statuses after retries.
type StatusError struct {
	URL    string
	Status int
}

func (e *StatusError) Error() string { return fmt.Sprintf("GET %s: HTTP %d", e.URL, e.Status) }

func (c *Client) do(ctx context.Context, method, rawURL string, hdr map[string]string) (*Response, error) {
	return c.doMax(ctx, method, rawURL, hdr, 0)
}

func (c *Client) doMax(ctx context.Context, method, rawURL string, hdr map[string]string, max int64) (*Response, error) {
	if max <= 0 {
		max = c.MaxBody
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	release, err := c.acquire(ctx, u.Host)
	if err != nil {
		return nil, err
	}
	defer release()
	delay := c.Backoff
	var lastErr error
	for attempt := 0; attempt <= c.Retries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			delay *= 2
		}
		req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", c.UserAgent)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		c.mu.Lock()
		c.stats.Requests++
		c.mu.Unlock()
		resp, err := c.HTTP.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		if resp.ContentLength > max {
			resp.Body.Close()
			return nil, fmt.Errorf("GET %s: %w (%d bytes, limit %d)", rawURL, ErrTooLarge, resp.ContentLength, max)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		if int64(len(body)) > max {
			return nil, fmt.Errorf("GET %s: %w (limit %d bytes)", rawURL, ErrTooLarge, max)
		}
		if resp.StatusCode == 429 || resp.StatusCode >= 500 ||
			(resp.StatusCode == 403 && resp.Header.Get("X-Ratelimit-Remaining") == "0") {
			lastErr = &StatusError{URL: rawURL, Status: resp.StatusCode}
			if ra, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && ra > 0 && ra < 120 {
				delay = time.Duration(ra) * time.Second
			}
			continue
		}
		return &Response{Status: resp.StatusCode, Body: body, Header: resp.Header}, nil
	}
	return nil, lastErr
}
