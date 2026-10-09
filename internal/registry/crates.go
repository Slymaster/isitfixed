package registry

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Slymaster/isitfixed/internal/httpx"
	"github.com/Slymaster/isitfixed/internal/versions"
)

// Crates reads crates.io.
type Crates struct {
	HTTP       *httpx.Client
	APIBase    string // default https://crates.io
	StaticBase string // default https://static.crates.io
}

// Ecosystem implements Registry.
func (c *Crates) Ecosystem() string { return versions.Crates }

func (c *Crates) api() string {
	if c.APIBase != "" {
		return strings.TrimRight(c.APIBase, "/")
	}
	return "https://crates.io"
}

func (c *Crates) static() string {
	if c.StaticBase != "" {
		return strings.TrimRight(c.StaticBase, "/")
	}
	return "https://static.crates.io"
}

type crateDoc struct {
	Versions []struct {
		Num       string    `json:"num"`
		CreatedAt time.Time `json:"created_at"`
		Yanked    bool      `json:"yanked"`
		Checksum  string    `json:"checksum"`
	} `json:"versions"`
}

func (c *Crates) docURL(name string) string {
	return c.api() + "/api/v1/crates/" + url.PathEscape(name)
}

func (c *Crates) doc(ctx context.Context, name string) (*crateDoc, error) {
	resp, err := c.HTTP.Get(ctx, httpx.Request{URL: c.docURL(name)})
	if err != nil {
		return nil, err
	}
	var d crateDoc
	if err := json.Unmarshal(resp.Body, &d); err != nil {
		return nil, fmt.Errorf("crates.io %s: %w", name, err)
	}
	return &d, nil
}

// Lookup implements Registry.
func (c *Crates) Lookup(ctx context.Context, name string) (*Package, error) {
	d, err := c.doc(ctx, name)
	if err != nil {
		return nil, err
	}
	p := &Package{Ecosystem: versions.Crates, Name: name, URL: c.docURL(name)}
	for _, v := range d.Versions {
		p.Releases = append(p.Releases, Release{Version: v.Num, Published: v.CreatedAt, Yanked: v.Yanked})
	}
	sortReleases(versions.Crates, p.Releases)
	return p, nil
}

// VersionURL implements Registry.
func (c *Crates) VersionURL(name, version string) string {
	return "https://crates.io/crates/" + name + "/" + version
}

// VersionExists implements Registry.
func (c *Crates) VersionExists(ctx context.Context, name, version string) (bool, error) {
	p, err := c.Lookup(ctx, name)
	if err != nil {
		return false, err
	}
	_, ok := p.Find(version)
	return ok, nil
}

// PublishedAt implements Registry.
func (c *Crates) PublishedAt(ctx context.Context, name, version string) (time.Time, bool) {
	p, err := c.Lookup(ctx, name)
	if err != nil {
		return time.Time{}, false
	}
	r, ok := p.Find(version)
	return r.Published, ok && !r.Published.IsZero()
}

// Artifact implements Registry: the .crate file, sha256-verified.
func (c *Crates) Artifact(ctx context.Context, name, version string) (*Artifact, error) {
	d, err := c.doc(ctx, name)
	if err != nil {
		return nil, err
	}
	sum := ""
	found := false
	for _, v := range d.Versions {
		if v.Num == version {
			sum, found = v.Checksum, true
		}
	}
	if !found {
		return nil, ErrNotFound
	}
	u := c.static() + "/crates/" + url.PathEscape(name) + "/" + url.PathEscape(name) + "-" + url.PathEscape(version) + ".crate"
	resp, err := c.HTTP.Get(ctx, httpx.Request{URL: u, Immutable: true, MaxBytes: MaxTarball})
	if err != nil {
		return nil, err
	}
	files, err := tgzArtifact(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", u, err)
	}
	a := &Artifact{URL: u, Kind: "source", files: files}
	if sum != "" {
		a.Digest = "sha256:" + sum
		got := sha256.Sum256(resp.Body)
		if hex.EncodeToString(got[:]) != sum {
			return nil, fmt.Errorf("%s: sha256 mismatch with crates.io metadata", u)
		}
		a.Verified = true
	}
	return a, nil
}

// PackageURL implements Registry.
func (c *Crates) PackageURL(name string) string { return c.docURL(name) }
