package registry

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Slymaster/isitfixed/internal/httpx"
	"github.com/Slymaster/isitfixed/internal/versions"
)

// Npm reads registry.npmjs.org.
type Npm struct {
	HTTP *httpx.Client
	Base string
}

// Ecosystem implements Registry.
func (n *Npm) Ecosystem() string { return versions.Npm }

func (n *Npm) base() string {
	if n.Base != "" {
		return strings.TrimRight(n.Base, "/")
	}
	return "https://registry.npmjs.org"
}

func (n *Npm) docURL(name string) string {
	return n.base() + "/" + strings.Replace(url.PathEscape(name), "%40", "@", 1)
}

type npmDoc struct {
	Versions map[string]struct {
		Dist struct {
			Tarball   string `json:"tarball"`
			Shasum    string `json:"shasum"`
			Integrity string `json:"integrity"`
		} `json:"dist"`
	} `json:"versions"`
	Time map[string]json.RawMessage `json:"time"`
}

func (n *Npm) doc(ctx context.Context, name string) (*npmDoc, error) {
	resp, err := n.HTTP.Get(ctx, httpx.Request{URL: n.docURL(name), Header: map[string]string{"Accept": "application/json"}})
	if err != nil {
		return nil, err
	}
	var d npmDoc
	if err := json.Unmarshal(resp.Body, &d); err != nil {
		return nil, fmt.Errorf("npm %s: %w", name, err)
	}
	return &d, nil
}

func (d *npmDoc) published(v string) time.Time {
	var s string
	if raw, ok := d.Time[v]; ok && json.Unmarshal(raw, &s) == nil {
		t, _ := time.Parse(time.RFC3339, s)
		return t
	}
	return time.Time{}
}

// Lookup implements Registry.
func (n *Npm) Lookup(ctx context.Context, name string) (*Package, error) {
	d, err := n.doc(ctx, name)
	if err != nil {
		return nil, err
	}
	p := &Package{Ecosystem: versions.Npm, Name: name, URL: n.docURL(name)}
	for v := range d.Versions {
		p.Releases = append(p.Releases, Release{Version: v, Published: d.published(v)})
	}
	if _, ok := d.Time["unpublished"]; ok && len(d.Versions) == 0 {
		p.Unpublished = true
		p.Note = "all versions were unpublished from npm"
	}
	sortReleases(versions.Npm, p.Releases)
	return p, nil
}

// VersionURL implements Registry.
func (n *Npm) VersionURL(name, version string) string { return n.docURL(name) + "/" + version }

// VersionExists implements Registry. The npm document is authoritative.
func (n *Npm) VersionExists(ctx context.Context, name, version string) (bool, error) {
	p, err := n.Lookup(ctx, name)
	if err != nil {
		return false, err
	}
	_, ok := p.Find(version)
	return ok, nil
}

// PublishedAt implements Registry.
func (n *Npm) PublishedAt(ctx context.Context, name, version string) (time.Time, bool) {
	d, err := n.doc(ctx, name)
	if err != nil {
		return time.Time{}, false
	}
	t := d.published(version)
	return t, !t.IsZero()
}

// Artifact implements Registry: the package tarball, sha1-verified.
func (n *Npm) Artifact(ctx context.Context, name, version string) (*Artifact, error) {
	d, err := n.doc(ctx, name)
	if err != nil {
		return nil, err
	}
	vi, ok := d.Versions[version]
	if !ok {
		return nil, ErrNotFound
	}
	u := vi.Dist.Tarball
	if u == "" {
		return nil, ErrNoArtifact
	}
	resp, err := n.HTTP.Get(ctx, httpx.Request{URL: u, Immutable: true, MaxBytes: MaxTarball})
	if err != nil {
		return nil, err
	}
	files, err := tgzArtifact(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", u, err)
	}
	a := &Artifact{URL: u, Kind: "source", files: files}
	if vi.Dist.Shasum != "" {
		a.Digest = "sha1:" + vi.Dist.Shasum
		sum := sha1.Sum(resp.Body)
		if hex.EncodeToString(sum[:]) != vi.Dist.Shasum {
			return nil, fmt.Errorf("%s: sha1 mismatch with registry metadata", u)
		}
		a.Verified = true
	}
	return a, nil
}

// PackageURL implements Registry.
func (n *Npm) PackageURL(name string) string { return n.docURL(name) }
