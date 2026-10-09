// Package registry talks to package registries (proxy.golang.org, npm,
// Maven Central, crates.io): package metadata, version lists, publication
// dates and downloadable artifacts.
package registry

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/Slymaster/isitfixed/internal/httpx"
	"github.com/Slymaster/isitfixed/internal/versions"
)

// ErrNotFound means the package does not exist in the registry.
var ErrNotFound = httpx.ErrNotFound

// ErrNoArtifact means the version exists but has no artifact isitfixed can
// inspect (e.g. a pom-only Maven artifact).
var ErrNoArtifact = errors.New("no inspectable artifact")

// Release is one published version.
type Release struct {
	Version   string
	Published time.Time // zero if the registry listing has no date
	Yanked    bool
}

// Package is registry metadata for a package.
type Package struct {
	Ecosystem string
	Name      string
	// Releases sorted ascending by ecosystem order.
	Releases []Release
	// URL is a human-checkable evidence URL for the listing.
	URL string
	// Note carries a caveat (e.g. "Go package inside module X").
	Note string
	// Unpublished is set for npm packages whose versions were all removed.
	Unpublished bool
}

// Versions returns the version strings in ascending order.
func (p *Package) Versions() []string {
	out := make([]string, len(p.Releases))
	for i, r := range p.Releases {
		out[i] = r.Version
	}
	return out
}

// Find returns the published release equal to v under ecosystem ordering.
func (p *Package) Find(v string) (Release, bool) {
	for _, r := range p.Releases {
		if versions.Equal(p.Ecosystem, r.Version, v) {
			return r, true
		}
	}
	return Release{}, false
}

func sortReleases(eco string, rs []Release) {
	sort.SliceStable(rs, func(i, j int) bool { return versions.Compare(eco, rs[i].Version, rs[j].Version) < 0 })
}

// Artifact is an inspectable published archive.
type Artifact struct {
	URL string
	// Digest is the digest the registry publishes for this file, e.g.
	// "sha1:…" (Maven .sha1), "sha256:…" (crates.io), "vcs:<commit>" (Go
	// proxy Origin.Hash).
	Digest string
	// Verified is true when isitfixed downloaded the whole file and its
	// digest matched Digest.
	Verified bool
	// Kind is "source" (source files) or "class" (compiled Java classes).
	Kind  string
	files map[string]func() ([]byte, error)
}

// Files lists the archive's file paths, relative to the archive root.
func (a *Artifact) Files() []string {
	out := make([]string, 0, len(a.files))
	for f := range a.files {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// Read returns the contents of one file.
func (a *Artifact) Read(rel string) ([]byte, error) {
	f, ok := a.files[rel]
	if !ok {
		return nil, errors.New("no such file: " + rel)
	}
	return f()
}

// Registry is implemented per ecosystem.
type Registry interface {
	Ecosystem() string
	// Lookup returns package metadata or ErrNotFound.
	Lookup(ctx context.Context, name string) (*Package, error)
	// PackageURL returns the listing URL checked for the package.
	PackageURL(name string) string
	// VersionURL returns an evidence URL for one version.
	VersionURL(name, version string) string
	// VersionExists checks a single version directly (used to confirm a
	// version missing from the listing, e.g. Go pseudo-versions or an
	// incomplete maven-metadata.xml).
	VersionExists(ctx context.Context, name, version string) (bool, error)
	// PublishedAt returns a version's publication time, if known.
	PublishedAt(ctx context.Context, name, version string) (time.Time, bool)
	// Artifact downloads (or range-reads) the inspectable archive for a version.
	Artifact(ctx context.Context, name, version string) (*Artifact, error)
}

const maxEntry = 8 << 20

// MaxTarball bounds npm/crates.io tarball downloads (they cannot be
// range-read like zips).
const MaxTarball = 40 << 20

// zipArtifact indexes a zip, stripping strip(name) to a relative path.
func zipArtifact(ra io.ReaderAt, size int64, strip func(string) (string, bool)) (map[string]func() ([]byte, error), error) {
	zr, err := zip.NewReader(ra, size)
	if err != nil {
		return nil, err
	}
	files := map[string]func() ([]byte, error){}
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || f.UncompressedSize64 > maxEntry {
			continue
		}
		rel, ok := strip(f.Name)
		if !ok {
			continue
		}
		f := f
		files[rel] = func() ([]byte, error) {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(io.LimitReader(rc, maxEntry))
		}
	}
	return files, nil
}

// tgzArtifact reads a .tar.gz fully into memory, stripping the first path
// component (npm "package/", crates "name-version/").
func tgzArtifact(b []byte) (map[string]func() ([]byte, error), error) {
	gz, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	files := map[string]func() ([]byte, error){}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag != tar.TypeReg || h.Size > maxEntry {
			continue
		}
		name := strings.TrimPrefix(path.Clean("/"+h.Name), "/")
		_, rel, ok := strings.Cut(name, "/")
		if !ok || rel == "" {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(tr, maxEntry))
		if err != nil {
			return nil, err
		}
		files[rel] = func() ([]byte, error) { return data, nil }
	}
	return files, nil
}

// NewMemArtifact builds an artifact from in-memory files (used by tests and
// fakes).
func NewMemArtifact(url, kind string, files map[string]string) *Artifact {
	m := map[string]func() ([]byte, error){}
	for k, v := range files {
		v := v
		m[k] = func() ([]byte, error) { return []byte(v), nil }
	}
	return &Artifact{URL: url, Kind: kind, files: m}
}
