package registry

import (
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Slymaster/isitfixed/internal/httpx"
	"github.com/Slymaster/isitfixed/internal/versions"
)

// DefaultMavenRepos are searched in order. GitHub advisories in the Maven
// ecosystem also cover artifacts that are not on Maven Central: Jenkins
// plugins, Android libraries, XWiki, Atlassian and OSGeo (GeoServer) artifacts.
var DefaultMavenRepos = []string{
	"https://repo1.maven.org/maven2",
	"https://repo.jenkins-ci.org/releases",
	"https://maven.google.com",
	"https://maven.xwiki.org/releases",
	"https://packages.atlassian.com/maven-public",
	"https://repo.osgeo.org/repository/release",
}

// Maven reads Maven repositories.
type Maven struct {
	HTTP  *httpx.Client
	Repos []string
}

// Ecosystem implements Registry.
func (m *Maven) Ecosystem() string { return versions.Maven }

func (m *Maven) repos() []string {
	if len(m.Repos) > 0 {
		return m.Repos
	}
	return DefaultMavenRepos
}

func splitGA(name string) (string, string, error) {
	g, a, ok := strings.Cut(name, ":")
	if !ok || g == "" || a == "" || strings.Contains(a, ":") {
		return "", "", fmt.Errorf("invalid Maven package name %q (want groupId:artifactId)", name)
	}
	return g, a, nil
}

func gaPath(repo, g, a string) string {
	return strings.TrimRight(repo, "/") + "/" + strings.ReplaceAll(g, ".", "/") + "/" + a
}

type mavenMeta struct {
	Versions []string `xml:"versioning>versions>version"`
}

// repoFor returns the first repository with metadata for the package.
func (m *Maven) repoFor(ctx context.Context, name string) (string, *mavenMeta, error) {
	g, a, err := splitGA(name)
	if err != nil {
		return "", nil, err
	}
	// Report the first repository that failed (normally Maven Central),
	// not whichever mirror happened to be tried last.
	var firstErr error
	for _, r := range m.repos() {
		resp, err := m.HTTP.Get(ctx, httpx.Request{URL: gaPath(r, g, a) + "/maven-metadata.xml"})
		if err == ErrNotFound {
			continue
		}
		if err == nil {
			var md mavenMeta
			if err = xml.Unmarshal(resp.Body, &md); err == nil {
				return r, &md, nil
			}
			err = fmt.Errorf("%s: invalid maven-metadata.xml for %s: %w", httpx.Host(r), name, err)
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return "", nil, firstErr
	}
	return "", nil, ErrNotFound
}

// Lookup implements Registry.
func (m *Maven) Lookup(ctx context.Context, name string) (*Package, error) {
	repo, md, err := m.repoFor(ctx, name)
	if err != nil {
		return nil, err
	}
	g, a, _ := splitGA(name)
	p := &Package{Ecosystem: versions.Maven, Name: name, URL: gaPath(repo, g, a) + "/maven-metadata.xml"}
	if repo != m.repos()[0] {
		p.Note = "found in " + repo
	}
	seen := map[string]bool{}
	for _, v := range md.Versions {
		v = strings.TrimSpace(v)
		if v != "" && !seen[v] {
			seen[v] = true
			p.Releases = append(p.Releases, Release{Version: v})
		}
	}
	sortReleases(versions.Maven, p.Releases)
	return p, nil
}

func (m *Maven) fileURL(repo, name, version, classifier, ext string) string {
	g, a, _ := splitGA(name)
	f := a + "-" + version
	if classifier != "" {
		f += "-" + classifier
	}
	return gaPath(repo, g, a) + "/" + version + "/" + f + "." + ext
}

// VersionURL implements Registry.
func (m *Maven) VersionURL(name, version string) string {
	return m.fileURL(m.repos()[0], name, version, "", "pom")
}

// VersionExists implements Registry: HEAD on the version's pom in every
// repository (maven-metadata.xml is occasionally incomplete).
func (m *Maven) VersionExists(ctx context.Context, name, version string) (bool, error) {
	if _, _, err := splitGA(name); err != nil {
		return false, err
	}
	var firstErr error
	for _, r := range m.repos() {
		_, err := m.HTTP.Head(ctx, httpx.Request{URL: m.fileURL(r, name, version, "", "pom"), Immutable: true})
		if err == nil {
			return true, nil
		}
		if err != ErrNotFound && firstErr == nil {
			firstErr = err
		}
	}
	return false, firstErr
}

// PublishedAt implements Registry using the pom's Last-Modified header.
func (m *Maven) PublishedAt(ctx context.Context, name, version string) (time.Time, bool) {
	repo, _, err := m.repoFor(ctx, name)
	if err != nil {
		return time.Time{}, false
	}
	resp, err := m.HTTP.Head(ctx, httpx.Request{URL: m.fileURL(repo, name, version, "", "pom"), Immutable: true})
	if err != nil {
		return time.Time{}, false
	}
	t, err := http.ParseTime(resp.Header.Get("Last-Modified"))
	return t, err == nil
}

// Artifact implements Registry: the -sources.jar, or the main jar (class
// files, lower confidence) when no sources are published.
func (m *Maven) Artifact(ctx context.Context, name, version string) (*Artifact, error) {
	repo, _, err := m.repoFor(ctx, name)
	if err != nil {
		return nil, err
	}
	for _, c := range []struct{ classifier, kind string }{{"sources", "source"}, {"", "class"}} {
		u := m.fileURL(repo, name, version, c.classifier, "jar")
		rf, err := m.HTTP.OpenRanged(ctx, u)
		if err == ErrNotFound {
			continue
		}
		if err != nil {
			return nil, err
		}
		files, err := zipArtifact(rf, rf.Size(), func(n string) (string, bool) {
			return n, !strings.HasPrefix(n, "META-INF/")
		})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", u, err)
		}
		a := &Artifact{URL: u, Kind: c.kind, files: files}
		if resp, err := m.HTTP.Get(ctx, httpx.Request{URL: u + ".sha1", Immutable: true}); err == nil {
			if f := strings.Fields(string(resp.Body)); len(f) > 0 {
				a.Digest = "sha1:" + f[0]
			}
		}
		return a, nil
	}
	return nil, ErrNoArtifact
}

// PackageURL implements Registry (Maven Central's metadata URL).
func (m *Maven) PackageURL(name string) string {
	g, a, err := splitGA(name)
	if err != nil {
		return ""
	}
	return gaPath(m.repos()[0], g, a) + "/maven-metadata.xml"
}

// RepoNames lists the repositories searched, by host.
func (m *Maven) RepoNames() []string {
	var out []string
	for _, r := range m.repos() {
		h := strings.TrimPrefix(strings.TrimPrefix(r, "https://"), "http://")
		h, _, _ = strings.Cut(h, "/")
		out = append(out, h)
	}
	return out
}
