// Package github fetches fix commits (and pull requests resolved to their
// merge commits) from the GitHub REST API, and file contents at a commit
// from raw.githubusercontent.com.
package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/Slymaster/isitfixed/internal/httpx"
)

// Ref is a parsed GitHub commit or pull request URL.
type Ref struct {
	Owner, Repo string
	SHA         string // commit
	PR          int    // pull request (when SHA is empty)
	URL         string
}

// RepoSlug returns owner/repo.
func (r Ref) RepoSlug() string { return r.Owner + "/" + r.Repo }

var (
	commitRe = regexp.MustCompile(`^https?://github\.com/([^/]+)/([^/]+)/(?:commit|commits)/([0-9a-fA-F]{7,40})(?:[/?#.].*)?$`)
	prCommit = regexp.MustCompile(`^https?://github\.com/([^/]+)/([^/]+)/pull/[0-9]+/commits/([0-9a-fA-F]{7,40})(?:[/?#].*)?$`)
	prRe     = regexp.MustCompile(`^https?://github\.com/([^/]+)/([^/]+)/pull/([0-9]+)(?:/files|/commits)?/?(?:[?#].*)?$`)
)

// ParseRef parses a commit or pull request URL.
func ParseRef(u string) (Ref, bool) {
	u = strings.TrimSpace(u)
	if m := prCommit.FindStringSubmatch(u); m != nil {
		return Ref{Owner: m[1], Repo: m[2], SHA: strings.ToLower(m[3]), URL: u}, true
	}
	if m := commitRe.FindStringSubmatch(u); m != nil {
		return Ref{Owner: m[1], Repo: m[2], SHA: strings.ToLower(m[3]), URL: u}, true
	}
	if m := prRe.FindStringSubmatch(u); m != nil {
		var n int
		fmt.Sscan(m[3], &n)
		return Ref{Owner: m[1], Repo: m[2], PR: n, URL: u}, true
	}
	return Ref{}, false
}

// Token returns GITHUB_TOKEN, or `gh auth token` if gh is installed.
func Token() string {
	if t := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); t != "" {
		return t
	}
	if _, err := exec.LookPath("gh"); err != nil {
		return ""
	}
	out, err := exec.Command("gh", "auth", "token").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// File is one changed file of a commit.
type File struct {
	Path         string `json:"filename"`
	PreviousPath string `json:"previous_filename"`
	Status       string `json:"status"` // added, modified, removed, renamed…
	Patch        string `json:"patch"`
}

// Commit is a fetched commit.
type Commit struct {
	Repo    string // owner/repo
	SHA     string
	Parent  string
	Message string
	Files   []File
	URL     string // html URL
}

// Client fetches from GitHub.
type Client struct {
	HTTP    *httpx.Client
	Token   string
	APIBase string // default https://api.github.com
	RawBase string // default https://raw.githubusercontent.com
}

func (c *Client) api() string {
	if c.APIBase != "" {
		return strings.TrimRight(c.APIBase, "/")
	}
	return "https://api.github.com"
}

func (c *Client) raw() string {
	if c.RawBase != "" {
		return strings.TrimRight(c.RawBase, "/")
	}
	return "https://raw.githubusercontent.com"
}

func (c *Client) get(ctx context.Context, path string, immutable bool) ([]byte, error) {
	h := map[string]string{"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
	if c.Token != "" {
		h["Authorization"] = "Bearer " + c.Token
	}
	resp, err := c.HTTP.Get(ctx, httpx.Request{URL: c.api() + path, Header: h, Immutable: immutable})
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// ErrUnmerged is returned for pull requests that were never merged.
var ErrUnmerged = errors.New("pull request is not merged")

// Resolve fetches the commit a Ref points to. A merged pull request
// resolves to its merge commit, with the PR's own file list (its diff
// against the base branch) as the patch.
func (c *Client) Resolve(ctx context.Context, r Ref) (*Commit, error) {
	if r.SHA != "" {
		return c.commit(ctx, r.Owner, r.Repo, r.SHA)
	}
	b, err := c.get(ctx, fmt.Sprintf("/repos/%s/%s/pulls/%d", r.Owner, r.Repo, r.PR), false)
	if err != nil {
		return nil, err
	}
	var pr struct {
		Merged         bool   `json:"merged"`
		MergeCommitSHA string `json:"merge_commit_sha"`
		Base           struct {
			SHA string `json:"sha"`
		} `json:"base"`
		HTMLURL string `json:"html_url"`
	}
	if err := json.Unmarshal(b, &pr); err != nil {
		return nil, err
	}
	if !pr.Merged || pr.MergeCommitSHA == "" {
		return nil, ErrUnmerged
	}
	mc, err := c.commit(ctx, r.Owner, r.Repo, pr.MergeCommitSHA)
	if err != nil {
		return nil, err
	}
	// The PR file list is the full change even for rebase merges, where the
	// merge commit only carries the PR's last commit.
	var files []File
	for page := 1; page <= 10; page++ {
		b, err := c.get(ctx, fmt.Sprintf("/repos/%s/%s/pulls/%d/files?per_page=100&page=%d", r.Owner, r.Repo, r.PR, page), false)
		if err != nil {
			return nil, err
		}
		var fs []File
		if err := json.Unmarshal(b, &fs); err != nil {
			return nil, err
		}
		files = append(files, fs...)
		if len(fs) < 100 {
			break
		}
	}
	mc.Files = files
	mc.Parent = pr.Base.SHA
	mc.URL = pr.HTMLURL
	return mc, nil
}

func (c *Client) commit(ctx context.Context, owner, repo, sha string) (*Commit, error) {
	b, err := c.get(ctx, fmt.Sprintf("/repos/%s/%s/commits/%s", owner, repo, sha), len(sha) == 40)
	if err != nil {
		return nil, err
	}
	var raw struct {
		SHA     string `json:"sha"`
		HTMLURL string `json:"html_url"`
		Commit  struct {
			Message string `json:"message"`
		} `json:"commit"`
		Parents []struct {
			SHA string `json:"sha"`
		} `json:"parents"`
		Files []File `json:"files"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	cm := &Commit{Repo: owner + "/" + repo, SHA: raw.SHA, Message: raw.Commit.Message, Files: raw.Files, URL: raw.HTMLURL}
	if len(raw.Parents) > 0 {
		cm.Parent = raw.Parents[0].SHA
	}
	return cm, nil
}

// RawFile returns a file's content at a commit, or httpx.ErrNotFound.
func (c *Client) RawFile(ctx context.Context, repo, sha, path string) ([]byte, error) {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	resp, err := c.HTTP.Get(ctx, httpx.Request{URL: c.raw() + "/" + repo + "/" + sha + "/" + strings.Join(segs, "/"), Immutable: true})
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}
