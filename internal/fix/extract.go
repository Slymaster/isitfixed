// Package fix extracts the distinctive lines a fix commit adds and checks
// whether a published artifact contains them. Matching is content-based, so
// it works for backports whose commit SHAs differ from the original fix.
package fix

import (
	"context"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/Slymaster/isitfixed/internal/github"
	"github.com/Slymaster/isitfixed/internal/httpx"
)

// MaxUnits bounds the number of distinctive lines kept per commit.
const MaxUnits = 20

// MinChars is the minimum number of non-whitespace characters for a line to
// be considered distinctive.
const MinChars = 12

// Unit is one distinctive added line.
type Unit struct {
	File string `json:"file"` // repository path
	Line string `json:"line"` // trimmed original line
	Norm string `json:"-"`    // whitespace-free form used for matching
	// Removed marks a line the fix deleted: its presence means the fix is
	// absent.
	Removed bool `json:"removed,omitempty"`
	// Tokens are identifiers/string literals of the line that do not occur
	// in the file on the other side of the fix; used to match compiled
	// .class files.
	Tokens []string `json:"-"`
}

// Set is the distinctive content of one fix commit.
type Set struct {
	Commit *github.Commit
	Units  []Unit
	// Added marks files created by the commit (absent before the fix).
	Added map[string]bool
}

// Fetcher is the subset of the GitHub client used here.
type Fetcher interface {
	Resolve(ctx context.Context, r github.Ref) (*github.Commit, error)
	RawFile(ctx context.Context, repo, sha, path string) ([]byte, error)
}

var sourceExt = map[string]bool{
	".go": true, ".js": true, ".mjs": true, ".cjs": true, ".ts": true, ".tsx": true, ".jsx": true,
	".mts": true, ".cts": true, ".rs": true, ".java": true, ".kt": true, ".scala": true, ".groovy": true,
	".py": true, ".rb": true, ".php": true, ".c": true, ".h": true, ".cc": true, ".cpp": true, ".hpp": true,
	".cs": true, ".swift": true, ".vue": true, ".svelte": true,
}

var testDirs = map[string]bool{
	"test": true, "tests": true, "__tests__": true, "testdata": true, "testing": true, "spec": true,
	"specs": true, "e2e": true, "fixtures": true, "__mocks__": true, "mocks": true, "examples": true,
	"example": true, "benches": true, "docs": true, "doc": true, "integration-tests": true, "it": true,
	"testutil": true, "testutils": true, "test-utils": true,
}

// Skippable reports whether a changed file should not contribute lines:
// tests, docs, lockfiles, generated files and non-source files.
func Skippable(p string) bool {
	base := path.Base(p)
	lb := strings.ToLower(base)
	if !sourceExt[strings.ToLower(path.Ext(base))] {
		return true
	}
	for _, seg := range strings.Split(strings.ToLower(path.Dir(p)), "/") {
		if testDirs[seg] {
			return true
		}
	}
	switch {
	case strings.HasSuffix(lb, "_test.go"), strings.Contains(lb, ".test."), strings.Contains(lb, ".spec."),
		strings.HasSuffix(base, "Test.java"), strings.HasSuffix(base, "Tests.java"), strings.HasSuffix(base, "IT.java"),
		strings.HasSuffix(base, "Test.kt"), strings.HasSuffix(base, "Tests.kt"),
		strings.HasPrefix(lb, "test_"), strings.HasSuffix(lb, "_test.py"), lb == "conftest.py",
		strings.HasSuffix(lb, "_test.rs"), strings.HasSuffix(lb, "_spec.rb"), strings.HasSuffix(lb, "_test.rb"):
		return true
	case strings.Contains(lb, ".pb.go"), strings.Contains(lb, "zz_generated"), strings.Contains(lb, "_generated"),
		strings.Contains(lb, ".generated."), strings.Contains(lb, ".gen."), strings.HasSuffix(lb, ".min.js"),
		strings.HasPrefix(lb, "mock_"), strings.HasSuffix(lb, "_mock.go"), strings.Contains(lb, "bindata"):
		return true
	}
	return false
}

var (
	goImportLine = regexp.MustCompile(`^(\w+\s+|\.\s+|_\s+)?"[^"]+"$`)
	identRe      = regexp.MustCompile(`[A-Za-z_$][A-Za-z0-9_$]{5,}`)
	stringLitRe  = regexp.MustCompile(`"([^"\\]{5,})"`)
)

func isComment(l, ext string) bool {
	for _, p := range []string{"//", "/*", "*/", "<!--", "-->"} {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	if l == "*" || strings.HasPrefix(l, "* ") {
		return true
	}
	switch ext {
	case ".py", ".rb":
		return strings.HasPrefix(l, "#") || strings.HasPrefix(l, `"""`) || strings.HasPrefix(l, "'''")
	case ".php":
		return strings.HasPrefix(l, "#")
	}
	return false
}

func isImport(l, ext string) bool {
	switch {
	case strings.HasPrefix(l, "import "), strings.HasPrefix(l, "import("), strings.HasPrefix(l, "package "),
		strings.HasPrefix(l, "#include"), strings.HasPrefix(l, "using "), strings.HasPrefix(l, "extern crate"),
		strings.HasPrefix(l, "require "), strings.HasPrefix(l, "require_relative "):
		return true
	case strings.HasPrefix(l, "from ") && strings.Contains(l, " import "):
		return true
	case (ext == ".rs" || ext == ".php") && (strings.HasPrefix(l, "use ") || strings.HasPrefix(l, "pub use ")):
		return true
	case strings.Contains(l, "require(") && (strings.HasPrefix(l, "const ") || strings.HasPrefix(l, "var ") || strings.HasPrefix(l, "let ")):
		return true
	case strings.HasPrefix(l, "} from ") || strings.HasPrefix(l, "export * from") || strings.HasPrefix(l, "export {") && strings.Contains(l, " from "):
		return true
	case ext == ".go" && goImportLine.MatchString(l):
		return true
	}
	return false
}

// Strip removes all whitespace (matching is whitespace-insensitive).
func Strip(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, s)
}

func hasLetters(s string) bool {
	n := 0
	for _, r := range s {
		if unicode.IsLetter(r) {
			n++
		}
	}
	return n >= 4
}

// parsePatch returns added and removed lines of a unified diff hunk set.
func parsePatch(p string) (added, removed []string) {
	for _, l := range strings.Split(p, "\n") {
		switch {
		case strings.HasPrefix(l, "+++"), strings.HasPrefix(l, "---"):
		case strings.HasPrefix(l, "+"):
			added = append(added, l[1:])
		case strings.HasPrefix(l, "-"):
			removed = append(removed, l[1:])
		}
	}
	return
}

var javaWords = map[string]bool{"public": true, "private": true, "protected": true, "static": true, "return": true,
	"final": true, "String": true, "boolean": true, "throws": true, "import": true, "Override": true, "string": true,
	"function": true, "const": true, "struct": true, "return;": true, "length": true, "equals": true, "null": true}

// classTokens returns identifiers and string literals of line that do not
// occur in the pre-fix file.
func classTokens(line string, parent []byte) []string {
	var toks []string
	seen := map[string]bool{}
	add := func(t string) {
		if !seen[t] && !javaWords[t] && (parent == nil || !strings.Contains(string(parent), t)) {
			seen[t] = true
			toks = append(toks, t)
		}
	}
	for _, m := range stringLitRe.FindAllStringSubmatch(line, -1) {
		add(m[1])
	}
	for _, m := range identRe.FindAllString(line, -1) {
		if len(m) >= 8 {
			add(m)
		}
	}
	return toks
}

// Extract computes the distinctive lines of a commit.
//
// An added line is distinctive when it is long enough, is not an import or
// comment, is not merely moved (removed elsewhere in the same diff) and does
// not already occur (whitespace-insensitively) in the pre-fix file.
//
// A removed line is distinctive under the same filters when it no longer
// occurs anywhere in the post-fix file; its presence in an artifact means
// the fix is absent. Removed lines matter for fixes that mostly delete code
// (e.g. dropping a secret from a log statement).
func Extract(ctx context.Context, f Fetcher, c *github.Commit) *Set {
	s := &Set{Commit: c, Added: map[string]bool{}}
	removedAll := map[string]bool{}
	addedAll := map[string]bool{}
	for _, fl := range c.Files {
		if fl.Patch == "" || Skippable(fl.Path) {
			continue
		}
		add, rem := parsePatch(fl.Patch)
		for _, r := range rem {
			removedAll[Strip(r)] = true
		}
		for _, a := range add {
			addedAll[Strip(a)] = true
		}
	}
	keep := func(l, ext string) (string, bool) {
		n := Strip(l)
		ok := len([]rune(n)) >= MinChars && hasLetters(n) && !isComment(l, ext) && !isImport(l, ext)
		return n, ok
	}
	perFile := map[string][]Unit{}
	perFileRem := map[string][]Unit{}
	var files []string
	for _, fl := range c.Files {
		if fl.Patch == "" || Skippable(fl.Path) || fl.Status == "removed" {
			continue
		}
		files = append(files, fl.Path)
		ext := strings.ToLower(path.Ext(fl.Path))
		var parent []byte
		if fl.Status == "added" {
			s.Added[fl.Path] = true
		} else if c.Parent != "" {
			pp := fl.Path
			if fl.PreviousPath != "" {
				pp = fl.PreviousPath
			}
			b, err := f.RawFile(ctx, c.Repo, c.Parent, pp)
			if err == nil {
				parent = b
			} else if err == httpx.ErrNotFound && fl.Status != "renamed" {
				// Not present before the fix: treat as added.
				s.Added[fl.Path] = true
			}
		}
		parentNorm := Strip(string(parent))
		add, rem := parsePatch(fl.Patch)
		seen := map[string]bool{}
		for _, raw := range add {
			l := strings.TrimSpace(raw)
			n, ok := keep(l, ext)
			if !ok || seen[n] || removedAll[n] || (parent != nil && strings.Contains(parentNorm, n)) {
				continue
			}
			seen[n] = true
			perFile[fl.Path] = append(perFile[fl.Path], Unit{File: fl.Path, Line: l, Norm: n, Tokens: classTokens(l, parent)})
		}
		if s.Added[fl.Path] || len(rem) == 0 || parent == nil {
			continue
		}
		post, err := f.RawFile(ctx, c.Repo, c.SHA, fl.Path)
		if err != nil {
			continue
		}
		postNorm := Strip(string(post))
		for _, raw := range rem {
			l := strings.TrimSpace(raw)
			n, ok := keep(l, ext)
			if !ok || seen[n] || addedAll[n] || strings.Contains(postNorm, n) {
				continue
			}
			seen[n] = true
			perFileRem[fl.Path] = append(perFileRem[fl.Path], Unit{File: fl.Path, Line: l, Norm: n, Removed: true, Tokens: classTokens(l, post)})
		}
	}
	s.Units = pick(files, perFile, MaxUnits)
	s.Units = append(s.Units, pick(files, perFileRem, MaxRemovedUnits)...)
	return s
}

// MaxRemovedUnits bounds the number of distinctive removed lines per commit.
const MaxRemovedUnits = 10

// pick prefers longer lines, round-robin across files so one big file does
// not crowd out the others.
func pick(files []string, perFile map[string][]Unit, max int) []Unit {
	for _, f := range files {
		us := perFile[f]
		sort.SliceStable(us, func(i, j int) bool { return len(us[i].Norm) > len(us[j].Norm) })
	}
	var out []Unit
	for round := 0; len(out) < max; round++ {
		took := false
		for _, f := range files {
			if round < len(perFile[f]) && len(out) < max {
				out = append(out, perFile[f][round])
				took = true
			}
		}
		if !took {
			break
		}
	}
	return out
}
