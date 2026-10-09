// Command isitfixed checks whether the version ranges in OSV / GitHub
// security advisories match what was actually published.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Slymaster/isitfixed/internal/check"
	"github.com/Slymaster/isitfixed/internal/github"
	"github.com/Slymaster/isitfixed/internal/httpx"
	"github.com/Slymaster/isitfixed/internal/osv"
	"github.com/Slymaster/isitfixed/internal/registry"
	"github.com/Slymaster/isitfixed/internal/report"
	"github.com/Slymaster/isitfixed/internal/versions"
)

// version is set with -ldflags "-X main.version=…"; otherwise the module
// version recorded by `go install` is used.
var version = ""

func toolVersion() string {
	if version != "" {
		return version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

const usage = `isitfixed checks whether the version ranges in OSV / GitHub security
advisories match what was actually published.

Usage:
  isitfixed check [flags] [ID ...]     check advisories (IDs are fetched from osv.dev)
  isitfixed version                    print the version

Flags for check:
`

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Fprint(stderr, usage)
		f := newFlags(stderr)
		f.fs.PrintDefaults()
		if len(args) == 0 {
			return 2
		}
		return 0
	}
	switch args[0] {
	case "version":
		fmt.Fprintln(stdout, "isitfixed", toolVersion())
		return 0
	case "check":
		return runCheck(args[1:], stdout, stderr)
	}
	fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
	return 2
}

type flags struct {
	fs          *flag.FlagSet
	files       multi
	dir         string
	ecosystem   string
	concurrency int
	format      string
	fixRefs     multi
	checks      string
	cacheDir    string
	noCache     bool
	minSev      string
	maxArt      int
	verbose     bool
}

func newFlags(out io.Writer) *flags {
	f := &flags{fs: flag.NewFlagSet("check", flag.ContinueOnError)}
	f.fs.SetOutput(out)
	f.fs.Var(&f.files, "file", "OSV JSON `file` to check (repeatable)")
	f.fs.StringVar(&f.dir, "dir", "", "`directory` to scan recursively for OSV JSON files")
	f.fs.StringVar(&f.ecosystem, "ecosystem", "", "only check advisories with a package in this `ecosystem` (Go, npm, Maven, crates.io)")
	f.fs.IntVar(&f.concurrency, "concurrency", 4, "advisories checked in parallel")
	f.fs.StringVar(&f.format, "format", "text", "output `format`: text or json")
	f.fs.Var(&f.fixRefs, "fix-ref", "extra fix commit or pull request `URL` used by FIX001 (repeatable)")
	f.fs.StringVar(&f.checks, "checks", "", "comma-separated check `IDs` to run (default: all)")
	f.fs.StringVar(&f.cacheDir, "cache-dir", "", "cache `directory` (default: <user cache dir>/isitfixed)")
	f.fs.BoolVar(&f.noCache, "no-cache", false, "do not read or write the on-disk cache")
	f.fs.StringVar(&f.minSev, "min-severity", "info", "hide findings below this `severity` (info, warning, error)")
	f.fs.IntVar(&f.maxArt, "max-artifacts", check.DefaultMaxArtifacts, "maximum artifacts inspected per package by FIX001")
	f.fs.BoolVar(&f.verbose, "v", false, "text output: also list advisories without findings")
	return f
}

func sevRank(s check.Severity) int {
	switch s {
	case check.Error:
		return 2
	case check.Warning:
		return 1
	}
	return 0
}

func runCheck(args []string, stdout, stderr io.Writer) int {
	f := newFlags(stderr)
	// Allow flags after positional IDs.
	var ids []string
	rest := args
	for {
		if err := f.fs.Parse(rest); err != nil {
			if errors.Is(err, flag.ErrHelp) {
				return 0
			}
			return 2
		}
		if f.fs.NArg() == 0 {
			break
		}
		ids = append(ids, f.fs.Arg(0))
		rest = f.fs.Args()[1:]
	}
	if len(ids) == 0 && len(f.files) == 0 && f.dir == "" {
		fmt.Fprintln(stderr, "isitfixed check: give advisory IDs, --file or --dir")
		return 2
	}
	if f.format != "text" && f.format != "json" {
		fmt.Fprintln(stderr, "isitfixed check: --format must be text or json")
		return 2
	}
	minSev := check.Severity(f.minSev)
	if minSev != check.Info && minSev != check.Warning && minSev != check.Error {
		fmt.Fprintln(stderr, "isitfixed check: --min-severity must be info, warning or error")
		return 2
	}
	if f.ecosystem != "" && !versions.Supported(f.ecosystem) {
		fmt.Fprintf(stderr, "isitfixed check: unsupported ecosystem %q (supported: Go, npm, Maven, crates.io)\n", f.ecosystem)
		return 2
	}
	var enabled map[string]bool
	if f.checks != "" {
		enabled = map[string]bool{}
		for _, c := range strings.Split(f.checks, ",") {
			c = strings.ToUpper(strings.TrimSpace(c))
			known := false
			for _, k := range check.AllChecks {
				known = known || k == c
			}
			if !known {
				fmt.Fprintf(stderr, "isitfixed check: unknown check %q\n", c)
				return 2
			}
			enabled[c] = true
		}
	}

	cacheDir := f.cacheDir
	if cacheDir == "" && !f.noCache {
		if d, err := os.UserCacheDir(); err == nil {
			cacheDir = filepath.Join(d, "isitfixed")
		}
	}
	if f.noCache {
		cacheDir = ""
	}
	ua := fmt.Sprintf("isitfixed/%s (+https://github.com/Slymaster/isitfixed)", toolVersion())
	hc := httpx.New(ua, cacheDir)
	api := &osv.API{HTTP: hc}
	token := github.Token()
	if token == "" {
		fmt.Fprintln(stderr, "isitfixed: no GITHUB_TOKEN (or gh auth token); GitHub API calls are limited to 60 per hour")
	}
	eng := &check.Engine{
		Registries: map[string]registry.Registry{
			versions.Go:     &registry.GoProxy{HTTP: hc},
			versions.Npm:    &registry.Npm{HTTP: hc},
			versions.Maven:  &registry.Maven{HTTP: hc},
			versions.Crates: &registry.Crates{HTTP: hc},
		},
		GitHub:       &github.Client{HTTP: hc, Token: token},
		OSV:          api,
		ExtraFixRefs: f.fixRefs,
		MaxArtifacts: f.maxArt,
		Enabled:      enabled,
	}

	type job struct{ id, path string }
	var jobs []job
	for _, id := range ids {
		jobs = append(jobs, job{id: id})
	}
	for _, p := range f.files {
		jobs = append(jobs, job{path: p})
	}
	if f.dir != "" {
		ps, err := osv.WalkDir(f.dir)
		if err != nil {
			fmt.Fprintln(stderr, "isitfixed check:", err)
			return 2
		}
		for _, p := range ps {
			jobs = append(jobs, job{path: p})
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	results := make([]*report.Advisory, len(jobs))
	n := f.concurrency
	if n < 1 {
		n = 1
	}
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	// Progress on an interactive terminal for long directory scans.
	var done atomic.Int32
	progress := func() {}
	interactive := false
	if fi, err := os.Stderr.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 && len(jobs) > 10 && stderr == os.Stderr {
		interactive = true
		progress = func() { fmt.Fprintf(stderr, "\rchecked %d/%d", done.Add(1), len(jobs)) }
	}
	for i, j := range jobs {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer progress()
			var v *osv.Vuln
			var err error
			src := j.id
			if j.path != "" {
				src = j.path
				v, err = osv.ParseFile(j.path)
			} else {
				v, err = api.Get(ctx, j.id)
				if errors.Is(err, httpx.ErrNotFound) {
					err = fmt.Errorf("%s not found on osv.dev", j.id)
				}
			}
			if err != nil {
				if j.path != "" && f.dir != "" {
					return // not an OSV file; skip silently in directory scans
				}
				results[i] = &report.Advisory{ID: strings.TrimSuffix(filepath.Base(src), ".json"), Source: src, Error: err.Error()}
				return
			}
			if f.ecosystem != "" && !v.HasEcosystem(f.ecosystem) {
				return
			}
			fs := eng.Run(ctx, v)
			var kept []check.Finding
			for _, x := range fs {
				if f.ecosystem != "" && x.Ecosystem != "" && !strings.EqualFold(x.Ecosystem, f.ecosystem) {
					continue
				}
				if sevRank(x.Severity) >= sevRank(minSev) {
					kept = append(kept, x)
				}
			}
			results[i] = &report.Advisory{ID: v.ID, Summary: v.Summary, Source: src, Findings: kept}
		}()
	}
	wg.Wait()
	if interactive {
		fmt.Fprintln(stderr)
	}

	var out []report.Advisory
	failed := false
	for _, r := range results {
		if r == nil {
			continue
		}
		out = append(out, *r)
		for _, x := range r.Findings {
			if x.Severity == check.Error {
				failed = true
			}
		}
	}
	if f.format == "json" {
		if err := report.JSON(stdout, toolVersion(), out); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	} else {
		report.Text(stdout, out, f.verbose)
	}
	if failed {
		return 1
	}
	return 0
}
