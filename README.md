# isitfixed

`isitfixed` checks whether the version ranges in OSV / GitHub security advisories match what was actually published.
It looks inside the published artifacts to see whether the "fixed" version really contains the fix, so it also works for backports whose commits have different SHAs.

```
go install github.com/Slymaster/isitfixed/cmd/isitfixed@latest
isitfixed check GHSA-pg5p-wwp8-97g8
```

## Why

Advisory ranges are written by hand, and mistakes in them are hard to spot:
a typo in a package name, a `fixed` version that was never released, a
`last_affected` that ignores twenty later patch releases, a release line that
falls between two ranges. Scanners trust these ranges, so each mistake either
hides a vulnerable version or flags a fixed one.

[`osv-linter`](https://github.com/ossf/osv-schema/tree/main/tools/osv-linter)
validates OSV records and checks that the packages and versions they name
exist. isitfixed overlaps with it on those two points (PKG001, VER001) and is
meant to be complementary. What it adds:

- **Content-based fix verification (FIX001).** It takes the fix commits or pull
  requests referenced by the advisory, extracts the lines the fix adds and
  removes, downloads the published artifacts (Go module zip, npm tarball,
  crate, Maven `-sources.jar`) and checks whether those lines are present. This
  answers "does 3.34.7 contain the fix?" directly, even when the fix reached
  3.34.7 through a backport commit that `git tag --contains` would not find.
- **Range-shape checks (RNG001, RNG002)** for stale `last_affected` events and
  release lines that no range covers, confirmed by content when a fix commit
  is available.
- **Cross-database comparison (XDB001)** against alias records on osv.dev
  (Go vulndb `GO-*`, RustSec, …).

## Usage

```
isitfixed check GHSA-xxxx-xxxx-xxxx [ID ...]   # fetch records from osv.dev
isitfixed check --file advisory.json           # a local OSV file (repeatable)
isitfixed check --dir advisories/ --ecosystem Go --concurrency 4
```

| Flag | Meaning |
|---|---|
| `--format text\|json` | Output format (default `text`). |
| `--ecosystem` | Only check advisories with a package in `Go`, `npm`, `Maven` or `crates.io`. |
| `--concurrency` | Advisories checked in parallel (default 4). Requests are also limited per host. |
| `--fix-ref URL` | Extra fix commit or pull request URL for FIX001 (repeatable). It applies to every advisory in the run, so use it when checking a single advisory that does not reference its fix. |
| `--checks` | Comma-separated check IDs to run (default: all). |
| `--min-severity` | Hide findings below `info`, `warning` or `error`. |
| `--max-artifacts` | Artifacts inspected per package by FIX001 (default 24). |
| `--cache-dir`, `--no-cache` | On-disk cache location (default `<user cache dir>/isitfixed`) or no cache. |
| `-v` | Text output: also list advisories without findings. |

The exit code is `1` when any finding has severity `error`, so the command can
gate a CI job; `2` means a usage or runtime error.

GitHub API calls (fix commits, pull requests, tags) use `GITHUB_TOKEN`, or the
output of `gh auth token` when the GitHub CLI is installed. Without a token the
API allows 60 requests per hour.

Supported ecosystems: Go (proxy.golang.org), npm (registry.npmjs.org), Maven
(Maven Central, plus the Jenkins, Google, XWiki, Atlassian and OSGeo repositories) and
crates.io. Version ordering uses
[`osv-scalibr/semantic`](https://github.com/google/osv-scalibr/tree/main/semantic),
the implementation used by Google's OSV tooling, so Maven `2.2.0` equals
`2.2.0.RELEASE` and `3.35.0.CR1` sorts before `3.35.0`.

## Checks

| ID | Severity | What it reports |
|---|---|---|
| PKG001 | error | The package does not exist in the registry. Suggests a similarly named package from the same advisory. |
| VER001 | error for `fixed`, warning for `introduced` (other than 0) and `last_affected` | A range version is not published. A version counts as published when a listed version is equal under ecosystem ordering, or a per-version lookup finds it (Go pseudo-versions, incomplete `maven-metadata.xml`). For Go it also reports when the version exists under another major-version module path (`github.com/x/y/v2`), and downgrades to info when the version is only a git tag that cannot be a module version (applications at v2+ without a `/v2` path). |
| RNG001 | warning (info when weak) | A range ends with `last_affected: X`, later versions of the same release line were published, no range covers them, and there is no `fixed` event. It is a warning when newer lines of the package have fixed versions (the line looks unpatched), info otherwise. Fix content can confirm it (the newest version still has the removed code) or downgrade it (the newest version contains the fix). |
| RNG002 | warning (info when ranges start mid-line) | A whole release line lies between two ranges and none of its versions is covered, for example Quarkus 3.28/3.29 between `[3.21.0, 3.27.3.1)` and `[3.30.0, …)`. Partially covered lines are not reported. Lines first published after the preceding fix are skipped, and the finding is info only when some range is introduced at a patch release (the vulnerable code may have arrived through a backport). Fix content can confirm or downgrade it. |
| FIX001 | error / warning / info | Fix-content verification, see below. **error**: the `fixed` version does not contain the fix while another version does. **warning**: the range includes versions that already contain the fix (with the earliest such version, found by bisection, and a suggested split of the range). **info**: verified results, pre-releases of the fixed release that already contain the fix, and "unverifiable" when the fix commit is missing, yields no usable lines, or matches nothing in any inspected artifact. |
| XDB001 | warning | An alias record on osv.dev marks a different set of published versions affected for the same package, or lists a similarly named package that this advisory spells differently. |

### How FIX001 works

1. Collect GitHub commit and pull request URLs from the advisory's `FIX`/`WEB`
   references, from `FIX` references of alias records (Go vulndb records often
   have them) and from `--fix-ref`. Pull requests resolve to their merge
   commit and file list.
2. From each commit, keep up to 20 added and 10 removed lines that are
   *distinctive*: in non-test source files (tests, docs, lockfiles and
   generated files are skipped), at least 12 non-space characters, not an
   import or comment, not moved within the diff, and (for added lines) absent
   from the pre-fix file or (for removed lines) absent from the post-fix file.
   Revert commits, and commits whose additions another referenced commit
   removes again, are dropped.
3. Map the commit's file paths to the artifact by path suffix (Go zip
   `module@version/…`, npm `package/…`, crate `name-version/…`, Maven sources
   under `src/main/java/`). Matching ignores whitespace. When a Maven artifact
   has no `-sources.jar`, identifiers and string literals are searched in the
   compiled classes and the result is marked low confidence.
4. A version *contains* the fix when at least 70% of the applicable lines are
   in their fixed state (added lines present, removed lines absent) and
   *lacks* it at 20% or less; anything in between is inconclusive. Commits
   with overlapping lines are treated as alternatives (backports of one fix),
   disjoint commits as parts that must all be present.
5. For each range, inspect the `fixed` version and the newest affected version
   of the (up to three) newest release lines it covers. When an affected
   version contains the fix, bisect within its line for the earliest one.
   Downloads are bounded per package, Go and Maven archives are read with HTTP
   range requests, and everything is cached on disk.

Evidence lists the artifact URLs with the digest the registry publishes for
them (Maven `.sha1`, npm `shasum`, crates.io `sha256`, Go proxy VCS commit).
npm and crate tarballs are downloaded whole and their digest is verified.

## Example

The advisory GHSA-rc95-pcm8-65v9 (original file from github/advisory-database,
in `testdata/advisories/`) references no fix commit, so the upstream fix is
passed with `--fix-ref`. Output as of 2026-10-08:

```
$ isitfixed check --file testdata/advisories/GHSA-rc95-pcm8-65v9.json \
    --fix-ref https://github.com/quarkusio/quarkus/commit/363d53a82a16b2b7c9de8d968694fd4d93e05062
GHSA-rc95-pcm8-65v9  Quarkus has Authentication/Authorization bypasses
  source: testdata/advisories/GHSA-rc95-pcm8-65v9.json
  ERROR   VER001  Maven io.quarkus:quarkus-vertx-http
          fixed version 3.35.1.1 is not published for io.quarkus:quarkus-vertx-http
          - nearest published versions: 3.35.1 < 3.35.1.1 < 3.35.2
          evidence: https://repo1.maven.org/maven2/io/quarkus/quarkus-vertx-http/maven-metadata.xml
          evidence: https://repo1.maven.org/maven2/io/quarkus/quarkus-vertx-http/3.35.1.1/quarkus-vertx-http-3.35.1.1.pom
  WARNING FIX001  Maven io.quarkus:quarkus-vertx-http
          range [3.34.0, 3.35.1.1) includes versions that already contain the fix
          - 3.34.x: the fix first appears in 3.34.7 (newest affected version checked: 3.34.7: contains (11/11 distinctive lines present))
          - fixed version 3.35.1.1 is not published; the earliest later 3.35.x version containing the fix is 3.35.2
          evidence: https://repo1.maven.org/maven2/io/quarkus/quarkus-vertx-http/3.34.7/quarkus-vertx-http-3.34.7-sources.jar (sha1:1c64c7a2b7acf34ed9d8ea752708fae74844bdf2, as published by the registry)
          evidence: https://github.com/quarkusio/quarkus/commit/363d53a82a16b2b7c9de8d968694fd4d93e05062
          suggested ranges:
            {"type":"ECOSYSTEM","events":[{"introduced":"3.34.0"},{"fixed":"3.34.7"}]}
            {"type":"ECOSYSTEM","events":[{"introduced":"3.35.0.CR1"},{"fixed":"3.35.2"}]}
  WARNING RNG002  Maven io.quarkus:quarkus-vertx-http
          release line(s) 3.28, 3.29 (13 versions: 3.28.0.CR1, 3.28.0 … 3.29.4) lie between affected ranges (after the range ending at 3.27.3.1, before the one introduced at 3.30.0) and no version of them is covered
          - a line released before the preceding fix and never patched is still vulnerable; if these versions are affected, add a range for them
          - confirmed by content: 3.29.4 lacks the fix (0/11 distinctive lines in their fixed state) and still contains 1/1 lines the fix removed
          evidence: https://repo1.maven.org/maven2/io/quarkus/quarkus-vertx-http/maven-metadata.xml
          evidence: https://repo1.maven.org/maven2/io/quarkus/quarkus-vertx-http/3.29.4/quarkus-vertx-http-3.29.4-sources.jar (sha1:be42a8404d69526c488129c32df6c34f2ed0164b, as published by the registry)
          suggested ranges:
            {"type":"ECOSYSTEM","events":[{"introduced":"3.28.0.CR1"},{"last_affected":"3.29.4"}]}
  INFO    FIX001  Maven io.quarkus:quarkus-vertx-http
          fix content checked against published artifacts
          - 3.20.6.1: contains (11/11 distinctive lines present)
          - 3.20.6: lacks (0/11 distinctive lines present)
          - 3.19.4: lacks (0/11 distinctive lines present)
          - 3.18.4: lacks (0/11 distinctive lines present)
          - 3.27.3.1: contains (11/11 distinctive lines present)
          - 3.27.3: lacks (0/11 distinctive lines present)
          - 3.26.4: lacks (0/11 distinctive lines present)
          - 3.25.4: lacks (0/11 distinctive lines present)
          - 3.33.1.1: contains (11/11 distinctive lines present)
          - 3.33.1: lacks (0/11 distinctive lines present)
          - 3.32.4: lacks (0/11 distinctive lines present)
          - 3.31.4: lacks (0/11 distinctive lines present)
          - 3.35.1: lacks (0/11 distinctive lines present)
          evidence: https://github.com/quarkusio/quarkus/commit/363d53a82a16b2b7c9de8d968694fd4d93e05062

1 advisories checked: 1 errors, 2 warnings, 1 info
```

## Real-world findings

These four errors in github/advisory-database were found by hand and are used
as test fixtures (the original files are in `testdata/advisories/`). isitfixed
reports each of them. Corrections were submitted upstream:

| Advisory | Problem | isitfixed | Submitted |
|---|---|---|---|
| [GHSA-w7c2-w76w-5hmj](https://github.com/advisories/GHSA-w7c2-w76w-5hmj) | The Cilium 1.18 range is attached to the misspelled module `github.com/cilium/ciliumCilium` (proxy.golang.org returns 404), so 1.18.0–1.18.10 of `github.com/cilium/cilium` are not marked affected. | PKG001 error; XDB001 against GO-2026-6596; RNG002 shows by content that the fix first appears in 1.18.11 | [#10239](https://github.com/github/advisory-database/pull/10239) |
| [GHSA-pg5p-wwp8-97g8](https://github.com/advisories/GHSA-pg5p-wwp8-97g8) | `last_affected: 1.10.0`, but 1.10.1–1.10.20 were published later and are unfixed: the fix (cilium/cilium@f490339) only reached 1.11.16+, and v1.10.20 still logs header values in `pkg/envoy/server.go`. | RNG001 warning listing 1.10.1 … 1.10.20; with `--fix-ref` it confirms 1.10.20 still contains the removed log line | [#10240](https://github.com/github/advisory-database/pull/10240) |
| [GHSA-2r2v-q399-qq93](https://github.com/advisories/GHSA-2r2v-q399-qq93) | Maven `fixed: 2.2.10.RELEASE0.5` does not exist; the fix shipped in 2.2.10.RELEASE. | VER001 error | [#10241](https://github.com/github/advisory-database/pull/10241) |
| [GHSA-rc95-pcm8-65v9](https://github.com/advisories/GHSA-rc95-pcm8-65v9) | `fixed: 3.35.1.1` does not exist; 3.34.7 already contains the backported fix but is inside a range; the 3.28.x and 3.29.x lines are vulnerable but not covered. | VER001 error; FIX001 warning (fix first appears in 3.34.7 and 3.35.2, with a suggested split); RNG002 warning for 3.28/3.29 confirmed by content | [#10242](https://github.com/github/advisory-database/pull/10242) |

## Limitations

- **Content matching needs source in the artifact.** npm packages that only
  ship transpiled or bundled code, and Maven artifacts without
  `-sources.jar`, often cannot be matched; FIX001 then says "unverifiable"
  rather than guessing. The class-file fallback is lower confidence.
- **FIX001 needs a fix reference on GitHub.** Many advisories link only to
  vendor pages; `--fix-ref` covers single advisories. GitLab and other forges
  are not supported yet.
- **Partial fixes.** When a fix spans several modules and the advisory names
  only one package, isitfixed can see only the part shipped in that package;
  such results are reported as info.
- **Absence of the fix is not proof of vulnerability.** For a purely additive
  fix, a version without the added lines may also never have had the
  vulnerable code. isitfixed says so instead of confirming the finding.
- **Heuristics.** RNG001/RNG002 encode common advisory-writing patterns
  (per-line ranges, mid-line introductions); they can be wrong for projects
  with unusual release histories. Treat warnings as leads to verify by hand.
- **Go module paths.** Repositories that moved (for example `lxc/lxd` →
  `canonical/lxd`) can make VER001 report versions that exist only as tags of
  the new repository.
- Release lines are `major.minor`, which does not fit every project's
  versioning.

## Roadmap

- A GitHub Action that runs isitfixed on changed advisory files in a pull
  request.
- More ecosystems (PyPI, RubyGems, NuGet, Packagist).
- GitLab and Bitbucket fix references.
- Automatic fix-commit discovery when an advisory references none.

## License

MIT, see [LICENSE](LICENSE). The advisory files in `testdata/advisories/` come
from github/advisory-database and are licensed under CC-BY 4.0.
