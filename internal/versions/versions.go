// Package versions wraps OSV ecosystem version semantics (from
// github.com/google/osv-scalibr/semantic) with the few helpers isitfixed
// needs: comparison, equality, sorting and "release line" keys.
package versions

import (
	"regexp"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/semantic"
)

// Supported ecosystems.
const (
	Go     = "Go"
	Npm    = "npm"
	Maven  = "Maven"
	Crates = "crates.io"
)

// Supported reports whether isitfixed knows how to handle the ecosystem.
func Supported(eco string) bool {
	switch eco {
	case Go, Npm, Maven, Crates:
		return true
	}
	return false
}

// Normalize returns the canonical OSV spelling of a version for the
// ecosystem. For Go it strips a leading "v" and a "+incompatible" suffix, so
// that proxy.golang.org versions compare equal to OSV versions.
func Normalize(eco, v string) string {
	v = strings.TrimSpace(v)
	if eco == Go {
		v = strings.TrimPrefix(v, "v")
		v = strings.TrimSuffix(v, "+incompatible")
	}
	return v
}

// Compare returns -1, 0 or +1 comparing a and b under the ecosystem's rules.
// Unparseable versions fall back to string comparison so that ordering is
// always total.
func Compare(eco, a, b string) int {
	a, b = Normalize(eco, a), Normalize(eco, b)
	if a == b {
		return 0
	}
	if a == "0" {
		return -1
	}
	if b == "0" {
		return 1
	}
	pa, err := semantic.Parse(a, eco)
	if err == nil {
		if c, err := pa.CompareStr(b); err == nil {
			return c
		}
	}
	return strings.Compare(a, b)
}

// Equal reports whether a and b are the same version under the ecosystem's
// ordering (e.g. Maven "2.2.0" equals "2.2.0.RELEASE").
func Equal(eco, a, b string) bool { return Compare(eco, a, b) == 0 }

// Sort sorts versions ascending in place.
func Sort(eco string, vs []string) {
	slices.SortStableFunc(vs, func(a, b string) int { return Compare(eco, a, b) })
}

var numRe = regexp.MustCompile(`^[0-9]+`)

// Line returns the release-line key of a version: "major.minor" built from
// the leading numeric components. Versions with a single numeric component
// form their own line ("20230101"). Returns "" when the version has no
// leading number.
func Line(eco, v string) string {
	v = Normalize(eco, v)
	parts := strings.FieldsFunc(v, func(r rune) bool { return r == '.' || r == '-' || r == '+' || r == '_' })
	var nums []string
	for i, p := range parts {
		m := numRe.FindString(p)
		if m == "" {
			break
		}
		nums = append(nums, trimZeros(m))
		if m != p || len(nums) == 2 || i == len(parts)-1 {
			break
		}
	}
	return strings.Join(nums, ".")
}

func trimZeros(s string) string {
	t := strings.TrimLeft(s, "0")
	if t == "" {
		return "0"
	}
	return t
}

// IsPrerelease reports whether a version carries a pre-release marker
// (semver "-…" for Go/npm/crates; alpha/beta/milestone/rc/cr/snapshot for
// Maven).
func IsPrerelease(eco, v string) bool {
	v = Normalize(eco, v)
	switch eco {
	case Maven:
		toks := mavenTokens(strings.ToLower(v))
		for i, t := range toks {
			switch t {
			case "alpha", "beta", "milestone", "rc", "cr", "snapshot", "preview", "ea", "dev", "pre":
				return true
			case "a", "b", "m":
				if i+1 < len(toks) && numRe.MatchString(toks[i+1]) {
					return true
				}
			}
		}
		return false
	default:
		core, _, _ := strings.Cut(v, "+")
		return strings.Contains(core, "-")
	}
}

// mavenTokens splits a lower-cased Maven version at separators and at
// letter/digit transitions ("3.0.0-rc1" -> 3 0 0 rc 1).
func mavenTokens(v string) []string {
	var toks []string
	cur := []rune{}
	flush := func() {
		if len(cur) > 0 {
			toks = append(toks, string(cur))
			cur = cur[:0]
		}
	}
	isDigit := func(r rune) bool { return r >= '0' && r <= '9' }
	for _, r := range v {
		if r == '.' || r == '-' || r == '_' || r == '+' {
			flush()
			continue
		}
		if len(cur) > 0 && isDigit(cur[len(cur)-1]) != isDigit(r) {
			flush()
		}
		cur = append(cur, r)
	}
	flush()
	return toks
}
