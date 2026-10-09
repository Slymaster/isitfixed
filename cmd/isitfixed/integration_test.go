package main

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Slymaster/isitfixed/internal/check"
)

// TestIntegration runs the four real-world fixtures (original files from
// github/advisory-database at commit 166511f9123) against the live
// registries. Enable with ISITFIXED_NETWORK=1.
func TestIntegration(t *testing.T) {
	if os.Getenv("ISITFIXED_NETWORK") != "1" {
		t.Skip("set ISITFIXED_NETWORK=1 to run network integration tests")
	}
	type want struct {
		check    string
		severity check.Severity
		contains []string
	}
	cases := []struct {
		file  string
		extra []string
		code  int // 1 when an error-severity finding is expected
		wants []want
	}{
		{
			file: "GHSA-w7c2-w76w-5hmj.json",
			code: 1,
			wants: []want{
				{check.PKG001, check.Error, []string{"github.com/cilium/ciliumCilium was not found"}},
				{check.XDB001, check.Warning, []string{"GO-2026-6596", "github.com/cilium/ciliumCilium"}},
			},
		},
		{
			file: "GHSA-pg5p-wwp8-97g8.json",
			wants: []want{
				{check.RNG001, check.Warning, []string{"last_affected 1.10.0", "1.10.1", "1.10.20"}},
			},
		},
		{
			file: "GHSA-2r2v-q399-qq93.json",
			code: 1,
			wants: []want{
				{check.VER001, check.Error, []string{"2.2.10.RELEASE0.5"}},
			},
		},
		{
			// The advisory references no fix commit; the upstream fix is
			// supplied the way a user would, with --fix-ref.
			file:  "GHSA-rc95-pcm8-65v9.json",
			code:  1,
			extra: []string{"--fix-ref", "https://github.com/quarkusio/quarkus/commit/363d53a82a16b2b7c9de8d968694fd4d93e05062"},
			wants: []want{
				{check.VER001, check.Error, []string{"3.35.1.1"}},
				{check.RNG002, check.Warning, []string{"3.28", "3.29"}},
				{check.FIX001, check.Warning, []string{"already contain the fix", "3.34.7"}},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			args := append([]string{"--format", "json", "--file", "../../testdata/advisories/" + tc.file}, tc.extra...)
			var out, errb bytes.Buffer
			code := run(append([]string{"check"}, args...), &out, &errb)
			if code != tc.code {
				t.Errorf("exit code = %d, want %d; stderr: %s", code, tc.code, errb.String())
			}
			var rep struct {
				Advisories []struct {
					ID       string          `json:"id"`
					Error    string          `json:"error"`
					Findings []check.Finding `json:"findings"`
				} `json:"advisories"`
			}
			if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
				t.Fatalf("bad JSON: %v\n%s", err, out.String())
			}
			if len(rep.Advisories) != 1 || rep.Advisories[0].Error != "" {
				t.Fatalf("unexpected report: %s", out.String())
			}
			fs := rep.Advisories[0].Findings
			for _, w := range tc.wants {
				found := false
				for _, f := range fs {
					text := f.Package + " " + f.Message + " " + strings.Join(f.Details, " ")
					ok := f.Check == w.check && f.Severity == w.severity
					for _, c := range w.contains {
						ok = ok && strings.Contains(text, c)
					}
					found = found || ok
				}
				if !found {
					t.Errorf("missing %s %s finding containing %q in:\n%s", w.severity, w.check, w.contains, out.String())
				}
			}
		})
	}
}
