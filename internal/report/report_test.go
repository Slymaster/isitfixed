package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Slymaster/isitfixed/internal/check"
	"github.com/Slymaster/isitfixed/internal/osv"
)

func sample() []Advisory {
	return []Advisory{{ID: "GHSA-1", Summary: "s", Findings: []check.Finding{{
		Advisory: "GHSA-1", Check: check.IF002, Slug: "version-missing", Severity: check.Error, Ecosystem: "Maven", Package: "g:a",
		Message: "fixed version 1.0.1 is not published", Evidence: []string{"https://example/x"},
		Suggested: [][]osv.Event{{{Introduced: "0"}, {Fixed: "1.0.2"}}},
	}}}, {ID: "GHSA-2"}}
}

func TestText(t *testing.T) {
	var b bytes.Buffer
	Text(&b, sample(), false)
	out := b.String()
	for _, want := range []string{"GHSA-1  s", "ERROR   IF002 version-missing  Maven g:a", "evidence: https://example/x",
		`{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"1.0.2"}]}`, "2 advisories checked: 1 errors"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "GHSA-2") {
		t.Error("advisories without findings are hidden unless verbose")
	}
}

func TestTextFailedAndSkipped(t *testing.T) {
	var b bytes.Buffer
	Text(&b, []Advisory{
		{ID: "GHSA-f", Findings: []check.Finding{{Check: check.IF001, Severity: check.Failed, Message: "could not check: package lookup on repo1.maven.org failed"}}},
		{ID: "GHSA-p", Skipped: "no package in a supported ecosystem (PyPI)"},
	}, false)
	out := b.String()
	for _, want := range []string{"FAILED  IF001", "GHSA-p  skipped: no package in a supported ecosystem (PyPI)", "1 could not be checked (exit status 2)", "1 skipped"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	b.Reset()
	Text(&b, sample()[:1], false)
	if !strings.Contains(b.String(), "1 advisory checked") {
		t.Errorf("singular: %s", b.String())
	}
}

func TestJSON(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, "test", sample()); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Advisories []Advisory
		Totals     Totals
	}
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Totals.Errors != 1 || got.Totals.ByCheck["IF002/error"] != 1 || got.Advisories[1].Findings == nil {
		t.Errorf("totals = %+v", got.Totals)
	}
}
