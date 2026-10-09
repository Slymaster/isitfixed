package osv

import (
	"path/filepath"
	"testing"
)

func TestParseFixture(t *testing.T) {
	v, err := ParseFile(filepath.Join("..", "..", "testdata", "advisories", "GHSA-rc95-pcm8-65v9.json"))
	if err != nil {
		t.Fatal(err)
	}
	if v.ID != "GHSA-rc95-pcm8-65v9" || len(v.Affected) != 4 || !v.HasEcosystem("Maven") || v.IsMalware() {
		t.Fatalf("unexpected record: %+v", v)
	}
	if got := v.Affected[3].Ranges[0].Events[1].Fixed; got != "3.35.1.1" {
		t.Errorf("fixed = %q", got)
	}
	if cwes := v.CWEs(); len(cwes) != 3 {
		t.Errorf("CWEs = %v", cwes)
	}
	paths, err := WalkDir(filepath.Join("..", "..", "testdata", "advisories"))
	if err != nil || len(paths) != 4 {
		t.Errorf("WalkDir = %v, %v", paths, err)
	}
}

func TestIsMalware(t *testing.T) {
	if !(&Vuln{ID: "GHSA-x", Summary: "Malware in foo"}).IsMalware() {
		t.Error("summary")
	}
	if !(&Vuln{ID: "GHSA-x", DatabaseSpecific: []byte(`{"cwe_ids":["CWE-506"]}`)}).IsMalware() {
		t.Error("CWE-506")
	}
}
