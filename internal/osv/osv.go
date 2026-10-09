// Package osv holds the subset of the OSV schema isitfixed reads, plus
// loaders for files, directories and the osv.dev API.
package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/Slymaster/isitfixed/internal/httpx"
)

// Vuln is an OSV record.
type Vuln struct {
	ID               string          `json:"id"`
	Modified         string          `json:"modified,omitempty"`
	Published        string          `json:"published,omitempty"`
	Withdrawn        string          `json:"withdrawn,omitempty"`
	Aliases          []string        `json:"aliases,omitempty"`
	Related          []string        `json:"related,omitempty"`
	Summary          string          `json:"summary,omitempty"`
	Affected         []Affected      `json:"affected,omitempty"`
	References       []Reference     `json:"references,omitempty"`
	DatabaseSpecific json.RawMessage `json:"database_specific,omitempty"`

	// Path is the local file the record was read from, if any.
	Path string `json:"-"`
}

// Affected is one affected[] entry.
type Affected struct {
	Package  Package  `json:"package"`
	Ranges   []Range  `json:"ranges,omitempty"`
	Versions []string `json:"versions,omitempty"`
}

// Package identifies a package.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}

// Range is an affected range.
type Range struct {
	Type   string  `json:"type"`
	Repo   string  `json:"repo,omitempty"`
	Events []Event `json:"events"`
}

// Event is a range event; exactly one field is set.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Reference is a reference URL.
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// CWEs returns database_specific.cwe_ids (GitHub advisories).
func (v *Vuln) CWEs() []string {
	var ds struct {
		CWEIDs []string `json:"cwe_ids"`
	}
	_ = json.Unmarshal(v.DatabaseSpecific, &ds)
	return ds.CWEIDs
}

// IsMalware reports whether the record describes a malicious package rather
// than a vulnerability (CWE-506 or a "Malware in …" summary). Range checks do
// not apply to those.
func (v *Vuln) IsMalware() bool {
	for _, c := range v.CWEs() {
		if c == "CWE-506" {
			return true
		}
	}
	return strings.HasPrefix(v.ID, "MAL-") || strings.HasPrefix(strings.ToLower(v.Summary), "malware in ")
}

// ParseFile reads one OSV JSON file.
func ParseFile(path string) (*Vuln, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v Vuln
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if v.ID == "" {
		return nil, fmt.Errorf("%s: not an OSV record (no id)", path)
	}
	v.Path = path
	return &v, nil
}

// WalkDir returns the paths of all .json files under root, sorted.
func WalkDir(root string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && strings.HasPrefix(d.Name(), ".") && p != root {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".json") {
			out = append(out, p)
		}
		return nil
	})
	return out, err
}

// HasEcosystem reports whether any affected entry is in eco.
func (v *Vuln) HasEcosystem(eco string) bool {
	for _, a := range v.Affected {
		if strings.EqualFold(a.Package.Ecosystem, eco) {
			return true
		}
	}
	return false
}

// API fetches records from osv.dev.
type API struct {
	HTTP *httpx.Client
	Base string // default https://api.osv.dev
}

// Get fetches one record by ID. A missing record returns httpx.ErrNotFound.
func (a *API) Get(ctx context.Context, id string) (*Vuln, error) {
	base := a.Base
	if base == "" {
		base = "https://api.osv.dev"
	}
	resp, err := a.HTTP.Get(ctx, httpx.Request{URL: base + "/v1/vulns/" + id})
	if err != nil {
		return nil, err
	}
	var v Vuln
	if err := json.Unmarshal(resp.Body, &v); err != nil {
		return nil, fmt.Errorf("osv.dev %s: %w", id, err)
	}
	return &v, nil
}

// URL returns the osv.dev web URL of a record.
func URL(id string) string { return "https://osv.dev/vulnerability/" + id }
