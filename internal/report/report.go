// Package report renders findings as text or JSON.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/Slymaster/isitfixed/internal/check"
	"github.com/Slymaster/isitfixed/internal/osv"
)

// Advisory is the result for one advisory.
type Advisory struct {
	ID       string          `json:"id"`
	Summary  string          `json:"summary,omitempty"`
	Source   string          `json:"source,omitempty"`
	Error    string          `json:"error,omitempty"`
	Findings []check.Finding `json:"findings"`
}

// Totals counts findings by severity.
type Totals struct {
	Advisories int            `json:"advisories"`
	Failed     int            `json:"failed"`
	Errors     int            `json:"errors"`
	Warnings   int            `json:"warnings"`
	Infos      int            `json:"infos"`
	ByCheck    map[string]int `json:"by_check"`
}

// Count computes totals.
func Count(as []Advisory) Totals {
	t := Totals{Advisories: len(as), ByCheck: map[string]int{}}
	for _, a := range as {
		if a.Error != "" {
			t.Failed++
		}
		for _, f := range a.Findings {
			switch f.Severity {
			case check.Error:
				t.Errors++
			case check.Warning:
				t.Warnings++
			default:
				t.Infos++
			}
			t.ByCheck[f.Check+"/"+string(f.Severity)]++
		}
	}
	return t
}

// JSON writes a machine-readable report.
func JSON(w io.Writer, version string, as []Advisory) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	for i := range as {
		if as[i].Findings == nil {
			as[i].Findings = []check.Finding{}
		}
	}
	return enc.Encode(struct {
		Tool       string     `json:"tool"`
		Version    string     `json:"version"`
		Advisories []Advisory `json:"advisories"`
		Totals     Totals     `json:"totals"`
	}{"isitfixed", version, as, Count(as)})
}

// Text writes a human-readable report grouped by advisory. Advisories
// without findings are listed only when verbose is set.
func Text(w io.Writer, as []Advisory, verbose bool) {
	for _, a := range as {
		if len(a.Findings) == 0 && a.Error == "" && !verbose {
			continue
		}
		title := a.ID
		if a.Summary != "" {
			title += "  " + a.Summary
		}
		fmt.Fprintln(w, title)
		if a.Source != "" && a.Source != a.ID {
			fmt.Fprintf(w, "  source: %s\n", a.Source)
		}
		if a.Error != "" {
			fmt.Fprintf(w, "  failed: %s\n", a.Error)
		}
		if len(a.Findings) == 0 && a.Error == "" {
			fmt.Fprintln(w, "  no findings")
		}
		for _, f := range a.Findings {
			pkg := strings.TrimSpace(f.Ecosystem + " " + f.Package)
			conf := ""
			if f.Confidence != "" {
				conf = " [" + f.Confidence + " confidence: compiled classes]"
			}
			fmt.Fprintf(w, "  %-7s %s  %s%s\n", strings.ToUpper(string(f.Severity)), f.Check, pkg, conf)
			fmt.Fprintf(w, "          %s\n", f.Message)
			for _, d := range f.Details {
				fmt.Fprintf(w, "          - %s\n", d)
			}
			for _, e := range f.Evidence {
				if e != "" {
					fmt.Fprintf(w, "          evidence: %s\n", e)
				}
			}
			if len(f.Suggested) > 0 {
				fmt.Fprintln(w, "          suggested ranges:")
				for _, r := range f.Suggested {
					b, _ := json.Marshal(struct {
						Type   string      `json:"type"`
						Events []osv.Event `json:"events"`
					}{"ECOSYSTEM", r})
					fmt.Fprintf(w, "            %s\n", b)
				}
			}
		}
		fmt.Fprintln(w)
	}
	t := Count(as)
	fmt.Fprintf(w, "%d advisories checked: %d errors, %d warnings, %d info", t.Advisories, t.Errors, t.Warnings, t.Infos)
	if t.Failed > 0 {
		fmt.Fprintf(w, ", %d could not be checked", t.Failed)
	}
	fmt.Fprintln(w)
}
