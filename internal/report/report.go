// Package report renders scan results for people and machines.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/linus1423/Securety-Checker/internal/discovery"
	"github.com/linus1423/Securety-Checker/internal/finding"
)

// Result is everything a scan produced.
type Result struct {
	Root     string            `json:"root"`
	Files    []discovery.File  `json:"files"`
	Findings []finding.Finding `json:"findings"`
}

// Formats lists the supported output formats.
var Formats = []string{"text", "json", "sarif", "html", "cis"}

// Write renders the result in the given format.
func Write(w io.Writer, format string, r Result) error {
	switch format {
	case "text":
		return writeText(w, r)
	case "json":
		return writeJSON(w, r)
	case "sarif":
		return writeSARIF(w, r)
	case "html":
		return writeHTML(w, r)
	case "cis":
		return writeCIS(w, r)
	default:
		return fmt.Errorf("unknown format %q (expected %s)", format, strings.Join(Formats, ", "))
	}
}

func writeJSON(w io.Writer, r Result) error {
	if r.Files == nil {
		r.Files = []discovery.File{}
	}
	if r.Findings == nil {
		r.Findings = []finding.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func writeText(w io.Writer, r Result) error {
	fmt.Fprintf(w, "Scanned %s: %d relevant file(s)\n", r.Root, len(r.Files))
	if len(r.Files) > 0 {
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, f := range r.Files {
			fmt.Fprintf(tw, "  %s\t%s\n", f.Kind, f.Path)
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if len(r.Findings) == 0 {
		_, err := fmt.Fprintln(w, "No findings.")
		return err
	}
	fmt.Fprintf(w, "\n%d finding(s):\n", len(r.Findings))
	for _, f := range r.Findings {
		loc := f.Location.File
		if f.Location.Line > 0 {
			loc = fmt.Sprintf("%s:%d", loc, f.Location.Line)
		}
		title := f.Title
		if f.Confidence != finding.ConfidenceHigh {
			title = fmt.Sprintf("%s (confidence: %s)", title, f.Confidence)
		}
		fmt.Fprintf(w, "  [%s] %s %s: %s\n", f.Severity, f.RuleID, loc, title)
		if f.Remediation != "" {
			fmt.Fprintf(w, "      fix: %s\n", f.Remediation)
		}
		if len(f.References) > 0 {
			fmt.Fprintf(w, "      see: %s\n", f.References[0])
		}
	}
	_, err := fmt.Fprintf(w, "\nSummary: %s\n", finding.Summary(r.Findings))
	return err
}
