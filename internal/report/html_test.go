package report

import (
	"strings"
	"testing"

	"github.com/linus1423/Securety-Checker/internal/discovery"
	"github.com/linus1423/Securety-Checker/internal/finding"
)

func TestWriteHTMLFindings(t *testing.T) {
	var b strings.Builder
	r := Result{
		Root:  "demo",
		Files: []discovery.File{{Kind: discovery.KindCompose, Path: "docker-compose.yml"}},
		Findings: []finding.Finding{
			{
				RuleID: "ATK-SQLI", Title: "Mögliche SQL-Injection",
				Severity: finding.SeverityHigh, Confidence: finding.ConfidenceMedium,
				Location:   finding.Location{File: "http://x/?id=", Line: 0},
				Message:    "<script>alert(1)</script>", // must be escaped
				References: []string{"https://owasp.org/"},
			},
		},
	}
	if err := Write(&b, "html", r); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"<!doctype html>", "ATK-SQLI", "b-high", "confidence: medium", "https://owasp.org/", "secchk Security Report"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML report should contain %q", want)
		}
	}
	// The dangerous message must be HTML-escaped, not rendered as a tag.
	if strings.Contains(out, "<script>alert(1)</script>") {
		t.Error("HTML report must escape finding content")
	}
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("expected escaped script tag in output")
	}
}

func TestWriteHTMLEmpty(t *testing.T) {
	var b strings.Builder
	if err := Write(&b, "html", Result{Root: "demo"}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "Keine Befunde.") {
		t.Errorf("empty report should say so, got %q", out)
	}
}

func TestHTMLIsAFormat(t *testing.T) {
	found := false
	for _, f := range Formats {
		if f == "html" {
			found = true
		}
	}
	if !found {
		t.Error("html should be a supported format")
	}
}
