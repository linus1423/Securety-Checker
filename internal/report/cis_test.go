package report

import (
	"strings"
	"testing"

	"github.com/linus1423/Securety-Checker/internal/finding"
)

func TestWriteCIS(t *testing.T) {
	var b strings.Builder
	// A DF001 finding fails CIS 4.1; everything else should pass.
	r := Result{
		Root:     "demo",
		Findings: []finding.Finding{{RuleID: "DF001", Severity: finding.SeverityHigh, Location: finding.Location{File: "Dockerfile"}}},
	}
	if err := Write(&b, "cis", r); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "4.1") || !strings.Contains(out, "FAIL") {
		t.Errorf("expected CIS 4.1 FAIL in output:\n%s", out)
	}
	if !strings.Contains(out, "PASS") {
		t.Errorf("expected some PASS rows in output:\n%s", out)
	}
	if !strings.Contains(out, "CIS-Kontrollen erfüllt") {
		t.Errorf("expected a summary line:\n%s", out)
	}
}

func TestWriteCISAllPass(t *testing.T) {
	var b strings.Builder
	if err := Write(&b, "cis", Result{Root: "clean"}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, "FAIL") {
		t.Errorf("clean scan should have no FAIL rows:\n%s", out)
	}
}
