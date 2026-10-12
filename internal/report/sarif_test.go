package report

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/linus1423/Securety-Checker/internal/finding"
)

func TestWriteSARIF(t *testing.T) {
	r := Result{Findings: []finding.Finding{
		{RuleID: "CMP007", Title: "Docker socket", Severity: finding.SeverityCritical, Location: finding.Location{File: "compose.yml", Line: 5}, Remediation: "Remove the socket mount."},
		{RuleID: "DF007", Title: "No healthcheck", Severity: finding.SeverityLow, Location: finding.Location{File: "Dockerfile"}},
	}}
	var buf bytes.Buffer
	if err := writeSARIF(&buf, r); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("invalid SARIF JSON: %v", err)
	}
	if len(log.Runs) != 1 || len(log.Runs[0].Results) != 2 || len(log.Runs[0].Tool.Driver.Rules) != 2 {
		t.Fatalf("unexpected SARIF shape: %+v", log.Runs)
	}
	if log.Runs[0].Results[0].Level != "error" {
		t.Errorf("critical finding level = %q, want error", log.Runs[0].Results[0].Level)
	}
	if log.Runs[0].Results[0].Locations[0].PhysicalLocation.Region.StartLine != 5 {
		t.Error("missing start line in SARIF location")
	}
	// Stable partial fingerprint for baseline/dedup in code scanning.
	fp := log.Runs[0].Results[0].PartialFingerprints["secchkFingerprint/v1"]
	if fp == "" || fp != r.Findings[0].Fingerprint() {
		t.Errorf("partialFingerprint = %q, want %q", fp, r.Findings[0].Fingerprint())
	}
	// Remediation flows into the rule's fullDescription.
	if d := log.Runs[0].Tool.Driver.Rules[0].FullDescription; d == nil || d.Text != "Remove the socket mount." {
		t.Errorf("rule fullDescription = %+v, want remediation text", d)
	}
}

func TestSARIFEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := writeSARIF(&buf, Result{}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(buf.Bytes(), []byte(`"results": []`)) {
		t.Errorf("empty SARIF should have an empty results array:\n%s", buf.String())
	}
}
