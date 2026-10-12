package finding

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseSeverity(t *testing.T) {
	for i, name := range []string{"info", "LOW", " medium ", "High", "critical"} {
		got, err := ParseSeverity(name)
		if err != nil || got != Severity(i) {
			t.Errorf("ParseSeverity(%q) = %v, %v; want %v", name, got, err, Severity(i))
		}
	}
	if _, err := ParseSeverity("severe"); err == nil {
		t.Error("ParseSeverity(\"severe\") returned no error")
	}
}

func TestSeverityJSON(t *testing.T) {
	b, err := json.Marshal(Finding{RuleID: "X", Severity: SeverityHigh})
	if err != nil {
		t.Fatal(err)
	}
	var f Finding
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if f.Severity != SeverityHigh {
		t.Errorf("round trip severity = %v, want high (json %s)", f.Severity, b)
	}
}

func TestSortAndThreshold(t *testing.T) {
	fs := []Finding{
		{RuleID: "B", Severity: SeverityLow, Location: Location{File: "a", Line: 2}},
		{RuleID: "A", Severity: SeverityCritical, Location: Location{File: "b", Line: 1}},
		{RuleID: "C", Severity: SeverityLow, Location: Location{File: "a", Line: 1}},
	}
	Sort(fs)
	got := fs[0].RuleID + fs[1].RuleID + fs[2].RuleID
	if got != "ACB" {
		t.Errorf("sorted order = %s, want ACB", got)
	}
	if !AnyAtLeast(fs, SeverityHigh) || AnyAtLeast(fs[1:], SeverityMedium) {
		t.Error("AnyAtLeast returned wrong result")
	}
}

func TestDedup(t *testing.T) {
	fs := []Finding{
		{RuleID: "A", Severity: SeverityHigh, Location: Location{File: "x", Line: 1}, Message: "m"},
		{RuleID: "A", Severity: SeverityHigh, Location: Location{File: "x", Line: 1}, Message: "m"}, // exact dup
		{RuleID: "A", Severity: SeverityHigh, Location: Location{File: "x", Line: 1}, Message: "n"}, // different message: kept
		{RuleID: "B", Severity: SeverityLow, Location: Location{File: "x", Line: 1}, Message: "m"},  // different rule: kept
	}
	got := Dedup(fs)
	if len(got) != 3 {
		t.Fatalf("Dedup kept %d, want 3: %+v", len(got), got)
	}
	// Order is preserved (first occurrence first).
	if got[0].Message != "m" || got[1].Message != "n" || got[2].RuleID != "B" {
		t.Errorf("Dedup changed order/content: %+v", got)
	}
	// Dedup must not mutate the caller's slice contents.
	if fs[2].Message != "n" {
		t.Error("Dedup mutated the input slice")
	}
}

func TestConfidenceJSON(t *testing.T) {
	// High is the zero value and is omitted from JSON.
	b, _ := json.Marshal(Finding{RuleID: "X", Confidence: ConfidenceHigh})
	if strings.Contains(string(b), "confidence") {
		t.Errorf("high confidence should be omitted: %s", b)
	}
	b, _ = json.Marshal(Finding{RuleID: "X", Confidence: ConfidenceMedium})
	var f Finding
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if f.Confidence != ConfidenceMedium {
		t.Errorf("round trip confidence = %v, want medium (json %s)", f.Confidence, b)
	}
}

func TestReferenceURLAndEnrich(t *testing.T) {
	if ReferenceURL("DF003") == "" || ReferenceURL("CMP007") == "" || ReferenceURL("ATK-SQLI") == "" {
		t.Error("expected reference URLs for known rule prefixes")
	}
	if ReferenceURL("UNKNOWN123") != "" {
		t.Error("expected no reference URL for an unknown prefix")
	}
	fs := []Finding{
		{RuleID: "DF003"},
		{RuleID: "CMP007", References: []string{"https://example.test/custom"}},
	}
	EnrichReferences(fs)
	if len(fs[0].References) != 1 || fs[0].References[0] == "" {
		t.Errorf("DF003 should get a default reference, got %+v", fs[0].References)
	}
	if fs[1].References[0] != "https://example.test/custom" {
		t.Error("EnrichReferences must not overwrite an explicit reference")
	}
}

func TestFingerprints(t *testing.T) {
	fs := []Finding{
		{RuleID: "A", Location: Location{File: "x", Line: 1}},
		{RuleID: "A", Location: Location{File: "x", Line: 2}},
	}
	fps := Fingerprints(fs)
	if len(fps) != 2 || fps[0] == fps[1] {
		t.Errorf("Fingerprints = %v, want two distinct", fps)
	}
	if fps[0] != fs[0].Fingerprint() {
		t.Error("Fingerprints disagree with Finding.Fingerprint")
	}
}

func TestSummary(t *testing.T) {
	if s := Summary(nil); s != "" {
		t.Errorf("Summary(nil) = %q, want empty", s)
	}
	fs := []Finding{
		{Severity: SeverityCritical}, {Severity: SeverityCritical},
		{Severity: SeverityHigh}, {Severity: SeverityLow},
	}
	if s := Summary(fs); s != "2 critical, 1 high, 1 low" {
		t.Errorf("Summary = %q", s)
	}
}
