package finding

import (
	"encoding/json"
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
