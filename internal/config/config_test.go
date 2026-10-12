package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/linus1423/Securety-Checker/internal/finding"
)

func TestLoadMissing(t *testing.T) {
	c, err := Load(t.TempDir())
	if err != nil || c.FailOn != "" || len(c.Ignore.Rules) != 0 {
		t.Fatalf("expected empty config, got %+v, err %v", c, err)
	}
}

func TestLoadAndApply(t *testing.T) {
	dir := t.TempDir()
	drop := finding.Finding{RuleID: "CMP001", Location: finding.Location{File: "a.yml", Line: 2}}
	cfgYAML := "fail_on: medium\nignore:\n  rules: [DF003]\n  paths: [\"deploy/**\", \"*.env\"]\nbaseline: [\"" + drop.Fingerprint() + "\"]\n"
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(cfgYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.FailOn != "medium" {
		t.Errorf("FailOn = %q, want medium", c.FailOn)
	}
	in := []finding.Finding{
		{RuleID: "DF003", Location: finding.Location{File: "Dockerfile"}},        // ignored by rule
		{RuleID: "DF001", Location: finding.Location{File: "deploy/x.yml"}},      // ignored by path **
		{RuleID: "DF006", Location: finding.Location{File: "deploy/secret.env"}}, // ignored by *.env base
		drop, // ignored by baseline
		{RuleID: "DF002", Location: finding.Location{File: "Dockerfile", Line: 1}}, // kept
	}
	got := c.Apply(in)
	if len(got) != 1 || got[0].RuleID != "DF002" {
		t.Errorf("Apply kept %+v, want only DF002", got)
	}
}

func TestSeverityOverride(t *testing.T) {
	c := &Config{SeverityOverrides: map[string]string{"DF007": "high"}}
	in := []finding.Finding{{RuleID: "DF007", Severity: finding.SeverityLow, Location: finding.Location{File: "Dockerfile"}}}
	got := c.Apply(in)
	if len(got) != 1 || got[0].Severity != finding.SeverityHigh {
		t.Fatalf("expected DF007 remapped to high, got %+v", got)
	}
}

func TestExceptionSuppressesUntilExpiry(t *testing.T) {
	c := &Config{Exceptions: []Exception{
		{Rule: "DF001", Path: "legacy/**", Reason: "wird migriert", Expires: "2030-01-01"},
		{Rule: "CMP007", Reason: "akzeptiert, kein Ablauf"},
	}}
	in := []finding.Finding{
		{RuleID: "DF001", Location: finding.Location{File: "legacy/Dockerfile"}}, // excepted (path + not expired)
		{RuleID: "DF001", Location: finding.Location{File: "app/Dockerfile"}},    // kept (path mismatch)
		{RuleID: "CMP007", Location: finding.Location{File: "compose.yml"}},      // excepted (no expiry, any path)
	}
	now := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	got := c.applyAt(in, now)
	if len(got) != 1 || got[0].Location.File != "app/Dockerfile" {
		t.Fatalf("expected only app/Dockerfile kept, got %+v", got)
	}
}

func TestExpiredExceptionResurfaces(t *testing.T) {
	c := &Config{Exceptions: []Exception{{Rule: "DF001", Reason: "temporär", Expires: "2025-01-01"}}}
	in := []finding.Finding{{RuleID: "DF001", Location: finding.Location{File: "Dockerfile"}}}
	now := time.Date(2026, 10, 12, 0, 0, 0, 0, time.UTC)
	if got := c.applyAt(in, now); len(got) != 1 {
		t.Fatalf("expired exception should not suppress, got %+v", got)
	}
}

func TestLoadRejectsBadPolicy(t *testing.T) {
	dir := t.TempDir()
	bad := "severity_overrides:\n  DF007: supercritical\n"
	if err := os.WriteFile(filepath.Join(dir, FileName), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("expected Load to reject an unknown severity in severity_overrides")
	}

	dir2 := t.TempDir()
	bad2 := "exceptions:\n  - rule: DF001\n    expires: nope\n"
	if err := os.WriteFile(filepath.Join(dir2, FileName), []byte(bad2), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir2); err == nil {
		t.Fatal("expected Load to reject a malformed expiry date")
	}
}
