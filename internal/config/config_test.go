package config

import (
	"os"
	"path/filepath"
	"testing"

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
