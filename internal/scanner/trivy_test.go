package scanner

import (
	"testing"

	"github.com/linus1423/Securety-Checker/internal/finding"
)

const imageJSON = `{
  "Results": [
    {
      "Target": "nginx:latest (debian 12.1)",
      "Class": "os-pkgs",
      "Vulnerabilities": [
        {
          "VulnerabilityID": "CVE-2023-1234",
          "PkgName": "openssl",
          "InstalledVersion": "3.0.9-1",
          "FixedVersion": "3.0.11-1",
          "Severity": "CRITICAL",
          "Title": "openssl: buffer overflow",
          "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-1234"
        },
        {
          "VulnerabilityID": "CVE-2022-9999",
          "PkgName": "zlib",
          "InstalledVersion": "1.2.13",
          "Severity": "LOW"
        }
      ],
      "Secrets": [
        {"RuleID": "aws-access-key-id", "Category": "AWS", "Severity": "HIGH", "Title": "AWS Access Key", "StartLine": 12}
      ]
    }
  ]
}`

func TestParseImageReport(t *testing.T) {
	fs, err := parseReport([]byte(imageJSON), locatorImage, "nginx:latest")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 3 {
		t.Fatalf("got %d findings, want 3", len(fs))
	}
	var crit, secret bool
	for _, f := range fs {
		if f.Location.File != "nginx:latest" {
			t.Errorf("finding location = %q, want image ref", f.Location.File)
		}
		if f.RuleID == "TRIVY-VULN" && f.Severity == finding.SeverityCritical {
			crit = true
			if f.Remediation == "" {
				t.Error("critical vuln has no remediation")
			}
		}
		if f.RuleID == "TRIVY-SECRET" {
			secret = true
			if f.Severity != finding.SeverityHigh || f.Location.Line != 12 {
				t.Errorf("secret finding wrong: %+v", f)
			}
		}
	}
	if !crit || !secret {
		t.Errorf("missing expected findings: crit=%v secret=%v", crit, secret)
	}
}

func TestParseFilesystemSecrets(t *testing.T) {
	const fsJSON = `{"Results":[{"Target":".env","Class":"secret","Secrets":[{"RuleID":"generic-token","Category":"general","Severity":"MEDIUM","Title":"Token","StartLine":3}]}]}`
	fs, err := parseReport([]byte(fsJSON), locatorFile, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Location.File != ".env" || fs[0].Location.Line != 3 {
		t.Fatalf("unexpected fs secret findings: %+v", fs)
	}
}

func TestParseEmpty(t *testing.T) {
	for _, in := range []string{"", "   ", `{"Results":[]}`, `{"Results":[{"Target":"x"}]}`} {
		fs, err := parseReport([]byte(in), locatorImage, "x")
		if err != nil || len(fs) != 0 {
			t.Errorf("parseReport(%q) = %v, %v; want 0 findings, nil", in, fs, err)
		}
	}
}

func TestMapSeverity(t *testing.T) {
	cases := map[string]finding.Severity{
		"CRITICAL": finding.SeverityCritical,
		"high":     finding.SeverityHigh,
		"Medium":   finding.SeverityMedium,
		"LOW":      finding.SeverityLow,
		"UNKNOWN":  finding.SeverityInfo,
		"":         finding.SeverityInfo,
	}
	for in, want := range cases {
		if got := mapSeverity(in); got != want {
			t.Errorf("mapSeverity(%q) = %v, want %v", in, got, want)
		}
	}
}
