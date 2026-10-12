package check

import (
	"sort"
	"testing"

	"github.com/linus1423/Securety-Checker/internal/discovery"
	"github.com/linus1423/Securety-Checker/internal/finding"
)

func scan(t *testing.T, root string) []finding.Finding {
	t.Helper()
	files, err := discovery.Walk(root)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := Run(root, files)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}

func ruleSet(fs []finding.Finding) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.RuleID] = true
	}
	return m
}

func TestBadFixtureFiresRules(t *testing.T) {
	got := ruleSet(scan(t, "testdata/bad"))
	want := []string{
		"DF001", "DF002", "DF003", "DF004", "DF005", "DF006", "DF007", "DF008", "DF009",
		"CMP001", "CMP002", "CMP003", "CMP004", "CMP006", "CMP007", "CMP008", "CMP010", "CMP011", "CMP013", "CMP014",
	}
	for _, id := range want {
		if !got[id] {
			t.Errorf("expected rule %s to fire on the bad fixture", id)
		}
	}
}

func TestGoodFixtureIsClean(t *testing.T) {
	fs := scan(t, "testdata/good")
	if len(fs) != 0 {
		ids := make([]string, 0, len(fs))
		for _, f := range fs {
			ids = append(ids, f.RuleID+"@"+f.Location.File)
		}
		sort.Strings(ids)
		t.Errorf("expected no findings on the good fixture, got %v", ids)
	}
}

func TestFindingsHaveMetadata(t *testing.T) {
	for _, f := range scan(t, "testdata/bad") {
		if f.Title == "" || f.Severity.String() == "" || f.Location.File == "" {
			t.Errorf("finding %s is missing metadata: %+v", f.RuleID, f)
		}
		if f.RuleID != "PARSE" && f.Remediation == "" {
			t.Errorf("rule %s has no remediation", f.RuleID)
		}
	}
}

func TestEveryRuleHasUniqueID(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range DockerfileRules {
		if seen[r.ID] {
			t.Errorf("duplicate rule ID %s", r.ID)
		}
		seen[r.ID] = true
	}
	for _, r := range ComposeRules {
		if seen[r.ID] {
			t.Errorf("duplicate rule ID %s", r.ID)
		}
		seen[r.ID] = true
	}
}

func TestParsePort(t *testing.T) {
	cases := []struct{ in, ip, port string }{
		{"8080", "", "8080"},
		{"8080:80", "0.0.0.0", "80"},
		{"127.0.0.1:5432:5432", "127.0.0.1", "5432"},
		{"5432:5432/tcp", "0.0.0.0", "5432"},
	}
	for _, c := range cases {
		ip, port := parsePort(c.in)
		if ip != c.ip || port != c.port {
			t.Errorf("parsePort(%q) = %q,%q; want %q,%q", c.in, ip, port, c.ip, c.port)
		}
	}
}
