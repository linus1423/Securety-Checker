package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func run(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := Execute(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestScanCleanProject(t *testing.T) {
	code, out, _ := run("scan", "../check/testdata/good")
	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d\n%s", code, ExitOK, out)
	}
	for _, want := range []string{"2 relevant file(s)", "compose.yaml", "No findings."} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestScanJSON(t *testing.T) {
	code, out, _ := run("scan", "--format", "json", "../check/testdata/good")
	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d", code, ExitOK)
	}
	var r struct {
		Files    []map[string]string `json:"files"`
		Findings []any               `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if len(r.Files) != 2 || r.Findings == nil || len(r.Findings) != 0 {
		t.Errorf("got %d files, %d findings", len(r.Files), len(r.Findings))
	}
}

func TestScanFailOn(t *testing.T) {
	// The bad fixture has high-severity findings, so the default --fail-on high exits 1.
	code, out, _ := run("scan", "../check/testdata/bad")
	if code != ExitFindings {
		t.Fatalf("exit code = %d, want %d\n%s", code, ExitFindings, out)
	}
	// Raising the threshold above any finding makes it pass again.
	code, _, _ = run("scan", "--fail-on", "critical", "../check/testdata/good")
	if code != ExitOK {
		t.Fatalf("clean scan exit code = %d, want %d", code, ExitOK)
	}
}

func TestScanErrors(t *testing.T) {
	cases := [][]string{
		{"scan", "does-not-exist"},
		{"scan", "--format", "xml", "."},
		{"scan", "--fail-on", "severe", "."},
		{"scan", "cli.go"},
	}
	for _, args := range cases {
		if code, _, stderr := run(args...); code != ExitError || stderr == "" {
			t.Errorf("%v: exit code = %d, stderr = %q; want %d with message", args, code, stderr, ExitError)
		}
	}
}

func TestVersion(t *testing.T) {
	code, out, _ := run("version")
	if code != ExitOK || !strings.HasPrefix(out, "secchk ") {
		t.Errorf("version: code %d, output %q", code, out)
	}
}
