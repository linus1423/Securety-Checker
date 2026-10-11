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

func TestScanText(t *testing.T) {
	code, out, _ := run("scan", "../discovery/testdata/project")
	if code != ExitOK {
		t.Fatalf("exit code = %d, want %d", code, ExitOK)
	}
	for _, want := range []string{"6 relevant file(s)", "docker-compose.yml", "No findings."} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestScanJSON(t *testing.T) {
	code, out, _ := run("scan", "--format", "json", "../discovery/testdata/project")
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
	if len(r.Files) != 6 || r.Findings == nil {
		t.Errorf("got %d files, findings=%v", len(r.Files), r.Findings)
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
