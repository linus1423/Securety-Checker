// Package check runs the static security rules over discovered files.
package check

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/linus1423/Securety-Checker/internal/compose"
	"github.com/linus1423/Securety-Checker/internal/discovery"
	"github.com/linus1423/Securety-Checker/internal/dockerfile"
	"github.com/linus1423/Securety-Checker/internal/finding"
)

// Hit is a single place a rule matched. The engine turns it into a Finding using
// the rule's metadata. Message adds context (which image, key or value matched).
type Hit struct {
	Line    int
	Message string
}

// DockerfileTarget is the parsed input a Dockerfile rule inspects.
type DockerfileTarget struct {
	Path            string
	DF              *dockerfile.Dockerfile
	HasDockerignore bool
}

// ComposeTarget is the parsed input a Compose rule inspects.
type ComposeTarget struct {
	Path string
	File *compose.File
}

// DockerfileRule is a single check over one Dockerfile.
type DockerfileRule struct {
	ID          string
	Title       string
	Severity    finding.Severity
	Remediation string
	Refs        []string
	Fn          func(*DockerfileTarget) []Hit
}

// ComposeRule is a single check over one Compose file.
type ComposeRule struct {
	ID          string
	Title       string
	Severity    finding.Severity
	Remediation string
	Refs        []string
	Fn          func(*ComposeTarget) []Hit
}

// Run parses every discovered file and applies the matching rules. Files that
// fail to parse produce an informational finding rather than aborting the scan.
func Run(root string, files []discovery.File) ([]finding.Finding, error) {
	var findings []finding.Finding
	for _, f := range files {
		abs := filepath.Join(root, filepath.FromSlash(f.Path))
		switch f.Kind {
		case discovery.KindDockerfile:
			df, err := dockerfile.ParseFile(abs)
			if err != nil {
				findings = append(findings, parseFinding(f.Path, err))
				continue
			}
			t := &DockerfileTarget{
				Path:            f.Path,
				DF:              df,
				HasDockerignore: hasDockerignore(root, abs),
			}
			for _, rule := range DockerfileRules {
				findings = append(findings, applyDockerfile(rule, t)...)
			}
		case discovery.KindCompose:
			cf, err := compose.ParseFile(abs)
			if err != nil {
				findings = append(findings, parseFinding(f.Path, err))
				continue
			}
			t := &ComposeTarget{Path: f.Path, File: cf}
			for _, rule := range ComposeRules {
				findings = append(findings, applyCompose(rule, t)...)
			}
		}
	}
	finding.Sort(findings)
	return findings, nil
}

func applyDockerfile(rule DockerfileRule, t *DockerfileTarget) []finding.Finding {
	var out []finding.Finding
	for _, h := range rule.Fn(t) {
		out = append(out, finding.Finding{
			RuleID:      rule.ID,
			Title:       rule.Title,
			Severity:    rule.Severity,
			Location:    finding.Location{File: t.Path, Line: h.Line},
			Message:     h.Message,
			Remediation: rule.Remediation,
			References:  rule.Refs,
		})
	}
	return out
}

func applyCompose(rule ComposeRule, t *ComposeTarget) []finding.Finding {
	var out []finding.Finding
	for _, h := range rule.Fn(t) {
		out = append(out, finding.Finding{
			RuleID:      rule.ID,
			Title:       rule.Title,
			Severity:    rule.Severity,
			Location:    finding.Location{File: t.Path, Line: h.Line},
			Message:     h.Message,
			Remediation: rule.Remediation,
			References:  rule.Refs,
		})
	}
	return out
}

func parseFinding(path string, err error) finding.Finding {
	return finding.Finding{
		RuleID:   "PARSE",
		Title:    "Datei konnte nicht geparst werden",
		Severity: finding.SeverityInfo,
		Location: finding.Location{File: path},
		Message:  err.Error(),
	}
}

// hasDockerignore reports whether a .dockerignore exists next to the Dockerfile
// or at the scan root (the two places Docker looks, depending on build context).
func hasDockerignore(root, dockerfileAbs string) bool {
	candidates := []string{
		filepath.Join(filepath.Dir(dockerfileAbs), ".dockerignore"),
		filepath.Join(root, ".dockerignore"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return true
		}
	}
	return false
}

// cis links to a CIS Docker Benchmark recommendation for a reference list.
func cis(section string) string {
	return fmt.Sprintf("CIS Docker Benchmark %s", section)
}
