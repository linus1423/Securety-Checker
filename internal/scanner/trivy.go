// Package scanner wraps external security scanners behind a small interface.
//
// The Trivy adapter shells out to the `trivy` binary for image vulnerabilities
// and secret detection. When Trivy is not installed the adapter reports that it
// is unavailable rather than failing, so the rest of the scan still runs.
package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/linus1423/Securety-Checker/internal/finding"
)

// Trivy runs the trivy CLI. The zero value uses "trivy" from PATH.
type Trivy struct {
	// Binary overrides the executable name/path (defaults to "trivy").
	Binary string
}

// binary returns the configured binary or the default.
func (t Trivy) binary() string {
	if t.Binary != "" {
		return t.Binary
	}
	return "trivy"
}

// Available reports whether the trivy binary can be found on PATH.
func (t Trivy) Available() bool {
	_, err := exec.LookPath(t.binary())
	return err == nil
}

// ScanImage scans one container image for vulnerabilities and secrets.
func (t Trivy) ScanImage(ctx context.Context, image string) ([]finding.Finding, error) {
	args := []string{"image", "--quiet", "--format", "json", "--scanners", "vuln,secret", image}
	out, err := t.run(ctx, args)
	if err != nil {
		return nil, err
	}
	return parseReport(out, locatorImage, image)
}

// ScanFilesystemSecrets scans a directory tree for committed secrets.
func (t Trivy) ScanFilesystemSecrets(ctx context.Context, root string) ([]finding.Finding, error) {
	args := []string{"fs", "--quiet", "--format", "json", "--scanners", "secret", root}
	out, err := t.run(ctx, args)
	if err != nil {
		return nil, err
	}
	return parseReport(out, locatorFile, "")
}

func (t Trivy) run(ctx context.Context, args []string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, t.binary(), args...)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("trivy %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(ee.Stderr)))
		}
		return nil, fmt.Errorf("trivy %s: %w", strings.Join(args, " "), err)
	}
	return out, nil
}

// locator decides what goes into a finding's Location.File.
type locator int

const (
	locatorImage locator = iota // use the image reference
	locatorFile                 // use the per-result target path
)

// trivyReport is the subset of Trivy's JSON output we consume.
type trivyReport struct {
	Results []struct {
		Target          string        `json:"Target"`
		Vulnerabilities []trivyVuln   `json:"Vulnerabilities"`
		Secrets         []trivySecret `json:"Secrets"`
	} `json:"Results"`
}

type trivyVuln struct {
	VulnerabilityID  string `json:"VulnerabilityID"`
	PkgName          string `json:"PkgName"`
	InstalledVersion string `json:"InstalledVersion"`
	FixedVersion     string `json:"FixedVersion"`
	Severity         string `json:"Severity"`
	Title            string `json:"Title"`
	PrimaryURL       string `json:"PrimaryURL"`
}

type trivySecret struct {
	RuleID    string `json:"RuleID"`
	Category  string `json:"Category"`
	Severity  string `json:"Severity"`
	Title     string `json:"Title"`
	StartLine int    `json:"StartLine"`
}

// parseReport converts Trivy JSON into findings. imageRef is used as the
// location when loc is locatorImage.
func parseReport(data []byte, loc locator, imageRef string) ([]finding.Finding, error) {
	if len(strings.TrimSpace(string(data))) == 0 {
		return nil, nil
	}
	var r trivyReport
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("parsing trivy output: %w", err)
	}
	var out []finding.Finding
	for _, res := range r.Results {
		file := imageRef
		if loc == locatorFile {
			file = res.Target
		}
		for _, v := range res.Vulnerabilities {
			fix := v.FixedVersion
			msg := fmt.Sprintf("%s in %s %s", v.VulnerabilityID, v.PkgName, v.InstalledVersion)
			rem := "Kein Fix verfügbar; Basisimage oder Paket im Auge behalten."
			if fix != "" {
				rem = fmt.Sprintf("Auf %s %s oder höher aktualisieren.", v.PkgName, fix)
			}
			title := v.Title
			if title == "" {
				title = v.VulnerabilityID
			}
			refs := []string{}
			if v.PrimaryURL != "" {
				refs = append(refs, v.PrimaryURL)
			}
			out = append(out, finding.Finding{
				RuleID:      "TRIVY-VULN",
				Title:       title,
				Severity:    mapSeverity(v.Severity),
				Location:    finding.Location{File: file},
				Message:     msg,
				Remediation: rem,
				References:  refs,
			})
		}
		for _, s := range res.Secrets {
			title := s.Title
			if title == "" {
				title = s.RuleID
			}
			out = append(out, finding.Finding{
				RuleID:      "TRIVY-SECRET",
				Title:       "Secret gefunden: " + title,
				Severity:    mapSeverity(s.Severity),
				Location:    finding.Location{File: file, Line: s.StartLine},
				Message:     s.Category,
				Remediation: "Secret entfernen, rotieren und über ein Secret-Management statt im Klartext bereitstellen.",
			})
		}
	}
	return out, nil
}

// mapSeverity maps a Trivy severity string to our Severity scale.
func mapSeverity(s string) finding.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return finding.SeverityCritical
	case "HIGH":
		return finding.SeverityHigh
	case "MEDIUM":
		return finding.SeverityMedium
	case "LOW":
		return finding.SeverityLow
	default:
		return finding.SeverityInfo
	}
}
