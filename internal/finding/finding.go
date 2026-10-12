// Package finding defines the common result format every check reports in.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// Severity ranks how serious a finding is. Higher values are more severe.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityNames = []string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < SeverityInfo || s > SeverityCritical {
		return fmt.Sprintf("severity(%d)", int(s))
	}
	return severityNames[s]
}

// MarshalText encodes the severity by name, so JSON output reads "high" instead of 3.
func (s Severity) MarshalText() ([]byte, error) {
	return []byte(s.String()), nil
}

// UnmarshalText decodes a severity name.
func (s *Severity) UnmarshalText(b []byte) error {
	v, err := ParseSeverity(string(b))
	if err != nil {
		return err
	}
	*s = v
	return nil
}

// ParseSeverity converts a name such as "high" into a Severity.
func ParseSeverity(name string) (Severity, error) {
	n := strings.ToLower(strings.TrimSpace(name))
	for i, s := range severityNames {
		if s == n {
			return Severity(i), nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q (expected one of %s)", name, strings.Join(severityNames, ", "))
}

// Location points at the place in a file a finding refers to. Line is 1-based; 0 means unknown.
type Location struct {
	File string `json:"file"`
	Line int    `json:"line,omitempty"`
}

// Finding is a single security issue reported by a check.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Title       string   `json:"title"`
	Severity    Severity `json:"severity"`
	Location    Location `json:"location"`
	Message     string   `json:"message,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	References  []string `json:"references,omitempty"`
}

// Fingerprint is a stable identifier for a finding, used for baselines and
// deduplication. It is independent of the message text, which may vary.
func (f Finding) Fingerprint() string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%d", f.RuleID, f.Location.File, f.Location.Line)))
	return hex.EncodeToString(sum[:8])
}

// Sort orders findings by severity (most severe first), then file, line and rule ID.
func Sort(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		a, b := fs[i], fs[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Location.File != b.Location.File {
			return a.Location.File < b.Location.File
		}
		if a.Location.Line != b.Location.Line {
			return a.Location.Line < b.Location.Line
		}
		return a.RuleID < b.RuleID
	})
}

// AnyAtLeast reports whether any finding has at least the given severity.
func AnyAtLeast(fs []Finding, min Severity) bool {
	for _, f := range fs {
		if f.Severity >= min {
			return true
		}
	}
	return false
}

// Dedup removes exact-duplicate findings, keeping the first occurrence and the
// original order. Two findings are duplicates when they share rule, location and
// message, as happens when the same service is reached on more than one path
// (e.g. a published host port and the container's internal IP). Findings that
// differ in message at the same location are kept, since they report different
// issues.
func Dedup(fs []Finding) []Finding {
	seen := make(map[string]bool, len(fs))
	out := fs[:0:0]
	for _, f := range fs {
		key := fmt.Sprintf("%s|%s|%d|%s", f.RuleID, f.Location.File, f.Location.Line, f.Message)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	return out
}

// Counts returns the number of findings at each severity.
func Counts(fs []Finding) map[Severity]int {
	m := make(map[Severity]int, len(severityNames))
	for _, f := range fs {
		m[f.Severity]++
	}
	return m
}

// Summary renders a one-line count of findings per severity, most severe first,
// omitting severities with no findings. It returns "" for no findings.
func Summary(fs []Finding) string {
	if len(fs) == 0 {
		return ""
	}
	counts := Counts(fs)
	var parts []string
	for s := SeverityCritical; s >= SeverityInfo; s-- {
		if n := counts[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	return strings.Join(parts, ", ")
}
