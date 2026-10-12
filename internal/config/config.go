// Package config loads an optional .secchk.yml and filters findings with it.
//
// It lets a project suppress accepted findings (by rule, by path or by a
// baseline of fingerprints) and set a default severity threshold, so repeat
// scans stay focused on what is new.
package config

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/linus1423/Securety-Checker/internal/finding"
	"gopkg.in/yaml.v3"
)

// FileName is the config file secchk looks for at the scan root.
const FileName = ".secchk.yml"

// dateLayout is the expected format for an exception's expiry.
const dateLayout = "2006-01-02"

// Exception is a documented, accepted finding: a project explicitly tolerates a
// rule (optionally only under a path) with a stated reason, optionally until an
// expiry date. Unlike a bare ignore, an exception records *why* and *until when*,
// and an expired exception stops suppressing so it resurfaces for review.
type Exception struct {
	Rule    string `yaml:"rule"`
	Path    string `yaml:"path"`    // optional glob; empty matches any path
	Reason  string `yaml:"reason"`  // why this is accepted
	Expires string `yaml:"expires"` // optional YYYY-MM-DD; empty never expires
}

// Config is the parsed .secchk.yml policy file.
type Config struct {
	// FailOn overrides the default severity threshold (empty = use the flag).
	FailOn string `yaml:"fail_on"`
	Ignore struct {
		Rules []string `yaml:"rules"`
		Paths []string `yaml:"paths"`
	} `yaml:"ignore"`
	// Baseline is a list of finding fingerprints to suppress.
	Baseline []string `yaml:"baseline"`
	// SeverityOverrides remaps a rule's severity per project policy, e.g. to
	// raise DF007 to medium or lower a noisy rule to info.
	SeverityOverrides map[string]string `yaml:"severity_overrides"`
	// Exceptions are documented, accepted findings (see Exception).
	Exceptions []Exception `yaml:"exceptions"`
}

// Load reads and validates .secchk.yml from root. A missing file yields an
// empty config.
func Load(root string) (*Config, error) {
	data, err := os.ReadFile(filepath.Join(root, FileName))
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if err := c.validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// validate checks severity-override names and exception expiry dates so a
// typo in the policy fails loudly instead of being silently ignored.
func (c *Config) validate() error {
	for rule, sev := range c.SeverityOverrides {
		if _, err := finding.ParseSeverity(sev); err != nil {
			return fmt.Errorf("severity_overrides[%s]: %w", rule, err)
		}
	}
	for i, e := range c.Exceptions {
		if e.Rule == "" {
			return fmt.Errorf("exceptions[%d]: rule is required", i)
		}
		if e.Expires != "" {
			if _, err := time.Parse(dateLayout, e.Expires); err != nil {
				return fmt.Errorf("exceptions[%d].expires: %q is not a YYYY-MM-DD date", i, e.Expires)
			}
		}
	}
	return nil
}

// Apply returns the findings that survive the config, after applying severity
// overrides. It uses the current date to decide which exceptions are still valid.
func (c *Config) Apply(findings []finding.Finding) []finding.Finding {
	return c.applyAt(findings, time.Now())
}

// applyAt is Apply with an injectable clock, so expiry logic is testable.
func (c *Config) applyAt(findings []finding.Finding, now time.Time) []finding.Finding {
	rules := toSet(c.Ignore.Rules)
	baseline := toSet(c.Baseline)
	out := findings[:0:0]
	for _, f := range findings {
		if sev, ok := c.SeverityOverrides[f.RuleID]; ok {
			if parsed, err := finding.ParseSeverity(sev); err == nil {
				f.Severity = parsed
			}
		}
		if rules[f.RuleID] {
			continue
		}
		if baseline[f.Fingerprint()] {
			continue
		}
		if c.pathIgnored(f.Location.File) {
			continue
		}
		if c.excepted(f, now) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// excepted reports whether a still-valid exception covers the finding.
func (c *Config) excepted(f finding.Finding, now time.Time) bool {
	for _, e := range c.Exceptions {
		if e.Rule != f.RuleID {
			continue
		}
		if e.Expires != "" {
			if exp, err := time.Parse(dateLayout, e.Expires); err == nil && now.After(exp) {
				continue // expired: no longer suppresses
			}
		}
		if e.Path == "" || matchPath(filepath.ToSlash(e.Path), filepath.ToSlash(f.Location.File)) {
			return true
		}
	}
	return false
}

func (c *Config) pathIgnored(file string) bool {
	file = filepath.ToSlash(file)
	for _, pat := range c.Ignore.Paths {
		pat = filepath.ToSlash(pat)
		if matchPath(pat, file) {
			return true
		}
	}
	return false
}

// matchPath supports exact paths, a trailing "/**" prefix match, and single
// path.Match globs ("*.yml", "dir/*").
func matchPath(pattern, file string) bool {
	if pattern == file {
		return true
	}
	if strings.HasSuffix(pattern, "/**") {
		prefix := strings.TrimSuffix(pattern, "/**")
		return file == prefix || strings.HasPrefix(file, prefix+"/")
	}
	if ok, _ := path.Match(pattern, file); ok {
		return true
	}
	// Also try matching just the base name, so "*.env" matches "deploy/x.env".
	if ok, _ := path.Match(pattern, path.Base(file)); ok {
		return true
	}
	return false
}

func toSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, i := range items {
		m[strings.TrimSpace(i)] = true
	}
	return m
}
