// Package config loads an optional .secchk.yml and filters findings with it.
//
// It lets a project suppress accepted findings (by rule, by path or by a
// baseline of fingerprints) and set a default severity threshold, so repeat
// scans stay focused on what is new.
package config

import (
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/linus1423/Securety-Checker/internal/finding"
	"gopkg.in/yaml.v3"
)

// FileName is the config file secchk looks for at the scan root.
const FileName = ".secchk.yml"

// Config is the parsed .secchk.yml.
type Config struct {
	// FailOn overrides the default severity threshold (empty = use the flag).
	FailOn string `yaml:"fail_on"`
	Ignore struct {
		Rules []string `yaml:"rules"`
		Paths []string `yaml:"paths"`
	} `yaml:"ignore"`
	// Baseline is a list of finding fingerprints to suppress.
	Baseline []string `yaml:"baseline"`
}

// Load reads .secchk.yml from root. A missing file yields an empty config.
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
	return &c, nil
}

// Apply returns the findings that survive the config's ignore rules, paths and
// baseline.
func (c *Config) Apply(findings []finding.Finding) []finding.Finding {
	rules := toSet(c.Ignore.Rules)
	baseline := toSet(c.Baseline)
	out := findings[:0:0]
	for _, f := range findings {
		if rules[f.RuleID] {
			continue
		}
		if baseline[f.Fingerprint()] {
			continue
		}
		if c.pathIgnored(f.Location.File) {
			continue
		}
		out = append(out, f)
	}
	return out
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
