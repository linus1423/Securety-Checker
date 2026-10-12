package report

import (
	"encoding/json"
	"io"

	"github.com/linus1423/Securety-Checker/internal/finding"
)

// SARIF 2.1.0 structures, trimmed to what GitHub code scanning needs.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string            `json:"id"`
	Name             string            `json:"name,omitempty"`
	ShortDescription sarifText         `json:"shortDescription"`
	FullDescription  *sarifText        `json:"fullDescription,omitempty"`
	HelpURI          string            `json:"helpUri,omitempty"`
	Properties       map[string]string `json:"properties,omitempty"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
	Properties          map[string]string `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region *sarifRegion `json:"region,omitempty"`
	} `json:"physicalLocation"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func writeSARIF(w io.Writer, r Result) error {
	rulesByID := map[string]sarifRule{}
	var results []sarifResult
	for _, f := range r.Findings {
		if _, ok := rulesByID[f.RuleID]; !ok {
			rule := sarifRule{
				ID:               f.RuleID,
				Name:             f.RuleID,
				ShortDescription: sarifText{Text: f.Title},
				Properties:       map[string]string{"severity": f.Severity.String()},
			}
			if f.Remediation != "" {
				rule.FullDescription = &sarifText{Text: f.Remediation}
			}
			if len(f.References) > 0 {
				rule.HelpURI = f.References[0]
			}
			rulesByID[f.RuleID] = rule
		}
		loc := sarifLocation{}
		loc.PhysicalLocation.ArtifactLocation.URI = f.Location.File
		if f.Location.Line > 0 {
			loc.PhysicalLocation.Region = &sarifRegion{StartLine: f.Location.Line}
		}
		msg := f.Title
		if f.Message != "" {
			msg = f.Title + ": " + f.Message
		}
		results = append(results, sarifResult{
			RuleID:              f.RuleID,
			Level:               sarifLevel(f.Severity),
			Message:             sarifText{Text: msg},
			Locations:           []sarifLocation{loc},
			PartialFingerprints: map[string]string{"secchkFingerprint/v1": f.Fingerprint()},
			Properties:          map[string]string{"confidence": f.Confidence.String()},
		})
	}
	rules := make([]sarifRule, 0, len(rulesByID))
	for _, f := range r.Findings {
		if rule, ok := rulesByID[f.RuleID]; ok {
			rules = append(rules, rule)
			delete(rulesByID, f.RuleID)
		}
	}
	if results == nil {
		results = []sarifResult{}
	}
	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "secchk",
				InformationURI: "https://github.com/linus1423/Securety-Checker",
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// sarifLevel maps a severity to a SARIF level.
func sarifLevel(s finding.Severity) string {
	switch {
	case s >= finding.SeverityHigh:
		return "error"
	case s == finding.SeverityMedium:
		return "warning"
	default:
		return "note"
	}
}
