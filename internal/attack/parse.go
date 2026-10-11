package attack

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/linus1423/Securety-Checker/internal/finding"
)

// nmapRun is the subset of nmap's XML output we read.
type nmapRun struct {
	Hosts []struct {
		Ports struct {
			Ports []struct {
				Protocol string `xml:"protocol,attr"`
				PortID   string `xml:"portid,attr"`
				State    struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name    string `xml:"name,attr"`
					Product string `xml:"product,attr"`
					Version string `xml:"version,attr"`
					Tunnel  string `xml:"tunnel,attr"`
				} `xml:"service"`
			} `xml:"port"`
		} `xml:"ports"`
	} `xml:"host"`
}

// parseNmapXML converts nmap XML into findings for the open ports found.
func parseNmapXML(data []byte, host string) ([]finding.Finding, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parsing nmap output: %w", err)
	}
	var out []finding.Finding
	for _, h := range run.Hosts {
		for _, p := range h.Ports.Ports {
			if p.State.State != "open" {
				continue
			}
			loc := finding.Location{File: fmt.Sprintf("%s:%s", host, p.PortID)}
			svc := p.Service.Name
			desc := strings.TrimSpace(svc + " " + p.Service.Product + " " + p.Service.Version)
			if riskyServices[strings.ToLower(svc)] && p.Service.Tunnel != "ssl" {
				out = append(out, finding.Finding{
					RuleID:      "ATK-PORT",
					Title:       "Unsicherer Dienst erreichbar: " + svc,
					Severity:    finding.SeverityHigh,
					Location:    loc,
					Message:     desc,
					Remediation: "Ersetze den Klartext-Dienst durch eine verschlüsselte Alternative oder entferne den Port.",
				})
				continue
			}
			out = append(out, finding.Finding{
				RuleID:      "ATK-PORT",
				Title:       "Offener Port: " + svc,
				Severity:    finding.SeverityInfo,
				Location:    loc,
				Message:     desc,
				Remediation: "Prüfe, ob dieser Port nach außen erreichbar sein muss.",
			})
		}
	}
	return out, nil
}

// nucleiResult is the subset of a nuclei JSONL record we read.
type nucleiResult struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
	Host      string `json:"host"`
	MatchedAt string `json:"matched-at"`
}

// parseNucleiJSONL converts nuclei JSONL output into findings, one per line.
func parseNucleiJSONL(data []byte) ([]finding.Finding, error) {
	var out []finding.Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var r nucleiResult
		if err := json.Unmarshal(line, &r); err != nil {
			continue // skip malformed lines rather than failing the whole scan
		}
		at := r.MatchedAt
		if at == "" {
			at = r.Host
		}
		name := r.Info.Name
		if name == "" {
			name = r.TemplateID
		}
		out = append(out, finding.Finding{
			RuleID:      "ATK-NUCLEI",
			Title:       name,
			Severity:    mapSeverity(r.Info.Severity),
			Location:    finding.Location{File: at},
			Message:     r.TemplateID,
			Remediation: "Siehe die Beschreibung der nuclei-Vorlage " + r.TemplateID + ".",
		})
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	return out, nil
}
