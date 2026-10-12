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
				Scripts []nmapScript `xml:"script"`
			} `xml:"port"`
		} `xml:"ports"`
	} `xml:"host"`
}

type nmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
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
			out = append(out, scriptFindings(p.Scripts, loc)...)
		}
	}
	return out, nil
}

// weakTLSMarkers in ssl-enum-ciphers output indicate a weak TLS configuration.
var weakTLSMarkers = []string{
	"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1", "RC4", "DES", "3DES", "EXPORT", "NULL", "anonymous",
	"least strength: C", "least strength: D", "least strength: E", "least strength: F",
}

// scriptFindings turns NSE script output into findings. It flags VULNERABLE
// results, weak TLS, expired certificates and dangerous HTTP methods.
func scriptFindings(scripts []nmapScript, loc finding.Location) []finding.Finding {
	var out []finding.Finding
	for _, s := range scripts {
		switch {
		case strings.Contains(s.Output, "VULNERABLE"):
			out = append(out, finding.Finding{
				RuleID: "ATK-VULN", Title: "nmap meldet VULNERABLE: " + s.ID,
				Severity: finding.SeverityHigh, Location: loc, Message: firstLine(s.Output),
				Remediation: "Dienst patchen oder die verwundbare Funktion abschalten.",
			})
		case s.ID == "ssl-enum-ciphers" && containsAny(s.Output, weakTLSMarkers):
			out = append(out, finding.Finding{
				RuleID: "ATK-TLS", Title: "Schwache TLS-Konfiguration",
				Severity: finding.SeverityMedium, Location: loc, Message: firstLine(s.Output),
				Remediation: "Deaktiviere alte Protokolle (SSLv3, TLS 1.0/1.1) und schwache Cipher.",
			})
		case s.ID == "ssl-cert" && (strings.Contains(s.Output, "expired") || strings.Contains(s.Output, "self-signed")):
			out = append(out, finding.Finding{
				RuleID: "ATK-TLS", Title: "Zertifikatsproblem",
				Severity: finding.SeverityMedium, Location: loc, Message: firstLine(s.Output),
				Remediation: "Gültiges, von einer CA signiertes Zertifikat verwenden.",
			})
		case s.ID == "http-methods" && (strings.Contains(s.Output, "PUT") || strings.Contains(s.Output, "DELETE") || strings.Contains(s.Output, "TRACE")):
			out = append(out, finding.Finding{
				RuleID: "ATK-HTTP", Title: "Gefährliche HTTP-Methoden erlaubt",
				Severity: finding.SeverityLow, Location: loc, Message: firstLine(s.Output),
				Remediation: "Erlaube nur die benötigten Methoden (GET/POST); schalte PUT/DELETE/TRACE ab.",
			})
		}
	}
	return out
}

func containsAny(s string, markers []string) bool {
	for _, m := range markers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return strings.TrimSpace(s[:i])
	}
	return s
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
