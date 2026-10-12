package attack

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/linus1423/Securety-Checker/internal/finding"
)

// sensitivePath is a path that should not be reachable, and how bad it is.
type sensitivePath struct {
	path     string
	severity finding.Severity
	what     string
}

// sensitivePaths are probed on every HTTP target.
var sensitivePaths = []sensitivePath{
	{"/.env", finding.SeverityCritical, "Umgebungsdatei mit Secrets"},
	{"/.git/config", finding.SeverityHigh, "Git-Repository exponiert"},
	{"/.aws/credentials", finding.SeverityCritical, "AWS-Zugangsdaten"},
	{"/actuator", finding.SeverityMedium, "Spring-Actuator"},
	{"/actuator/env", finding.SeverityHigh, "Spring-Actuator env (Secrets)"},
	{"/server-status", finding.SeverityMedium, "Apache server-status"},
	{"/metrics", finding.SeverityMedium, "Prometheus-Metriken"},
	{"/phpinfo.php", finding.SeverityMedium, "phpinfo"},
	{"/config.json", finding.SeverityMedium, "Konfigurationsdatei"},
	{"/swagger.json", finding.SeverityLow, "API-Dokumentation"},
	{"/admin", finding.SeverityLow, "Admin-Oberfläche"},
}

// httpClient is a short-timeout client that does not follow redirects or verify
// certs (the sandbox often uses self-signed certs).
func httpClient() *http.Client {
	return &http.Client{
		Timeout: 8 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
}

// ProbeHTTP checks one HTTP(S) base URL for header hygiene, CORS, version
// disclosure, directory listing and exposed sensitive paths. It needs no
// external tool.
func ProbeHTTP(ctx context.Context, baseURL string) ([]finding.Finding, error) {
	client := httpClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()

	out := analyzeHTTP(baseURL, resp.StatusCode, resp.Header, string(body))
	out = append(out, probeSensitivePaths(ctx, client, baseURL)...)
	return out, nil
}

// analyzeHTTP inspects a response's status, headers and body. It is pure so it
// can be tested without a live server.
func analyzeHTTP(url string, status int, header http.Header, body string) []finding.Finding {
	loc := finding.Location{File: url}
	var out []finding.Finding
	isHTTPS := strings.HasPrefix(url, "https://")

	var missing []string
	for _, h := range []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options"} {
		if header.Get(h) == "" {
			missing = append(missing, h)
		}
	}
	if isHTTPS && header.Get("Strict-Transport-Security") == "" {
		missing = append(missing, "Strict-Transport-Security")
	}
	if len(missing) > 0 {
		out = append(out, finding.Finding{
			RuleID: "ATK-HEADER", Title: "Fehlende Security-Header",
			Severity: finding.SeverityLow, Location: loc, Message: strings.Join(missing, ", "),
			Remediation: "Setze die fehlenden Security-Header (CSP, X-Frame-Options, X-Content-Type-Options, HSTS).",
		})
	}

	acao := header.Get("Access-Control-Allow-Origin")
	if acao == "*" {
		sev := finding.SeverityLow
		msg := "Access-Control-Allow-Origin: *"
		if strings.EqualFold(header.Get("Access-Control-Allow-Credentials"), "true") {
			sev = finding.SeverityHigh
			msg = "ACAO * zusammen mit Allow-Credentials: true"
		}
		out = append(out, finding.Finding{
			RuleID: "ATK-CORS", Title: "Permissive CORS-Konfiguration",
			Severity: sev, Location: loc, Message: msg,
			Remediation: "Beschränke Access-Control-Allow-Origin auf bekannte Ursprünge.",
		})
	}

	for _, h := range []string{"Server", "X-Powered-By"} {
		if v := header.Get(h); v != "" && strings.ContainsAny(v, "0123456789") {
			out = append(out, finding.Finding{
				RuleID: "ATK-INFO", Title: "Versionsinformation im HTTP-Header",
				Severity: finding.SeverityInfo, Location: loc, Message: h + ": " + v,
				Remediation: "Unterdrücke Versionsangaben in " + h + ".",
			})
		}
	}

	if status == http.StatusOK && strings.Contains(body, "Index of /") {
		out = append(out, finding.Finding{
			RuleID: "ATK-DIRLIST", Title: "Directory Listing aktiv",
			Severity: finding.SeverityMedium, Location: loc, Message: "Verzeichnisinhalt wird angezeigt",
			Remediation: "Deaktiviere das automatische Directory Listing.",
		})
	}
	return out
}

func probeSensitivePaths(ctx context.Context, client *http.Client, baseURL string) []finding.Finding {
	base := strings.TrimRight(baseURL, "/")
	var out []finding.Finding
	for _, sp := range sensitivePaths {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+sp.path, nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK && len(strings.TrimSpace(string(body))) > 0 {
			out = append(out, finding.Finding{
				RuleID: "ATK-EXPOSED", Title: "Exponierter Pfad: " + sp.what,
				Severity: sp.severity, Location: finding.Location{File: base + sp.path},
				Message:     "HTTP 200 auf " + sp.path,
				Remediation: "Pfad sperren oder entfernen; er sollte nicht öffentlich erreichbar sein.",
			})
		}
	}
	return out
}
