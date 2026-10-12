package attack

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"regexp"
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

// apiDocPaths expose a machine-readable API specification.
var apiDocPaths = []string{"/swagger.json", "/openapi.json", "/v2/api-docs", "/v3/api-docs", "/api-docs"}

// graphQLPaths are common GraphQL endpoints.
var graphQLPaths = []string{"/graphql", "/api/graphql", "/v1/graphql", "/query"}

// sqlErrorMarkers are substrings that reveal a backend SQL error, i.e. that an
// injected quote reached the database (possible SQL injection).
var sqlErrorMarkers = []string{
	"SQL syntax", "SQLSTATE", "mysql_fetch", "ORA-01756", "ORA-00933",
	"unclosed quotation mark", "quoted string not properly terminated",
	"pg_query", "PG::SyntaxError", "SQLiteException", "near \"'\": syntax error",
	"You have an error in your SQL syntax",
}

// ProbeAPI tests the API surface of one HTTP(S) base URL: exposed OpenAPI/Swagger
// specs, unauthenticated GraphQL introspection, path traversal and reflected SQL
// errors. The injection probes send only harmless GET requests against the
// sandbox. It needs no external tool.
func ProbeAPI(ctx context.Context, baseURL string) []finding.Finding {
	client := httpClient()
	base := strings.TrimRight(baseURL, "/")
	var out []finding.Finding

	// Exposed API documentation.
	for _, p := range apiDocPaths {
		body, status := httpGet(ctx, client, base+p)
		if status == http.StatusOK && containsAny(body, []string{"\"swagger\"", "\"openapi\"", "\"paths\""}) {
			out = append(out, finding.Finding{
				RuleID: "ATK-APIDOC", Title: "API-Spezifikation öffentlich erreichbar",
				Severity: finding.SeverityLow, Location: finding.Location{File: base + p},
				Message:     "OpenAPI/Swagger-Dokument ohne Authentifizierung abrufbar",
				Remediation: "Schütze die API-Dokumentation oder stelle sie nicht öffentlich bereit.",
			})
			break
		}
	}

	// GraphQL introspection enabled.
	for _, p := range graphQLPaths {
		if graphQLIntrospection(ctx, client, base+p) {
			out = append(out, finding.Finding{
				RuleID: "ATK-GRAPHQL", Title: "GraphQL-Introspection aktiviert",
				Severity: finding.SeverityMedium, Location: finding.Location{File: base + p},
				Message:     "Das vollständige Schema ist ohne Authentifizierung abrufbar",
				Remediation: "Deaktiviere die Introspection in Produktion oder erfordere Authentifizierung.",
			})
			break
		}
	}

	// Path traversal.
	for _, probe := range []string{"/../../../../../../etc/passwd", "/..%2f..%2f..%2f..%2f..%2fetc%2fpasswd"} {
		body, status := httpGet(ctx, client, base+probe)
		if status == http.StatusOK && rootPasswdRe.MatchString(body) {
			out = append(out, finding.Finding{
				RuleID: "ATK-TRAVERSAL", Title: "Path Traversal möglich",
				Severity: finding.SeverityCritical, Location: finding.Location{File: base + probe},
				Message:     "/etc/passwd konnte über die URL gelesen werden",
				Remediation: "Normalisiere und validiere Pfadangaben; verlasse nie das erlaubte Verzeichnis.",
			})
			break
		}
	}

	// Reflected SQL error (possible SQL injection).
	for _, param := range []string{"id", "q", "search", "user"} {
		body, _ := httpGet(ctx, client, base+"/?"+param+"=1%27")
		if marker, ok := firstMarker(body, sqlErrorMarkers); ok {
			out = append(out, finding.Finding{
				RuleID: "ATK-SQLI", Title: "Mögliche SQL-Injection",
				Severity: finding.SeverityHigh, Confidence: finding.ConfidenceMedium,
				Location:    finding.Location{File: base + "/?" + param + "="},
				Message:     "Injizierter Quote löst einen SQL-Fehler aus: " + marker,
				Remediation: "Verwende parametrisierte Queries / Prepared Statements.",
			})
			break
		}
	}
	return out
}

// rootPasswdRe matches an /etc/passwd root line.
var rootPasswdRe = regexp.MustCompile(`root:.*:0:0:`)

func httpGet(ctx context.Context, client *http.Client, url string) (body string, status int) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", 0
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	resp.Body.Close()
	return string(b), resp.StatusCode
}

func graphQLIntrospection(ctx context.Context, client *http.Client, url string) bool {
	payload := `{"query":"{__schema{queryType{name}}}"}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(payload))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16*1024))
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK && strings.Contains(string(body), "__schema") && strings.Contains(string(body), "queryType")
}

func firstMarker(s string, markers []string) (string, bool) {
	for _, m := range markers {
		if strings.Contains(s, m) {
			return m, true
		}
	}
	return "", false
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
