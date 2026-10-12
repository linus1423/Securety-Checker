package attack

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/linus1423/Securety-Checker/internal/finding"
)

// ProbeServices checks a target for services that are reachable without
// authentication: unprotected databases and caches, message-broker admin
// consoles, exposed container/orchestration APIs and anonymous FTP. The service
// is chosen from the target's canonical (container) port. Every probe only ever
// talks to the sandbox secchk started; a closed or protected service simply
// yields no finding.
func ProbeServices(ctx context.Context, tgt Target) []finding.Finding {
	host, port := tgt.Host, tgt.Port
	addr := net.JoinHostPort(host, port)
	loc := finding.Location{File: addr}
	switch tgt.canonicalPort() {
	case "6379": // Redis
		if redisUnauthenticated(rawProbe(ctx, addr, "PING\r\n")) {
			return []finding.Finding{noAuth(loc, "Redis", finding.SeverityCritical,
				"Redis ist ohne Authentifizierung erreichbar")}
		}
	case "11211": // Memcached
		if strings.HasPrefix(rawProbe(ctx, addr, "version\r\n"), "VERSION") {
			return []finding.Finding{noAuth(loc, "Memcached", finding.SeverityHigh,
				"Memcached ist ohne Authentifizierung erreichbar")}
		}
	case "21": // FTP
		if ftpAnonymous(ctx, addr) {
			return []finding.Finding{{
				RuleID: "ATK-FTP", Title: "Anonymer FTP-Zugriff erlaubt",
				Severity: finding.SeverityHigh, Location: loc,
				Message:     "Anonymer Login (anonymous) wird akzeptiert",
				Remediation: "Deaktiviere anonymen FTP-Zugriff oder ersetze FTP durch SFTP/FTPS.",
			}}
		}
	case "9200", "9201": // Elasticsearch
		return httpNoAuth(ctx, "http://"+addr+"/", "Elasticsearch", []string{"cluster_name", "lucene_version"}, loc, finding.SeverityHigh)
	case "5984": // CouchDB
		return httpNoAuth(ctx, "http://"+addr+"/_all_dbs", "CouchDB", []string{"["}, loc, finding.SeverityHigh)
	case "2375": // Docker Engine API (plaintext)
		return httpNoAuth(ctx, "http://"+addr+"/version", "Docker Engine API", []string{"ApiVersion", "GitCommit"}, loc, finding.SeverityCritical)
	case "10250": // Kubelet read/write API
		return httpNoAuth(ctx, "https://"+addr+"/pods", "Kubelet-API", []string{"PodList", "\"items\""}, loc, finding.SeverityCritical)
	case "15672": // RabbitMQ management (default guest:guest)
		if rabbitDefaultCreds(ctx, "http://"+addr+"/api/overview") {
			return []finding.Finding{{
				RuleID: "ATK-DEFAULTCRED", Title: "RabbitMQ mit Standard-Zugangsdaten",
				Severity: finding.SeverityHigh, Location: loc,
				Message:     "Management-API akzeptiert guest:guest",
				Remediation: "Lösche/ändere den guest-Benutzer und vergib ein starkes Passwort.",
			}}
		}
	}
	return nil
}

func noAuth(loc finding.Location, svc string, sev finding.Severity, msg string) finding.Finding {
	return finding.Finding{
		RuleID: "ATK-NOAUTH", Title: "Dienst ohne Authentifizierung: " + svc,
		Severity: sev, Location: loc, Message: msg,
		Remediation: "Aktiviere Authentifizierung und binde den Dienst nicht nach außen.",
	}
}

// rawProbe opens a TCP connection, sends req and returns the first chunk of the
// response as a string. Any error yields an empty string.
func rawProbe(ctx context.Context, addr, req string) string {
	d := net.Dialer{Timeout: 4 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(4 * time.Second))
	if _, err := conn.Write([]byte(req)); err != nil {
		return ""
	}
	buf := make([]byte, 2048)
	n, _ := conn.Read(buf)
	return string(buf[:n])
}

// redisUnauthenticated reports whether a Redis PING succeeded without auth.
// A server that requires auth answers with a "-NOAUTH" / "-ERR ... auth" error.
func redisUnauthenticated(resp string) bool {
	if resp == "" {
		return false
	}
	if strings.Contains(resp, "NOAUTH") || strings.Contains(strings.ToLower(resp), "authentication required") {
		return false
	}
	return strings.HasPrefix(resp, "+PONG")
}

// ftpAnonymous reports whether the FTP server at addr accepts an anonymous login.
func ftpAnonymous(ctx context.Context, addr string) bool {
	d := net.Dialer{Timeout: 4 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(6 * time.Second))
	buf := make([]byte, 512)
	readCode := func() string {
		n, _ := conn.Read(buf)
		return string(buf[:n])
	}
	if !strings.HasPrefix(strings.TrimSpace(readCode()), "220") {
		return false
	}
	if _, err := conn.Write([]byte("USER anonymous\r\n")); err != nil {
		return false
	}
	resp := strings.TrimSpace(readCode())
	if strings.HasPrefix(resp, "230") {
		return true // logged in without a password
	}
	if !strings.HasPrefix(resp, "331") {
		return false
	}
	if _, err := conn.Write([]byte("PASS anonymous@example.com\r\n")); err != nil {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(readCode()), "230")
}

// httpNoAuth does a GET and reports an unauthenticated service when the response
// is 200 and the body carries one of the fingerprint markers.
func httpNoAuth(ctx context.Context, url, svc string, markers []string, loc finding.Location, sev finding.Severity) []finding.Finding {
	client := httpClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	resp.Body.Close()
	if resp.StatusCode == http.StatusOK && containsAny(string(body), markers) {
		return []finding.Finding{noAuth(loc, svc, sev, svc+" antwortet ohne Authentifizierung (HTTP 200)")}
	}
	return nil
}

// rabbitDefaultCreds reports whether the RabbitMQ management API accepts the
// well-known default guest:guest credentials.
func rabbitDefaultCreds(ctx context.Context, url string) bool {
	client := httpClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	req.SetBasicAuth("guest", "guest")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	return resp.StatusCode == http.StatusOK && strings.Contains(string(body), "rabbitmq_version")
}
