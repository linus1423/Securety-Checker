package attack

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http"
	"testing"
	"time"

	"github.com/linus1423/Securety-Checker/internal/finding"
	"github.com/linus1423/Securety-Checker/internal/sandbox"
)

const nmapXML = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="23">
        <state state="open"/>
        <service name="telnet" product="Linux telnetd"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open"/>
        <service name="http" product="nginx" version="1.25"/>
      </port>
      <port protocol="tcp" portid="9">
        <state state="closed"/>
        <service name="discard"/>
      </port>
    </ports>
  </host>
</nmaprun>`

func TestParseNmapXML(t *testing.T) {
	fs, err := parseNmapXML([]byte(nmapXML), "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("got %d findings, want 2 (open ports only)", len(fs))
	}
	var telnetHigh bool
	for _, f := range fs {
		if f.Location.File == "127.0.0.1:23" && f.Severity == finding.SeverityHigh {
			telnetHigh = true
		}
	}
	if !telnetHigh {
		t.Error("expected telnet to be flagged High")
	}
}

func TestParseNucleiJSONL(t *testing.T) {
	data := `{"template-id":"tech-detect","info":{"name":"Nginx","severity":"info"},"matched-at":"http://127.0.0.1:8080"}
not json
{"template-id":"exposed-panel","info":{"name":"Admin Panel","severity":"high"},"matched-at":"http://127.0.0.1:8080/admin"}`
	fs, err := parseNucleiJSONL([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("got %d findings, want 2 (malformed line skipped)", len(fs))
	}
	if fs[1].Severity != finding.SeverityHigh || fs[1].Location.File != "http://127.0.0.1:8080/admin" {
		t.Errorf("unexpected finding: %+v", fs[1])
	}
}

func TestTargetsFromContainers(t *testing.T) {
	var c sandbox.Container
	c.Name = "/web"
	c.NetworkSettings.Ports = map[string][]struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	}{
		"8080/tcp": {{HostIP: "0.0.0.0", HostPort: "8080"}},
		"5432/tcp": {{HostIP: "127.0.0.1", HostPort: "5432"}},
	}
	targets := TargetsFromContainers([]sandbox.Container{c})
	if len(targets) != 2 {
		t.Fatalf("got %d targets, want 2", len(targets))
	}
	var sawHTTP, sawDB bool
	for _, tg := range targets {
		if tg.Port == "8080" {
			sawHTTP = tg.IsHTTP && tg.Host == "127.0.0.1"
		}
		if tg.Port == "5432" {
			sawDB = !tg.IsHTTP
		}
	}
	if !sawHTTP || !sawDB {
		t.Errorf("target classification wrong: http=%v db=%v", sawHTTP, sawDB)
	}
}

func TestClusterFindings(t *testing.T) {
	mk := func(name, net string) sandbox.Container {
		var c sandbox.Container
		c.Name = "/" + name
		c.NetworkSettings.Networks = map[string]struct {
			NetworkID string `json:"NetworkID"`
			IPAddress string `json:"IPAddress"`
		}{net: {NetworkID: "id-" + net}}
		return c
	}
	containers := []sandbox.Container{mk("web", "default"), mk("api", "default"), mk("db", "default")}
	fs := clusterFindings(containers)
	if len(fs) != 1 || fs[0].RuleID != "ATK-NETSEG" {
		t.Fatalf("expected one segmentation finding, got %+v", fs)
	}
	// Two services sharing a net is below the threshold.
	if got := clusterFindings(containers[:2]); len(got) != 0 {
		t.Errorf("expected no finding for 2 services, got %+v", got)
	}
}

func TestAnalyzeTLS(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	name := pkix.Name{CommonName: "self.local"}
	selfSigned := &x509.Certificate{
		Subject:  name,
		Issuer:   name,
		NotAfter: now.Add(365 * 24 * time.Hour),
	}
	fs := analyzeTLS(0x0301 /* TLS 1.0 */, selfSigned, "127.0.0.1:8443", now)
	ids := ruleIDs(fs)
	if !ids["ATK-TLS"] {
		t.Fatalf("expected ATK-TLS findings, got %+v", fs)
	}
	var oldVersion, selfSignedHit bool
	for _, f := range fs {
		if f.Title == "Veraltete TLS-Version ausgehandelt" {
			oldVersion = true
		}
		if f.Title == "Selbstsigniertes Zertifikat" {
			selfSignedHit = true
		}
	}
	if !oldVersion || !selfSignedHit {
		t.Errorf("missing TLS findings: oldVersion=%v selfSigned=%v", oldVersion, selfSignedHit)
	}

	// Expired certificate, modern TLS version: only the expiry should fire.
	expired := &x509.Certificate{
		Subject:  pkix.Name{CommonName: "a"},
		Issuer:   pkix.Name{CommonName: "b"},
		NotAfter: now.Add(-24 * time.Hour),
	}
	fs = analyzeTLS(tls.VersionTLS13, expired, "127.0.0.1:8443", now)
	var expiredHit bool
	for _, f := range fs {
		if f.Title == "Zertifikat abgelaufen" && f.Severity == finding.SeverityHigh {
			expiredHit = true
		}
	}
	if !expiredHit {
		t.Errorf("expected expired-cert finding, got %+v", fs)
	}
}

func TestAnalyzeHTTP(t *testing.T) {
	header := http.Header{}
	header.Set("Access-Control-Allow-Origin", "*")
	header.Set("Access-Control-Allow-Credentials", "true")
	header.Set("Server", "nginx/1.25.3")
	fs := analyzeHTTP("https://127.0.0.1:8443/", http.StatusOK, header, "Index of /")
	ids := ruleIDs(fs)
	for _, want := range []string{"ATK-HEADER", "ATK-CORS", "ATK-INFO", "ATK-DIRLIST"} {
		if !ids[want] {
			t.Errorf("expected %s finding, got %+v", want, fs)
		}
	}
	// ACAO * with credentials must be High.
	for _, f := range fs {
		if f.RuleID == "ATK-CORS" && f.Severity != finding.SeverityHigh {
			t.Errorf("CORS with credentials should be High, got %v", f.Severity)
		}
	}

	// A well-configured HTTP response yields no header/CORS findings.
	good := http.Header{}
	good.Set("Content-Security-Policy", "default-src 'self'")
	good.Set("X-Frame-Options", "DENY")
	good.Set("X-Content-Type-Options", "nosniff")
	good.Set("Strict-Transport-Security", "max-age=63072000")
	if fs := analyzeHTTP("https://127.0.0.1:8443/", http.StatusOK, good, "hello"); len(fs) != 0 {
		t.Errorf("expected no findings for hardened response, got %+v", fs)
	}
}

func TestScriptFindings(t *testing.T) {
	loc := finding.Location{File: "127.0.0.1:443"}
	scripts := []nmapScript{
		{ID: "ssl-poodle", Output: "VULNERABLE:\n  SSL POODLE information leak"},
		{ID: "ssl-enum-ciphers", Output: "TLSv1.0:\n  ciphers: RC4"},
		{ID: "ssl-cert", Output: "Subject: self-signed"},
		{ID: "http-methods", Output: "Supported Methods: GET POST PUT DELETE"},
		{ID: "http-title", Output: "Site title"},
	}
	fs := scriptFindings(scripts, loc)
	ids := ruleIDs(fs)
	for _, want := range []string{"ATK-VULN", "ATK-TLS", "ATK-HTTP"} {
		if !ids[want] {
			t.Errorf("expected %s from script findings, got %+v", want, fs)
		}
	}
}

func ruleIDs(fs []finding.Finding) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.RuleID] = true
	}
	return m
}

func TestInternalScanHosts(t *testing.T) {
	mk := func(name, net, ip string) sandbox.Container {
		var c sandbox.Container
		c.Name = "/" + name
		c.NetworkSettings.Networks = map[string]struct {
			NetworkID string `json:"NetworkID"`
			IPAddress string `json:"IPAddress"`
		}{net: {NetworkID: "id", IPAddress: ip}}
		return c
	}
	hosts := InternalScanHosts([]sandbox.Container{
		mk("web", "default", "172.20.0.2"),
		mk("db", "default", "172.20.0.3"),
		mk("noip", "default", ""), // no IP: skipped
	})
	if len(hosts) != 2 {
		t.Fatalf("got %d scan hosts, want 2 (empty IP skipped)", len(hosts))
	}
	// A duplicate IP is only returned once.
	dup := InternalScanHosts([]sandbox.Container{
		mk("a", "n1", "172.20.0.2"),
		mk("b", "n2", "172.20.0.2"),
	})
	if len(dup) != 1 {
		t.Errorf("duplicate IP should collapse to 1 host, got %d", len(dup))
	}
}

func TestURLFor(t *testing.T) {
	if got := urlFor(Target{Host: "127.0.0.1", Port: "8443"}); got != "https://127.0.0.1:8443" {
		t.Errorf("urlFor https = %q", got)
	}
	if got := urlFor(Target{Host: "127.0.0.1", Port: "8080"}); got != "http://127.0.0.1:8080" {
		t.Errorf("urlFor http = %q", got)
	}
}
