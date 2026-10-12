package attack

import (
	"testing"

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

func TestURLFor(t *testing.T) {
	if got := urlFor(Target{Host: "127.0.0.1", Port: "8443"}); got != "https://127.0.0.1:8443" {
		t.Errorf("urlFor https = %q", got)
	}
	if got := urlFor(Target{Host: "127.0.0.1", Port: "8080"}); got != "http://127.0.0.1:8080" {
		t.Errorf("urlFor http = %q", got)
	}
}
