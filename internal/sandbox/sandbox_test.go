package sandbox

import (
	"strings"
	"testing"

	"github.com/linus1423/Securety-Checker/internal/finding"
	"gopkg.in/yaml.v3"
)

const composeIn = `services:
  web:
    image: nginx:latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./site:/usr/share/nginx/html
      - /etc:/host-etc:ro
      - data:/var/lib/data
      - /anon-only
  db:
    image: postgres:16
    volumes:
      - pgdata:/var/lib/postgresql/data
volumes:
  data:
  pgdata:
`

func TestSandboxCompose(t *testing.T) {
	tr, err := SandboxCompose([]byte(composeIn))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Services map[string]struct {
			Volumes []string `yaml:"volumes"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(tr.YAML, &doc); err != nil {
		t.Fatalf("output is not valid yaml: %v\n%s", err, tr.YAML)
	}
	web := doc.Services["web"].Volumes
	joined := strings.Join(web, ",")
	if strings.Contains(joined, "docker.sock") {
		t.Errorf("docker.sock mount was not removed: %v", web)
	}
	if strings.Contains(joined, "./site") || strings.Contains(joined, "/etc:") {
		t.Errorf("host bind mounts were not replaced: %v", web)
	}
	// The container destinations survive as anonymous volumes.
	if !contains(web, "/usr/share/nginx/html") || !contains(web, "/host-etc") {
		t.Errorf("container paths missing after sandboxing: %v", web)
	}
	// Named volumes and anonymous volumes are kept.
	if !contains(web, "data:/var/lib/data") || !contains(web, "/anon-only") {
		t.Errorf("named/anonymous volumes not preserved: %v", web)
	}
	if doc.Services["db"].Volumes[0] != "pgdata:/var/lib/postgresql/data" {
		t.Errorf("db named volume changed: %v", doc.Services["db"].Volumes)
	}
}

func TestAnalyzeInspectDangerous(t *testing.T) {
	var c Container
	c.Name = "/app"
	c.Config.User = ""
	c.HostConfig.Privileged = true
	c.HostConfig.CapAdd = []string{"SYS_ADMIN"}
	c.HostConfig.Binds = []string{"/var/run/docker.sock:/var/run/docker.sock"}
	c.HostConfig.NetworkMode = "host"
	c.HostConfig.SecurityOpt = []string{"seccomp=unconfined"}
	c.NetworkSettings.Ports = map[string][]struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	}{"5432/tcp": {{HostIP: "0.0.0.0", HostPort: "5432"}}}

	got := ruleSet(AnalyzeInspect([]Container{c}))
	for _, id := range []string{"RUN001", "RUN002", "RUN003", "RUN004", "RUN005", "RUN006", "RUN007", "RUN008"} {
		if !got[id] {
			t.Errorf("expected runtime rule %s", id)
		}
	}
}

func TestAnalyzeInspectClean(t *testing.T) {
	var c Container
	c.Name = "/api"
	c.Config.User = "1000:1000"
	c.HostConfig.CapDrop = []string{"ALL"}
	c.HostConfig.ReadonlyRootfs = true
	c.State.Health = &struct {
		Status string `json:"Status"`
	}{Status: "healthy"}
	c.NetworkSettings.Ports = map[string][]struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	}{"8080/tcp": {{HostIP: "127.0.0.1", HostPort: "8080"}}}

	if fs := AnalyzeInspect([]Container{c}); len(fs) != 0 {
		t.Errorf("expected no runtime findings, got %+v", fs)
	}
}

func TestAnalyzeInspectHardening(t *testing.T) {
	var c Container
	c.Name = "/web"
	c.Config.User = "1000"
	c.State.Health = &struct {
		Status string `json:"Status"`
	}{Status: "healthy"}
	c.AppArmorProfile = "unconfined"
	c.HostConfig.Binds = []string{"/etc:/host-etc"} // writable sensitive host path

	got := ruleSet(AnalyzeInspect([]Container{c}))
	for _, id := range []string{"RUN009", "RUN010", "RUN011", "RUN012"} {
		if !got[id] {
			t.Errorf("expected runtime rule %s", id)
		}
	}
}

func TestBindSource(t *testing.T) {
	cases := []struct {
		bind     string
		src      string
		readOnly bool
	}{
		{"/etc:/host-etc:ro", "/etc", true},
		{"/etc:/host-etc", "/etc", false},
		{"/etc:/host-etc:rw", "/etc", false},
		{"data:/var/lib/data", "data", false},
	}
	for _, tc := range cases {
		src, ro := bindSource(tc.bind)
		if src != tc.src || ro != tc.readOnly {
			t.Errorf("bindSource(%q) = (%q, %v), want (%q, %v)", tc.bind, src, ro, tc.src, tc.readOnly)
		}
	}
	if !isSensitiveHostPath("/etc/passwd") {
		t.Error("expected /etc/passwd to be sensitive")
	}
	if isSensitiveHostPath("/srv/app/data") {
		t.Error("did not expect /srv/app/data to be sensitive")
	}
	if !capDropsAll([]string{"CAP_ALL"}) || !capDropsAll([]string{"ALL"}) {
		t.Error("capDropsAll should match ALL and CAP_ALL")
	}
	if capDropsAll([]string{"NET_ADMIN"}) {
		t.Error("capDropsAll should not match NET_ADMIN")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func ruleSet(fs []finding.Finding) map[string]bool {
	m := map[string]bool{}
	for _, f := range fs {
		m[f.RuleID] = true
	}
	return m
}
