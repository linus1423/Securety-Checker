package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/linus1423/Securety-Checker/internal/finding"
)

// Container is the subset of `docker inspect` output the runtime checks use.
type Container struct {
	Name            string `json:"Name"`
	AppArmorProfile string `json:"AppArmorProfile"`
	Config          struct {
		User string `json:"User"`
	} `json:"Config"`
	HostConfig struct {
		Privileged     bool     `json:"Privileged"`
		CapAdd         []string `json:"CapAdd"`
		CapDrop        []string `json:"CapDrop"`
		Binds          []string `json:"Binds"`
		NetworkMode    string   `json:"NetworkMode"`
		PidMode        string   `json:"PidMode"`
		IpcMode        string   `json:"IpcMode"`
		SecurityOpt    []string `json:"SecurityOpt"`
		ReadonlyRootfs bool     `json:"ReadonlyRootfs"`
		Memory         int64    `json:"Memory"`
		NanoCpus       int64    `json:"NanoCpus"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
		Networks map[string]struct {
			NetworkID         string `json:"NetworkID"`
			IPAddress         string `json:"IPAddress"`
			GlobalIPv6Address string `json:"GlobalIPv6Address"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
	State struct {
		Health *struct {
			Status string `json:"Status"`
		} `json:"Health"`
	} `json:"State"`
}

var runtimeDangerousCaps = map[string]bool{
	"ALL": true, "SYS_ADMIN": true, "NET_ADMIN": true, "SYS_PTRACE": true,
	"SYS_MODULE": true, "DAC_READ_SEARCH": true, "SYS_BOOT": true, "NET_RAW": true,
}

var runtimeDBPorts = map[string]string{
	"3306": "MySQL", "5432": "PostgreSQL", "27017": "MongoDB", "6379": "Redis",
	"9200": "Elasticsearch", "5984": "CouchDB", "11211": "Memcached", "1433": "MS SQL",
	"5672": "RabbitMQ", "9092": "Kafka", "2379": "etcd", "1521": "Oracle",
}

// AnalyzeInspect turns `docker inspect` output into runtime findings. It reports
// the container's *effective* configuration, which can differ from the Compose
// file because of image defaults and merged overrides.
func AnalyzeInspect(containers []Container) []finding.Finding {
	var out []finding.Finding
	add := func(c Container, id, title string, sev finding.Severity, msg, rem string) {
		out = append(out, finding.Finding{
			RuleID:      id,
			Title:       title,
			Severity:    sev,
			Location:    finding.Location{File: containerName(c.Name)},
			Message:     msg,
			Remediation: rem,
		})
	}
	for _, c := range containers {
		name := containerName(c.Name)
		if u := strings.SplitN(c.Config.User, ":", 2)[0]; u == "" || u == "root" || u == "0" {
			add(c, "RUN001", "Container läuft zur Laufzeit als root", finding.SeverityHigh,
				name+": effektiver User ist root", "Setze einen unprivilegierten User im Image oder per `user:`.")
		}
		if c.HostConfig.Privileged {
			add(c, "RUN002", "Container läuft privilegiert", finding.SeverityHigh,
				name, "Entferne privileged; vergib nur die nötigen Capabilities.")
		}
		for _, cap := range c.HostConfig.CapAdd {
			if runtimeDangerousCaps[strings.ToUpper(strings.TrimPrefix(strings.ToUpper(cap), "CAP_"))] {
				add(c, "RUN003", "Gefährliche Capability zur Laufzeit", finding.SeverityHigh,
					name+": "+cap, "Entferne die Capability oder ersetze sie durch die minimal nötige.")
			}
		}
		for _, b := range c.HostConfig.Binds {
			if strings.Contains(b, "docker.sock") {
				add(c, "RUN004", "Docker-Socket zur Laufzeit gemountet", finding.SeverityCritical,
					name+": "+b, "Mounte den Docker-Socket nicht in Container.")
			}
		}
		for label, mode := range map[string]string{"network": c.HostConfig.NetworkMode, "pid": c.HostConfig.PidMode, "ipc": c.HostConfig.IpcMode} {
			if strings.HasPrefix(mode, "host") {
				add(c, "RUN005", "Host-Namespace zur Laufzeit geteilt", finding.SeverityHigh,
					name+": "+label+"="+mode, "Verzichte auf host-Namespaces.")
			}
		}
		for _, opt := range c.HostConfig.SecurityOpt {
			if strings.Contains(strings.ToLower(opt), "unconfined") {
				add(c, "RUN007", "Sicherheitsprofil zur Laufzeit deaktiviert", finding.SeverityHigh,
					name+": "+opt, "Aktiviere die Default-seccomp/apparmor-Profile.")
			}
		}
		for portProto, bindings := range c.NetworkSettings.Ports {
			port := strings.SplitN(portProto, "/", 2)[0]
			svc, isDB := runtimeDBPorts[port]
			if !isDB {
				continue
			}
			for _, b := range bindings {
				if b.HostIP != "127.0.0.1" && b.HostIP != "localhost" && b.HostPort != "" {
					add(c, "RUN006", "Datenbank-Port zur Laufzeit veröffentlicht", finding.SeverityHigh,
						fmt.Sprintf("%s: %s-Port auf %s:%s", name, svc, hostIPLabel(b.HostIP), b.HostPort),
						"Binde interne Dienste an 127.0.0.1 oder gar nicht nach außen.")
				}
			}
		}
		if c.State.Health == nil {
			add(c, "RUN008", "Kein HEALTHCHECK zur Laufzeit", finding.SeverityLow,
				name, "Definiere einen HEALTHCHECK, damit ungesunde Container erkannt werden.")
		} else if c.State.Health.Status != "" && c.State.Health.Status != "healthy" {
			add(c, "RUN008", "Container nicht gesund", finding.SeverityLow,
				name+": Health "+c.State.Health.Status, "Prüfe, warum der HEALTHCHECK fehlschlägt.")
		}
		if c.AppArmorProfile == "unconfined" {
			add(c, "RUN009", "AppArmor unconfined", finding.SeverityHigh,
				name, "Lass das AppArmor-Default-Profil greifen, statt es auf unconfined zu setzen.")
		}
		if !capDropsAll(c.HostConfig.CapDrop) {
			add(c, "RUN010", "Capabilities nicht per Default entzogen", finding.SeverityLow,
				name+": kein cap_drop ALL", "Entziehe mit `cap_drop: [ALL]` alle Capabilities und füge nur die nötigen wieder hinzu.")
		}
		if !c.HostConfig.ReadonlyRootfs {
			add(c, "RUN011", "Root-Dateisystem zur Laufzeit beschreibbar", finding.SeverityLow,
				name, "Setze read_only und mounte nur die nötigen Pfade beschreibbar.")
		}
		for _, b := range c.HostConfig.Binds {
			if src, ro := bindSource(b); isSensitiveHostPath(src) && !ro {
				add(c, "RUN012", "Sensibler Host-Pfad zur Laufzeit beschreibbar gemountet", finding.SeverityHigh,
					name+": "+b, "Mounte Systempfade nicht oder nur read-only.")
			}
		}
		if c.HostConfig.Memory == 0 {
			add(c, "RUN013", "Kein Memory-Limit zur Laufzeit", finding.SeverityLow,
				name, "Setze `mem_limit`/`deploy.resources.limits.memory`, damit ein Container den Host nicht per OOM lahmlegt (DoS).")
		}
		if c.HostConfig.NanoCpus == 0 {
			add(c, "RUN014", "Kein CPU-Limit zur Laufzeit", finding.SeverityLow,
				name, "Setze `cpus`/`deploy.resources.limits.cpus`, damit ein Container nicht die gesamte CPU des Hosts belegt (DoS).")
		}
	}
	finding.Sort(out)
	return out
}

func containerName(n string) string {
	return strings.TrimPrefix(n, "/")
}

func hostIPLabel(ip string) string {
	if ip == "" || ip == "0.0.0.0" || ip == "::" {
		return "0.0.0.0"
	}
	return ip
}

// capDropsAll reports whether the container drops all capabilities by default.
func capDropsAll(caps []string) bool {
	for _, c := range caps {
		if strings.EqualFold(strings.TrimPrefix(strings.ToUpper(c), "CAP_"), "ALL") {
			return true
		}
	}
	return false
}

// bindSource splits a `docker inspect` bind string ("src:dst[:mode]") into its
// host source path and whether it is mounted read-only.
func bindSource(bind string) (src string, readOnly bool) {
	parts := strings.Split(bind, ":")
	if len(parts) == 0 {
		return "", false
	}
	src = parts[0]
	if len(parts) >= 3 {
		for _, opt := range strings.Split(parts[len(parts)-1], ",") {
			if opt == "ro" {
				readOnly = true
			}
		}
	}
	return src, readOnly
}

// runtimeSensitiveHostPaths are host paths that must not be mounted writable.
var runtimeSensitiveHostPaths = []string{
	"/", "/etc", "/var/run/docker.sock", "/var/run", "/root", "/home",
	"/boot", "/proc", "/sys", "/dev", "/var/lib/docker", "/usr", "/bin", "/sbin",
}

// isSensitiveHostPath reports whether src is (or lies under) a sensitive host path.
func isSensitiveHostPath(src string) bool {
	clean := filepath.Clean(src)
	for _, p := range runtimeSensitiveHostPaths {
		if clean == p {
			return true
		}
		if p != "/" && strings.HasPrefix(clean, p+"/") {
			return true
		}
	}
	return false
}

// Runner orchestrates a live sandbox run via the docker CLI.
type Runner struct {
	DockerBinary string // defaults to "docker"
}

func (r Runner) docker() string {
	if r.DockerBinary != "" {
		return r.DockerBinary
	}
	return "docker"
}

// Available reports whether docker and the compose plugin are usable.
func (r Runner) Available() bool {
	if _, err := exec.LookPath(r.docker()); err != nil {
		return false
	}
	cmd := exec.Command(r.docker(), "compose", "version")
	return cmd.Run() == nil
}

// RunFile starts one Compose file in a data-safe sandbox, inspects every
// container and tears the stack down afterwards, returning runtime findings.
func (r Runner) RunFile(ctx context.Context, composePath string) ([]finding.Finding, error) {
	return r.RunFileWith(ctx, composePath, nil)
}

// RunFileWith is like RunFile but also calls during while the stack is still
// running, so callers (the dynamic attack phase) can test the live services.
// Its findings are appended to the runtime findings.
func (r Runner) RunFileWith(ctx context.Context, composePath string, during func(context.Context, []Container) []finding.Finding) ([]finding.Finding, error) {
	data, err := os.ReadFile(composePath)
	if err != nil {
		return nil, err
	}
	tr, err := SandboxCompose(data)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(composePath)
	tmp := filepath.Join(dir, ".secchk-sandbox-"+randToken()+".yml")
	if err := os.WriteFile(tmp, tr.YAML, 0o600); err != nil {
		return nil, err
	}
	defer os.Remove(tmp)

	project := "secchk-" + randToken()
	base := []string{"compose", "-p", project, "-f", tmp}

	// Always tear down, even if bringing the stack up fails partway.
	defer func() {
		down := exec.Command(r.docker(), append(append([]string{}, base...), "down", "-v", "--remove-orphans")...)
		_ = down.Run()
	}()

	up := exec.CommandContext(ctx, r.docker(), append(append([]string{}, base...), "up", "-d", "--wait", "--quiet-pull")...)
	if out, err := up.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("compose up: %w: %s", err, strings.TrimSpace(string(out)))
	}

	ids, err := r.containerIDs(ctx, base)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}
	containers, err := r.inspect(ctx, ids)
	if err != nil {
		return nil, err
	}
	findings := AnalyzeInspect(containers)
	if during != nil {
		findings = append(findings, during(ctx, containers)...)
	}
	return findings, nil
}

func (r Runner) containerIDs(ctx context.Context, base []string) ([]string, error) {
	cmd := exec.CommandContext(ctx, r.docker(), append(append([]string{}, base...), "ps", "-q")...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("compose ps: %w", err)
	}
	var ids []string
	for _, line := range strings.Fields(string(out)) {
		ids = append(ids, line)
	}
	return ids, nil
}

func (r Runner) inspect(ctx context.Context, ids []string) ([]Container, error) {
	cmd := exec.CommandContext(ctx, r.docker(), append([]string{"inspect"}, ids...)...)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker inspect: %w", err)
	}
	var containers []Container
	if err := json.Unmarshal(out, &containers); err != nil {
		return nil, fmt.Errorf("parsing inspect output: %w", err)
	}
	return containers, nil
}

func randToken() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
