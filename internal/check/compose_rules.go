package check

import (
	"strings"

	"github.com/linus1423/Securety-Checker/internal/finding"
)

// dangerousCaps are Linux capabilities that largely undo container isolation.
var dangerousCaps = map[string]bool{
	"ALL": true, "SYS_ADMIN": true, "NET_ADMIN": true, "SYS_PTRACE": true,
	"SYS_MODULE": true, "DAC_READ_SEARCH": true, "SYS_BOOT": true, "NET_RAW": true,
}

// sensitiveHostPaths are host directories that should never be bind-mounted writable.
var sensitiveHostPaths = []string{"/", "/etc", "/var", "/usr", "/bin", "/sbin", "/boot", "/root", "/home", "/sys", "/proc", "/dev"}

// dbPorts maps well-known database ports to their service, for exposure checks.
var dbPorts = map[string]string{
	"3306": "MySQL", "5432": "PostgreSQL", "27017": "MongoDB", "6379": "Redis",
	"9200": "Elasticsearch", "5984": "CouchDB", "11211": "Memcached", "1433": "MS SQL",
	"5672": "RabbitMQ", "9092": "Kafka", "2379": "etcd", "1521": "Oracle",
}

// ComposeRules is the set of static Compose checks applied in M1.
var ComposeRules = []ComposeRule{
	{
		ID: "CMP001", Title: "Service läuft privilegiert", Severity: finding.SeverityHigh,
		Remediation: "Entferne `privileged: true`; vergib bei Bedarf einzelne Capabilities per cap_add.",
		Refs:        []string{cis("5.4")}, Fn: ruleComposePrivileged,
	},
	{
		ID: "CMP002", Title: "Gefährliche Linux-Capability", Severity: finding.SeverityHigh,
		Remediation: "Entferne die Capability oder ersetze sie durch die minimal nötige; ALL und SYS_ADMIN heben die Isolation auf.",
		Refs:        []string{cis("5.3")}, Fn: ruleComposeCaps,
	},
	{
		ID: "CMP003", Title: "Host-Namespace geteilt", Severity: finding.SeverityHigh,
		Remediation: "Verzichte auf network_mode/pid/ipc: host; nutze eigene Netze und Namespaces.",
		Refs:        []string{cis("5.9"), cis("5.15"), cis("5.16")}, Fn: ruleComposeHostNamespace,
	},
	{
		ID: "CMP004", Title: "Sicherheitsprofil deaktiviert", Severity: finding.SeverityHigh,
		Remediation: "Entferne seccomp:unconfined bzw. apparmor:unconfined, damit die Default-Profile greifen.",
		Refs:        []string{cis("5.21")}, Fn: ruleComposeUnconfined,
	},
	{
		ID: "CMP005", Title: "no-new-privileges nicht gesetzt", Severity: finding.SeverityLow,
		Remediation: "Setze `security_opt: [\"no-new-privileges:true\"]`, damit Prozesse keine Rechte dazugewinnen.",
		Refs:        []string{cis("5.25")}, Fn: ruleComposeNoNewPrivs,
	},
	{
		ID: "CMP006", Title: "Service läuft als root", Severity: finding.SeverityMedium,
		Remediation: "Setze `user:` auf einen unprivilegierten Benutzer statt root bzw. 0.",
		Refs:        []string{cis("4.1")}, Fn: ruleComposeUserRoot,
	},
	{
		ID: "CMP007", Title: "Docker-Socket gemountet", Severity: finding.SeverityCritical,
		Remediation: "Mounte /var/run/docker.sock nicht in Container; das gibt vollen Root-Zugriff auf den Host.",
		Refs:        []string{cis("5.31")}, Fn: ruleComposeDockerSock,
	},
	{
		ID: "CMP008", Title: "Sensibler Host-Pfad beschreibbar gemountet", Severity: finding.SeverityHigh,
		Remediation: "Mounte Systempfade gar nicht oder nur read-only (`:ro`).",
		Refs:        []string{cis("5.5")}, Fn: ruleComposeSensitiveMount,
	},
	{
		ID: "CMP009", Title: "Root-Dateisystem nicht read-only", Severity: finding.SeverityLow,
		Remediation: "Setze `read_only: true` und mounte nur die wirklich beschreibbaren Pfade als tmpfs oder Volume.",
		Refs:        []string{cis("5.12")}, Fn: ruleComposeReadOnly,
	},
	{
		ID: "CMP010", Title: "Datenbank-Port nach außen veröffentlicht", Severity: finding.SeverityHigh,
		Remediation: "Binde interne Dienste an 127.0.0.1 oder veröffentliche sie gar nicht; nutze das interne Compose-Netz.",
		Refs:        []string{cis("5.7")}, Fn: ruleComposeExposedDBPort,
	},
	{
		ID: "CMP011", Title: "Secret im Klartext in environment", Severity: finding.SeverityHigh,
		Remediation: "Verwende Docker-Secrets oder eine .env, die nicht eingecheckt ist, statt Klartext in der Compose-Datei.",
		Refs:        []string{cis("5.10")}, Fn: ruleComposeEnvSecret,
	},
	{
		ID: "CMP012", Title: "Keine Ressourcenlimits", Severity: finding.SeverityLow,
		Remediation: "Setze mem_limit/cpus (bzw. deploy.resources.limits), damit ein Container den Host nicht erschöpft.",
		Refs:        []string{cis("5.10"), cis("5.11")}, Fn: ruleComposeNoLimits,
	},
	{
		ID: "CMP013", Title: "Image ohne festen Tag oder mit latest", Severity: finding.SeverityMedium,
		Remediation: "Pinne das Image auf einen konkreten Tag statt latest oder keinem Tag.",
		Refs:        []string{cis("4.2")}, Fn: ruleComposeFloatingImage,
	},
}

func ruleComposePrivileged(t *ComposeTarget) []Hit {
	var hits []Hit
	for _, s := range t.File.Services {
		if v, line, ok := s.Bool("privileged"); ok && v {
			hits = append(hits, Hit{Line: line, Message: "Service " + s.Name})
		}
	}
	return hits
}

func ruleComposeCaps(t *ComposeTarget) []Hit {
	var hits []Hit
	for _, s := range t.File.Services {
		caps, line, ok := s.Seq("cap_add")
		if !ok {
			continue
		}
		for _, c := range caps {
			if dangerousCaps[strings.ToUpper(strings.TrimPrefix(strings.ToUpper(c), "CAP_"))] {
				hits = append(hits, Hit{Line: line, Message: "Service " + s.Name + " fügt " + c + " hinzu"})
			}
		}
	}
	return hits
}

func ruleComposeHostNamespace(t *ComposeTarget) []Hit {
	var hits []Hit
	for _, s := range t.File.Services {
		for _, key := range []string{"network_mode", "pid", "ipc"} {
			if v, line, ok := s.Scalar(key); ok && strings.HasPrefix(v, "host") {
				hits = append(hits, Hit{Line: line, Message: "Service " + s.Name + ": " + key + ": " + v})
			}
		}
	}
	return hits
}

func ruleComposeUnconfined(t *ComposeTarget) []Hit {
	var hits []Hit
	for _, s := range t.File.Services {
		opts, line, ok := s.Seq("security_opt")
		if !ok {
			continue
		}
		for _, o := range opts {
			if strings.Contains(strings.ToLower(o), "unconfined") {
				hits = append(hits, Hit{Line: line, Message: "Service " + s.Name + ": " + o})
			}
		}
	}
	return hits
}

func ruleComposeNoNewPrivs(t *ComposeTarget) []Hit {
	var hits []Hit
	for _, s := range t.File.Services {
		opts, _, ok := s.Seq("security_opt")
		found := false
		if ok {
			for _, o := range opts {
				if strings.Contains(strings.ToLower(o), "no-new-privileges") && strings.Contains(o, "true") {
					found = true
				}
			}
		}
		if !found {
			hits = append(hits, Hit{Line: s.Line, Message: "Service " + s.Name})
		}
	}
	return hits
}

func ruleComposeUserRoot(t *ComposeTarget) []Hit {
	var hits []Hit
	for _, s := range t.File.Services {
		if v, line, ok := s.Scalar("user"); ok {
			id := strings.SplitN(v, ":", 2)[0]
			if id == "root" || id == "0" {
				hits = append(hits, Hit{Line: line, Message: "Service " + s.Name + ": user " + v})
			}
		}
	}
	return hits
}

func ruleComposeDockerSock(t *ComposeTarget) []Hit {
	var hits []Hit
	for _, s := range t.File.Services {
		vols, line, ok := s.Seq("volumes")
		if !ok {
			continue
		}
		for _, v := range vols {
			if strings.Contains(v, "docker.sock") {
				hits = append(hits, Hit{Line: line, Message: "Service " + s.Name + ": " + v})
			}
		}
	}
	return hits
}

func ruleComposeSensitiveMount(t *ComposeTarget) []Hit {
	var hits []Hit
	for _, s := range t.File.Services {
		vols, line, ok := s.Seq("volumes")
		if !ok {
			continue
		}
		for _, v := range vols {
			parts := strings.Split(v, ":")
			if len(parts) < 2 || !strings.HasPrefix(parts[0], "/") {
				continue
			}
			src := strings.TrimRight(parts[0], "/")
			if src == "" {
				src = "/"
			}
			readOnly := len(parts) >= 3 && parts[len(parts)-1] == "ro"
			if !readOnly && isSensitivePath(src) {
				hits = append(hits, Hit{Line: line, Message: "Service " + s.Name + " mountet " + parts[0] + " beschreibbar"})
			}
		}
	}
	return hits
}

func ruleComposeReadOnly(t *ComposeTarget) []Hit {
	var hits []Hit
	for _, s := range t.File.Services {
		if v, _, ok := s.Bool("read_only"); !ok || !v {
			hits = append(hits, Hit{Line: s.Line, Message: "Service " + s.Name})
		}
	}
	return hits
}

func ruleComposeExposedDBPort(t *ComposeTarget) []Hit {
	var hits []Hit
	for _, s := range t.File.Services {
		ports, line, ok := s.Seq("ports")
		if !ok {
			continue
		}
		for _, p := range ports {
			hostIP, container := parsePort(p)
			svc, isDB := dbPorts[container]
			if isDB && hostIP != "127.0.0.1" && hostIP != "localhost" {
				hits = append(hits, Hit{Line: line, Message: "Service " + s.Name + " veröffentlicht " + svc + "-Port " + p})
			}
		}
	}
	return hits
}

func ruleComposeEnvSecret(t *ComposeTarget) []Hit {
	var hits []Hit
	for _, s := range t.File.Services {
		for _, e := range s.Env() {
			if e.HasValue && looksSecret(e.Name, e.Value) {
				hits = append(hits, Hit{Line: e.Line, Message: "Service " + s.Name + ": " + e.Name})
			}
		}
	}
	return hits
}

func ruleComposeNoLimits(t *ComposeTarget) []Hit {
	var hits []Hit
	for _, s := range t.File.Services {
		if s.Has("mem_limit") || s.Has("cpus") || s.Has("deploy") {
			continue
		}
		hits = append(hits, Hit{Line: s.Line, Message: "Service " + s.Name})
	}
	return hits
}

func ruleComposeFloatingImage(t *ComposeTarget) []Hit {
	var hits []Hit
	for _, s := range t.File.Services {
		img, line, ok := s.Scalar("image")
		if !ok {
			continue // build-only service
		}
		tag := imageTag(img)
		if tag == "" {
			hits = append(hits, Hit{Line: line, Message: "Service " + s.Name + ": " + img + " ohne Tag"})
		} else if tag == "latest" {
			hits = append(hits, Hit{Line: line, Message: "Service " + s.Name + ": " + img + " nutzt latest"})
		}
	}
	return hits
}

func isSensitivePath(src string) bool {
	for _, p := range sensitiveHostPaths {
		if src == p {
			return true
		}
	}
	return false
}

// parsePort splits a short-form compose port mapping into its host IP and
// container port. An entry with only a container port reports an empty host IP.
func parsePort(entry string) (hostIP, containerPort string) {
	entry = strings.TrimSpace(entry)
	if i := strings.Index(entry, "/"); i >= 0 {
		entry = entry[:i] // drop /tcp or /udp
	}
	parts := strings.Split(entry, ":")
	switch len(parts) {
	case 1:
		return "", parts[0]
	case 2:
		return "0.0.0.0", parts[1]
	default:
		return parts[0], parts[len(parts)-1]
	}
}
