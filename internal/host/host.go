// Package host checks the Docker daemon and host configuration, following the
// Docker Bench for Security recommendations.
package host

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"

	"github.com/linus1423/Securety-Checker/internal/finding"
)

// DefaultDaemonConfigPath is where the Docker daemon config normally lives.
const DefaultDaemonConfigPath = "/etc/docker/daemon.json"

// DaemonConfig is the subset of daemon.json we inspect. Pointers distinguish an
// explicit value from an absent key, which often defaults to the insecure side.
type DaemonConfig struct {
	ICC             *bool  `json:"icc"`
	UsernsRemap     string `json:"userns-remap"`
	LiveRestore     *bool  `json:"live-restore"`
	NoNewPrivileges *bool  `json:"no-new-privileges"`
}

// Info is the subset of `docker info` (JSON) we inspect.
type Info struct {
	SecurityOptions []string `json:"SecurityOptions"`
}

// Analyze turns the daemon config and docker info into findings. A nil daemon
// means no daemon.json was found, so defaults apply.
func Analyze(daemon *DaemonConfig, info *Info) []finding.Finding {
	loc := finding.Location{File: "docker-daemon"}
	var out []finding.Finding
	add := func(id, title string, sev finding.Severity, msg, rem string) {
		out = append(out, finding.Finding{
			RuleID: id, Title: title, Severity: sev, Location: loc,
			Message: msg, Remediation: rem,
			References: []string{"CIS Docker Benchmark 2.x"},
		})
	}

	if daemon == nil || daemon.ICC == nil || *daemon.ICC {
		add("HOST001", "Inter-Container-Kommunikation nicht deaktiviert", finding.SeverityLow,
			"icc ist aktiv (Standard)", "Setze \"icc\": false in daemon.json und verbinde Container gezielt über eigene Netze.")
	}
	if daemon == nil || strings.TrimSpace(daemon.UsernsRemap) == "" {
		add("HOST002", "User-Namespace-Remapping nicht aktiviert", finding.SeverityMedium,
			"userns-remap ist nicht gesetzt", "Aktiviere \"userns-remap\": \"default\", damit Container-root nicht Host-root ist.")
	}
	if daemon == nil || daemon.LiveRestore == nil || !*daemon.LiveRestore {
		add("HOST003", "live-restore nicht aktiviert", finding.SeverityLow,
			"Container stoppen bei Daemon-Neustart", "Setze \"live-restore\": true in daemon.json.")
	}
	if daemon == nil || daemon.NoNewPrivileges == nil || !*daemon.NoNewPrivileges {
		add("HOST004", "no-new-privileges nicht als Default gesetzt", finding.SeverityLow,
			"Prozesse können per setuid Rechte gewinnen", "Setze \"no-new-privileges\": true in daemon.json.")
	}
	if info != nil && !hasRootless(info.SecurityOptions) {
		add("HOST005", "Docker läuft nicht rootless", finding.SeverityLow,
			"Der Daemon läuft als root", "Erwäge den Rootless-Modus, um die Angriffsfläche des Hosts zu senken.")
	}
	return out
}

func hasRootless(opts []string) bool {
	for _, o := range opts {
		if strings.Contains(o, "rootless") {
			return true
		}
	}
	return false
}

// Check reads the daemon config and docker info and returns host findings.
// A missing daemon.json is fine (defaults apply); a docker info failure means
// the rootless check is skipped.
func Check(ctx context.Context, dockerBin, daemonPath string) ([]finding.Finding, error) {
	if dockerBin == "" {
		dockerBin = "docker"
	}
	if daemonPath == "" {
		daemonPath = DefaultDaemonConfigPath
	}
	var daemon *DaemonConfig
	if data, err := os.ReadFile(daemonPath); err == nil {
		var dc DaemonConfig
		if json.Unmarshal(data, &dc) == nil {
			daemon = &dc
		}
	}
	var info *Info
	if out, err := exec.CommandContext(ctx, dockerBin, "info", "--format", "{{json .}}").Output(); err == nil {
		var i Info
		if json.Unmarshal(out, &i) == nil {
			info = &i
		}
	}
	return Analyze(daemon, info), nil
}
