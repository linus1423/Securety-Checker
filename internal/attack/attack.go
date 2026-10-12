// Package attack runs dynamic security tests against a live sandbox: it scans
// every open port of each container individually with nmap (an intensive
// all-ports scan of the container's own sandbox IP), scans the published host
// ports, probes HTTP services natively and with nuclei, checks for
// unauthenticated services and default credentials (databases, caches, broker
// consoles, exposed Docker/Kubelet APIs, anonymous FTP) and probes the API
// surface (OpenAPI/Swagger, GraphQL introspection, path traversal, SQL errors).
//
// The attacks only ever target the sandbox that secchk started itself, never a
// production or third-party system. Each external tool is optional; a missing
// tool is reported and that attack is skipped.
package attack

import (
	"context"
	"os/exec"
	"strings"

	"github.com/linus1423/Securety-Checker/internal/finding"
	"github.com/linus1423/Securety-Checker/internal/sandbox"
)

// Target is one reachable endpoint of a sandbox service.
type Target struct {
	Service       string
	Host          string // the host address the published port is reachable on
	Port          string // the published host port
	ContainerPort string // the in-container port; identifies the likely service
	IsHTTP        bool
}

// canonicalPort returns the port that best identifies the service: the container
// port if known, else the published port.
func (t Target) canonicalPort() string {
	if t.ContainerPort != "" {
		return t.ContainerPort
	}
	return t.Port
}

// httpPorts are container ports that usually speak HTTP(S).
var httpPorts = map[string]bool{
	"80": true, "443": true, "8000": true, "8080": true, "8443": true,
	"3000": true, "5000": true, "8008": true, "9000": true,
}

// TargetsFromContainers derives attack targets from a stack's published ports.
func TargetsFromContainers(containers []sandbox.Container) []Target {
	var targets []Target
	for _, c := range containers {
		service := strings.TrimPrefix(c.Name, "/")
		for portProto, bindings := range c.NetworkSettings.Ports {
			containerPort := strings.SplitN(portProto, "/", 2)[0]
			for _, b := range bindings {
				if b.HostPort == "" {
					continue
				}
				host := b.HostIP
				if host == "" || host == "0.0.0.0" || host == "::" {
					host = "127.0.0.1"
				}
				targets = append(targets, Target{
					Service:       service,
					Host:          host,
					Port:          b.HostPort,
					ContainerPort: containerPort,
					IsHTTP:        httpPorts[containerPort] || httpPorts[b.HostPort],
				})
			}
		}
	}
	return targets
}

// ScanHost is a sandbox-internal host (one container's own IP) that can be
// scanned across all ports without touching anything outside the sandbox.
type ScanHost struct {
	Service string
	IP      string
}

// InternalScanHosts returns each container's internal sandbox IP addresses.
// Those IPs are owned by the sandbox containers alone, so scanning every port
// on them stays confined to the stack secchk started.
func InternalScanHosts(containers []sandbox.Container) []ScanHost {
	var hosts []ScanHost
	seen := map[string]bool{}
	for _, c := range containers {
		service := strings.TrimPrefix(c.Name, "/")
		for _, net := range c.NetworkSettings.Networks {
			ip := net.IPAddress
			if ip == "" || seen[ip] {
				continue
			}
			seen[ip] = true
			hosts = append(hosts, ScanHost{Service: service, IP: ip})
		}
	}
	return hosts
}

// Tools holds the external attack tools. Empty fields use the binary names.
type Tools struct {
	NmapBin   string
	NucleiBin string
	// DAST enables nuclei's fuzzing templates (SQLi, XSS, SSRF, LFI, cmd
	// injection). It is more intrusive, so it runs only inside the sandbox.
	DAST bool
}

func (t Tools) nmap() string {
	if t.NmapBin != "" {
		return t.NmapBin
	}
	return "nmap"
}

func (t Tools) nuclei() string {
	if t.NucleiBin != "" {
		return t.NucleiBin
	}
	return "nuclei"
}

// HasNmap reports whether nmap is available.
func (t Tools) HasNmap() bool { return lookPath(t.nmap()) }

// HasNuclei reports whether nuclei is available.
func (t Tools) HasNuclei() bool { return lookPath(t.nuclei()) }

func lookPath(bin string) bool {
	_, err := exec.LookPath(bin)
	return err == nil
}

// nmapScripts are the NSE scripts secchk runs for broad coverage: service
// banners, TLS/crypto configuration, HTTP hygiene and the general vuln category.
var nmapScripts = []string{
	"banner", "ssl-cert", "ssl-enum-ciphers", "ssl-dh-params", "ssl-heartbleed",
	"http-security-headers", "http-methods", "http-title",
	"ftp-anon", "ssh-auth-methods", "ssh2-enum-algos",
	"mongodb-info", "redis-info", "vuln",
}

// ScanPorts runs an nmap service/version scan with a broad script set against
// one host:port and returns findings for open ports, TLS/crypto issues and any
// VULNERABLE scripts.
func (t Tools) ScanPorts(ctx context.Context, host, port string) ([]finding.Finding, error) {
	args := []string{
		"-sV", "-Pn", "-p", port, "--open",
		"--script", strings.Join(nmapScripts, ","),
		"-oX", "-", host,
	}
	out, err := exec.CommandContext(ctx, t.nmap(), args...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, &toolError{tool: "nmap", stderr: string(ee.Stderr), err: err}
		}
		return nil, err
	}
	return parseNmapXML(out, host)
}

// ScanAllPorts runs an intensive nmap scan over *all* TCP ports of one host and
// tests each open port individually with the full script set. It is meant for a
// container's internal sandbox IP, which belongs to that container alone, so the
// all-ports scan stays confined to the sandbox. Never call it on a shared host
// address such as 127.0.0.1, where it would hit unrelated host services.
func (t Tools) ScanAllPorts(ctx context.Context, host string) ([]finding.Finding, error) {
	args := []string{
		"-sV", "--version-all", "-Pn", "-T4", "-p-", "--open",
		"--script", strings.Join(nmapScripts, ","),
		"-oX", "-", host,
	}
	out, err := exec.CommandContext(ctx, t.nmap(), args...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, &toolError{tool: "nmap", stderr: string(ee.Stderr), err: err}
		}
		return nil, err
	}
	return parseNmapXML(out, host)
}

// ScanURL runs nuclei against one URL and returns its findings. All template
// categories and severities are included for the widest coverage; with DAST set
// it also runs the fuzzing templates.
func (t Tools) ScanURL(ctx context.Context, url string) ([]finding.Finding, error) {
	args := []string{"-u", url, "-jsonl", "-silent", "-disable-update-check"}
	if t.DAST {
		args = append(args, "-dast")
	}
	out, err := exec.CommandContext(ctx, t.nuclei(), args...).Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			// nuclei exits non-zero when it finds issues; still parse the output.
			if parsed, perr := parseNucleiJSONL(out); perr == nil && len(parsed) > 0 {
				return parsed, nil
			}
			return nil, &toolError{tool: "nuclei", stderr: string(ee.Stderr), err: err}
		}
		return nil, err
	}
	return parseNucleiJSONL(out)
}

// riskyServices are cleartext or legacy services that should not be exposed.
var riskyServices = map[string]bool{
	"telnet": true, "ftp": true, "rlogin": true, "rsh": true, "vnc": true,
	"rexec": true, "tftp": true, "snmp": true,
}

func urlFor(target Target) string {
	scheme := "http"
	if target.Port == "443" || target.Port == "8443" {
		scheme = "https"
	}
	return scheme + "://" + target.Host + ":" + target.Port
}

func mapSeverity(s string) finding.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return finding.SeverityCritical
	case "high":
		return finding.SeverityHigh
	case "medium":
		return finding.SeverityMedium
	case "low":
		return finding.SeverityLow
	default:
		return finding.SeverityInfo
	}
}

type toolError struct {
	tool   string
	stderr string
	err    error
}

func (e *toolError) Error() string {
	if e.stderr != "" {
		return e.tool + ": " + strings.TrimSpace(e.stderr)
	}
	return e.tool + ": " + e.err.Error()
}
