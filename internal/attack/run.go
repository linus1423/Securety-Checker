package attack

import (
	"context"
	"fmt"
	"sort"

	"github.com/linus1423/Securety-Checker/internal/finding"
	"github.com/linus1423/Securety-Checker/internal/sandbox"
)

// Options controls the dynamic attack phase.
type Options struct {
	Tools  Tools
	Notify func(string) // called with human-readable notes (missing tool, errors)
}

// Run attacks a live sandbox: it scans every published port and probes HTTP
// services, and checks the stack's network segmentation. It never aborts: a
// missing tool or a tool error becomes a note and the other attacks continue.
func Run(ctx context.Context, containers []sandbox.Container, opts Options) []finding.Finding {
	notify := opts.Notify
	if notify == nil {
		notify = func(string) {}
	}
	var findings []finding.Finding
	findings = append(findings, clusterFindings(containers)...)

	targets := TargetsFromContainers(containers)
	hasNmap := opts.Tools.HasNmap()
	hasNuclei := opts.Tools.HasNuclei()
	if !hasNmap && (len(targets) > 0 || len(containers) > 0) {
		notify("nmap nicht gefunden; Portscans werden übersprungen")
	}

	// Intensive full-port scan per container: find and test *every* open port of
	// each container individually, not just the host-published ones. This scans
	// the container's own sandbox IP, so it never reaches outside the stack.
	if hasNmap {
		for _, h := range InternalScanHosts(containers) {
			if fs, err := opts.Tools.ScanAllPorts(ctx, h.IP); err != nil {
				notify(fmt.Sprintf("Intensiver Portscan übersprungen für %s (%s): %v", h.Service, h.IP, err))
			} else {
				findings = append(findings, fs...)
			}
			// UDP services on the same container IP (DNS, NTP, SNMP, ...).
			if fs, err := opts.Tools.ScanUDP(ctx, h.IP); err != nil {
				notify(fmt.Sprintf("UDP-Scan übersprungen für %s (%s): %v", h.Service, h.IP, err))
			} else {
				findings = append(findings, fs...)
			}
			// IPv6 interface, if the container has a global IPv6 address.
			if h.IPv6 != "" {
				if fs, err := opts.Tools.ScanIPv6(ctx, h.IPv6); err != nil {
					notify(fmt.Sprintf("IPv6-Scan übersprungen für %s (%s): %v", h.Service, h.IPv6, err))
				} else {
					findings = append(findings, fs...)
				}
			}
		}
	}

	nucleiNoted := false
	for _, tgt := range targets {
		if hasNmap {
			if fs, err := opts.Tools.ScanPorts(ctx, tgt.Host, tgt.Port); err != nil {
				notify(fmt.Sprintf("Portscan übersprungen für %s:%s: %v", tgt.Host, tgt.Port, err))
			} else {
				findings = append(findings, fs...)
			}
		}

		// Native TLS probe (no external tool). A plaintext port simply fails the
		// handshake, so errors are expected and ignored.
		if fs, err := ProbeTLS(ctx, tgt.Host, tgt.Port); err == nil {
			findings = append(findings, fs...)
		}

		// Native unauthenticated-service / default-credential probe (no external
		// tool): unprotected DBs, caches, broker consoles, exposed Docker/Kubelet
		// APIs and anonymous FTP.
		findings = append(findings, ProbeServices(ctx, tgt)...)

		if tgt.IsHTTP {
			url := urlFor(tgt)
			// Native HTTP hygiene / exposure probe (no external tool).
			if fs, err := ProbeHTTP(ctx, url); err == nil {
				findings = append(findings, fs...)
			}
			// Native API-surface and injection probe (no external tool).
			findings = append(findings, ProbeAPI(ctx, url)...)
			if hasNuclei {
				if fs, err := opts.Tools.ScanURL(ctx, url); err != nil {
					notify(fmt.Sprintf("Web-Scan übersprungen für %s: %v", url, err))
				} else {
					findings = append(findings, fs...)
				}
			} else if !nucleiNoted {
				notify("nuclei nicht gefunden; der tiefe Web-Scan wird übersprungen (native HTTP-Checks laufen trotzdem)")
				nucleiNoted = true
			}
		}
	}
	finding.Sort(findings)
	return findings
}

// clusterFindings checks the stack as a whole for weak network segmentation:
// when several services share one common network, any compromised service can
// reach the others (lateral movement).
func clusterFindings(containers []sandbox.Container) []finding.Finding {
	if len(containers) < 2 {
		return nil
	}
	// network name -> set of services on it
	members := map[string]map[string]bool{}
	for _, c := range containers {
		svc := trimName(c.Name)
		for net := range c.NetworkSettings.Networks {
			if members[net] == nil {
				members[net] = map[string]bool{}
			}
			members[net][svc] = true
		}
	}
	var out []finding.Finding
	for net, svcs := range members {
		if len(svcs) >= 3 {
			names := make([]string, 0, len(svcs))
			for s := range svcs {
				names = append(names, s)
			}
			sort.Strings(names)
			out = append(out, finding.Finding{
				RuleID:      "ATK-NETSEG",
				Title:       "Schwache Netzsegmentierung",
				Severity:    finding.SeverityMedium,
				Location:    finding.Location{File: "network/" + net},
				Message:     fmt.Sprintf("%d Services teilen das Netz %s: %v", len(svcs), net, names),
				Remediation: "Trenne Services in eigene Netze, damit ein kompromittierter Service nicht jeden anderen erreicht.",
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Location.File < out[j].Location.File })
	return out
}

func trimName(n string) string {
	if len(n) > 0 && n[0] == '/' {
		return n[1:]
	}
	return n
}
