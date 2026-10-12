package attack

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/linus1423/Securety-Checker/internal/finding"
	"github.com/linus1423/Securety-Checker/internal/sandbox"
)

// defaultConcurrency bounds how many containers/targets are probed at once.
const defaultConcurrency = 4

// Options controls the dynamic attack phase.
type Options struct {
	Tools  Tools
	Notify func(string) // called with human-readable notes (missing tool, errors)
	// Progress, when set, is called with a short live-log line as each host or
	// target is picked up, so a long attack phase shows what it is doing.
	Progress func(string)
	// Concurrency is the maximum number of containers/targets probed in
	// parallel. Values <= 0 use a sensible default.
	Concurrency int
}

// Run attacks a live sandbox: it scans every published port and probes HTTP
// services, and checks the stack's network segmentation. Containers and targets
// are probed in parallel (bounded by Concurrency). It never aborts: a missing
// tool or a tool error becomes a note and the other attacks continue.
func Run(ctx context.Context, containers []sandbox.Container, opts Options) []finding.Finding {
	notify := opts.Notify
	if notify == nil {
		notify = func(string) {}
	}
	progress := opts.Progress
	if progress == nil {
		progress = func(string) {}
	}
	conc := opts.Concurrency
	if conc <= 0 {
		conc = defaultConcurrency
	}

	var (
		mu       sync.Mutex
		findings []finding.Finding
		wg       sync.WaitGroup
		sem      = make(chan struct{}, conc)
	)
	collect := func(fs ...finding.Finding) {
		if len(fs) == 0 {
			return
		}
		mu.Lock()
		findings = append(findings, fs...)
		mu.Unlock()
	}
	// spawn runs job in a bounded worker goroutine.
	spawn := func(job func()) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			job()
		}()
	}

	collect(clusterFindings(containers)...)

	targets := TargetsFromContainers(containers)
	hasNmap := opts.Tools.HasNmap()
	hasNuclei := opts.Tools.HasNuclei()
	if !hasNmap && (len(targets) > 0 || len(containers) > 0) {
		notify("nmap nicht gefunden; Portscans werden übersprungen")
	}
	if !hasNuclei && anyHTTP(targets) {
		notify("nuclei nicht gefunden; der tiefe Web-Scan wird übersprungen (native HTTP-Checks laufen trotzdem)")
	}

	// Intensive per-container scans: every open TCP port, common UDP ports and
	// the IPv6 interface, each on the container's own sandbox IP so it never
	// reaches outside the stack.
	if hasNmap {
		for _, h := range InternalScanHosts(containers) {
			h := h
			spawn(func() {
				progress(fmt.Sprintf("Intensiver Portscan: %s (%s)", h.Service, h.IP))
				if fs, err := opts.Tools.ScanAllPorts(ctx, h.IP); err != nil {
					notify(fmt.Sprintf("Intensiver Portscan übersprungen für %s (%s): %v", h.Service, h.IP, err))
				} else {
					collect(fs...)
				}
				progress(fmt.Sprintf("UDP-Scan: %s (%s)", h.Service, h.IP))
				if fs, err := opts.Tools.ScanUDP(ctx, h.IP); err != nil {
					notify(fmt.Sprintf("UDP-Scan übersprungen für %s (%s): %v", h.Service, h.IP, err))
				} else {
					collect(fs...)
				}
				if h.IPv6 != "" {
					progress(fmt.Sprintf("IPv6-Scan: %s (%s)", h.Service, h.IPv6))
					if fs, err := opts.Tools.ScanIPv6(ctx, h.IPv6); err != nil {
						notify(fmt.Sprintf("IPv6-Scan übersprungen für %s (%s): %v", h.Service, h.IPv6, err))
					} else {
						collect(fs...)
					}
				}
			})
		}
	}

	for _, tgt := range targets {
		tgt := tgt
		spawn(func() {
			progress(fmt.Sprintf("Probe %s auf %s:%s", tgt.Service, tgt.Host, tgt.Port))
			collect(probeTarget(ctx, opts.Tools, tgt, hasNmap, hasNuclei, notify)...)
		})
	}

	wg.Wait()
	finding.Sort(findings)
	return findings
}

// probeTarget runs every per-target probe and returns the findings. It is
// self-contained so it can run concurrently with other targets.
func probeTarget(ctx context.Context, tools Tools, tgt Target, hasNmap, hasNuclei bool, notify func(string)) []finding.Finding {
	var out []finding.Finding
	if hasNmap {
		if fs, err := tools.ScanPorts(ctx, tgt.Host, tgt.Port); err != nil {
			notify(fmt.Sprintf("Portscan übersprungen für %s:%s: %v", tgt.Host, tgt.Port, err))
		} else {
			out = append(out, fs...)
		}
	}

	// Native TLS probe (no external tool). A plaintext port simply fails the
	// handshake, so errors are expected and ignored.
	if fs, err := ProbeTLS(ctx, tgt.Host, tgt.Port); err == nil {
		out = append(out, fs...)
	}

	// Native unauthenticated-service / default-credential probe (no external
	// tool): unprotected DBs, caches, broker consoles, exposed Docker/Kubelet
	// APIs and anonymous FTP.
	out = append(out, ProbeServices(ctx, tgt)...)

	if tgt.IsHTTP {
		url := urlFor(tgt)
		// Native HTTP hygiene / exposure probe (no external tool).
		if fs, err := ProbeHTTP(ctx, url); err == nil {
			out = append(out, fs...)
		}
		// Native API-surface and injection probe (no external tool).
		out = append(out, ProbeAPI(ctx, url)...)
		if hasNuclei {
			if fs, err := tools.ScanURL(ctx, url); err != nil {
				notify(fmt.Sprintf("Web-Scan übersprungen für %s: %v", url, err))
			} else {
				out = append(out, fs...)
			}
		}
	}
	return out
}

func anyHTTP(targets []Target) bool {
	for _, t := range targets {
		if t.IsHTTP {
			return true
		}
	}
	return false
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
