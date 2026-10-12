package attack

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/linus1423/Securety-Checker/internal/finding"
)

// ProbeTLS connects to host:port over TLS and reports configuration problems.
// It needs no external tool. Certificate verification is intentionally skipped
// so that a self-signed or expired certificate can be inspected and reported.
func ProbeTLS(ctx context.Context, host, port string) ([]finding.Finding, error) {
	dialer := &tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}}
	conn, err := dialer.DialContext(ctx, "tcp", host+":"+port)
	if err != nil {
		return nil, err // not a TLS service, or unreachable
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	var leaf *x509.Certificate
	if len(state.PeerCertificates) > 0 {
		leaf = state.PeerCertificates[0]
	}
	return analyzeTLS(state.Version, leaf, host+":"+port, time.Now()), nil
}

// analyzeTLS turns a negotiated TLS version and leaf certificate into findings.
func analyzeTLS(version uint16, leaf *x509.Certificate, target string, now time.Time) []finding.Finding {
	loc := finding.Location{File: target}
	var out []finding.Finding
	if version != 0 && version < tls.VersionTLS12 {
		out = append(out, finding.Finding{
			RuleID: "ATK-TLS", Title: "Veraltete TLS-Version ausgehandelt",
			Severity: finding.SeverityMedium, Location: loc, Message: tlsVersionName(version),
			Remediation: "Erzwinge mindestens TLS 1.2 und deaktiviere ältere Protokolle.",
		})
	}
	if leaf != nil {
		switch {
		case now.After(leaf.NotAfter):
			out = append(out, finding.Finding{
				RuleID: "ATK-TLS", Title: "Zertifikat abgelaufen",
				Severity: finding.SeverityHigh, Location: loc,
				Message:     fmt.Sprintf("abgelaufen am %s", leaf.NotAfter.Format("2006-01-02")),
				Remediation: "Zertifikat erneuern.",
			})
		case now.Add(30 * 24 * time.Hour).After(leaf.NotAfter):
			out = append(out, finding.Finding{
				RuleID: "ATK-TLS", Title: "Zertifikat läuft bald ab",
				Severity: finding.SeverityLow, Location: loc,
				Message:     fmt.Sprintf("läuft am %s ab", leaf.NotAfter.Format("2006-01-02")),
				Remediation: "Zertifikat rechtzeitig erneuern.",
			})
		}
		if isSelfSigned(leaf) {
			out = append(out, finding.Finding{
				RuleID: "ATK-TLS", Title: "Selbstsigniertes Zertifikat",
				Severity: finding.SeverityLow, Location: loc, Message: leaf.Subject.String(),
				Remediation: "Verwende ein von einer vertrauenswürdigen CA signiertes Zertifikat.",
			})
		}
	}
	return out
}

func isSelfSigned(c *x509.Certificate) bool {
	return c.Subject.String() == c.Issuer.String()
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
