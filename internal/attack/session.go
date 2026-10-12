package attack

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"

	"github.com/linus1423/Securety-Checker/internal/finding"
)

// sessionCookieRe matches cookie names that usually carry a session or auth token.
var sessionCookieRe = regexp.MustCompile(`(?i)(session|sess|sid|auth|token|jwt|csrf|xsrf|login|remember)`)

// jwtRe matches a JSON Web Token: three base64url segments separated by dots,
// the first two being JSON objects (header and payload both begin "eyJ").
var jwtRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*`)

// weakJWTSecrets are HMAC signing keys that are shipped as defaults or trivially
// guessed; if one verifies a token's signature the signing key is effectively
// public.
var weakJWTSecrets = []string{
	"secret", "password", "changeme", "123456", "jwt", "key", "token",
	"your-256-bit-secret", "admin", "test", "mysecret", "supersecret",
	"default", "s3cr3t", "secretkey", "jwtsecret",
}

// analyzeCookies inspects Set-Cookie headers for session cookies that lack the
// Secure, HttpOnly or SameSite protections. It is pure so it can be tested
// without a live server.
func analyzeCookies(url string, header http.Header, isHTTPS bool) []finding.Finding {
	loc := finding.Location{File: url}
	var out []finding.Finding
	for _, sc := range header.Values("Set-Cookie") {
		name, attrs := parseSetCookie(sc)
		if name == "" || !sessionCookieRe.MatchString(name) {
			continue
		}
		var missing []string
		if !attrs["httponly"] {
			missing = append(missing, "HttpOnly")
		}
		if isHTTPS && !attrs["secure"] {
			missing = append(missing, "Secure")
		}
		if _, ok := attrs["samesite"]; !ok {
			missing = append(missing, "SameSite")
		}
		if len(missing) > 0 {
			out = append(out, finding.Finding{
				RuleID: "ATK-COOKIE", Title: "Session-Cookie ohne Schutzattribute",
				Severity: finding.SeverityMedium, Location: loc,
				Message:     "Cookie " + name + " fehlt: " + strings.Join(missing, ", "),
				Remediation: "Setze Session-Cookies mit HttpOnly, Secure (über HTTPS) und SameSite.",
			})
		}
	}
	return out
}

// analyzeJWTs finds JWTs in Set-Cookie headers and in the response body and
// reports unsigned tokens (alg none / empty signature) and tokens signed with a
// weak, guessable HMAC key. It is pure so it can be tested without a live server.
func analyzeJWTs(url, body string, header http.Header) []finding.Finding {
	loc := finding.Location{File: url}
	var out []finding.Finding
	seen := map[string]bool{}
	tokens := jwtRe.FindAllString(strings.Join(header.Values("Set-Cookie"), "\n"), -1)
	tokens = append(tokens, jwtRe.FindAllString(body, -1)...)
	for _, tok := range tokens {
		if seen[tok] {
			continue
		}
		seen[tok] = true
		if f, ok := analyzeJWT(loc, tok); ok {
			out = append(out, f)
		}
	}
	return out
}

// analyzeJWT inspects one token. It returns a finding only for a real weakness.
func analyzeJWT(loc finding.Location, tok string) (finding.Finding, bool) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return finding.Finding{}, false
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return finding.Finding{}, false
	}
	var h struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerJSON, &h); err != nil {
		return finding.Finding{}, false
	}
	alg := strings.ToLower(h.Alg)

	// Unsigned token: alg "none" or an empty signature segment.
	if alg == "none" || alg == "" || parts[2] == "" {
		return finding.Finding{
			RuleID: "ATK-JWT", Title: "Unsigniertes JWT akzeptiert/ausgestellt",
			Severity: finding.SeverityCritical, Location: loc,
			Message:     "JWT mit alg=\"" + h.Alg + "\" ohne gültige Signatur",
			Remediation: "Lehne alg=none ab und signiere Tokens mit einem starken, geheimen Schlüssel (z. B. RS256).",
		}, true
	}

	// Weak HMAC signing key: try a short list of default/guessable secrets.
	if strings.HasPrefix(alg, "hs") {
		if secret, ok := crackHS(tok, alg); ok {
			return finding.Finding{
				RuleID: "ATK-JWT", Title: "JWT mit schwachem Signaturschlüssel",
				Severity: finding.SeverityCritical, Location: loc,
				Message:     "HMAC-Schlüssel erraten: \"" + secret + "\" (Tokens sind fälschbar)",
				Remediation: "Verwende einen langen, zufälligen Signaturschlüssel und rotiere ihn.",
			}, true
		}
	}
	return finding.Finding{}, false
}

// crackHS tries the weak-secret list against an HS256/384/512 token's signature.
func crackHS(tok, alg string) (string, bool) {
	i := strings.LastIndex(tok, ".")
	if i < 0 {
		return "", false
	}
	signingInput := tok[:i]
	sig, err := base64.RawURLEncoding.DecodeString(tok[i+1:])
	if err != nil {
		return "", false
	}
	// Only HS256 is verified here; it is by far the most common and the one that
	// weak-key misuse affects. Other sizes simply skip the check.
	if alg != "hs256" {
		return "", false
	}
	for _, secret := range weakJWTSecrets {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(signingInput))
		if hmac.Equal(mac.Sum(nil), sig) {
			return secret, true
		}
	}
	return "", false
}

// parseSetCookie splits a Set-Cookie value into the cookie name and its
// lower-cased attribute set (flag attributes map to true; SameSite is present
// with any value).
func parseSetCookie(sc string) (name string, attrs map[string]bool) {
	attrs = map[string]bool{}
	segs := strings.Split(sc, ";")
	if len(segs) == 0 {
		return "", attrs
	}
	nv := strings.SplitN(strings.TrimSpace(segs[0]), "=", 2)
	name = strings.TrimSpace(nv[0])
	for _, s := range segs[1:] {
		k := strings.ToLower(strings.TrimSpace(s))
		if eq := strings.IndexByte(k, '='); eq >= 0 {
			k = k[:eq]
		}
		attrs[k] = true
	}
	return name, attrs
}
