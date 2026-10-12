package attack

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"testing"
)

// makeJWT builds a token with the given alg header. If secret is non-empty the
// signature is a real HS256 MAC; otherwise the signature segment is set to sig.
func makeJWT(alg, secret, sig string) string {
	b64 := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	header := b64(`{"alg":"` + alg + `","typ":"JWT"}`)
	payload := b64(`{"sub":"1","role":"user"}`)
	signingInput := header + "." + payload
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(signingInput))
		sig = base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	}
	return signingInput + "." + sig
}

func TestParseSetCookie(t *testing.T) {
	name, attrs := parseSetCookie("sessionid=abc; Path=/; HttpOnly; SameSite=Lax")
	if name != "sessionid" {
		t.Fatalf("name = %q", name)
	}
	if !attrs["httponly"] || !attrs["samesite"] || !attrs["path"] {
		t.Fatalf("attrs = %v", attrs)
	}
	if attrs["secure"] {
		t.Fatalf("secure should be absent")
	}
}

func TestAnalyzeCookies(t *testing.T) {
	h := http.Header{}
	h.Add("Set-Cookie", "sessionid=abc; Path=/") // session cookie, no protections
	h.Add("Set-Cookie", "theme=dark; Path=/")    // not a session cookie: ignored
	fs := analyzeCookies("https://x", h, true)
	if len(fs) != 1 || fs[0].RuleID != "ATK-COOKIE" {
		t.Fatalf("expected one ATK-COOKIE, got %+v", fs)
	}
	for _, want := range []string{"HttpOnly", "Secure", "SameSite"} {
		if !strings.Contains(fs[0].Message, want) {
			t.Errorf("message should mention missing %s: %q", want, fs[0].Message)
		}
	}

	// A fully protected session cookie produces nothing.
	h2 := http.Header{}
	h2.Add("Set-Cookie", "sessionid=abc; Path=/; HttpOnly; Secure; SameSite=Strict")
	if got := analyzeCookies("https://x", h2, true); len(got) != 0 {
		t.Fatalf("hardened cookie should be clean, got %+v", got)
	}
}

func TestAnalyzeJWTNoneAlg(t *testing.T) {
	tok := makeJWT("none", "", "")
	fs := analyzeJWTs("http://x", "token="+tok, http.Header{})
	if len(fs) != 1 || fs[0].RuleID != "ATK-JWT" || fs[0].Severity.String() != "critical" {
		t.Fatalf("expected critical ATK-JWT for alg=none, got %+v", fs)
	}
}

func TestAnalyzeJWTWeakKey(t *testing.T) {
	tok := makeJWT("HS256", "secret", "") // signed with a weak, listed key
	h := http.Header{}
	h.Add("Set-Cookie", "jwt="+tok+"; Path=/")
	fs := analyzeJWTs("http://x", "", h)
	if len(fs) != 1 || fs[0].RuleID != "ATK-JWT" {
		t.Fatalf("expected ATK-JWT for weak key, got %+v", fs)
	}
	if !strings.Contains(fs[0].Message, "secret") {
		t.Errorf("message should name the cracked secret: %q", fs[0].Message)
	}
}

func TestAnalyzeJWTStrongKeyClean(t *testing.T) {
	tok := makeJWT("HS256", "a-very-long-random-signing-key-not-in-the-list-9f8a7", "")
	fs := analyzeJWTs("http://x", "body "+tok, http.Header{})
	if len(fs) != 0 {
		t.Fatalf("strong-key token should be clean, got %+v", fs)
	}
}

func TestAnalyzeJWTIgnoresNonToken(t *testing.T) {
	if fs := analyzeJWTs("http://x", "no tokens here", http.Header{}); len(fs) != 0 {
		t.Fatalf("expected no findings, got %+v", fs)
	}
}
