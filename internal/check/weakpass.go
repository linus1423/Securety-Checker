package check

import (
	"regexp"
	"strings"
)

// passwordKeyRe matches variable names that hold a password (narrower than
// secretKeyRe: only password-like keys, so the weak-password check does not fire
// on tokens or keys, which are rated by their own rules).
var passwordKeyRe = regexp.MustCompile(`(?i)(password|passwd|^pwd$|_pwd$|[_-]pwd[_-]|root_?pw|db_?pw)`)

// defaultPasswords are credentials shipped by popular images or picked by hand
// that attackers try first. A match is an actively exploitable weakness, not
// merely a hygiene issue.
var defaultPasswords = map[string]bool{
	"password": true, "passwd": true, "pass": true, "password123": true,
	"admin": true, "admin123": true, "administrator": true, "root": true,
	"toor": true, "changeme": true, "change-me": true, "secret": true,
	"default": true, "test": true, "test123": true, "guest": true,
	"123456": true, "1234": true, "12345": true, "12345678": true, "123456789": true,
	"qwerty": true, "letmein": true, "welcome": true, "p@ssw0rd": true, "passw0rd": true,
	"postgres": true, "mysql": true, "redis": true, "mongo": true, "example": true,
	"docker": true, "user": true, "demo": true, "abc123": true,
}

// weakPassword classifies a password value. It returns whether the value is weak
// and a short reason. A placeholder (${VAR}) or an empty value is never weak,
// since the real value is injected elsewhere.
func weakPassword(value string) (reason string, weak bool) {
	v := strings.Trim(strings.TrimSpace(value), `"'`)
	if v == "" || placeholderRe.MatchString(v) {
		return "", false
	}
	if defaultPasswords[strings.ToLower(v)] {
		return "bekanntes Default-/Trivialpasswort", true
	}
	// Heuristically weak: short, or no character-class variety.
	if len(v) < 8 {
		return "sehr kurz (< 8 Zeichen)", true
	}
	switch {
	case onlyDigits(v):
		return "nur Ziffern", true
	case onlyLettersLower(v):
		return "nur Kleinbuchstaben", true
	}
	return "", false
}

func onlyDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func onlyLettersLower(s string) bool {
	for _, r := range s {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}

// ruleWeakPasswordDockerfile flags weak or default passwords hard-coded in ENV
// or ARG instructions.
func ruleWeakPasswordDockerfile(t *DockerfileTarget) []Hit {
	var hits []Hit
	for _, in := range t.DF.Instructions() {
		switch in.Cmd {
		case "ENV":
			for i := 0; i+1 < len(in.Args); i += 2 {
				if passwordKeyRe.MatchString(in.Args[i]) {
					if reason, weak := weakPassword(in.Args[i+1]); weak {
						hits = append(hits, Hit{Line: in.Line, Message: "ENV " + in.Args[i] + ": " + reason})
					}
				}
			}
		case "ARG":
			for _, a := range in.Args {
				name, val, has := strings.Cut(a, "=")
				if has && passwordKeyRe.MatchString(name) {
					if reason, weak := weakPassword(val); weak {
						hits = append(hits, Hit{Line: in.Line, Message: "ARG " + name + ": " + reason})
					}
				}
			}
		}
	}
	return hits
}

// ruleWeakPasswordCompose flags weak or default passwords in a service's
// environment block.
func ruleWeakPasswordCompose(t *ComposeTarget) []Hit {
	var hits []Hit
	for _, s := range t.File.Services {
		for _, e := range s.Env() {
			if !e.HasValue || !passwordKeyRe.MatchString(e.Name) {
				continue
			}
			if reason, weak := weakPassword(e.Value); weak {
				hits = append(hits, Hit{Line: e.Line, Message: "Service " + s.Name + ": " + e.Name + " (" + reason + ")"})
			}
		}
	}
	return hits
}
