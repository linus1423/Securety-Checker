package check

import (
	"regexp"
	"strings"

	"github.com/linus1423/Securety-Checker/internal/dockerfile"
	"github.com/linus1423/Securety-Checker/internal/finding"
)

// secretKeyRe matches variable names that usually hold secrets.
var secretKeyRe = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)`)

// pipeToShellRe matches downloading a script and piping it into a shell.
var pipeToShellRe = regexp.MustCompile(`(?is)(curl|wget)\b.*\|\s*(sudo\s+)?(sh|bash|zsh)\b`)

// placeholderRe matches values that are build-time variables, not literals.
var placeholderRe = regexp.MustCompile(`\$\{?\w+`)

// DockerfileRules is the set of static Dockerfile checks applied in M1.
var DockerfileRules = []DockerfileRule{
	{
		ID:          "DF001",
		Title:       "Container läuft als root",
		Severity:    finding.SeverityHigh,
		Remediation: "Lege einen unprivilegierten Benutzer an und setze ihn mit USER, z. B. `RUN adduser -D app` und `USER app`.",
		Refs:        []string{cis("4.1"), "https://owasp.org/www-project-docker-security/"},
		Fn:          ruleRootUser,
	},
	{
		ID:          "DF002",
		Title:       "Basisimage ohne festen Tag oder mit latest",
		Severity:    finding.SeverityMedium,
		Remediation: "Verwende einen konkreten Versions-Tag statt latest oder keinem Tag, idealerweise zusätzlich einen Digest.",
		Refs:        []string{cis("4.2")},
		Fn:          ruleFloatingTag,
	},
	{
		ID:          "DF003",
		Title:       "Basisimage nicht per Digest gepinnt",
		Severity:    finding.SeverityLow,
		Remediation: "Pinne das Image per Digest, z. B. `FROM alpine:3.20@sha256:...`, damit Builds reproduzierbar sind.",
		Refs:        []string{cis("4.2")},
		Fn:          ruleNoDigest,
	},
	{
		ID:          "DF004",
		Title:       "ADD lädt eine entfernte URL",
		Severity:    finding.SeverityMedium,
		Remediation: "Lade Dateien mit COPY aus dem Build-Kontext oder mit einem RUN-Schritt, der die Prüfsumme verifiziert.",
		Refs:        []string{"https://docs.docker.com/develop/develop-images/instructions/#add-or-copy"},
		Fn:          ruleAddRemote,
	},
	{
		ID:          "DF005",
		Title:       "Entferntes Skript wird in eine Shell gepipt",
		Severity:    finding.SeverityHigh,
		Remediation: "Lade das Skript, prüfe seine Prüfsumme und führe es erst dann aus, statt `curl ... | sh`.",
		Refs:        []string{"https://owasp.org/www-project-docker-security/"},
		Fn:          rulePipeToShell,
	},
	{
		ID:          "DF006",
		Title:       "Mögliches Secret in ENV oder ARG",
		Severity:    finding.SeverityHigh,
		Remediation: "Übergib Secrets zur Laufzeit oder per BuildKit-Secret-Mount, nie als ENV/ARG, das im Image-Layer landet.",
		Refs:        []string{cis("4.10")},
		Fn:          ruleSecretEnvArg,
	},
	{
		ID:          "DF007",
		Title:       "Kein HEALTHCHECK definiert",
		Severity:    finding.SeverityLow,
		Remediation: "Füge einen HEALTHCHECK hinzu, damit die Orchestrierung ungesunde Container erkennt.",
		Refs:        []string{cis("4.6")},
		Fn:          ruleNoHealthcheck,
	},
	{
		ID:          "DF008",
		Title:       "COPY/ADD des gesamten Kontexts ohne .dockerignore",
		Severity:    finding.SeverityMedium,
		Remediation: "Lege eine .dockerignore an, damit Secrets, .git und lokale Artefakte nicht ins Image gelangen.",
		Refs:        []string{"https://docs.docker.com/build/building/context/#dockerignore-files"},
		Fn:          ruleCopyAllNoIgnore,
	},
	{
		ID:          "DF009",
		Title:       "Verwendung von sudo im Build",
		Severity:    finding.SeverityLow,
		Remediation: "Führe Build-Schritte direkt als passender Benutzer aus, statt sudo zu installieren oder zu nutzen.",
		Refs:        []string{cis("4.1")},
		Fn:          ruleSudo,
	},
	{
		ID:          "DF010",
		Title:       "Schwaches oder Default-Passwort in ENV/ARG",
		Severity:    finding.SeverityHigh,
		Remediation: "Verwende ein starkes, zufälliges Passwort und übergib es zur Laufzeit per Secret, nie als Default im Image.",
		Refs:        []string{cis("4.10"), "https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_password"},
		Fn:          ruleWeakPasswordDockerfile,
	},
}

func finalStage(t *DockerfileTarget) *dockerfile.Stage {
	return t.DF.FinalStage()
}

func ruleRootUser(t *DockerfileTarget) []Hit {
	s := finalStage(t)
	if s == nil {
		return nil
	}
	var lastUser *dockerfile.Instruction
	for i := range s.Instr {
		if s.Instr[i].Cmd == "USER" {
			lastUser = &s.Instr[i]
		}
	}
	if lastUser == nil {
		return []Hit{{Line: firstLine(s), Message: "kein USER gesetzt; der Container läuft als root"}}
	}
	name := strings.SplitN(firstArgOf(lastUser.Args), ":", 2)[0]
	if name == "root" || name == "0" {
		return []Hit{{Line: lastUser.Line, Message: "USER ist " + firstArgOf(lastUser.Args)}}
	}
	return nil
}

func ruleFloatingTag(t *DockerfileTarget) []Hit {
	names := t.DF.StageNames()
	var hits []Hit
	for _, s := range t.DF.Stages {
		ref := s.From
		if ref == "" || isStageRef(ref, names) {
			continue
		}
		tag := imageTag(ref)
		if tag == "" {
			hits = append(hits, Hit{Line: fromLine(&s), Message: ref + " hat keinen Tag"})
		} else if tag == "latest" {
			hits = append(hits, Hit{Line: fromLine(&s), Message: ref + " nutzt latest"})
		}
	}
	return hits
}

func ruleNoDigest(t *DockerfileTarget) []Hit {
	names := t.DF.StageNames()
	var hits []Hit
	for _, s := range t.DF.Stages {
		ref := s.From
		if ref == "" || ref == "scratch" || isStageRef(ref, names) || strings.HasPrefix(ref, "$") {
			continue
		}
		if !strings.Contains(ref, "@sha256:") {
			hits = append(hits, Hit{Line: fromLine(&s), Message: ref + " ist nicht per Digest gepinnt"})
		}
	}
	return hits
}

func ruleAddRemote(t *DockerfileTarget) []Hit {
	var hits []Hit
	for _, in := range t.DF.Instructions() {
		if in.Cmd != "ADD" {
			continue
		}
		for _, a := range in.Args {
			if strings.Contains(a, "://") {
				hits = append(hits, Hit{Line: in.Line, Message: "ADD " + a})
				break
			}
		}
	}
	return hits
}

func rulePipeToShell(t *DockerfileTarget) []Hit {
	var hits []Hit
	for _, in := range t.DF.Instructions() {
		if in.Cmd == "RUN" && pipeToShellRe.MatchString(in.Original) {
			hits = append(hits, Hit{Line: in.Line, Message: "RUN pipt heruntergeladenen Code in eine Shell"})
		}
	}
	return hits
}

func ruleSecretEnvArg(t *DockerfileTarget) []Hit {
	var hits []Hit
	for _, in := range t.DF.Instructions() {
		switch in.Cmd {
		case "ENV":
			for i := 0; i+1 < len(in.Args); i += 2 {
				if looksSecret(in.Args[i], in.Args[i+1]) {
					hits = append(hits, Hit{Line: in.Line, Message: "ENV " + in.Args[i]})
				}
			}
		case "ARG":
			for _, a := range in.Args {
				name, val, has := strings.Cut(a, "=")
				if has && looksSecret(name, val) {
					hits = append(hits, Hit{Line: in.Line, Message: "ARG " + name})
				}
			}
		}
	}
	return hits
}

func ruleNoHealthcheck(t *DockerfileTarget) []Hit {
	s := finalStage(t)
	if s == nil {
		return nil
	}
	for _, in := range s.Instr {
		if in.Cmd == "HEALTHCHECK" {
			return nil
		}
	}
	return []Hit{{Line: firstLine(s), Message: "kein HEALTHCHECK in der finalen Stage"}}
}

func ruleCopyAllNoIgnore(t *DockerfileTarget) []Hit {
	if t.HasDockerignore {
		return nil
	}
	var hits []Hit
	for _, in := range t.DF.Instructions() {
		if in.Cmd != "COPY" && in.Cmd != "ADD" {
			continue
		}
		src := nonFlagArgs(in.Args)
		if len(src) >= 2 && (src[0] == "." || src[0] == "./") {
			hits = append(hits, Hit{Line: in.Line, Message: in.Cmd + " kopiert den gesamten Kontext"})
		}
	}
	return hits
}

func ruleSudo(t *DockerfileTarget) []Hit {
	var hits []Hit
	for _, in := range t.DF.Instructions() {
		if in.Cmd == "RUN" && regexp.MustCompile(`\bsudo\b`).MatchString(in.Original) {
			hits = append(hits, Hit{Line: in.Line, Message: "RUN verwendet sudo"})
		}
	}
	return hits
}

// looksSecret reports whether a name/value pair looks like a hard-coded secret.
func looksSecret(name, value string) bool {
	value = strings.Trim(value, `"'`)
	if value == "" || placeholderRe.MatchString(value) {
		return false
	}
	return secretKeyRe.MatchString(name)
}

func isStageRef(ref string, names map[string]bool) bool {
	return names[strings.ToLower(ref)]
}

// imageTag returns the tag of an image reference, after stripping any digest.
func imageTag(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	lastSlash := strings.LastIndex(ref, "/")
	name := ref[lastSlash+1:]
	if i := strings.Index(name, ":"); i >= 0 {
		return name[i+1:]
	}
	return ""
}

func firstArgOf(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

func firstLine(s *dockerfile.Stage) int {
	if len(s.Instr) > 0 {
		return s.Instr[0].Line
	}
	return 1
}

func fromLine(s *dockerfile.Stage) int {
	for _, in := range s.Instr {
		if in.Cmd == "FROM" {
			return in.Line
		}
	}
	return firstLine(s)
}

// nonFlagArgs drops leading --flag arguments (e.g. --chown=...).
func nonFlagArgs(args []string) []string {
	var out []string
	for _, a := range args {
		if strings.HasPrefix(a, "--") {
			continue
		}
		out = append(out, a)
	}
	return out
}
