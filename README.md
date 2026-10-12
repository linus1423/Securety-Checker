# Securety-Checker

`secchk` ist ein Kommandozeilen-Tool, das Projekte mit Docker- und Docker-Compose-Deployment auf Sicherheitsprobleme prüft: Dockerfiles, Compose-Dateien, `.env`-Dateien und (später) die verwendeten Images.

> Status: alle geplanten Meilensteine (M0–M5) umgesetzt. `secchk` deckt statische Analyse, Image- und Secret-Scan, Sandbox-Laufzeitprüfung, dynamische Angriffe sowie Host-/Daemon-Checks ab und gibt Text, JSON oder SARIF aus.

## Installation

```sh
go install github.com/linus1423/Securety-Checker/cmd/secchk@latest
```

## Benutzung

```sh
secchk scan [pfad]                 # Projektverzeichnis scannen (Standard: .)
secchk scan --format json .        # Ausgabe als JSON
secchk scan --fail-on medium .     # Exit-Code 1 ab Schweregrad "medium"
secchk rules                       # alle Checks auflisten
secchk scan --no-images --no-secrets .   # externe Scanner überspringen
secchk scan --live .               # Stack in Sandbox starten und zur Laufzeit prüfen
secchk scan --attack .             # Stack starten und dynamisch angreifen
secchk scan --format sarif .       # SARIF für GitHub Code Scanning
secchk scan --format sarif -o out.sarif .   # Report in eine Datei schreiben
secchk scan --fail-on medium .     # Schwelle setzen (auch über .secchk.yml)
secchk scan --write-baseline base.txt .     # aktuellen Stand als Baseline speichern
secchk scan --baseline base.txt .           # nur neue Findings gegenüber der Baseline zeigen
secchk version
```

Exit-Codes: `0` keine Findings ab dem Schwellwert, `1` Findings ab dem Schwellwert (`--fail-on`, Standard `high`), `2` Fehler.

Die Textausgabe endet mit einer Zusammenfassung der Findings pro Schweregrad. Mehrfach gemeldete, identische Findings (z. B. derselbe Dienst über veröffentlichten Port *und* interne Sandbox-IP) werden zusammengefasst. Die SARIF-Ausgabe enthält stabile `partialFingerprints`, damit GitHub Code Scanning Findings zuverlässig wiedererkennt. Mit `-o`/`--output` wird der Report in eine Datei statt nach stdout geschrieben.

Jedes Finding hat ein Confidence-Level (`high` ist Standard; heuristische Checks wie die reflektierte SQL-Fehlererkennung melden `medium`), das in Text-, JSON- und SARIF-Ausgabe erscheint und hilft, False Positives einzuordnen. Zu jeder Regel wird ein Remediation-/Referenz-Link ausgegeben (Docker-Docs, OWASP, CIS), sofern kein spezifischer vorhanden ist.

Für CI eignet sich der Baseline-Diff: `--write-baseline <datei>` speichert die Fingerprints des aktuellen Laufs, `--baseline <datei>` blendet alle dort bekannten Findings aus, sodass nur neue angezeigt werden (und nur diese `--fail-on` auslösen).

Erkannte Dateien:

| Art | Dateinamen |
| --- | --- |
| Dockerfile | `Dockerfile`, `Dockerfile.*`, `*.dockerfile`, `Containerfile` |
| Compose | `docker-compose*.yml/.yaml`, `compose*.yml/.yaml` |
| Env | `.env`, `.env.*`, `*.env` |

Verzeichnisse wie `.git`, `node_modules` und `vendor` werden übersprungen.

Für den Image- und Secret-Scan muss [Trivy](https://aquasecurity.github.io/trivy/) installiert sein. Fehlt es, überspringt `secchk` diese Schritte mit einem Hinweis und prüft nur statisch.

`--attack` setzt `--live` voraus. Es greift die laufende Sandbox möglichst breit an und testet dabei auch ohne externe Tools zahlreiche Schwachstellen:

- **Intensiver Portscan (nmap)**: Pro Container wird dessen interne Sandbox-IP mit einem Vollscan über **alle** TCP-Ports (`-p-`, `-sV --version-all`) geprüft, sodass jeder offene Port einzeln und intensiv getestet wird – nicht nur die nach außen veröffentlichten. Zusätzlich werden die veröffentlichten Host-Ports geprüft. NSE-Skripte decken Banner, schwache TLS-Cipher, Zertifikate, Heartbleed, HTTP-Methoden, FTP-Anonymous, SSH-Konfiguration, MongoDB/Redis-Info und bekannte Verwundbarkeiten (`vuln`) ab und melden unsichere Klartext-Dienste (`ATK-PORT`), `VULNERABLE`-Treffer (`ATK-VULN`), schwache TLS-Konfiguration (`ATK-TLS`), gefährliche HTTP-Methoden (`ATK-HTTP`) und anonymen FTP-Zugriff (`ATK-FTP`). Der Vollscan läuft nur gegen die containereigenen Sandbox-IPs und bleibt so auf den Stack beschränkt.
- **Tiefer Web-Scan (nuclei)** im DAST-Modus (`ATK-NUCLEI`): Fuzzing-Vorlagen für SQLi, XSS, SSRF, LFI/Path-Traversal, XXE und Command Injection gegen die erkannten HTTP-Endpunkte.
- **Native TLS-Prüfung** ohne externe Tools: veraltete TLS-Version, abgelaufene/bald ablaufende und selbstsignierte Zertifikate (`ATK-TLS`).
- **Native HTTP-Prüfung** ohne externe Tools: fehlende Security-Header (`ATK-HEADER`), permissive CORS-Konfiguration (`ATK-CORS`), Versions-/Infoleaks (`ATK-INFO`), aktives Directory-Listing (`ATK-DIRLIST`) sowie exponierte sensible Pfade wie `/.env`, `/.git/config`, `/.aws/credentials` oder Spring-Actuator-Endpunkte (`ATK-EXPOSED`).
- **Native API-/Injection-Prüfung** ohne externe Tools: öffentlich erreichbare OpenAPI/Swagger-Spezifikationen (`ATK-APIDOC`), aktivierte GraphQL-Introspection (`ATK-GRAPHQL`), Path Traversal auf `/etc/passwd` (`ATK-TRAVERSAL`) und reflektierte SQL-Fehler als Hinweis auf SQL-Injection (`ATK-SQLI`).
- **Native Dienst-/Default-Credential-Prüfung** ohne externe Tools: ungeschützte Datenbanken, Caches und APIs – Redis, Memcached, Elasticsearch, CouchDB ohne Authentifizierung (`ATK-NOAUTH`), exponierte Docker-Engine- und Kubelet-API (`ATK-NOAUTH`, kritisch), anonymer FTP-Zugriff (`ATK-FTP`) und RabbitMQ mit Standard-Zugangsdaten `guest:guest` (`ATK-DEFAULTCRED`).
- **Clusterprüfung**: schwache Netzsegmentierung, wenn zu viele Services ein Netz teilen und ein kompromittierter Service die anderen erreichen kann (`ATK-NETSEG`).

nmap und nuclei sind optional; fehlen sie, werden nur die betroffenen Angriffe mit einem Hinweis übersprungen – die nativen TLS-, HTTP-, API- und Dienst-Checks laufen trotzdem. Angegriffen wird ausschließlich die von `secchk` selbst gestartete Sandbox.

Der Vollständigkeit halber nicht aktiv ausgeführt werden aktive DoS-Angriffe (z. B. Slowloris), um die Sandbox nicht lahmzulegen – stattdessen wird fehlendes CPU-/Memory-Limit als DoS-Angriffsfläche gemeldet (`RUN013`/`RUN014`). Image-Supply-Chain-Prüfungen (CVEs, unsignierte/veraltete Images) laufen über den Trivy-Scan sowie die statischen Dockerfile-Regeln (fehlender Digest-Pin, Floating-Tag).

`--live` braucht eine laufende Docker-Umgebung. Zur Laufzeit prüft `secchk` die *effektive* Container-Konfiguration aus `docker inspect`, u. a. root-User, privileged, gefährliche Capabilities, gemountete Docker-Sockets, geteilte Host-Namespaces, veröffentlichte Datenbank-Ports, deaktivierte Sicherheitsprofile (`AppArmor unconfined`), fehlendes `cap_drop: ALL`, beschreibbares Root-Dateisystem, beschreibbar gemountete sensible Host-Pfade sowie fehlende CPU-/Memory-Limits als DoS-Angriffsfläche (`RUN001`–`RUN014`).

Der Lauf ist daten-sicher: `secchk` startet den Stack unter einem eigenen Projektnamen, ersetzt Bind-Mounts von Host-Pfaden durch Wegwerf-Volumes, entfernt gemountete Docker-Sockets und räumt danach alles inklusive der Volumes wieder ab. Echte Daten werden nie angefasst.

## Konfiguration

Eine optionale `.secchk.yml` im Projekt steuert Schwelle, Ausnahmen und Baseline. Siehe [`.secchk.example.yml`](.secchk.example.yml):

```yaml
fail_on: high
ignore:
  rules: [DF003]
  paths: ["examples/**"]
baseline: []
```

Ausgabeformate: `text` (Standard), `json`, `sarif`. SARIF lässt sich in GitHub Code Scanning hochladen; ein Beispiel-Workflow liegt unter [`.github/workflows/secchk.yml`](.github/workflows/secchk.yml). Der Haupteinsatz bleibt aber lokal.

## Entwicklung

```sh
go test ./...
go vet ./...
go build -o secchk ./cmd/secchk
```

Aufbau:

- `cmd/secchk` – Einstiegspunkt
- `internal/cli` – Befehle und Flags (Cobra)
- `internal/discovery` – findet relevante Dateien im Projekt
- `internal/dockerfile` – Dockerfile-Parser (BuildKit) mit Zeilennummern
- `internal/compose` – Compose-Parser (yaml.v3) mit Zeilennummern
- `internal/check` – die statischen Regeln (Dockerfile und Compose)
- `internal/scanner` – Adapter für externe Scanner (Trivy)
- `internal/sandbox` – daten-sicheres Starten des Stacks und Laufzeit-Checks
- `internal/attack` – dynamische Angriffe (nmap, nuclei, Netzsegmentierung)
- `internal/host` – Checks für Docker-Daemon und Host
- `internal/config` – `.secchk.yml` (Ignores, Baseline, Schwelle)
- `internal/finding` – gemeinsames Findings-Format mit Schweregraden
- `internal/report` – Ausgabe als Text oder JSON

## Roadmap

1. **M0** Grundgerüst, CLI, Datei-Erkennung, CI
2. **M1** Statische Checks für Dockerfile und Compose ✅
3. **M2** Image-Schwachstellen und Secrets über Trivy ✅
4. **M3** Sandbox-Start und Laufzeit-Checks ✅
5. **M4** Dynamische Angriffe gegen die Services ✅
