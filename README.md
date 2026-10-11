# Securety-Checker

`secchk` ist ein Kommandozeilen-Tool, das Projekte mit Docker- und Docker-Compose-Deployment auf Sicherheitsprobleme prüft: Dockerfiles, Compose-Dateien, `.env`-Dateien und (später) die verwendeten Images.

> Status: Meilenstein M4. `secchk scan --attack` startet den Stack in der Sandbox und greift ihn dynamisch an: Portscan (nmap), Web-Schwachstellen (nuclei) je Service und eine Prüfung der Netzsegmentierung im Verbund. Es fehlt noch M5 (Host-Checks, SARIF, CI).

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
secchk version
```

Exit-Codes: `0` keine Findings ab dem Schwellwert, `1` Findings ab dem Schwellwert (`--fail-on`, Standard `high`), `2` Fehler.

Erkannte Dateien:

| Art | Dateinamen |
| --- | --- |
| Dockerfile | `Dockerfile`, `Dockerfile.*`, `*.dockerfile`, `Containerfile` |
| Compose | `docker-compose*.yml/.yaml`, `compose*.yml/.yaml` |
| Env | `.env`, `.env.*`, `*.env` |

Verzeichnisse wie `.git`, `node_modules` und `vendor` werden übersprungen.

Für den Image- und Secret-Scan muss [Trivy](https://aquasecurity.github.io/trivy/) installiert sein. Fehlt es, überspringt `secchk` diese Schritte mit einem Hinweis und prüft nur statisch.

`--attack` setzt `--live` voraus und braucht zusätzlich nmap und nuclei; fehlen sie, werden die betroffenen Angriffe mit einem Hinweis übersprungen. Angegriffen wird ausschließlich die von `secchk` selbst gestartete Sandbox.

`--live` braucht eine laufende Docker-Umgebung. Der Lauf ist daten-sicher: `secchk` startet den Stack unter einem eigenen Projektnamen, ersetzt Bind-Mounts von Host-Pfaden durch Wegwerf-Volumes, entfernt gemountete Docker-Sockets und räumt danach alles inklusive der Volumes wieder ab. Echte Daten werden nie angefasst.

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
- `internal/finding` – gemeinsames Findings-Format mit Schweregraden
- `internal/report` – Ausgabe als Text oder JSON

## Roadmap

1. **M0** Grundgerüst, CLI, Datei-Erkennung, CI
2. **M1** Statische Checks für Dockerfile und Compose ✅
3. **M2** Image-Schwachstellen und Secrets über Trivy ✅
4. **M3** Sandbox-Start und Laufzeit-Checks ✅
5. **M4** Dynamische Angriffe gegen die Services ✅
