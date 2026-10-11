# Securety-Checker

`secchk` ist ein Kommandozeilen-Tool, das Projekte mit Docker- und Docker-Compose-Deployment auf Sicherheitsprobleme prüft: Dockerfiles, Compose-Dateien, `.env`-Dateien und (später) die verwendeten Images.

> Status: Meilenstein M1. Das Tool findet die relevanten Dateien und prüft sie mit 22 statischen Regeln (9 für Dockerfile, 13 für Compose). Image-Scans, Secrets und dynamische Tests folgen ab M2.

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
- `internal/finding` – gemeinsames Findings-Format mit Schweregraden
- `internal/report` – Ausgabe als Text oder JSON

## Roadmap

1. **M0** Grundgerüst, CLI, Datei-Erkennung, CI
2. **M1** Statische Checks für Dockerfile und Compose ✅
3. **M2** Image-Schwachstellen und Secrets über Trivy
4. **M3** SARIF, Ignores und Baseline, GitHub Action (v1.0)
5. **M4** Checks gegen laufende Container und den Docker-Daemon
