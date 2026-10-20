# Mitarbeiten & Git-Ablauf

Sprache im ganzen Projekt: **Deutsch** – Oberfläche, Kommentare, Commits, Issues.
Die fachlichen Regeln (keine erfundenen Daten, Einheiten in der Datenbank, Fallen,
die schon zugeschnappt sind) stehen in [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) und gelten für
Menschen genauso.

## Entwicklungsumgebung

```bash
git clone https://github.com/Felixitus/network-lag-analyzer.git
cd network-lag-analyzer
python3 -m venv .venv && . .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
python -m pytest tests -q
python -m backend.main --dev --data-dir /tmp/nla --port 8099   # Demo, http://localhost:8099
```

Der Dev-Modus läuft auch unter Windows und macOS (simulierte Daten, DEMO-Banner).
Echte Messungen gibt es nur auf Linux mit `CAP_NET_RAW`.

## Zweige

| Zweig | Zweck |
|---|---|
| `main` | Immer lauffähig, CI grün. Hiervon wird installiert. Kein direkter Push. |
| `feature/<kurz>` | Neue Funktion, z. B. `feature/sni-parser` |
| `fix/<kurz>` | Fehlerbehebung, z. B. `fix/pcap-budget` |
| `docs/<kurz>` | Nur Dokumentation |

## Ablauf einer Änderung

```bash
git switch main && git pull
git switch -c fix/kurze-beschreibung
# … ändern, testen …
python -m pytest tests -q
git add -p
git commit
git push -u origin fix/kurze-beschreibung
gh pr create --fill          # oder über die GitHub-Oberfläche
```

Der Pull Request muss die CI bestehen (Tests auf Python 3.11 und 3.13,
`install.sh`-Prüfung, LF-Zeilenenden). Gemergt wird per **Squash**, damit `main`
eine Zeile pro Änderung hat.

## Commit-Messages

Deutsch, Imperativ, erste Zeile ≤ 72 Zeichen, danach Leerzeile und das **Warum**:

```
PCAP-Budget auch für Incident-Mitschnitte durchsetzen

max_files × file_size_mb galt nur für den laufenden Ring. Mitschnitte zu
Incidents lagen außerhalb und ließen das Verzeichnis auf 40 GB wachsen.
```

## Tests

* Jeder behobene Fehler bekommt einen Test, der ihn festnagelt.
* Testnamen auf Deutsch, sie beschreiben das Verhalten:
  `test_gespeichertes_fritzbox_passwort_geht_nicht_an_eine_neue_adresse`.
* Testdaten nur aus den Dokumentationsbereichen (RFC 5737: `192.0.2.x`,
  `203.0.113.x`) und mit lokal verwalteten MACs (`02:00:00:…`).

## Release

1. Version in `backend/__init__.py` erhöhen (SemVer: Fix → Patch, Funktion → Minor,
   inkompatible Konfiguration/Schema → Major).
2. In `CHANGELOG.md` den Abschnitt „Unveröffentlicht" in die neue Version umbenennen.
3. Commit `Version 1.2.0`, dann Tag und Release:

```bash
git tag -a v1.2.0 -m "Version 1.2.0"
git push origin main --tags
gh release create v1.2.0 --notes-from-tag
```

Auf dem Pi aktualisieren:

```bash
cd ~/network-lag-analyzer && git pull && sudo ./install.sh
```

## Was nie ins Repo gehört

`config.yaml`, Datenbanken (`*.sqlite3`), Mitschnitte (`*.pcap`), `session.key` –
die `.gitignore` deckt das ab. Vor dem ersten `git add .` in einem neuen Klon
trotzdem `git status` lesen. Wurde doch ein Passwort committet: Passwort sofort
ändern; aus der Historie entfernen allein reicht nicht.
