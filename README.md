# Network Lag Analyzer

Lokale Netzwerk-Diagnose für den Raspberry Pi (mit Pi-hole), die eine Frage beantwortet:

> **„Warum hatte ich genau zu diesem Zeitpunkt Lag oder Packet Loss?"**

Die Anwendung misst jede Sekunde Ping, Jitter und Packet Loss zu Router und Internet,
erfasst – soweit technisch sichtbar – den Traffic jedes Geräts, erkennt Auffälligkeiten
automatisch und korreliert sie zeitlich. Ergebnis ist z. B.:

```
INCIDENT #124 · 21.09.2026 20:43:12 · Dauer 4,2 s
Ping 18 → 184 ms · Jitter 2 → 61 ms · Packet Loss 8 % · Gateway 1,1 ms

Possible Cause: Upload-Sättigung durch iPhone        Confidence: High
Evidence:
  • Upload-Auslastung bis 97 % der Leitung (38,8 von 40 Mbit/s)
  • Upload-Anstieg begann vor dem Latenzanstieg (2 s vorher)
  • Router-Latenz blieb stabil
  • 3 externe Ziele zeigten gleichzeitig erhöhte Latenz/Verlust
  • iPhone verursachte 96 % des Uploads
```

Alles läuft lokal. Keine Cloud, keine Telemetrie, keine Payload-Speicherung.

---

## Inhalt

1. [Funktionen](#funktionen)
2. [Architektur](#architektur)
3. [Raspberry-Pi-Anforderungen](#raspberry-pi-anforderungen)
4. [Installation](#installation)
5. [Netzwerkarchitektur & Traffic Visibility](#netzwerkarchitektur--traffic-visibility)
6. [FRITZ!Box einrichten (empfohlen)](#fritzbox-einrichten-empfohlen)
7. [Port Mirroring](#port-mirroring)
8. [Raspberry Pi als Gateway](#raspberry-pi-als-gateway)
9. [Pi-hole-Integration](#pi-hole-integration)
10. [Bedienung](#bedienung)
11. [Ursachenanalyse – so wird entschieden](#ursachenanalyse--so-wird-entschieden)
12. [Konfiguration](#konfiguration)
13. [Datenbank & Backup](#datenbank--backup)
14. [Security](#security)
15. [Performance & Load Guard](#performance--load-guard)
16. [Troubleshooting](#troubleshooting)
17. [Entwicklung & Tests](#entwicklung--tests)

---

## Funktionen

| Bereich | Umfang |
|---|---|
| Latenz | ICMP zu Router + frei wählbaren Internetzielen, 1/s (Gaming Mode 4/s), ein dauerhaft offener Socket, Kernel-Zeitstempel |
| Kennzahlen | RTT (Median/Min/Max), Jitter, Packet Loss über 5 s/10 s/30 s/60 s/5 min, Erreichbarkeit |
| Traffic | pro Gerät Upload/Download, UDP-Anteil, TCP-Retransmissions (je Richtung), Flows (nur Metadaten) |
| Events | `PING_SPIKE`, `PACKET_LOSS`, `HIGH_JITTER`, `HIGH_UPLOAD`, `HIGH_DOWNLOAD`, `TCP_RETRANSMISSION_SPIKE`, `CONNECTION_DROP`, `DNS_FAILURE`, `GATEWAY_LATENCY`, `INTERNET_LATENCY`, `GAME_FLOW_GAP` |
| Incidents | automatische Korrelation + dokumentierte Ursachenregeln mit Confidence und Evidenz |
| Handlungsempfehlung | zu jeder Kategorie eine konkrete Maßnahme – inkl. Hinweis, ob selbst behebbar oder Sache des Anbieters |
| Latenz unter Last | Bufferbloat-Kennzahl je Richtung („+120 ms unter Download-Last"), Langzeitverlauf über Wochen |
| „ICH HATTE GERADE LAG" | analysiert sofort 10 s/30 s/60 s/5 min und erzeugt einen Incident mit Zeitleiste |
| Gaming Mode | manuell oder automatisch; Game-Server-Erkennung, Paketlücken im Game-Flow, Session-Zusammenfassung |
| Web-UI | Dashboard, gemeinsame Timeline, Geräte-Lanes, Heatmap, Incident-Details, Top Talker, Setup-Wizard; hell/dunkel, responsiv |
| Deep Capture | optionaler PCAP-Ringpuffer (nur Header), Incident-Mitschnitte werden geschützt und sind downloadbar; **harte Gesamtgrenze** über `max_total_mb` |
| Timeline | gestapelte Panels mit EINER Zeitachse, Werte-Ablesen am Cursor, Zoom per Ziehen, Schraffur für nicht gemessene Zeiträume |
| Langzeit | Tages-Zusammenfassung über Jahre (`daily_stats`), unabhängig von der Aufbewahrung der Detaildaten |
| Speicher | Größe je Tabelle, Löschen nach Datum mit Vorschau, VACUUM, automatische Größengrenze |
| Betrieb | systemd, journald, SQLite (WAL), Schema-Migrationen mit Sicherungskopie, Aggregation 1 s → 10 s → 1 min, Retention, Load Guard |

**Keine Fake-Daten:** Was nicht gemessen werden kann, erscheint als „Not available" mit
Begründung. Simulierte Daten gibt es nur mit `dev_mode: true` – dann mit dauerhaftem
„DEMO-MODUS"-Banner.

---

## Architektur

Details: [ARCHITECTURE.md](ARCHITECTURE.md).

```
backend/
  main.py              Einstiegspunkt (uvicorn)
  config.py            Konfiguration (YAML + Überschreibungen aus der UI), Validierung
  core.py              Orchestrierung aller Komponenten
  collectors/
    ping.py            ICMP-Prober (ein Socket, SO_TIMESTAMPNS)
    dns.py             DNS-Prober (Pi-hole + Upstream)
    fritzbox.py        FRITZ!Box: Login (PBKDF2), TR-064, Mitschnitt-URL
    traffic.py         Capture-Prozess (FRITZ!Box-Stream oder AF_PACKET), PCAP-Ring
    pcapstream.py      inkrementeller pcap/pcapng-Parser
    flows.py           Paketanalyse: Bytes je Gerät, Flows, Retransmissions, Game-Flow
    pihole.py          Pi-hole FTL-Datenbank (read-only)
    devices.py         Geräteverzeichnis (FRITZ!Box, Pi-hole, ARP, Capture)
  analysis/
    metrics.py         Sekunden-Assembler, Jitter/Loss, 1-h-Ringpuffer
    events.py          Event Detection mit Hysterese und Baselines
    correlation.py     Incidents, Lag-Report
    root_cause.py      Ursachenregeln (je Regel dokumentiert)
    gaming.py          Gaming Sessions
  database/            Schema, Batch-Writer, Aggregation, Retention
  api/                 REST + Server-Sent Events, Security-Middleware
  setup_wizard.py      Diagnose der Netzwerkarchitektur
  simulation.py        NUR Tests/Dev-Modus
frontend/              HTML/CSS/JS (ES-Module), uPlot lokal eingebunden
deploy/                systemd-Unit
tests/                 Unit-, Szenario- und API-Tests
```

Das Paketparsing läuft in einem **eigenen Prozess**. So verfälscht es weder die
ICMP-Zeitstempel im Hauptprozess, noch bremst es die Web-API aus.

---

## Raspberry-Pi-Anforderungen

| | Minimum | Empfohlen |
|---|---|---|
| Modell | Raspberry Pi 3B+ | Raspberry Pi 4/5 (2 GB+) |
| OS | Raspberry Pi OS / Debian 12 (Bookworm), Python ≥ 3.10 | 64-bit |
| Anbindung | LAN | **LAN-Kabel** (WLAN verfälscht Jitter/Latenz der Messung selbst) |
| Speicher | ~200 MB für Programm, Daten je nach Traffic 50–500 MB | SSD statt SD-Karte bei Deep Capture |
| RAM-Bedarf | ~80–150 MB (Hauptprozess + Capture-Prozess) | – |

Pi-hole läuft unverändert weiter. Der Dienst hat niedrigere CPU-Priorität als Pi-hole
(`Nice=10`, `CPUWeight=50`) und ist auf 350 MB RAM begrenzt.

---

## Installation

```bash
# Projekt auf den Pi kopieren (z. B. per scp) und entpacken
tar xzf network-lag-analyzer.tar.gz
cd network-lag-analyzer
sudo ./install.sh
```

Der Installer:

1. installiert fehlende Pakete (`python3`, `python3-venv`, `python3-pip`) – **kein** `apt upgrade`,
2. legt den Systembenutzer `nla` an und nimmt ihn in die Gruppe `pihole` auf (nur Leserecht),
3. kopiert das Programm nach `/opt/network-lag-analyzer` und erstellt dort ein venv,
4. legt `/etc/network-lag-analyzer/config.yaml` an (bestehende bleibt erhalten),
5. erstellt `/var/lib/network-lag-analyzer` (Datenbank, PCAPs),
6. installiert und startet `network-lag-analyzer.service`.

Danach im Browser (z. B. vom Windows-PC):

```
http://raspberrypi:8088      oder      http://IP-DES-PI:8088
```

Beim ersten Aufruf auf **Setup** gehen, Diagnose ausführen, FRITZ!Box-Zugang eintragen.

Update: neue Version entpacken, erneut `sudo ./install.sh` – Konfiguration und Daten bleiben.
Deinstallation: `sudo ./install.sh --uninstall`.

**Pi-hole wird nicht verändert.** Der Installer fasst weder `/etc/pihole`, dnsmasq/FTL noch
den Pi-hole-Webserver an. Der Standardport 8088 kollidiert nicht mit Pi-hole (80/443).

---

## Netzwerkarchitektur & Traffic Visibility

Wichtigster Punkt: **Pi-hole sieht nur DNS.** Ein Raspberry Pi, der nicht Router ist,
sieht den Datenverkehr anderer Geräte grundsätzlich nicht – ein Switch schickt ihm nur
Pakete, die an ihn adressiert sind. Promiscuous Mode ändert daran nichts.

| Messung | Pi im LAN (Standard) | + FRITZ!Box-Mitschnitt | + Port-Mirroring | Pi als Gateway |
|---|:-:|:-:|:-:|:-:|
| Ping/Jitter/Loss Router + Internet | ✓ | ✓ | ✓ | ✓ |
| DNS-Aktivität je Gerät (Pi-hole) | ✓ | ✓ | ✓ | ✓ |
| WAN-Gesamtrate (TR-064) | ✓¹ | ✓ | ✓¹ | ✓ |
| Traffic pro Gerät | ✗ | ✓ | ✓ | ✓ |
| TCP-Retransmissions, Flows | ✗ | ✓ | ✓ | ✓ |
| Game-Flow-Analyse (Paketlücken) | ✗ | ✓ | ✓ | ✓ |

¹ mit FRITZ!Box-Zugangsdaten.

Der **Setup-Wizard** prüft das aktiv (u. a. lauscht er 2 s am Interface, ob fremde
Unicast-Frames ankommen) und zeigt die Fähigkeitsmatrix. Fehlt eine Quelle, sagt die
Oberfläche das – und die Ursachenanalyse benennt dann **kein Gerät**.

### Empfehlung für ein Heimnetz mit FRITZ!Box + Deco (AP-Modus)

Der FRITZ!Box-Paketmitschnitt ist die beste Lösung ohne Zusatzhardware. Der Deco im
Access-Point-Modus bridged; alle Clients (auch WLAN-Clients am Deco) haben eigene
IP/MAC im Netz der FRITZ!Box, und ihr Internet-Traffic läuft über deren LAN-Bridge.

---

## FRITZ!Box einrichten (empfohlen)

1. **TR-064 aktivieren:** Heimnetz → Netzwerk → Netzwerkeinstellungen → „Zugriff für
   Anwendungen zulassen".
2. **Eigenen Benutzer anlegen:** System → FRITZ!Box-Benutzer → Hinzufügen, z. B. `nla`,
   starkes Passwort, Recht **„FRITZ!Box Einstellungen"** (nötig für den Paketmitschnitt).
   Kein Internetzugriff auf die Box nötig.
3. In der Weboberfläche → **Setup** → „FRITZ!Box & Traffic-Quelle": Integration aktivieren,
   Benutzer/Passwort eintragen, **„Verbindung & Mitschnitt testen"**, speichern.

Technisch öffnet der Pi einen dauerhaften HTTP-Stream
`/cgi-bin/capture_notimeout?ifaceorminor=1-lan&snaplen=128`. Die FRITZ!Box schickt einen
libpcap-Strom ihrer LAN-Bridge – mit `snaplen=128` **nur Header, keine Inhalte**.
Je nach FRITZ!OS ist das entweder klassisches pcap oder die Variante „modified pcap"
(Magic `a1b2cd34`, 24-Byte-Recordheader); beide werden unterstützt, ebenso pcapng. Der Pi
zählt daraus Bytes/Pakete pro MAC (Upload = Client → Router, Download = Router → Client)
und bildet Flows. Die Mitschnitt-Verbindung selbst wird herausgefiltert.

Hinweise:
* Das Interface heißt je nach FRITZ!OS meist `1-lan`. Der Test zeigt gefundene Interfaces an.
* Der Mitschnitt belastet die FRITZ!Box-CPU etwas und erzeugt ~1–2 MB/s LAN-Traffic bei
  hoher Last. Bei sehr hohen Paketraten (Gigabit voll ausgelastet) schaltet der Load Guard
  auf Sampling und kennzeichnet Werte als geschätzt.
* Ohne Mitschnitt, aber mit Zugangsdaten, liefert TR-064 wenigstens die WAN-Gesamtrate
  (ohne Geräteaufteilung) und die Leitungskapazität.

---

## Port Mirroring

Alternative mit Zusatzhardware: Ein Managed Switch (z. B. TP-Link TL-SG105E/108E,
Netgear GS105E) zwischen FRITZ!Box und dem restlichen Netz spiegelt den Uplink-Port auf
den Port des Pi.

```
FRITZ!Box LAN ── [Port 1] Managed Switch [Port 2..n] ── Deco, PC, …
                          [Port 5 = Mirror-Ziel] ── Raspberry Pi
```

Einstellungen: Quelle = Port zur FRITZ!Box (ein- und ausgehend), Ziel = Port des Pi.
In der Oberfläche: Traffic-Quelle = „Lokales Interface", Interface `eth0`. Der Wizard
erkennt gespiegelten Traffic automatisch („Fremder Client-Traffic am Pi sichtbar ✓").

Achtung: Manche günstige Switches spiegeln nur eine Richtung oder deaktivieren den
normalen Netzwerkzugang des Ziel-Ports – dann einen zweiten Netzwerkadapter (USB) am Pi
als Mirror-Port nutzen.

---

## Raspberry Pi als Gateway

Möglich (Quelle „Lokales Interface", IP-Forwarding aktiv), aber für dieses Ziel **nicht
empfohlen**: Jedes Paket läuft dann über den Pi. Das erzeugt zusätzliche Latenz, und fällt
der Pi aus, ist das Internet weg. Für ein Lag-Diagnosewerkzeug ist das der falsche
Kompromiss. Der FRITZ!Box-Mitschnitt oder Port-Mirroring liefern dieselbe Sicht ohne
dieses Risiko.

---

## Pi-hole-Integration

* Gelesen wird ausschließlich (read-only) `/etc/pihole/pihole-FTL.db` (Pi-hole v5 und v6):
  Tabellen `network`/`network_addresses` (MAC, IP, Hostname, Hersteller) und `queries`.
* Verwendung: Namen für Geräte, DNS-Aktivität und Top-Domains je Gerät (Geräte-Seite).
* **DNS-Anfragen werden nie als Bandbreite interpretiert.** Viele DNS-Anfragen bedeuten
  nicht viel Traffic.
* FTL schreibt standardmäßig einmal pro Minute in die Datenbank – DNS-Daten sind daher bis
  zu ~60 s verzögert. Für die Lag-Analyse spielt das keine Rolle.
* Zusätzlich misst ein eigener DNS-Prober alle 5 s Pi-hole (127.0.0.1) und einen
  Upstream-Resolver. So wird ein DNS-Ausfall erkannt und von echtem Lag unterschieden.

---

## Bedienung

**Dashboard:** Live-Kacheln (Internet, Ping, Jitter, Packet Loss, Gateway, Download,
Upload), der große Button **„ICH HATTE GERADE LAG"**, Live-Charts mit Zeitbereichen
LIVE/5 MIN/15 MIN/1 H/6 H/24 H/7 D, Top-Geräte, letzte Incidents, aktive Events.
Aktualisierung per Server-Sent Events, ohne Neuladen.

**Timeline:** Ping, Loss, Jitter, Upload, Download, Retransmissions und darunter je Gerät
eine Upload-/Download-Lane – alles auf **einer gemeinsamen Zeitachse** mit synchronem
Cursor. Incidents sind rote Bänder (Klick öffnet den Incident), gemeldeter Lag ist orange,
Events sind Striche am oberen Rand. Darunter die Heatmap (Geräte × Zeit).

**Incidents:** Liste und Detailansicht (Kennzahlen vorher → Spitze, Possible Cause,
Confidence, Evidenz, Top Traffic, alle geprüften Erklärungen, Events, Verbindungen,
Charts rund um den Zeitpunkt, PCAP-Download bei Deep Capture).

**Gaming:** Session starten/stoppen, Game-Server und Paketlücken live, Zusammenfassungen:

```
Gaming Session 19:32–22:14
Ping Durchschnitt 19 ms · Maximum 214 ms · Jitter Ø 3,2 ms
Packet-Loss-Events 4 · Lag Events 7
Mögliche Ursachen: 3× Upload-Sättigung, 2× WAN/ISP, 1× LAN/WLAN, 1× Unbekannt
```

Automatische Erkennung: Hat der Gaming-PC anhaltend (≥ 20 s) bidirektionalen UDP-Traffic
zu einem Internet-Server (≥ 15 Pakete/s je Richtung), startet die Session von selbst. Den
Gaming-PC unter **Geräte** markieren (Haken „Gaming-PC").

**Hinweis zum Game-Server:** Viele Spieleserver (z. B. Azure/AWS bei Rainbow Six Siege)
antworten nicht auf Ping. Dann steht dort „Not available". Die Verbindung wird trotzdem
über **Paketlücken im Game-Flow** überwacht: Schickt der Server länger als 250 ms keine
Pakete, entsteht ein `GAME_FLOW_GAP`-Event.

---

### Timeline lesen

Alle Panels teilen sich eine Zeitachse; nur das unterste trägt die Uhrzeiten. Beim
Überfahren zeigt die Leiste oben **alle Werte zum selben Zeitpunkt** – Ping, Loss,
Jitter, Download, Upload und Retransmissions gleichzeitig. Das ist die Ansicht für
„was war um 20:14 los?". Ein Panel lässt sich per ▸ aufklappen, ein Ziehen im Chart
zoomt in den Zeitraum (mit passender Auflösung), „Zoom aufheben" kehrt zurück.

Grau schraffierte Flächen sind Zeiträume **ohne Messdaten** – etwa weil der Dienst
stand. Sie werden nicht als Null gezeichnet, weil das eine Messung vortäuschen würde.
Bei „Traffic pro Gerät" lassen sich die Lanes auf eine **gemeinsame Skala** stellen;
ohne sie hat jede Lane ihre eigene Achse und die Höhen sind nicht vergleichbar.

---

## Ursachenanalyse – so wird entschieden

Jede Regel steht als eigene, kommentierte Funktion in `backend/analysis/root_cause.py`.
Die Regel mit der höchsten Punktzahl gewinnt. Liegt eine zweite Erklärung einer anderen
Kategorie gleichauf, wird die Confidence abgestuft.

| Beobachtung | Ergebnis |
|---|---|
| Gateway-Ping hoch + Internet-Ping hoch | LAN/WLAN/Router-Problem |
| Gateway normal + Internet-Ping hoch (mehrere Ziele) | WAN/ISP/Bufferbloat |
| Gateway + Internet normal, nur ein Ziel auffällig | Zielserver/Routing |
| Hoher Upload eines Geräts + Ping/Jitter hoch | Upload-Sättigung/Bufferbloat (+ Gerät) |
| Hoher Download + Ping-Spike | Download-Sättigung/Bufferbloat (+ Gerät) |
| TCP-Retransmissions stark erhöht | Paketverluste (Richtung wird angegeben) |
| Mehrere externe Ziele gleichzeitig Packet Loss | WAN/ISP wahrscheinlicher als ein Server |
| Nur ein externes Ziel betroffen | Routing/Zielserver wahrscheinlicher |
| Router + Internet normal, Game-Flow hat Lücken | Game-Server/Routing |
| DNS-Probes scheitern, Ping normal | DNS-Störung (Pi-hole bzw. Upstream) |
| Alle Ziele weg, Router erreichbar/nicht erreichbar | Internet-Ausfall bzw. LAN-Verbindungsverlust |

Confidence: ≥ 80 Punkte **High** („wahrscheinlicher Verursacher"), ≥ 55 **Medium**
(„möglicher Verursacher"), sonst **Low** („zeitlich korreliert"). Ein Gerät wird nur dann
als Verursacher genannt, wenn Traffic pro Gerät gemessen wurde und das Gerät den
Engpass dominiert (≥ 60 % des Traffics in der gesättigten Richtung).

**Leitungskapazität:** Für die Auslastung in % muss die Kapazität bekannt sein. `auto`
nutzt die Linkrate der FRITZ!Box (TR-064). Liegt die gebuchte Rate darunter (Drosselung
beim Provider), trage die gebuchte Rate unter Setup → Messung ein. Das ist genauer.

### Handlungsempfehlung statt nur Diagnose

Zu jeder Kategorie gehört eine konkrete Maßnahme (`recommendation` in der Analyse,
sichtbar im Incident unter „Was jetzt hilft"). Sie sagt auch, ob sich das überhaupt
selbst beheben lässt:

| `scope` | Bedeutung |
|---|---|
| `self` | in der eigenen Hand – Gerät, Router, WLAN |
| `provider` | nur der Anschlussanbieter kann es ändern (dokumentieren und melden) |
| `remote` | liegt beim Zielserver oder im Routing dorthin |
| `none` | Datenlage reicht für keine belastbare Empfehlung |

Wichtig ist dabei die Richtung, weil die Maßnahmen gegensätzlich sind:

* **Upload-Sättigung** – die Warteschlange steht im eigenen Router. Priorisierung in der
  FRITZ!Box wirkt hier tatsächlich.
* **Download-Sättigung** – die Warteschlange steht beim Provider. Lokale Priorisierung
  kann Pakete, die bereits dort warten, nicht überholen; es hilft nur, das ladende Gerät
  zu bremsen.

### Latenz unter Last (Bufferbloat)

`backend/analysis/bufferbloat.py` misst, wie viel Ping dazukommt, wenn die Leitung voll
ist – getrennt nach Richtung. Sekunden werden nach Auslastung gruppiert und die
Median-RTT der Gruppen verglichen:

* **ruhig** ≤ 20 % Auslastung in beiden Richtungen
* **unter Last** ≥ 70 % in einer Richtung, während die andere < 40 % bleibt
* Sind beide Richtungen voll, wird die Sekunde verworfen – die Ursache wäre nicht trennbar.

Pro Gruppe sind mindestens 5 Sekunden nötig, sonst bleibt das Ergebnis leer (kein
Schätzwert). Bewertung: < 30 ms „gut", < 100 ms „mäßig", darüber „stark".

Sichtbar an drei Stellen: als Karte auf dem Dashboard (1 h / 24 h / 7 d / 30 T), im
Incident für dessen Analysefenster und über `GET /api/bufferbloat?range=…`. Damit der
Verlauf Wochen übersteht, schreibt die Wartung alle 10 Minuten ein Fenster in die
Tabelle `bufferbloat` (9 Zahlen) – die 1-s-Rohwerte werden nur einen Tag aufbewahrt.
Kurze Zeiträume rechnet die API direkt aus den Sekundenwerten (`source: live`), längere
aus den gespeicherten Fenstern (`source: windows`).

---

## Konfiguration

`/etc/network-lag-analyzer/config.yaml` (Vorlage: `config.example.yaml`). Die wichtigsten
Werte lassen sich in der Oberfläche ändern; diese Änderungen liegen in der Datenbank und
überschreiben die Datei. „Setup" zeigt die wirksamen Werte.

```yaml
gateway: auto
targets: [1.1.1.1, 8.8.8.8, 9.9.9.9]
gaming_pc:
  ip: 192.168.178.20
thresholds:
  ping_warning: 50
  ping_critical: 100
  jitter_warning: 20
  packet_loss_warning: 1
retention:
  raw_days: 1
  detailed_days: 7
  aggregate_days: 30
```

Umgebungsvariablen: `NLA_CONFIG`, `NLA_DATA_DIR`, `NLA_PORT`, `NLA_DEV_MODE`, `NLA_LOG_LEVEL`.

---

## Datenbank & Backup

SQLite im WAL-Modus: `/var/lib/network-lag-analyzer/nla.sqlite3`.

| Tabelle | Inhalt |
|---|---|
| `measurements` | Netzwerkzustand je Bucket (`res` = 1/10/60 s) |
| `target_measurements` | RTT/Verlust je Ziel |
| `ping_samples` | einzelne Probes – **standardmäßig aus** (`retention.ping_samples`) |
| `device_traffic` | Bytes je Gerät und Bucket (Schlüssel: `devices.id`) |
| `daily_stats` | Tages-Zusammenfassung, **von der Retention ausgenommen** |
| `bufferbloat` | Latenz unter Last je 10-Minuten-Fenster |
| `network_flows` | abgeschlossene Flows (nur Metadaten) |
| `devices` | Geräte inkl. eigener Namen |
| `events`, `incidents` | erkannte Events, Incidents inkl. Analyse (JSON) |
| `dns_queries` | DNS-Aktivität je Client und Minute (aus Pi-hole) |
| `gaming_sessions` | Sessions inkl. Zusammenfassung |
| `pcap_files` | Deep-Capture-Dateien |
| `settings` | Überschreibungen aus der Weboberfläche |

Aggregation jede Minute: 1 s → 10 s → 1 min (Spitzen bleiben über `rtt_max` erhalten).
Retention stündlich laut Konfiguration.

### Speicherformat

Messwerte liegen als **INTEGER in festen Einheiten** (Zeiten in 1/100 ms, Anteile in
1/100 %, Raten in bit/s). SQLite belegt für jedes REAL acht Bytes, für kleine
Ganzzahlen zwei bis vier. Die Umrechnung passiert ausschließlich in
`repository.py` (`enc`/`dec`); der übrige Code rechnet weiter in Millisekunden.
`device_traffic` verweist über `devices.id` statt über die MAC als Text.

Gemessen an einem Tag mit vier Zielen und 15 dauerhaft aktiven Geräten:

| Tabelle | vorher | jetzt |
|---|---|---|
| `device_traffic` | 63,3 MB | **26,7 MB** |
| `target_measurements` | 12,1 MB | **7,8 MB** |
| `measurements` | 9,3 MB | **5,6 MB** |
| `ping_samples` | 9,6 MB | **0** (standardmäßig aus) |
| **Summe je Tag** | **94,4 MB** | **40,1 MB** (−58 %) |

Auf einer SD-Karte zählt jeder gesparte Schreibvorgang; aus rund 34 GB im Jahr
werden so rund 15 GB.

### Schema-Migrationen

`backend/database/migrations.py` enthält nummerierte Schritte. Beim Start wird die
gespeicherte `schema_version` gelesen und jeder fällige Schritt in einer eigenen
Transaktion angewendet – davor legt der Dienst eine Sicherungskopie
(`nla.sqlite3.pre-migration.bak`) an, sofern genug Platz frei ist. Das Ergebnis
steht in `/api/system` unter `migration` und im Journal. Bestehende Daten werden
umgerechnet, nicht verworfen.

### Deep Capture: wie viel Platz es wirklich braucht

`max_files × file_size_mb` begrenzt nur den **laufenden Ring**. Gehört eine Datei zu
einem Incident, wird sie aus dem Ring genommen, damit sie nicht überschrieben wird –
und zählte früher gegen gar keine Grenze. Bei einem Dutzend Incidents am Tag und 90
Tagen Aufbewahrung werden daraus zweistellige Gigabyte, obwohl in den Einstellungen
„5 × 50 MB" steht.

Deshalb gibt es drei Stellschrauben, und nur die erste ist eine Garantie:

| Einstellung | Standard | Wirkung |
|---|---|---|
| `max_total_mb` | 1024 | **harte Obergrenze für das ganze Verzeichnis**. Ist sie erreicht, fällt der älteste Incident-Mitschnitt weg |
| `protected_days` | 7 | so lange werden Incident-Mitschnitte höchstens aufgehoben |
| `protect_auto` | `critical` | wofür überhaupt ein Mitschnitt festgehalten wird: `none` (nur gemeldeter Lag), `critical`, `all` |

Der Platzverbrauch steht unter **Setup → Datenbank** mit eigenem Balken – er zählt
**nicht** zur Datenbankgröße, weil die Dateien daneben liegen. Dort gibt es auch
„Jetzt aufräumen".

**Abschalten:** Setup → Speicher & Deep Capture → Haken bei „Deep Capture
(PCAP-Ringpuffer)" entfernen → Speichern. Das wirkt sofort, ohne Neustart des
Dienstes. Die laufenden Ringdateien werden beim nächsten Aufräumen (stündlich, oder
sofort über „Jetzt aufräumen") gelöscht; Incident-Mitschnitte bleiben noch
`protected_days`, damit sie herunterladbar sind.

Beim Start übernimmt der Mitschnitt vorhandene Dateien in seinen Ring. Das ist
wichtig, weil der Capture-Prozess sich bei Störungen neu startet: Vorher waren die
Dateien des vorherigen Laufs danach herrenlos – in keinem Ring, nicht geschützt, und
damit für immer auf der Platte.

### Platz verwalten

Unter **Setup → Datenbank** stehen Größe je Tabelle, ältester Datenpunkt und freier
Platz auf dem Datenträger. Dort lassen sich Daten **nach Datum löschen** – wahlweise
„alles vor einem Datum" oder ein Zeitraum, mit Vorschau der betroffenen Zeilen und
anschließendem VACUUM. Gerätenamen, Ziele, Einstellungen und die
Tages-Zusammenfassung bleiben dabei immer erhalten.

`retention.max_db_mb` ist zusätzlich eine Notbremse: Wird die Grenze überschritten,
löscht der Dienst stündlich von selbst – zuerst Ping-Rohdaten, dann 1-s-Werte, dann
Flows und 10-s-Werte, und nur so weit, bis wieder Luft ist. Maßstab ist der belegte
Platz, nicht die Dateigröße (gelöschte Seiten bleiben zunächst in der Datei liegen).

**Backup** (im laufenden Betrieb konsistent):

```bash
sudo -u nla sqlite3 /var/lib/network-lag-analyzer/nla.sqlite3 ".backup '/tmp/nla-backup.sqlite3'"
sudo cp /etc/network-lag-analyzer/config.yaml /tmp/
```

Wiederherstellen: Dienst stoppen, Datei zurückkopieren (`chown nla:nla`), Dienst starten.

---

## Security

* Läuft als Benutzer `nla`, **nicht als root**. Einzige Zusatzberechtigung: `CAP_NET_RAW`
  (ICMP, optional AF_PACKET) über systemd `AmbientCapabilities`.
* systemd-Härtung: `ProtectSystem=strict`, `ProtectHome`, `NoNewPrivileges`,
  eingeschränkte Adressfamilien; Schreibzugriff nur auf `/var/lib/network-lag-analyzer`.
* Keine Shell-Aufrufe; Eingaben werden mit Pydantic validiert (IP-Adressen, Hostnamen,
  Interface-Namen per Whitelist).
* CSRF-Schutz für alle schreibenden Requests (Double-Submit-Token), Origin-Prüfung.
* Security-Header (CSP ohne Inline-Skripte, `X-Frame-Options: DENY`, `nosniff`).
* Hostnamen aus dem Netz werden im Browser ausschließlich als Text gerendert (kein `innerHTML`).
* Optionaler Login (Setup → Zugriffsschutz): scrypt-Hash, HttpOnly-Session-Cookie.
* Das FRITZ!Box-Passwort wird nie über die API ausgegeben. `config.yaml` hat die Rechte 0640 (root:nla).
* Pi-hole-Datenbank nur lesend. Payloads werden nie gespeichert (snaplen, nur Header).
* Nur für das LAN gedacht – den Port **nicht** im Router freigeben.

---

## Performance & Load Guard

* Anzeige-Verzögerung: Messwerte erscheinen ~3 s nach der Messung (Wartezeit auf
  verspätete Ping-Antworten). Der gepufferte Router-Mitschnitt verzögert die Anzeige
  NICHT: Traffic-Werte werden nachgetragen, sobald sie eintreffen. Nur die
  Ursachenanalyse wartet bewusst, bis die Sekunde vollständig ist (`analysis_delay`).
* ICMP: ein Socket, keine Prozessstarts; wenige hundert Byte/s. Die Pings werden
  gleichmäßig über das Messintervall verteilt, damit sie nirgends als Burst
  rate-limitiert werden (das sähe wie Paketverlust aus).
* Paketanalyse im eigenen Prozess (`nice 5`), nur Header, Aggregation im Speicher,
  einmal pro Sekunde ein Batch-Insert in SQLite.
* Load Guard (`backend/util/loadguard.py`):

| Stufe | Auslöser | Maßnahme |
|---|---|---|
| 1 | CPU > 75 % (10 s) oder Capture-Rückstand > 2 s | Flow-/Retransmission-Analyse aus |
| 2 | CPU > 90 %, RAM < 150 MB oder Rückstand > 5 s | Sampling 1:4, als „geschätzt" markiert |
| 3 | Stufe 2 länger als 60 s | Mitschnitt 5 min pausiert |

Die aktuelle Stufe steht als Banner in der Oberfläche.

---

## Troubleshooting

| Problem | Lösung |
|---|---|
| Seite nicht erreichbar | `systemctl status network-lag-analyzer`, `journalctl -u network-lag-analyzer -n 100`; Port frei? (`ss -ltnp \| grep 8088`) |
| „Ping-Messung nicht möglich" | Dienst muss über systemd laufen (CAP_NET_RAW). Manuell: `sudo setcap cap_net_raw+ep $(readlink -f /opt/network-lag-analyzer/venv/bin/python)` |
| Pi-hole „nicht lesbar" | `id nla` → Gruppe `pihole`? Rechte: `ls -l /etc/pihole/pihole-FTL.db` (Gruppe muss lesen dürfen). Danach Dienst neu starten |
| FRITZ!Box-Login fehlgeschlagen | Benutzer/Passwort; zu viele Fehlversuche sperren den Login kurz (BlockTime) |
| Mitschnitt HTTP 403/404 | Benutzer braucht Recht „FRITZ!Box Einstellungen"; Interface-Namen im Test prüfen |
| „Unbekanntes Mitschnitt-Format (Magic …)" | Version ≥ 1.0.1 nötig: unterstützt pcap, pcap-modified (`a1b2cd34`) und pcapng |
| „Interface liefert Linktype … statt Ethernet" | Falsches Mitschnitt-Interface (z. B. WAN/PPP). LAN-Bridge wählen, meist `1-lan` |
| TR-064 401/Timeout | „Zugriff für Anwendungen zulassen" aktivieren |
| Geräte-Traffic erscheint nur kurz und verschwindet wieder | Ab 1.0.2/1.0.3 behoben: Die FRITZ!Box liefert den Mitschnitt schubweise (`capture_delay` in `/api/status`, oft 3–9 s). Anzeige bleibt live, Traffic-Werte werden nachgetragen, die Auswertung wartet auf vollständige Daten (`analysis_delay`) |
| „Game-Paketlücke"-Events ohne Spiel | Ab 1.0.3 behoben: Diese Events entstehen nur noch während einer laufenden Gaming Session |
| Traffic je Gerät bleibt leer | Setup → Diagnose; Status „capture" in `/api/status`; Router-MAC erkannt? |
| Werte „geschätzt" | Load Guard aktiv – Pi überlastet; Deep Capture abschalten, Pi 4/5 verwenden |
| Konstant ~33 % (oder 25/50 %) Packet Loss, obwohl `ping` sauber läuft | Ab 1.0.4 behoben: Die Pings gingen als Bündel im Millisekundenabstand raus und wurden unterwegs rate-limitiert. Jetzt werden sie über das Intervall verteilt (~175 ms Abstand bei 4 Zielen) |
| Ein Ziel antwortet dauerhaft nicht | Ab 1.0.4 wird es als „antwortet nicht" markiert und aus Verlust/Latenz herausgerechnet, statt Dauerverlust vorzutäuschen. Verlustquote je Ziel steht in `/api/status` unter `targets` |
| „Verbindung & Mitschnitt testen" meldet „Keine Pakete empfangen" | Ab 1.0.4 behoben: Die FRITZ!Box erlaubt nur EINEN Mitschnitt je Interface. Läuft der Dienst bereits, zeigt der Test jetzt dessen Live-Werte statt einen zweiten Mitschnitt zu öffnen (der zuvor den laufenden beendete) |
| Download/Upload auf dem Dashboard „Not available" | Ab 1.0.5: Solange der gepufferte Mitschnitt unterwegs ist, füllt die WAN-Gesamtrate aus TR-064 die Lücke („FRITZ!Box gesamt (Summe)"), die exakten Werte je Gerät werden nachgetragen. Bleibt es leer: `capture.state` in `/api/status` prüfen und Dienst neu starten |
| „Latenz unter Last" zeigt nichts an | Es braucht ruhige UND ausgelastete Phasen sowie eine bekannte Leitungskapazität. Ohne eine Phase über 70 % Auslastung bleibt die Karte leer – das ist kein Fehler |
| PCAP-Verzeichnis belegt mehrere Gigabyte | Ab 1.1.1 begrenzt `deep_capture.max_total_mb` das gesamte Verzeichnis (Standard 1 GB) und beim Start wird der Bestand übernommen; vorhandene Altlasten verschwinden beim ersten Start oder über Setup → Datenbank → „Jetzt aufräumen" |
| Datenbank wird zu groß / Speicherkarte voll | Setup → Datenbank: Größe je Tabelle ansehen, nach Datum löschen, danach „Datei verkleinern". Dauerhaft: `retention.max_db_mb` setzen und `retention.ping_samples` aus lassen |
| Nach einem Update dauert der erste Start länger | Ab 1.1.0 werden bestehende Datenbanken auf das kompakte Format umgebaut (einmalig, mit Sicherungskopie `nla.sqlite3.pre-migration.bak`). Fortschritt steht im Journal |
| Ein Ziel meldet dauerhaft Verluste | Setup → Diagnose prüft jedes Ziel zweimal (verteilt und als Bündel). Verluste nur im Bündel = das Ziel drosselt ICMP, kein Netzwerkproblem |
| Oberfläche zeigt nach einem Update altes Verhalten | Ab 1.0.4 werden Frontend-Dateien nicht mehr gecacht; einmal mit Strg+F5 neu laden |
| Viele PING_SPIKE-Events ohne spürbaren Lag | Schwellwerte in Setup anheben; ICMP-Rate-Limiting einzelner Ziele → andere Ziele wählen |
| Pi misst selbst über WLAN | LAN-Kabel verwenden, sonst misst du die eigene WLAN-Strecke mit |
| Zeitstempel verschoben | NTP auf Pi und FRITZ!Box prüfen (`timedatectl`). Der Capture-Prozess gleicht Offsets automatisch aus |

API-Übersicht: `http://PI:8088/api/docs`.

---

## Entwicklung & Tests

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python -m pytest -q                       # Unit-, Szenario- und API-Tests
python -m backend.main --dev --data-dir /tmp/nla --port 8099   # Demo mit simulierten Daten
```

Simulierte Testszenarien (`tests/test_scenarios.py`): Upload Saturation, Download
Saturation, ISP Packet Loss, lokales Gateway-Problem, nur ein Zielserver betroffen,
DNS-Ausfall, Game-Server-Problem sowie Normalbetrieb ohne Fehlalarme.

### Umsetzung nach Phasen

| Phase | Inhalt | Tests |
|---|---|---|
| 1–3 | Anforderungsanalyse, Umgebung, [ARCHITECTURE.md](ARCHITECTURE.md) | – |
| 4–5 | Grundprojekt, SQLite-Schema, ICMP/Jitter/Loss, Dashboard, SSE | `test_metrics.py` |
| 6 | Device Discovery (FRITZ!Box, Pi-hole, ARP, Capture), Pi-hole | `test_api.py` |
| 7 | FRITZ!Box-Mitschnitt, pcap/pcapng-Parser, Flows, Retransmissions | `test_capture.py` |
| 8 | Event Detection, Incident-Korrelation, Ursachenregeln | `test_scenarios.py` |
| 9 | Gaming Mode, „ICH HATTE GERADE LAG" | `test_scenarios.py`, `test_misc.py` |
| 10 | Load Guard, PCAP-Ring, systemd, Installer, README | `test_misc.py` |

### Bekannte Grenzen

* ICMP-Ziele nur IPv4; IPv6-Traffic wird im Mitschnitt aber pro Gerät (über die MAC) gezählt.
* Traffic zwischen zwei Geräten hinter demselben Deco läuft nicht über die FRITZ!Box und
  ist nicht sichtbar. Für Internet-Lag ist das unerheblich.
* Game-Server, die ICMP blockieren, werden nur über Paketlücken im Game-Flow bewertet.
* Retransmissions werden heuristisch erkannt (wie Wireshark: Sequenz ≤ bereits gesehen).
  Umsortierte Pakete zählen mit.
