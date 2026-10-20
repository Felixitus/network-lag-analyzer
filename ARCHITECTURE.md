# Network Lag Analyzer – Architektur

Dieses Dokument beschreibt das konkrete technische Design. Ziel: die Frage
**„Warum hatte ich genau zu diesem Zeitpunkt Lag?"** beantworten, ohne Daten
vorzutäuschen, die der Raspberry Pi technisch nicht sehen kann.

## 1. Ausgangslage (Phase 1/2 – Analyse)

Zielumgebung:

```
Internet ── FRITZ!Box 7690 (Router, DHCP, 192.168.178.1)
               ├── LAN ── TP-Link Deco XE75 (Access-Point-Modus, LAN-Backhaul)
               │             ├── Gaming-PC (LAN am Deco)
               │             └── WLAN-Clients (iPhone, Smart-TV …)
               ├── WLAN-Clients der FRITZ!Box
               └── Raspberry Pi (Pi-hole, DNS)  ← diese Anwendung
```

Konsequenzen:

* Der Pi ist **nicht im Datenpfad**. Er sieht nur eigenen Traffic, Broadcasts
  und DNS-Anfragen (Pi-hole). Promiscuous Mode am Pi-Port hilft nicht, weil
  der Switch nur Frames an die MAC des Pi ausliefert.
* Pi-hole liefert **DNS-Metadaten**, nie Bandbreite. DNS-Anfragen werden
  ausschließlich zur Zuordnung IP → Hostname und als Aktivitäts-Hinweis
  genutzt, niemals als Traffic-Wert.
* Da der Deco im AP-Modus bridged, gibt es **kein doppeltes NAT**. Alle
  Clients haben eigene IPs/MACs im Netz der FRITZ!Box und ihr Internet-Traffic
  läuft durch die LAN-Bridge der FRITZ!Box.

Da der Pi in der Zielumgebung nicht erreichbar war, prüft der **Setup-Wizard**
(Abschnitt 9) die tatsächliche Umgebung beim ersten Start automatisch.

## 2. Datenquellen und Sichtbarkeit

| Datenquelle | Liefert | Voraussetzung | Standard |
|---|---|---|---|
| ICMP-Prober (eigener Socket) | RTT, Loss, Jitter zu Gateway + Internetzielen | CAP_NET_RAW oder `ping_group_range` | an |
| DNS-Prober | DNS-Antwortzeit/Ausfall (Pi-hole + Upstream) | – | an |
| FRITZ!Box TR-064 | WAN-Gesamtrate ↑/↓, Leitungskapazität, Hostliste (IP/MAC/Name) | FRITZ!Box-Benutzer, TR-064 aktiv | an, wenn Zugangsdaten gesetzt |
| **FRITZ!Box Paketmitschnitt** | Traffic pro Gerät, Flows, TCP-Retransmissions, UDP-Game-Flows | Benutzer mit Recht „FRITZ!Box Einstellungen" | an, wenn Zugangsdaten gesetzt |
| Lokaler AF_PACKET-Capture | wie oben | Pi ist Gateway oder hängt an Mirror-Port | aus |
| Pi-hole FTL-Datenbank | Hostnamen, MAC, Hersteller, DNS-Anfragen je Client | Leserecht (Gruppe `pihole`) | automatisch |
| `/proc/net/arp` | IP ↔ MAC | – | an |
| psutil | CPU/RAM/Temperatur des Pi | – | an |

### Warum der FRITZ!Box-Paketmitschnitt?

Bewertete Alternativen:

* **libpcap/tcpdump/eBPF/nftables/conntrack am Pi**: sehen nur Traffic, der
  den Pi passiert. Nutzlos, solange der Pi nicht Gateway ist.
* **Pi als Gateway**: vollständige Sicht, aber jeder Paketpfad hängt dann
  am Pi. Ein Pi-Ausfall legt das Internet lahm und bringt zusätzliche Latenz,
  ungeeignet für ein Lag-Diagnosetool.
* **Managed Switch mit Port-Mirroring**: sehr gut, erfordert aber neue
  Hardware (vom Nutzer aktuell nicht gewünscht; als Quelle `local` unterstützt).
* **FRITZ!Box TR-064**: liefert nur Gesamt-WAN-Raten, nicht pro Gerät.
* **FRITZ!Box-Mitschnitt (`/cgi-bin/capture_notimeout`)**: die FRITZ!Box
  streamt einen libpcap-Datenstrom ihrer LAN-Bridge über HTTP (klassisches pcap,
  „modified pcap" mit Magic `a1b2cd34` und 24-Byte-Recordheader, oder pcapng –
  der Parser erkennt alle drei). Mit
  `snaplen=128` werden nur Header übertragen (keine Payload). Der Pi zählt
  daraus Bytes/Pakete pro MAC und Flow-Metadaten. **Keine Zusatzhardware,
  vollständige Sicht auf den Internet-Traffic aller Clients.**

Gewählt: **FRITZ!Box-Mitschnitt als Primärquelle**, TR-064 als
Gesamtraten-Fallback, AF_PACKET als Alternative für Mirror-/Gateway-Setups.

Kosten des Mitschnitts:

* Pro Paket ~16 Byte pcap-Header + max. 128 Byte Header-Daten. Bei 10 000
  Paketen/s ≈ 1,4 MB/s LAN-Traffic vom Router zum Pi – im Gigabit-LAN
  vernachlässigbar.
* Der Mitschnitt-Datenstrom läuft selbst über die LAN-Bridge und wird
  mitgeschnitten (Rückkopplung ≈ 1/10, konvergiert). Diese Verbindung wird
  über ihr 4-Tupel **aus allen Statistiken ausgefiltert**.
* Die FRITZ!Box-CPU wird zusätzlich belastet. Das Setup zeigt das an; der
  Mitschnitt ist abschaltbar.
* Grenze: Python parst auf einem Pi 4 grob 30–50 kpps. Bei voll ausgelasteter
  Gigabit-Leitung reicht das nicht; der Load-Guard (Abschnitt 8) schaltet
  dann auf Sampling mit Hochrechnung um und **kennzeichnet die Werte als
  geschätzt**.

### Zuordnung von Paketen zu Geräten

Auf der LAN-Bridge hat jedes Paket eine Quell- und Ziel-MAC:

* Die **Router-MAC** wird aus der ARP-Tabelle (Gateway-IP) bestimmt und
  zusätzlich gelernt (die MAC, die Pakete mit öffentlichen Quell-IPs sendet).
* `src_mac = Client, dst_mac = Router, Ziel-IP nicht lokal` → **Upload** des Clients.
* `src_mac = Router, dst_mac = Client, Quell-IP nicht lokal` → **Download** des Clients.
* Alles andere → LAN-intern (separat gezählt, nicht als WAN-Last).

Der Schlüssel ist die **MAC**, dadurch funktioniert die Zuordnung auch für
IPv6 (Privacy-Adressen). Die angezeigte IPv4 wird aus ARP/FRITZ!Box/Pi-hole
bzw. aus beobachteten Paketen gelernt.

## 3. Prozess- und Modulstruktur

```
                ┌───────────────────────────── Hauptprozess (asyncio) ─────────────────────────────┐
                │ collectors/ping.py   ICMP-Prober (1 Socket, SO_TIMESTAMPNS)                        │
                │ collectors/dns.py    DNS-Prober                                                    │
                │ collectors/fritzbox.py  TR-064 (WAN-Raten, Linkrate, Hostliste)                    │
                │ collectors/pihole.py  FTL-DB read-only (Hostnamen, DNS je Client)                 │
                │ collectors/devices.py Gerätetabelle (ARP + FRITZ!Box + Pi-hole + Capture)          │
                │ analysis/metrics.py   Sekunden-Assembler, Ringpuffer (1 h live)                   │
                │ analysis/events.py    Event Detection (Hysterese, Baseline)                        │
                │ analysis/correlation.py Incidents, Lag-Report, Timeline-Fenster                    │
                │ analysis/root_cause.py  dokumentierte Ursachen-Regeln + Empfehlungen               │
                │ analysis/bufferbloat.py Latenz unter Last (je Richtung)                           │
                │ analysis/gaming.py    Gaming Sessions, Server-Erkennung                            │
                │ analysis/daily.py     Tages-Zusammenfassung (Langzeit)                            │
                │ database/migrations.py nummerierte Schema-Schritte + Sicherungskopie              │
                │ database/*            SQLite WAL, Batch-Writer, Aggregation, Retention             │
                │ api/*                 FastAPI REST + Server-Sent Events                            │
                └───────────────▲──────────────────────────────────────────────────────────────────┘
                                │ multiprocessing.Queue (Sekunden-Aggregate, Flows, Status)
                ┌───────────────┴────────── Capture-Prozess (collectors/traffic.py) ──────────────┐
                │ Quelle: FRITZ!Box-HTTP-Stream | AF_PACKET | none                                │
                │ collectors/pcapstream.py  inkrementeller pcap/pcapng-Parser                      │
                │ collectors/flows.py       Paket-Dekodierung, Bins pro MAC, Flow-Tabelle,         │
                │                           TCP-Retransmission-Heuristik, Game-Flow-Gaps           │
                │ PCAP-Ringpuffer (optional, Deep Capture)                                         │
                └──────────────────────────────────────────────────────────────────────────────────┘
```

Das CPU-intensive Paketparsing läuft **in einem eigenen Prozess**, damit der
GIL die Zeitstempel der ICMP-Messungen im Hauptprozess nicht verfälscht und
ein zweiter CPU-Kern genutzt wird. Zwischen den Prozessen werden nur
Sekunden-Aggregate übertragen, keine Pakete.

## 4. Messverfahren

### ICMP

* Ein einziger Socket für alle Ziele (`SOCK_DGRAM/IPPROTO_ICMP`, Fallback
  `SOCK_RAW` mit CAP_NET_RAW). Kein Prozessstart pro Ping.
* Empfangszeit per Kernel-Zeitstempel (`SO_TIMESTAMPNS`), damit Event-Loop-
  Verzögerungen die RTT nicht verfälschen.
* Standard: 1 Probe/s pro Ziel; im Gaming-Modus 4 Probes/s. Die Probes eines
  Zyklus werden gleichmäßig über das Intervall verteilt (bei 4 Zielen ~175 ms
  Abstand) – ein ICMP-Burst würde von Routern, Providern oder Zielservern
  rate-limitiert und wie Paketverlust aussehen.
* Ein Ziel, das `unreachable_after` Sekunden am Stück nicht antwortet, während
  andere Ziele weiterhin antworten, gilt als "antwortet nicht" und fließt nicht
  mehr in Verlust/Latenz ein (sichtbar in `/api/status`). Fallen alle Ziele aus,
  bleibt es ein echter Ausfall.
* Timeout 1,5 s → gilt als verloren. Sekunde *T* wird bei *T + 1 + Timeout*
  finalisiert, das Dashboard hinkt also ~2,5 s hinterher (bewusst, damit
  Verlust korrekt gezählt wird).

### Umgang mit dem gepufferten Router-Stream

Die FRITZ!Box liefert den Mitschnitt nicht kontinuierlich, sondern in Schüben
(bei wenig Traffic mehrere Sekunden am Stück). Würde eine Sekunde stur nach
Zeitplan finalisiert, fehlten dort die Traffic-Daten – das Dashboard flackert.
Deshalb:

* Der Hauptprozess misst die tatsächliche Zustellverzögerung der Sekunden-Bins
  (90. Perzentil der letzten 60) und trennt danach zwei Pfade:
  **Anzeige** (max. 3 s Wartezeit, damit Ping/Jitter/Loss live bleiben) und
  **Auswertung** (Event-Engine und Incidents bekommen eine Sekunde erst, wenn ihre
  Traffic-Daten da sind, spätestens nach `analysis_delay` = Pufferzeit + 3 s).
* Kommt ein Bin trotzdem zu spät, wird die betroffene Sekunde im Ringpuffer und
  in der Datenbank nachgetragen und die Oberfläche per `tick_patch`-Ereignis
  aktualisiert.
* Bleibt der Mitschnitt ganz aus, finalisiert die Auswertung nach spätestens
  `traffic_grace` Sekunden trotzdem – dann ehrlich ohne Traffic-Werte.
* Für die Gesamtraten überbrückt TR-064 die Wartezeit (Quelle `tr064`, alle 2 s,
  ohne Geräte-Zuordnung). Trifft der Mitschnitt ein, ersetzt er diese Werte. Die
  Ursachenanalyse akzeptiert TR-064 NICHT als vollständig, weil ihr damit die
  Zuordnung zum Gerät fehlt.

### Kennzahlen pro Sekunde

* **Internet-RTT**: Median der Internetziele (robust gegen ein einzelnes
  langsames Ziel), zusätzlich Min/Max.
* **Jitter**: mittlere absolute Differenz aufeinanderfolgender RTTs je Ziel
  (RFC 3550-Idee, ungeglättet) über 10 s, Median über die Ziele.
* **Packet Loss**: verlorene/gesendete Probes der Internetziele; Fenster
  5 s/10 s/30 s/60 s/5 min aus dem Ringpuffer.
* **Durchsatz**: aus dem Mitschnitt (pro Gerät, exakt) oder TR-064
  (nur gesamt). Die Quelle wird immer mit angezeigt.
* **TCP-Retransmissions**: Segment mit Payload, dessen Sequenzende ≤ bereits
  gesehenem Maximum derselben Richtung (Wireshark-ähnliche Heuristik),
  getrennt nach Download-/Upload-Richtung.

## 5. Event Detection

Sprünge der Systemuhr (NTP nach dem Boot) werden erkannt: Weicht die Wanduhr um
mehr als zwei Sekunden von der monotonen Uhr ab, werden angefangene Sekunden
verworfen und die Zeitrechnung rastet neu ein – lieber eine ehrliche Lücke als
Messwerte unter falschem Zeitstempel. Erkannte Sprünge stehen in `/api/system`.

Jede finalisierte Sekunde läuft durch die Detektoren in `analysis/events.py`.
Baseline = gleitender Median der letzten 5 min (ohne Spike-Sekunden).
Jeder Detektor hat eine Start- und eine End-Bedingung (Hysterese), Events
haben Start, Ende, Spitzenwert, Baseline und Details.

Event-Typen: `PING_SPIKE, PACKET_LOSS, HIGH_JITTER, HIGH_UPLOAD,
HIGH_DOWNLOAD, TCP_RETRANSMISSION_SPIKE, CONNECTION_DROP, DNS_FAILURE,
GATEWAY_LATENCY, INTERNET_LATENCY, GAME_FLOW_GAP`.

## 6. Incidents und Ursachenanalyse

* Lag-relevante Events öffnen einen **Incident**; er schließt 5 s nach dem
  letzten Lag-Event. Danach wird das Fenster [Start − 30 s, Ende + 5 s]
  analysiert.
* Der **„ICH HATTE GERADE LAG"-Button** erzeugt sofort einen Incident für
  die letzten 10 s/30 s/60 s/5 min und liefert eine Zeitleiste der Funde.
* `analysis/root_cause.py` enthält jede Regel als eigene, dokumentierte
  Funktion. Jede Regel liefert Kategorie, Punktzahl, Evidenzliste und ggf.
  Gerät. Die Confidence wird aus der Evidenz abgeleitet:

| Confidence | Formulierung | Bedeutung |
|---|---|---|
| low | „zeitlich korreliert" | trat gleichzeitig auf, mehr nicht |
| medium | „möglicher Verursacher" | plausibel, aber Evidenz unvollständig |
| high | „wahrscheinlicher Verursacher" | Reihenfolge, Dauer und Ausschlusskriterien passen |

Fehlt eine Datenquelle (z. B. kein Traffic pro Gerät), sagt die Analyse das
ausdrücklich und benennt kein Gerät.

* Zu jeder Kategorie gehört eine **Handlungsempfehlung** (`RECOMMENDATIONS` in
  `root_cause.py`) mit einem `scope`: `self` (selbst behebbar), `provider`
  (nur der Anbieter kann es ändern), `remote` (Zielserver/Routing) oder `none`.
  Upload- und Download-Sättigung bekommen bewusst gegensätzliche Ratschläge:
  beim Upload steht die Warteschlange im eigenen Router (Priorisierung wirkt),
  beim Download beim Provider (nur Drosseln des ladenden Geräts wirkt).
* `analysis/bufferbloat.py` misst die **Latenz unter Last** je Richtung:
  Median-RTT ruhiger Sekunden (≤ 20 % Auslastung) gegen die Median-RTT
  ausgelasteter Sekunden (≥ 70 % in einer Richtung, < 40 % in der anderen).
  Mindestens 5 Sekunden je Gruppe, sonst kein Ergebnis. Wird im Incident
  mitgeliefert (`metrics.latency_under_load`) und über `/api/bufferbloat`
  als Zeitraum-Kennzahl ausgegeben.

## 7. Datenhaltung (SQLite, WAL)

Tabellen: `settings, targets, ping_samples, measurements, target_measurements,
devices, device_traffic, network_flows, events, incidents, dns_queries,
gaming_sessions, pcap_files, bufferbloat, daily_stats`.

* `measurements`, `target_measurements`, `device_traffic` haben eine Spalte
  `res` (1, 10, 60 s). Ein Aggregations-Job verdichtet minütlich 1 s → 10 s → 60 s.
* Retention (konfigurierbar): 1 s-Werte 24 h, 10 s-Werte 7 Tage, 60 s-Werte
  30 Tage, Flows 7 Tage, Events/Incidents 90 Tage.
* Messwerte liegen als INTEGER in festen Einheiten (1/100 ms, 1/100 %, bit/s);
  umgerechnet wird nur in `repository.py` (`enc`/`dec`). `device_traffic` nutzt
  `devices.id` statt der MAC als Text. Zusammen rund 58 % weniger Schreibvolumen
  – auf einer SD-Karte der entscheidende Punkt.
* Schema-Änderungen laufen über nummerierte Schritte in `migrations.py`. Beim
  Start wird `schema_version` gelesen, jeder fällige Schritt in einer eigenen
  Transaktion angewendet, davor eine Sicherungskopie angelegt (sofern Platz frei).
* `daily_stats` hält je Tag rund 200 Byte (Perzentile, Verlust, Spitzen,
  Bufferbloat, Incidents je Kategorie) und ist von der Retention ausgenommen.
* `retention.max_db_mb` ist eine Notbremse: Überschreitet der BELEGTE Platz die
  Grenze, wird schrittweise gelöscht (Rohdaten → 1 s → Flows → 10 s) und danach
  VACUUM ausgeführt. Freie Seiten zählen nicht mit, sonst liefe das Löschen endlos.
* Deep Capture hat ein **Gesamtbudget** (`max_total_mb`), nicht nur `max_files`.
  Geschützte Incident-Mitschnitte liegen außerhalb des Rings und bekommen den
  Rest des Budgets; ist es voll, fällt der älteste weg. Beim Start übernimmt der
  Ring den vorhandenen Bestand – ohne das blieben nach jedem Neustart des
  Capture-Prozesses dessen Dateien herrenlos liegen.
* `bufferbloat` speichert je 10-Minuten-Fenster neun Zahlen (Ruhe-Median,
  Median und Spitze je Richtung, Sekundenzahlen). Damit bleibt der Verlauf der
  Latenz unter Last über Wochen sichtbar, obwohl die 1-s-Werte nach einem Tag
  gelöscht werden. Aufbewahrung wie Events (90 Tage).
* Schreiben ausschließlich über einen Batch-Writer (ein Thread, eine
  Transaktion pro Sekunde). Lesen über separate Verbindungen.
* Live-Charts und die Lag-Analyse lesen primär aus dem In-Memory-Ringpuffer
  (1 h), historische Bereiche aus der Datenbank.

## 8. Ressourcenschutz (Load Guard)

`util/loadguard.py` überwacht System-CPU, verfügbaren RAM, Temperatur und
den Rückstand des Capture-Prozesses:

| Stufe | Auslöser (Standard) | Maßnahme |
|---|---|---|
| 0 | normal | volle Analyse |
| 1 | CPU > 75 % (10 s) oder Rückstand > 2 s | keine Flow-/Retransmission-Analyse, nur Bytes pro Gerät |
| 2 | CPU > 90 % oder RAM < 150 MB oder Rückstand > 5 s | Sampling 1:4, hochgerechnet, als „geschätzt" markiert |
| 3 | anhaltend Stufe 2 für 60 s | Mitschnitt pausiert für 5 min, UI zeigt „Not available (Last)" |

Pi-hole hat Vorrang: der Dienst läuft mit `Nice=10`, `CPUWeight=50`,
`MemoryMax=300M`.

## 9. Setup-Wizard

Prüft Interfaces, IP, Default-Gateway, Pi-hole, ob der Pi Gateway ist,
IP-Forwarding, sichtbare Clients, Promiscuous Mode, FRITZ!Box-Login,
TR-064 und Mitschnitt – und zeigt eine ehrliche Fähigkeitsmatrix
(„Traffic all LAN devices: ✗ – Pi nicht im Datenpfad …").

## 10. Sicherheit

* Dienst läuft als Benutzer `nla`, nicht root. `CAP_NET_RAW` (ICMP,
  AF_PACKET) über systemd `AmbientCapabilities`.
* Keine Shell-Aufrufe; keine Benutzereingabe erreicht einen Subprozess.
* Pydantic-Validierung aller Eingaben, IP-Adressen über `ipaddress`.
* Optionaler Login (scrypt-Hash, HttpOnly-Session-Cookie). CSRF-Schutz für
  alle schreibenden Requests über Double-Submit-Token (`X-CSRF-Token`).
* FRITZ!Box-Passwort in `/etc/network-lag-analyzer/config.yaml` (0640,
  root:nla) bzw. DB-Setting; wird nie über die API zurückgegeben.
* Pi-hole wird nur **lesend** geöffnet (`mode=ro`).

## 11. Keine Fake-Daten

Jeder Messwert ist entweder gemessen oder `null`. Das Frontend zeigt `null`
als **„Not available"** mit Begründung. Synthetische Daten gibt es nur mit
`dev_mode: true`, dann mit dauerhaftem Banner „DEMO-MODUS".
