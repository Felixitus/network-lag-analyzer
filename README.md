# Network Lag Analyzer

[![Tests](https://github.com/Felixitus/network-lag-analyzer/actions/workflows/tests.yml/badge.svg)](https://github.com/Felixitus/network-lag-analyzer/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Local network diagnostics for the Raspberry Pi (with Pi-hole) that answers one question:

> **"Why did I have lag or packet loss at exactly this moment?"**

The application measures ping, jitter and packet loss to the router and the internet every
second, records - as far as technically visible - the traffic of every device, detects
anomalies automatically and correlates them in time. A result looks like this:

```
INCIDENT #124 · 2026-09-21 20:43:12 · duration 4.2 s
Ping 18 → 184 ms · Jitter 2 → 61 ms · Packet Loss 8 % · Gateway 1.1 ms

Possible Cause: Upload saturation by iPhone          Confidence: High
Evidence:
  • Upload utilization up to 97 % of the line (38.8 of 40 Mbit/s)
  • Upload increase started before the latency increase (2 s earlier)
  • Router latency stayed stable
  • 3 external targets showed increased latency/loss at the same time
  • iPhone caused 96 % of the upload
```

Everything runs locally. No cloud, no telemetry, no payload storage.

---

## Contents

1. [Features](#features)
2. [Architecture](#architecture)
3. [Raspberry Pi requirements](#raspberry-pi-requirements)
4. [Installation](#installation)
5. [Network architecture & traffic visibility](#network-architecture--traffic-visibility)
6. [Setting up the FRITZ!Box (recommended)](#setting-up-the-fritzbox-recommended)
7. [Port mirroring](#port-mirroring)
8. [Raspberry Pi as gateway](#raspberry-pi-as-gateway)
9. [Pi-hole integration](#pi-hole-integration)
10. [DNS usage per device](#dns-usage-per-device)
11. [Usage](#usage)
12. [Root cause analysis - how it decides](#root-cause-analysis---how-it-decides)
13. [Configuration](#configuration)
14. [Database & backup](#database--backup)
15. [Security](#security)
16. [Performance & load guard](#performance--load-guard)
17. [Troubleshooting](#troubleshooting)
18. [License](#license)

---

## Features

| Area | Scope |
|---|---|
| Latency | ICMP to the router + freely selectable internet targets, 1/s (Gaming Mode 4/s), one permanently open socket, kernel timestamps |
| Metrics | RTT (median/min/max), jitter, packet loss over 5 s/10 s/30 s/60 s/5 min, reachability |
| Traffic | upload/download per device, UDP share, TCP retransmissions (per direction), flows (metadata only) |
| Events | `PING_SPIKE`, `PACKET_LOSS`, `HIGH_JITTER`, `HIGH_UPLOAD`, `HIGH_DOWNLOAD`, `TCP_RETRANSMISSION_SPIKE`, `CONNECTION_DROP`, `DNS_FAILURE`, `GATEWAY_LATENCY`, `INTERNET_LATENCY`, `GAME_FLOW_GAP` |
| Incidents | automatic correlation + documented cause rules with confidence and evidence |
| Path measurement | traceroute (mtr style) to the worst targets when an incident starts: from which hop on packets are lost, in your network or the provider's |
| Upstream DNS | reply times per DNS server behind Pi-hole, from its own log - median, 95 %, queries without a reply |
| Recommendations | a concrete action for every category - including whether you can fix it yourself or it is up to the provider |
| Latency under load | bufferbloat metric per direction ("+120 ms under download load"), long-term history over weeks |
| "I JUST HAD LAG" | immediately analyzes 10 s/30 s/60 s/5 min and creates an incident with a timeline |
| Gaming Mode | manual or automatic; game server detection, packet gaps in the game flow, session summary |
| Web UI | dashboard, shared timeline, device lanes, heatmap, incident details, top talkers, setup wizard; light/dark, responsive |
| Deep Capture | optional PCAP ring buffer (headers only), incident captures are protected and downloadable; **hard total limit** via `max_total_mb` |
| Timeline | stacked panels with ONE time axis, value readout at the cursor, zoom by dragging, hatching for periods that were not measured |
| Long-term | daily summary over years (`daily_stats`), independent of the retention of the detail data |
| Storage | size per table, deletion by date with preview, VACUUM, automatic size limit |
| Operations | systemd, journald, SQLite (WAL), schema migrations with backup copy, aggregation 1 s → 10 s → 1 min, retention, load guard |

**No fake data:** whatever cannot be measured appears as "Not available" with a reason.
Simulated data only exists with `dev_mode: true` - and then with a permanent
"DEMO MODE" banner.

---

## Architecture

Details: [ARCHITECTURE.md](ARCHITECTURE.md).

```
backend/
  main.py              entry point (uvicorn)
  config.py            configuration (YAML + overrides from the UI), validation
  core.py              orchestration of all components
  collectors/
    ping.py            ICMP prober (one socket, SO_TIMESTAMPNS)
    dns.py             DNS prober (Pi-hole + upstream)
    fritzbox.py        FRITZ!Box: login (PBKDF2), TR-064, capture URL
    traffic.py         capture process (FRITZ!Box stream or AF_PACKET), PCAP ring
    pcapstream.py      incremental pcap/pcapng parser
    flows.py           packet analysis: bytes per device, flows, retransmissions, game flow
    pihole.py          Pi-hole FTL database (read-only)
    devices.py         device registry (FRITZ!Box, Pi-hole, ARP, capture)
  analysis/
    metrics.py         per-second assembler, jitter/loss, 1 h ring buffer
    events.py          event detection with hysteresis and baselines
    correlation.py     incidents, lag report
    root_cause.py      cause rules (each rule documented)
    gaming.py          gaming sessions
  database/            schema, batch writer, aggregation, retention
  api/                 REST + server-sent events, security middleware
  setup_wizard.py      diagnosis of the network architecture
  simulation.py        ONLY tests/dev mode
frontend/              HTML/CSS/JS (ES modules), uPlot bundled locally
deploy/                systemd unit
tests/                 unit, scenario and API tests
```

Packet parsing runs in a **separate process**. That way it neither distorts the ICMP
timestamps in the main process nor slows down the web API.

---

## Raspberry Pi requirements

| | Minimum | Recommended |
|---|---|---|
| Model | Raspberry Pi 3B+ | Raspberry Pi 4/5 (2 GB+) |
| OS | Raspberry Pi OS / Debian 12 (Bookworm), Python ≥ 3.10 | 64-bit |
| Connection | LAN | **LAN cable** (Wi-Fi distorts jitter/latency of the measurement itself) |
| Storage | ~200 MB for the program, data 50–500 MB depending on traffic | SSD instead of SD card when using Deep Capture |
| RAM | ~80–150 MB (main process + capture process) | – |

Pi-hole keeps running unchanged. The service has a lower CPU priority than Pi-hole
(`Nice=10`, `CPUWeight=50`) and is limited to 350 MB RAM.

---

## Installation

```bash
sudo apt install -y git
git clone https://github.com/Felixitus/network-lag-analyzer.git
cd network-lag-analyzer
sudo ./install.sh
```

The installer:

1. installs missing packages (`python3`, `python3-venv`, `python3-pip`) - **no** `apt upgrade`,
2. creates the system user `nla` and adds it to the group `pihole` (read access only),
3. copies the program to `/opt/network-lag-analyzer` and creates a venv there,
4. creates `/etc/network-lag-analyzer/config.yaml` (an existing one is kept),
5. creates `/var/lib/network-lag-analyzer` (database, PCAPs),
6. installs and starts `network-lag-analyzer.service` (enabled: starts again after a reboot),
7. asks for the **login account** (username + password) if none exists yet.

The account can only be created on the Pi - there is no sign-up page, so nobody on the
network can claim a fresh installation first. Create or reset it later with:

```bash
cd /opt/network-lag-analyzer
sudo -u nla env NLA_CONFIG=/etc/network-lag-analyzer/config.yaml venv/bin/python -m backend.account set --username admin
```

`... -m backend.account show` shows the account and open sessions, `logout-all` ends all
sessions. An optional password from versions before 1.2 becomes the user `admin`.

Then open in a browser (e.g. from your PC) and sign in:

```
http://raspberrypi:8088      or      http://PI-IP-ADDRESS:8088
```

On first use go to **Setup**, run the diagnosis and enter the FRITZ!Box access.

**Update:** `git pull && sudo ./install.sh` in the cloned directory - configuration and
data are kept; schema changes are migrated on start (with a backup copy before tables
are rebuilt).

**Uninstall:** `sudo ./install.sh --uninstall` stops and removes the service, the program
in `/opt/network-lag-analyzer` and the systemd unit. Data (`/var/lib/network-lag-analyzer`)
and configuration (`/etc/network-lag-analyzer`) are kept; to remove them as well:

```bash
sudo rm -rf /var/lib/network-lag-analyzer /etc/network-lag-analyzer
sudo userdel nla
```

Pi-hole is not touched by either.

**Pi-hole is not modified by the installer or the statistics.** The installer touches
neither `/etc/pihole`, dnsmasq/FTL nor the Pi-hole web server. The default port 8088 does
not collide with Pi-hole (80/443). Only if you switch on *Setup → Pi-hole actions* (with an
app password from Pi-hole) can the DNS pages pause blocking, allow or block a domain,
restart DNS or update the blocklists - through Pi-hole's own API, each after a
confirmation and logged with your user name.

---

## Network architecture & traffic visibility

Most important point: **Pi-hole only sees DNS.** A Raspberry Pi that is not the router
fundamentally does not see other devices' traffic - a switch only sends it packets that
are addressed to it. Promiscuous mode does not change that.

| Measurement | Pi on the LAN (default) | + FRITZ!Box capture | + port mirroring | Pi as gateway |
|---|:-:|:-:|:-:|:-:|
| Ping/jitter/loss router + internet | ✓ | ✓ | ✓ | ✓ |
| DNS activity per device (Pi-hole) | ✓ | ✓ | ✓ | ✓ |
| Total WAN rate (TR-064) | ✓¹ | ✓ | ✓¹ | ✓ |
| Traffic per device | ✗ | ✓ | ✓ | ✓ |
| TCP retransmissions, flows | ✗ | ✓ | ✓ | ✓ |
| Game flow analysis (packet gaps) | ✗ | ✓ | ✓ | ✓ |

¹ with FRITZ!Box credentials.

The **setup wizard** checks this actively (among other things it listens on the interface
for 2 s to see whether foreign unicast frames arrive) and shows the capability matrix. If a
source is missing, the UI says so - and the root cause analysis then names **no device**.

---

## Setting up the FRITZ!Box (recommended)

1. **Enable TR-064:** Home Network → Network → Network Settings → "Allow access for
   applications".
2. **Create a dedicated user:** System → FRITZ!Box Users → Add user, e.g. `nla`,
   strong password, permission **"FRITZ!Box Settings"** (needed for the packet capture).
   No internet access to the box is needed.
3. In the web UI → **Setup** → "FRITZ!Box & traffic source": enable the integration,
   enter user/password, click **"Test connection & capture"**, save.

Technically, the Pi opens a permanent HTTP stream
`/cgi-bin/capture_notimeout?ifaceorminor=1-lan&snaplen=600`. The FRITZ!Box sends a
libpcap stream of its LAN bridge with the first 600 bytes of each packet: the headers, and
for new TLS and QUIC connections the server name they ask for. That part is only read in
memory; the PCAP files of the deep capture keep **headers only** (128 bytes,
`deep_capture.snaplen`). `fritzbox.snaplen: 128` sends headers only in the first place, at
the price of no server names.
Depending on FRITZ!OS this is either classic pcap or the "modified pcap" variant
(magic `a1b2cd34`, 24-byte record headers); both are supported, as is pcapng. From it the Pi
counts bytes/packets per MAC (upload = client → router, download = router → client)
and builds flows. The capture connection itself is filtered out.

Notes:
* Depending on FRITZ!OS the interface is usually called `1-lan`. The test shows the interfaces it finds.
* The capture puts some load on the FRITZ!Box CPU and creates ~1–2 MB/s of LAN traffic under
  high load. At very high packet rates (gigabit fully utilized) the load guard switches to
  sampling and marks values as estimated.
* Without a capture but with credentials, TR-064 at least delivers the total WAN rate
  (without a per-device split) and the line capacity.

---

## Port mirroring

Alternative with extra hardware: a managed switch (e.g. TP-Link TL-SG105E/108E,
Netgear GS105E) between the FRITZ!Box and the rest of the network mirrors the uplink port
to the Pi's port.

```
FRITZ!Box LAN ── [Port 1] Managed switch [Port 2..n] ── Deco, PC, …
                          [Port 5 = mirror target] ── Raspberry Pi
```

Settings: source = port to the FRITZ!Box (ingress and egress), target = the Pi's port.
In the UI: traffic source = "Local interface", interface `eth0`. The wizard detects
mirrored traffic automatically ("Foreign client traffic visible at the Pi ✓").

Caution: some cheap switches only mirror one direction or disable the normal network
access of the target port - in that case use a second network adapter (USB) on the Pi
as the mirror port.

---

## Raspberry Pi as gateway

Possible (source "Local interface", IP forwarding active), but **not recommended** for
this purpose: every packet then passes through the Pi. That adds latency, and if the Pi
fails, the internet is gone. For a lag diagnosis tool that is the wrong trade-off. The
FRITZ!Box capture or port mirroring provide the same view without this risk.

---

## Pi-hole integration

* Only `/etc/pihole/pihole-FTL.db` is read (read-only, Pi-hole v5 and v6):
  tables `network`/`network_addresses` (MAC, IP, host name, vendor) and `queries`.
* Used for: device names, DNS activity and top domains per device (devices page).
* **DNS queries are never interpreted as bandwidth.** Many DNS queries do not mean
  a lot of traffic.
* By default FTL writes to the database once per minute - so DNS data is delayed by up
  to ~60 s. That does not matter for the lag analysis.
* In addition, a dedicated DNS prober measures Pi-hole (127.0.0.1) and an upstream
  resolver every 5 s. This detects a DNS outage and distinguishes it from real lag.
* `/etc/pihole/dhcp.leases` (read-only) gives the host names of the current DHCP leases
  where Pi-hole is the DHCP server. Host name priority: DHCP lease, Pi-hole, FRITZ!Box.
  **Refresh host names** (devices page) asks all sources again right away; own names stay.

---

## DNS usage per device

The page **DNS usage** shows per device which names it looked up through Pi-hole -
queries, blocked queries, domains, categories, a timeline, an estimate of activity phases
per service, and CSV/XLSX export. Method, storage and limits: **[docs/dns-usage.md](docs/dns-usage.md)**.

In short:

* Source is Pi-hole's query log, read incrementally and read-only; only compact counters
  are stored (about 400 KB per day on the test Pi, all of it subject to retention).
* Queries are attributed to devices by MAC only where that is sound (own IP history,
  FRITZ!Box cross-check); otherwise they stay "IP only".
* Categories are local rules (~400 domains of known services, own rules, optional UT1 lists
  with adult content, gambling, dating, VPN/DNS bypass and malware). CDNs and shared
  platforms are never attributed to a service.
* Activity phases are **estimated DNS activity, not usage time** - confidence at most
  "medium", "Not reliably determinable" where the data does not allow an estimate.
* Lookups that bypass Pi-hole (DNS over HTTPS, iCloud Private Relay, VPN, fixed DNS
  servers) are missing; the client identification check on the page lists devices that
  never ask Pi-hole.

---

## Usage

**Dashboard:** live tiles (internet, ping, jitter, packet loss, gateway, download,
upload), the big **"I JUST HAD LAG"** button, live charts with the time ranges
LIVE/5 MIN/15 MIN/1 H/6 H/24 H/7 D, top devices, latest incidents, active events.
Updated via server-sent events, without reloading.

**Timeline:** ping, loss, jitter, upload, download, retransmissions and below them an
upload/download lane per device - all on **one shared time axis** with a synchronized
cursor. Incidents are red bands (clicking opens the incident), reported lag is orange,
events are ticks at the top. Below that the heatmap (devices × time).

**Incidents:** list and detail view (metrics before → peak, possible cause,
confidence, evidence, top traffic, all explanations checked, events, connections,
charts around the time, PCAP download with Deep Capture).

**Gaming:** start/stop a session, game server and packet gaps live, summaries:

```
Gaming session 19:32–22:14
Ping average 19 ms · maximum 214 ms · jitter avg 3.2 ms
Packet loss events 4 · lag events 7
Possible causes: 3× upload saturation, 2× WAN/ISP, 1× LAN/Wi-Fi, 1× unknown
```

Automatic detection: if the gaming PC has sustained (≥ 20 s) bidirectional UDP traffic
to an internet server (≥ 15 packets/s per direction), the session starts by itself.
Mark the gaming PC under **Devices** (checkbox "Gaming PC").

**Note on the game server:** many game servers (e.g. Azure/AWS for Rainbow Six Siege)
do not answer pings. Then it says "Not available" there. The connection is still
monitored via **packet gaps in the game flow**: if the server sends no packets for more
than 250 ms, a `GAME_FLOW_GAP` event is created.

---

### Reading the timeline

All panels share one time axis; only the bottom one carries the times. When hovering,
the bar at the top shows **all values at the same point in time** - ping, loss,
jitter, download, upload and retransmissions at once. This is the view for
"what was going on at 20:14?". A panel can be expanded with ▸, dragging in a chart
zooms into the time span (with a matching resolution), "Reset zoom" goes back.

Grey hatched areas are periods **without measurements** - for example because the
service was stopped. They are not drawn as zero, because that would fake a measurement.
Under "Traffic per device" the lanes can be switched to a **shared scale**; without it
every lane has its own axis and the heights are not comparable.

---

## Root cause analysis - how it decides

Every rule is a separate, commented function in `backend/analysis/root_cause.py`.
The rule with the highest score wins. If a second explanation of a different category
is on par, the confidence is lowered.

| Observation | Result |
|---|---|
| Gateway ping high + internet ping high | LAN/Wi-Fi/router problem |
| Gateway normal + internet ping high (several targets) | WAN/ISP/bufferbloat |
| Gateway + internet normal, only one target abnormal | target server/routing |
| High upload of a device + ping/jitter high | upload saturation/bufferbloat (+ device) |
| High download + ping spike | download saturation/bufferbloat (+ device) |
| TCP retransmissions strongly increased | packet loss (direction is stated) |
| Several external targets with packet loss at once | WAN/ISP more likely than a single server |
| Only one external target affected | routing/target server more likely |
| Router + internet normal, game flow has gaps | game server/routing |
| DNS probes fail, ping normal | DNS disruption (Pi-hole or upstream) |
| All targets gone, router reachable/not reachable | internet outage or LAN connection loss |

Confidence: ≥ 80 points **High** ("likely cause"), ≥ 55 **Medium**
("possible cause"), otherwise **Low** ("temporally correlated"). A device is only named
as the cause if traffic per device was measured and the device dominates the
bottleneck (≥ 60 % of the traffic in the saturated direction).

**Line capacity:** for utilization in %, the capacity must be known. `auto`
uses the link rate of the FRITZ!Box (TR-064). If the booked rate is lower (throttling
at the provider), enter the booked rate under Setup → Measurement. That is more accurate.

### Recommendations, not just a diagnosis

Every category comes with a concrete action (`recommendation` in the analysis,
visible in the incident under "What helps now"). It also says whether you can fix it
yourself at all:

| `scope` | Meaning |
|---|---|
| `self` | in your own hands - device, router, Wi-Fi |
| `provider` | only the internet provider can change it (document and report) |
| `remote` | lies with the target server or the routing to it |
| `none` | the data is not enough for a reliable recommendation |

The direction matters, because the actions are opposite:

* **Upload saturation** - the queue sits in your own router. Prioritization in the
  FRITZ!Box really works here.
* **Download saturation** - the queue sits at the provider. Local prioritization
  cannot overtake packets that are already waiting there; the only thing that helps is
  slowing down the downloading device.

### Path measurement: where on the way?

The cause rules see whether one target or all of them suffer, and whether the router is
fine. Where the path breaks they cannot see. So when an incident starts (or a lag is
reported) the Pi measures the path to the worst targets of that moment, while the
problem is still on: every hop ten times, one round per second, probes 25 ms apart.

* Loss that begins at one hop and **lasts to the target** is located: "Losses begin at
  hop 3 (… usually your provider)".
* A hop that drops answers while later hops are fine is **not** the problem - routers
  answer traceroutes at low priority. The incident says so instead of blaming it.
* A hop that never answers is normal and says nothing.
* The segment is read from the address: RFC 1918 = your network, 100.64.0.0/10 and the
  first public hop = usually your provider, everything after = further along the path.

It needs the raw ICMP socket the service already has (`CAP_NET_RAW`). At most one
automatic measurement per target every 5 minutes, none at load guard level 2 or higher
(`traceroute` in the settings). The internet line page starts one by hand.

### Latency under load (bufferbloat)

`backend/analysis/bufferbloat.py` measures how much ping is added when the line is
full - separately per direction. Seconds are grouped by utilization and the median RTT
of the groups is compared:

* **quiet** ≤ 20 % utilization in both directions
* **under load** ≥ 70 % in one direction while the other stays < 40 %
* If both directions are full, the second is discarded - the cause could not be separated.

Each group needs at least 5 seconds, otherwise the result stays empty (no estimate).
Rating: < 30 ms "good", < 100 ms "moderate", above that "severe".

Visible in three places: as a card on the dashboard (1 h / 24 h / 7 d / 30 d), in the
incident for its analysis window and via `GET /api/bufferbloat?range=…`. So that the
history survives for weeks, maintenance writes a window into the `bufferbloat` table
every 10 minutes (9 numbers) - the 1 s raw values are only kept for one day.
Short spans are computed by the API directly from the per-second values (`source: live`),
longer ones from the stored windows (`source: windows`).

---

## Configuration

`/etc/network-lag-analyzer/config.yaml` (template: `config.example.yaml`). The most
important values can be changed in the UI; those changes live in the database and
override the file. "Setup" shows the effective values.

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

Environment variables: `NLA_CONFIG`, `NLA_DATA_DIR`, `NLA_PORT`, `NLA_DEV_MODE`, `NLA_LOG_LEVEL`.

---

## Database & backup

SQLite in WAL mode: `/var/lib/network-lag-analyzer/nla.sqlite3`.

| Table | Content |
|---|---|
| `measurements` | network state per bucket (`res` = 1/10/60 s) |
| `target_measurements` | RTT/loss per target |
| `ping_samples` | individual probes - **off by default** (`retention.ping_samples`) |
| `device_traffic` | bytes per device and bucket (key: `devices.id`) |
| `daily_stats` | daily summary, **exempt from retention** |
| `bufferbloat` | latency under load per 10-minute window |
| `network_flows` | finished flows (metadata only) |
| `devices` | devices incl. custom names |
| `events`, `incidents` | detected events, incidents incl. analysis (JSON) |
| `dns_queries` | DNS activity per client and minute (lag context) |
| `dns_clients`, `dns_client_hourly`, `dns_domain_daily`, `dns_domain_hourly`, `dns_service_minutes`, `dns_ip_history` | DNS usage counters ([docs/dns-usage.md](docs/dns-usage.md)) |
| `auth_sessions` | login sessions (SHA-256 of the token only) |
| `gaming_sessions` | sessions incl. summary |
| `pcap_files` | Deep Capture files |
| `settings` | overrides from the web UI |

Aggregation every minute: 1 s → 10 s → 1 min (peaks are kept via `rtt_max`).
Retention hourly according to the configuration.

### Backup and restore

The database contains the settings (including the FRITZ!Box password), the login account
(as a hash) and the DNS statistics - keep backups as private as the Pi itself. Pi-hole's
own data is not part of it (use Pi-hole's Teleporter for that).

**Automatic:** once a week at 03:00 (Setup → Backups, also "Back up now") the service
writes a checked copy of the database and of `config.yaml` to
`/var/lib/network-lag-analyzer/backups/` and keeps the two newest. They are on the same
SD card - copy one off the Pi now and then.

Manual backup, while the service runs (SQLite's online backup is consistent; needs the
`sqlite3` package):

```bash
sudo apt install -y sqlite3        # once
B=/var/lib/network-lag-analyzer/backup-$(date +%F)
sudo -u nla sqlite3 /var/lib/network-lag-analyzer/nla.sqlite3 ".backup $B.sqlite3"
sudo cp -p /etc/network-lag-analyzer/config.yaml $B.config.yaml
sudo -u nla sqlite3 "file:$B.sqlite3?mode=ro" "PRAGMA integrity_check"     # must print: ok
```

Copy the two files off the Pi (e.g. `scp`) if the backup should survive a broken SD card.

Restore:

```bash
sudo systemctl stop network-lag-analyzer
D=/var/lib/network-lag-analyzer
sudo rm -f $D/nla.sqlite3-wal $D/nla.sqlite3-shm
sudo install -o nla -g nla -m 0640 /path/to/backup.sqlite3 $D/nla.sqlite3
sudo install -o root -g nla -m 0640 /path/to/backup.config.yaml /etc/network-lag-analyzer/config.yaml
sudo systemctl start network-lag-analyzer
journalctl -u network-lag-analyzer -n 20      # "started", migrations if the backup is older
```

A backup from an older version is migrated on start. The DNS counters continue where the
backup ended: queries that Pi-hole still has are read again, nothing is counted twice.

### Storage format

Measurements are stored as **INTEGER in fixed units** (times in 1/100 ms, shares in
1/100 %, rates in bit/s). SQLite uses eight bytes for every REAL, two to four for small
integers. Conversion happens exclusively in `repository.py` (`enc`/`dec`); the rest of
the code keeps working in milliseconds. `device_traffic` references `devices.id` instead
of the MAC as text.

Measured on one day with four targets and 15 permanently active devices:

| Table | before | now |
|---|---|---|
| `device_traffic` | 63.3 MB | **26.7 MB** |
| `target_measurements` | 12.1 MB | **7.8 MB** |
| `measurements` | 9.3 MB | **5.6 MB** |
| `ping_samples` | 9.6 MB | **0** (off by default) |
| **Total per day** | **94.4 MB** | **40.1 MB** (−58 %) |

On an SD card every write saved counts; this turns about 34 GB per year into about 15 GB.

### Schema migrations

`backend/database/migrations.py` contains numbered steps. On start the stored
`schema_version` is read and every due step is applied in its own transaction -
before that the service creates a backup copy (`nla.sqlite3.pre-migration.bak`), as long
as there is enough free space. The result is shown in `/api/system` under `migration`
and in the journal. Existing data is converted, not discarded.

### Deep Capture: how much space it really needs

`max_files × file_size_mb` only limits the **running ring**. If a file belongs to an
incident, it is taken out of the ring so that it is not overwritten - and used to count
against no limit at all. With a dozen incidents per day and 90 days of retention this
adds up to tens of gigabytes, although the settings say "5 × 50 MB".

That is why there are three knobs, and only the first is a guarantee:

| Setting | Default | Effect |
|---|---|---|
| `max_total_mb` | 1024 | **hard upper limit for the whole directory**. When it is reached, the oldest incident capture is dropped |
| `protected_days` | 7 | incident captures are kept at most this long |
| `protect_auto` | `critical` | for what a capture is kept at all: `none` (only reported lag), `critical`, `all` |

The space used is shown under **Setup → Database** with its own bar - it does **not**
count towards the database size, because the files live next to it. There is also
"Clean up now".

**Disabling:** Setup → Storage & Deep Capture → uncheck "Deep Capture (PCAP ring
buffer)" → Save. This takes effect immediately, without restarting the service. The
running ring files are deleted at the next cleanup (hourly, or right away via "Clean up
now"); incident captures stay for `protected_days` so that they can be downloaded.

On start the capture adopts existing files into its ring. That matters because the
capture process restarts itself on errors: before, the files of the previous run were
then orphaned - in no ring, not protected, and therefore on disk forever.

### Managing space

**Setup → Database** shows the size per table, the oldest data point and the free
space on disk. There you can **delete data by date** - either "everything before a date"
or a time span, with a preview of the affected rows and a VACUUM afterwards. Device
names, targets, settings and the daily summary are always kept.

`retention.max_db_mb` is also an emergency brake: if the limit is exceeded, the service
deletes data by itself every hour - first raw ping data, then 1 s values, then flows and
10 s values, and only as far as needed to get some room again. The measure is the space
used, not the file size (deleted pages initially stay in the file).

**Backup** (consistent while running):

```bash
sudo -u nla sqlite3 /var/lib/network-lag-analyzer/nla.sqlite3 ".backup '/tmp/nla-backup.sqlite3'"
sudo cp /etc/network-lag-analyzer/config.yaml /tmp/
```

Restore: stop the service, copy the file back (`chown nla:nla`), start the service.

---

## Security

* Runs as user `nla`, **not as root**. Only extra capability: `CAP_NET_RAW`
  (ICMP, optionally AF_PACKET) via systemd `AmbientCapabilities`.
* systemd hardening: `ProtectSystem=strict`, `ProtectHome`, `NoNewPrivileges`,
  restricted address families; write access only to `/var/lib/network-lag-analyzer`.
* No shell calls; input is validated with Pydantic (IP addresses, host names,
  interface names via allowlist).
* CSRF protection for all writing requests (double-submit token), origin check.
* Security headers (CSP without inline scripts, `X-Frame-Options: DENY`, `nosniff`).
* Host names from the network are only ever rendered as text in the browser (no `innerHTML`).
* **Mandatory login** (username + password, scrypt). The account is created on the Pi
  only (`python -m backend.account set`, see Installation). Sessions are random 256-bit
  tokens in an HttpOnly, SameSite=Strict cookie; the database stores only their SHA-256.
  Logout ends the session on the server, a password change ends all other sessions.
  Sessions expire after 7 days and after 24 h without requests. Throttling: 5 failed
  attempts per address and 30 in total per 15 minutes. The cookie cannot be `Secure`
  because the UI is plain HTTP inside the LAN.
* The web UI listens on the **LAN address only** (`server.host: auto`); `0.0.0.0` would
  listen on every interface of the Pi.
* `/api/health` is the only data-free endpoint without login (for monitoring).
* The FRITZ!Box password is never returned by the API and only sent to the address it was
  entered for. `config.yaml` has mode 0640 (root:nla).
* Pi-hole database read-only. Payloads are never stored: the PCAP files keep 128 bytes per
  packet, headers only (`deep_capture.snaplen`).
* Meant for the LAN only - do **not** forward the port in the router. For remote access
  use a VPN (e.g. the FRITZ!Box's WireGuard VPN), then the page is reached like at home.
* Exports (CSV/XLSX) neutralize cells that a spreadsheet would evaluate as formulas.

Threat model and how to report vulnerabilities: [SECURITY.md](SECURITY.md).

---

## Performance & load guard

* Display delay: values appear ~3 s after the measurement (waiting for late ping
  replies). The buffered router capture does NOT delay the display: traffic values are
  filled in as soon as they arrive. Only the root cause analysis deliberately waits
  until the second is complete (`analysis_delay`).
* ICMP: one socket, no process starts; a few hundred bytes/s. The pings are spread
  evenly over the measuring interval so that they are not rate-limited anywhere as a
  burst (that would look like packet loss).
* Packet analysis in a separate process (`nice 5`), headers only, aggregation in
  memory, one batch insert into SQLite per second.
* Load guard (`backend/util/loadguard.py`):

| Level | Trigger | Action |
|---|---|---|
| 1 | CPU > 75 % (10 s) or capture backlog > 2 s | flow/retransmission analysis off |
| 2 | CPU > 90 %, RAM < 150 MB or backlog > 5 s | sampling 1:4, marked as "estimated" |
| 3 | level 2 for longer than 60 s | capture paused for 5 min |

The current level is shown as a banner in the UI.

---

## Troubleshooting

| Problem | Solution |
|---|---|
| Page not reachable | `systemctl status network-lag-analyzer`, `journalctl -u network-lag-analyzer -n 100`; port free? (`ss -ltnp \| grep 8088`) |
| "Ping measurement not possible" | The service must run via systemd (CAP_NET_RAW). Manually: `sudo setcap cap_net_raw+ep $(readlink -f /opt/network-lag-analyzer/venv/bin/python)` |
| Pi-hole "not readable" | `id nla` → group `pihole`? Permissions: `ls -l /etc/pihole/pihole-FTL.db` (the group must be able to read). Then restart the service |
| FRITZ!Box login failed | User/password; too many failed attempts block the login for a while (BlockTime) |
| Capture HTTP 403/404 | The user needs the "FRITZ!Box Settings" permission; check the interface name in the test |
| "Unknown capture format (magic …)" | Version ≥ 1.0.1 needed: supports pcap, pcap-modified (`a1b2cd34`) and pcapng |
| "Interface delivers link type … instead of Ethernet" | Wrong capture interface (e.g. WAN/PPP). Select the LAN bridge, usually `1-lan` |
| TR-064 401/timeout | Enable "Allow access for applications" |
| Device traffic shows up only briefly and disappears again | Fixed in 1.0.2/1.0.3: the FRITZ!Box delivers the capture in bursts (`capture_delay` in `/api/status`, often 3–9 s). The display stays live, traffic values are filled in later, the evaluation waits for complete data (`analysis_delay`) |
| "Game packet gap" events without a game | Fixed in 1.0.3: these events are only created during a running gaming session |
| Traffic per device stays empty | Setup → diagnosis; status "capture" in `/api/status`; router MAC detected? |
| Values "estimated" | Load guard active - Pi overloaded; disable Deep Capture, use a Pi 4/5 |
| Constant ~33 % (or 25/50 %) packet loss although `ping` runs cleanly | Fixed in 1.0.4: the pings went out as a burst milliseconds apart and were rate-limited along the way. Now they are spread over the interval (~175 ms apart with 4 targets) |
| A target never answers | Since 1.0.4 it is marked as "not answering" and excluded from loss/latency instead of faking a permanent loss. The loss rate per target is in `/api/status` under `targets` |
| "Test connection & capture" reports "No packets received" | Fixed in 1.0.4: the FRITZ!Box allows only ONE capture per interface. If the service is already running, the test now shows its live values instead of opening a second capture (which used to end the running one) |
| Download/upload on the dashboard "Not available" | Since 1.0.5: while the buffered capture is on its way, the total WAN rate from TR-064 fills the gap ("FRITZ!Box total (sum)"), the exact per-device values are filled in later. If it stays empty: check `capture.state` in `/api/status` and restart the service |
| "Latency under load" shows nothing | It needs quiet AND saturated phases plus a known line capacity. Without a phase above 70 % utilization the card stays empty - that is not an error |
| PCAP directory uses several gigabytes | Since 1.1.1, `deep_capture.max_total_mb` limits the whole directory (default 1 GB) and existing files are adopted on start; old leftovers disappear on the first start or via Setup → Database → "Clean up now" |
| Database gets too big / memory card full | Setup → Database: look at the size per table, delete by date, then "Shrink file". Permanently: set `retention.max_db_mb` and keep `retention.ping_samples` off |
| The first start after an update takes longer | Since 1.1.0 existing databases are converted to the compact format (once, with backup copy `nla.sqlite3.pre-migration.bak`). Progress is shown in the journal |
| A target permanently reports losses | Setup → diagnosis checks every target twice (spread out and as a burst). Losses only in the burst = the target throttles ICMP, not a network problem |
| The UI shows old behavior after an update | Since 1.0.4 frontend files are no longer cached; reload once with Ctrl+F5 |
| Many PING_SPIKE events without noticeable lag | Raise the thresholds in Setup; ICMP rate limiting of individual targets → choose other targets |
| The Pi itself measures over Wi-Fi | Use a LAN cable, otherwise you measure your own Wi-Fi link as well |
| Timestamps shifted | Check NTP on the Pi and the FRITZ!Box (`timedatectl`). The capture process compensates offsets automatically |

API overview: `http://PI:8088/api/docs`.

---

### Known limitations

* ICMP targets IPv4 only; IPv6 traffic is still counted per device in the capture (via the MAC).
* Traffic between two devices behind the same Deco does not pass through the FRITZ!Box and
  is not visible. For internet lag that does not matter.
* Game servers that block ICMP are only assessed via packet gaps in the game flow.
* Retransmissions are detected heuristically (like Wireshark: sequence ≤ already seen).
  Reordered packets count as well.
* DNS usage: lookups are not usage time. Queries older than Pi-hole's network table
  (or before the own IP history started) cannot always be attributed to a device and
  stay "IP only". Behind mesh access points the FRITZ!Box reports every device as
  cable-connected, so Wi-Fi vs. LAN is not available. Details: [docs/dns-usage.md](docs/dns-usage.md).

---

## License

[MIT](LICENSE). Includes [uPlot](https://github.com/leeoniya/uPlot) (MIT, see
`frontend/vendor/uPlot.LICENSE`).
