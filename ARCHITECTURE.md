# Network Lag Analyzer - Architecture

This document describes the concrete technical design. Goal: answer the question
**"Why did I have lag at exactly this moment?"** without faking data that the
Raspberry Pi technically cannot see.

## 1. Starting point (phase 1/2 - analysis)

Target environment:

```
Internet ── FRITZ!Box 7690 (router, DHCP, 192.168.178.1)
               ├── LAN ── TP-Link Deco XE75 (access point mode, LAN backhaul)
               │             ├── gaming PC (LAN on the Deco)
               │             └── Wi-Fi clients (iPhone, smart TV …)
               ├── Wi-Fi clients of the FRITZ!Box
               └── Raspberry Pi (Pi-hole, DNS)  ← this application
```

Consequences:

* The Pi is **not in the data path**. It only sees its own traffic, broadcasts
  and DNS queries (Pi-hole). Promiscuous mode on the Pi's port does not help,
  because the switch only delivers frames addressed to the Pi's MAC.
* Pi-hole delivers **DNS metadata**, never bandwidth. DNS queries are used
  exclusively to map IP → host name and as an activity hint, never as a
  traffic value.
* Since the Deco bridges in AP mode, there is **no double NAT**. All clients
  have their own IPs/MACs in the FRITZ!Box network, and their internet traffic
  passes through the FRITZ!Box LAN bridge.

Since the Pi in the target environment was not reachable during development, the
**setup wizard** (section 9) checks the actual environment automatically on first start.

## 2. Data sources and visibility

| Data source | Delivers | Prerequisite | Default |
|---|---|---|---|
| ICMP prober (own socket) | RTT, loss, jitter to gateway + internet targets | CAP_NET_RAW or `ping_group_range` | on |
| DNS prober | DNS response time/failure (Pi-hole + upstream) | – | on |
| FRITZ!Box TR-064 | total WAN rate ↑/↓, line capacity, host list (IP/MAC/name) | FRITZ!Box user, TR-064 enabled | on when credentials are set |
| **FRITZ!Box packet capture** | traffic per device, flows, TCP retransmissions, UDP game flows | user with the "FRITZ!Box Settings" permission | on when credentials are set |
| Local AF_PACKET capture | as above | Pi is the gateway or sits on a mirror port | off |
| Pi-hole FTL database | host names, MAC, vendor, DNS queries per client | read access (group `pihole`) | automatic |
| `/proc/net/arp` | IP ↔ MAC | – | on |
| psutil | CPU/RAM/temperature of the Pi | – | on |

### Why the FRITZ!Box packet capture?

Alternatives considered:

* **libpcap/tcpdump/eBPF/nftables/conntrack on the Pi**: only see traffic that
  passes the Pi. Useless as long as the Pi is not the gateway.
* **Pi as gateway**: full visibility, but every packet path then depends on the
  Pi. A Pi failure takes down the internet and adds latency - unsuitable for a
  lag diagnosis tool.
* **Managed switch with port mirroring**: very good, but needs new hardware
  (not wanted by the user at the moment; supported as source `local`).
* **FRITZ!Box TR-064**: only delivers total WAN rates, not per device.
* **FRITZ!Box capture (`/cgi-bin/capture_notimeout`)**: the FRITZ!Box streams a
  libpcap data stream of its LAN bridge over HTTP (classic pcap, "modified pcap"
  with magic `a1b2cd34` and 24-byte record headers, or pcapng - the parser
  recognizes all three). With `snaplen=128` only headers are transferred (no
  payload). From it the Pi counts bytes/packets per MAC and flow metadata.
  **No extra hardware, full visibility of all clients' internet traffic.**

Chosen: **FRITZ!Box capture as the primary source**, TR-064 as the total-rate
fallback, AF_PACKET as the alternative for mirror/gateway setups.

Cost of the capture:

* Per packet ~16 bytes of pcap header + at most 128 bytes of header data. At 10,000
  packets/s that is ≈ 1.4 MB/s of LAN traffic from the router to the Pi - negligible
  on a gigabit LAN.
* The capture stream itself passes through the LAN bridge and is captured too
  (feedback ≈ 1/10, converges). This connection is **filtered out of all
  statistics** via its 4-tuple.
* The FRITZ!Box CPU gets additional load. Setup shows this; the capture can be
  switched off.
* Limit: Python parses roughly 30–50 kpps on a Pi 4. That is not enough for a fully
  utilized gigabit line; the load guard (section 8) then switches to sampling with
  extrapolation and **marks the values as estimated**.

### Mapping packets to devices

On the LAN bridge every packet has a source and destination MAC:

* The **router MAC** is determined from the ARP table (gateway IP) and is also
  learned (the MAC that sends packets with public source IPs).
* `src_mac = client, dst_mac = router, destination IP not local` → **upload** of the client.
* `src_mac = router, dst_mac = client, source IP not local` → **download** of the client.
* Everything else → LAN-internal (counted separately, not as WAN load).

The key is the **MAC**, so the mapping also works for IPv6 (privacy addresses).
The IPv4 shown is learned from ARP/FRITZ!Box/Pi-hole or from observed packets.

## 3. Process and module structure

```
                ┌───────────────────────────── main process (asyncio) ─────────────────────────────┐
                │ collectors/ping.py   ICMP prober (1 socket, SO_TIMESTAMPNS)                        │
                │ collectors/dns.py    DNS prober                                                    │
                │ collectors/fritzbox.py  TR-064 (WAN rates, link rate, host list)                   │
                │ collectors/pihole.py  FTL DB read-only (host names, DNS per client)               │
                │ collectors/devices.py device table (ARP + FRITZ!Box + Pi-hole + capture)           │
                │ analysis/metrics.py   per-second assembler, ring buffer (1 h live)                │
                │ analysis/events.py    event detection (hysteresis, baseline)                       │
                │ analysis/correlation.py incidents, lag report, timeline windows                    │
                │ analysis/root_cause.py  documented cause rules + recommendations                   │
                │ analysis/bufferbloat.py latency under load (per direction)                        │
                │ analysis/gaming.py    gaming sessions, server detection                            │
                │ analysis/daily.py     daily summary (long-term)                                   │
                │ database/migrations.py numbered schema steps + backup copy                        │
                │ database/*            SQLite WAL, batch writer, aggregation, retention             │
                │ api/*                 FastAPI REST + server-sent events                            │
                └───────────────▲──────────────────────────────────────────────────────────────────┘
                                │ multiprocessing.Queue (per-second aggregates, flows, status)
                ┌───────────────┴────────── capture process (collectors/traffic.py) ──────────────┐
                │ source: FRITZ!Box HTTP stream | AF_PACKET | none                                │
                │ collectors/pcapstream.py  incremental pcap/pcapng parser                         │
                │ collectors/flows.py       packet decoding, bins per MAC, flow table,             │
                │                           TCP retransmission heuristic, game flow gaps           │
                │ PCAP ring buffer (optional, Deep Capture)                                        │
                └──────────────────────────────────────────────────────────────────────────────────┘
```

The CPU-intensive packet parsing runs **in a separate process** so that the GIL does
not distort the timestamps of the ICMP measurements in the main process and a second
CPU core is used. Only per-second aggregates are transferred between the processes,
no packets.

## 4. Measuring methods

### ICMP

* A single socket for all targets (`SOCK_DGRAM/IPPROTO_ICMP`, fallback
  `SOCK_RAW` with CAP_NET_RAW). No process start per ping.
* Receive time via kernel timestamps (`SO_TIMESTAMPNS`) so that event loop
  delays do not distort the RTT.
* Default: 1 probe/s per target; 4 probes/s in Gaming Mode. The probes of one
  cycle are spread evenly over the interval (~175 ms apart with 4 targets) -
  an ICMP burst would be rate-limited by routers, providers or target servers and
  look like packet loss.
* A target that does not answer for `unreachable_after` seconds in a row while
  other targets keep answering counts as "not answering" and is no longer included
  in loss/latency (visible in `/api/status`). If all targets fail, it remains a
  real outage.
* Timeout 1.5 s → counts as lost. Second *T* is finalized at *T + 1 + timeout*,
  so the dashboard lags ~2.5 s behind (deliberately, so that loss is counted
  correctly).

### Dealing with the buffered router stream

The FRITZ!Box does not deliver the capture continuously, but in bursts
(several seconds at a time when there is little traffic). If a second were
finalized strictly on schedule, its traffic data would be missing - the dashboard
would flicker. Therefore:

* The main process measures the actual delivery delay of the per-second bins
  (90th percentile of the last 60) and separates two paths based on it:
  **display** (at most 3 s wait so that ping/jitter/loss stay live) and
  **evaluation** (the event engine and incidents only get a second once its
  traffic data is there, at the latest after `analysis_delay` = buffer time + 3 s).
* If a bin still arrives too late, the affected second is patched in the ring
  buffer and in the database, and the UI is updated via a `tick_patch` event.
* If the capture stops entirely, the evaluation still finalizes after at most
  `traffic_grace` seconds - honestly without traffic values.
* For the total rates TR-064 bridges the wait (source `tr064`, every 2 s,
  without per-device mapping). When the capture arrives, it replaces these values.
  The root cause analysis does NOT accept TR-064 as complete, because it lacks
  the mapping to devices.

### Metrics per second

* **Internet RTT**: median of the internet targets (robust against a single
  slow target), plus min/max.
* **Jitter**: mean absolute difference of consecutive RTTs per target
  (RFC 3550 idea, unsmoothed) over 10 s, median across the targets.
* **Packet loss**: lost/sent probes of the internet targets; windows
  5 s/10 s/30 s/60 s/5 min from the ring buffer.
* **Throughput**: from the capture (per device, exact) or TR-064
  (total only). The source is always shown.
* **TCP retransmissions**: a segment with payload whose sequence end ≤ the maximum
  already seen in the same direction (Wireshark-like heuristic), separated into
  download and upload direction.

## 5. Event detection

Jumps of the system clock (NTP after boot) are detected: if the wall clock deviates
from the monotonic clock by more than two seconds, started seconds are discarded and
the time base locks in again - an honest gap is better than measurements under a
wrong timestamp. Detected jumps are listed in `/api/system`.

Every finalized second passes through the detectors in `analysis/events.py`.
Baseline = rolling median of the last 5 min (without spike seconds).
Every detector has a start and an end condition (hysteresis); events
have a start, end, peak value, baseline and details.

Event types: `PING_SPIKE, PACKET_LOSS, HIGH_JITTER, HIGH_UPLOAD,
HIGH_DOWNLOAD, TCP_RETRANSMISSION_SPIKE, CONNECTION_DROP, DNS_FAILURE,
GATEWAY_LATENCY, INTERNET_LATENCY, GAME_FLOW_GAP`.

## 6. Incidents and root cause analysis

* Lag-relevant events open an **incident**; it closes 2 minutes after the last lag
  event (at most 30 minutes long), so one loss episode stays one incident. Then the
  window [start − 30 s, end + 5 s] is analyzed. A problem of one external target while
  the line is fine, and an unexplained blip under 5 s, are kept as events only
  (`correlation.dismiss_reason`).
* The **"I JUST HAD LAG" button** immediately creates an incident for the last
  10 s/30 s/60 s/5 min and returns a timeline of the findings.
* `analysis/root_cause.py` contains every rule as a separate, documented function.
  Every rule returns a category, score, list of evidence and possibly a device.
  The confidence is derived from the evidence:

| Confidence | Wording | Meaning |
|---|---|---|
| low | "temporally correlated" | happened at the same time, nothing more |
| medium | "possible cause" | plausible, but evidence incomplete |
| high | "likely cause" | order, duration and exclusion criteria fit |

If a data source is missing (e.g. no traffic per device), the analysis says so
explicitly and names no device.

* Every category comes with a **recommendation** (`RECOMMENDATIONS` in
  `root_cause.py`) with a `scope`: `self` (fixable yourself), `provider`
  (only the provider can change it), `remote` (target server/routing) or `none`.
  Upload and download saturation deliberately get opposite advice:
  for the upload the queue sits in your own router (prioritization works),
  for the download at the provider (only throttling the downloading device works).
* `analysis/bufferbloat.py` measures the **latency under load** per direction:
  median RTT of quiet seconds (≤ 20 % utilization) against the median RTT of
  saturated seconds (≥ 70 % in one direction, < 40 % in the other).
  At least 5 seconds per group, otherwise no result. Included in the incident
  (`metrics.latency_under_load`) and returned as a time-span metric via
  `/api/bufferbloat`.

## 7. Data storage (SQLite, WAL)

Tables: `settings, targets, ping_samples, measurements, target_measurements,
devices, device_traffic, network_flows, events, incidents, dns_queries,
gaming_sessions, pcap_files, bufferbloat, daily_stats`.

* `measurements`, `target_measurements`, `device_traffic` have a column
  `res` (1, 10, 60 s). An aggregation job condenses 1 s → 10 s → 60 s every minute.
* Retention (configurable): 1 s values 24 h, 10 s values 7 days, 60 s values
  30 days, flows 7 days, events/incidents 90 days.
* Measurements are stored as INTEGER in fixed units (1/100 ms, 1/100 %, bit/s);
  conversion only happens in `repository.py` (`enc`/`dec`). `device_traffic` uses
  `devices.id` instead of the MAC as text. Together about 58 % less write volume -
  on an SD card the decisive point.
* Schema changes go through numbered steps in `migrations.py`. On start
  `schema_version` is read, every due step is applied in its own transaction, and a
  backup copy is made beforehand (if there is enough space).
* `daily_stats` keeps about 200 bytes per day (percentiles, loss, peaks,
  bufferbloat, incidents per category) and is exempt from retention.
* `retention.max_db_mb` is an emergency brake: if the USED space exceeds the limit,
  data is deleted step by step (raw data → 1 s → flows → 10 s) and VACUUM runs
  afterwards. Free pages do not count, otherwise the deletion would run forever.
* Deep Capture has a **total budget** (`max_total_mb`), not just `max_files`.
  Protected incident captures live outside the ring and get the rest of the budget;
  when it is full, the oldest one is dropped. On start the ring adopts the existing
  files - without that, the capture process's files would be left orphaned after
  every restart.
* `bufferbloat` stores nine numbers per 10-minute window (idle median, median and
  peak per direction, second counts). This keeps the history of the latency under
  load visible over weeks, although the 1 s values are deleted after one day.
  Retention as for events (90 days).
* Writing happens exclusively via a batch writer (one thread, one transaction per
  second). Reading via separate connections.
* Live charts and the lag analysis read primarily from the in-memory ring buffer
  (1 h), historical ranges from the database.

## 8. Resource protection (load guard)

`util/loadguard.py` monitors system CPU, available RAM, temperature and the
backlog of the capture process:

| Level | Trigger (default) | Action |
|---|---|---|
| 0 | normal | full analysis |
| 1 | CPU > 75 % (10 s) or backlog > 2 s | no flow/retransmission analysis, only bytes per device |
| 2 | CPU > 90 % or RAM < 150 MB or backlog > 5 s | sampling 1:4, extrapolated, marked as "estimated" |
| 3 | level 2 sustained for 60 s | capture paused for 5 min, UI shows "Not available (load)" |

Pi-hole takes precedence: the service runs with `Nice=10`, `CPUWeight=50`,
`MemoryMax=350M`.

## 9. Setup wizard

Checks interfaces, IP, default gateway, Pi-hole, whether the Pi is the gateway,
IP forwarding, visible clients, promiscuous mode, FRITZ!Box login,
TR-064 and capture - and shows an honest capability matrix
("Traffic all LAN devices: ✗ - Pi not in the data path …").

## 10. Security

* The service runs as user `nla`, not root. `CAP_NET_RAW` (ICMP,
  AF_PACKET) via systemd `AmbientCapabilities`.
* No shell calls; no user input reaches a subprocess.
* Pydantic validation of all input, IP addresses via `ipaddress`.
* Optional login (scrypt hash, HttpOnly session cookie, throttled after failed
  attempts). CSRF protection for all writing requests via a double-submit token
  (`X-CSRF-Token`).
* FRITZ!Box password in `/etc/network-lag-analyzer/config.yaml` (0640,
  root:nla) or DB setting; never returned by the API and only sent to the address
  it was entered for.
* Pi-hole is only opened **read-only** (`mode=ro`).

Threat model: [SECURITY.md](SECURITY.md).

## 11. No fake data

Every measurement is either measured or `null`. The frontend shows `null`
as **"Not available"** with a reason. Synthetic data only exists with
`dev_mode: true`, then with a permanent "DEMO MODE" banner.
