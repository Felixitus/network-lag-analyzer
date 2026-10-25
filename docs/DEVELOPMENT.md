# Development notes

Local network diagnostics on a Raspberry Pi running Pi-hole. Answers one question:
**"Why did I have lag or packet loss at exactly this moment?"**

Measures ICMP to the router and internet targets (1/s, 4/s in Gaming Mode), traffic per
device via the FRITZ!Box capture, DNS via Pi-hole. Detects events, groups them into
incidents and names a likely cause using documented rules.

Language: **English** - UI, comments, commit messages, log messages, tests, docs.

## Commands

```bash
python3 -m pytest tests -q                    # all tests (currently 306, must be green)
NLA_DEV_MODE=1 NLA_DATA_DIR=/tmp/nla NLA_CONFIG=/nonexistent.yaml \
  NLA_PORT=8088 python3 -m backend.main       # dev mode with simulated data
sudo ./install.sh                             # installation (systemd, user nla)
sudo ./install.sh --uninstall
```

Web UI: `http://<pi>:8088`. Service: `network-lag-analyzer`.

## Hard rules

These come before everything else. They are the reason you can trust the numbers.

1. **No made-up data.** Whatever could not be measured is `None` and is shown as
   "Not available" with a reason - never 0, never estimated, never interpolated.
   This applies visually too: periods without measurements are hatched in charts,
   not drawn as a zero line.
2. **Simulated data only in dev mode** (`dev_mode: true`), then with a permanent
   DEMO banner. `backend/simulation.py` is never imported in production.
3. **DNS is not a measure of bandwidth.** DNS queries serve to map IP→device and as
   context, never as a traffic or usage measure.
4. **Do not fake causality.** Simultaneity alone yields at most confidence "low"
   ("temporally correlated"). A device is only named if traffic per device was
   actually measured.
5. **Pi-hole is not modified.** Read-only access to the FTL database.
6. **The Pi must not be overloaded.** The load guard (levels 0–3) throttles when
   needed; Pi-hole takes precedence.

## Layout

```
backend/
  core.py                 orchestrator: collectors, per-second pipeline, incidents, maintenance
  config.py               Pydantic models, EDITABLE_SECTIONS, CONFIG_ALIASES
  collectors/
    ping.py               ICMP, one socket, kernel timestamps, probes spread over the interval
    traffic.py            capture process (separate process!), PcapRing
    pcapstream.py         pcap / pcap-modified / pcapng parser
    flows.py              packet analysis, flows, retransmissions
    fritzbox.py           TR-064 + capture_notimeout
    pihole.py             FTL DB read-only (lag context per minute)
    ftl_queries.py        FTL query log read-only, v5/v6 schema, time ranges on the index only
    devices.py            device registry, assigns the numeric IDs itself
  analysis/
    metrics.py            per-second assembler, ring buffer (1 h)
    events.py             event detection with hysteresis
    correlation.py        incidents, lag report, timeline
    root_cause.py         cause rules + recommendations
    bufferbloat.py        latency under load per direction
    daily.py              daily summary (long-term)
    dns_clients.py        DNS query → device attribution (mac / ip / local) + own IP history
    dns_ingest.py         FTL log → hourly/daily counters per device, crash-safe position
    dns_usage.py          read side: totals, domain lists, category breakdowns
    categories.py         domain → service → category rules (layers: manual, local, builtin, ut1)
    activity.py           estimated activity phases per service (from dns_service_minutes)
    client_match.py       FRITZ!Box vs Pi-hole: can the per-device DNS numbers be trusted?
    overview.py           status lights and the timeline of the overview page, restart log
    line.py               internet line: FRITZ!Box event log, outages from our pings, error deltas
  data/domain_categories.yaml   shipped category rules (hand-maintained)
  database/
    models.py             schema + SCHEMA_VERSION
    migrations.py         numbered steps, backup copy before rebuilding
    repository.py         writer thread, enc/dec, aggregation, retention
  api/                    FastAPI + SSE (dns.py: DNS usage per device, dns_export.py: CSV/XLSX)
    security.py           mandatory login, server-side sessions, CSRF, headers
    auth.py               login/logout/password change, /api/health
  account.py              CLI: create the login account on the Pi (never via the web UI)
  util/tabular.py         CSV + XLSX writer without dependencies, formula-injection safe
frontend/                 vanilla ES modules, uPlot vendored, no build step (pages/dns.js: DNS usage,
                          overview.js start page, line.js)
```

## Conventions

* **Comments explain the why**, not the what. Especially where a solution is not
  obvious - every such comment stands for a bug that once cost hours.
* **Measurements are stored as INTEGER in fixed units** in the database: times in
  1/100 ms, shares in 1/100 %, rates in bit/s. Conversion happens **exclusively**
  in `repository.py` (`enc` / `dec` / `decode_row`). Everywhere else it is
  milliseconds and percent as floats.
* **Every schema change needs a migration step** in `migrations.py` and a bumped
  `SCHEMA_VERSION`. `CREATE TABLE IF NOT EXISTS` is only enough for new tables.
* **Test names describe the behavior**, not the implementation. Every fixed bug
  gets a test that pins it down.
* **Demo and test data use the documentation ranges** (RFC 5737: `192.0.2.x`,
  `203.0.113.x`) and locally administered MACs (`02:00:00:…`) - never anything that
  looks like a real home network.
* **Git workflow** is described in [CONTRIBUTING.md](../CONTRIBUTING.md): feature branches,
  PR with green CI, squash merge, changelog entry.

## Traps that have already snapped shut

Do not walk into them again - the tests for them are there on purpose.

* **The FRITZ!Box delivers "modified pcap"** (magic `a1b2cd34`, 24-byte record headers),
  not classic pcap. The parser supports both plus pcapng.
* **The capture arrives in bursts** (up to ~13 s delay). Hence separated:
  `traffic_grace` for the display (≤ 3 s), `analysis_delay` for the evaluation,
  plus patching in late bins (`_patch_late_traffic`).
* **ICMP targets throttle.** Pings go out spread over the interval (~175 ms
  apart), not as a burst. As a burst they produced a seemingly constant 33 % "loss".
* **PCAP budget**: `max_files × file_size_mb` only limits the running ring.
  Incident captures live outside of it and need `max_total_mb`. Without it the
  directory grew to 40 GB in practice. The ring adopts the existing files on
  start, otherwise files are left orphaned after process restarts.
* **`sudo sqlite3` on Pi-hole databases** leaves root-owned `-wal`/`-shm`
  files, after which FTL can no longer access its database. Always stop FTL and
  `chown pihole:pihole` afterwards.
* **The system clock jumps** (Pi without RTC, NTP after boot). Jumps > 2 s are detected,
  started seconds are discarded - an honest gap is better than wrong timestamps.
* **FRITZ!OS 8 dropped TR-064 actions** (`GetAddonInfos`: HTTP 500, UPnP error 401
  "Invalid Action"). Every FRITZ!Box request needs a fallback or must fail on its own -
  one missing action once took the host list down with it.
* **The stored FRITZ!Box password is bound to its address.** Changing the FRITZ!Box
  host or the gateway without re-entering the password is rejected; otherwise any
  LAN device could redirect the login to its own server.

## Open / next

* **Read SNI from the TLS ClientHello** instead of guessing names from DNS. Needed:
  `snaplen` from 128 to ~600 (the upper limit in `config.py` is still 256),
  a parser in the capture process, result into `network_flows.dns_name`. After that:
  build sessions from flows (gap > 2 min = new session) for "when, how long,
  how often, how much" per service.
* QUIC/HTTP3 (UDP 443) is not covered by the SNI approach - either decrypt Initial
  packets (RFC 9001) or block UDP 443 and force the TCP fallback.

## Notes

* The capture runs as a **separate process** (`multiprocessing`, spawn) so that
  packet parsing does not disturb the ICMP timestamps. Communication only via queues.
* Settings from the UI live in the database and **override `config.yaml`**. If you
  change something in the file and it has no effect, it was set in the UI.
* The frontend deliberately has no build step: change files, Ctrl+F5, done.
