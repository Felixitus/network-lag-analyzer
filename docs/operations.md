# Operations: data, backups, load, troubleshooting

Back to the [README](../README.md).

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
| `dns_clients`, `dns_client_hourly`, `dns_domain_daily`, `dns_domain_hourly`, `dns_service_minutes`, `dns_ip_history` | DNS usage counters ([docs/dns-usage.md](dns-usage.md)) |
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
  cable-connected, so Wi-Fi vs. LAN is not available. Details: [docs/dns-usage.md](dns-usage.md).
