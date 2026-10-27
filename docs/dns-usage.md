# DNS usage per device - method and limits

The page **DNS usage** shows, per device, which names it looked up through Pi-hole:
how many queries, how many were blocked, which domains, which categories, and an
*estimate* of activity phases per service. This document describes where the
numbers come from, how they are computed and what they cannot tell.

**DNS lookups are not usage time and not data volume.** A lookup says that an app or
browser on a device asked for a name. It does not say that a person looked at it, for
how long, or how much data followed.

---

## Data sources

| Source | Access | Used for |
|---|---|---|
| Pi-hole query log `/etc/pihole/pihole-FTL.db` | read-only (`mode=ro`, group `pihole`) | every DNS query: time, client IP, name, status |
| Pi-hole network table (same file) | read-only | IP → MAC and host name, as Pi-hole knows them *now* |
| Pi-hole DHCP leases `/etc/pihole/dhcp.leases` | read-only | host names of the current leases (only if Pi-hole is the DHCP server) |
| FRITZ!Box host list (TR-064) | read-only, optional | second, independent view of the devices |
| Own database `/var/lib/network-lag-analyzer/nla.sqlite3` | read/write | counters, IP history, aliases, settings |

Pi-hole is never modified. The service runs as user `nla`, which is a member of the
group `pihole` for read access only. Never use `sudo sqlite3` on Pi-hole's files (it
leaves root-owned `-wal`/`-shm` files behind and locks FTL out of its own database).

Pi-hole's official API (v6) is not used for the statistics. Large ranges through the
API are computed by FTL itself and compete with name resolution; the read-only
database access reads directly and is throttled by our own load guard.

---

## From query to device

Pi-hole logs the **client IP** only. The device behind it:

1. **Own IP history.** From the first start on, the service records which MAC held
   which IP when (`dns_ip_history`). A query is attributed to the MAC that held the IP
   at that time.
2. **Before the history starts** (the backfill of older queries): FTL's network table,
   which only knows the *current* owner of an IP. A query older than the device that
   holds the IP today stays **"IP only"** - naming today's owner would be made up.
3. **No MAC known** (IPv6 without neighbour entry, clients behind another router) →
   "IP only". **The Pi itself** (127.0.0.1 and its own addresses) is counted
   separately and left out of network totals.

Retries and duplicate in-flight queries (FTL status 12, 13, 14) are not counted as
queries; they are shown as "retries".

`python -m backend.dns_mapping_report --hours 24` prints how much of the log can be
attributed to devices.

### Client identification (FRITZ!Box vs Pi-hole)

The DNS overview compares both views of the network, per device: consistent, IP
differs, IP conflict, FRITZ!Box only, Pi-hole only. Most important: **devices that are
active in the FRITZ!Box but never asked Pi-hole** - they resolve names elsewhere and
are missing from the statistics. Nothing is merged or guessed from this comparison.

If Pi-hole sees almost every query from one address (a router forwarding all DNS),
per-device statistics are impossible; the page says so. Fix: hand out Pi-hole as DNS
server via DHCP.

---

## Storage

Single queries are **not** copied - Pi-hole keeps them (91 days by default). The
service keeps only compact counters:

| Table | Content | Kept (default) | Size on the test Pi |
|---|---|---|---|
| `dns_client_hourly` | queries/blocked/retries per device and hour | 400 days | ~11 KB/day |
| `dns_domain_daily` | queries per device, local day and domain; completed days keep the 300 busiest domains, the rest is summed up | 180 days | ~110 KB/day |
| `dns_domain_hourly` | the same per hour, for exact short ranges | 48 hours | – |
| `dns_service_minutes` | minutes with lookups per device and service (activity phases) | 31 days | ~250 KB/day |
| `dns_ip_history`, `dns_clients`, `dns_domains`, `dns_services` | lookups and history | with the counters | small |

Reading the log is incremental (`id > last_id`). The position is written in the same
transaction as the counters: a crash or power cut neither loses nor double-counts
queries. On the first start the last 91 days are read in small steps, only while the
load guard is at level 0 (on the test Pi: 10 million queries in about 20 minutes).

Settings: `dns_usage.*` and `retention.dns_*` (see `config.example.yaml`).

---

## Categories

Rule based and offline. Layers, highest priority first:

1. **manual** - rules entered on the page *Category rules*
2. **local** - `domain_categories.local.yaml` in the data directory (same format)
3. **builtin** - `backend/data/domain_categories.yaml`, ~400 domains of known services
4. **ut1** - optional import of the UT1 lists of the Université Toulouse Capitole
   (CC BY-SA 4.0, download them yourself; the commands are in the header of
   `backend/dns_category_import.py`). Mapped: adult content, gambling, dating,
   malware & phishing, VPN / proxy / DNS-over-HTTPS servers, and the lists that match
   existing categories (social networks, games, shopping, press, ...). The 5 million
   names are kept as a hash index on disk (8 bytes per name, ~40 MB), not in memory;
   every match says "UT1 list" and has confidence "medium" - a list entry is a judgement
   by its maintainers, not a fact about the domain.

The most specific rule wins (`youtubei.googleapis.com` beats `googleapis.com`); for the
same name the higher layer wins. Every domain shows the rule, the layer and the
confidence. Categories that are never someone's use are kept apart:

* **Shared infrastructure** (CDNs and cloud platforms) names the provider - "Amazon
  CloudFront (CDN)", "Akamai", "Google", "Apple", "Microsoft" - with low confidence and
  never a service: it says who delivered something, not which service was behind it.
  On the test Pi CloudFront alone was 17 % of all lookups.
* **Network & connectivity checks**: captive portal detection (Amazon devices: 9 % of all
  lookups on the test Pi), time servers, reverse lookups, names inside the home network.
* **Ads, tracking & telemetry** includes device and app telemetry, crash reports and ad SDKs.
* **Not categorized yet** ("unknown") means no rule matched - not that a name is harmless.

Click any domain for its details: what it is and what its category means, the rule and
the source behind it, how sure that rule is, which devices looked it up, and how Pi-hole
answered it in the last 24 hours (cache, forwarded, blocked by a blocklist, a regex or
your denylist). From there a rule can be set for the name or its owner. The overview
lists the busiest names without a rule, bundled per owner, and explains the terms. SDK domains such as
`graph.facebook.com` count as ads & tracking, not as Facebook use. Category shares use
each domain's primary category, so they add up to 100 %.

---

## Activity phases (estimated)

Per device and service (client detail page):

1. Minutes in which the device looked up names of the service, **blocked lookups
   excluded** (a blocked service cannot be in use).
2. Minutes belong to the same phase while the pause is at most the **gap**: 5 minutes
   by default, selectable on the page, longer for some services in the rules (video
   10 min, game platforms 15 min).
3. A phase lasts from its first to its last minute. **Pauses are never counted.**
4. The estimate is the sum of the phases. Resolution: one minute.

Confidence is **at most "medium"**. Instead of a number the page shows
**"Not reliably determinable"** for background or shared services, too few lookups,
only isolated lookups, or lookups in 18 or more hours of an average day (a TV in
standby looked like "10 h of streaming a day" before this rule existed). Messengers,
cloud sync, activity between 01:00 and 05:00, many active hours per day and mostly
single-minute phases lower the confidence to "low".

After a change of the category rules, the activity minutes are rebuilt from Pi-hole's
log in the background (about 3 minutes on the test Pi); the page says so meanwhile.

### Why this can be wrong

* **Background services** refresh feeds, sync and keep push connections while nobody
  uses the device.
* **DNS caches**: a device asks again only when the cached answer expires (often after
  1-5 minutes), so a long session can look like several short phases - or like none.
* **Prefetching**: browsers and apps resolve names in advance.
* **HTTPS**: one lookup can serve a connection that stays open for a long time.
* **Encrypted DNS** (DNS over HTTPS/TLS in browsers, iCloud Private Relay, VPNs)
  bypasses Pi-hole completely.
* **Shared infrastructure**: lookups to CDNs cannot be attributed to a service.

A more precise source is planned: the server name from the TLS handshake (SNI) of the
FRITZ!Box capture, which shows connections instead of lookups (see "Open / next" in
[DEVELOPMENT.md](DEVELOPMENT.md)). QUIC/HTTP3 would still be missing from it.

---

## Export

CSV (one table; German Excel by default: UTF-8 with BOM, semicolon, decimal comma) and
XLSX (one sheet per table) from the overview and the client page, always with the
range and filters on screen. Every file starts with export time, range, filters, data
source and method. Text cells starting with `=`, `+`, `-`, `@`, tab or CR get a leading
apostrophe (formula injection). Files are created on request and streamed; nothing is
stored on the Pi.

---

## Privacy

These statistics show who in the household looked up what, and when. If other people
use the network, they should know that it is recorded. The page is behind a mandatory
login; reach it from outside only through a VPN, never through a port forwarding.
