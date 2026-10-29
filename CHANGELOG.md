# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versions follow [SemVer](https://semver.org/).

## [Unreleased]

### Added
- **A backup before every update**: `install.sh` writes a checked copy of the database and of
  `config.yaml` (`backups/backup-pre-update-*`, the two newest are kept) before it restarts the
  service, and stops without a restart if the copy fails. `--no-backup` skips it. The copies
  are listed under Setup → Backups next to the weekly ones.

### Fixed
- A backup that failed halfway no longer leaves an empty copy behind that looked like a backup.

### Project
- Dependabot keeps the pinned CI actions up to date (one grouped PR a month).

## [1.4.0] - 2026-10-29

Path measurement at incidents, QUIC server names, a weekly report, HTML e-mails, the
version and update command in the web UI, and calmer, shorter pages.

### Added
- **Version and updates in view**: the installed version stands at the bottom of every page
  and turns into a hint when a newer release is out. The Pi page has a Software card with the
  last check, a "Check for updates now" button and the exact update command for this Pi
  (the folder `install.sh` ran from) with a copy button; the update banner shows it too.
- **QUIC connections get their server name too** (HTTP/3, most of YouTube and Google):
  the capture decrypts the client's Initial packets with the keys RFC 9001 derives from
  the packet itself (v1 and v2), joins the ClientHello fragments that browsers shuffle
  over several packets, and reads the name - also from packets cut off by the snaplen as
  long as the name is inside. Needs the Python package `cryptography` (installed by
  `install.sh`); the connections card shows what is still unnamed.
- **Weekly report** over the notification channels (Monday from 08:00 by default, Setup →
  Notifications): how much of the week was measured, internet outages and FRITZ!Box line
  events, the three worst hours by loss and ping, incident causes, new devices, devices
  that probably resolve past Pi-hole and lookups of malware/phishing domains. A section
  without data says so. The settings page previews the report and can send it at once.
  If the Pi is off at that hour, the report follows when it is back the same day.

- **Path measurement at incidents** (traceroute in the style of mtr): when an incident starts
  or a lag is reported, the Pi measures the path to the worst targets of the moment - every
  hop ten times - and the incident shows from which hop on packets are lost or delayed, and
  whether that hop is in your network, usually your provider's, or further along. A hop that
  only drops traceroute answers while later hops are fine is said to be harmless. At most
  one automatic measurement per target every 5 minutes, none at load guard level 2 or
  higher; the internet line page can start one by hand.
- **Upstream DNS servers**: how fast the servers behind Pi-hole answer (median, 95 %, slowest,
  queries without a recorded reply), read from Pi-hole's own log - nothing extra is sent.
  On the DNS page as a table and chart per server, and with each incident for the minute
  around it.

- **Pause Pi-hole blocking from the overview page** (5, 15 or 60 minutes, or switch it back on),
  when the Pi-hole actions are switched on; otherwise the page says where to switch them on.

### Changed
- **Shorter README**: requirements, installation and links; the technical details moved to
  `docs/setup.md`, `docs/usage.md` and `docs/operations.md`, security notes to `SECURITY.md`.
- **Long lists and tables scroll inside their card** (incidents, latest DNS queries, top
  domains, FRITZ!Box events, ...) instead of stretching the page to tens of thousands of
  pixels; table headers stay visible while scrolling. The sections of the Setup page fold
  (open ones are remembered per browser), Live and Overview show only the latest entries.
  A footer with the project links.
- **E-mail notifications are compact HTML**: a coloured strip for the kind of message (alert,
  resolved, event, weekly report), sections and lists of the weekly report laid out, and a
  button to the matching page of the analyzer. The subject starts with the message itself.
  A plain text part is still included.
- Incident bands in the charts are a faint wash with a solid strip at the bottom, so the lines
  stay readable while an incident covers most of the chart.
- **The FRITZ!Box capture now sends 600 bytes per packet by default** (was 128), so that the
  server names of TLS and QUIC connections are readable out of the box. The PCAP files of
  the deep capture still keep only 128 bytes per packet (`deep_capture.snaplen`): the rest
  is read in memory and never written to the SD card. A snaplen set in the UI or in
  `config.yaml` stays as it is.

### Fixed
- Downloading the PCAP of a long incident no longer risks the service's memory limit or stalls the
  measurements while the archive is built: it is written to a temporary file in the background.
- Incidents left open when the service stopped stayed "Ongoing" forever and were drawn as a
  band up to now - on a long-running Pi that tinted every chart red. They are closed on start
  where their last event ended, marked as interrupted, and get no made-up cause.
- The Pi-hole card no longer shows the word "null" when there is no error.
- Stopping or restarting the service no longer hangs for 20 s until systemd kills the
  capture process: SIGTERM now interrupts a read of the FRITZ!Box capture stream at once,
  while the capture is still stopped cleanly on the box.

## [1.3.0] - 2026-10-27

Overview page, internet line, the Pi itself, devices and presence, notifications,
automatic backups, a much more precise DNS section and measured connections per service.

### Added
- **Measured connections per service** on the device page: the TLS server name (SNI)
  is read from the first packet of every connection in the FRITZ!Box capture (new column
  `network_flows.sni`, schema 13), and connections are grouped into sessions per service
  (a pause > 2 minutes starts a new one) with duration and bytes - measured, not
  estimated. Needs `fritzbox.snaplen` ≈ 600 (allowed up to 1024 now; the default 128
  cuts the name off, and the page says so). QUIC (HTTP/3) is not covered and shown as
  such. The DNS guess for a connection's name stays in `dns_name`, apart from the SNI.
- **Pi-hole actions** (off by default, Setup → Pi-hole actions with an app password
  from Pi-hole): pause blocking for 5/15/60 minutes, switch it on again, restart DNS and
  update the blocklists on the DNS page; "Always allow" / "Block" in a domain's details.
  Only through Pi-hole's own v6 API, only to the Pi-hole on this Pi, one session per
  action, each after a confirmation and logged with the user. The FTL database stays
  read-only.
- **DNS past Pi-hole per device:** the DNS overview lists devices whose numbers are
  probably incomplete, and the device page says so: lookups of VPN, proxy and
  DNS-over-HTTPS services or iCloud Private Relay, active in the FRITZ!Box without any
  Pi-hole query, or many hours in the network with lookups in few of them. Signs, not
  proof; Firefox's DoH check (`use-application-dns.net`) is shown as information only.
- **The UT1 lists update themselves** where they were imported once: every 30 days
  at night (load guard level 0) the archive is downloaded (at most 300 MB), compared by
  checksum and - only if it changed - imported in a separate low-priority process, so
  the per-second measurements do not stall. The import reads the lists straight from
  the archive; nothing from it is extracted to disk. A failed update keeps the old index.
  The rules page shows the list date and the last update.
- **Automatic backups**: weekly at 03:00 (configurable, only at load guard level 0) a
  consistent copy of the database and `config.yaml` in `<data dir>/backups`, checked with
  `quick_check` before it counts; the two newest are kept, manual copies are never
  touched. "Back up now" and the list are under Setup → Backups. Skipped with too little
  free space.
- **Notifications** via ntfy (push to the phone), Telegram or e-mail (Setup →
  Notifications, with a test button): packet loss to the router, internet down,
  Pi-hole not answering, the Pi critical (power, heat, storage), internet line problems
  and FRITZ!Box events (DSL lost, disconnected), and new devices. Each alert needs a
  minimum duration, repeats at most once per cooldown (30 min) and ends with an "all
  clear" saying how long it lasted. Tokens and passwords are shown masked and kept
  when saved unchanged; errors never contain the Telegram token.
- **Categories per device** (DNS usage → Categories per device): every device with a bar
  of its lookups per category, background in grey; per device a table of lookups and
  share, active hours (clock hours with an allowed lookup) and - only where single
  services allow it - the estimated activity, kept as three separate columns. UT1 and
  background categories never get an estimate.
- **DNS: what a domain is and where that comes from.** Every domain opens its details:
  category with a one-line definition, service or provider, the matching rule and its
  source (shipped list, UT1 list, your rule), the confidence and what it means, the
  devices that looked it up, and how Pi-hole answered it in the last 24 hours (cache,
  forwarded, blocked by blocklist, regex or denylist). A rule can be set from there.
- **Clear separation of what is not use:** "Other" is split into *Shared
  infrastructure* (one entry per provider - CloudFront, Akamai, Google, Apple,
  Microsoft, ...) and *Network & connectivity checks* (captive portal detection, time
  servers, reverse lookups, local names). Both are background for activity phases and
  drawn in grey. New rules for telemetry and ad SDKs, Amazon and Samsung TV device
  services, TikTok EU, Prime Video and Netflix CDNs; iCloud Private Relay counts as VPN.
- **Not categorized yet:** the busiest names without a rule, bundled per owner, with
  their share of the lookups; a glossary explains lookups, blocks, retries, "IP only",
  categories and what DNS cannot see.
- **More categories from the UT1 lists**: adult content, gambling, dating, malware &
  phishing, and VPN / proxy / DNS-over-HTTPS servers (devices that may resolve past
  Pi-hole), besides the existing mappings. The import now writes a hash index searched
  on disk (8 bytes per name; 5 million names in ~40 MB instead of gigabytes of RAM), so
  the big adult list no longer has to be skipped. VPN and malware lookups count as
  background, not as use.
- **Overview** is the new start page: one status light each for internet, the link to the
  router, Pi-hole, FRITZ!Box, traffic capture and the Pi, and a timeline of the last 24
  hours or 7 days (internet, latency, link to router, DNS) from the stored per-minute
  values. Periods without measurements are hatched, never "OK". Incidents, service starts
  and Pi reboots are marked on it. The previous dashboard is now called **Live**.
- **Internet line** page: DSL sync and attainable rate, noise margin, attenuation and line
  errors (CRC, errored seconds, resyncs) from the FRITZ!Box every 5 minutes; its event log
  (reconnects, DSL sync lost, firmware updates) kept for 400 days (`retention.line_days`);
  outages measured by the Pi with the FRITZ!Box events around them, and an outage report
  as CSV for the provider. Boxes without DSL show only the connection state. On the
  overview: a light for the line, and its events on the timeline.
- **Raspberry Pi** page: temperature, under-voltage alarm, CPU, memory, swap, free storage,
  data written to the SD card, whether pihole-FTL runs, and the counters of the Pi's own
  network port (link drops, receive errors), once a minute without root rights.
  Optional `lan_reference`: a second always-on LAN device pinged like the router. If both
  lose packets at the same time, the page names the Pi's own cable, port or switch.
  On the overview: the Pi's findings in its light, and a timeline row for it.
- **Devices**: new devices (after the first hour of the database) and devices without any
  name are listed until marked as known; presence lanes show when which device was in
  the network (24 h / 7 d, minute resolution). On the overview: a light for the devices,
  and new devices on the timeline.
- **Gaps are filled from Pi-hole's log** once after each start, at load guard level 0:
  DNS minutes for the lag analysis that were not counted (service down, or the broken
  device loop since 1.2.0) - exactly as live, within the 7-day retention; and presence
  for the 31 days before it was recorded, from the hourly DNS counters per device. Those
  periods are whole hours in which a device looked up names, shown striped and labelled;
  a device that asked nothing is not shown there. Pi health and line values cannot be
  filled - nothing stored them.

### Security
- The FRITZ!Box login no longer falls back to the old MD5 challenge scheme
  (FRITZ!OS before 7.24). Anyone on the LAN who saw one MD5 login could
  brute-force the password offline. Older FRITZ!OS versions now get a clear error.

### Project
- A note in the web UI when a newer release is on GitHub (one request a day, no data of
  this installation; `update_check: false` switches it off). It never installs anything.
- CI checks the syntax of every frontend JavaScript file (`node --check`): the frontend
  has no build step, so a syntax error used to show up only as a blank page.

### Changed
- **Shorter README**: requirements, installation and links; the technical details moved to
  `docs/setup.md`, `docs/usage.md` and `docs/operations.md`, security notes to `SECURITY.md`.
- **Smaller database:** incident analyses are stored zlib-compressed and without their
  copy of the events (those are in the events table). On a copy of the Pi's database:
  207 → 135 MB, the incidents 99 → 34 MB (schema 12; the migration takes about 45 s once
  at the first start, including the backup copy and VACUUM).
- **Fewer, merged incidents.** An incident now stays open until no lag event came for
  2 minutes (was 5 s) and lasts at most 30 minutes (was 10). On the Pi, 72 % of the
  incidents had started within a minute of the previous one - one loss episode cut into
  hundreds of pieces (~800 a day). A problem of one external target while the line is
  fine, and a blip under 5 s that no rule explains, stay events instead of incidents;
  the incidents page says so. Reports of the user are never dropped.

### Fixed
- Since 1.2.0 the device loop stopped on its first round: `poll_queries` had ended up
  inside `read_dhcp_leases` and no longer existed. Devices seen via ARP and Pi-hole were
  not saved and the DNS minutes for the lag analysis were missing - without a word in
  the log. An error in one round is now logged and the loop goes on. The start of the
  Pi-hole poll reads the indexed table instead of the view (27 s → instant on the Pi).
- `PRAGMA integrity_check` (the backup check in the README) reported "NULL value in
  fritz_events.kind" for every row with the SQLite of Debian 12 (3.40.1), although the data
  was fine. The table now has its key columns first (schema 11, migration step).
- FRITZ!OS 8 (seen on a FRITZ!Box 7690 with 8.02) no longer offers the TR-064 action
  `GetAddonInfos`. The WAN rate now comes from the link utilization of
  `GetCommonLinkProperties` on such boxes. Before, the failing call also stopped the
  host list, so the client identification on the DNS page stayed "Not available".
- A failing FRITZ!Box request no longer stops the others; the status shows the UPnP
  error code instead of a bare "HTTP 500".
- The system loop (load guard) stopped on Windows without performance counters, because
  reading the load average raised there (dev mode only).
- Code scanning findings: a misread character range in the XLSX writer's
  regular expression and a false "clear-text logging" alert in the account CLI.

## [1.2.0] - 2026-10-22

DNS usage per device (Pi-hole), mandatory login. Method and limits: `docs/dns-usage.md`.

### Added
- Documentation of the DNS usage module (`docs/dns-usage.md`), backup and
  restore instructions, uninstall details and the new settings in
  `config.example.yaml`.
- Groundwork for the DNS usage module: read-only access to Pi-hole's DNS query
  log (normalized v6 schema and the older v5 `queries` table), streamed per time
  range and client on the indexed columns only.
- DNS queries are attributed to devices by MAC only where that is sound. Queries
  from IPs without a known MAC, or older than the device now using the IP, stay
  "IP only" instead of being given to today's owner. The Pi's own queries are
  counted separately; retries and duplicate in-flight queries are not counted.
- `python -m backend.dns_mapping_report`: shows how much of the DNS log can be
  attributed to individual devices, and warns when everything comes from one
  router or forwarder address.
- DNS usage data model (schema version 4): the Pi-hole query log is read
  incrementally into hourly totals and daily domain counts per device, with an
  own record of which device held which IP. Single queries are not copied.
  The position is written in the same transaction as the counters, so restarts
  and power cuts neither lose nor double-count queries. On the first start the
  last 91 days are read in small steps; the backfill only runs while the load
  guard is at level 0 and pauses from level 2. On the Pi: 30 days (4 million
  queries) in 4.5 minutes at low priority, about 150 KB per day.
- New settings `dns_usage` (interval, backfill days, batch size, domains kept per
  device and day) and `retention.dns_hourly_days` (400) / `dns_domain_days` (180).
- API: `/api/dns/status`, `/api/dns/clients`, `/api/dns/clients/{id}/hourly`,
  `/api/dns/clients/{id}/domains` (paginated, optionally blocked only).
- New page **DNS usage**:
  - Overview: known/active clients, queries, blocked, queries per hour,
    top domains, categories, latest queries, status of Pi-hole, FRITZ!Box and
    the ingestion.
  - Client list with search, online status and an "IP only" badge where no MAC
    is known.
  - Client detail: comparison with the previous period (only when that period
    is fully recorded), categories, top domains, and a domain list filterable by
    category, name and allowed/blocked, sortable and paginated. Aliases are set
    there or on the devices page.
  - Time ranges 1 h, 24 h, 7 d, 30 d or custom. Hours before recording started
    are hatched, not drawn as zero.
- Domain categories, rule based and offline:
  - A shipped rule file covers about 400 domains of known services (Facebook,
    Instagram, TikTok, YouTube, Twitch, Steam, Discord, Reddit, Microsoft 365, …).
  - Shared infrastructure (CDNs, cloud hosting, big platforms) is "Other" with
    low confidence, never a service. SDK domains such as `graph.facebook.com`
    are ads & tracking, not Facebook use.
  - Every domain shows the rule, the rule layer and the confidence.
  - Manual rules in the UI win over the shipped list for the same name. An
    optional `domain_categories.local.yaml` in the data directory adds own rules.
    `python -m backend.dns_category_import` adds the UT1 lists (download them
    yourself; CC BY-SA) as the lowest layer.
- Domain lists of the last 48 h are exact to the hour (new short-term table
  `dns_domain_hourly`, `retention.dns_domain_hourly_hours`). Longer ranges use
  whole local days and say so.
- Dev mode: the DNS pages run the real ingestion pipeline against a generated
  demo FTL log (demo devices only).
- **Activity phases (estimated)** on the client detail page, per service:
  DNS queries, phases, estimated activity and confidence, a timeline of the
  phases, and an explanation of the known sources of error.
  - A phase runs from the first to the last lookup of a service. A pause longer
    than the gap ends it (default 5 min, selectable in the UI; some services
    have their own gap in the rules). Pauses are never counted.
  - Confidence is at most "medium". Background and shared services, too few
    lookups and devices looking up names almost around the clock (TVs in
    standby) show "Not reliably determinable" instead of a number. Messengers,
    cloud sync, activity at night and many active hours per day lower it.
  - Blocked lookups are counted but form no phases.
  - Based on a new compact table of activity minutes per device and service
    (schema version 5, `retention.dns_minute_days` = 31, about 250 KB per day on
    the Pi). Reading the Pi-hole log for this took ~20 s of full CPU per request
    for 31 days; now 0.4 s. After a change of the category rules the table is
    rebuilt from the Pi-hole log in the background (about 3 minutes on the Pi).
  - Named manual rules define a service of their own, with phases.
- **Export** on the DNS overview and the client detail page, always with the
  range and filters on screen:
  - CSV: clients, domain list, category statistics, blocked domains, time series
    and activity phases. Default is German Excel (UTF-8 with BOM, semicolon,
    decimal comma); a comma/point variant is selectable.
  - XLSX with one sheet per table: the whole network, or a single client
    including summary, comparison and activity phases. Written without
    additional packages.
  - Every file starts with export time, range, client, filters, data source and
    method.
  - Text cells starting with `=`, `+`, `-`, `@`, tab or carriage return get a
    leading apostrophe, so domain names and device names cannot inject
    spreadsheet formulas.
  - Files are only created on request and streamed; nothing is stored on the Pi.
- **Client identification** on the DNS overview: the FRITZ!Box host list
  (TR-064, read-only, as before) compared with Pi-hole's view of the network.
  - Per device: consistent, IP differs, IP conflict, FRITZ!Box only, Pi-hole only.
  - Active devices that never asked Pi-hole are listed: they resolve names
    elsewhere (fixed DNS, DNS over HTTPS, VPN) and are missing from the DNS
    statistics.
  - Warns when the router forwards all DNS to Pi-hole and hides the devices,
    and when mesh access points make every device look cable-connected.
  - Nothing is merged or guessed from the comparison.
  - Measured on the Pi: all 30 devices of the FRITZ!Box are known to Pi-hole
    with the same IP, no conflicts.
- The client list shows the connection type as reported by the FRITZ!Box.
- **"Refresh host names"** on the devices page and the DNS page: forgets the
  learned host names and IPs and asks Pi-hole, its DHCP leases and the
  FRITZ!Box again right away. Own names (aliases) stay. The result shows what
  changed.

### Fixed
- Device host names flipped between sources: whichever of FRITZ!Box (every
  2 min) and Pi-hole (every minute) reported last won. Now a fixed priority
  applies: Pi-hole DHCP lease, then Pi-hole, then FRITZ!Box.
- Devices got old IPs and names from Pi-hole: FTL keeps every IP a device ever
  had (on the Pi up to 34 per device) and the last row read won. Now only the
  newest IPv4 and the newest name per device are used.
- A wrong host name could never be cleared from the database (the update kept
  the old value when the new one was empty).
- The DNS pages showed Pi-hole's host name from the time of the first queries
  instead of the name on the devices page.

### Security
- **Login is mandatory.** Username and password (scrypt). The account is created
  on the Pi only: `python -m backend.account set` (install.sh asks for it). There
  is no way to create it through the web UI, so nobody on the network can claim a
  fresh installation first. Until it exists, the API answers only `/api/health`
  and `/api/auth/state`.
- An existing login password keeps working: it becomes the user `admin`.
- Server-side sessions: random 256-bit tokens, stored only as SHA-256. Logout ends
  the session on the server, a password change ends all other sessions, "Sign out
  everywhere" and `python -m backend.account logout-all` end all of them. Sessions
  expire after `security.session_hours` (7 days) and after `security.idle_hours`
  (24 h) without requests.
- Login throttling also across addresses (30 failed attempts in 15 minutes in
  total), the same answer for a wrong username and a wrong password.
- The web UI listens on the LAN address only (`server.host: auto`, new default).
  Without a LAN address at start the service exits and systemd retries, instead
  of listening on every interface. install.sh offers to switch an existing
  `host: 0.0.0.0`.
- API responses are sent with `Cache-Control: no-store`; stricter
  Content-Security-Policy and a Permissions-Policy.
- New `/api/health` for monitoring; it reveals nothing but up/down.

### Changed
- **Shorter README**: requirements, installation and links; the technical details moved to
  `docs/setup.md`, `docs/usage.md` and `docs/operations.md`, security notes to `SECURITY.md`.
- The whole project is now in English: web UI, analysis texts and
  recommendations, log messages, API errors, comments, tests and documentation.
- Dates are shown as `YYYY-MM-DD`, numbers with a decimal point.
- The safety confirmation for deleting data is now `"DELETE"` (was `"LOESCHEN"`).
  Only relevant if you call `POST /api/database/delete` directly.
- `install.sh` also copies `LICENSE` to `/opt/network-lag-analyzer`.

Texts that were already stored in the database (incident causes and evidence of
older incidents) stay in German.

## [1.1.3] - 2026-10-20

### Security
- The stored FRITZ!Box password is only sent to the address it was entered for.
  Changing the FRITZ!Box address or the gateway (including in the connection test)
  requires entering the password again. Before, a device on the LAN could point the
  address at its own server and capture the login response.
- Login: locked for 15 minutes after 5 failed attempts per address.
- `session.key` is created with mode 0600 right away.

### Project
- Published on GitHub: MIT license, CI (tests on Python 3.11/3.13),
  `CONTRIBUTING.md`, `SECURITY.md`, `.gitattributes` (LF enforced).

## [1.1.2]

First version in the repository.
