# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versions follow [SemVer](https://semver.org/).

## [Unreleased]

### Added
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

### Changed
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
