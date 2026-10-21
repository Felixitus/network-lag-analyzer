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
