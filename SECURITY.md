# Security

## Reporting a vulnerability

Please do **not** open a public issue. Instead, report it privately via GitHub
"Security → Report a vulnerability". You will usually get a response within a week.

## Threat model

Network Lag Analyzer is a tool **for your own home network**. It is not built
to be reachable from the internet.

| Assumption | Consequence |
|---|---|
| Port 8088 is **not** forwarded in the router | Attackers have to be on the LAN |
| The web UI always needs a login | Every page and every API call except `/api/health` |
| Device names and DNS names come from the network and are **not trustworthy** | The frontend renders them as text only |

The UI shows traffic and DNS lookups per device - that is sensitive information. Give the
login account a strong password.

## What is protected

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
  only (`python -m backend.account set`) - there is no sign-up page. Sessions are random
  256-bit tokens in an HttpOnly, SameSite=Strict cookie; the database stores only their
  SHA-256. Logout ends the session on the server, a password change ends all other
  sessions. Sessions expire after 7 days and after 24 h without requests. Throttling:
  5 failed attempts per address and 30 in total per 15 minutes.
* The web UI listens on the **LAN address only** (`server.host: auto`).
* The FRITZ!Box password is never returned by the API and is only sent to the address it
  was entered for; changing the address or the gateway requires entering it again.
* `config.yaml` 0640 (root:nla), data directory 0750.
* Pi-hole database read-only; Pi-hole is only changed through its own API, after a
  confirmation, when the Pi-hole actions are switched on.
* Payloads are never stored: the PCAP files keep 128 bytes per packet, headers only
  (`deep_capture.snaplen`). The running ring stays in RAM by default; only incident
  captures reach the SD card.
* Exports (CSV/XLSX) neutralize cells that a spreadsheet would evaluate as formulas.

## What is deliberately not protected

* HTTPS is off by default: a public certificate is not possible for a LAN address. With
  `server.https: true` the Pi uses a self-signed certificate (compare its fingerprint from the
  log once); the session cookie is then `Secure`. To reach the UI from other networks, use a
  VPN (e.g. the FRITZ!Box WireGuard) either way.
* Without HTTPS the session cookie cannot be `Secure`.
* The FRITZ!Box password is stored in plain text in `config.yaml` or the database,
  because TR-064 needs it in plain text. So create a **dedicated FRITZ!Box user**
  with only the "FRITZ!Box Settings" permission.
