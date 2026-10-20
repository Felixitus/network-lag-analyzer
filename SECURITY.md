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
| Without login enabled, every device on the LAN can do everything | Change settings, delete data, download captures |
| With login: scrypt hash, signed HttpOnly cookie, 5 failed attempts / 15 min per address | |
| Device names and DNS names come from the network and are **not trustworthy** | The frontend renders them as text only |

**Recommendation:** enable the login under *Setup → Access protection* as soon
as other people or untrusted devices are on your Wi-Fi (guests, IoT). The UI
shows traffic per device - that is sensitive information.

## What is protected

* The service runs as `nla`, not as root; the only extra capability is `CAP_NET_RAW`.
  systemd hardening (`ProtectSystem=strict`, `NoNewPrivileges`, …).
* CSRF protection (double-submit token + origin check) for all writing requests,
  CSP without inline scripts, `X-Frame-Options: DENY`.
* The FRITZ!Box password is never returned by the API and is only sent to the
  address it was entered for. Changing the address or the gateway requires
  entering it again.
* `config.yaml` 0640 (root:nla), data directory 0750, `session.key` 0600.
* Pi-hole database read-only. Captures contain headers only (`snaplen`), no payload.

## What is deliberately not protected

* No HTTPS - not reasonably possible on a LAN without your own CA. If you want to
  reach the UI from other networks, use a VPN (e.g. the FRITZ!Box WireGuard).
* Logging out deletes the cookie in the browser; a cookie copied beforehand stays
  valid until it expires (`session_hours`). To end all sessions: delete `session.key`
  in the data directory and restart the service.
* The FRITZ!Box password is stored in plain text in `config.yaml` or the database,
  because TR-064 needs it in plain text. So create a **dedicated FRITZ!Box user**
  with only the "FRITZ!Box Settings" permission.
