# Network Lag Analyzer

[![Tests](https://github.com/Felixitus/network-lag-analyzer/actions/workflows/tests.yml/badge.svg)](https://github.com/Felixitus/network-lag-analyzer/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Network diagnostics for a Raspberry Pi running Pi-hole. It answers one question:

> **"Why did I have lag or packet loss at exactly this moment?"**

It pings the router and the internet every second, counts the traffic of every device
through the FRITZ!Box, detects anomalies, groups them into incidents and names a likely
cause - with the evidence for it.

```
INCIDENT #124 · 2026-09-21 20:43:12 · duration 4.2 s
Ping 18 → 184 ms · Jitter 2 → 61 ms · Packet Loss 8 %

Possible Cause: Upload saturation by iPhone          Confidence: High
  • Upload utilization up to 97 % of the line (38.8 of 40 Mbit/s)
  • Upload increase started 2 s before the latency increase
  • Router latency stayed stable
```

Everything runs locally: no cloud, no telemetry, no payload storage. Whatever could not
be measured is shown as "Not available" - never as an estimate.

## Features

- **Latency, jitter, packet loss** to the router and freely chosen targets, 1/s (4/s in Gaming Mode)
- **Traffic per device** from the FRITZ!Box packet capture, TCP retransmissions, flows
- **Incidents with a cause**: documented rules, confidence, evidence and what helps now
- **Path measurement** when an incident starts: in your network or at the provider?
- **"I just had lag" button** that analyzes the last seconds and minutes right away
- **DNS usage per device** from Pi-hole's log, reply times of the upstream DNS servers
- **Gaming Mode**, latency under load (bufferbloat), internet line and Pi health pages
- **Notifications** via ntfy, Telegram or e-mail, plus a weekly report

## Requirements

| | |
|---|---|
| Hardware | Raspberry Pi 4 or 5 (2 GB+) recommended, 3B+ works - **on a LAN cable** |
| System | Raspberry Pi OS / Debian 12 (Bookworm) or newer, Python ≥ 3.10 |
| Pi-hole | v5 or v6 on the same Pi (optional, for device names and DNS data) |
| Router | FRITZ!Box for traffic per device (optional; ping, loss and DNS work without) |
| Storage | ~200 MB for the program, 50-500 MB of data |

Pi-hole keeps running unchanged; the service runs at a lower priority and is limited to 350 MB RAM.

## Installation

```bash
sudo apt install -y git
git clone https://github.com/Felixitus/network-lag-analyzer.git
cd network-lag-analyzer
sudo ./install.sh
```

The installer creates the user `nla`, installs the program to `/opt/network-lag-analyzer`,
starts the systemd service and asks for the login account. It does not touch Pi-hole and
runs no `apt upgrade`.

Then open `http://PI-IP-ADDRESS:8088`, sign in, go to **Setup**, run the diagnosis and
enter the FRITZ!Box access.

**FRITZ!Box** (for traffic per device): allow access for applications (Home Network →
Network → Network Settings) and create a dedicated user with the permission
"FRITZ!Box Settings". Details: [docs/setup.md](docs/setup.md).

**Update:** `git pull && sudo ./install.sh` - configuration and data are kept.

**Uninstall:** `sudo ./install.sh --uninstall` - data and configuration are kept until you
delete `/var/lib/network-lag-analyzer` and `/etc/network-lag-analyzer`.

**Forgotten password:**

```bash
cd /opt/network-lag-analyzer
sudo -u nla env NLA_CONFIG=/etc/network-lag-analyzer/config.yaml venv/bin/python -m backend.account set
```

Meant for the LAN only: do not forward port 8088 in the router; use a VPN for remote access.

## Documentation

| | |
|---|---|
| [Setup](docs/setup.md) | what the Pi can see, FRITZ!Box, port mirroring, Pi-hole, configuration |
| [Using it](docs/usage.md) | the pages, reading the timeline, how causes are decided, path measurement |
| [DNS usage](docs/dns-usage.md) | DNS per device: method, categories, limits |
| [Operations](docs/operations.md) | database, backup and restore, storage, load guard, troubleshooting |
| [Architecture](ARCHITECTURE.md) | how the parts fit together |
| [Security](SECURITY.md) | threat model, what is protected, reporting a vulnerability |
| [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md) | |

## License

[MIT](LICENSE). Includes [uPlot](https://github.com/leeoniya/uPlot) (MIT, see
`frontend/vendor/uPlot.LICENSE`).
