# Setup: network, FRITZ!Box, Pi-hole

How the Pi gets to see the traffic, and what each source adds. Back to the [README](../README.md).

## Network architecture & traffic visibility

Most important point: **Pi-hole only sees DNS.** A Raspberry Pi that is not the router
fundamentally does not see other devices' traffic - a switch only sends it packets that
are addressed to it. Promiscuous mode does not change that.

| Measurement | Pi on the LAN (default) | + FRITZ!Box capture | + port mirroring | Pi as gateway |
|---|:-:|:-:|:-:|:-:|
| Ping/jitter/loss router + internet | ✓ | ✓ | ✓ | ✓ |
| DNS activity per device (Pi-hole) | ✓ | ✓ | ✓ | ✓ |
| Total WAN rate (TR-064) | ✓¹ | ✓ | ✓¹ | ✓ |
| Traffic per device | ✗ | ✓ | ✓ | ✓ |
| TCP retransmissions, flows | ✗ | ✓ | ✓ | ✓ |
| Game flow analysis (packet gaps) | ✗ | ✓ | ✓ | ✓ |

¹ with FRITZ!Box credentials.

The **setup wizard** checks this actively (among other things it listens on the interface
for 2 s to see whether foreign unicast frames arrive) and shows the capability matrix. If a
source is missing, the UI says so - and the root cause analysis then names **no device**.

---

## Setting up the FRITZ!Box (recommended)

1. **Enable TR-064:** Home Network → Network → Network Settings → "Allow access for
   applications".
2. **Create a dedicated user:** System → FRITZ!Box Users → Add user, e.g. `nla`,
   strong password, permission **"FRITZ!Box Settings"** (needed for the packet capture).
   No internet access to the box is needed.
3. In the web UI → **Setup** → "FRITZ!Box & traffic source": enable the integration,
   enter user/password, click **"Test connection & capture"**, save.

Technically, the Pi opens a permanent HTTP stream
`/cgi-bin/capture_notimeout?ifaceorminor=1-lan&snaplen=600`. The FRITZ!Box sends a
libpcap stream of its LAN bridge with the first 600 bytes of each packet: the headers, and
for new TLS and QUIC connections the server name they ask for. That part is only read in
memory; the PCAP files of the deep capture keep **headers only** (128 bytes,
`deep_capture.snaplen`). `fritzbox.snaplen: 128` sends headers only in the first place, at
the price of no server names.
Depending on FRITZ!OS this is either classic pcap or the "modified pcap" variant
(magic `a1b2cd34`, 24-byte record headers); both are supported, as is pcapng. From it the Pi
counts bytes/packets per MAC (upload = client → router, download = router → client)
and builds flows. The capture connection itself is filtered out.

Notes:
* Depending on FRITZ!OS the interface is usually called `1-lan`. The test shows the interfaces it finds.
* The capture puts some load on the FRITZ!Box CPU and creates ~1–2 MB/s of LAN traffic under
  high load. At very high packet rates (gigabit fully utilized) the load guard switches to
  sampling and marks values as estimated.
* Without a capture but with credentials, TR-064 at least delivers the total WAN rate
  (without a per-device split) and the line capacity.

---

## Port mirroring

Alternative with extra hardware: a managed switch (e.g. TP-Link TL-SG105E/108E,
Netgear GS105E) between the FRITZ!Box and the rest of the network mirrors the uplink port
to the Pi's port.

```
FRITZ!Box LAN ── [Port 1] Managed switch [Port 2..n] ── Deco, PC, …
                          [Port 5 = mirror target] ── Raspberry Pi
```

Settings: source = port to the FRITZ!Box (ingress and egress), target = the Pi's port.
In the UI: traffic source = "Local interface", interface `eth0`. The wizard detects
mirrored traffic automatically ("Foreign client traffic visible at the Pi ✓").

Caution: some cheap switches only mirror one direction or disable the normal network
access of the target port - in that case use a second network adapter (USB) on the Pi
as the mirror port.

---

## Raspberry Pi as gateway

Possible (source "Local interface", IP forwarding active), but **not recommended** for
this purpose: every packet then passes through the Pi. That adds latency, and if the Pi
fails, the internet is gone. For a lag diagnosis tool that is the wrong trade-off. The
FRITZ!Box capture or port mirroring provide the same view without this risk.

---

## Pi-hole integration

* Only `/etc/pihole/pihole-FTL.db` is read (read-only, Pi-hole v5 and v6):
  tables `network`/`network_addresses` (MAC, IP, host name, vendor) and `queries`.
* Used for: device names, DNS activity and top domains per device (devices page).
* **DNS queries are never interpreted as bandwidth.** Many DNS queries do not mean
  a lot of traffic.
* By default FTL writes to the database once per minute - so DNS data is delayed by up
  to ~60 s. That does not matter for the lag analysis.
* In addition, a dedicated DNS prober measures Pi-hole (127.0.0.1) and an upstream
  resolver every 5 s. This detects a DNS outage and distinguishes it from real lag.
* `/etc/pihole/dhcp.leases` (read-only) gives the host names of the current DHCP leases
  where Pi-hole is the DHCP server. Host name priority: DHCP lease, Pi-hole, FRITZ!Box.
  **Refresh host names** (devices page) asks all sources again right away; own names stay.

---

## Configuration

`/etc/network-lag-analyzer/config.yaml` (template: `config.example.yaml`). The most
important values can be changed in the UI; those changes live in the database and
override the file. "Setup" shows the effective values.

```yaml
gateway: auto
targets: [1.1.1.1, 8.8.8.8, 9.9.9.9]
gaming_pc:
  ip: 192.168.178.20
thresholds:
  ping_warning: 50
  ping_critical: 100
  jitter_warning: 20
  packet_loss_warning: 1
retention:
  raw_days: 1
  detailed_days: 7
  aggregate_days: 30
```

Environment variables: `NLA_CONFIG`, `NLA_DATA_DIR`, `NLA_PORT`, `NLA_DEV_MODE`, `NLA_LOG_LEVEL`.

### E-mail notifications

Port 587 with STARTTLS is the default. For providers that only offer port 465, switch on
"TLS from the start (port 465)" in Setup → Notifications and set the port to 465.

### HTTPS (optional)

```yaml
server:
  https: true
```

Then `sudo systemctl restart network-lag-analyzer`. On the first start the Pi makes a
self-signed certificate (`/var/lib/network-lag-analyzer/tls/`, valid for 10 years) and logs
its SHA-256 fingerprint:

```bash
journalctl -u network-lag-analyzer | grep fingerprint -i
```

The browser warns once, because no public authority signed it; compare the fingerprint in
the certificate details with the log and accept it. From then on the UI is
`https://PI-IP-ADDRESS:8088` (plain `http://` no longer answers on that port), the session
cookie is `Secure`, and copying the update command works directly. Delete both files in
`tls/` to get a new certificate, e.g. after the Pi got a new name or address.
