# Using the analyzer

The pages of the web UI and how the analysis reaches its verdict. Back to the [README](../README.md).

## The pages

**Dashboard:** live tiles (internet, ping, jitter, packet loss, gateway, download,
upload), the big **"I JUST HAD LAG"** button, live charts with the time ranges
LIVE/5 MIN/15 MIN/1 H/6 H/24 H/7 D, top devices, latest incidents, active events.
Updated via server-sent events, without reloading.

**Timeline:** ping, loss, jitter, upload, download, retransmissions and below them an
upload/download lane per device - all on **one shared time axis** with a synchronized
cursor. Incidents are red bands (clicking opens the incident), reported lag is orange,
events are ticks at the top. Below that the heatmap (devices × time).

**Incidents:** list and detail view (metrics before → peak, possible cause,
confidence, evidence, top traffic, all explanations checked, events, connections,
charts around the time, PCAP download with Deep Capture).

**Gaming:** start/stop a session, game server and packet gaps live, summaries:

```
Gaming session 19:32–22:14
Ping average 19 ms · maximum 214 ms · jitter avg 3.2 ms
Packet loss events 4 · lag events 7
Possible causes: 3× upload saturation, 2× WAN/ISP, 1× LAN/Wi-Fi, 1× unknown
```

Automatic detection: if the gaming PC has sustained (≥ 20 s) bidirectional UDP traffic
to an internet server (≥ 15 packets/s per direction), the session starts by itself.
Mark the gaming PC under **Devices** (checkbox "Gaming PC").

**Note on the game server:** many game servers (e.g. Azure/AWS for Rainbow Six Siege)
do not answer pings. Then it says "Not available" there. The connection is still
monitored via **packet gaps in the game flow**: if the server sends no packets for more
than 250 ms, a `GAME_FLOW_GAP` event is created.

---

### Reading the timeline

All panels share one time axis; only the bottom one carries the times. When hovering,
the bar at the top shows **all values at the same point in time** - ping, loss,
jitter, download, upload and retransmissions at once. This is the view for
"what was going on at 20:14?". A panel can be expanded with ▸, dragging in a chart
zooms into the time span (with a matching resolution), "Reset zoom" goes back.

Grey hatched areas are periods **without measurements** - for example because the
service was stopped. They are not drawn as zero, because that would fake a measurement.
Under "Traffic per device" the lanes can be switched to a **shared scale**; without it
every lane has its own axis and the heights are not comparable.

---

## Root cause analysis - how it decides

Every rule is a separate, commented function in `backend/analysis/root_cause.py`.
The rule with the highest score wins. If a second explanation of a different category
is on par, the confidence is lowered.

| Observation | Result |
|---|---|
| Gateway ping high + internet ping high | LAN/Wi-Fi/router problem |
| Gateway normal + internet ping high (several targets) | WAN/ISP/bufferbloat |
| Gateway + internet normal, only one target abnormal | target server/routing |
| High upload of a device + ping/jitter high | upload saturation/bufferbloat (+ device) |
| High download + ping spike | download saturation/bufferbloat (+ device) |
| TCP retransmissions strongly increased | packet loss (direction is stated) |
| Several external targets with packet loss at once | WAN/ISP more likely than a single server |
| Only one external target affected | routing/target server more likely |
| Router + internet normal, game flow has gaps | game server/routing |
| DNS probes fail, ping normal | DNS disruption (Pi-hole or upstream) |
| All targets gone, router reachable/not reachable | internet outage or LAN connection loss |

Confidence: ≥ 80 points **High** ("likely cause"), ≥ 55 **Medium**
("possible cause"), otherwise **Low** ("temporally correlated"). A device is only named
as the cause if traffic per device was measured and the device dominates the
bottleneck (≥ 60 % of the traffic in the saturated direction).

**Line capacity:** for utilization in %, the capacity must be known. `auto`
uses the link rate of the FRITZ!Box (TR-064). If the booked rate is lower (throttling
at the provider), enter the booked rate under Setup → Measurement. That is more accurate.

### Recommendations, not just a diagnosis

Every category comes with a concrete action (`recommendation` in the analysis,
visible in the incident under "What helps now"). It also says whether you can fix it
yourself at all:

| `scope` | Meaning |
|---|---|
| `self` | in your own hands - device, router, Wi-Fi |
| `provider` | only the internet provider can change it (document and report) |
| `remote` | lies with the target server or the routing to it |
| `none` | the data is not enough for a reliable recommendation |

The direction matters, because the actions are opposite:

* **Upload saturation** - the queue sits in your own router. Prioritization in the
  FRITZ!Box really works here.
* **Download saturation** - the queue sits at the provider. Local prioritization
  cannot overtake packets that are already waiting there; the only thing that helps is
  slowing down the downloading device.

### Path measurement: where on the way?

The cause rules see whether one target or all of them suffer, and whether the router is
fine. Where the path breaks they cannot see. So when an incident starts (or a lag is
reported) the Pi measures the path to the worst targets of that moment, while the
problem is still on: every hop ten times, one round per second, probes 25 ms apart.

* Loss that begins at one hop and **lasts to the target** is located: "Losses begin at
  hop 3 (… usually your provider)".
* A hop that drops answers while later hops are fine is **not** the problem - routers
  answer traceroutes at low priority. The incident says so instead of blaming it.
* A hop that never answers is normal and says nothing.
* The segment is read from the address: RFC 1918 = your network, 100.64.0.0/10 and the
  first public hop = usually your provider, everything after = further along the path.

It needs the raw ICMP socket the service already has (`CAP_NET_RAW`). At most one
automatic measurement per target every 5 minutes, none at load guard level 2 or higher
(`traceroute` in the settings). The internet line page starts one by hand.

### Latency under load (bufferbloat)

`backend/analysis/bufferbloat.py` measures how much ping is added when the line is
full - separately per direction. Seconds are grouped by utilization and the median RTT
of the groups is compared:

* **quiet** ≤ 20 % utilization in both directions
* **under load** ≥ 70 % in one direction while the other stays < 40 %
* If both directions are full, the second is discarded - the cause could not be separated.

Each group needs at least 5 seconds, otherwise the result stays empty (no estimate).
Rating: < 30 ms "good", < 100 ms "moderate", above that "severe".

Visible in three places: as a card on the dashboard (1 h / 24 h / 7 d / 30 d), in the
incident for its analysis window and via `GET /api/bufferbloat?range=…`. So that the
history survives for weeks, maintenance writes a window into the `bufferbloat` table
every 10 minutes (9 numbers) - the 1 s raw values are only kept for one day.
Short spans are computed by the API directly from the per-second values (`source: live`),
longer ones from the stored windows (`source: windows`).

---

## DNS usage per device

The page **DNS usage** shows per device which names it looked up through Pi-hole -
queries, blocked queries, domains, categories, a timeline, an estimate of activity phases
per service, and CSV/XLSX export. Method, storage and limits: **[docs/dns-usage.md](dns-usage.md)**.

In short:

* Source is Pi-hole's query log, read incrementally and read-only; only compact counters
  are stored (about 400 KB per day on the test Pi, all of it subject to retention).
* Queries are attributed to devices by MAC only where that is sound (own IP history,
  FRITZ!Box cross-check); otherwise they stay "IP only".
* Categories are local rules (~400 domains of known services, own rules, optional UT1 lists
  with adult content, gambling, dating, VPN/DNS bypass and malware). CDNs and shared
  platforms are never attributed to a service.
* Activity phases are **estimated DNS activity, not usage time** - confidence at most
  "medium", "Not reliably determinable" where the data does not allow an estimate.
* Lookups that bypass Pi-hole (DNS over HTTPS, iCloud Private Relay, VPN, fixed DNS
  servers) are missing; the client identification check on the page lists devices that
  never ask Pi-hole.
