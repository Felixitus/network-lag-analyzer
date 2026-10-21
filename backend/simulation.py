"""Simulated network data - ONLY for tests and the explicit dev mode (`dev_mode: true`).

This module is never imported in production. In dev mode the web UI
permanently shows the "DEMO MODE" banner.

Scenarios (also used in tests/test_scenarios.py):
  normal, upload_saturation, download_saturation, isp_loss, local_gateway,
  single_target, dns_outage, game_server
"""
from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass

GW_TID, T1, T2, T3 = 1, 2, 3, 4          # target IDs in the test setup
MAC_PC = "02:00:00:00:00:20"
MAC_IPHONE = "02:00:00:00:00:42"
MAC_TV = "02:00:00:00:00:51"
MAC_LAPTOP = "02:00:00:00:00:33"
# Addresses from the ranges reserved for documentation (RFC 5737 TEST-NET-1
# 192.0.2.0/24, RFC 2606 for names) and locally administered MACs (02:...). This way
# demo devices can be told apart from real ones at first glance and never collide
# with a real home network.
DEMO_GATEWAY = "192.0.2.1"
DEMO_DNS_UPSTREAM = "192.0.2.53"
DEMO_GAME_SERVER = "203.0.113.77"        # RFC 5737 TEST-NET-3
DEMO_DEVICES = {
    MAC_PC: ("192.0.2.20", "Gaming-PC (Demo)"),
    MAC_IPHONE: ("192.0.2.42", "iPhone (Demo)"),
    MAC_TV: ("192.0.2.51", "Smart-TV (Demo)"),
    MAC_LAPTOP: ("192.0.2.33", "Laptop (Demo)"),
}
CAP_DOWN = 100e6
CAP_UP = 40e6
SCENARIOS = ["upload_saturation", "download_saturation", "isp_loss", "local_gateway", "single_target",
             "dns_outage"]


@dataclass
class Second:
    probes: dict          # tid → [rtt | None, ...]
    devices: dict         # mac → [rx, tx, rxp, txp, udp, lan, retrans]  (bytes)
    glob: dict
    dns: list             # [(server, ms, status)]


def _dev(rx_bps: float, tx_bps: float, udp_frac: float = 0.0, retrans: int = 0) -> list[int]:
    rx, tx = int(rx_bps / 8), int(tx_bps / 8)
    return [rx, tx, max(1, rx // 1200) if rx else 0, max(1, tx // 400) if tx else 0,
            int((rx + tx) * udp_frac), 0, retrans]


def make_second(scenario: str, k: int, rng: random.Random, probes_per_target: int = 1,
                onset: int = 5, gaming: bool = False) -> Second:
    """Generates one second of measurements. k = second relative to the scenario start."""
    active = scenario != "normal" and k >= onset
    base = {T1: 14.0, T2: 17.0, T3: 21.0}

    def rtt(tid: int, extra: float = 0.0, loss: float = 0.0, jitter: float = 1.5) -> float | None:
        if rng.random() < loss:
            return None
        return round(base[tid] + extra + abs(rng.gauss(0, jitter)), 2)

    gw_extra, gw_loss = 0.0, 0.0
    extra = {T1: 0.0, T2: 0.0, T3: 0.0}
    loss = {T1: 0.0, T2: 0.0, T3: 0.0}
    jit = 1.5
    pc = _dev(3e6, 0.4e6, udp_frac=0.3 if gaming else 0.0)
    iphone = _dev(0.3e6, 0.2e6)
    tv = _dev(4e6, 0.1e6)
    laptop = _dev(0.8e6, 0.3e6)
    dns = [("127.0.0.1", round(rng.uniform(0.5, 3), 2), "ok"),
           (DEMO_DNS_UPSTREAM, round(rng.uniform(9, 14), 2), "ok")]
    retr_down = 0

    if scenario == "upload_saturation":
        if k >= onset - 1:
            iphone = _dev(0.4e6, CAP_UP * rng.uniform(0.9, 0.98))
        if active:
            for t in extra:
                extra[t] = rng.uniform(120, 190)
                loss[t] = 0.08
            jit = 25
    elif scenario == "download_saturation":
        if k >= onset - 1:
            tv = _dev(CAP_DOWN * rng.uniform(0.92, 0.99), 0.5e6)
        if active:
            for t in extra:
                extra[t] = rng.uniform(60, 110)
            jit = 18
    elif scenario == "isp_loss" and active:
        for t in extra:
            extra[t] = rng.uniform(20, 60)
            loss[t] = 0.35
        retr_down = 12
    elif scenario == "local_gateway" and active:
        gw_extra, gw_loss = rng.uniform(60, 220), 0.25
        for t in extra:
            extra[t] = gw_extra + rng.uniform(0, 20)
            loss[t] = 0.25
    elif scenario == "single_target" and active:
        extra[T2] = rng.uniform(150, 260)
        loss[T2] = 0.3
    elif scenario == "dns_outage" and active:
        dns = [("127.0.0.1", None, "timeout"), (DEMO_DNS_UPSTREAM, round(rng.uniform(9, 14), 2), "ok")]

    probes = {GW_TID: [None if rng.random() < gw_loss else round(0.9 + gw_extra + abs(rng.gauss(0, 0.2)), 2)
                       for _ in range(probes_per_target)]}
    for t in (T1, T2, T3):
        probes[t] = [rtt(t, extra[t], loss[t], jit) for _ in range(probes_per_target)]
    devices = {MAC_PC: pc, MAC_IPHONE: iphone, MAC_TV: tv, MAC_LAPTOP: laptop}
    glob = {"wan_rx": sum(d[0] for d in devices.values()), "wan_tx": sum(d[1] for d in devices.values()),
            "tcp_segs": 800, "retrans_down": retr_down + rng.randint(0, 2), "retrans_up": rng.randint(0, 1),
            "pkts": 2000, "tcp_analysis": True}
    if gaming:
        gap = 30.0 + abs(rng.gauss(0, 5))
        if scenario == "game_server" and active:
            gap = rng.uniform(300, 700)
        glob.update(game_pps=128, game_gap_ms=round(gap, 1))
    return Second(probes, devices, glob, dns)


def feed_second(hub, ts: int, s: Second, spread: bool = True, tid_map: dict | None = None) -> None:
    """Feeds one simulated second into the MetricsHub."""
    for tid, samples in s.probes.items():
        if tid_map is not None:
            if tid not in tid_map:
                continue
            tid = tid_map[tid]
        n = len(samples)
        for i, r in enumerate(samples):
            hub.add_probe(tid, ts + (i / n if spread else 0) + 0.01, r)
    for server, ms, status in s.dns:
        hub.add_dns(server, ts + 0.5, ms, status)
    hub.add_traffic_bin(ts, s.devices, s.glob)


class LiveSimulator:
    """Dev mode: feeds simulated data in real time (normal operation + cyclic disruptions)."""

    def __init__(self, core):
        self.core = core
        self.rng = random.Random()
        self.scenario = "normal"
        self.k = 0
        self.next_change = time.time() + 45
        self.gaming = False

    def gaming_started(self, sess) -> None:
        self.gaming = True
        sess.server_ip = DEMO_GAME_SERVER
        sess.server_port = 3074
        sess.server_icmp = "blocked"

    async def run(self) -> None:
        core = self.core
        core.link_capacity = (CAP_DOWN, CAP_UP)
        core.capture_status = {"state": "running", "source": "simulated", "pps": 0, "lag_s": 0, "level": 0}
        core.fritz_status = {"enabled": False, "note": "dev mode"}
        core.pihole_status = {"enabled": False, "note": "dev mode"}
        core.hub.dns_primary = "127.0.0.1"
        gw = [tid for tid, t in core.targets.items() if t["kind"] == "gateway"]
        inet = [tid for tid, t in core.targets.items() if t["kind"] == "internet"]
        self.tid_map = dict(zip([GW_TID], gw)) | dict(zip([T1, T2, T3], inet))
        now = time.time()
        for mac, (ip, name) in DEMO_DEVICES.items():
            core.devices.observe(mac, ip=ip, hostname=name, source="simulated", seen=now)
        # 5 minutes of lead time so that baselines and charts are filled immediately
        start = int(now) - 300
        for i in range(300):
            feed_second(core.hub, start + i, make_second("normal", 0, self.rng), tid_map=self.tid_map)
        core.hub.finalize_due(now=now - 3)
        while True:
            now = time.time()
            if now >= self.next_change:
                if self.scenario == "normal":
                    self.scenario = self.rng.choice(SCENARIOS + (["game_server"] if self.gaming else []))
                    self.next_change = now + self.rng.randint(15, 25)
                else:
                    self.scenario = "normal"
                    self.next_change = now + self.rng.randint(60, 120)
                self.k = 0
            sec = int(now)
            s = make_second(self.scenario, self.k, self.rng, probes_per_target=4 if core.gaming else 1,
                            onset=3, gaming=core.gaming is not None)
            feed_second(core.hub, sec, s, tid_map=self.tid_map)
            if sec % 20 == 0 and core.dns_usage is not None:
                await asyncio.to_thread(build_demo_ftl, core.dns_usage.ftl.db_path, time.time())
            self.k += 1
            await asyncio.sleep(max(0.05, sec + 1.02 - time.time()))


# ---------------------------------------------------------------------------- demo DNS log
# Dev mode feeds the real DNS ingestion pipeline from a generated FTL database,
# so the DNS pages run the same code path as production - with demo devices only.
DEMO_IP_ONLY = "192.0.2.99"              # a client Pi-hole knows no MAC for
_FTL_SCHEMA = """
CREATE TABLE IF NOT EXISTS query_storage (id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL,
  type INTEGER NOT NULL, status INTEGER NOT NULL, domain INTEGER NOT NULL, client INTEGER NOT NULL,
  forward INTEGER, additional_info INTEGER, reply_type INTEGER, reply_time REAL, dnssec INTEGER,
  list_id INTEGER, ede INTEGER);
CREATE INDEX IF NOT EXISTS idx_queries_timestamp ON query_storage (timestamp);
CREATE TABLE IF NOT EXISTS domain_by_id (id INTEGER PRIMARY KEY, domain TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS client_by_id (id INTEGER PRIMARY KEY, ip TEXT NOT NULL, name TEXT, UNIQUE(ip, name));
CREATE TABLE IF NOT EXISTS network (id INTEGER PRIMARY KEY NOT NULL, hwaddr TEXT UNIQUE NOT NULL,
  interface TEXT NOT NULL, firstSeen INTEGER NOT NULL, lastQuery INTEGER NOT NULL, numQueries INTEGER NOT NULL,
  macVendor TEXT, aliasclient_id INTEGER);
CREATE TABLE IF NOT EXISTS network_addresses (network_id INTEGER NOT NULL, ip TEXT UNIQUE NOT NULL,
  lastSeen INTEGER NOT NULL, name TEXT, nameUpdated INTEGER);
"""
# service → (domains, fixed status or None). Status 1 = blocked, 2 = forwarded, 3 = cached.
_SERVICES = {
    "steam": (["store.steampowered.com", "steamcommunity.com", "cdn.steamstatic.com", "api.steampowered.com"], None),
    "discord": (["discord.com", "gateway.discord.gg", "cdn.discordapp.com"], None),
    "youtube": (["www.youtube.com", "i.ytimg.com", "rr3---sn-demo.googlevideo.com", "youtubei.googleapis.com"], None),
    "twitch": (["www.twitch.tv", "video-weaver.demo.hls.ttvnw.net"], None),
    "instagram": (["i.instagram.com", "scontent.cdninstagram.com", "graph.instagram.com"], None),
    "whatsapp": (["g.whatsapp.net", "mmg.whatsapp.net"], None),
    "tiktok": (["www.tiktok.com", "v16m.tiktokcdn.com"], None),
    "facebook": (["www.facebook.com", "static.xx.fbcdn.net", "graph.facebook.com"], None),
    "netflix": (["www.netflix.com", "ipv4-c001.demo.nflxvideo.net", "assets.nflxext.com"], None),
    "spotify": (["spclient.wg.spotify.com", "i.scdn.co"], None),
    "office": (["outlook.office.com", "www.office.com", "teams.microsoft.com"], None),
    "github": (["github.com", "avatars.githubusercontent.com"], None),
    "news": (["www.spiegel.de", "www.tagesschau.de", "www.heise.de"], None),
    "shopping": (["www.amazon.de", "m.media-amazon.com", "www.ebay.de"], None),
    "icloud": (["gateway.icloud.com", "p42-contacts.icloud.com"], None),
    "ads": (["securepubads.g.doubleclick.net", "www.google-analytics.com", "app-measurement.com"], 1),
    "cdn": (["d1demo.cloudfront.net", "a1234.dscx.akamaiedge.net", "fonts.gstatic.com"], None),
    "updates": (["fe2.update.microsoft.com", "settings-win.data.microsoft.com"], None),
    "unknown": (["api.weather.example", "telemetry.example"], None),
}
# device → (services, active local hours [from, to))
_PROFILES = {
    MAC_PC: (["steam", "discord", "youtube", "twitch", "ads", "updates", "cdn"], (15, 24)),
    MAC_IPHONE: (["instagram", "whatsapp", "tiktok", "facebook", "icloud", "ads", "cdn", "spotify"], (7, 24)),
    MAC_TV: (["netflix", "youtube", "ads", "unknown"], (18, 24)),
    MAC_LAPTOP: (["office", "github", "news", "shopping", "ads", "cdn"], (8, 19)),
}


def _demo_rows(rng: random.Random, t_from: float, t_to: float) -> list[tuple[int, str, str, int]]:
    """(ts, client_ip, domain, status) for all demo clients with t_from <= ts < t_to."""
    rows: list[tuple[int, str, str, int]] = []
    t = int(t_from) // 3600 * 3600
    while t < t_to:
        hour = time.localtime(t).tm_hour
        for mac, (services, (h0, h1)) in _PROFILES.items():
            ip = DEMO_DEVICES[mac][0]
            # background lookups every hour, also at night
            for _ in range(rng.randint(2, 6)):
                rows.append((t + rng.randint(0, 3599), ip, rng.choice(_SERVICES["cdn"][0]), 3))
            if not (h0 <= hour < h1) or rng.random() < 0.35:
                continue
            for svc in rng.sample(services, k=min(len(services), rng.randint(1, 3))):
                domains, status = _SERVICES[svc]
                ts = t + rng.randint(0, 2400)
                for _ in range(rng.randint(10, 60)):
                    ts += rng.randint(5, 40)
                    rows.append((ts, ip, rng.choice(domains), status if status is not None else rng.choice((2, 3, 3))))
                    if rng.random() < 0.02:
                        rows.append((ts, ip, rng.choice(domains), 14))   # in-flight duplicate
        rows.append((t + rng.randint(0, 3599), DEMO_IP_ONLY, rng.choice(_SERVICES["unknown"][0]), 2))
        rows.append((t + rng.randint(0, 3599), "127.0.0.1", "pi.hole", 3))
        t += 3600
    return sorted(r for r in rows if t_from <= r[0] < t_to)


def build_demo_ftl(path: str, now: float, days: float = 8) -> None:
    """Create the demo FTL database, or catch it up to `now`."""
    import sqlite3
    rng = random.Random()
    c = sqlite3.connect(path)
    try:
        c.executescript(_FTL_SCHEMA)
        if not c.execute("SELECT 1 FROM network").fetchone():
            for mac, (ip, name) in DEMO_DEVICES.items():
                nid = c.execute("INSERT INTO network (hwaddr, interface, firstSeen, lastQuery, numQueries) "
                                "VALUES (?, 'eth0', ?, 0, 0)", (mac, int(now - days * 86400 - 3600))).lastrowid
                c.execute("INSERT INTO network_addresses (network_id, ip, lastSeen, name) VALUES (?,?,?,?)",
                          (nid, ip, int(now), name))
        last = c.execute("SELECT MAX(timestamp) FROM query_storage").fetchone()[0]
        rows = _demo_rows(rng, (last + 1) if last else now - days * 86400, now)
        for _ts, ip, domain, _st in rows:
            c.execute("INSERT OR IGNORE INTO domain_by_id (domain) VALUES (?)", (domain,))
            c.execute("INSERT OR IGNORE INTO client_by_id (ip, name) VALUES (?, NULL)", (ip,))
        dom = {d: i for i, d in c.execute("SELECT id, domain FROM domain_by_id")}
        cli = {ip: i for i, ip in c.execute("SELECT id, ip FROM client_by_id")}
        c.executemany("INSERT INTO query_storage (timestamp, type, status, domain, client) VALUES (?,1,?,?,?)",
                      [(ts, st, dom[d], cli[ip]) for ts, ip, d, st in rows])
        c.execute("UPDATE network_addresses SET lastSeen = ?", (int(now),))
        c.commit()
    finally:
        c.close()
