"""Simulierte Netzwerkdaten – NUR für Tests und den expliziten Dev-Modus (`dev_mode: true`).

Im produktiven Betrieb wird dieses Modul nie importiert. Im Dev-Modus zeigt die
Weboberfläche dauerhaft das Banner "DEMO-MODUS".

Szenarien (auch in tests/test_scenarios.py verwendet):
  normal, upload_saturation, download_saturation, isp_loss, local_gateway,
  single_target, dns_outage, game_server
"""
from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass

GW_TID, T1, T2, T3 = 1, 2, 3, 4          # Ziel-IDs im Testaufbau
MAC_PC = "02:00:00:00:00:20"
MAC_IPHONE = "02:00:00:00:00:42"
MAC_TV = "02:00:00:00:00:51"
MAC_LAPTOP = "02:00:00:00:00:33"
# Adressen aus den für Dokumentation reservierten Bereichen (RFC 5737 TEST-NET-1
# 192.0.2.0/24, RFC 2606 für Namen) und lokal verwaltete MACs (02:...). So sind
# Demo-Geräte auf den ersten Blick von echten zu unterscheiden und kollidieren
# nie mit einem realen Heimnetz.
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
    devices: dict         # mac → [rx, tx, rxp, txp, udp, lan, retrans]  (Bytes)
    glob: dict
    dns: list             # [(server, ms, status)]


def _dev(rx_bps: float, tx_bps: float, udp_frac: float = 0.0, retrans: int = 0) -> list[int]:
    rx, tx = int(rx_bps / 8), int(tx_bps / 8)
    return [rx, tx, max(1, rx // 1200) if rx else 0, max(1, tx // 400) if tx else 0,
            int((rx + tx) * udp_frac), 0, retrans]


def make_second(scenario: str, k: int, rng: random.Random, probes_per_target: int = 1,
                onset: int = 5, gaming: bool = False) -> Second:
    """Erzeugt eine Sekunde Messdaten. k = Sekunde relativ zum Szenario-Beginn."""
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
    """Speist eine simulierte Sekunde in den MetricsHub ein."""
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
    """Dev-Modus: speist in Echtzeit simulierte Daten ein (Normalbetrieb + zyklische Störungen)."""

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
        core.fritz_status = {"enabled": False, "note": "Dev-Modus"}
        core.pihole_status = {"enabled": False, "note": "Dev-Modus"}
        core.hub.dns_primary = "127.0.0.1"
        gw = [tid for tid, t in core.targets.items() if t["kind"] == "gateway"]
        inet = [tid for tid, t in core.targets.items() if t["kind"] == "internet"]
        self.tid_map = dict(zip([GW_TID], gw)) | dict(zip([T1, T2, T3], inet))
        now = time.time()
        for mac, (ip, name) in DEMO_DEVICES.items():
            core.devices.observe(mac, ip=ip, hostname=name, source="simulated", seen=now)
        # 5 Minuten Vorlauf, damit Baselines und Charts sofort gefüllt sind
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
            self.k += 1
            await asyncio.sleep(max(0.05, sec + 1.02 - time.time()))
