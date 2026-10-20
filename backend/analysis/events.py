"""Event Detection Engine.

Every finalized second (see metrics.MetricsHub) is passed through all detectors.
Each detector has
* a start condition that must hold for `start_n` seconds in a row,
* an end condition (hysteresis): `end_n` seconds in a row not met.

Baselines are rolling medians of the last 5 minutes, excluding seconds with an
active latency event (so that a long spike does not "pull up" the
baseline).
"""
from __future__ import annotations

import logging
import statistics
from collections import deque
from dataclasses import dataclass, field
from typing import Callable

log = logging.getLogger(__name__)

PING_SPIKE = "PING_SPIKE"
PACKET_LOSS = "PACKET_LOSS"
HIGH_JITTER = "HIGH_JITTER"
HIGH_UPLOAD = "HIGH_UPLOAD"
HIGH_DOWNLOAD = "HIGH_DOWNLOAD"
TCP_RETRANSMISSION_SPIKE = "TCP_RETRANSMISSION_SPIKE"
CONNECTION_DROP = "CONNECTION_DROP"
DNS_FAILURE = "DNS_FAILURE"
GATEWAY_LATENCY = "GATEWAY_LATENCY"
INTERNET_LATENCY = "INTERNET_LATENCY"
GAME_FLOW_GAP = "GAME_FLOW_GAP"

# Events that trigger an incident ("lag"). HIGH_UPLOAD/HIGH_DOWNLOAD are context only.
INCIDENT_TYPES = {PING_SPIKE, PACKET_LOSS, HIGH_JITTER, CONNECTION_DROP, GATEWAY_LATENCY,
                  INTERNET_LATENCY, TCP_RETRANSMISSION_SPIKE, GAME_FLOW_GAP, DNS_FAILURE}

EVENT_LABELS = {
    PING_SPIKE: "Ping spike", PACKET_LOSS: "Packet loss", HIGH_JITTER: "High jitter",
    HIGH_UPLOAD: "High upload", HIGH_DOWNLOAD: "High download",
    TCP_RETRANSMISSION_SPIKE: "TCP retransmissions", CONNECTION_DROP: "Connection drop",
    DNS_FAILURE: "DNS failure", GATEWAY_LATENCY: "Router latency", INTERNET_LATENCY: "Internet latency",
    GAME_FLOW_GAP: "Game packet gap",
}


@dataclass
class Event:
    id: int
    type: str
    ts_start: float
    severity: str = "warning"
    ts_end: float | None = None
    peak: float | None = None
    baseline: float | None = None
    target: str | None = None
    mac: str | None = None
    details: dict = field(default_factory=dict)
    incident_id: int | None = None

    def to_dict(self) -> dict:
        return {"id": self.id, "type": self.type, "label": EVENT_LABELS.get(self.type, self.type),
                "severity": self.severity, "ts_start": self.ts_start, "ts_end": self.ts_end,
                "peak": self.peak, "baseline": self.baseline, "target": self.target, "mac": self.mac,
                "details": self.details, "incident_id": self.incident_id}


@dataclass
class _DetState:
    active: Event | None = None
    hits: int = 0
    misses: int = 0


class RollingMedian:
    def __init__(self, size: int = 300):
        self.values: deque[float] = deque(maxlen=size)

    def add(self, v: float | None) -> None:
        if v is not None:
            self.values.append(v)

    def value(self) -> float | None:
        if len(self.values) < 5:
            return None
        return statistics.median(self.values)


class EventEngine:
    """Detects events from per-second rows. Callbacks: on_start(ev), on_end(ev)."""

    def __init__(self, thresholds, capacity_fn: Callable[[], tuple[float | None, float | None]],
                 next_id: Callable[[], int], top_device_fn: Callable[[dict, str], str | None] | None = None,
                 gaming_active_fn: Callable[[], bool] | None = None):
        self.t = thresholds
        self.capacity_fn = capacity_fn
        self.next_id = next_id
        self.top_device_fn = top_device_fn or (lambda row, direction: None)
        # Game flow gaps are only meaningful during a gaming session; otherwise
        # every UDP service with send pauses (e.g. sync services) causes false alarms.
        self.gaming_active_fn = gaming_active_fn or (lambda: False)
        self.on_start: list[Callable[[Event], None]] = []
        self.on_end: list[Callable[[Event], None]] = []
        self.on_update: list[Callable[[Event], None]] = []
        self.rtt_base = RollingMedian(300)
        self.gw_base = RollingMedian(300)
        self.state: dict[str, _DetState] = {}
        self._rtt10: deque[float | None] = deque(maxlen=10)
        self._loss10: deque[tuple[int, int]] = deque(maxlen=10)
        self._retr5: deque[tuple[int, int]] = deque(maxlen=5)
        self._dns_fail: dict[tuple[str, str], int] = {}
        self._drop_run = 0
        self.last_ts = 0

    # ------------------------------------------------------------------ public
    def open_events(self) -> list[Event]:
        return [s.active for s in self.state.values() if s.active is not None]

    def process(self, row: dict) -> None:
        ts = row["ts"]
        self.last_ts = ts
        t = self.t
        base = self.rtt_base.value()
        gwb = self.gw_base.value()
        rtt = row.get("rtt_avg")
        self._rtt10.append(rtt)
        self._loss10.append((row.get("probes") or 0, row.get("lost") or 0))
        if row.get("tcp_segs") is not None:
            self._retr5.append((row.get("tcp_segs") or 0, row.get("retrans") or 0))

        # ---------------- PING_SPIKE: short-term sharply increased internet RTT
        spike = False
        if rtt is not None:
            ref = base if base is not None else rtt
            spike = (rtt - ref >= t.spike_min_delta and (rtt >= t.ping_warning or rtt >= ref * t.spike_factor)) \
                or (base is None and rtt >= t.ping_critical)
        self._step(PING_SPIKE, spike, ts, value=rtt, baseline=base, start_n=1, end_n=2,
                   severity="critical" if rtt is not None and rtt >= t.ping_critical else "warning",
                   details={"rtt_max": row.get("rtt_max")})

        # ---------------- INTERNET_LATENCY: 10 s median persistently above the warning threshold
        vals = [v for v in self._rtt10 if v is not None]
        med10 = statistics.median(vals) if len(vals) >= 5 else None
        sustained = med10 is not None and med10 >= t.ping_warning and \
            (base is None or med10 - base >= t.spike_min_delta)
        self._step(INTERNET_LATENCY, sustained, ts, value=med10, baseline=base, start_n=3, end_n=5)

        # ---------------- GATEWAY_LATENCY: router answers slowly or not at all
        gw = row.get("gw_rtt")
        gw_probes, gw_lost = row.get("gw_probes") or 0, row.get("gw_lost") or 0
        gw_bad = (gw is not None and gw >= max(t.gateway_warning, (gwb or 0) * 5)) or \
                 (gw_probes > 0 and gw_lost == gw_probes)
        self._step(GATEWAY_LATENCY, gw_bad, ts, value=gw, baseline=gwb, start_n=2, end_n=3,
                   details={"lost": gw_lost, "probes": gw_probes})

        # ---------------- PACKET_LOSS: loss in the 10 s window
        p10 = sum(p for p, _ in self._loss10)
        l10 = sum(l for _, l in self._loss10)
        pct10 = 100.0 * l10 / p10 if p10 else 0.0
        loss_now = (row.get("lost") or 0) > 0 and l10 >= t.packet_loss_min_lost and pct10 >= t.packet_loss_warning
        st = self.state.get(PACKET_LOSS)
        keep = st is not None and st.active is not None and (row.get("lost") or 0) > 0
        self._step(PACKET_LOSS, loss_now or keep, ts, value=round(pct10, 1), start_n=1, end_n=3,
                   severity="critical" if pct10 >= 5 else "warning",
                   details={"lost_10s": l10, "probes_10s": p10})

        # ---------------- HIGH_JITTER
        jit = row.get("jitter")
        self._step(HIGH_JITTER, jit is not None and jit >= t.jitter_warning, ts, value=jit,
                   start_n=2, end_n=3)

        # ---------------- CONNECTION_DROP: all internet targets without reply for N s
        probes, lost = row.get("probes") or 0, row.get("lost") or 0
        all_lost = probes > 0 and lost == probes
        self._step(CONNECTION_DROP, all_lost, ts, value=None, start_n=t.connection_drop_seconds, end_n=1,
                   severity="critical", details={"gateway_reachable": gw is not None})

        # ---------------- HIGH_UPLOAD / HIGH_DOWNLOAD (only with known capacity)
        cap_down, cap_up = self.capacity_fn()
        up, down = row.get("up_bps"), row.get("down_bps")
        hu = up is not None and cap_up and up >= cap_up * t.high_upload_pct / 100
        hd = down is not None and cap_down and down >= cap_down * t.high_download_pct / 100
        self._step(HIGH_UPLOAD, bool(hu), ts, value=up, start_n=2, end_n=3,
                   mac=self.top_device_fn(row, "up") if hu else None,
                   details={"capacity_bps": cap_up, "util_pct": round(100 * up / cap_up, 1) if hu else None})
        self._step(HIGH_DOWNLOAD, bool(hd), ts, value=down, start_n=2, end_n=3,
                   mac=self.top_device_fn(row, "down") if hd else None,
                   details={"capacity_bps": cap_down, "util_pct": round(100 * down / cap_down, 1) if hd else None})

        # ---------------- TCP_RETRANSMISSION_SPIKE (5 s window)
        segs = sum(s for s, _ in self._retr5)
        retr = sum(r for _, r in self._retr5)
        rpct = 100.0 * retr / segs if segs else 0.0
        self._step(TCP_RETRANSMISSION_SPIKE, segs >= 50 and retr >= 5 and rpct >= t.retrans_warning_pct,
                   ts, value=round(rpct, 2), start_n=1, end_n=5,
                   details={"retrans_down": row.get("retrans_down"), "retrans_up": row.get("retrans_up")})

        # ---------------- GAME_FLOW_GAP: gap in the downstream of the game flow
        # Only during a gaming session and only for a plausible game packet stream
        # (at least 10 packets/s) - otherwise every UDP send pause would be a "game packet gap".
        gap = row.get("game_gap_ms")
        game_flow = self.gaming_active_fn() and (row.get("game_pps") or 0) >= 10
        self._step(GAME_FLOW_GAP, game_flow and gap is not None and gap >= t.game_gap_ms,
                   ts, value=gap, start_n=1, end_n=2, details={"game_pps": row.get("game_pps")})

        # ---------------- DNS_FAILURE: 2 consecutive failures per server AND kind
        # Cached and uncached are counted separately. Otherwise a broken upstream
        # would be masked: the cached probe keeps answering from the cache and
        # would reset the counter every other time.
        for server, ms, status, kind in row.get("dns") or []:
            fail_key = (server, kind)
            key = f"{DNS_FAILURE}:{server}:{kind}"
            if ms is None or status == "servfail":
                self._dns_fail[fail_key] = self._dns_fail.get(fail_key, 0) + 1
            else:
                self._dns_fail[fail_key] = 0
            label = server if kind == "cached" else f"{server} (ungecacht)"
            self._step(key, self._dns_fail[fail_key] >= 2, ts, value=None, start_n=1, end_n=1,
                       target=label, event_type=DNS_FAILURE, details={"status": status, "kind": kind})

        # Feed baselines only with "quiet" seconds
        if not spike and not sustained:
            self.rtt_base.add(rtt)
        if not gw_bad:
            self.gw_base.add(gw)

    def close_all(self, ts: float) -> None:
        for key, st in self.state.items():
            if st.active:
                self._end(st, ts)

    # ------------------------------------------------------------------ internals
    def _step(self, key: str, cond: bool, ts: float, value: float | None, start_n: int, end_n: int,
              baseline: float | None = None, severity: str = "warning", details: dict | None = None,
              target: str | None = None, mac: str | None = None, event_type: str | None = None) -> None:
        st = self.state.get(key)
        if st is None:
            st = self.state[key] = _DetState()
        if cond:
            st.hits += 1
            st.misses = 0
            if st.active is None and st.hits >= start_n:
                ev = Event(id=self.next_id(), type=event_type or key, ts_start=ts - (start_n - 1),
                           severity=severity, peak=value, baseline=_r(baseline), target=target, mac=mac,
                           details=dict(details or {}))
                st.active = ev
                for cb in self.on_start:
                    cb(ev)
            elif st.active is not None:
                ev = st.active
                changed = False
                if value is not None and (ev.peak is None or _worse(ev.type, value, ev.peak)):
                    ev.peak = value
                    changed = True
                    if details:
                        ev.details.update({k: v for k, v in details.items() if v is not None})
                if severity == "critical" and ev.severity != "critical":
                    ev.severity = "critical"
                    changed = True
                if mac and not ev.mac:
                    ev.mac = mac
                    changed = True
                if changed:
                    for cb in self.on_update:
                        cb(ev)
        else:
            st.hits = 0
            if st.active is not None:
                st.misses += 1
                if st.misses >= end_n:
                    self._end(st, ts - end_n)

    def _end(self, st: _DetState, ts: float) -> None:
        ev = st.active
        assert ev is not None
        ev.ts_end = max(ts, ev.ts_start)
        st.active = None
        st.misses = 0
        for cb in self.on_end:
            cb(ev)


def _worse(etype: str, new: float, old: float) -> bool:
    return new > old


def _r(v: float | None) -> float | None:
    return None if v is None else round(v, 2)
