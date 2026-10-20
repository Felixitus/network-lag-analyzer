"""Per-second assembler and metrics.

All raw data (ICMP probes, DNS probes, traffic bins, TR-064 rates) is bundled per
second. A second T is only finalized once all probes sent in T have been
answered or have timed out (T + 1 + timeout). After that the row is
immutable and is distributed to the event engine, database and live
stream.

No fake data: if a source is missing, the value stays None.
"""
from __future__ import annotations

import logging
import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Callable, Iterable

log = logging.getLogger(__name__)

RING_SECONDS = 3600
JITTER_WINDOW = 10.0
LOSS_WINDOWS = (5, 10, 30, 60, 300)

# Indices in the device bin (identical to the capture process)
RX, TX, RXP, TXP, UDP, LAN, RETR = range(7)


# ---------------------------------------------------------------- pure functions
def jitter_ms(rtts: Iterable[float | None]) -> float | None:
    """Mean absolute difference of consecutive successful RTTs.

    Follows the idea of the RFC 3550 interarrival jitter estimate, but
    unsmoothed over a fixed window so that spikes stay visible.
    Lost probes (None) are skipped. At least 2 values required.
    """
    vals = [r for r in rtts if r is not None]
    if len(vals) < 2:
        return None
    diffs = [abs(b - a) for a, b in zip(vals, vals[1:])]
    return sum(diffs) / len(diffs)


def loss_percent(probes: int, lost: int) -> float | None:
    if probes <= 0:
        return None
    return 100.0 * lost / probes


def median_or_none(vals: list[float]) -> float | None:
    return statistics.median(vals) if vals else None


@dataclass
class TargetInfo:
    target_id: int
    address: str
    kind: str          # gateway | internet | game
    name: str | None = None


@dataclass
class _SecondAcc:
    samples: dict[int, list] = field(default_factory=lambda: defaultdict(list))
    dns: list = field(default_factory=list)


class MetricsHub:
    """Collects raw data, finalizes seconds and keeps a 1 h ring buffer."""

    def __init__(self, timeout: float = 1.5, ring_seconds: int = RING_SECONDS):
        self.timeout = timeout
        self.targets: dict[int, TargetInfo] = {}
        self._acc: dict[int, _SecondAcc] = defaultdict(_SecondAcc)
        self._traffic: dict[int, dict] = {}
        self._tr064: dict[int, tuple[float, float]] = {}
        self._last_tr064: tuple[float, float, float] | None = None  # ts, down, up
        self.ring: deque[dict] = deque(maxlen=ring_seconds)
        self._jitter_hist: dict[int, deque] = defaultdict(lambda: deque(maxlen=400))
        self.subscribers: list[Callable[[dict], None]] = []
        self.patch_subscribers: list[Callable[[dict], None]] = []
        self.last_finalized: int = 0
        self.capture_active_until: float = 0.0
        self.late_traffic = 0
        self.last_bin_sec: int | None = None
        # Target states: detects targets that do not answer ICMP at all (any more)
        self._tstate: dict[int, dict] = {}
        self.unreachable_after = 30          # seconds without any reply
        # How long to wait for late traffic bins (buffered router stream)
        self.traffic_grace: float = 6.0
        self.dns_primary: str | None = None

    def reset_pending(self) -> None:
        """Discard started, not yet completed seconds.

        Needed after a jump of the system clock: the half-finished seconds belong
        to the old time base and would otherwise end up under a wrong timestamp.
        The ring buffer is kept - what was completely measured is correct.
        `last_finalized` is reset so that the time base locks in again
        (important for a backwards jump, otherwise evaluation would stall).
        """
        self._acc.clear()
        self._traffic.clear()
        self._tr064.clear()
        self._last_tr064 = None
        self.last_bin_sec = None
        self.last_finalized = 0

    def drop_range(self, start: float | None, end: float) -> int:
        """Remove seconds from the ring buffer that were just deleted.

        Otherwise the live charts would still show values that no longer exist in
        the database - and on the next reload they would suddenly be gone.
        """
        keep = [r for r in self.ring if not (r["ts"] < end and (start is None or r["ts"] >= start))]
        removed = len(self.ring) - len(keep)
        if removed:
            self.ring.clear()
            self.ring.extend(keep)
        return removed

    # --------------------------------------------------------------- targets
    def set_target(self, t: TargetInfo) -> None:
        self.targets[t.target_id] = t

    def remove_target(self, target_id: int) -> None:
        self.targets.pop(target_id, None)
        self._tstate.pop(target_id, None)

    # --------------------------------------------------------------- inputs
    def add_probe(self, target_id: int, send_ts: float, rtt_ms: float | None) -> None:
        sec = int(send_ts)
        if sec <= self.last_finalized:
            return  # too late (should not happen because of the timeout wait)
        self._acc[sec].samples[target_id].append(rtt_ms)

    def add_dns(self, server: str, ts: float, ms: float | None, status: str,
                kind: str = "cached") -> None:
        """kind: "cached" measures the resolver itself, "uncached" the whole path to the upstream."""
        sec = int(ts)
        if sec <= self.last_finalized:
            sec = self.last_finalized + 1
        self._acc[sec].dns.append((server, ms, status, kind))

    def add_traffic_bin(self, sec: int, devices: dict[str, list[int]], glob: dict) -> None:
        """A per-second bin from the capture process (empty bins too = 'measured, 0')."""
        self.capture_active_until = max(self.capture_active_until, sec + 10)
        self.last_bin_sec = sec if self.last_bin_sec is None else max(self.last_bin_sec, sec)
        if sec <= self.last_finalized:
            self.late_traffic += 1
            self._patch_late_traffic(sec, devices, glob)
            return
        cur = self._traffic.get(sec)
        if cur is None:
            self._traffic[sec] = {"devices": devices, "glob": dict(glob)}
        else:  # merge (should rarely happen)
            for mac, v in devices.items():
                if mac in cur["devices"]:
                    cur["devices"][mac] = [a + b for a, b in zip(cur["devices"][mac], v)]
                else:
                    cur["devices"][mac] = v
            for k, v in glob.items():
                if isinstance(v, (int, float)) and isinstance(cur["glob"].get(k), (int, float)):
                    cur["glob"][k] = max(cur["glob"][k], v) if k.endswith(("_gap_ms", "_max")) else cur["glob"][k] + v
                else:
                    cur["glob"][k] = v

    def add_wan_rate(self, ts: float, down_bps: float, up_bps: float) -> None:
        """TR-064 total rate. Applies retroactively to the seconds since the last query."""
        start = int(self._last_tr064[0]) + 1 if self._last_tr064 else int(ts) - 1
        start = max(start, int(ts) - 10, self.last_finalized + 1)
        for s in range(start, int(ts) + 1):
            self._tr064[s] = (down_bps, up_bps)
        self._last_tr064 = (ts, down_bps, up_bps)

    # --------------------------------------------------------------- finalization
    def finalize_due(self, now: float | None = None) -> list[dict]:
        now = time.time() if now is None else now
        horizon = int(now - 1 - self.timeout - 0.2)
        # The FRITZ!Box delivers the capture buffered (bursts of several seconds).
        # So wait briefly for the traffic bins instead of finalizing rows without traffic.
        if self.last_bin_sec is not None and self.capture_active(now):
            horizon = min(horizon, max(self.last_bin_sec, int(now - self.traffic_grace)))
        if self.last_finalized == 0:
            candidates = sorted(s for s in list(self._acc) + list(self._traffic) if s <= horizon)
            if not candidates:
                return []
            self.last_finalized = candidates[0] - 1
        elif horizon - self.last_finalized > 600:
            # Gap (e.g. after suspend/clock jump): do not create arbitrarily many empty seconds
            self.last_finalized = horizon - 600
        rows = []
        for sec in range(self.last_finalized + 1, horizon + 1):
            rows.append(self._finalize_second(sec))
            self.last_finalized = sec
        # Clean up
        for d in (self._acc, self._traffic, self._tr064):
            for k in [k for k in d if k <= self.last_finalized]:
                del d[k]
        for row in rows:
            self.ring.append(row)
            for cb in self.subscribers:
                try:
                    cb(row)
                except Exception:  # pragma: no cover - subscriber errors must not block
                    log.exception("Subscriber error")
        return rows

    def _finalize_second(self, sec: int) -> dict:
        acc = self._acc.get(sec) or _SecondAcc()
        per_target: dict[int, dict] = {}
        inet_means: list[float] = []
        inet_all: list[float] = []
        probes = lost = 0
        gw_vals: list[float] = []
        gw_probes = gw_lost = 0
        game_vals: list[float] = []

        for tid, samples in acc.samples.items():
            t = self.targets.get(tid)
            if t is None:
                continue
            ok = [s for s in samples if s is not None]
            n_lost = len(samples) - len(ok)
            per_target[tid] = {
                "rtt": sum(ok) / len(ok) if ok else None,
                "max": max(ok) if ok else None,
                "probes": len(samples),
                "lost": n_lost,
            }
            hist = self._jitter_hist[tid]
            for s in samples:
                hist.append((sec, s))
            if t.kind == "internet":
                # A target that permanently does not answer at all (ICMP blocked, server gone)
                # must not count as packet loss of your own line.
                if self._target_health(tid, bool(ok), n_lost, sec):
                    per_target[tid]["unreachable"] = True
                    continue
                probes += len(samples)
                lost += n_lost
                if ok:
                    inet_means.append(sum(ok) / len(ok))
                    inet_all.extend(ok)
            elif t.kind == "gateway":
                gw_probes += len(samples)
                gw_lost += n_lost
                gw_vals.extend(ok)
            elif t.kind == "game":
                game_vals.extend(ok)

        # Jitter: per internet target over JITTER_WINDOW, median across targets
        jit_vals = []
        for tid, t in self.targets.items():
            if t.kind != "internet":
                continue
            hist = self._jitter_hist.get(tid)
            if not hist:
                continue
            window = [r for (s, r) in hist if sec - JITTER_WINDOW < s <= sec]
            j = jitter_ms(window)
            if j is not None:
                jit_vals.append(j)

        row: dict = {
            "ts": sec,
            "rtt_avg": _r(median_or_none(inet_means)),
            "rtt_min": _r(min(inet_all)) if inet_all else None,
            "rtt_max": _r(max(inet_all)) if inet_all else None,
            "gw_rtt": _r(sum(gw_vals) / len(gw_vals)) if gw_vals else None,
            "gw_probes": gw_probes,
            "gw_lost": gw_lost,
            "jitter": _r(median_or_none(jit_vals)),
            "loss_pct": _r(loss_percent(probes, lost)),
            "probes": probes,
            "lost": lost,
            "game_rtt": _r(sum(game_vals) / len(game_vals)) if game_vals else None,
            "targets": per_target,
            "down_bps": None, "up_bps": None, "traffic_src": None,
            "retrans": None, "tcp_segs": None, "retrans_down": None, "retrans_up": None,
            "game_pps": None, "game_gap_ms": None,
            "devices": {},
            "dns_ms": None, "dns_fail": None, "dns": [],
        }

        tr = self._traffic.get(sec)
        if tr is not None:
            _apply_traffic(row, tr["devices"], tr["glob"])
        elif sec in self._tr064:
            d, u = self._tr064[sec]
            row.update({"down_bps": d, "up_bps": u, "traffic_src": "tr064"})

        if acc.dns:
            row["dns"] = acc.dns
            # dns_ms is deliberately the response time of your own resolver for a
            # cached name - that is the number that answers "is Pi-hole still responding?".
            primary = [ms for (srv, ms, st, k) in acc.dns
                       if srv == self.dns_primary and ms is not None and k == "cached"]
            anyms = [ms for (_s, ms, _st, k) in acc.dns if ms is not None and k == "cached"]
            row["dns_ms"] = _r(primary[0] if primary else (anyms[0] if anyms else None))
            row["dns_fail"] = sum(1 for (_s, ms, st, _k) in acc.dns if ms is None or st == "servfail")
        return row

    # ------------------------------------------------------------ target reachability
    def _target_health(self, tid: int, ok: bool, n_lost: int, sec: int) -> bool:
        """Maintains the state of an internet target and says whether to exclude it right now.

        A target counts as "not answering" if it has not delivered a single reply for
        `unreachable_after` seconds in a row WHILE at least one other internet target
        answers. If all targets fail at once, that is a real outage and is counted
        normally as packet loss or CONNECTION_DROP.
        """
        st = self._tstate.setdefault(tid, {"consec_lost": 0, "last_ok": None, "unreachable": False,
                                           "since": None})
        if ok:
            st.update(consec_lost=0, last_ok=sec, unreachable=False, since=None)
            return False
        st["consec_lost"] += max(1, n_lost)
        if st["unreachable"]:
            return True
        # "Currently" really means currently here: in a total outage nobody answers any more,
        # then no target may be excluded (otherwise the real outage would vanish).
        others_ok = any(s["last_ok"] is not None and sec - s["last_ok"] <= 5
                        for k, s in self._tstate.items() if k != tid)
        if st["consec_lost"] >= self.unreachable_after and others_ok:
            st["unreachable"] = True
            st["since"] = sec - st["consec_lost"] + 1
            t = self.targets.get(tid)
            log.warning("Target %s has not answered ICMP for %s s - excluded from the "
                        "loss calculation", t.address if t else tid, st["consec_lost"])
            return True
        return False

    def target_health(self, window: int = 120) -> list[dict]:
        """State and loss rate per target (for status, UI and troubleshooting)."""
        rows = list(self.ring)[-window:]
        out = []
        for tid, t in self.targets.items():
            st = self._tstate.get(tid, {})
            probes = sum((r.get("targets") or {}).get(tid, {}).get("probes", 0) for r in rows)
            lost = sum((r.get("targets") or {}).get(tid, {}).get("lost", 0) for r in rows)
            rtts = [(r["targets"][tid] or {}).get("rtt") for r in rows
                    if (r.get("targets") or {}).get(tid, {}).get("rtt") is not None]
            out.append({"id": tid, "address": t.address, "name": t.name, "kind": t.kind,
                        "unreachable": bool(st.get("unreachable")), "since": st.get("since"),
                        "last_ok": st.get("last_ok"), "consec_lost": st.get("consec_lost", 0),
                        "probes": probes, "lost": lost,
                        "loss_pct": _r(loss_percent(probes, lost)),
                        "rtt_avg": _r(sum(rtts) / len(rtts)) if rtts else None,
                        "window_seconds": len(rows)})
        return out

    def _patch_late_traffic(self, sec: int, devices: dict, glob: dict) -> None:
        """Bin arrived after finalizing: patch the row in the ring buffer and notify subscribers."""
        for row in reversed(self.ring):
            if row["ts"] == sec:
                if row["traffic_src"] in (None, "tr064"):
                    _apply_traffic(row, devices, glob)
                    row["late"] = True
                    for cb in self.patch_subscribers:
                        try:
                            cb(row)
                        except Exception:  # pragma: no cover
                            log.exception("Patch subscriber error")
                break
            if row["ts"] < sec:
                break

    # --------------------------------------------------------------- queries
    def window(self, seconds: int, end: int | None = None) -> list[dict]:
        end = self.last_finalized if end is None else end
        start = end - seconds + 1
        return [r for r in self.ring if start <= r["ts"] <= end]

    def range(self, t0: float, t1: float) -> list[dict]:
        return [r for r in self.ring if t0 <= r["ts"] <= t1]

    def loss_windows(self) -> dict[str, float | None]:
        out = {}
        rows = list(self.ring)
        for w in LOSS_WINDOWS:
            sel = rows[-w:]
            p = sum(r["probes"] for r in sel)
            l = sum(r["lost"] for r in sel)
            out[f"{w}s"] = _r(loss_percent(p, l))
        return out

    def capture_active(self, now: float | None = None) -> bool:
        return (time.time() if now is None else now) < self.capture_active_until

    def internet_online(self) -> bool | None:
        rows = list(self.ring)[-5:]
        if not rows or sum(r["probes"] for r in rows) == 0:
            return None
        return any(r["rtt_avg"] is not None for r in rows)


def _apply_traffic(row: dict, devices: dict, glob: dict) -> None:
    """Transfers a capture bin into a per-second row (also when patching late bins)."""
    tcp = glob.get("tcp_analysis", True)
    row.update({
        "down_bps": glob.get("wan_rx", 0) * 8.0,
        "up_bps": glob.get("wan_tx", 0) * 8.0,
        "traffic_src": "capture" + ("~" if glob.get("sampled") else ""),
        "retrans": (glob.get("retrans_down", 0) + glob.get("retrans_up", 0)) if tcp else None,
        "tcp_segs": glob.get("tcp_segs") if tcp else None,
        "retrans_down": glob.get("retrans_down") if tcp else None,
        "retrans_up": glob.get("retrans_up") if tcp else None,
        "game_pps": glob.get("game_pps"),
        "game_gap_ms": glob.get("game_gap_ms"),
        "devices": devices,
    })


def _r(v: float | None, nd: int = 2) -> float | None:
    return None if v is None else round(v, nd)
