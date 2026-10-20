"""Gaming Mode: session management, automatic detection, game server detection.

During a session:
* the ICMP measuring interval is increased (4 probes/s instead of 1/s),
* the capture process logs the game flow of the gaming PC to the second
  (packets/s, gaps in the downstream = "server sends nothing"),
* the game server is detected as the strongest bidirectional UDP flow and - if it
  answers ICMP - pinged additionally.

Automatic detection: bidirectional UDP flow of the gaming PC with at least
`min_pps` packets/s per direction over `min_seconds` seconds.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field

from ..util.netinfo import is_private

log = logging.getLogger(__name__)

ICMP_GIVE_UP_PROBES = 12


@dataclass
class GamingSession:
    id: int
    ts_start: float
    mac: str | None
    device_ip: str | None
    auto_detected: bool
    server_ip: str | None = None
    server_port: int | None = None
    ts_end: float | None = None
    server_icmp: str = "unknown"         # unknown | ok | blocked
    server_candidates: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"id": self.id, "ts_start": self.ts_start, "ts_end": self.ts_end, "mac": self.mac,
                "device_ip": self.device_ip, "server_ip": self.server_ip, "server_port": self.server_port,
                "auto_detected": self.auto_detected, "server_icmp": self.server_icmp}


class GamingDetector:
    """State machine for automatic start/stop."""

    def __init__(self, min_pps: float, min_seconds: int, stop_after_idle: int):
        self.min_pps = min_pps
        self.min_seconds = min_seconds
        self.stop_after_idle = stop_after_idle
        self._run_start: float | None = None
        self.last_game_traffic: float = 0.0

    def feed(self, now: float, gaming_mac: str | None, candidates: list[dict]) -> tuple[bool, dict | None]:
        """Returns (game traffic detected for min_seconds, best candidate)."""
        best = None
        if gaming_mac:
            mine = [c for c in candidates if c["mac"] == gaming_mac and not is_private(c["remote_ip"])
                    and c["pps_up"] >= self.min_pps and c["pps_down"] >= self.min_pps]
            if mine:
                best = max(mine, key=lambda c: c["pps_up"] + c["pps_down"])
        if best:
            self.last_game_traffic = now
            if self._run_start is None:
                self._run_start = now
        elif now - self.last_game_traffic > 5:
            self._run_start = None
        sustained = self._run_start is not None and now - self._run_start >= self.min_seconds
        return sustained, best

    def idle_for(self, now: float) -> float:
        return now - self.last_game_traffic if self.last_game_traffic else float("inf")


def pick_server(session: GamingSession, cand: dict | None) -> bool:
    """Updates the game server of the session. True if the server changed."""
    if not cand:
        return False
    key = (cand["remote_ip"], cand["remote_port"])
    c = session.server_candidates.setdefault(key, 0)
    session.server_candidates[key] = c + cand["pps_up"] + cand["pps_down"]
    best_key = max(session.server_candidates, key=session.server_candidates.get)
    if (session.server_ip, session.server_port) != best_key:
        # Switch only if the new candidate clearly dominates (server change between rounds)
        cur = session.server_candidates.get((session.server_ip, session.server_port), 0)
        if session.server_ip is None or session.server_candidates[best_key] > cur * 1.5:
            session.server_ip, session.server_port = best_key
            session.server_icmp = "unknown"
            return True
    return False


def summarize_session(rows: list[dict], events: list[dict], incidents: list[dict]) -> dict:
    """Summary after the session ends (see requirement 11)."""
    rtt = [r["rtt_avg"] for r in rows if r.get("rtt_avg") is not None]
    rmax = [r["rtt_max"] for r in rows if r.get("rtt_max") is not None]
    jit = [r["jitter"] for r in rows if r.get("jitter") is not None]
    game_rtt = [r["game_rtt"] for r in rows if r.get("game_rtt") is not None]
    gaps = [r["game_gap_ms"] for r in rows if r.get("game_gap_ms") is not None]
    probes = sum(r.get("probes") or 0 for r in rows)
    lost = sum(r.get("lost") or 0 for r in rows)
    causes: dict[str, int] = {}
    for i in incidents:
        lbl = i.get("category_label") or i.get("category") or "unknown"
        causes[lbl] = causes.get(lbl, 0) + 1
    return {
        "seconds": len(rows),
        "ping_avg": round(sum(rtt) / len(rtt), 1) if rtt else None,
        "ping_max": max(rmax) if rmax else None,
        "jitter_avg": round(sum(jit) / len(jit), 1) if jit else None,
        "loss_pct": round(100 * lost / probes, 2) if probes else None,
        "packet_loss_events": sum(1 for e in events if e["type"] == "PACKET_LOSS"),
        "lag_events": len(incidents),
        "game_rtt_avg": round(sum(game_rtt) / len(game_rtt), 1) if game_rtt else None,
        "game_gap_max": max(gaps) if gaps else None,
        "game_gap_events": sum(1 for e in events if e["type"] == "GAME_FLOW_GAP"),
        "causes": dict(sorted(causes.items(), key=lambda kv: -kv[1])),
        "generated_at": time.time(),
    }
