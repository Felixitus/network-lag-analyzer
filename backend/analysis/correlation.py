"""Incident correlation and "I JUST HAD LAG" analysis.

* Lag-relevant events open an incident. Further events that start in the
  meantime are attached. The incident closes when no lag event has been open
  for 2 minutes (max. 30 min per incident).
* Not every closed incident is kept: a problem of one external target while the
  line is fine, and a blip of a few seconds that no rule can explain, stay events.
* After closing, the window [start − 30 s, end + 5 s] is analyzed with the rules
  from root_cause.py.
* A user report analyzes the last 10 s / 30 s / 60 s / 5 min and immediately
  creates an incident with a timeline of the findings.
"""
from __future__ import annotations

import logging
import statistics
from dataclasses import dataclass, field
from typing import Callable

from .events import EVENT_LABELS, INCIDENT_TYPES, Event
from .root_cause import Window, analyze

log = logging.getLogger(__name__)

PRE_SECONDS = 30
POST_SECONDS = 5
# A loss episode on a bad cable is a burst every few seconds for hours. With 5 s the Pi
# recorded ~800 incidents a day, 72 % of them within a minute of the previous one -
# the same problem, cut into pieces. 2 minutes keep one episode one incident.
CLOSE_AFTER = 120
MAX_INCIDENT = 1800
BLIP_SECONDS = 5
REPORT_WINDOWS = (10, 30, 60, 300)


@dataclass
class Incident:
    id: int
    source: str                 # auto | user
    ts_start: float
    ts_end: float | None = None
    reported_at: float | None = None
    title: str | None = None
    cause: str | None = None
    category: str | None = None
    confidence: str | None = None
    analysis: dict = field(default_factory=dict)
    event_ids: list[int] = field(default_factory=list)
    session_id: int | None = None
    last_activity: float = 0.0

    def to_dict(self) -> dict:
        return {"id": self.id, "source": self.source, "ts_start": self.ts_start, "ts_end": self.ts_end,
                "reported_at": self.reported_at, "title": self.title, "cause": self.cause,
                "category": self.category, "confidence": self.confidence, "analysis": self.analysis,
                "session_id": self.session_id}


def dismiss_reason(inc: Incident, result: dict) -> str | None:
    """Why a closed incident is no incident after all - or None to keep it.

    Kept apart from the analysis: the rules still name what happened, this only decides
    whether it is worth an entry of its own. The events are stored either way."""
    if result.get("category") == "target":
        # One external target was slow or lost packets while the router and the other
        # targets were fine: a problem of that server or its route, not of this line.
        # (A game server stays an incident - category "game_server".)
        return "single_target"
    duration = (inc.ts_end or inc.ts_start) - inc.ts_start
    if duration < BLIP_SECONDS and result.get("confidence") == "low" and result.get("category") in ("loss", "unknown", None):
        return "blip"
    return None


DISMISS_LABELS = {"single_target": "only one external target affected", "blip": f"shorter than {BLIP_SECONDS} s, no cause found"}


class Correlator:
    def __init__(self, window_fn: Callable[[float, float], Window], next_id: Callable[[], int],
                 on_close: Callable[[Incident, list[Event]], None], on_open: Callable[[Incident], None] | None = None,
                 on_dismiss: Callable[[Incident, list[Event], str], None] | None = None,
                 dismiss_fn: Callable[[Incident, dict], str | None] | None = None):
        self.window_fn = window_fn
        self.next_id = next_id
        self.on_close = on_close
        self.on_open = on_open or (lambda i: None)
        self.on_dismiss = on_dismiss
        self.dismiss_fn = dismiss_fn
        self.current: Incident | None = None
        self.open_events: dict[int, Event] = {}
        self.events: list[Event] = []
        self.session_id_fn: Callable[[], int | None] = lambda: None

    # ------------------------------------------------------------------ event callbacks
    def event_started(self, ev: Event) -> None:
        if ev.type not in INCIDENT_TYPES:
            if self.current is not None:
                self.events.append(ev)   # take context along (e.g. HIGH_UPLOAD)
            return
        if self.current is None:
            self.current = Incident(id=self.next_id(), source="auto", ts_start=ev.ts_start,
                                    session_id=self.session_id_fn())
            self.events = []
            self.on_open(self.current)
        ev.incident_id = self.current.id
        self.current.event_ids.append(ev.id)
        self.current.last_activity = ev.ts_start
        self.open_events[ev.id] = ev
        self.events.append(ev)

    def event_ended(self, ev: Event) -> None:
        if ev.id in self.open_events:
            del self.open_events[ev.id]
            if self.current is not None:
                self.current.last_activity = max(self.current.last_activity, ev.ts_end or ev.ts_start)

    def tick(self, ts: float) -> Incident | None:
        """Call once per finalized second; closes and analyzes due incidents."""
        inc = self.current
        if inc is None:
            return None
        too_long = ts - inc.ts_start >= MAX_INCIDENT
        if (not self.open_events and ts - inc.last_activity >= CLOSE_AFTER + POST_SECONDS) or too_long:
            inc.ts_end = inc.last_activity if not too_long else ts
            self._finish(inc)
            self.current = None
            if too_long and self.open_events:
                # new incident for the events that are still open
                cont = Incident(id=self.next_id(), source="auto", ts_start=ts, last_activity=ts,
                                session_id=self.session_id_fn())
                for e in self.open_events.values():
                    cont.event_ids.append(e.id)
                self.current = cont
                self.events = list(self.open_events.values())
                self.on_open(cont)
            return inc
        return None

    def _finish(self, inc: Incident) -> None:
        t0, t1 = int(inc.ts_start), int(inc.ts_end or inc.ts_start)
        w = self.window_fn(t0, t1)
        w.events = [e.to_dict() for e in self.events]
        result = analyze(w)
        # The events are stored in their own table with this incident's id; a copy here
        # was a quarter of every incident's size.
        result["event_ids"] = [e.id for e in self.events]
        inc.analysis = result
        inc.cause = result["cause"]
        inc.category = result["category"]
        inc.confidence = result["confidence"]
        inc.title = _title(result, self.events)
        reason = self.dismiss_fn(inc, result) if self.dismiss_fn and inc.source == "auto" else None
        if reason and self.on_dismiss:
            self.on_dismiss(inc, list(self.events), reason)
            return
        self.on_close(inc, list(self.events))

    def flush(self, ts: float) -> None:
        if self.current is not None:
            self.current.ts_end = self.current.last_activity or ts
            self._finish(self.current)
            self.current = None


def _title(result: dict, events: list[Event]) -> str:
    kinds = []
    for e in events:
        lbl = EVENT_LABELS.get(e.type, e.type)
        if lbl not in kinds and e.type in INCIDENT_TYPES:
            kinds.append(lbl)
    m = result.get("metrics", {})
    parts = []
    if m.get("ping_peak") is not None:
        parts.append(f"Ping {m['ping_peak']:.0f} ms")
    if m.get("loss_pct"):
        parts.append(f"{m['loss_pct']:.0f} % Loss")
    return " + ".join(kinds[:3]) + (f" ({', '.join(parts)})" if parts else "")


# ====================================================================== user report
def find_anomalies(rows: list[dict], baseline_rows: list[dict], thresholds, device_label,
                   context: list[dict] | None = None) -> list[dict]:
    """Finds conspicuous seconds and traffic increases for the lag report timeline.

    Somewhat more sensitive than the event engine, because the user explicitly
    noticed lag: RTT >= baseline + max(15 ms, baseline), any packet loss,
    jitter >= half the warning threshold, router anomalies, game packet gaps.
    """
    rtts = [r["rtt_avg"] for r in baseline_rows if r.get("rtt_avg") is not None]
    base = statistics.median(rtts) if rtts else None
    gws = [r["gw_rtt"] for r in baseline_rows if r.get("gw_rtt") is not None]
    gw_base = statistics.median(gws) if gws else None
    out: list[dict] = []
    for r in rows:
        ts = r["ts"]
        rtt = r.get("rtt_max") if r.get("rtt_max") is not None else r.get("rtt_avg")
        if rtt is not None and base is not None and rtt - base >= max(15.0, base):
            out.append({"ts": ts, "kind": "ping", "text": f"Ping {rtt:.0f} ms", "value": rtt})
        if (r.get("lost") or 0) > 0:
            out.append({"ts": ts, "kind": "loss",
                        "text": f"Packet Loss ({r['lost']}/{r['probes']} Probes)", "value": r["lost"]})
        j = r.get("jitter")
        if j is not None and j >= thresholds.jitter_warning / 2:
            out.append({"ts": ts, "kind": "jitter", "text": f"Jitter {j:.0f} ms", "value": j})
        gw = r.get("gw_rtt")
        if (gw is not None and gw_base is not None and gw >= max(thresholds.gateway_warning, gw_base * 3 + 2)) or \
                ((r.get("gw_probes") or 0) and r.get("gw_lost") == r.get("gw_probes")):
            out.append({"ts": ts, "kind": "gateway",
                        "text": f"Router {gw:.0f} ms" if gw is not None else "Router not answering", "value": gw})
        gap = r.get("game_gap_ms")
        if gap is not None and gap >= thresholds.game_gap_ms:
            out.append({"ts": ts, "kind": "game_gap", "text": f"Game server {gap:.0f} ms without packets", "value": gap})
        for server, ms, status, kind in r.get("dns") or []:
            if ms is None or status == "servfail":
                wo = " (uncached)" if kind == "uncached" else ""
                out.append({"ts": ts, "kind": "dns", "text": f"DNS {server}{wo}: {status}", "value": None})
    out.extend(traffic_onsets(rows, device_label, context=context))
    out.sort(key=lambda x: (x["ts"], x["kind"]))
    return out


def traffic_onsets(rows: list[dict], device_label, min_bps: float = 1e6,
                   context: list[dict] | None = None) -> list[dict]:
    """Start and course of heavy upload/download phases of individual devices.

    Steady background traffic is NOT reported. A "starts" is only claimed
    if less than 25 % of the peak was actually measured before (in the window
    or in the context before it).
    """
    out = []
    series: dict[tuple[str, int], list[tuple[int, float]]] = {}
    ctx: dict[tuple[str, int], list[float]] = {}
    for r in context or []:
        for mac, v in (r.get("devices") or {}).items():
            ctx.setdefault((mac, 1), []).append(v[1] * 8.0)
            ctx.setdefault((mac, 0), []).append(v[0] * 8.0)
    covered_ctx = any((r.get("traffic_src") or "").startswith("capture") for r in context or [])
    for r in rows:
        for mac, v in (r.get("devices") or {}).items():
            series.setdefault((mac, 1), []).append((r["ts"], v[1] * 8.0))
            series.setdefault((mac, 0), []).append((r["ts"], v[0] * 8.0))
    for (mac, idx), s in series.items():
        peak = max(v for _, v in s)
        if peak < min_bps:
            continue
        high = [(ts, v) for ts, v in s if v >= peak * 0.5]
        start, end = high[0][0], high[-1][0]
        before = [v for ts, v in s if ts < start] + (ctx.get((mac, idx), []) if not [v for ts, v in s if ts < start] else [])
        if not before and covered_ctx:
            before = [0.0]            # capture was running, device had no traffic before
        began_here = bool(before) and max(before) < peak * 0.25
        vals = sorted(v for _, v in s)
        median = vals[len(vals) // 2]
        if not began_here and peak < 2 * max(median, 1.0):
            continue                  # steady background traffic
        lbl = device_label(mac)
        name = "Upload" if idx == 1 else "Download"
        lo = min(v for _, v in high)
        out.append({"ts": start, "kind": "traffic_start" if began_here else "traffic",
                    "text": f"{lbl['name']} {name} {'starts' if began_here else 'rises'}", "mac": mac, "value": peak,
                    "direction": "up" if idx == 1 else "down"})
        out.append({"ts": start, "ts_end": end, "kind": "traffic_range",
                    "text": f"{lbl['name']} {name} {lo / 1e6:.0f}–{peak / 1e6:.0f} Mbit/s", "mac": mac, "value": peak,
                    "direction": "up" if idx == 1 else "down"})
    return out


def compress_timeline(items: list[dict]) -> list[dict]:
    """Merges contiguous findings of the same kind (>= 3 seconds in a row) into one time span."""
    net_kinds = {"ping", "loss", "jitter", "gateway", "game_gap", "dns"}
    runs: dict[tuple, list[dict]] = {}
    out: list[dict] = []
    for it in sorted(items, key=lambda x: x["ts"]):
        if it["kind"] not in net_kinds:
            out.append(it)
            continue
        key = (it["kind"], it["text"] if it["kind"] == "dns" else "")
        run = runs.get(key)
        if run and it["ts"] - run[-1]["ts"] <= 1:
            run.append(it)
        else:
            if run:
                out.extend(_collapse(run))
            runs[key] = [it]
    for run in runs.values():
        out.extend(_collapse(run))
    out.sort(key=lambda x: (x["ts"], x["kind"]))
    return out


def _collapse(run: list[dict]) -> list[dict]:
    if len(run) < 3:
        return run
    first, n = run[0], len(run)
    kind = first["kind"]
    vals = [r["value"] for r in run if isinstance(r.get("value"), (int, float))]
    peak = max(vals) if vals else None
    text = {
        "ping": f"Ping elevated, up to {peak:.0f} ms ({n} s)" if peak is not None else f"Ping elevated ({n} s)",
        "loss": f"Packet loss in {n} seconds ({int(sum(vals))} probes lost)",
        "jitter": f"Jitter elevated, up to {peak:.0f} ms ({n} s)" if peak is not None else f"Jitter elevated ({n} s)",
        "gateway": f"Router slow/unreachable ({n} s)",
        "game_gap": f"Game server packet gaps, up to {peak:.0f} ms ({n} s)" if peak is not None else f"Game packet gaps ({n} s)",
        "dns": f"{first['text']} ({n}×)",
    }[kind]
    return [{**first, "ts_end": run[-1]["ts"], "text": text, "value": peak}]


def window_summary(rows: list[dict]) -> dict:
    rtt = [r["rtt_max"] for r in rows if r.get("rtt_max") is not None]
    jit = [r["jitter"] for r in rows if r.get("jitter") is not None]
    probes = sum(r.get("probes") or 0 for r in rows)
    lost = sum(r.get("lost") or 0 for r in rows)
    ups = [r["up_bps"] for r in rows if r.get("up_bps") is not None]
    downs = [r["down_bps"] for r in rows if r.get("down_bps") is not None]
    return {"seconds": len(rows), "ping_max": max(rtt) if rtt else None,
            "ping_median": statistics.median([r["rtt_avg"] for r in rows if r.get("rtt_avg") is not None])
            if any(r.get("rtt_avg") is not None for r in rows) else None,
            "jitter_max": max(jit) if jit else None,
            "loss_pct": round(100 * lost / probes, 1) if probes else None,
            "up_max": max(ups) if ups else None, "down_max": max(downs) if downs else None}


def analyze_user_report(reported_at: float, rows_fn: Callable[[float, float], list[dict]],
                        window_fn: Callable[[float, float], Window], thresholds, device_label,
                        events: list[dict], default_window: int = 30) -> dict:
    """Analysis for the 'I JUST HAD LAG' button."""
    end = int(reported_at)
    windows = {}
    for w in REPORT_WINDOWS:
        windows[f"{w}s"] = window_summary(rows_fn(end - w + 1, end))
    baseline_rows = rows_fn(end - 300 - 120, end - 300)
    if len(baseline_rows) < 30:
        baseline_rows = rows_fn(end - 300, end)
    NET = ("ping", "loss", "jitter", "gateway", "game_gap", "dns")
    chosen = None
    for w in REPORT_WINDOWS:
        a = find_anomalies(rows_fn(end - w + 1, end), baseline_rows, thresholds, device_label)
        if any(x["kind"] in NET for x in a):
            chosen = w
            break
    if chosen is None:
        chosen = default_window
    # Trace a disturbance that reaches into the chosen window back to its start (max. 5 min)
    long_rows = rows_fn(end - 299, end)
    all_net = sorted({x["ts"] for x in find_anomalies(long_rows, baseline_rows, thresholds, device_label)
                      if x["kind"] in NET})
    in_window = [t for t in all_net if t >= end - chosen + 1]
    if in_window:
        t0 = in_window[0]
        for t in reversed([t for t in all_net if t < t0]):
            if t0 - t <= 5:
                t0 = t
            else:
                break
        t1 = in_window[-1]
    else:
        t0, t1 = end - chosen + 1, end
    ctx_start = min(t0 - 30, end - chosen + 1)
    anomalies = [x for x in find_anomalies(rows_fn(ctx_start, end), baseline_rows, thresholds, device_label,
                                           context=rows_fn(ctx_start - 30, ctx_start - 1))
                 if x["kind"] not in NET or x["ts"] >= t0]
    net = [a for a in anomalies if a["kind"] in NET]
    w = window_fn(t0, t1)
    w.events = [e for e in events if e["ts_start"] <= t1 and (e.get("ts_end") or t1) >= t0 - 10]
    result = analyze(w)
    if not net:
        result["cause"] = "No network anomalies were measured in the reported time span"
        result["category"] = "unknown"
        result["confidence"] = "low"
        result["confidence_label"] = "temporally correlated"
        result["evidence"] = ["Ping, jitter and packet loss to router and internet targets normal"]
        result["notes"].insert(0, "Possible causes outside the measurement: game server, client/PC (FPS, CPU), "
                                  "Wi-Fi of the gaming device. Tip: start a gaming session, then the game flow is monitored.")
    result["analysis_window"] = {"start": min(t0, end - chosen + 1), "end": end, "seconds": chosen}
    result["windows"] = windows
    result["timeline"] = compress_timeline(anomalies)[:60]
    result["events"] = w.events
    return result
