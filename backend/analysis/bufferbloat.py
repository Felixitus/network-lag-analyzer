"""Bufferbloat: how much does latency rise when the line is saturated?

This is the decisive metric for gaming. It is measured separately per
direction, because the consequence differs:

* **Upload load**: the queue sits in your own router. Prioritization
  (FRITZ!Box: "Prioritization/real-time applications") or throttling the device helps.
* **Download load**: the queue sits at the provider (DSLAM/BRAS). Local
  prioritization does NOT help - only slowing the downloading device (or SQM/CAKE on
  a router that supports it).

Method: seconds are split into groups by utilization and the RTT of the
groups is compared. Nothing is estimated - if measurements are missing for a group,
the result stays empty.

For the long-term history 10-minute windows are stored (table
`bufferbloat`), because 1 s values are only kept for one day. For longer
spans the median of these windows is shown; this is documented in
`aggregate()`.
"""
from __future__ import annotations

import statistics

IDLE_MAX = 0.20      # up to 20 % utilization the line counts as "quiet"
LOAD_MIN = 0.70      # from 70 % as "under load"
ISOLATE_MAX = 0.40   # the other direction must stay below this
MIN_SAMPLES = 5
BUCKET = 600         # length of a stored window in seconds

# Rating of the latency increase under load (ms)
GRADES = ((30, "good", "good"), (100, "moderate", "warning"), (float("inf"), "severe", "critical"))

UP_ADVICE = ("Queue in your own router: FRITZ!Box prioritization for the gaming PC "
             "or throttle the uploading device.")
DOWN_ADVICE = ("Queue at the provider: local prioritization does not help here - "
               "slow down the downloading device (e.g. limit the console's download rate).")
ADVICE = {"up": UP_ADVICE, "down": DOWN_ADVICE}


def grade(delta_ms: float | None) -> tuple[str, str] | tuple[None, None]:
    if delta_ms is None:
        return None, None
    for limit, label, level in GRADES:
        if delta_ms < limit:
            return label, level
    return None, None


def _median(vals: list[float]) -> float | None:
    return statistics.median(vals) if vals else None


def classify(rows: list[dict], cap_down: float, cap_up: float) -> dict[str, list[float]]:
    """Splits seconds into quiet / under upload load / under download load."""
    out: dict[str, list[float]] = {"idle": [], "up": [], "down": []}
    for r in rows:
        rtt, down, up = r.get("rtt_avg"), r.get("down_bps"), r.get("up_bps")
        if rtt is None or down is None or up is None:
            continue
        ud, uu = down / cap_down, up / cap_up
        if max(ud, uu) <= IDLE_MAX:
            out["idle"].append(rtt)
        elif uu >= LOAD_MIN and ud < ISOLATE_MAX:
            out["up"].append(rtt)
        elif ud >= LOAD_MIN and uu < ISOLATE_MAX:
            out["down"].append(rtt)
    return out


def measure(rows: list[dict], cap_down: float | None, cap_up: float | None,
            idle_rows: list[dict] | None = None) -> dict:
    """Compares the RTT on a quiet line with the RTT under load.

    rows:      per-second rows with rtt_avg, down_bps, up_bps.
    idle_rows: optionally a larger time span from which the idle baseline is
               determined. Needed when `rows` is saturated throughout (long
               download) and therefore contains no quiet seconds itself.
    """
    out: dict = {"idle_ms": None, "up": None, "down": None, "samples": {"idle": 0, "up": 0, "down": 0},
                 "capacity_known": bool(cap_down and cap_up), "note": None}
    if not (cap_down and cap_up):
        out["note"] = "Line capacity unknown - enter it under Settings → Measurement."
        return out

    groups = classify(rows, cap_down, cap_up)
    idle = groups["idle"]
    if len(idle) < MIN_SAMPLES and idle_rows:
        idle = classify(idle_rows, cap_down, cap_up)["idle"]

    out["samples"] = {"idle": len(idle), "up": len(groups["up"]), "down": len(groups["down"])}
    base = _median(idle) if len(idle) >= MIN_SAMPLES else None
    out["idle_ms"] = round(base, 1) if base is not None else None
    if base is None:
        out["note"] = "Too few seconds with a quiet line for a comparison."
        return out

    for key in ("up", "down"):
        vals = groups[key]
        if len(vals) < MIN_SAMPLES:
            continue
        med = _median(vals)
        delta = med - base
        label, level = grade(delta)
        out[key] = {
            "loaded_ms": round(med, 1), "delta_ms": round(delta, 1), "worst_ms": round(max(vals), 1),
            "seconds": len(vals), "grade": label, "level": level, "advice": ADVICE[key],
        }
    if out["up"] is None and out["down"] is None:
        out["note"] = "No phase with high utilization measured yet."
    return out


def storable(m: dict) -> bool:
    """Is a stored window worth it? Only with an idle AND a load phase."""
    return m["idle_ms"] is not None and (m["up"] is not None or m["down"] is not None)


def aggregate(buckets: list[dict]) -> dict:
    """Merges stored 10-minute windows into a statement about the time span.

    The windows already contain medians; across the span the median of these
    window medians is taken (and the maximum as the peak value).
    This is coarser than a calculation over all individual seconds, but honestly
    composed: every window counts equally.
    """
    out: dict = {"idle_ms": None, "up": None, "down": None, "windows": len(buckets),
                 "samples": {"idle": 0, "up": 0, "down": 0}, "capacity_known": True, "note": None,
                 "aggregated": True}
    if not buckets:
        out["note"] = "No evaluated time windows yet - this needs quiet AND saturated phases."
        return out
    idle = [b["idle_ms"] for b in buckets if b.get("idle_ms") is not None]
    base = _median(idle)
    out["idle_ms"] = round(base, 1) if base is not None else None
    out["samples"]["idle"] = sum(b.get("idle_secs") or 0 for b in buckets)
    for key in ("up", "down"):
        vals = [b[f"{key}_ms"] for b in buckets if b.get(f"{key}_ms") is not None]
        if not vals or base is None:
            continue
        med = _median(vals)
        worst = max(b[f"{key}_worst_ms"] for b in buckets if b.get(f"{key}_worst_ms") is not None)
        secs = sum(b.get(f"{key}_secs") or 0 for b in buckets)
        out["samples"][key] = secs
        delta = med - base
        label, level = grade(delta)
        out[key] = {"loaded_ms": round(med, 1), "delta_ms": round(delta, 1), "worst_ms": round(worst, 1),
                    "seconds": secs, "windows": len(vals), "grade": label, "level": level,
                    "advice": ADVICE[key]}
    if out["up"] is None and out["down"] is None:
        out["note"] = "No phase with high utilization in the time span."
    return out


def trend(buckets: list[dict], direction: str) -> list[dict]:
    """Time series of the latency increase for the history view."""
    out = []
    for b in buckets:
        loaded, base = b.get(f"{direction}_ms"), b.get("idle_ms")
        if loaded is None or base is None:
            continue
        out.append({"ts": b["ts"], "delta_ms": round(loaded - base, 1), "idle_ms": base,
                    "loaded_ms": loaded, "seconds": b.get(f"{direction}_secs") or 0})
    return out
