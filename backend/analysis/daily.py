"""Daily summary for long-term comparison.

The detail data disappears after days to weeks - but the question "has it gotten
better since the change?" only comes up months later. So a handful of metrics
is kept per day: about 200 bytes, exempt from
retention.

The basis is the finest resolution of the day that still exists. Which one that
was is stored in `seconds` (number of data points) - so you can later tell
how reliable a row is. Nothing is estimated: if a value is missing, it stays NULL.
"""
from __future__ import annotations

import json
import sqlite3
import time
from datetime import date, datetime, timedelta

from ..database import repository as repo

DAY = 86400


def day_bounds(day: str) -> tuple[int, int]:
    """Local day boundaries as Unix seconds [start, end)."""
    d = datetime.strptime(day, "%Y-%m-%d")
    start = int(d.timestamp())
    return start, int((d + timedelta(days=1)).timestamp())


def yesterday(now: float | None = None) -> str:
    return (date.fromtimestamp(now or time.time()) - timedelta(days=1)).isoformat()


def _pick_resolution(conn: sqlite3.Connection, t0: int, t1: int) -> int | None:
    """Finest resolution that still covers the day."""
    for res in (1, 10, 60):
        n = conn.execute("SELECT COUNT(*) FROM measurements WHERE res=? AND ts >= ? AND ts < ?",
                         (res, t0, t1)).fetchone()[0]
        if n:
            return res
    return None


def _percentile(conn: sqlite3.Connection, col: str, res: int, t0: int, t1: int, p: float) -> int | None:
    """p-quantile of a column, directly in SQL over the sorted values."""
    n = conn.execute(f"SELECT COUNT(*) FROM measurements WHERE res=? AND ts>=? AND ts<? AND {col} IS NOT NULL",
                     (res, t0, t1)).fetchone()[0]
    if not n:
        return None
    off = min(n - 1, int(n * p))
    r = conn.execute(f"SELECT {col} FROM measurements WHERE res=? AND ts>=? AND ts<? AND {col} IS NOT NULL "
                     f"ORDER BY {col} LIMIT 1 OFFSET ?", (res, t0, t1, off)).fetchone()
    return r[0] if r else None


def compute(conn: sqlite3.Connection, day: str) -> tuple | None:
    """One row for `daily_stats`. None if nothing was measured on that day."""
    t0, t1 = day_bounds(day)
    res = _pick_resolution(conn, t0, t1)
    if res is None:
        return None
    agg = conn.execute(
        "SELECT COUNT(*) n, MAX(rtt_max) rtt_max, SUM(probes) probes, SUM(lost) lost, "
        "MAX(down_bps) down_peak, MAX(up_bps) up_peak, "
        "SUM(COALESCE(down_bps,0)) down_sum, SUM(COALESCE(up_bps,0)) up_sum, "
        "SUM(CASE WHEN probes > 0 AND lost >= probes THEN 1 ELSE 0 END) outage "
        "FROM measurements WHERE res=? AND ts >= ? AND ts < ?", (res, t0, t1)).fetchone()
    probes, lost = agg["probes"] or 0, agg["lost"] or 0
    bloat = conn.execute(
        "SELECT AVG(up_ms - idle_ms) up, AVG(down_ms - idle_ms) down FROM bufferbloat "
        "WHERE ts >= ? AND ts < ?", (t0, t1)).fetchone()
    cats: dict[str, int] = {}
    for r in conn.execute("SELECT category, COUNT(*) n FROM incidents WHERE ts_start >= ? AND ts_start < ? "
                          "GROUP BY category", (t0, t1)):
        cats[r["category"] or "unknown"] = r["n"]
    rnd = lambda v: None if v is None else int(round(v))      # noqa: E731
    return (
        day, agg["n"] * res,
        _percentile(conn, "rtt_avg", res, t0, t1, 0.5), _percentile(conn, "rtt_avg", res, t0, t1, 0.95),
        agg["rtt_max"],
        _percentile(conn, "gw_rtt", res, t0, t1, 0.5),
        _percentile(conn, "jitter", res, t0, t1, 0.5), _percentile(conn, "jitter", res, t0, t1, 0.95),
        int(round(10000.0 * lost / probes)) if probes else None,
        probes, lost,
        agg["down_peak"], agg["up_peak"],
        int((agg["down_sum"] or 0) * res / 8), int((agg["up_sum"] or 0) * res / 8),
        rnd(bloat["up"]), rnd(bloat["down"]),
        (agg["outage"] or 0) * res,
        json.dumps(cats, ensure_ascii=False) if cats else None,
    )


INSERT = ("INSERT OR REPLACE INTO daily_stats(day, seconds, rtt_p50, rtt_p95, rtt_max, gw_p50, "
          "jitter_p50, jitter_p95, loss_pct, probes, lost, down_peak, up_peak, down_bytes, up_bytes, "
          "bloat_up, bloat_down, outage_secs, incidents) VALUES (" + ",".join("?" * 19) + ")")

_MS = ("rtt_p50", "rtt_p95", "rtt_max", "gw_p50", "jitter_p50", "jitter_p95", "bloat_up", "bloat_down")


def write_missing(conn: sqlite3.Connection, now: float | None = None, max_days: int = 40) -> list[str]:
    """Backfill missing days (completed days, backwards up to max_days)."""
    now = now or time.time()
    have = {r[0] for r in conn.execute("SELECT day FROM daily_stats")}
    today = date.fromtimestamp(now)
    written = []
    for i in range(1, max_days + 1):
        day = (today - timedelta(days=i)).isoformat()
        if day in have:
            continue
        params = compute(conn, day)
        if params is None:
            continue
        conn.execute(INSERT, params)
        written.append(day)
    return written


def read(conn: sqlite3.Connection, days: int = 90) -> list[dict]:
    """Daily rows in milliseconds/percent, most recent day last."""
    start = (date.today() - timedelta(days=days)).isoformat()
    out = []
    for r in conn.execute("SELECT * FROM daily_stats WHERE day >= ? ORDER BY day", (start,)):
        d = dict(r)
        for k in _MS:
            if d.get(k) is not None:
                d[k] = d[k] / repo.CENTI
        if d.get("loss_pct") is not None:
            d["loss_pct"] = d["loss_pct"] / repo.CENTI
        d["incidents"] = json.loads(d["incidents"] or "{}")
        out.append(d)
    return out
