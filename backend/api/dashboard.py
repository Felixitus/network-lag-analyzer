"""Dashboard-API: Status, Live-Stream (SSE), Verlauf, Geräte-Traffic, Heatmap, Top Talker."""
from __future__ import annotations

import asyncio
import json
import time
from typing import Literal

from fastapi import APIRouter, Query, Request
from fastapi.responses import StreamingResponse

from ..analysis import bufferbloat as bb
from ..database import repository as repo

router = APIRouter(prefix="/api")

RANGES: dict[str, tuple[int, int]] = {   # Name → (Sekunden, Auflösung)
    "live": (300, 1), "5m": (300, 1), "15m": (900, 1), "1h": (3600, 1),
    "6h": (21600, 10), "24h": (86400, 60), "7d": (604800, 60),
}
RangeName = Literal["live", "5m", "15m", "1h", "6h", "24h", "7d"]
SERIES = ("rtt_avg", "rtt_min", "rtt_max", "gw_rtt", "jitter", "loss_pct", "down_bps", "up_bps",
          "game_rtt", "game_gap_ms", "dns_ms")


def core_of(request: Request):
    return request.app.state.core


def _grid(range_name: str, end: int | None = None) -> tuple[int, int, int]:
    secs, res = RANGES[range_name]
    end = end or int(time.time())
    end = end // res * res
    start = end - secs
    return start, end, res


# Auflösung für einen frei gewählten Zeitraum (Zoom per Ziehen in der Timeline).
# Dieselben Stufen wie bei den festen Bereichen – die 1-s-Werte gibt es nur einen Tag.
def _grid_span(start: float, end: float) -> tuple[int, int, int]:
    start, end = int(start), int(end)
    if end - start < 10:
        end = start + 10
    span = end - start
    res = 1 if span <= 3600 else 10 if span <= 6 * 3600 else 60
    return start // res * res, end // res * res, res


def _ring_covers(core, start: int) -> bool:
    return bool(core.hub.ring) and core.hub.ring[0]["ts"] <= start + 1


@router.get("/status")
async def status(request: Request):
    return core_of(request).status()


@router.get("/stream")
async def stream(request: Request):
    """Server-Sent Events: 'tick' jede Sekunde, 'event'/'incident'/'gaming' bei Änderungen."""
    core = core_of(request)
    q = core.broadcaster.subscribe()

    async def gen():
        try:
            yield f"event: hello\ndata: {json.dumps({'ts': time.time()})}\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    msg = await asyncio.wait_for(q.get(), timeout=15)
                    yield msg
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            core.broadcaster.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


def _history_from_ring(core, start: int, end: int, res: int) -> dict[int, dict]:
    out = {}
    for r in core.hub.range(start, end):
        d = {k: r.get(k) for k in SERIES}
        d["retrans_pct"] = round(100 * r["retrans"] / r["tcp_segs"], 2) if r.get("tcp_segs") else None
        d["traffic_src"] = r.get("traffic_src")
        out[r["ts"]] = d
    return out


def _history_from_db(c, start: int, end: int, res: int) -> dict[int, dict]:
    out = {}
    q = (f"SELECT ts, {', '.join(SERIES)}, retrans, tcp_segs, traffic_src FROM measurements "
         "WHERE res=? AND ts BETWEEN ? AND ? ORDER BY ts")
    for r in c.execute(q, (res, start, end)):
        d = {k: repo.dec(r[k], k) for k in SERIES}       # gespeicherte Ganzzahlen → ms/%
        d["retrans_pct"] = round(100 * r["retrans"] / r["tcp_segs"], 2) if r["tcp_segs"] else None
        d["traffic_src"] = r["traffic_src"]
        out[r["ts"]] = d
    return out


@router.get("/history")
async def history(request: Request, range: RangeName = "15m", end: int | None = None,
                  start: int | None = None):
    """Zeitreihen. Mit `start` UND `end` wird ein frei gewählter Zeitraum geliefert."""
    core = core_of(request)
    if start is not None and end is not None:
        start, end, res = _grid_span(start, end)
        range = "custom"
    else:
        start, end, res = _grid(range, end)
    if res == 1 and _ring_covers(core, start):
        data = _history_from_ring(core, start, end, res)
    else:
        data = await core.db.read(lambda c: _history_from_db(c, start, end, res))
        if res == 1:
            data.update(_history_from_ring(core, start, end, res))
    ts = list(range_(start, end, res))
    cols: dict[str, list] = {"ts": ts}
    for k in (*SERIES, "retrans_pct"):
        cols[k] = [data.get(t, {}).get(k) for t in ts]
    # Welche Sekunden sind überhaupt gemessen? Ohne diese Angabe sähe eine Lücke
    # in der Anzeige wie eine Null aus – und das wäre eine erfundene Messung.
    cols["covered"] = [t in data for t in ts]
    srcs = {d.get("traffic_src") for d in data.values() if d.get("traffic_src")}
    events = await core.db.read(lambda c: [dict(r) for r in c.execute(
        "SELECT id, type, severity, ts_start, ts_end, peak, mac, target, incident_id FROM events "
        "WHERE ts_start <= ? AND COALESCE(ts_end, ?) >= ? ORDER BY ts_start LIMIT 2000", (end, end, start))])
    incidents = await core.db.read(lambda c: [dict(r) for r in c.execute(
        "SELECT id, source, ts_start, ts_end, title, cause, category, confidence FROM incidents "
        "WHERE ts_start <= ? AND COALESCE(ts_end, ?) >= ? ORDER BY ts_start LIMIT 500", (end, end, start))])
    return {"range": range, "res": res, "start": start, "end": end, "series": cols,
            "traffic_sources": sorted(srcs), "events": events, "incidents": incidents,
            "per_target": _per_target_ring(core, start, end) if res == 1 and _ring_covers(core, start) else None}


def range_(start: int, end: int, step: int):
    return range(start, end + 1, step)


def _per_target_ring(core, start: int, end: int) -> dict:
    out: dict[str, list] = {}
    rows = core.hub.range(start, end)
    by_ts = {r["ts"]: r for r in rows}
    ts = list(range_(start, end, 1))
    for tid, t in core.targets.items():
        out[str(tid)] = {"name": t["name"] or t["address"], "kind": t["kind"],
                         "rtt": [((by_ts.get(x) or {}).get("targets") or {}).get(tid, {}).get("rtt") for x in ts]}
    return out


def _device_series_ring(core, start: int, end: int) -> dict[str, dict[int, tuple[float, float]]]:
    out: dict[str, dict[int, tuple[float, float]]] = {}
    for r in core.hub.range(start, end):
        for mac, v in (r.get("devices") or {}).items():
            out.setdefault(mac, {})[r["ts"]] = (v[0] * 8.0, v[1] * 8.0)
    return out


DEVICE_TRAFFIC_Q = ("SELECT t.ts, d.mac, t.rx_bytes, t.tx_bytes FROM device_traffic t "
                    "JOIN devices d ON d.id = t.dev WHERE t.res=? AND t.ts BETWEEN ? AND ?")


def _device_series_db(c, start: int, end: int, res: int) -> dict[str, dict[int, tuple[float, float]]]:
    out: dict[str, dict[int, tuple[float, float]]] = {}
    for r in c.execute(DEVICE_TRAFFIC_Q, (res, start, end)):
        out.setdefault(r["mac"], {})[r["ts"]] = (r["rx_bytes"] * 8.0 / res, r["tx_bytes"] * 8.0 / res)
    return out


@router.get("/history/devices")
async def history_devices(request: Request, range: RangeName = "15m", end: int | None = None,
                          start: int | None = None, top: int = Query(8, ge=1, le=30)):
    """Traffic pro Gerät (bit/s) auf demselben Zeitraster wie /history."""
    core = core_of(request)
    if start is not None and end is not None:
        start, end, res = _grid_span(start, end)
        range = "custom"
    else:
        start, end, res = _grid(range, end)
    if res == 1 and _ring_covers(core, start):
        data = _device_series_ring(core, start, end)
    else:
        data = await core.db.read(lambda c: _device_series_db(c, start, end, res))
    covered = await _covered(core, start, end, res)
    totals = {m: sum(a + b for a, b in s.values()) for m, s in data.items()}
    macs = sorted((m for m in totals if totals[m] > 0), key=lambda m: -totals[m])[:top]
    ts = list(range_(start, end, res))
    devices = []
    for mac in macs:
        s = data[mac]
        lbl = core.devices.label(mac)
        # 0 nur dort, wo der Mitschnitt lief; sonst None (= nicht gemessen, keine Fake-Null)
        devices.append({**lbl, "down": [s[t][0] if t in s else (0 if t in covered else None) for t in ts],
                        "up": [s[t][1] if t in s else (0 if t in covered else None) for t in ts],
                        "total_bytes": totals[mac] * res / 8})
    available = core.capture_status.get("state") == "running" or bool(data)
    return {"range": range, "res": res, "ts": ts, "devices": devices, "available": available,
            "reason": None if available else (core.capture_status.get("error") or "Keine Traffic-Quelle aktiv")}


async def _covered(core, start: int, end: int, res: int) -> set[int]:
    """Zeitpunkte, zu denen Traffic pro Gerät tatsächlich gemessen wurde."""
    if res == 1 and _ring_covers(core, start):
        return {r["ts"] for r in core.hub.range(start, end) if (r.get("traffic_src") or "").startswith("capture")}
    return await core.db.read(lambda c: {r[0] for r in c.execute(
        "SELECT ts FROM measurements WHERE res=? AND ts BETWEEN ? AND ? AND traffic_src LIKE 'capture%'",
        (res, start, end))})


@router.get("/heatmap")
async def heatmap(request: Request, range: RangeName = "1h", cols: int = Query(120, ge=10, le=400),
                  top: int = Query(20, ge=1, le=60)):
    core = core_of(request)
    start, end, res = _grid(range)
    if res == 1 and _ring_covers(core, start):
        data = _device_series_ring(core, start, end)
    else:
        data = await core.db.read(lambda c: _device_series_db(c, start, end, res))
    span = max(1, end - start)
    width = span / cols
    rows = []
    for mac, s in data.items():
        buckets = [0.0] * cols
        for t, (d, u) in s.items():
            i = min(cols - 1, int((t - start) / width))
            buckets[i] += (d + u) * res / 8   # Bytes
        rows.append({**core.devices.label(mac), "values": buckets, "total": sum(buckets)})
    rows.sort(key=lambda r: -r["total"])
    return {"range": range, "start": start, "end": end, "cols": cols, "bucket_seconds": width, "rows": rows[:top]}


@router.get("/top-talkers")
async def top_talkers(request: Request, seconds: int = Query(10, ge=1, le=3600), start: float | None = None,
                      end: float | None = None, n: int = Query(10, ge=1, le=50)):
    """Aktuell (letzte N s) oder historisch (start/end) aktivste Geräte."""
    core = core_of(request)
    if start is None or end is None:
        end = core.hub.last_finalized
        start = end - seconds + 1
    t0, t1 = int(start), int(end)
    ring_ok = _ring_covers(core, t0)
    if ring_ok:
        acc: dict[str, list[float]] = {}
        rows = core.hub.range(t0, t1)
        for r in rows:
            for mac, v in (r.get("devices") or {}).items():
                a = acc.setdefault(mac, [0.0, 0.0, 0.0, 0.0])
                a[0] += v[0]
                a[1] += v[1]
                a[2] = max(a[2], v[0] * 8)
                a[3] = max(a[3], v[1] * 8)
        secs = max(1, len(rows))
    else:
        def q(c):
            out = {}
            res = 1 if t1 - t0 <= 86400 else 60
            q = ("SELECT d.mac mac, SUM(t.rx_bytes) rx, SUM(t.tx_bytes) tx, "
                 "MAX(t.rx_bytes) mrx, MAX(t.tx_bytes) mtx FROM device_traffic t "
                 "JOIN devices d ON d.id = t.dev WHERE t.res=? AND t.ts BETWEEN ? AND ? GROUP BY d.mac")
            for r in c.execute(q, (res, t0, t1)):
                out[r["mac"]] = [r["rx"], r["tx"], r["mrx"] * 8 / res, r["mtx"] * 8 / res]
            return out
        acc = await core.db.read(q)
        secs = max(1, t1 - t0 + 1)
    items = []
    for mac, (rx, tx, prx, ptx) in acc.items():
        if rx + tx <= 0:
            continue
        items.append({**core.devices.label(mac), "down_bps": rx * 8 / secs, "up_bps": tx * 8 / secs,
                      "down_peak_bps": prx, "up_peak_bps": ptx, "bytes": rx + tx})
    items.sort(key=lambda x: -(x["down_bps"] + x["up_bps"]))
    return {"start": t0, "end": t1, "devices": items[:n],
            "available": core.hub.capture_active() or bool(items),
            "reason": None if (core.hub.capture_active() or items) else
            (core.capture_status.get("error") or "Traffic pro Gerät nicht verfügbar")}


BLOAT_RANGES: dict[str, int] = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000}
BloatRange = Literal["1h", "6h", "24h", "7d", "30d"]


@router.get("/bufferbloat")
async def bufferbloat_api(request: Request, range: BloatRange = "24h"):
    """Latenz unter Last, getrennt nach Richtung.

    Kurze Zeiträume werden direkt aus den 1-s-Werten berechnet (`source: live`),
    längere aus den gespeicherten 10-Minuten-Fenstern (`source: windows`), weil
    die 1-s-Werte nur einen Tag aufbewahrt werden.
    """
    core = core_of(request)
    secs = BLOAT_RANGES[range]
    now = int(time.time())
    start = now - secs
    cd, cu, csrc = core.capacity_info()
    buckets = await core.db.read(lambda c: repo.read_bufferbloat(c, start, now))
    ring = list(core.hub.ring)

    live_rows = [r for r in ring if r["ts"] >= start] if secs <= 3600 else []
    if live_rows:
        # Der Ring umfasst eine Stunde – für kurze Zeiträume ist die Rechnung über
        # die Einzelsekunden genauer als der Median gespeicherter Fenster.
        summary = bb.measure(live_rows, cd, cu, idle_rows=ring)
        source = "live"
    else:
        summary = bb.aggregate(buckets) if (cd and cu) else bb.measure([], cd, cu)
        source = "windows"
        if summary["up"] is None and summary["down"] is None and ring and cd and cu:
            # Noch keine gespeicherten Fenster (frisch gestartet) – dann wenigstens die
            # letzte Stunde aus dem Ring zeigen, statt eine leere Karte.
            live = bb.measure(ring, cd, cu)
            if live["up"] or live["down"]:
                summary, source, live_rows = live, "live", ring
    return {
        "range": range, "start": start, "end": now, "source": source,
        "seconds_covered": len(live_rows) if source == "live" else None,
        "window_seconds": bb.BUCKET,
        "summary": summary,
        "history": {d: bb.trend(buckets, d) for d in ("up", "down")},
        "capacity": {"down_bps": cd, "up_bps": cu, "source": csrc},
        "thresholds": {"idle_max": bb.IDLE_MAX, "load_min": bb.LOAD_MIN,
                       "grades": [{"below_ms": g[0] if g[0] != float("inf") else None,
                                   "label": g[1], "level": g[2]} for g in bb.GRADES]},
    }


@router.get("/flows/active")
async def active_flows(request: Request):
    core = core_of(request)
    if not core.active_flows:
        return {"ts": None, "flows": []}
    ts, flows = core.active_flows[-1]
    return {"ts": ts, "flows": [{**f, "device": core.devices.label(f["mac"])["name"],
                                 "dns_name": core.devices.ip_names.get(f["remote_ip"])} for f in flows]}


@router.get("/flows")
async def flows(request: Request, start: float, end: float, mac: str | None = None,
                limit: int = Query(200, ge=1, le=2000)):
    core = core_of(request)

    def q(c):
        sql = "SELECT * FROM network_flows WHERE ts_start <= ? AND ts_end >= ?"
        args: list = [end, start]
        if mac:
            sql += " AND mac = ?"
            args.append(mac.lower())
        sql += " ORDER BY bytes_up + bytes_down DESC LIMIT ?"
        args.append(limit)
        return [dict(r) for r in c.execute(sql, args)]
    rows = await core.db.read(q)
    for r in rows:
        r["device"] = core.devices.label(r["mac"])["name"] if r["mac"] else None
    return {"flows": rows}
