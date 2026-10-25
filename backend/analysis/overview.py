"""Overview page: one status light per area, and a timeline of the last hours.

Every light and every timeline cell is computed from measurements only. A cell
without measurements is `None` (shown hatched), never "good": an empty hour is not
a quiet hour.
"""
from __future__ import annotations

import time

from ..database.repository import dec, decode_pi_health
from . import pi_health

LEVELS = ("good", "warning", "critical")
RESTART_LOG_KEY = "restart_log"
RESTART_LOG_MAX = 200


def worst(*levels: str | None) -> str | None:
    known = [lv for lv in levels if lv in LEVELS]
    return max(known, key=LEVELS.index) if known else None


def _light(key: str, label: str, level: str | None, value: str, detail: str = "", href: str | None = None) -> dict:
    return {"key": key, "label": label, "level": level or "unknown", "value": value, "detail": detail, "href": href}


def loss_level(pct: float | None, th) -> str | None:
    if pct is None:
        return None
    return "critical" if pct >= 5 else "warning" if pct >= th.packet_loss_warning else "good"


def rtt_level(ms: float | None, warn: float, crit: float | None = None) -> str | None:
    if ms is None:
        return None
    if crit is not None and ms >= crit:
        return "critical"
    return "warning" if ms >= warn else "good"


# ------------------------------------------------------------------ lights (now)
def internet_light(core) -> dict:
    th = core.cfg.thresholds
    online = core.hub.internet_online()
    if online is None:
        return _light("internet", "Internet", None, "Not available", "No ping measurements in the last seconds", "#/dashboard")
    if online is False:
        return _light("internet", "Internet", "critical", "Offline", "No internet target answers", "#/dashboard")
    last = core.hub.ring[-1] if core.hub.ring else {}
    loss = core.hub.loss_windows().get("60s")
    rtt = last.get("rtt_avg")
    level = worst(loss_level(loss, th), rtt_level(rtt, th.ping_warning, th.ping_critical))
    parts = [f"Ping {rtt:.0f} ms" if rtt is not None else None, f"loss {loss:.1f} % (60 s)" if loss is not None else None]
    return _light("internet", "Internet", level, "Online", " · ".join(p for p in parts if p), "#/dashboard")


def router_light(core) -> dict:
    """The Pi's own path to the router. Losses here look like internet trouble, but are not."""
    th = core.cfg.thresholds
    gw = [t for t in core.hub.target_health() if t["kind"] == "gateway" and t["address"] == core.gateway]
    if not gw or not gw[0]["probes"]:
        return _light("router", "Link to router", None, "Not available", "The router is not measured", "#/dashboard")
    t = gw[0]
    if t["unreachable"]:
        return _light("router", "Link to router", "critical", "No answer", f"{t['address']} does not answer pings", "#/dashboard")
    level = worst(loss_level(t["loss_pct"], th), rtt_level(t["rtt_avg"], th.gateway_warning))
    detail = f"{t['rtt_avg']:.1f} ms · loss {t['loss_pct']:.1f} % ({t['window_seconds']} s)" if t["rtt_avg"] is not None \
        else f"loss {t['loss_pct']:.1f} %"
    verdict = core.link_verdict() if hasattr(core, "link_verdict") else None
    if verdict and verdict.get("text"):
        detail = verdict["text"]
    value = "OK" if level == "good" else "Packet loss" if (t["loss_pct"] or 0) >= th.packet_loss_warning else "Slow"
    return _light("router", "Link to router", level, value, detail, "#/dashboard")


def dns_light(core) -> dict:
    ph = core.pihole_status or {}
    probe = (core.dns.last if core.dns else {}) or {}
    local = next((v for k, v in probe.items() if k.startswith("127.") or k == "::1"), None)
    if local is not None and time.time() - local["ts"] < 60:
        if local["ms"] is None or local["status"] not in ("ok", "nxdomain"):
            return _light("dns", "Pi-hole (DNS)", "critical", "Not answering",
                          f"Last test query: {local['status']}", "#/dns")
        return _light("dns", "Pi-hole (DNS)", "warning" if local["ms"] >= 200 else "good", "Answering",
                      f"Test query {local['ms']:.0f} ms", "#/dns")
    if not ph.get("enabled"):
        return _light("dns", "Pi-hole (DNS)", None, "Not available", "Pi-hole integration is off", "#/settings")
    return _light("dns", "Pi-hole (DNS)", "good" if ph.get("ok") else "critical",
                  "Readable" if ph.get("ok") else "Not available", ph.get("message") or "", "#/dns")


def fritz_light(core) -> dict:
    fs = core.fritz_status or {}
    if not fs.get("enabled"):
        return _light("fritzbox", "FRITZ!Box", None, "Not available", "No FRITZ!Box access configured", "#/settings")
    model = " ".join(x for x in (fs.get("model"), fs.get("firmware")) if x)
    if fs.get("ok") is None:
        return _light("fritzbox", "FRITZ!Box", None, "Connecting…", model, "#/settings")
    if not fs.get("ok"):
        return _light("fritzbox", "FRITZ!Box", "warning", "Error", fs.get("error") or "", "#/settings")
    return _light("fritzbox", "FRITZ!Box", "good", "Connected", model, "#/settings")


def capture_light(core) -> dict:
    cap = core.capture_status or {}
    state = cap.get("state") or "off"
    if state == "running":
        return _light("capture", "Traffic per device", "good", "Measuring", cap.get("source") or "", "#/devices")
    if state in ("disabled", "off", "stopped"):
        return _light("capture", "Traffic per device", None, "Not available", cap.get("error") or f"Capture {state}", "#/settings")
    return _light("capture", "Traffic per device", "warning", state.capitalize(), cap.get("error") or "", "#/settings")


def pi_light(core) -> dict:
    ph = getattr(core, "pi_health", None) or {}
    s = {**(core.loadguard.last or {}), **{k: v for k, v in ph.items() if v is not None}}
    guard = {0: "good", 1: "warning", 2: "warning", 3: "critical"}.get(core.loadguard.level)
    level = worst(guard, ph.get("level"))
    parts = [f"CPU {s['cpu_pct']:.0f} %" if s.get("cpu_pct") is not None else None,
             f"{s['mem_available_mb']} MB free" if s.get("mem_available_mb") is not None else None,
             f"{s['temp_c']:.0f} °C" if s.get("temp_c") is not None else None]
    notes = ph.get("notes") or []
    value = "OK" if level == "good" else (f"Load Guard {core.loadguard.level}" if guard != "good" else "Check")
    return _light("pi", "Raspberry Pi", level, value, notes[0] if notes else " · ".join(p for p in parts if p), "#/pi")


def line_light(core) -> dict:
    ls = core.line_status or {}
    if not ls.get("enabled"):
        return _light("line", "Internet line", None, "Not available", "No FRITZ!Box access configured", "#/line")
    dsl, wan = ls.get("dsl"), ls.get("wan")
    if dsl is None and wan is None:
        return _light("line", "Internet line", None, "Not available", ls.get("error") or "Waiting for the first values", "#/line")
    if wan and (wan.get("status") or "").lower() not in ("connected", ""):
        return _light("line", "Internet line", "critical", wan["status"], "Connection state of the FRITZ!Box", "#/line")
    if dsl:
        detail = f"{(dsl.get('down_kbit') or 0) / 1000:.0f}/{(dsl.get('up_kbit') or 0) / 1000:.0f} Mbit/s"
        if dsl.get("down_snr_db") is not None:
            detail += f" · margin {dsl['down_snr_db']:.0f} dB"
        return _light("line", "Internet line", ls.get("level"), "DSL " + (dsl.get("status") or "?"),
                      (ls.get("notes") or [detail])[0], "#/line")
    return _light("line", "Internet line", "good", wan.get("status") or "?", "", "#/line")


LIGHTS = [internet_light, router_light, line_light, dns_light, fritz_light, capture_light, pi_light]


def lights(core) -> list[dict]:
    return [fn(core) for fn in LIGHTS]


# ------------------------------------------------------------------ timeline (history)
def _bucket_rows(conn, start: int, end: int, bucket: int, gateway: str | None) -> dict[int, dict]:
    out: dict[int, dict] = {}

    def cell(ts: int) -> dict:
        return out.setdefault(start + (ts - start) // bucket * bucket, {
            "probes": 0, "lost": 0, "outage_min": 0, "rtt_max": None, "dns_fail": None, "dns_fail_min": 0,
            "gw_probes": 0, "gw_lost": 0, "gw_rtt_max": None})

    for ts, probes, lost, rtt, dns_fail in conn.execute(
            "SELECT ts, probes, lost, rtt_avg, dns_fail FROM measurements WHERE res=60 AND ts>=? AND ts<?", (start, end)):
        c = cell(ts)
        if probes:
            c["probes"] += probes
            c["lost"] += lost or 0
            c["outage_min"] += 1 if lost == probes else 0
        if rtt is not None:
            c["rtt_max"] = max(c["rtt_max"] or 0, dec(rtt, "rtt_avg"))
        if dns_fail is not None:
            c["dns_fail"] = (c["dns_fail"] or 0) + dns_fail
            c["dns_fail_min"] += 1 if dns_fail else 0
    if gateway:
        for ts, probes, lost, rtt in conn.execute(
                """SELECT m.ts, m.probes, m.lost, m.rtt_avg FROM target_measurements m JOIN targets t ON t.id = m.target_id
                   WHERE m.res=60 AND t.kind='gateway' AND t.address=? AND m.ts>=? AND m.ts<?""", (gateway, start, end)):
            c = cell(ts)
            c["gw_probes"] += probes or 0
            c["gw_lost"] += lost or 0
            if rtt is not None:
                c["gw_rtt_max"] = max(c["gw_rtt_max"] or 0, dec(rtt, "rtt_avg"))
    return out


def _pct(lost: int, probes: int) -> float | None:
    return 100.0 * lost / probes if probes else None


def timeline(conn, th, gateway: str | None, start: int, end: int, bucket: int) -> dict:
    """Rows of cells {level, text}; level None = no measurements in that bucket."""
    agg = _bucket_rows(conn, start, end, bucket, gateway)
    starts = list(range(start, end, bucket))
    rows = {"internet": [], "latency": [], "router": [], "dns": []}
    for t in starts:
        c = agg.get(t)
        if c is None:
            for r in rows.values():
                r.append(None)
            continue
        loss = _pct(c["lost"], c["probes"])
        lvl = "critical" if c["outage_min"] else loss_level(loss, th)
        rows["internet"].append(None if loss is None else {
            "level": lvl, "text": (f"{c['outage_min']} min offline · " if c["outage_min"] else "") + f"loss {loss:.1f} %"})
        rows["latency"].append(None if c["rtt_max"] is None else {
            "level": rtt_level(c["rtt_max"], th.ping_warning, th.ping_critical), "text": f"worst minute {c['rtt_max']:.0f} ms"})
        gl = _pct(c["gw_lost"], c["gw_probes"])
        rows["router"].append(None if gl is None else {
            "level": worst(loss_level(gl, th), rtt_level(c["gw_rtt_max"], th.gateway_warning)),
            "text": f"loss {gl:.1f} %" + (f" · worst minute {c['gw_rtt_max']:.1f} ms" if c["gw_rtt_max"] is not None else "")})
        # A failed test query in a single minute is a hiccup; in three or more minutes of
        # the same bucket names stopped resolving for long enough to be noticed.
        rows["dns"].append(None if c["dns_fail"] is None else {
            "level": "good" if not c["dns_fail"] else "critical" if c["dns_fail_min"] >= 3 else "warning",
            "text": f"{c['dns_fail']} failed test queries" if c["dns_fail"] else "all test queries answered"})
    rows["pi"] = pi_cells(conn, starts, bucket)
    labels = {"internet": "Internet", "latency": "Latency", "router": "Link to router", "dns": "DNS", "pi": "Raspberry Pi"}
    return {"start": start, "end": end, "bucket": bucket, "starts": starts,
            "rows": [{"key": k, "label": labels[k], "cells": v} for k, v in rows.items()]}


def pi_cells(conn, starts: list[int], bucket: int) -> list[dict | None]:
    """Worst state of the Pi per bucket: heat, under-voltage, link drops and receive errors on its port."""
    if not starts:
        return []
    rows = [decode_pi_health(r) for r in conn.execute(
        "SELECT * FROM pi_health WHERE ts>=? AND ts<? ORDER BY ts", (starts[0] - 120, starts[-1] + bucket))]
    agg: dict[int, dict] = {}
    for r, d in zip(rows, pi_health.deltas(rows)):
        if r["ts"] < starts[0]:
            continue
        c = agg.setdefault(starts[0] + (r["ts"] - starts[0]) // bucket * bucket,
                           {"temp": None, "undervolt": False, "flaps": 0, "rx_errors": 0, "ftl_down": False})
        if r["temp_c"] is not None:
            c["temp"] = max(c["temp"] or 0, r["temp_c"])
        c["undervolt"] |= bool(r["undervolt"])
        c["ftl_down"] |= r["pihole_active"] == 0
        c["flaps"] += d["carrier_changes"] or 0
        c["rx_errors"] += d["rx_errors"] or 0
    out = []
    for t in starts:
        c = agg.get(t)
        if c is None:
            out.append(None)
            continue
        level, parts = "good", []
        if c["undervolt"] or c["ftl_down"] or (c["temp"] or 0) >= pi_health.TEMP_CRIT:
            level = "critical"
        elif c["flaps"] or c["rx_errors"] or (c["temp"] or 0) >= pi_health.TEMP_WARN:
            level = "warning"
        if c["temp"] is not None:
            parts.append(f"max {c['temp']:.0f} °C")
        if c["undervolt"]:
            parts.append("under-voltage")
        if c["ftl_down"]:
            parts.append("pihole-FTL not running")
        if c["flaps"]:
            parts.append(f"link dropped {c['flaps']}×")
        if c["rx_errors"]:
            parts.append(f"{c['rx_errors']} receive errors")
        out.append({"level": level, "text": " · ".join(parts) or "OK"})
    return out


# ------------------------------------------------------------------ restarts
def record_start(log: list[dict], now: float, boot: float | None) -> list[dict]:
    """Appends this service start; a boot time newer than the previous start means the Pi rebooted."""
    log = list(log or [])
    log.append({"ts": now, "boot": boot})
    return log[-RESTART_LOG_MAX:]


def restarts(log: list[dict], start: float, end: float) -> list[dict]:
    """Service starts and Pi reboots in [start, end). The boot time comes from the kernel's uptime and
    is only trusted when it lies before the service start (the clock may jump after boot)."""
    out, prev_boot = [], None
    for e in log or []:
        boot = e.get("boot")
        rebooted = boot is not None and boot <= e["ts"] and (prev_boot is None or boot - prev_boot > 60)
        if rebooted and start <= boot < end:
            out.append({"ts": boot, "kind": "boot", "label": "Pi started"})
        if start <= e["ts"] < end:
            out.append({"ts": e["ts"], "kind": "service", "label": "Service started"})
        if boot is not None:
            prev_boot = boot
    return out
