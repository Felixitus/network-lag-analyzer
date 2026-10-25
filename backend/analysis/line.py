"""Internet line: DSL values from the FRITZ!Box, its event log, and outages from our own pings.

The two sources answer different questions. The FRITZ!Box knows what happened on the
line (resync, reconnect, firmware update); our pings know when the internet was really
unreachable from inside the home. An outage report for the provider needs both, and
neither is guessed from the other.
"""
from __future__ import annotations

import re
from datetime import datetime

# FRITZ!OS writes its log in the language of its UI; German and English are covered.
EVENT_KINDS: list[tuple[str, re.Pattern]] = [
    ("dsl_down", re.compile(r"DSL antwortet nicht|DSL-Synchronisierung beginnt|DSL ist nicht verfügbar|"
                            r"DSL is not responding|DSL synchroni[sz]ation (begins|started)|DSL not available", re.I)),
    ("dsl_up", re.compile(r"DSL ist verfügbar|DSL is available|DSL-Synchronisierung .*erfolgreich", re.I)),
    ("disconnected", re.compile(r"Internetverbindung wurde (getrennt|unterbrochen)|Internet connection (was )?"
                                r"(disconnected|interrupted|cut)|Zeitüberschreitung bei der PPP-Aushandlung|"
                                r"PPPoE-Fehler|Anmeldung beim Internetanbieter ist fehlgeschlagen", re.I)),
    ("renewed", re.compile(r"Internetverbindung wurde erfolgreich erneuert|Internet connection (was )?"
                           r"(successfully )?renewed|Zwangstrennung", re.I)),
    ("connected", re.compile(r"Internetverbindung wurde erfolgreich hergestellt|Internet connection "
                             r"(was )?(successfully )?established", re.I)),
    ("firmware", re.compile(r"FRITZ!OS.*(aktualisiert|Update|update)|firmware (update|updated)", re.I)),
    # Only the box itself: "WireGuard ... gestartet" and similar are not a restart of the FRITZ!Box.
    ("reboot", re.compile(r"(FRITZ!Box|System).{0,40}(neu gestartet|Neustart|restarted|rebooted)|Neustart nach", re.I)),
]
LINE_KINDS = ("dsl_down", "dsl_up", "disconnected", "renewed", "connected", "firmware", "reboot")
KIND_LABELS = {"dsl_down": "DSL sync lost", "dsl_up": "DSL synchronized", "disconnected": "Internet disconnected",
               "renewed": "Connection renewed (reconnect)", "connected": "Internet connected",
               "firmware": "Firmware update", "reboot": "FRITZ!Box restarted", "other": "Other"}


def classify(msg: str) -> str:
    for kind, rx in EVENT_KINDS:
        if rx.search(msg or ""):
            return kind
    return "other"


def parse_event(ev: dict) -> dict | None:
    """FRITZ!Box log entry → {ts, kind, grp, msg}. The box logs local time as dd.mm.yy hh:mm:ss."""
    try:
        ts = datetime.strptime(f"{ev.get('date')} {ev.get('time')}", "%d.%m.%y %H:%M:%S").timestamp()
    except (TypeError, ValueError):
        return None
    msg = (ev.get("msg") or "").strip()
    if not msg:
        return None
    return {"ts": int(ts), "kind": classify(msg), "grp": ev.get("group") or None, "msg": msg}


# ------------------------------------------------------------------ assessment of the current values
def assess(dsl: dict | None) -> tuple[str | None, list[str]]:
    """Level and findings for the current DSL values. Conservative: only clear signs are named."""
    if not dsl:
        return None, []
    if dsl.get("status") and dsl["status"].lower() != "up":
        return "critical", [f"DSL is {dsl['status']}"]
    notes, level = [], "good"
    snr = [v for v in (dsl.get("down_snr_db"), dsl.get("up_snr_db")) if v is not None]
    if snr and min(snr) < 3:
        level, notes = "critical", notes + [f"Noise margin only {min(snr):.1f} dB - the line is close to losing sync"]
    elif snr and min(snr) < 6:
        level, notes = "warning", notes + [f"Noise margin {min(snr):.1f} dB is below the usual 6 dB"]
    if dsl.get("down_kbit") and dsl.get("down_max_kbit") and dsl["down_kbit"] > dsl["down_max_kbit"]:
        notes.append("Synchronized above the attainable rate - the line has no reserve")
    return level, notes


# ------------------------------------------------------------------ history
def error_deltas(rows: list[dict], keys=("crc", "fec", "errored_secs", "severe_secs", "retrains")) -> list[dict]:
    """Cumulative counters → increase per stored interval.

    After a resync the box starts counting from 0 again; the value then IS the increase
    since the resync. A missing value stays missing - it is not 0."""
    out, prev = [], None
    for r in rows:
        d = {"ts": r["ts"]}
        for k in keys:
            cur, old = r.get(k), (prev or {}).get(k)
            d[k] = None if cur is None or old is None else (cur - old if cur >= old else cur)
        out.append(d)
        prev = r
    return out


def outages(conn, start: int, end: int, min_minutes: int = 1) -> list[dict]:
    """Periods in which no internet target answered a single ping, from the per-minute values.

    A minute without measurements ends a period: we cannot tell whether the line was down
    while the Pi itself was not measuring (reboot, power cut)."""
    out, cur, last_ts = [], None, None
    for ts, probes, lost in conn.execute(
            "SELECT ts, probes, lost FROM measurements WHERE res=60 AND ts>=? AND ts<? ORDER BY ts", (start, end)):
        down = bool(probes) and lost == probes
        contiguous = last_ts is not None and ts - last_ts == 60
        if cur and (not down or not contiguous):
            out.append(cur)
            cur = None
        if down:
            cur = cur or {"start": ts, "end": ts + 60}
            cur["end"] = ts + 60
        last_ts = ts
    if cur:
        out.append(cur)
    for o in out:
        o["minutes"] = (o["end"] - o["start"]) // 60
    return [o for o in out if o["minutes"] >= min_minutes]


def match_events(outage: dict, events: list[dict], slack: int = 300) -> list[dict]:
    """FRITZ!Box events that lie within or just around an outage (cause candidates, not proof)."""
    return [e for e in events if outage["start"] - slack <= e["ts"] <= outage["end"] + slack and e["kind"] in LINE_KINDS]

