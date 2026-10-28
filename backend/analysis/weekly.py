"""The weekly report: the past seven days of the network in a few lines for the phone.

Built only from what was measured. A week in which the Pi was off for two days says
"measured 71 % of the week" instead of looking calmer than it was (hard rule 1), and
every section that had no data says so instead of "none".
"""
from __future__ import annotations

import time

from ..database import repository as repo
from . import line

WEEK = 7 * 86400
DAYS = ("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")


def measured_share(conn, start: int, end: int) -> float:
    """Share of the minutes with ping measurements at all."""
    n = conn.execute("SELECT COUNT(*) FROM measurements WHERE res=60 AND ts>=? AND ts<? AND probes>0",
                     (start, end)).fetchone()[0]
    return min(1.0, n * 60 / (end - start))


def worst_hours(conn, start: int, end: int, warn_ms: float, n: int = 3) -> list[dict]:
    """Hours with the most packet loss, then the highest latency - only hours that were bad at all.

    Minutes in which no target answered are left out: those are outages and listed as such."""
    out = []
    for h, probes, lost, avg, mx, minutes in conn.execute(
            """SELECT ts / 3600 * 3600 AS h, SUM(probes), SUM(lost), CAST(ROUND(AVG(rtt_avg)) AS INTEGER),
                      MAX(rtt_max), COUNT(*)
               FROM measurements WHERE res=60 AND ts>=? AND ts<? AND probes>0 AND lost<probes GROUP BY h""",
            (start, end)):
        loss = 100 * lost / probes
        rtt = repo.dec(avg, "rtt_avg")
        if loss < 1 and (rtt is None or rtt < warn_ms):
            continue
        out.append({"ts": h, "loss_pct": round(loss, 1), "rtt_ms": rtt, "rtt_max_ms": repo.dec(mx, "rtt_max"),
                    "minutes": minutes})
    return sorted(out, key=lambda x: (-x["loss_pct"], -(x["rtt_ms"] or 0)))[:n]


def incident_causes(conn, start: int, end: int) -> list[tuple[str, int]]:
    return [(c or "unknown", k) for c, k in conn.execute(
        "SELECT category, COUNT(*) FROM incidents WHERE source='auto' AND ts_start>=? AND ts_start<? "
        "GROUP BY category ORDER BY 2 DESC", (start, end))]


def line_events(conn, start: int, end: int) -> dict[str, int]:
    return dict(conn.execute("SELECT kind, COUNT(*) FROM fritz_events WHERE ts>=? AND ts<? "
                             "AND kind IN ('dsl_down', 'disconnected') GROUP BY kind", (start, end)).fetchall())


def collect(conn, start: int, end: int, warn_ms: float) -> dict:
    """Everything of the report that comes from the database (blocking: run in the reader)."""
    return {"measured": measured_share(conn, start, end), "outages": line.outages(conn, start, end),
            "worst_hours": worst_hours(conn, start, end, warn_ms), "incidents": incident_causes(conn, start, end),
            "line_events": line_events(conn, start, end)}


def _when(ts: float) -> str:
    t = time.localtime(ts)
    return f"{DAYS[t.tm_wday][:3]} {time.strftime('%d.%m. %H:%M', t)}"


def _minutes(m: int) -> str:
    return f"{m} min" if m < 120 else f"{m / 60:.1f} h"


def render(r: dict) -> tuple[str, str]:
    """(title, body) as plain text: it goes to ntfy, Telegram and e-mail alike."""
    start, end = r["start"], r["end"]
    title = f"Weekly report {time.strftime('%d.%m.', time.localtime(start))}–{time.strftime('%d.%m.%Y', time.localtime(end - 1))}"
    L = [f"Measured {100 * r['measured']:.0f} % of the week."
         + (" Gaps are not counted as good or bad." if r["measured"] < 0.95 else "")]

    L.append("")
    outs = r["outages"]
    if outs:
        total = sum(o["minutes"] for o in outs)
        longest = max(outs, key=lambda o: o["minutes"])
        L.append(f"INTERNET OUTAGES: {len(outs)}, {_minutes(total)} in total; longest {_minutes(longest['minutes'])} "
                 f"on {_when(longest['start'])}.")
    else:
        L.append("INTERNET OUTAGES: none measured.")
    ev = r["line_events"]
    if ev:
        L.append("FRITZ!Box: " + ", ".join(f"{n}× {line.KIND_LABELS.get(k, k)}" for k, n in sorted(ev.items())) + ".")

    L.append("")
    wh = r["worst_hours"]
    if wh:
        L.append("WORST HOURS:")
        for x in wh:
            rtt = f", ping {x['rtt_ms']:.0f} ms (max {x['rtt_max_ms']:.0f})" if x["rtt_ms"] is not None else ""
            L.append(f"- {_when(x['ts'])}: {x['loss_pct']:.1f} % loss{rtt}")
    else:
        L.append("WORST HOURS: no hour with loss or high ping.")
    inc = r["incidents"]
    if inc:
        L.append(f"Incidents: {sum(n for _c, n in inc)} (" + ", ".join(f"{c} {n}" for c, n in inc[:4]) + ").")

    L.append("")
    new = r["new_devices"]
    if new:
        L.append(f"NEW DEVICES: {len(new)}")
        L += [f"- {d['name']} ({d.get('vendor') or d['mac']}), first seen {_when(d['first_seen'])}" for d in new[:8]]
        if len(new) > 8:
            L.append(f"- and {len(new) - 8} more")
    else:
        L.append("NEW DEVICES: none.")

    L.append("")
    dns = r.get("dns")
    if dns is None:
        L.append(f"DNS: not available{' - ' + r['dns_error'] if r.get('dns_error') else ''}.")
    else:
        flagged = [d for d in dns["devices"] if d["level"] in ("bypassing", "partial")]
        if flagged:
            L.append("DNS PAST PI-HOLE (signs, not proof):")
            L += [f"- {d['client']['name']}: {d['text']}" for d in flagged[:6]]
        else:
            L.append("DNS: no device shows signs of resolving past Pi-hole.")
        for t in dns.get("threats", [])[:5]:
            L.append(f"Malware/phishing lookups: {t['client']['name']} {t['lookups']}× ({', '.join(t['names'][:3])})")
    return title, "\n".join(L).strip()


def due(now: float, last: float | None, weekday: int, hour: int) -> bool:
    """On the configured weekday from the configured hour on, once a week - also if the Pi was
    off at exactly that hour, the report follows as soon as it is back the same day."""
    t = time.localtime(now)
    return t.tm_wday == weekday and t.tm_hour >= hour and (last is None or now - last > 6 * 86400)
