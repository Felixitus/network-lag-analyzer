"""Measured connections per service: when, how long, how much - from the TLS server names.

Unlike the DNS estimate this is measurement: the capture saw the connection to the named
server, and how many bytes went through it. A session of a service runs from the first
connection's start to the last one's end; a pause of more than two minutes without any
connection to it starts a new session.

Not covered, and said so: connections without a readable server name (snaplen too small,
non-TLS), and QUIC (HTTP/3 over UDP 443), whose ClientHello is encrypted.
"""
from __future__ import annotations

from .dns_usage import group_name

SESSION_GAP = 120


def service_of(sni: str, classifier) -> tuple[str, str, str]:
    """(key, name, category) for a server name: the service if a rule names one, else the owner domain."""
    c = classifier.classify(sni)
    if c.service:
        return c.service, c.service_name or c.service, c.primary
    g = group_name(sni)
    return f"~{g}", (c.service_name or g), c.primary


def sessions(flows: list[dict], classifier, gap: int = SESSION_GAP) -> list[dict]:
    """flows: dicts with ts_start, ts_end, bytes_up, bytes_down, sni (only those with an sni count)."""
    by: dict[str, dict] = {}
    for f in sorted((f for f in flows if f.get("sni")), key=lambda f: f["ts_start"]):
        key, name, cat = service_of(f["sni"], classifier)
        s = by.setdefault(key, {"service": key, "name": name, "category": cat, "sessions": [], "servers": set()})
        s["servers"].add(f["sni"])
        cur = s["sessions"][-1] if s["sessions"] else None
        if cur and f["ts_start"] - cur["end"] <= gap:
            cur["end"] = max(cur["end"], f["ts_end"])
            cur["bytes"] += f["bytes_up"] + f["bytes_down"]
            cur["connections"] += 1
        else:
            s["sessions"].append({"start": f["ts_start"], "end": f["ts_end"], "bytes": f["bytes_up"] + f["bytes_down"],
                                  "connections": 1})
    out = []
    for s in by.values():
        ss = s["sessions"]
        out.append({"service": s["service"], "name": s["name"], "category": s["category"],
                    "servers": sorted(s["servers"])[:8], "sessions": ss, "session_count": len(ss),
                    "seconds": sum(x["end"] - x["start"] for x in ss), "bytes": sum(x["bytes"] for x in ss)})
    return sorted(out, key=lambda x: -x["bytes"])


def coverage(flows: list[dict]) -> dict:
    """How much of the device's traffic the server names explain."""
    total = sum(f["bytes_up"] + f["bytes_down"] for f in flows)
    named = sum(f["bytes_up"] + f["bytes_down"] for f in flows if f.get("sni"))
    quic = sum(f["bytes_up"] + f["bytes_down"] for f in flows if f["proto"] == "udp" and f["remote_port"] == 443)
    return {"bytes": total, "named_bytes": named, "quic_bytes": quic,
            "named_share": named / total if total else None, "quic_share": quic / total if total else None}
