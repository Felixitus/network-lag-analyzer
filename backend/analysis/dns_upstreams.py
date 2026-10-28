"""How fast Pi-hole's upstream DNS servers answer, from Pi-hole's own query log.

Passive: nothing extra is sent. Every query Pi-hole forwards is logged with the server it
went to and the time the answer took (`reply_time`). Cached answers never reach an
upstream and are not part of it.

"No reply recorded" is said that way on purpose. FTL logs no reply time when the server
did not answer - but also when dnsmasq asked again and another server answered first.
Queries younger than `SETTLE_S` are left out of that share: their reply may still come.
"""
from __future__ import annotations

import math

KNOWN = {
    "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare", "2606:4700:4700::1111": "Cloudflare",
    "2606:4700:4700::1001": "Cloudflare", "8.8.8.8": "Google", "8.8.4.4": "Google",
    "2001:4860:4860::8888": "Google", "2001:4860:4860::8844": "Google",
    "9.9.9.9": "Quad9", "149.112.112.112": "Quad9", "9.9.9.10": "Quad9 (unfiltered)",
    "149.112.112.10": "Quad9 (unfiltered)", "9.9.9.11": "Quad9 (ECS)",
}
SETTLE_S = 120
SLOW_FACTOR = 2.0        # median this much above the fastest server ...
SLOW_MIN_MS = 30.0       # ... and at least this much slower, before it is called slow
NO_REPLY_PCT = 5.0
MIN_QUERIES = 20         # fewer than this and a median says little


def label(forward: str) -> tuple[str, str | None]:
    """'9.9.9.10#53' → ('9.9.9.10', 'Quad9 (unfiltered)'); a port other than 53 stays visible."""
    addr, _, port = forward.rpartition("#") if "#" in forward else (forward, "", "53")
    shown = addr if port in ("", "53") else forward
    if addr.startswith("127.") or addr == "::1":
        return shown, "local resolver (e.g. unbound)"
    return shown, KNOWN.get(addr)


def _q(sorted_vals: list[float], q: float) -> float | None:
    """Nearest-rank quantile."""
    if not sorted_vals:
        return None
    i = min(len(sorted_vals) - 1, max(0, math.ceil(q * len(sorted_vals)) - 1))
    return sorted_vals[i]


def _stats(items: list[tuple[float, float | None]], settled_before: float) -> dict:
    ms = sorted(r * 1000 for _ts, r in items if r is not None)
    settled = [r for ts, r in items if ts < settled_before]
    no_reply = sum(1 for r in settled if r is None)
    return {"forwarded": len(items), "answered": len(ms), "no_reply": no_reply,
            "no_reply_pct": round(100 * no_reply / len(settled), 1) if settled else None,
            "median_ms": None if not ms else round(_q(ms, 0.5), 1),
            "p95_ms": None if not ms else round(_q(ms, 0.95), 1),
            "max_ms": None if not ms else round(ms[-1], 1)}


def summarize(rows: list[tuple[float, str, float | None]], start: float, end: float, now: float,
              bucket: int = 3600) -> dict:
    """Per upstream server: totals over the range and one value per `bucket` seconds."""
    settled_before = now - SETTLE_S
    by: dict[str, list[tuple[float, float | None]]] = {}
    for ts, fwd, reply in rows:
        by.setdefault(fwd, []).append((ts, reply))
    servers = []
    for fwd, items in by.items():
        shown, name = label(fwd)
        buckets: dict[int, list] = {}
        for ts, r in items:
            buckets.setdefault(int(ts // bucket * bucket), []).append((ts, r))
        series = [{"ts": b, **_stats(v, settled_before)} for b, v in sorted(buckets.items())]
        servers.append({"upstream": shown, "name": name, **_stats(items, settled_before), "series": series})
    servers.sort(key=lambda s: -s["forwarded"])
    return {"start": start, "end": end, "bucket": bucket, "servers": servers, "notes": assess(servers)}


def assess(servers: list[dict]) -> list[str]:
    notes = []
    enough = [s for s in servers if s["answered"] >= MIN_QUERIES and s["median_ms"] is not None]
    if len(enough) >= 2:
        fastest = min(enough, key=lambda s: s["median_ms"])
        for s in enough:
            if s is not fastest and s["median_ms"] >= fastest["median_ms"] * SLOW_FACTOR \
                    and s["median_ms"] - fastest["median_ms"] >= SLOW_MIN_MS:
                notes.append(f"{s['upstream']} answers clearly slower than {fastest['upstream']} "
                             f"(median {s['median_ms']:.0f} ms against {fastest['median_ms']:.0f} ms).")
    for s in servers:
        if (s["no_reply_pct"] or 0) >= NO_REPLY_PCT and s["forwarded"] >= MIN_QUERIES:
            notes.append(f"For {s['no_reply_pct']} % of the queries to {s['upstream']} no reply was recorded "
                         "- the server did not answer, or another one answered first.")
    if not servers:
        notes.append("No forwarded queries in this range - everything came from the cache or was blocked.")
    return notes
