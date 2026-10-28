"""Reading a path measurement: from which hop on do losses or delays begin?

Rules, and why they are this cautious:

* A hop that drops answers while later hops answer fine is NOT where packets get lost.
  Routers answer traceroutes at low priority and limit those answers; the traffic itself
  is forwarded. Only loss that continues up to the target counts.
* A hop that never answers ("no answer") is normal for many routers and says nothing.
* The segment comes from the address alone: RFC 1918 and link-local addresses are your own network,
  100.64.0.0/10 is the provider's carrier-grade NAT, the first public hop after your
  network is "usually your provider". Which provider owns an address is not looked up.
"""
from __future__ import annotations

import ipaddress

LOSS_PCT = 20.0          # 2 of 10 rounds - one lost answer can be a single dropped reply
DELAY_STEP_MS = 30.0     # a delay that appears at one hop and stays to the target
CGNAT = ipaddress.ip_network("100.64.0.0/10")
# Not `is_private`: that also covers documentation and benchmark ranges, which are not a home network.
HOME_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
                                               "fc00::/7", "fe80::/10")]


def segment(ip: str | None, seen_public: bool) -> str | None:
    if not ip:
        return None
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if a in CGNAT:
        return "provider"
    if any(a in n for n in HOME_NETS if n.version == a.version):
        return "home"
    return "beyond" if seen_public else "provider"


SEGMENT_LABELS = {"home": "your network", "provider": "usually your provider", "beyond": "further along the path"}


def annotate(hops: list[dict]) -> list[dict]:
    """Adds `segment` to every hop. The first public hop is the provider's, later ones are beyond."""
    out, seen_public = [], False
    for h in hops:
        seg = segment(h.get("ip"), seen_public)
        if seg in ("provider", "beyond") and ipaddress.ip_address(h["ip"]) not in CGNAT:
            seen_public = True
        out.append({**h, "segment": seg, "segment_label": SEGMENT_LABELS.get(seg)})
    return out


def _where(h: dict) -> str:
    seg = h.get("segment_label")
    return f"hop {h['ttl']} ({h['ip']}{', ' + seg if seg else ''})"


def assess(trace: dict) -> dict:
    """Plain findings for a measurement. `verdict` is one of: error, clean, loss, delay, unreached."""
    if trace.get("error"):
        return {"verdict": "error", "findings": [f"Path measurement not available: {trace['error']}"]}
    hops = annotate(trace.get("hops") or [])
    answering = [h for h in hops if h.get("received")]
    findings: list[str] = []
    if not answering:
        return {"verdict": "unreached", "hops": hops,
                "findings": ["No hop answered - not even your router. The measurement itself did not get out."]}
    last = answering[-1]
    verdict = "clean"

    # Loss that continues: from the first hop whose loss stays at or above the limit on every
    # answering hop after it, the target included.
    start = None
    for i, h in enumerate(answering):
        if all((x.get("loss_pct") or 0) >= LOSS_PCT for x in answering[i:]):
            start = h
            break
    if trace.get("reached") and start is not None:
        verdict = "loss"
        findings.append(f"Losses begin at {_where(start)} and continue to the target "
                        f"({last.get('loss_pct')} % at the target).")
    elif not trace.get("reached"):
        verdict = "unreached"
        findings.append(f"The target did not answer. The last hop that answered was {_where(last)}.")

    # Delay that appears at one hop and stays.
    prev = None
    for i, h in enumerate(answering):
        if prev is not None and h.get("rtt_avg") is not None and prev.get("rtt_avg") is not None:
            step = h["rtt_avg"] - prev["rtt_avg"]
            rest = [x["rtt_avg"] for x in answering[i:] if x.get("rtt_avg") is not None]
            if step >= DELAY_STEP_MS and rest and min(rest) - prev["rtt_avg"] >= DELAY_STEP_MS:
                findings.append(f"The delay grows by {step:.0f} ms at {_where(h)} and stays up to the target.")
                if verdict == "clean":
                    verdict = "delay"
                break
        if h.get("rtt_avg") is not None:
            prev = h

    # Loss only in the middle: say plainly that it is not the problem.
    for h in answering[:-1]:
        if (h.get("loss_pct") or 0) >= LOSS_PCT and (start is None or h["ttl"] < start["ttl"]):
            later = [x for x in answering if x["ttl"] > h["ttl"]]
            if later and min(x.get("loss_pct") or 0 for x in later) < LOSS_PCT:
                findings.append(f"{_where(h).capitalize()} drops {h['loss_pct']} % of the answers, but later hops "
                                "do not - that router only answers traceroutes sparingly, traffic passes.")
    silent = [h["ttl"] for h in hops if not h.get("received") and h["ttl"] < last["ttl"]]
    if silent:
        findings.append(f"Hop{'s' if len(silent) > 1 else ''} {', '.join(map(str, silent))} never answered "
                        "- normal for many routers, it says nothing about the path.")
    if verdict == "clean":
        findings.insert(0, "No losses or delay jumps on the path to the target during the measurement.")
    return {"verdict": verdict, "hops": hops, "findings": findings}


def pick_targets(targets: list[dict], rows: list[dict], n: int = 2) -> list[dict]:
    """Which targets to measure the path to: a game target first, then the internet targets
    that lost the most probes (then the highest latency) in `rows`.

    `targets`: dicts with target_id, address (resolved IPv4), kind, name.
    """
    def score(t: dict) -> tuple:
        lost = sum(((r.get("targets") or {}).get(t["target_id"]) or {}).get("lost") or 0 for r in rows)
        rtts = [v for r in rows if (v := ((r.get("targets") or {}).get(t["target_id"]) or {}).get("rtt")) is not None]
        return (t["kind"] == "game", lost, max(rtts) if rtts else -1.0)

    cands = [t for t in targets if t.get("kind") in ("internet", "game") and t.get("address")]
    return sorted(cands, key=score, reverse=True)[:n]
