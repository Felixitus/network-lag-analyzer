"""Ursachenanalyse (Root Cause Rules).

Jede Regel ist eine eigene Funktion `rule_*` mit dokumentierter Logik. Eine Regel
bekommt ein `Window` (alle Messwerte rund um den Incident) und liefert entweder
None (trifft nicht zu) oder ein `Finding` mit Punktzahl und Evidenzliste.

Die Regel mit der höchsten Punktzahl wird als Ursache gewählt. Die Confidence
leitet sich aus der Punktzahl ab und wird bewusst vorsichtig formuliert:

    Punktzahl >= 80  → high   → "wahrscheinlicher Verursacher"
    Punktzahl >= 55  → medium → "möglicher Verursacher"
    sonst            → low    → "zeitlich korreliert"

Grundsätze:
* Keine Kausalität vortäuschen: Gleichzeitigkeit allein ergibt höchstens "low".
* Ein Gerät wird nur benannt, wenn Traffic pro Gerät tatsächlich gemessen wurde.
* Fehlende Datenquellen werden in `notes` ausdrücklich genannt.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Callable

from . import bufferbloat
from .events import (CONNECTION_DROP, DNS_FAILURE)

CATEGORY_LABELS = {
    "upload": "Upload-Sättigung / Bufferbloat",
    "download": "Download-Sättigung / Bufferbloat",
    "local": "LAN/WLAN/Router-Problem",
    "wan": "WAN/ISP-Problem",
    "target": "Zielserver/Routing",
    "game_server": "Game-Server/Routing",
    "loss": "Paketverluste/Übertragungsprobleme",
    "dns": "DNS-Störung",
    "drop_wan": "Internet-Ausfall (WAN)",
    "drop_local": "Verbindungsverlust im LAN",
    "unknown": "Unbekannt",
}
CONFIDENCE_LABELS = {"high": "wahrscheinlicher Verursacher", "medium": "möglicher Verursacher",
                     "low": "zeitlich korreliert"}

TARGET_DELTA_MS = 25.0       # ab dieser Erhöhung gilt ein Ziel als "betroffen"
UTIL_HIGH = 0.6              # Auslastung, ab der eine Leitung als "hoch ausgelastet" zählt
DOMINANT_SHARE = 0.6         # Anteil am Gesamt-Traffic, ab dem ein Gerät dominiert


# =============================================================================== Datenmodell
@dataclass
class Window:
    rows: list[dict]                   # 1-s-Zeilen [t0 - pre, t1 + post]
    t0: int                            # Beginn der Auffälligkeit
    t1: int                            # Ende der Auffälligkeit
    targets: dict[int, dict]           # target_id → {"address", "name", "kind"}
    events: list[dict] = field(default_factory=list)
    cap_down: float | None = None      # bit/s
    cap_up: float | None = None
    cap_source: str | None = None      # config | tr064 | learned
    thresholds: object | None = None
    device_label: Callable[[str], dict] = lambda mac: {"mac": mac, "name": mac, "ip": None}
    gaming: dict | None = None         # aktive Gaming Session (server_ip, mac, …)

    # ---- abgeleitete Größen (lazy) ----
    def pre(self) -> list[dict]:
        return [r for r in self.rows if r["ts"] < self.t0]

    def inside(self) -> list[dict]:
        return [r for r in self.rows if self.t0 <= r["ts"] <= self.t1]

    def around(self, before: int = 10) -> list[dict]:
        return [r for r in self.rows if self.t0 - before <= r["ts"] <= self.t1]

    @property
    def traffic_available(self) -> bool:
        return any(r.get("up_bps") is not None for r in self.inside())

    @property
    def per_device_available(self) -> bool:
        return any((r.get("traffic_src") or "").startswith("capture") for r in self.inside())

    def events_of(self, *types: str) -> list[dict]:
        return [e for e in self.events if e["type"] in types]


@dataclass
class Finding:
    rule: str
    category: str
    score: int
    cause: str
    evidence: list[str]
    device: dict | None = None
    details: dict = field(default_factory=dict)


# =============================================================================== Hilfsfunktionen
def _med(vals: list[float | None]) -> float | None:
    v = [x for x in vals if x is not None]
    return statistics.median(v) if v else None


def _max(vals: list[float | None]) -> float | None:
    v = [x for x in vals if x is not None]
    return max(v) if v else None


def _mbit(bps: float | None) -> str:
    return "n/a" if bps is None else f"{bps / 1e6:.1f} Mbit/s"


def _gw_threshold(w: Window) -> float:
    t = w.thresholds
    base = _med([r.get("gw_rtt") for r in w.pre()]) or 1.0
    return max(getattr(t, "gateway_warning", 20.0), base * 3 + 2)


def gateway_stats(w: Window) -> dict:
    ins = w.inside()
    return {
        "before": _med([r.get("gw_rtt") for r in w.pre()]),
        "peak": _max([r.get("gw_rtt") for r in ins]),
        "lost": sum(r.get("gw_lost") or 0 for r in ins),
        "probes": sum(r.get("gw_probes") or 0 for r in ins),
    }


def gateway_stable(w: Window) -> bool | None:
    g = gateway_stats(w)
    if g["probes"] == 0:
        return None
    return (g["peak"] is None or g["peak"] < _gw_threshold(w)) and g["lost"] == 0


def target_impact(w: Window) -> dict[int, dict]:
    """Pro Internet-/Game-Ziel: Baseline, Spitze, Verluste, betroffen ja/nein."""
    out: dict[int, dict] = {}
    for tid, info in w.targets.items():
        if info["kind"] == "gateway":
            continue
        pre = [r["targets"].get(tid, {}).get("rtt") for r in w.pre() if r.get("targets")]
        ins = [r["targets"].get(tid, {}) for r in w.inside() if r.get("targets")]
        base = _med(pre)
        peak = _max([x.get("max") for x in ins])
        lost = sum(x.get("lost") or 0 for x in ins)
        probes = sum(x.get("probes") or 0 for x in ins)
        if probes == 0:
            continue
        elevated = peak is not None and base is not None and peak - base >= TARGET_DELTA_MS and peak >= base * 1.8
        out[tid] = {"address": info["address"], "name": info.get("name"), "kind": info["kind"], "base": base,
                    "peak": peak, "lost": lost, "probes": probes, "affected": elevated or lost > 0,
                    "elevated": elevated}
    return out


def utilization(w: Window, direction: str) -> tuple[list[float], float | None]:
    """Auslastung je Sekunde im Incident (0..1) bezogen auf die Kapazität."""
    cap = w.cap_up if direction == "up" else w.cap_down
    key = "up_bps" if direction == "up" else "down_bps"
    if not cap:
        return [], None
    vals = [r[key] / cap for r in w.inside() if r.get(key) is not None]
    return vals, (max(vals) if vals else None)


def device_rates(w: Window, rows: list[dict], direction: str) -> dict[str, list[tuple[int, float]]]:
    """mac → [(ts, bit/s)] für Upload (tx) bzw. Download (rx)."""
    idx = 1 if direction == "up" else 0
    out: dict[str, list[tuple[int, float]]] = {}
    for r in rows:
        for mac, v in (r.get("devices") or {}).items():
            out.setdefault(mac, []).append((r["ts"], v[idx] * 8.0))
    return out


def top_device(w: Window, direction: str) -> tuple[str | None, float, float]:
    """(mac, Anteil am Gesamt-Traffic im Incident, Spitzenrate) des stärksten Geräts."""
    rates = device_rates(w, w.inside(), direction)
    if not rates:
        return None, 0.0, 0.0
    totals = {m: sum(v for _, v in s) for m, s in rates.items()}
    grand = sum(totals.values())
    if grand <= 0:
        return None, 0.0, 0.0
    mac = max(totals, key=totals.get)
    return mac, totals[mac] / grand, max(v for _, v in rates[mac])


def onset(w: Window, series: list[tuple[int, float]], level: float) -> int | None:
    """Beginn des zusammenhängenden Abschnitts >= level, der den Incident-Start berührt."""
    by_ts = dict(series)
    t = None
    s = w.t0 + 1
    # vom Incident-Start aus rückwärts suchen
    for ts in range(s, w.t0 - 60, -1):
        if by_ts.get(ts, 0.0) >= level:
            t = ts
        elif t is not None:
            break
    if t is not None:
        return t
    # sonst: erster Zeitpunkt innerhalb des Incidents
    for ts in range(w.t0, w.t1 + 1):
        if by_ts.get(ts, 0.0) >= level:
            return ts
    return None


def latency_onset(w: Window) -> int:
    """Erste Sekunde, in der die Internet-RTT deutlich über der Baseline lag oder Verlust auftrat."""
    base = _med([r.get("rtt_avg") for r in w.pre()])
    for r in w.around(0):
        rtt = r.get("rtt_avg")
        if (r.get("lost") or 0) > 0 or (rtt is not None and base is not None and rtt - base >= TARGET_DELTA_MS):
            return r["ts"]
    return w.t0


def _confidence(score: int) -> str:
    return "high" if score >= 80 else "medium" if score >= 55 else "low"


# =============================================================================== Regeln
def _saturation_rule(w: Window, direction: str) -> Finding | None:
    """Gemeinsame Logik für Upload- und Download-Sättigung (Bufferbloat).

    Hintergrund: Ist eine Richtung der Leitung voll ausgelastet, füllen sich die
    Puffer im Router/Modem und ALLE Pakete (auch Game-Pakete und Pings) warten.
    Typisch: Router-Ping bleibt niedrig, alle Internetziele steigen gleichzeitig.

    Evidenz und Punkte:
      E1 (Pflicht, 40)  Richtung im Incident >= 60 % ausgelastet (mind. die Hälfte der Sekunden)
      E2 (20)           Traffic-Anstieg begann vor oder mit dem Latenzanstieg
      E3 (15)           Router-Latenz blieb stabil (spricht gegen LAN/WLAN-Problem)
      E4 (10)           mehrere Internetziele gleichzeitig betroffen (gemeinsamer Engpass)
      E5 (15)           ein Gerät verursacht >= 60 % des Traffics → wird benannt
    """
    utils, peak_util = utilization(w, direction)
    name = "Upload" if direction == "up" else "Download"
    key = "up_bps" if direction == "up" else "down_bps"
    if peak_util is None:
        return None
    high_secs = sum(1 for u in utils if u >= UTIL_HIGH)
    if not utils or high_secs < max(1, len(utils) / 2):
        return None
    score = 40
    ev = [f"{name}-Auslastung bis {peak_util * 100:.0f} % der Leitung "
          f"({_mbit(_max([r.get(key) for r in w.inside()]))} von {_mbit(w.cap_up if direction == 'up' else w.cap_down)}"
          f"{', Kapazität geschätzt' if w.cap_source == 'learned' else ''})"]
    cap = w.cap_up if direction == "up" else w.cap_down
    total_series = [(r["ts"], r.get(key) or 0.0) for r in w.rows]
    lat_on = latency_onset(w)
    t_on = onset(w, total_series, cap * UTIL_HIGH * 0.8)
    if t_on is not None and t_on <= lat_on + 1:
        score += 20
        ev.append(f"{name}-Anstieg begann {'vor' if t_on < lat_on else 'gleichzeitig mit'} dem Latenzanstieg "
                  f"({lat_on - t_on} s vorher)" if t_on < lat_on else f"{name}-Anstieg zeitgleich mit dem Latenzanstieg")
    if high_secs >= len(utils) * 0.8:
        ev.append(f"{name} blieb während fast des gesamten Incidents hoch")
    gs = gateway_stable(w)
    if gs:
        score += 15
        ev.append("Router-Latenz blieb stabil")
    impacted = [t for t in target_impact(w).values() if t["affected"] and t["kind"] == "internet"]
    if len(impacted) >= 2:
        score += 10
        ev.append(f"{len(impacted)} externe Ziele zeigten gleichzeitig erhöhte Latenz/Verlust")
    device = None
    if w.per_device_available:
        mac, share, dev_peak = top_device(w, direction)
        if mac and share >= DOMINANT_SHARE:
            score += 15
            device = {**w.device_label(mac), "share": round(share, 2), "peak_bps": dev_peak}
            ev.append(f"{device['name']} verursachte {share * 100:.0f} % des {name}s (Spitze {_mbit(dev_peak)})")
            dev_on = onset(w, device_rates(w, w.rows, direction).get(mac, []), dev_peak * 0.5)
            if dev_on is not None:
                device["onset"] = dev_on
        elif mac:
            ev.append(f"Kein einzelnes Gerät dominiert (stärkstes: {w.device_label(mac)['name']} mit {share * 100:.0f} %)")
    cause = f"{name}-Sättigung" + (f" durch {device['name']}" if device else "")
    if not w.per_device_available:
        cause += " (Gerät nicht bestimmbar – kein Traffic pro Gerät verfügbar)"
    return Finding(f"rule_{direction}load_saturation", "upload" if direction == "up" else "download",
                   score, cause, ev, device, {"peak_util": round(peak_util, 3), "onset": t_on})


def rule_upload_saturation(w: Window) -> Finding | None:
    """Hoher Upload eines Gerätes + gleichzeitig Internet-Ping/Jitter hoch → Upload Saturation/Bufferbloat."""
    return _saturation_rule(w, "up")


def rule_download_saturation(w: Window) -> Finding | None:
    """Hoher Download + Ping-Spike → Download Saturation/Bufferbloat."""
    return _saturation_rule(w, "down")


def rule_local_problem(w: Window) -> Finding | None:
    """Gateway-Ping hoch + Internet-Ping hoch → mögliches LAN/WLAN/Routerproblem.

    Der Router ist nur einen Hop entfernt. Steigt schon dessen Latenz (oder
    antwortet er nicht), liegt das Problem vor dem Internetanschluss: LAN, WLAN,
    Router-CPU – oder die Anbindung des Raspberry Pi selbst.
      Pflicht (50)  Router-Latenz über Schwelle oder Router-Verluste
      +20           Internetziele gleichzeitig betroffen
      +15           Router-Anstieg begann nicht nach dem Internet-Anstieg
    Abzug -25, wenn gleichzeitig eine Leitung stark ausgelastet ist (ein
    ausgelasteter Router antwortet oft verzögert auf ICMP).
    """
    g = gateway_stats(w)
    if g["probes"] == 0:
        return None
    thr = _gw_threshold(w)
    bad = (g["peak"] is not None and g["peak"] >= thr) or g["lost"] > 0
    if not bad:
        return None
    score = 50
    ev = [f"Router-Latenz {g['before'] or 0:.1f} → {g['peak'] or 0:.1f} ms"
          + (f", {g['lost']}/{g['probes']} Router-Probes verloren" if g["lost"] else "")]
    impacted = [t for t in target_impact(w).values() if t["affected"]]
    if impacted:
        score += 20
        ev.append("Internetziele gleichzeitig betroffen")
    gw_series = [(r["ts"], r.get("gw_rtt") or (thr if (r.get("gw_lost") or 0) else 0.0)) for r in w.rows]
    gw_on = onset(w, gw_series, thr)
    if gw_on is not None and gw_on <= latency_onset(w):
        score += 15
        ev.append("Router-Latenz stieg zuerst bzw. gleichzeitig")
    for d in ("up", "down"):
        _, pu = utilization(w, d)
        if pu is not None and pu >= 0.85:
            score -= 25
            ev.append(f"Achtung: {'Upload' if d == 'up' else 'Download'} gleichzeitig stark ausgelastet – "
                      "Router könnte nur wegen Last langsam auf Pings antworten")
    ev.append("Hinweis: Gemessen vom Raspberry Pi aus – auch dessen eigene LAN/WLAN-Anbindung kann betroffen sein")
    return Finding("rule_local_problem", "local", score, "LAN/WLAN- oder Router-Problem", ev)


def rule_wan_isp(w: Window) -> Finding | None:
    """Gateway normal + Internet-Ping hoch → WAN/ISP/Bufferbloat möglich.

    Router antwortet normal, aber mehrere externe Ziele gleichzeitig schlecht und
    keine eigene Leitungsauslastung → Engpass hinter dem Router (Anschluss/ISP).
      Pflicht (45)  Router stabil UND mindestens 2 Internetziele betroffen
      +15           alle Internetziele betroffen
      +10           keine Leitung über 50 % ausgelastet (eigener Traffic unwahrscheinlich)
      +10           Retransmissions in Download-Richtung erhöht (Verluste vor dem Router)
    """
    if not gateway_stable(w):
        return None
    ti = [t for t in target_impact(w).values() if t["kind"] == "internet"]
    impacted = [t for t in ti if t["affected"]]
    if len(impacted) < 2:
        return None
    score = 45
    ev = ["Router-Latenz blieb stabil",
          f"{len(impacted)} von {len(ti)} externen Zielen betroffen: " +
          ", ".join(f"{t['name'] or t['address']}" for t in impacted)]
    if len(impacted) == len(ti):
        score += 15
    utils = [utilization(w, d)[1] for d in ("up", "down")]
    if all(u is not None for u in utils) and max(utils) < 0.5:
        score += 10
        ev.append("Eigene Leitung nicht ausgelastet – Engpass vermutlich beim Anschluss/ISP")
    elif all(u is None for u in utils):
        ev.append("Leitungsauslastung unbekannt – Upload/Download-Sättigung nicht ausschließbar")
    rd = sum(r.get("retrans_down") or 0 for r in w.inside())
    if rd >= 5:
        score += 10
        ev.append(f"{rd} TCP-Retransmissions aus dem Internet (Verluste vor dem Router)")
    return Finding("rule_wan_isp", "wan", score, "WAN/ISP-Problem oder Bufferbloat beim Anschluss", ev)


def rule_multi_target_loss(w: Window) -> Finding | None:
    """Mehrere externe Ziele gleichzeitig Packet Loss → WAN/ISP wahrscheinlicher als einzelner Server.

      Pflicht (55)  in derselben Sekunde Verluste bei >= 2 Internetzielen, Router ohne Verlust
      +15           in mehreren Sekunden aufgetreten
      +10           Router-Latenz stabil
    """
    ids = [tid for tid, i in w.targets.items() if i["kind"] == "internet"]
    multi_secs = 0
    for r in w.inside():
        lost_targets = sum(1 for tid in ids if (r.get("targets") or {}).get(tid, {}).get("lost"))
        if lost_targets >= 2:
            multi_secs += 1
    g = gateway_stats(w)
    if multi_secs == 0 or g["lost"] > 0:
        return None
    score = 55 + (15 if multi_secs >= 2 else 0)
    ev = [f"In {multi_secs} Sekunde(n) Paketverlust bei mehreren externen Zielen gleichzeitig",
          "Router ohne Paketverlust"]
    if gateway_stable(w):
        score += 10
    # Eigene Sättigung kann ebenfalls Verluste verursachen → Abzug
    for d in ("up", "down"):
        _, pu = utilization(w, d)
        if pu is not None and pu >= 0.85:
            score -= 30
            ev.append(f"{'Upload' if d == 'up' else 'Download'} zeitgleich stark ausgelastet – Verluste evtl. durch eigenen Traffic")
    return Finding("rule_multi_target_loss", "wan", score, "Paketverlust hinter dem Router (WAN/ISP)", ev)


def rule_single_target(w: Window) -> Finding | None:
    """Gateway normal + Internet normal + einzelnes Ziel problematisch → Zielserver/Routingproblem möglich.
    Nur ein externes Ziel betroffen → Routing/Zielserver wahrscheinlicher.

      Pflicht (50)  genau ein Ziel betroffen, alle anderen normal, Router stabil
      +10           das Ziel hatte Paketverluste
      +10           das Ziel ist der Game-Server
    """
    ti = target_impact(w)
    impacted = [t for t in ti.values() if t["affected"]]
    normal = [t for t in ti.values() if not t["affected"]]
    if len(impacted) != 1 or not normal or gateway_stable(w) is False:
        return None
    t = impacted[0]
    score = 50
    ev = [f"Nur {t['name'] or t['address']} betroffen "
          f"({(t['base'] or 0):.0f} → {(t['peak'] or 0):.0f} ms, {t['lost']}/{t['probes']} verloren)",
          f"{len(normal)} andere Ziele normal", "Router-Latenz stabil"]
    if t["lost"]:
        score += 10
    cat = "target"
    if t["kind"] == "game":
        score += 10
        cat = "game_server"
    return Finding("rule_single_target", cat, score,
                   f"Problem beim Ziel {t['name'] or t['address']} oder dem Routing dorthin", ev)


def rule_tcp_retransmissions(w: Window) -> Finding | None:
    """TCP Retransmissions stark erhöht → mögliche Paketverluste/Übertragungsprobleme.

    Retransmissions sind ein indirektes Verlustsignal. Die Richtung hilft:
    * Download-Richtung (Server sendet erneut): Verlust zwischen Server und Router
    * Upload-Richtung (Client sendet erneut): Verlust auf dem Upload oder im LAN/WLAN
      Pflicht (35)  >= 3 % Retransmissions bei >= 50 Datensegmenten
      +10           gleichzeitig ICMP-Verluste
    """
    segs = sum(r.get("tcp_segs") or 0 for r in w.inside())
    rd = sum(r.get("retrans_down") or 0 for r in w.inside())
    ru = sum(r.get("retrans_up") or 0 for r in w.inside())
    if segs < 50 or (rd + ru) / segs < 0.03:
        return None
    score = 35
    ev = [f"{(rd + ru) / segs * 100:.1f} % TCP-Retransmissions ({rd} aus dem Internet, {ru} von LAN-Geräten)"]
    if sum(r.get("lost") or 0 for r in w.inside()) > 0:
        score += 10
        ev.append("Gleichzeitig ICMP-Paketverlust")
    where = "zwischen Internet-Servern und Router" if rd >= ru else "im Upload oder LAN/WLAN"
    return Finding("rule_tcp_retransmissions", "loss", score, f"Paketverluste/Übertragungsprobleme ({where})", ev)


def rule_game_server(w: Window) -> Finding | None:
    """Router und Internet normal, aber Game-Verbindung hat Probleme → Game-Server/Routing (Fall C).

    Nur während einer Gaming Session auswertbar (sonst ist nicht bekannt, ob der
    beobachtete UDP-Strom überhaupt ein Spiel ist). Signal: Lücken im Downstream des
    Game-Flows (keine Pakete vom Server) oder erhöhte ICMP-RTT zum Game-Server,
    während alle Referenzziele normal sind.
      Pflicht (55)  Game-Paketlücke oder Game-RTT-Anstieg, Referenzziele normal, Router stabil
      +10           Lücke >= 500 ms
    """
    if not w.gaming:
        return None          # ohne laufende Session ist kein Game-Flow beobachtet worden
    ins = w.inside()
    gaps = [r.get("game_gap_ms") for r in ins if r.get("game_gap_ms") is not None]
    game_rtt_pre = _med([r.get("game_rtt") for r in w.pre()])
    game_rtt_peak = _max([r.get("game_rtt") for r in ins])
    thr = getattr(w.thresholds, "game_gap_ms", 250)
    gap_bad = bool(gaps) and max(gaps) >= thr
    rtt_bad = game_rtt_pre is not None and game_rtt_peak is not None and game_rtt_peak - game_rtt_pre >= TARGET_DELTA_MS
    if not (gap_bad or rtt_bad):
        return None
    inet = [t for t in target_impact(w).values() if t["kind"] == "internet"]
    if any(t["affected"] for t in inet) or gateway_stable(w) is False:
        return None
    score = 55
    ev = ["Referenzziele (Internet) und Router normal"]
    if gap_bad:
        ev.append(f"Game-Flow: bis zu {max(gaps):.0f} ms keine Pakete vom Server")
        if max(gaps) >= 500:
            score += 10
    if rtt_bad:
        ev.append(f"Ping zum Game-Server {game_rtt_pre:.0f} → {game_rtt_peak:.0f} ms")
    srv = (w.gaming or {}).get("server_ip")
    return Finding("rule_game_server", "game_server", score,
                   "Problem beim Game-Server oder im Routing dorthin" + (f" ({srv})" if srv else ""), ev)


def rule_dns_failure(w: Window) -> Finding | None:
    """DNS-Ausfall bei normaler Erreichbarkeit → DNS-Problem (kein Lag im Spiel).

      Pflicht (60)  DNS-Probes fehlgeschlagen, ICMP-Ziele erreichbar ohne Verlust
      +15           nur der lokale Resolver (Pi-hole) betroffen → Pi-hole/Pi prüfen
    """
    dns = [x for r in w.around(5) for x in (r.get("dns") or [])]
    fails = [x for x in dns if x[1] is None or x[2] == "servfail"]
    if not fails and not w.events_of(DNS_FAILURE):
        return None
    if sum(r.get("lost") or 0 for r in w.inside()) > 0:
        return None
    failed_servers = sorted({x[0] for x in fails} | {e.get("target") for e in w.events_of(DNS_FAILURE) if e.get("target")})
    ok_servers = sorted({x[0] for x in dns if x[1] is not None} - set(failed_servers))
    score = 60
    ev = [f"DNS-Anfragen fehlgeschlagen an: {', '.join(failed_servers)}", "ICMP-Erreichbarkeit normal"]
    cause = "DNS-Störung"
    # Fiel nur die ungecachte Probe aus, funktioniert der Resolver noch, aber die
    # Auflösung nach außen nicht – das ist der Upstream, nicht Pi-hole.
    kinds = {x[3] for x in fails if len(x) > 3}
    if kinds == {"uncached"}:
        cause = "DNS-Störung beim Upstream-Resolver"
        ev.append("Gecachte Antworten kamen weiter – der lokale Resolver läuft, "
                  "die Auflösung nach außen nicht")
    elif failed_servers == ["127.0.0.1"] or (ok_servers and all(s != "127.0.0.1" for s in ok_servers)):
        score += 15
        cause = "DNS-Störung des lokalen Resolvers (Pi-hole)"
        ev.append("Upstream-DNS funktionierte → Pi-hole/FTL prüfen")
    ev.append("DNS beeinflusst keine laufende Spielverbindung, aber Verbindungsaufbau/Matchmaking")
    return Finding("rule_dns_failure", "dns", score, cause, ev)


def rule_connection_drop(w: Window) -> Finding | None:
    """Kompletter Verbindungsverlust.

    * Router weiterhin erreichbar → Internetanschluss ausgefallen (WAN/ISP), 75 Punkte
    * Router ebenfalls nicht erreichbar → Verbindungsverlust im LAN (bzw. Pi), 70 Punkte
    """
    drops = w.events_of(CONNECTION_DROP)
    if not drops:
        return None
    g = gateway_stats(w)
    dur = sum(((e.get("ts_end") or w.t1) - e["ts_start"] + 1) for e in drops)
    if g["probes"] and g["lost"] < g["probes"] * 0.5:
        return Finding("rule_connection_drop", "drop_wan", 75, "Internet-Ausfall (Router erreichbar, Internet nicht)",
                       [f"Alle externen Ziele {dur:.0f} s nicht erreichbar", "Router antwortete weiterhin"])
    return Finding("rule_connection_drop", "drop_local", 70, "Verbindungsverlust im LAN/zum Router",
                   [f"Alle externen Ziele {dur:.0f} s nicht erreichbar", "Auch der Router antwortete nicht"])


RULES: list[Callable[[Window], Finding | None]] = [
    rule_upload_saturation,
    rule_download_saturation,
    rule_local_problem,
    rule_wan_isp,
    rule_multi_target_loss,
    rule_single_target,
    rule_tcp_retransmissions,
    rule_game_server,
    rule_dns_failure,
    rule_connection_drop,
]


# =============================================================================== Handlungsempfehlung
# Zu jeder Kategorie gehört eine konkrete Maßnahme – die Diagnose allein hilft nicht weiter.
# `scope` sagt ehrlich, ob sich das überhaupt selbst beheben lässt:
#   self     → in der eigenen Hand (Gerät, Router, WLAN)
#   provider → nur der Anschlussanbieter kann es ändern
#   remote   → liegt beim Zielserver/Routing, lokal nicht behebbar
RECOMMENDATIONS: dict[str, dict] = {
    "upload": {
        "scope": "self",
        "headline": "Upload begrenzen oder Spiel priorisieren",
        "steps": [
            "FRITZ!Box → Internet → Filter → Priorisierung: {device_or_gamer} als „Echtzeitanwendung“ eintragen. "
            "Beim Upload steht die Warteschlange im eigenen Router, deshalb wirkt die Priorisierung hier wirklich.",
            "{uploader} während des Spielens drosseln oder pausieren "
            "(Cloud-Backup, Video-Upload, Streaming, Seeding).",
            "Dauerhaft: Upload-Rate der verursachenden Anwendung auf ca. 80 % der Leitung begrenzen – "
            "ein zu 100 % gefüllter Upload erzeugt den Lag, nicht die Datenmenge an sich.",
        ],
    },
    "download": {
        "scope": "self",
        "headline": "Download drosseln – Priorisierung hilft hier nicht",
        "steps": [
            "{uploader} bremsen: Steam → Einstellungen → Downloads → Bandbreite begrenzen, "
            "PS5/Xbox-Downloads pausieren, Streaming-Qualität senken.",
            "Wichtig: Die Warteschlange steht beim Provider, nicht im eigenen Router. "
            "Eine Priorisierung in der FRITZ!Box kann Pakete, die bereits beim Provider warten, nicht überholen.",
            "Dauerhafte Lösung wäre ein Router mit SQM/CAKE, der den Download künstlich knapp unter die "
            "Leitungsgrenze bremst – die FRITZ!Box beherrscht das nicht.",
        ],
    },
    "local": {
        "scope": "self",
        "headline": "Verbindung im eigenen Netz prüfen",
        "steps": [
            "Läuft der Gaming-PC über WLAN? Mit Kabel testen – das ist der häufigste Einzelbefund.",
            "WLAN: Kanal und Band prüfen (5 GHz statt 2,4 GHz), Abstand zum Access Point, "
            "Mesh-Übergänge (Deco) im Blick behalten.",
            "Router-Auslastung prüfen (FRITZ!Box → System → Ereignisse), Router-Neustart als letzter Test.",
            "Zur Einordnung: Gemessen wird vom Raspberry Pi aus. Hängt der Pi selbst am WLAN, "
            "kann auch dessen Anbindung die Ursache sein – dann ist das Spiel womöglich gar nicht betroffen.",
        ],
    },
    "wan": {
        "scope": "provider",
        "headline": "Anschluss dokumentieren und beim Anbieter melden",
        "steps": [
            "FRITZ!Box → Internet → DSL-Informationen → Störsicherheit: Fehlerzähler (ES/SES, CRC) "
            "und Leitungsdämpfung notieren – steigende Werte sind belastbare Argumente.",
            "Diesen Incident als Beleg aufheben: Uhrzeit, Dauer und betroffene Ziele stehen hier bereits.",
            "Wiederholt es sich zur gleichen Tageszeit, spricht das für Überbuchung im Segment des Anbieters – "
            "das lässt sich lokal nicht beheben, nur melden.",
            "Lokal bleibt nur Schadensbegrenzung: eigene Leitung während des Spielens frei halten.",
        ],
    },
    "target": {
        "scope": "remote",
        "headline": "Liegt beim Ziel oder am Weg dorthin",
        "steps": [
            "Nur ein Ziel war betroffen – die eigene Leitung und der Router waren in Ordnung.",
            "Falls es der Spiel- oder Matchmaking-Server ist: anderen Server bzw. andere Region wählen.",
            "Sonst keine lokale Maßnahme sinnvoll; wiederholt sich das Muster, hilft ein Traceroute zum Ziel "
            "während des Problems.",
        ],
    },
    "game_server": {
        "scope": "remote",
        "headline": "Game-Server oder Routing dorthin",
        "steps": [
            "Referenzziele und Router waren gleichzeitig unauffällig – das Problem liegt auf der Strecke zum Spielserver.",
            "Anderen Server / andere Region im Spiel wählen und beobachten, ob es verschwindet.",
            "Serverstatus des Spiels prüfen, bevor am eigenen Netz geschraubt wird.",
        ],
    },
    "loss": {
        "scope": "self",
        "headline": "Übertragungsfehler eingrenzen",
        "steps": [
            "Richtung beachten: Verluste aus dem Internet deuten auf Anschluss/Provider, "
            "Verluste beim Senden auf Upload-Sättigung oder WLAN.",
            "WLAN-Geräte testweise per Kabel anschließen, um Funkstörungen auszuschließen.",
            "Bleibt es, den Anschluss prüfen lassen (DSL-Fehlerzähler wie oben).",
        ],
    },
    "dns": {
        "scope": "self",
        "headline": "Pi-hole / DNS prüfen",
        "steps": [
            "Pi-hole-Dienst prüfen: `pihole status`, danach `sudo systemctl restart pihole-FTL`.",
            "Upstream-DNS in Pi-hole kontrollieren (Settings → DNS) und einen zweiten Upstream eintragen.",
            "Zur Einordnung: DNS unterbricht kein laufendes Spiel – es trifft Verbindungsaufbau, "
            "Matchmaking, Updates und Webseiten.",
        ],
    },
    "drop_wan": {
        "scope": "provider",
        "headline": "Internetausfall dokumentieren",
        "steps": [
            "Der Router war erreichbar, das Internet nicht – der Ausfall lag hinter dem Router.",
            "FRITZ!Box → System → Ereignisse: dort steht, ob die PPP-/DSL-Verbindung getrennt wurde.",
            "Häufen sich die Trennungen, mit Zeitstempeln beim Anbieter melden. "
            "Eine tägliche Zwangstrennung nachts ist dagegen normal.",
        ],
    },
    "drop_local": {
        "scope": "self",
        "headline": "Verbindung des Messgeräts und des LAN prüfen",
        "steps": [
            "Auch der Router war nicht erreichbar – das betrifft den Weg Pi ↔ Router.",
            "Kabel/Port am Raspberry Pi prüfen; hängt der Pi am WLAN, auf Kabel umstellen.",
            "Access Point bzw. Switch auf Neustarts prüfen (Deco-App → Ereignisprotokoll).",
        ],
    },
    "unknown": {
        "scope": "none",
        "headline": "Keine belastbare Empfehlung",
        "steps": [
            "Die Messwerte reichen für keine eindeutige Zuordnung. "
            "Fehlende Datenquellen stehen unter „Hinweise“ – werden die ergänzt, wird die nächste Analyse genauer.",
        ],
    },
}


def recommend(w: Window, best: Finding) -> dict:
    """Konkrete Maßnahme zur erkannten Kategorie – mit Gerätenamen, wo bekannt."""
    tpl = RECOMMENDATIONS.get(best.category) or RECOMMENDATIONS["unknown"]
    dev = (best.device or {}).get("name")
    gmac = (w.gaming or {}).get("mac")
    gamer = f"„{w.device_label(gmac)['name']}“" if gmac else "den Gaming-PC"
    fields = {
        "uploader": f"„{dev}“" if dev else "Das verursachende Gerät",
        "device_or_gamer": gamer,
    }
    steps = [s.format(**fields) for s in tpl["steps"]]
    if best.category in ("upload", "download") and not w.per_device_available:
        steps.append("Kein Traffic pro Gerät verfügbar – welches Gerät die Leitung füllt, "
                     "zeigt erst ein laufender FRITZ!Box-Mitschnitt (Einstellungen → FRITZ!Box).")
    return {"category": best.category, "scope": tpl["scope"], "headline": tpl["headline"], "steps": steps}


# =============================================================================== Auswertung
def summarize_metrics(w: Window) -> dict:
    pre, ins = w.pre(), w.inside()
    probes = sum(r.get("probes") or 0 for r in ins)
    lost = sum(r.get("lost") or 0 for r in ins)
    g = gateway_stats(w)
    return {
        "duration": w.t1 - w.t0 + 1,
        "ping_before": _med([r.get("rtt_avg") for r in pre]),
        "ping_peak": _max([r.get("rtt_max") for r in ins]),
        "ping_peak_median": _max([r.get("rtt_avg") for r in ins]),
        "jitter_before": _med([r.get("jitter") for r in pre]),
        "jitter_peak": _max([r.get("jitter") for r in ins]),
        "loss_pct": round(100.0 * lost / probes, 1) if probes else None,
        "lost": lost, "probes": probes,
        "gw_before": g["before"], "gw_peak": g["peak"], "gw_lost": g["lost"],
        "up_peak": _max([r.get("up_bps") for r in ins]),
        "down_peak": _max([r.get("down_bps") for r in ins]),
        "traffic_source": next((r.get("traffic_src") for r in ins if r.get("traffic_src")), None),
        "game_gap_peak": _max([r.get("game_gap_ms") for r in ins]),
        "game_rtt_peak": _max([r.get("game_rtt") for r in ins]),
        # Latenz unter Last: Vergleich ruhige Sekunden ↔ ausgelastete Sekunden im Fenster.
        # Baseline notfalls aus dem gesamten Fenster, weil der Incident selbst durchgehend belastet sein kann.
        "latency_under_load": bufferbloat.measure(ins, w.cap_down, w.cap_up, idle_rows=w.rows),
    }


def top_talkers(w: Window, rows: list[dict] | None = None, n: int = 5) -> list[dict]:
    rows = rows if rows is not None else w.inside()
    acc: dict[str, list[float]] = {}
    peak: dict[str, list[float]] = {}
    for r in rows:
        for mac, v in (r.get("devices") or {}).items():
            a = acc.setdefault(mac, [0.0, 0.0])
            a[0] += v[1] * 8
            a[1] += v[0] * 8
            p = peak.setdefault(mac, [0.0, 0.0])
            p[0] = max(p[0], v[1] * 8)
            p[1] = max(p[1], v[0] * 8)
    secs = max(1, len(rows))
    out = []
    for mac, (up, down) in sorted(acc.items(), key=lambda kv: -(kv[1][0] + kv[1][1]))[:n]:
        if up + down <= 0:
            continue
        out.append({**w.device_label(mac), "up_bps": up / secs, "down_bps": down / secs,
                    "up_peak_bps": peak[mac][0], "down_peak_bps": peak[mac][1]})
    return out


def analyze(w: Window) -> dict:
    """Wendet alle Regeln an und liefert das Analyseergebnis (JSON-serialisierbar)."""
    findings = []
    for rule in RULES:
        try:
            f = rule(w)
        except Exception as e:  # pragma: no cover - eine defekte Regel darf die Analyse nicht stoppen
            f = Finding(rule.__name__, "unknown", 0, f"Regel fehlgeschlagen: {e}", [])
        if f is not None:
            findings.append(f)
    findings.sort(key=lambda f: f.score, reverse=True)
    notes = []
    if not w.traffic_available:
        notes.append("Traffic-Daten nicht verfügbar – Upload/Download-Sättigung kann nicht bewertet werden.")
    elif not w.per_device_available:
        notes.append("Nur Gesamt-Traffic (FRITZ!Box TR-064) verfügbar – kein Traffic pro Gerät, daher kein Gerät benennbar.")
    if w.cap_up is None or w.cap_down is None:
        notes.append("Leitungskapazität unbekannt – Auslastung in % nicht berechenbar.")
    elif w.cap_source == "learned":
        notes.append("Leitungskapazität aus bisher gemessenen Spitzenwerten geschätzt.")
    if not w.gaming:
        notes.append("Keine Gaming Session aktiv – Verbindung zum Game-Server wurde nicht beobachtet.")

    if findings and findings[0].score > 0:
        best = findings[0]
        conf = _confidence(best.score)
    else:
        best = Finding("fallback", "unknown", 10, "Keine eindeutige Ursache erkennbar",
                       ["Keine Regel traf eindeutig zu"])
        conf = "low"
    # Konkurrierende Erklärungen mit ähnlicher Punktzahl → Confidence senken
    if len(findings) >= 2 and findings[1].score >= best.score - 5 and findings[1].category != best.category:
        conf = {"high": "medium", "medium": "low", "low": "low"}[conf]
        notes.append(f"Alternative Erklärung ähnlich plausibel: {findings[1].cause}")

    correlated = []
    if w.per_device_available:
        # Nur Geräte, deren Traffic sich im Incident deutlich verändert hat (nicht Dauer-Hintergrund)
        pre = {t["mac"]: t for t in top_talkers(w, rows=w.pre(), n=50)}
        for t in top_talkers(w, n=3):
            if best.device and t["mac"] == best.device.get("mac"):
                continue
            p = pre.get(t["mac"])
            before = (p["up_bps"] + p["down_bps"]) if p else 0.0
            if t["up_peak_bps"] + t["down_peak_bps"] >= max(1e6, 2 * before):
                correlated.append({**t, "label": CONFIDENCE_LABELS["low"]})
    return {
        "cause": best.cause,
        "category": best.category,
        "category_label": CATEGORY_LABELS.get(best.category, best.category),
        "confidence": conf,
        "confidence_label": CONFIDENCE_LABELS[conf],
        "evidence": best.evidence,
        "recommendation": recommend(w, best),
        "device": best.device,
        "rules": [{"rule": f.rule, "category": f.category, "score": f.score, "cause": f.cause,
                   "evidence": f.evidence} for f in findings],
        "metrics": summarize_metrics(w),
        "targets": list(target_impact(w).values()),
        "top_talkers": top_talkers(w),
        "correlated_devices": correlated,
        "notes": notes,
        "capacity": {"down_bps": w.cap_down, "up_bps": w.cap_up, "source": w.cap_source},
    }
