"""Bufferbloat: Wie stark steigt die Latenz, wenn die Leitung ausgelastet ist?

Das ist die entscheidende Kennzahl für Gaming. Sie wird getrennt nach Richtung
gemessen, weil die Konsequenz unterschiedlich ist:

* **Upload-Last**: Die Warteschlange steht im eigenen Router. Priorisierung
  (FRITZ!Box: "Priorisierung/Echtzeitanwendungen") oder Drosseln des Geräts hilft.
* **Download-Last**: Die Warteschlange steht beim Provider (DSLAM/BRAS). Lokale
  Priorisierung hilft NICHT – nur das ladende Gerät bremsen (oder SQM/CAKE auf
  einem Router, der das beherrscht).

Verfahren: Sekunden werden nach Auslastung in Gruppen geteilt und die RTT der
Gruppen verglichen. Es wird nichts geschätzt – fehlen Messwerte für eine Gruppe,
bleibt das Ergebnis leer.

Für den Langzeitverlauf werden 10-Minuten-Fenster gespeichert (Tabelle
`bufferbloat`), weil die 1-s-Werte nur einen Tag aufbewahrt werden. Über längere
Zeiträume wird der Median dieser Fenster gezeigt; das ist in `aggregate()`
dokumentiert.
"""
from __future__ import annotations

import statistics

IDLE_MAX = 0.20      # bis 20 % Auslastung gilt die Leitung als "ruhig"
LOAD_MIN = 0.70      # ab 70 % als "unter Last"
ISOLATE_MAX = 0.40   # die jeweils andere Richtung muss darunter bleiben
MIN_SAMPLES = 5
BUCKET = 600         # Länge eines gespeicherten Fensters in Sekunden

# Bewertung des Latenzanstiegs unter Last (ms)
GRADES = ((30, "gut", "good"), (100, "mäßig", "warning"), (float("inf"), "stark", "critical"))

UP_ADVICE = ("Warteschlange im eigenen Router: FRITZ!Box-Priorisierung für den Gaming-PC "
             "oder das hochladende Gerät drosseln.")
DOWN_ADVICE = ("Warteschlange beim Provider: Lokale Priorisierung hilft hier nicht – "
               "das ladende Gerät bremsen (z. B. Downloadrate der Konsole begrenzen).")
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
    """Teilt Sekunden in ruhig / unter Upload-Last / unter Download-Last."""
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
    """Vergleicht die RTT bei ruhiger Leitung mit der RTT unter Last.

    rows:      Sekunden-Zeilen mit rtt_avg, down_bps, up_bps.
    idle_rows: Optional ein größerer Zeitraum, aus dem die Ruhe-Baseline bestimmt
               wird. Nötig, wenn `rows` durchgehend ausgelastet ist (langer
               Download) und deshalb selbst keine ruhigen Sekunden enthält.
    """
    out: dict = {"idle_ms": None, "up": None, "down": None, "samples": {"idle": 0, "up": 0, "down": 0},
                 "capacity_known": bool(cap_down and cap_up), "note": None}
    if not (cap_down and cap_up):
        out["note"] = "Leitungskapazität unbekannt – unter Einstellungen → Messung eintragen."
        return out

    groups = classify(rows, cap_down, cap_up)
    idle = groups["idle"]
    if len(idle) < MIN_SAMPLES and idle_rows:
        idle = classify(idle_rows, cap_down, cap_up)["idle"]

    out["samples"] = {"idle": len(idle), "up": len(groups["up"]), "down": len(groups["down"])}
    base = _median(idle) if len(idle) >= MIN_SAMPLES else None
    out["idle_ms"] = round(base, 1) if base is not None else None
    if base is None:
        out["note"] = "Zu wenige Sekunden mit ruhiger Leitung für einen Vergleich."
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
        out["note"] = "Noch keine Phase mit hoher Auslastung gemessen."
    return out


def storable(m: dict) -> bool:
    """Lohnt sich ein gespeichertes Fenster? Nur mit Ruhe- UND Lastphase."""
    return m["idle_ms"] is not None and (m["up"] is not None or m["down"] is not None)


def aggregate(buckets: list[dict]) -> dict:
    """Fasst gespeicherte 10-Minuten-Fenster zu einer Aussage über den Zeitraum zusammen.

    Die Fenster enthalten bereits Mediane; über den Zeitraum wird deshalb der
    Median dieser Fenster-Mediane gebildet (und das Maximum als Spitzenwert).
    Das ist gröber als eine Rechnung über alle Einzelsekunden, aber ehrlich
    zusammengesetzt: jedes Fenster zählt gleich viel.
    """
    out: dict = {"idle_ms": None, "up": None, "down": None, "windows": len(buckets),
                 "samples": {"idle": 0, "up": 0, "down": 0}, "capacity_known": True, "note": None,
                 "aggregated": True}
    if not buckets:
        out["note"] = "Noch keine ausgewerteten Zeitfenster – dafür braucht es ruhige UND ausgelastete Phasen."
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
        out["note"] = "Keine Phase mit hoher Auslastung im Zeitraum."
    return out


def trend(buckets: list[dict], direction: str) -> list[dict]:
    """Zeitreihe des Latenzanstiegs für die Verlaufsanzeige."""
    out = []
    for b in buckets:
        loaded, base = b.get(f"{direction}_ms"), b.get("idle_ms")
        if loaded is None or base is None:
            continue
        out.append({"ts": b["ts"], "delta_ms": round(loaded - base, 1), "idle_ms": base,
                    "loaded_ms": loaded, "seconds": b.get(f"{direction}_secs") or 0})
    return out
