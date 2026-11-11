"""How much an incident could be felt: severe, noticeable or minor.

Rated when the list is read, from the numbers stored with the incident - no new measurement,
no stored verdict, so a changed threshold applies to old incidents too. The list hides minor
ones by default: on a real line most detected incidents are retransmissions at a normal ping,
and between them the ones that hurt were hard to find.

An incident whose numbers are missing is not rated (None) and is always shown - "not measured"
must not look like "harmless".
"""
from __future__ import annotations

LOSS_NOTICEABLE, LOSS_SEVERE = 1.0, 5.0        # % of the pings to the internet targets
PING_NOTICEABLE, PING_SEVERE = 40.0, 100.0     # ms above the ping before the incident
GAP_NOTICEABLE = 500.0                         # ms without a packet in the game's own stream
BLIP = 5                                       # s; shorter than this nothing is called severe

LABELS = {"severe": "Severe", "noticeable": "Noticeable", "minor": "Minor"}


def rate(source: str | None, metrics: dict | None) -> str | None:
    m = metrics or {}
    loss, peak, before = m.get("loss_pct"), m.get("ping_peak"), m.get("ping_before")
    gap, duration = m.get("game_gap_peak"), m.get("duration")
    if loss is None and peak is None and gap is None:
        # a report is a person saying they felt it; that needs no number
        return "noticeable" if source == "user" else None
    rise = peak - before if peak is not None and before is not None else None
    severe = (loss is not None and loss >= LOSS_SEVERE) or (rise is not None and rise >= PING_SEVERE)
    if severe and (duration is None or duration >= BLIP):
        return "severe"
    if (severe or source == "user" or (loss is not None and loss >= LOSS_NOTICEABLE)
            or (rise is not None and rise >= PING_NOTICEABLE) or (gap is not None and gap >= GAP_NOTICEABLE)):
        return "noticeable"
    return "minor"
