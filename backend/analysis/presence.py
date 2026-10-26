"""When was which device in the network, and which devices are new.

Presence comes from the device registry: a device counts as present while the FRITZ!Box
reports it active or another source (ARP, Pi-hole, DHCP) saw it within the last five
minutes. The resolution is therefore minutes, not seconds - a phone that sleeps its
Wi-Fi for a moment does not produce a new period every time.
"""
from __future__ import annotations

ACK_KEY = "acknowledged_devices"   # settings: {mac: time it was marked as known}
INITIAL_INVENTORY_S = 3600         # devices found in the first hour are the starting inventory, not "new"
FLUSH_EVERY_S = 600                # open periods are written back this often (crash safety vs. SD writes)


class PresenceTracker:
    """Open periods per device, kept in memory and mirrored to `device_presence`."""

    def __init__(self) -> None:
        self.open: dict[int, dict] = {}       # dev id → {row, start, last}
        self._flushed = 0.0

    def load(self, rows: list[tuple[int, int, int, int]], now: float, grace: float = 600) -> None:
        """Continue periods that were still open when the service stopped - if it was not down for long."""
        for row_id, dev, start, end in rows:
            if now - end <= grace:
                self.open[dev] = {"row": row_id, "start": start, "last": end}

    def step(self, now: float, present: set[int]) -> tuple[list[int], list[tuple[int, int, int]], bool]:
        """→ (devices whose period starts now, [(row, dev, end)] periods that ended, flush due)."""
        started = [dev for dev in present if dev not in self.open]
        ended = []
        for dev, p in list(self.open.items()):
            if dev in present:
                p["last"] = int(now)
            else:
                ended.append((p["row"], dev, p["last"]))
                del self.open[dev]
        flush = now - self._flushed >= FLUSH_EVERY_S
        if flush:
            self._flushed = now
        return started, ended, flush

    def opened(self, dev: int, row_id: int, now: float) -> None:
        self.open[dev] = {"row": row_id, "start": int(now), "last": int(now)}


def new_devices(devices: list[dict], acknowledged: dict[str, float], since: float) -> list[dict]:
    """Devices first seen after `since` that nobody has marked as known yet.

    The very first hour of the database is the inventory: on a fresh install every device
    is "first seen", and listing all of them as new would make the list useless."""
    if not devices:
        return []
    inventory_end = min(d["first_seen"] for d in devices) + INITIAL_INVENTORY_S
    return sorted((d for d in devices if d["first_seen"] >= max(since, inventory_end) and d["mac"] not in acknowledged),
                  key=lambda d: d["first_seen"], reverse=True)


def unknown_devices(devices: list[dict], acknowledged: dict[str, float]) -> list[dict]:
    """Devices without any name (no alias, no host name from any source) that are not marked as known."""
    return [d for d in devices if not d.get("custom_name") and not d.get("hostname") and d["mac"] not in acknowledged]


def lanes(periods: list[tuple], start: int, end: int) -> dict[int, list[list]]:
    """Presence periods per device, clipped to [start, end]: [from, to, source]."""
    out: dict[int, list[list]] = {}
    for dev, s, e, *src in periods:
        if e < start or s > end:
            continue
        out.setdefault(dev, []).append([max(s, start), min(e, end), src[0] if src else None])
    return out
