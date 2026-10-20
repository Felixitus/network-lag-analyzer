"""Geräteverzeichnis: führt FRITZ!Box-Hostliste, Pi-hole, ARP und Capture-Beobachtungen zusammen.

Primärschlüssel ist die MAC-Adresse. Benutzerdefinierte Namen werden dauerhaft in
der Tabelle `devices` gespeichert und nie von automatischen Quellen überschrieben.
"""
from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field

from ..util.netinfo import normalize_mac

ACTIVE_SECONDS = 300


def is_randomized_mac(mac: str) -> bool:
    """Lokal administrierte MAC (z. B. iOS/Android 'Private WLAN-Adresse')."""
    try:
        return bool(int(mac.split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


@dataclass
class Device:
    mac: str
    id: int = 0                      # devices.id, Schlüssel in device_traffic
    ip: str | None = None
    hostname: str | None = None
    custom_name: str | None = None
    vendor: str | None = None
    interface: str | None = None
    sources: set[str] = field(default_factory=set)
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    fritz_active: bool | None = None
    dirty: bool = True

    @property
    def display_name(self) -> str:
        if self.custom_name:
            return self.custom_name
        if self.hostname:
            return self.hostname
        if self.vendor:
            return f"{self.vendor} ({self.ip or self.mac})"
        return self.ip or self.mac

    @property
    def active(self) -> bool:
        if self.fritz_active:
            return True
        return time.time() - self.last_seen < ACTIVE_SECONDS

    def to_dict(self) -> dict:
        return {
            "mac": self.mac, "ip": self.ip, "hostname": self.hostname, "custom_name": self.custom_name,
            "name": self.display_name, "vendor": self.vendor or ("Private MAC (randomisiert)" if is_randomized_mac(self.mac) else None),
            "interface": self.interface, "sources": sorted(self.sources), "first_seen": self.first_seen,
            "last_seen": self.last_seen, "active": self.active,
        }


class DeviceRegistry:
    """Geräteliste im Arbeitsspeicher.

    Jedes Gerät bekommt hier – nicht erst in der Datenbank – eine numerische `id`.
    Grund: `device_traffic` wird im selben Moment geschrieben, in dem ein Gerät
    zum ersten Mal Traffic erzeugt; auf eine vom Writer-Thread vergebene ID zu
    warten würde die Sekunde verzögern. Die ID wird beim Upsert ausdrücklich
    mitgeschrieben, ein Konflikt auf der MAC behält die bestehende ID.
    """

    def __init__(self) -> None:
        self.by_mac: dict[str, Device] = {}
        self.ip_names: dict[str, str] = {}   # IP → Hostname für Clients ohne bekannte MAC
        self._next_id = 1

    # ----------------------------------------------------------------- Laden/Speichern
    def load(self, conn: sqlite3.Connection) -> None:
        for r in conn.execute("SELECT * FROM devices"):
            d = Device(id=r["id"], mac=r["mac"], ip=r["ip"], hostname=r["hostname"],
                       custom_name=r["custom_name"], vendor=r["vendor"], interface=r["interface"],
                       sources=set(json.loads(r["sources"] or "[]")),
                       first_seen=r["first_seen"], last_seen=r["last_seen"], dirty=False)
            self.by_mac[d.mac] = d
            self._next_id = max(self._next_id, (d.id or 0) + 1)

    def dirty_rows(self) -> list[tuple]:
        rows = []
        for d in self.by_mac.values():
            if d.dirty:
                rows.append((d.id, d.mac, d.ip, d.hostname, d.vendor, json.dumps(sorted(d.sources)),
                             d.interface, d.first_seen, d.last_seen, int(d.active)))
                d.dirty = False
        return rows

    UPSERT = (
        "INSERT INTO devices(id, mac, ip, hostname, vendor, sources, interface, first_seen, last_seen, active) "
        "VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip, "
        "hostname=COALESCE(excluded.hostname, devices.hostname), vendor=COALESCE(excluded.vendor, devices.vendor), "
        "sources=excluded.sources, interface=COALESCE(excluded.interface, devices.interface), "
        "last_seen=MAX(excluded.last_seen, devices.last_seen), active=excluded.active"
    )

    # ----------------------------------------------------------------- Quellen
    def _get(self, mac: str) -> Device:
        d = self.by_mac.get(mac)
        if d is None:
            d = Device(mac=mac, id=self._next_id)
            self._next_id += 1
            self.by_mac[mac] = d
        return d

    def id_for(self, mac: str) -> int:
        """Numerische ID für `device_traffic`; legt das Gerät bei Bedarf an."""
        return self._get(mac).id

    def mac_for_id(self, dev_id: int) -> str | None:
        for d in self.by_mac.values():
            if d.id == dev_id:
                return d.mac
        return None

    def observe(self, mac: str | None, ip: str | None = None, hostname: str | None = None,
                vendor: str | None = None, interface: str | None = None, source: str = "",
                seen: float | None = None, fritz_active: bool | None = None) -> Device | None:
        mac = normalize_mac(mac)
        if mac is None or mac in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
            if ip and hostname:
                self.ip_names[ip] = hostname
            return None
        d = self._get(mac)
        changed = False
        if ip and ":" not in ip and d.ip != ip:
            d.ip, changed = ip, True
        if hostname and hostname != d.hostname and not _is_placeholder_name(hostname):
            d.hostname, changed = hostname, True
        if vendor and vendor != d.vendor:
            d.vendor, changed = vendor, True
        if interface and interface != d.interface:
            d.interface, changed = interface, True
        if source and source not in d.sources:
            d.sources.add(source)
            changed = True
        if fritz_active is not None and fritz_active != d.fritz_active:
            d.fritz_active, changed = fritz_active, True
        if seen and seen > d.last_seen + 30:
            d.last_seen, changed = seen, True
        if changed:
            d.dirty = True
        return d

    def rename(self, mac: str, name: str | None) -> Device | None:
        mac = normalize_mac(mac) or ""
        d = self.by_mac.get(mac)
        if d is None:
            return None
        d.custom_name = name or None
        return d

    # ----------------------------------------------------------------- Lookups
    def by_ip(self, ip: str) -> Device | None:
        best = None
        for d in self.by_mac.values():
            if d.ip == ip and (best is None or d.last_seen > best.last_seen):
                best = d
        return best

    def name_for_mac(self, mac: str) -> str:
        d = self.by_mac.get(mac)
        return d.display_name if d else mac

    def label(self, mac: str) -> dict:
        d = self.by_mac.get(mac)
        if d is None:
            return {"mac": mac, "ip": None, "name": mac}
        return {"mac": mac, "ip": d.ip, "name": d.display_name}

    def mac_for_ip(self, ip: str) -> str | None:
        d = self.by_ip(ip)
        return d.mac if d else None

    def all(self) -> list[dict]:
        return sorted((d.to_dict() for d in self.by_mac.values()),
                      key=lambda x: (not x["active"], _ip_sort(x["ip"])))


def _is_placeholder_name(name: str) -> bool:
    n = name.lower()
    return n.startswith("pc-") and n.count("-") >= 4 or n in ("unknown", "*", "")


def _ip_sort(ip: str | None) -> tuple:
    if not ip:
        return (999,)
    try:
        return tuple(int(p) for p in ip.split("."))
    except ValueError:
        return (998,)
