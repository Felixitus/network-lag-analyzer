"""The Pi watching itself: temperature, power, memory, storage, its own network port, Pi-hole's service.

All values come from files a normal user may read (sysfs, procfs) and psutil - no root,
no vcgencmd. What a system does not offer stays None ("Not available"); on a PC in
dev mode that is most of the Pi-specific values, which is the honest answer there.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

SYS = Path("/sys")
TEMP_WARN, TEMP_CRIT = 70.0, 80.0     # the Pi 4 starts throttling its CPU at 80 °C


def _read(path: Path) -> str | None:
    try:
        return path.read_text().strip()
    except OSError:
        return None


def _int(path: Path) -> int | None:
    v = _read(path)
    return int(v) if v is not None and v.lstrip("-").isdigit() else None


def temperature(sys_root: Path = SYS) -> float | None:
    v = _int(sys_root / "class/thermal/thermal_zone0/temp")
    return None if v is None else round(v / 1000, 1)


def undervoltage(sys_root: Path = SYS) -> bool | None:
    """The firmware's under-voltage alarm (hwmon "rpi_volt"). Only the current state - an earlier
    dip is visible in the stored history, not here."""
    for hw in sorted((sys_root / "class/hwmon").glob("hwmon*")):
        if _read(hw / "name") == "rpi_volt":
            v = _int(hw / "in0_lcrit_alarm")
            return None if v is None else bool(v)
    return None


def link(iface: str | None, sys_root: Path = SYS) -> dict | None:
    """Counters of the Pi's own network port, cumulative since boot."""
    if not iface:
        return None
    base = sys_root / "class/net" / iface
    if not base.exists():
        return None
    st = base / "statistics"
    return {"iface": iface, "carrier": _int(base / "carrier"), "speed_mbit": _int(base / "speed"),
            "duplex": _read(base / "duplex"), "carrier_changes": _int(base / "carrier_changes"),
            "rx_errors": _int(st / "rx_errors"), "tx_errors": _int(st / "tx_errors"),
            "rx_crc_errors": _int(st / "rx_crc_errors")}


def sd_written_bytes(sys_root: Path = SYS) -> int | None:
    """Bytes written to the SD card since boot (sector count × 512)."""
    v = _read(sys_root / "block/mmcblk0/stat")
    try:
        return int(v.split()[6]) * 512 if v else None
    except (IndexError, ValueError):
        return None


def service_active(name: str) -> bool | None:
    try:
        r = subprocess.run(["systemctl", "is-active", name], capture_output=True, text=True, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return r.stdout.strip() == "active"


def read(data_dir: str, iface: str | None, loadguard_last: dict | None, pihole_service: str | None) -> dict:
    """One snapshot. Blocking (subprocess, sysfs): call it in a thread."""
    import psutil
    s = loadguard_last or {}
    try:
        du = shutil.disk_usage(data_dir)
        disk = {"free_mb": du.free // 1048576, "total_mb": du.total // 1048576}
    except OSError:
        disk = {"free_mb": None, "total_mb": None}
    try:
        sw = psutil.swap_memory()
        swap = sw.used // 1048576 if sw.total else None
    except Exception:  # noqa: BLE001 - e.g. Windows without performance counters (dev mode)
        swap = None
    try:
        boot = psutil.boot_time()
    except Exception:  # noqa: BLE001
        boot = None
    return {
        "ts": time.time(), "temp_c": temperature(), "undervoltage": undervoltage(),
        "cpu_pct": s.get("cpu_pct"), "mem_available_mb": s.get("mem_available_mb"), "mem_total_mb": s.get("mem_total_mb"),
        "swap_used_mb": swap,
        "load1": s.get("load1"), "cpu_count": s.get("cpu_count") or os.cpu_count(),
        "disk_free_mb": disk["free_mb"], "disk_total_mb": disk["total_mb"],
        "boot_ts": boot, "link": link(iface), "sd_written_bytes": sd_written_bytes(),
        "pihole_active": service_active(pihole_service) if pihole_service else None,
    }


def deltas(rows: list[dict], keys=("carrier_changes", "rx_errors", "tx_errors")) -> list[dict]:
    """Cumulative port counters → increase per row. A new boot time restarts the counters, so the
    first row after a reboot counts from zero; a missing value stays missing."""
    out, prev = [], None
    for r in rows:
        d = {"ts": r["ts"]}
        same_boot = prev is not None and prev.get("boot_ts") == r.get("boot_ts")
        for k in keys:
            cur = r.get(k)
            if cur is None or prev is None:
                d[k] = None
            elif same_boot and prev.get(k) is not None and cur >= prev[k]:
                d[k] = cur - prev[k]
            else:
                d[k] = cur
        out.append(d)
        prev = r
    return out


def assess(h: dict, recent: dict | None = None) -> tuple[str, list[str]]:
    """Level and findings. `recent` = port counter increases of the last hour."""
    notes, levels = [], []

    def add(level: str, text: str) -> None:
        levels.append(level)
        notes.append(text)
    if h.get("undervoltage"):
        add("critical", "Under-voltage: the power supply is too weak or the cable too thin")
    t = h.get("temp_c")
    if t is not None and t >= TEMP_CRIT:
        add("critical", f"{t:.0f} °C - the CPU is being throttled")
    elif t is not None and t >= TEMP_WARN:
        add("warning", f"{t:.0f} °C - getting hot")
    if h.get("pihole_active") is False:
        add("critical", "Pi-hole's DNS service (pihole-FTL) is not running")
    free, total = h.get("disk_free_mb"), h.get("disk_total_mb")
    if free is not None and total:
        if free < 1024 or free / total < 0.05:
            add("critical", f"Only {free / 1024:.1f} GB free storage for the data")
        elif free / total < 0.15:
            add("warning", f"{free / 1024:.1f} GB free storage for the data ({100 * free / total:.0f} %)")
    mem = h.get("mem_available_mb")
    if mem is not None and mem < 200:
        add("warning", f"Only {mem} MB memory available")
    lk = h.get("link") or {}
    if lk and lk.get("carrier") == 0:
        add("critical", f"No network link on {lk['iface']}")
    elif lk and lk.get("speed_mbit") is not None and 0 < lk["speed_mbit"] < 1000 and lk["iface"].startswith("eth"):
        add("warning", f"{lk['iface']} runs at {lk['speed_mbit']} Mbit/s only - often a damaged cable")
    r = recent or {}
    if r.get("carrier_changes"):
        add("warning", f"Network link dropped {r['carrier_changes']}× in the last hour - cable, port or switch")
    if r.get("rx_errors"):
        add("warning", f"{r['rx_errors']} receive errors on the Pi's port in the last hour - cable or port")
    order = ("good", "warning", "critical")
    return (max(levels, key=order.index) if levels else "good"), notes


def link_verdict(gateway: dict | None, lan: dict | None, warn_pct: float) -> dict | None:
    """Where is packet loss inside the home network? The Pi pings the router and a second LAN device.

    Both lossy at the same time: the common part - the Pi's own cable, port or switch.
    Only the router: the router or the path to it. This needs both measured; with the router
    alone the answer is "unknown", not a guess."""
    def lossy(t):
        return t is not None and t.get("probes") and (t.get("loss_pct") or 0) >= warn_pct
    if gateway is None or not gateway.get("probes"):
        return None
    if lan is None or not lan.get("probes"):
        return {"where": "unknown", "text": "Set a second LAN device as reference to tell the Pi's own link from the router"
                if lossy(gateway) else None}
    if lossy(gateway) and lossy(lan):
        return {"where": "pi_link", "text": "Router and LAN reference lose packets at the same time: "
                                            "the Pi's own cable, port or switch"}
    if lossy(gateway):
        return {"where": "router", "text": "Only the router loses packets: the router or the path to it"}
    if lossy(lan):
        return {"where": "reference", "text": "Only the LAN reference loses packets: that device or its connection"}
    return {"where": "ok", "text": None}
