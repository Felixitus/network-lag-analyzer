"""Konfiguration: config.yaml + Überschreibungen aus der Weboberfläche (DB).

Reihenfolge: Defaults (dieses Modul) < config.yaml < DB-Setting "config_overrides".
Alle Werte werden über Pydantic validiert.
"""
from __future__ import annotations

import copy
import ipaddress
import logging
import os
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, field_validator

log = logging.getLogger(__name__)

DEFAULT_CONFIG_PATH = "/etc/network-lag-analyzer/config.yaml"
DEFAULT_DATA_DIR = "/var/lib/network-lag-analyzer"


def _valid_host(value: str) -> str:
    """Erlaubt IPv4-Adressen und einfache Hostnamen (keine Shell-Sonderzeichen)."""
    value = value.strip()
    try:
        ipaddress.IPv4Address(value)
        return value
    except ValueError:
        pass
    import re

    if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9\-\.]{0,251}[A-Za-z0-9])?", value):
        raise ValueError(f"Ungültiges Ziel: {value!r}")
    return value


class Target(BaseModel):
    address: str
    name: str | None = None

    @field_validator("address")
    @classmethod
    def _addr(cls, v: str) -> str:
        return _valid_host(v)


class ServerCfg(BaseModel):
    host: str = "0.0.0.0"
    port: int = Field(8088, ge=1, le=65535)


class ProbeCfg(BaseModel):
    interval: float = Field(1.0, ge=0.2, le=10)
    gaming_interval: float = Field(0.25, ge=0.1, le=2)
    timeout: float = Field(1.5, ge=0.3, le=5)


class DnsProbeCfg(BaseModel):
    enabled: bool = True
    interval: float = Field(5.0, ge=1, le=300)
    timeout: float = Field(2.0, ge=0.5, le=10)
    # Gecachter Name: misst nur, ob der eigene Resolver noch reagiert (RFC 2606).
    query_name: str = "example.com"
    # Ungecachte Probe: zufälliger Name unter dieser Endung erzwingt den vollen Weg
    # zum Upstream. ".invalid" ist dafür reserviert und belastet keine fremde Zone.
    # Leer lassen schaltet die zweite Probe ab.
    uncached_suffix: str = "nla-probe.invalid"
    servers: list[str] = Field(default_factory=lambda: ["local", "1.1.1.1"])


class GamingPcCfg(BaseModel):
    ip: str | None = None
    name: str = "Gaming-PC"

    @field_validator("ip")
    @classmethod
    def _ip(cls, v: str | None) -> str | None:
        if v in (None, ""):
            return None
        return str(ipaddress.IPv4Address(v))


class Thresholds(BaseModel):
    ping_warning: float = 50
    ping_critical: float = 100
    spike_factor: float = 3.0          # RTT >= Baseline * Faktor ...
    spike_min_delta: float = 25        # ... und mindestens so viele ms über Baseline
    jitter_warning: float = 20
    packet_loss_warning: float = 1     # Prozent im 10-s-Fenster
    packet_loss_min_lost: int = 2      # mindestens so viele verlorene Probes im 10-s-Fenster
    gateway_warning: float = 20
    connection_drop_seconds: int = 3
    high_upload_pct: float = 70        # Prozent der Upload-Kapazität
    high_download_pct: float = 80
    retrans_warning_pct: float = 3
    game_gap_ms: float = 250


class CapacityCfg(BaseModel):
    """Leitungskapazität in Mbit/s. 'auto' = aus FRITZ!Box (TR-064)."""
    down_mbit: float | Literal["auto"] = "auto"
    up_mbit: float | Literal["auto"] = "auto"


class FritzCfg(BaseModel):
    enabled: bool = False
    host: str = "auto"                 # auto = Default-Gateway
    username: str = ""
    password: str = ""
    tr064_port: int = 49000
    capture_enabled: bool = True
    capture_interface: str = "1-lan"   # LAN-Bridge der FRITZ!Box
    snaplen: int = Field(128, ge=64, le=256)
    poll_interval: float = Field(2.0, ge=1, le=60)
    hostlist_interval: float = Field(120, ge=30, le=3600)


class CaptureCfg(BaseModel):
    source: Literal["auto", "fritzbox", "local", "none"] = "auto"
    local_interface: str = "eth0"
    promiscuous: bool = True
    flow_idle_udp: int = 30
    flow_idle_tcp: int = 120
    flow_min_store_bytes: int = 20_000


class PiholeCfg(BaseModel):
    enabled: bool = True
    ftl_db: str = "/etc/pihole/pihole-FTL.db"
    poll_interval: float = Field(15, ge=5, le=600)


class RetentionCfg(BaseModel):
    raw_days: float = Field(1, ge=0.1, le=30)          # 1-s-Werte
    detailed_days: float = Field(7, ge=1, le=90)       # 10-s-Aggregate
    aggregate_days: float = Field(30, ge=1, le=730)    # 60-s-Aggregate
    flow_days: float = Field(7, ge=1, le=90)
    event_days: float = Field(90, ge=1, le=3650)
    # Einzelne ICMP-Probes. Keine Auswertung liest sie, sie kosten aber rund 14 MB
    # je Tag an Schreibzugriffen auf die SD-Karte. Nur für die Fehlersuche einschalten.
    ping_samples: bool = False
    # Notbremse: Wird die Datenbank größer, werden die am wenigsten wichtigen Daten
    # gelöscht (erst Rohdaten, dann 1-s-Werte, dann 10-s-Werte). 0 = keine Grenze.
    max_db_mb: int = Field(1024, ge=0, le=100_000)


class DeepCaptureCfg(BaseModel):
    """PCAP-Ringpuffer. `max_files` × `file_size_mb` gilt nur für die LAUFENDEN Dateien.

    Zu einem Incident gehörende Dateien werden aus dem Ring genommen, damit sie nicht
    überschrieben werden – sie brauchen deshalb eine eigene Grenze. `max_total_mb` ist
    die Obergrenze für das gesamte Verzeichnis und die einzige Zahl, auf die man sich
    verlassen kann.
    """
    enabled: bool = False
    max_files: int = Field(5, ge=2, le=50)
    file_size_mb: int = Field(50, ge=5, le=500)
    # Harte Obergrenze für das ganze pcap-Verzeichnis (Ring + geschützte Dateien).
    max_total_mb: int = Field(1024, ge=50, le=200_000)
    # So lange werden Incident-Mitschnitte höchstens aufgehoben. Vorher galt die
    # Event-Retention (90 Tage) – viel zu lang für 50-MB-Dateien.
    protected_days: float = Field(7, ge=0.5, le=365)
    # Für welche automatisch erkannten Incidents überhaupt ein Mitschnitt festgehalten
    # wird. "critical" spart den Großteil: Ein kurzer Jitter-Ausschlag friert sonst
    # 50 MB ein. Gemeldete Lags ("ICH HATTE GERADE LAG") werden immer festgehalten.
    protect_auto: Literal["none", "critical", "all"] = "critical"


class LoadGuardCfg(BaseModel):
    cpu_high: float = 75
    cpu_critical: float = 90
    mem_min_available_mb: float = 150
    capture_lag_high: float = 2
    capture_lag_critical: float = 5


class SecurityCfg(BaseModel):
    login_enabled: bool = False
    password_hash: str = ""            # scrypt$<salt-hex>$<hash-hex>
    session_hours: int = 24 * 7


class GamingCfg(BaseModel):
    auto_detect: bool = True
    min_pps: float = 15                # UDP-Pakete/s je Richtung
    min_seconds: int = 20
    stop_after_idle: int = 60


class Config(BaseModel):
    dev_mode: bool = False
    data_dir: str = DEFAULT_DATA_DIR
    server: ServerCfg = ServerCfg()
    gateway: str = "auto"
    targets: list[Target] = Field(default_factory=lambda: [
        Target(address="1.1.1.1", name="Cloudflare"),
        Target(address="8.8.8.8", name="Google"),
        Target(address="9.9.9.9", name="Quad9"),
    ])
    probe: ProbeCfg = ProbeCfg()
    dns_probe: DnsProbeCfg = DnsProbeCfg()
    gaming_pc: GamingPcCfg = GamingPcCfg()
    gaming: GamingCfg = GamingCfg()
    thresholds: Thresholds = Thresholds()
    capacity: CapacityCfg = CapacityCfg()
    fritzbox: FritzCfg = FritzCfg()
    capture: CaptureCfg = CaptureCfg()
    pihole: PiholeCfg = PiholeCfg()
    retention: RetentionCfg = RetentionCfg()
    deep_capture: DeepCaptureCfg = DeepCaptureCfg()
    load_guard: LoadGuardCfg = LoadGuardCfg()
    security: SecurityCfg = SecurityCfg()
    local_networks: list[str] = Field(default_factory=list)  # leer = automatisch

    @field_validator("gateway")
    @classmethod
    def _gw(cls, v: str) -> str:
        return v if v == "auto" else str(ipaddress.IPv4Address(v))

    @field_validator("local_networks")
    @classmethod
    def _nets(cls, v: list[str]) -> list[str]:
        return [str(ipaddress.ip_network(n, strict=False)) for n in v]

    # --- Ansicht für die API: Geheimnisse entfernen -----------------------
    def public_dict(self) -> dict[str, Any]:
        d = self.model_dump()
        d["fritzbox"]["password"] = "********" if self.fritzbox.password else ""
        d["security"].pop("password_hash", None)
        d["security"]["password_set"] = bool(self.security.password_hash)
        return d


def fritz_target(cfg: Config) -> tuple[str, str | None]:
    """Wohin das FRITZ!Box-Passwort geschickt wird. Bei "auto" entscheidet das Gateway."""
    host = cfg.fritzbox.host.strip().lower()
    return host, (cfg.gateway if host == "auto" else None)


# Felder, die über die Weboberfläche geändert werden dürfen (Top-Level-Schlüssel).
EDITABLE_SECTIONS = {
    "gateway", "targets", "probe", "dns_probe", "gaming_pc", "gaming", "thresholds",
    "capacity", "fritzbox", "capture", "pihole", "retention", "deep_capture",
    "load_guard", "local_networks",
}
# Änderungen an diesen Sektionen erfordern einen Neustart der Collectors.
RESTART_SECTIONS = {"fritzbox", "capture", "pihole", "server"}


def deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


def load_yaml(path: str | None = None) -> tuple[dict, str | None]:
    path = path or os.environ.get("NLA_CONFIG") or DEFAULT_CONFIG_PATH
    p = Path(path)
    if not p.exists():
        return {}, None
    with p.open("r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path}: erwartet ein YAML-Mapping")
    return _normalize_yaml(data), str(p)


# Umbenannte Schlüssel. Eine bestehende config.yaml soll nach einem Update weiter
# funktionieren, statt beim Start mit einem Validierungsfehler stehen zu bleiben.
# Format: ("alter.pfad", "neuer.pfad"). Einträge werden nie entfernt.
CONFIG_ALIASES: list[tuple[str, str]] = [
    ("retention.keep_raw_days", "retention.raw_days"),
    ("retention.max_size_mb", "retention.max_db_mb"),
    ("dns_probe.query", "dns_probe.query_name"),
]


def _dig(data: dict, path: str, create: bool = False) -> tuple[dict | None, str]:
    node = data
    parts = path.split(".")
    for p in parts[:-1]:
        nxt = node.get(p)
        if not isinstance(nxt, dict):
            if not create:
                return None, parts[-1]
            nxt = node[p] = {}
        node = nxt
    return node, parts[-1]


def apply_aliases(data: dict) -> list[str]:
    """Alte Schlüsselnamen auf die aktuellen umschreiben. Liefert die Umbenennungen."""
    done = []
    for old, new in CONFIG_ALIASES:
        src, key = _dig(data, old)
        if src is None or key not in src:
            continue
        value = src.pop(key)
        dst, nkey = _dig(data, new, create=True)
        if nkey not in dst:                     # ein bereits gesetzter neuer Wert gewinnt
            dst[nkey] = value
        done.append(f"{old} → {new}")
    return done


def _normalize_yaml(data: dict) -> dict:
    """Erlaubt die Kurzform `targets: [1.1.1.1, 8.8.8.8]` und übersetzt alte Schlüssel."""
    renamed = apply_aliases(data)
    if renamed:
        log.warning("Veraltete Schlüssel in der Konfiguration übersetzt: %s", ", ".join(renamed))
    t = data.get("targets")
    if isinstance(t, list):
        data["targets"] = [{"address": x} if isinstance(x, str) else x for x in t]
    return data


def build_config(yaml_data: dict, overrides: dict | None = None) -> Config:
    merged = _normalize_yaml(deep_merge(yaml_data, overrides or {}))
    if os.environ.get("NLA_DATA_DIR"):
        merged["data_dir"] = os.environ["NLA_DATA_DIR"]
    if os.environ.get("NLA_DEV_MODE") in ("1", "true", "yes"):
        merged["dev_mode"] = True
    if os.environ.get("NLA_PORT"):
        merged.setdefault("server", {})["port"] = int(os.environ["NLA_PORT"])
    return Config.model_validate(merged)
