"""Configuration: config.yaml + overrides from the web UI (DB).

Order: defaults (this module) < config.yaml < DB setting "config_overrides".
All values are validated with Pydantic.
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
    """Allows IPv4 addresses and simple host names (no shell special characters)."""
    value = value.strip()
    try:
        ipaddress.IPv4Address(value)
        return value
    except ValueError:
        pass
    import re

    if not re.fullmatch(r"[A-Za-z0-9]([A-Za-z0-9\-\.]{0,251}[A-Za-z0-9])?", value):
        raise ValueError(f"Invalid target: {value!r}")
    return value


class Target(BaseModel):
    address: str
    name: str | None = None

    @field_validator("address")
    @classmethod
    def _addr(cls, v: str) -> str:
        return _valid_host(v)


class ServerCfg(BaseModel):
    # "auto": the IPv4 address of the interface with the default route, i.e. only
    # the LAN - not every interface of the Pi. "0.0.0.0" listens everywhere.
    host: str = "auto"
    port: int = Field(8088, ge=1, le=65535)


class ProbeCfg(BaseModel):
    interval: float = Field(1.0, ge=0.2, le=10)
    gaming_interval: float = Field(0.25, ge=0.1, le=2)
    timeout: float = Field(1.5, ge=0.3, le=5)


class DnsProbeCfg(BaseModel):
    enabled: bool = True
    interval: float = Field(5.0, ge=1, le=300)
    timeout: float = Field(2.0, ge=0.5, le=10)
    # Cached name: only measures whether your own resolver still responds (RFC 2606).
    query_name: str = "example.com"
    # Uncached probe: a random name under this suffix forces the full path
    # to the upstream. ".invalid" is reserved for this and burdens no foreign zone.
    # Leaving it empty disables the second probe.
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
    spike_factor: float = 3.0          # RTT >= baseline * factor ...
    spike_min_delta: float = 25        # ... and at least this many ms above baseline
    jitter_warning: float = 20
    packet_loss_warning: float = 1     # percent in the 10 s window
    packet_loss_min_lost: int = 2      # at least this many lost probes in the 10 s window
    gateway_warning: float = 20
    connection_drop_seconds: int = 3
    high_upload_pct: float = 70        # percent of the upload capacity
    high_download_pct: float = 80
    retrans_warning_pct: float = 3
    game_gap_ms: float = 250


class CapacityCfg(BaseModel):
    """Line capacity in Mbit/s. 'auto' = from the FRITZ!Box (TR-064)."""
    down_mbit: float | Literal["auto"] = "auto"
    up_mbit: float | Literal["auto"] = "auto"


class FritzCfg(BaseModel):
    enabled: bool = False
    host: str = "auto"                 # auto = default gateway
    username: str = ""
    password: str = ""
    tr064_port: int = 49000
    capture_enabled: bool = True
    capture_interface: str = "1-lan"   # LAN bridge of the FRITZ!Box
    # Bytes kept per packet. 128 is enough for traffic per device; reading TLS server names
    # (SNI) needs ~600, at about 4× the capture data for full-size packets.
    snaplen: int = Field(128, ge=64, le=1024)
    poll_interval: float = Field(2.0, ge=1, le=60)
    hostlist_interval: float = Field(120, ge=30, le=3600)


class BackupCfg(BaseModel):
    """Automatic database backups in <data dir>/backups, the oldest removed beyond `keep`."""
    enabled: bool = True
    interval_days: float = Field(7, ge=1, le=90)
    keep: int = Field(2, ge=1, le=20)
    hour: int = Field(3, ge=0, le=23)          # local hour; quiet time, and Pi-hole's gravity update is on Sundays

NOTIFY_SECRETS = ("ntfy_token", "telegram_bot_token", "smtp_password")


class NotifyCfg(BaseModel):
    """Push messages when something needs attention. Every channel is optional."""
    enabled: bool = False
    ntfy_url: str = ""                 # e.g. https://ntfy.sh/<a long random topic>
    ntfy_token: str = ""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    smtp_host: str = ""
    smtp_port: int = Field(587, ge=1, le=65535)
    smtp_starttls: bool = True
    smtp_username: str = ""
    smtp_password: str = ""
    mail_from: str = ""
    mail_to: str = ""
    cooldown_minutes: int = Field(30, ge=5, le=1440)     # repeat an ongoing alert at most this often
    router_loss: bool = True
    router_loss_pct: float = Field(5, ge=0.5, le=100)    # over the last 2 minutes
    internet_down: bool = True
    internet_down_seconds: int = Field(60, ge=10, le=3600)
    pihole_down: bool = True
    new_device: bool = True
    pi_health: bool = True
    line: bool = True

    @field_validator("ntfy_url")
    @classmethod
    def _url(cls, v: str) -> str:
        v = v.strip()
        if v and not v.startswith(("https://", "http://")):
            raise ValueError("The ntfy address must start with https:// (or http:// for a server in the LAN)")
        return v


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
    dhcp_leases: str = "/etc/pihole/dhcp.leases"     # read-only; host names of the current leases
    poll_interval: float = Field(15, ge=5, le=600)
    # Actions through Pi-hole's own API (pause blocking, allow/deny a domain, restart DNS,
    # update the blocklists). Off by default; needs an app password from Pi-hole's settings.
    api_enabled: bool = False
    api_url: str = "http://127.0.0.1"
    api_password: str = ""

    @field_validator("api_url")
    @classmethod
    def _local_only(cls, v: str) -> str:
        # The app password may only go to the Pi-hole on this Pi - like the FRITZ!Box password,
        # it must not be redirectable to another device on the LAN.
        from urllib.parse import urlparse
        u = urlparse(v.strip())
        if u.scheme not in ("http", "https") or u.hostname not in ("127.0.0.1", "localhost", "::1"):
            raise ValueError("Pi-hole actions only work with the Pi-hole on this Pi (http://127.0.0.1)")
        return v.strip().rstrip("/")


class DnsUsageCfg(BaseModel):
    """DNS usage per device, read from Pi-hole's query log (see backend/analysis/dns_ingest.py)."""
    enabled: bool = True
    interval: float = Field(30, ge=10, le=600)
    # How far back to read on the first start. Pi-hole keeps 91 days by default;
    # older data does not exist there anyway.
    backfill_days: float = Field(91, ge=0, le=365)
    # Rows per step. The backfill runs in many small steps so that FTL and the
    # per-second pipeline are never blocked for long.
    batch_rows: int = Field(20_000, ge=1_000, le=200_000)
    # Completed days keep the busiest domains per device; the rest is summed up.
    top_domains_per_day: int = Field(300, ge=20, le=5_000)
    # Activity phases: a pause longer than this ends a phase (services may define
    # their own gap in the category rules).
    phase_gap_minutes: float = Field(5, ge=1, le=120)
    # Refresh the UT1 lists - only where they were imported once (opt-in by the import itself).
    ut1_auto_update: bool = True
    ut1_update_days: float = Field(30, ge=7, le=365)


class RetentionCfg(BaseModel):
    raw_days: float = Field(1, ge=0.1, le=30)          # 1 s values
    detailed_days: float = Field(7, ge=1, le=90)       # 10 s aggregates
    aggregate_days: float = Field(30, ge=1, le=730)    # 60 s aggregates
    flow_days: float = Field(7, ge=1, le=90)
    event_days: float = Field(90, ge=1, le=3650)
    # DNS usage: hourly totals per device are tiny (~15 KB per day), domain lists
    # per device and day are larger (~140 KB per day on the Pi), hence the shorter default.
    dns_hourly_days: float = Field(400, ge=7, le=3650)
    dns_domain_days: float = Field(180, ge=7, le=3650)
    dns_domain_hourly_hours: float = Field(48, ge=24, le=24 * 31)
    # Activity minutes per device and service (~60 KB per day); also the longest
    # range for activity phases.
    dns_minute_days: float = Field(31, ge=1, le=91)
    # Internet line values every 5 minutes (~15 KB per day) and the FRITZ!Box event log:
    # long enough to show a provider that a problem has been going on for months.
    line_days: float = Field(400, ge=7, le=3650)
    # Individual ICMP probes. No evaluation reads them, but they cost about 14 MB
    # of writes to the SD card per day. Only enable for troubleshooting.
    ping_samples: bool = False
    # Emergency brake: if the database grows larger, the least important data is
    # deleted (first raw data, then 1 s values, then 10 s values). 0 = no limit.
    max_db_mb: int = Field(1024, ge=0, le=100_000)


class DeepCaptureCfg(BaseModel):
    """PCAP ring buffer. `max_files` × `file_size_mb` only applies to the RUNNING files.

    Files belonging to an incident are taken out of the ring so that they are not
    overwritten - they therefore need their own limit. `max_total_mb` is the
    upper limit for the whole directory and the only number you can
    rely on.
    """
    enabled: bool = False
    max_files: int = Field(5, ge=2, le=50)
    file_size_mb: int = Field(50, ge=5, le=500)
    # Hard upper limit for the whole pcap directory (ring + protected files).
    max_total_mb: int = Field(1024, ge=50, le=200_000)
    # Incident captures are kept at most this long. Previously the event retention
    # applied (90 days) - far too long for 50 MB files.
    protected_days: float = Field(7, ge=0.5, le=365)
    # For which automatically detected incidents a capture is kept at all.
    # "critical" saves most of it: otherwise a short jitter blip freezes
    # 50 MB. Reported lags ("I JUST HAD LAG") are always kept.
    protect_auto: Literal["none", "critical", "all"] = "critical"


class LoadGuardCfg(BaseModel):
    cpu_high: float = 75
    cpu_critical: float = 90
    mem_min_available_mb: float = 150
    capture_lag_high: float = 2
    capture_lag_critical: float = 5


class SecurityCfg(BaseModel):
    # Login is mandatory. `require_login: false` is only meant for an own,
    # authenticating reverse proxy in front of the service.
    require_login: bool = True
    # Dev mode shows demo data only and runs without login unless this is set.
    require_login_in_dev: bool = False
    session_hours: int = Field(24 * 7, ge=1, le=24 * 90)     # absolute lifetime of a session
    idle_hours: float = Field(24, ge=0.25, le=24 * 30)       # ends after this long without requests
    # Before mandatory login: optional password without a username. Migrated to
    # the account "admin" on start (api/security.migrate_legacy).
    login_enabled: bool = False
    password_hash: str = ""            # scrypt$<salt-hex>$<hash-hex>


class GamingCfg(BaseModel):
    auto_detect: bool = True
    min_pps: float = 15                # UDP packets/s per direction
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
    dns_usage: DnsUsageCfg = DnsUsageCfg()
    retention: RetentionCfg = RetentionCfg()
    deep_capture: DeepCaptureCfg = DeepCaptureCfg()
    load_guard: LoadGuardCfg = LoadGuardCfg()
    security: SecurityCfg = SecurityCfg()
    notify: NotifyCfg = NotifyCfg()
    backup: BackupCfg = BackupCfg()
    local_networks: list[str] = Field(default_factory=list)  # empty = automatic
    # A second always-on device in the LAN (access point, switch, NAS). Pinged like the router,
    # it tells a fault of the Pi's own cable or port apart from a fault of the router.
    lan_reference: str | None = None
    # Once a day: is there a newer release on GitHub? Only shows a note, never installs.
    update_check: bool = True

    @field_validator("gateway")
    @classmethod
    def _gw(cls, v: str) -> str:
        return v if v == "auto" else str(ipaddress.IPv4Address(v))

    @field_validator("lan_reference")
    @classmethod
    def _lanref(cls, v: str | None) -> str | None:
        if v in (None, ""):
            return None
        a = ipaddress.IPv4Address(v)
        if not a.is_private or a.is_loopback:
            raise ValueError("The LAN reference must be a device in the home network (private IPv4)")
        return str(a)

    @field_validator("local_networks")
    @classmethod
    def _nets(cls, v: list[str]) -> list[str]:
        return [str(ipaddress.ip_network(n, strict=False)) for n in v]

    # --- view for the API: remove secrets -----------------------
    def public_dict(self) -> dict[str, Any]:
        d = self.model_dump()
        d["fritzbox"]["password"] = "********" if self.fritzbox.password else ""
        for k in NOTIFY_SECRETS:
            d["notify"][k] = "********" if getattr(self.notify, k) else ""
        d["pihole"]["api_password"] = "********" if self.pihole.api_password else ""
        d["security"].pop("password_hash", None)
        d["security"]["password_set"] = bool(self.security.password_hash)
        return d


def fritz_target(cfg: Config) -> tuple[str, str | None]:
    """Where the FRITZ!Box password is sent. With "auto" the gateway decides."""
    host = cfg.fritzbox.host.strip().lower()
    return host, (cfg.gateway if host == "auto" else None)


# Fields that may be changed via the web UI (top-level keys).
EDITABLE_SECTIONS = {
    "gateway", "targets", "probe", "dns_probe", "gaming_pc", "gaming", "thresholds",
    "capacity", "fritzbox", "capture", "pihole", "dns_usage", "retention", "deep_capture",
    "load_guard", "local_networks", "lan_reference", "notify", "backup", "update_check",
}
# Changes to these sections require a restart of the collectors.
RESTART_SECTIONS = {"fritzbox", "capture", "pihole", "dns_usage", "server"}


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
        raise ValueError(f"{path}: expected a YAML mapping")
    return _normalize_yaml(data), str(p)


# Renamed keys. An existing config.yaml should keep working after an update
# instead of stopping with a validation error on start.
# Format: ("old.path", "new.path"). Entries are never removed.
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
    """Rewrite old key names to the current ones. Returns the renames."""
    done = []
    for old, new in CONFIG_ALIASES:
        src, key = _dig(data, old)
        if src is None or key not in src:
            continue
        value = src.pop(key)
        dst, nkey = _dig(data, new, create=True)
        if nkey not in dst:                     # a new value that is already set wins
            dst[nkey] = value
        done.append(f"{old} → {new}")
    return done


def _normalize_yaml(data: dict) -> dict:
    """Allows the short form `targets: [1.1.1.1, 8.8.8.8]` and translates old keys."""
    renamed = apply_aliases(data)
    if renamed:
        log.warning("Translated outdated keys in the configuration: %s", ", ".join(renamed))
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
