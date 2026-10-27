"""Orchestration of all components (runs in the main process, asyncio)."""
from __future__ import annotations

import asyncio
import json
import logging
import multiprocessing as mp
import os
import queue
import threading
import time
from collections import deque
from typing import Any

from . import __version__
from .analysis import backfill, bufferbloat, daily, line, overview, pi_health, presence
from .analysis.alerts import Alerts, Message
from .analysis.categories import Classifier
from .analysis.correlation import Correlator, Incident, analyze_user_report, dismiss_reason
from .analysis.dns_ingest import DnsIngestor, delete_unused_domains, fold_completed_days, local_day, minutes_key
from .analysis.events import EVENT_LABELS, Event, EventEngine
from .analysis.gaming import ICMP_GIVE_UP_PROBES, GamingDetector, GamingSession, pick_server, summarize_session
from .analysis.metrics import MetricsHub, TargetInfo
from .analysis.root_cause import CATEGORY_LABELS, Window
from .collectors.devices import DeviceRegistry
from .collectors.dns import DnsProber
from .collectors.fritzbox import FritzClient, FritzError
from .collectors.ftl_queries import FtlQueryLog
from .collectors.pihole import PiholeReader, read_dhcp_leases
from .collectors.ping import IcmpProber, ProbeScheduler, ProbeTarget
from .config import Config, build_config, fritz_target, load_yaml
from .database import repository as repo
from .database.repository import Database
from .util import netinfo
from .util.loadguard import LoadGuard

log = logging.getLogger("nla.core")

# From this deviation between wall clock and monotonic clock on, the system time counts as jumped
# (NTP after boot, DST on systems without a UTC clock, manual setting).
CLOCK_JUMP_S = 2.0


class Broadcaster:
    """Distributes live data to all SSE clients (one bounded queue per client)."""

    def __init__(self) -> None:
        self.clients: set[asyncio.Queue] = set()

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=50)
        self.clients.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self.clients.discard(q)

    def publish(self, kind: str, data: Any) -> None:
        if not self.clients:
            return
        msg = f"event: {kind}\ndata: {json.dumps(data, separators=(',', ':'))}\n\n"
        for q in list(self.clients):
            try:
                q.put_nowait(msg)
            except asyncio.QueueFull:
                pass  # a slow client loses frames, but blocks nothing


class Core:
    def __init__(self, config_path: str | None = None):
        self.config_path = config_path
        self.yaml_data, self.yaml_path = load_yaml(config_path)
        self.cfg: Config = build_config(self.yaml_data)
        self.db = Database(os.path.join(self.cfg.data_dir, "nla.sqlite3"))
        self.hub = MetricsHub(timeout=self.cfg.probe.timeout)
        self.devices = DeviceRegistry()
        self.broadcaster = Broadcaster()
        self.loadguard = LoadGuard(self.cfg.load_guard)
        self.started_at = time.time()
        self.tasks: list[asyncio.Task] = []
        self.prober: IcmpProber | None = None
        self.scheduler: ProbeScheduler | None = None
        self.dns: DnsProber | None = None
        self.fritz: FritzClient | None = None
        self.fritz_status: dict = {"enabled": False}
        self.line_status: dict = {"enabled": False}
        self.pi_health: dict = {}
        self.alerts = Alerts()
        self.notify_log: deque = deque(maxlen=50)
        self._notified_devices: set[str] = set()
        self.presence = presence.PresenceTracker()
        self._pi_recent: deque = deque(maxlen=61)    # one snapshot per minute → last hour
        # Last FRITZ!Box host list, for the client identification check of the DNS pages.
        self.fritz_hosts: list = []
        self.fritz_hosts_at: float | None = None
        self.pihole: PiholeReader | None = None
        self.pihole_status: dict = {"enabled": False}
        self.dns_usage: DnsIngestor | None = None
        self.dns_usage_status: dict = {"enabled": False, "ok": None, "message": "Not available: disabled"}
        self.classifier: Classifier = Classifier.load(None)
        self.capture_proc: mp.Process | None = None
        self.capture_ctrl: Any = None
        self.capture_out: Any = None
        self.capture_status: dict = {"state": "disabled"}
        self.capture_reader: threading.Thread | None = None
        self.link_capacity: tuple[float | None, float | None] = (None, None)
        self.gateway: str | None = None
        self.gateway_mac: str | None = None
        self.pi_ip: str | None = None
        self.local_nets: list[str] = []
        self.targets: dict[int, dict] = {}
        self.recent_events: deque[dict] = deque(maxlen=500)
        self.recent_incidents: deque[dict] = deque(maxlen=200)
        self.dismissed_incidents: dict[str, int] = {}     # since the start, by reason
        self.active_flows: deque[tuple[float, list]] = deque(maxlen=720)
        self.udp_candidates: list[dict] = []
        self.gaming: GamingSession | None = None
        self.gaming_detector = GamingDetector(self.cfg.gaming.min_pps, self.cfg.gaming.min_seconds,
                                              self.cfg.gaming.stop_after_idle)
        self._game_target_id: int | None = None
        self._game_probe_stats = [0, 0]
        self._cap_delays: deque[float] = deque(maxlen=60)
        self.capture_delay: float | None = None
        # Display runs immediately; the evaluation waits for the (delayed) traffic data
        self._analysis_q: deque[dict] = deque()
        self.analysis_delay: float = 4.0
        self.display_grace_max: float = 3.0
        self._ids = {"event": 0, "incident": 0, "session": 0}
        self._last_agg = {10: 0, 60: 0}
        self._last_bloat = 0
        self.db_guard: dict | None = None      # state of the size limit, for /api/status
        self.clock_jumps: list[dict] = []      # detected jumps of the system clock
        self.loop: asyncio.AbstractEventLoop | None = None
        self.simulator = None
        self.setup_done = False
        self.version = __version__

    # ================================================================== start/stop
    async def start(self) -> None:
        self.loop = asyncio.get_running_loop()
        await self.db.init()
        overrides = await self.db.read(lambda c: repo.get_setting(c, "config_overrides", {}))
        if overrides:
            try:
                self.cfg = build_config(self.yaml_data, overrides)
            except Exception as e:  # invalid overrides must not prevent startup
                log.error("Stored settings invalid, ignoring them: %s", e)
        self.setup_done = await self.db.read(lambda c: repo.get_setting(c, "setup_done", False))
        self.reload_classifier(await self.db.read(lambda c: repo.get_setting(c, "dns_category_overrides", {})))
        from .api.security import migrate_legacy
        if await self.db.write(lambda c: migrate_legacy(c, self.cfg.security.password_hash)):
            log.warning("Login: the previous password now belongs to the user 'admin' (usernames are new)")
        await self.db.read(self._load_state)
        await self.db.write(self._log_start)
        self._init_network()

        self.events = EventEngine(self.cfg.thresholds, self.capacity, lambda: self._next_id("event"),
                                  self._top_device_of_row, gaming_active_fn=lambda: self.gaming is not None)
        self.correlator = Correlator(self.build_window, lambda: self._next_id("incident"),
                                     self._incident_closed, self._incident_opened,
                                     on_dismiss=self._incident_dismissed, dismiss_fn=dismiss_reason)
        self.correlator.session_id_fn = lambda: self.gaming.id if self.gaming else None
        self.events.on_start.append(self._event_started)
        self.events.on_end.append(self._event_ended)
        self.events.on_update.append(self._event_updated)
        self.hub.subscribers.append(self._on_second)
        self.hub.patch_subscribers.append(self._on_second_patched)

        await self._setup_targets()
        if self.cfg.dev_mode:
            from .simulation import LiveSimulator
            self.simulator = LiveSimulator(self)
            self._start_demo_dns_usage()
            self.tasks.append(asyncio.create_task(self.simulator.run(), name="simulator"))
            from .simulation import DemoLine, demo_line_history
            rows = demo_line_history(time.time())
            await self.db.write(lambda c: c.executemany(repo.INSERT_LINE, rows))
            self.tasks.append(asyncio.create_task(self._line_loop(DemoLine()), name="line"))
        else:
            await self._start_collectors()

        self.tasks += [
            asyncio.create_task(self._finalize_loop(), name="finalize"),
            asyncio.create_task(self._flush_loop(), name="db-flush"),
            asyncio.create_task(self._maintenance_loop(), name="maintenance"),
            asyncio.create_task(self._system_loop(), name="system"),
            asyncio.create_task(self._devices_loop(), name="devices"),
            asyncio.create_task(self._notify_loop(), name="notify"),
        ]
        log.info("Network Lag Analyzer %s started (dev_mode=%s, data: %s)",
                 self.version, self.cfg.dev_mode, self.cfg.data_dir)

    async def stop(self) -> None:
        now = time.time()
        if self.gaming:
            await self.stop_gaming()
        self._drain_analysis(now + 3600)          # drain the queue
        self.events.close_all(self.hub.last_finalized or now)
        self.correlator.flush(now)
        for t in self.tasks:
            t.cancel()
        await self._stop_collectors()
        self._persist_devices()
        await self.db.flush()
        self.db.close()

    def _load_state(self, c) -> None:
        self.devices.load(c)
        for kind, table in (("event", "events"), ("incident", "incidents"), ("session", "gaming_sessions")):
            r = c.execute(f"SELECT MAX(id) FROM {table}").fetchone()
            self._ids[kind] = r[0] or 0
        for r in c.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 200").fetchall()[::-1]:
            self.recent_incidents.append(_incident_row(r))
        for r in c.execute("SELECT * FROM events ORDER BY id DESC LIMIT 500").fetchall()[::-1]:
            self.recent_events.append(_event_row(r))
        # close open events/sessions from the last run
        for res in (10, 60):
            r = c.execute("SELECT MAX(ts) FROM measurements WHERE res=?", (res,)).fetchone()
            self._last_agg[res] = (r[0] + res) if r[0] else 0

    def _next_id(self, kind: str) -> int:
        self._ids[kind] += 1
        return self._ids[kind]

    def _init_network(self) -> None:
        route = netinfo.default_route()
        self.gateway = route.gateway if route else None
        if self.cfg.gateway != "auto":
            self.gateway = self.cfg.gateway
        self.pi_ip = netinfo.primary_ipv4(route.interface if route else None)
        self.local_nets = [str(n) for n in netinfo.local_networks(self.cfg.local_networks)]
        self.gateway_mac = netinfo.arp_table().get(self.gateway or "")
        if self.cfg.dev_mode and not self.gateway:
            from .simulation import DEMO_GATEWAY
            self.gateway = DEMO_GATEWAY      # demo data only (RFC 5737 range)

    async def _setup_targets(self) -> None:
        wanted: list[tuple[str, str | None, str]] = []
        if self.gateway:
            wanted.append((self.gateway, "Router", "gateway"))
        for t in self.cfg.targets:
            if t.address != self.gateway:
                wanted.append((t.address, t.name, "internet"))
        ref = self.cfg.lan_reference
        if ref and ref != self.gateway:
            wanted.append((ref, "LAN reference", "lan"))

        def _ensure(c):
            return [(repo.ensure_target(c, a, n, k), a, n, k) for a, n, k in wanted]
        ids = await self.db.write(_ensure)
        self.targets = {tid: {"address": a, "name": n, "kind": k} for tid, a, n, k in ids}
        self.hub.targets.clear()
        for tid, a, n, k in ids:
            self.hub.set_target(TargetInfo(tid, a, k, n))
        if self.scheduler:
            self.scheduler.set_targets([ProbeTarget(tid, a, k, n) for tid, a, n, k in ids])

    # ================================================================== Collectors
    async def _start_collectors(self) -> None:
        cfg = self.cfg
        self.prober = IcmpProber(self._on_probe, timeout=cfg.probe.timeout)
        await self.prober.start()
        self.scheduler = ProbeScheduler(self.prober, cfg.probe.interval, cfg.probe.gaming_interval)
        self.scheduler.set_targets([ProbeTarget(tid, t["address"], t["kind"], t["name"])
                                    for tid, t in self.targets.items()])
        await self.scheduler.start()

        self.pihole = PiholeReader(cfg.pihole.ftl_db) if cfg.pihole.enabled else None
        pihole_ok = False
        if self.pihole:
            pihole_ok, msg = await asyncio.to_thread(self.pihole.check)
            self.pihole_status = {"enabled": True, "ok": pihole_ok, "message": msg}
        self._start_dns_usage(pihole_ok)
        if pihole_ok:
            self.tasks.append(asyncio.create_task(self._backfill_loop(), name="backfill"))
        if cfg.dns_probe.enabled:
            self.dns = DnsProber(cfg.dns_probe.servers, cfg.dns_probe.query_name, cfg.dns_probe.interval,
                                 cfg.dns_probe.timeout, self.hub.add_dns,
                                 pihole_present=self.pihole is not None and self.pihole.available(),
                                 uncached_suffix=cfg.dns_probe.uncached_suffix)
            self.hub.dns_primary = self.dns.servers[0] if self.dns.servers else None
            await self.dns.start()

        if cfg.fritzbox.enabled and cfg.fritzbox.password:
            host = self.gateway if cfg.fritzbox.host == "auto" else cfg.fritzbox.host
            if host:
                self.fritz = FritzClient(host, cfg.fritzbox.username, cfg.fritzbox.password, cfg.fritzbox.tr064_port)
                self.fritz_status = {"enabled": True, "host": host, "ok": None}
                self.tasks.append(asyncio.create_task(self._fritz_loop(), name="fritz"))
                self.tasks.append(asyncio.create_task(self._line_loop(self.fritz), name="line"))
        self._start_capture()

    def _log_start(self, c) -> None:
        """Remembers service starts and the kernel's boot time for the overview timeline."""
        try:
            import psutil
            boot = psutil.boot_time()
        except Exception:  # noqa: BLE001 - no boot time is no reason not to start
            boot = None
        log_ = repo.get_setting(c, overview.RESTART_LOG_KEY, [])
        repo.set_setting(c, overview.RESTART_LOG_KEY, overview.record_start(log_, self.started_at, boot))

    @property
    def login_required(self) -> bool:
        sec = self.cfg.security
        return sec.require_login_in_dev if self.cfg.dev_mode else sec.require_login

    def reload_classifier(self, overrides: dict) -> None:
        self.classifier = Classifier.load(self.cfg.data_dir, overrides)
        for e in self.classifier.errors:
            log.error("Category rules: %s", e)

    def _start_demo_dns_usage(self) -> None:
        """Dev mode only: the real ingestion pipeline, fed from a generated FTL database."""
        from .simulation import build_demo_ftl
        path = os.path.join(self.cfg.data_dir, "demo-pihole-FTL.db")
        build_demo_ftl(path, time.time())
        self.dns_usage = DnsIngestor(FtlQueryLog(path), self.cfg.dns_usage.model_copy(update={"backfill_days": 8}),
                                     hourly_domain_hours=self.cfg.retention.dns_domain_hourly_hours,
                                     classifier=lambda: self.classifier,
                                     minute_days=self.cfg.retention.dns_minute_days)
        self.dns_usage_status = self.dns_usage.status
        self.dns_usage_status["demo"] = True
        self.tasks.append(asyncio.create_task(self._dns_usage_loop(self.dns_usage), name="dns-usage"))

    def _start_dns_usage(self, pihole_ok: bool) -> None:
        cfg = self.cfg
        if not cfg.dns_usage.enabled:
            self.dns_usage_status = {"enabled": False, "ok": None, "message": "Not available: disabled"}
            return
        if self.pihole is None or not pihole_ok:
            reason = self.pihole_status.get("message") or "Pi-hole integration disabled"
            self.dns_usage_status = {"enabled": True, "ok": False, "message": f"Not available: {reason}"}
            return
        own = [a["address"] for i in netinfo.interface_addresses().values() for a in i["ipv4"]]
        own += [a for i in netinfo.interface_addresses().values() for a in i["ipv6"]]
        self.dns_usage = DnsIngestor(FtlQueryLog(cfg.pihole.ftl_db), cfg.dns_usage, own_ips=own,
                                     hourly_domain_hours=cfg.retention.dns_domain_hourly_hours,
                                     classifier=lambda: self.classifier, minute_days=cfg.retention.dns_minute_days)
        self.dns_usage_status = self.dns_usage.status
        self.tasks.append(asyncio.create_task(self._dns_usage_loop(self.dns_usage), name="dns-usage"))

    async def _dns_usage_loop(self, ing: DnsIngestor) -> None:
        """Feed DNS usage counters. Pi-hole and the measurements take precedence:
        the backfill only runs at load level 0, everything pauses from level 2."""
        await self.db.read(ing.load)
        while True:
            pause = self.cfg.dns_usage.interval
            level = self.loadguard.level
            if level >= 2:
                ing.status.update(message=f"Paused (load guard level {level})")
            else:
                try:
                    fp = minutes_key(self.classifier.fingerprint)
                    if ing.minutes_fp != fp:
                        plan = await asyncio.to_thread(ing.plan_rebuild, fp, time.time())
                        await self.db.write(lambda c: ing.write_rebuild(c, plan))
                        ing.applied_rebuild(plan)
                        if plan["rebuild"]:
                            log.info("DNS usage: category rules changed, rebuilding activity minutes")
                    b = await asyncio.to_thread(ing.step, time.time(), level == 0)
                    await self.db.write(lambda c: ing.commit(c, b))
                    ing.applied(b)
                    if b.more:
                        pause = 2.0       # backfill: small steps with breathing room
                except Exception as e:
                    log.exception("DNS usage step failed")
                    ing.status.update(ok=False, message=f"Error reading the Pi-hole query log: {e}")
            await asyncio.sleep(pause)

    async def _stop_collectors(self) -> None:
        if self.scheduler:
            await self.scheduler.stop()
        if self.prober:
            await self.prober.stop()
        if self.dns:
            await self.dns.stop()
        self._stop_capture()
        if self.fritz:
            self.fritz.close()

    def capture_source(self) -> str:
        c = self.cfg
        if c.capture.source != "auto":
            return c.capture.source
        if c.fritzbox.enabled and c.fritzbox.password and c.fritzbox.capture_enabled:
            return "fritzbox"
        if netinfo.ip_forwarding():
            return "local"
        return "none"

    def _start_capture(self) -> None:
        src = self.capture_source()
        if src == "none":
            self.capture_status = {"state": "disabled", "source": "none",
                                   "error": "No traffic source configured (FRITZ!Box access, port mirroring or Pi as gateway)"}
            return
        cfg = self.cfg
        host = self.gateway if cfg.fritzbox.host == "auto" else cfg.fritzbox.host
        router_macs = [m for m in [self.gateway_mac] if m]
        if src == "local" and netinfo.ip_forwarding():
            own = netinfo.interface_addresses().get(cfg.capture.local_interface, {}).get("mac")
            if own:
                router_macs.append(own)
        wcfg = {
            "source": src, "data_dir": cfg.data_dir, "capture": cfg.capture.model_dump(),
            "fritzbox": {**cfg.fritzbox.model_dump(), "host": host},
            "deep_capture": cfg.deep_capture.model_dump(), "local_networks": self.local_nets,
            # So that the new process adopts the old one's files instead of leaving them
            # orphaned (that was the main source of the sprawl).
            "protected_pcaps": self._protected_pcap_paths(),
            "router_macs": router_macs, "gaming_mac": self._gaming_mac(),
            "ignore_pair": [self.pi_ip, _resolve_v4(host)] if (src == "fritzbox" and self.pi_ip and _resolve_v4(host)) else None,
        }
        ctx = mp.get_context("spawn")
        self.capture_out = ctx.Queue(maxsize=2000)
        self.capture_ctrl = ctx.Queue()
        from .collectors.traffic import run_capture_process
        self.capture_proc = ctx.Process(target=run_capture_process, args=(wcfg, self.capture_out, self.capture_ctrl),
                                        name="nla-capture", daemon=True)
        self.capture_proc.start()
        self.loadguard.set_capture_pid(self.capture_proc.pid)
        self.capture_status = {"state": "starting", "source": src}
        self.capture_reader = threading.Thread(target=self._capture_reader_thread, name="capture-reader", daemon=True)
        self.capture_reader.start()

    def _stop_capture(self) -> None:
        if self.capture_proc is None:
            return
        proc = self.capture_proc
        self.capture_proc = None          # prevents auto restart on an intended stop
        self._stopping_proc = proc
        try:
            self.capture_ctrl.put_nowait(("stop",))
        except Exception:
            pass
        proc.join(timeout=5)
        if proc.is_alive():
            proc.terminate()
            proc.join(timeout=3)
        self.loadguard.set_capture_pid(None)

    def capture_command(self, *msg) -> None:
        if self.capture_proc is not None and self.capture_ctrl is not None:
            try:
                self.capture_ctrl.put_nowait(msg)
            except Exception:
                pass

    def _capture_reader_thread(self) -> None:
        out = self.capture_out
        proc = self.capture_proc
        while proc is not None and (proc.is_alive() or not out.empty()):
            try:
                msg = out.get(timeout=0.5)
            except queue.Empty:
                continue
            except (EOFError, OSError):
                break
            if self.loop:
                self.loop.call_soon_threadsafe(self._on_capture_msg, msg)
        if self.loop and self.capture_proc is proc:
            self.loop.call_soon_threadsafe(self._capture_died)

    def _capture_died(self) -> None:
        """Capture process ended unexpectedly → report status and restart after 30 s."""
        self.capture_status = {**self.capture_status, "state": "stopped",
                               "error": (self.capture_status.get("error") or "Capture process ended") +
                               " - restarting in 30 s"}
        log.error("Capture process ended (exit code %s), restarting in 30 s",
                  self.capture_proc.exitcode if self.capture_proc else None)
        self.capture_proc = None

        async def _restart():
            await asyncio.sleep(30)
            if self.capture_proc is None and not self.cfg.dev_mode:
                self._start_capture()
        self.tasks.append(asyncio.create_task(_restart(), name="capture-restart"))

    def _on_capture_msg(self, msg: tuple) -> None:
        kind = msg[0]
        if kind == "bin":
            _, sec, devs, glob = msg
            self._note_capture_delay(sec)
            self.hub.add_traffic_bin(sec, devs, glob)
        elif kind == "status":
            self.capture_status = msg[1]
            self.loadguard.capture_lag = msg[1].get("lag_s") or 0.0
        elif kind == "flows":
            rows = []
            for f in msg[1]:
                rows.append(f[:15] + (self.devices.ip_names.get(f[6]),))
            self.db.enqueue_many(repo.INSERT_FLOW, rows)
        elif kind == "active_flows":
            self.active_flows.append((msg[1], msg[2]))
        elif kind == "macip":
            for mac, ip in msg[1].items():
                self.devices.observe(mac, ip=ip, source="capture", seen=time.time())
        elif kind == "udp_candidates":
            self.udp_candidates = msg[2]
            self._gaming_candidates(msg[1], msg[2])
        elif kind == "pcap":
            self._pcap_msg(msg[1])

    def _note_capture_delay(self, sec: int) -> None:
        """How long does a per-second bin take to get here? (The FRITZ!Box buffers the stream in bursts.)

        This determines the wait time the MetricsHub grants the traffic data -
        otherwise seconds would be finalized without traffic and the dashboard would flicker.
        """
        delay = time.time() - (sec + 1)
        self._cap_delays.append(delay)
        if len(self._cap_delays) >= 5:
            worst = sorted(self._cap_delays)[int(len(self._cap_delays) * 0.9)]
            # Display: wait only briefly so that ping/loss stay live
            grace = min(self.display_grace_max, max(1.0, round(worst + 0.5, 1)))
            # Evaluation: wait until the traffic data has really arrived
            analysis = min(25.0, max(4.0, round(worst + 3.0, 1)))
            if abs(analysis - self.analysis_delay) >= 1.0:
                log.info("Router buffers the capture ~%.1f s → evaluation waits %.1f s "
                         "(display %.1f s)", worst, analysis, grace)
            self.hub.traffic_grace = grace
            self.analysis_delay = analysis
            self.capture_delay = round(worst, 2)

    def _pcap_msg(self, m: dict) -> None:
        op = m.get("op")
        if op in ("new", "update"):
            self.db.enqueue("INSERT INTO pcap_files(path, ts_start, ts_end, size, protected) VALUES (?,?,?,?,?) "
                            "ON CONFLICT(path) DO UPDATE SET ts_end=excluded.ts_end, size=excluded.size",
                            (m["path"], m["ts_start"], m["ts_end"], m["size"], int(m.get("protected", False))))
        elif op == "delete":
            # Without restricting to protected=0: the ring only reports "delete" when the
            # file is really gone - even if it was sacrificed because of the budget.
            # Otherwise a database row without a file would remain.
            self.db.enqueue("DELETE FROM pcap_files WHERE path=?", (m["path"],))
        elif op == "adopted":
            log.info("PCAP: adopted %d existing files (%.0f MB)",
                     m.get("files", 0), (m.get("bytes") or 0) / 1e6)
        elif op == "protect":
            for p in m.get("paths", []):
                self.db.enqueue("UPDATE pcap_files SET protected=1, incident_id=? WHERE path=?",
                                (m.get("incident_id"), p))

    # ------------------------------------------------------------------ Probes
    def _on_probe(self, target_id: int, send_ts: float, rtt: float | None) -> None:
        self.hub.add_probe(target_id, send_ts, rtt)
        if self.cfg.retention.ping_samples:
            # Individual probes are raw data: about 14 MB per day that no evaluation reads.
            # Off by default; only enable for troubleshooting.
            self.db.enqueue(repo.INSERT_PING, (round(send_ts, 3), target_id, rtt, 0 if rtt is not None else 1))
        if target_id == self._game_target_id:
            self._game_probe_stats[0] += 1
            if rtt is not None:
                self._game_probe_stats[1] += 1
                if self.gaming:
                    self.gaming.server_icmp = "ok"
            elif self._game_probe_stats[0] >= ICMP_GIVE_UP_PROBES and self._game_probe_stats[1] == 0:
                # Server does not answer ICMP → not a loss, but "not measurable"
                if self.gaming:
                    self.gaming.server_icmp = "blocked"
                self._remove_game_target()

    # ------------------------------------------------------------------ FRITZ!Box
    async def _fritz_loop(self) -> None:
        fb = self.fritz
        assert fb is not None
        last_hosts = last_cap = 0.0
        while True:
            now = time.time()
            # Each part on its own: one action the box does not offer (FRITZ!OS 8 dropped
            # GetAddonInfos) must not take the host list and the client identification with it.
            errors = []
            try:
                if not self.fritz_status.get("model"):
                    info = await asyncio.to_thread(fb.device_info)
                    self.fritz_status.update(model=info.get("NewModelName"), firmware=info.get("NewSoftwareVersion"))
                if now - last_cap > 600:
                    self.link_capacity = await asyncio.to_thread(fb.link_capacity)
                    last_cap = now
                # TR-064 delivers the total WAN rate immediately. On some FRITZ!Boxes the
                # capture arrives several seconds late - until then TR-064 fills the
                # gap; the exact per-device values are patched in later.
                down, up = await asyncio.to_thread(fb.wan_rates)
                self.hub.add_wan_rate(time.time(), down, up)
            except Exception as e:  # noqa: BLE001
                errors.append(f"{type(e).__name__}: {e}")
            if now - last_hosts > self.cfg.fritzbox.hostlist_interval:
                try:
                    hosts = await asyncio.to_thread(fb.host_list)
                    self.fritz_hosts, self.fritz_hosts_at = hosts, now
                    for h in hosts:
                        self.devices.observe(h.mac, ip=h.ip, hostname=h.name, interface=h.interface, source="fritzbox",
                                             seen=now if h.active else None, fritz_active=h.active)
                    last_hosts = now
                except Exception as e:  # noqa: BLE001
                    errors.append(f"{type(e).__name__}: {e}")
            if errors:
                self.fritz_status.update(ok=False, error="; ".join(errors))
                await asyncio.sleep(10)
            else:
                self.fritz_status.update(ok=True, error=None, last_ok=now)
            await asyncio.sleep(self.cfg.fritzbox.poll_interval)

    LINE_INTERVAL = 300      # DSL values: they change slowly, and every row is a write to the SD card
    LOG_INTERVAL = 900       # the box keeps a few hundred entries, so 15 minutes lose nothing

    async def _line_loop(self, src) -> None:
        """Internet line values and the FRITZ!Box event log. Its own task: a box without DSL or
        without some action must neither stop the host list nor the measurements."""
        self.line_status = {"enabled": True, "ok": None}
        last_log = 0.0
        while True:
            now = time.time()
            errors = []
            dsl = wan = None
            try:
                dsl = await asyncio.to_thread(src.dsl_info)
            except Exception as e:  # noqa: BLE001
                errors.append(f"DSL values: {type(e).__name__}: {e}")
            try:
                wan = await asyncio.to_thread(src.wan_status)
            except Exception as e:  # noqa: BLE001
                errors.append(f"Connection state: {type(e).__name__}: {e}")
            if dsl is not None or wan is not None:
                row = repo.line_params(int(now), dsl, wan)
                await self.db.write(lambda c: c.execute(repo.INSERT_LINE, row))
            if now - last_log >= self.LOG_INTERVAL:
                try:
                    evs = [e for e in (line.parse_event(x) for x in await asyncio.to_thread(src.device_log)) if e]
                    await self.db.write(lambda c: c.executemany(
                        repo.INSERT_FRITZ_EVENT, [(e["ts"], e["kind"], e["grp"], e["msg"]) for e in evs]))
                    last_log = now
                except Exception as e:  # noqa: BLE001
                    errors.append(f"Event log: {type(e).__name__}: {e}")
            level, notes = line.assess(dsl)
            self.line_status = {"enabled": True, "ok": not errors, "error": "; ".join(errors) or None, "ts": now,
                                "dsl": dsl, "wan": wan, "level": level, "notes": notes,
                                "has_dsl": dsl is not None}
            await asyncio.sleep(self.LINE_INTERVAL)

    # ------------------------------------------------------------------ devices / Pi-hole
    async def _devices_loop(self) -> None:
        last_ph_hosts = last_arp = last_presence = 0.0
        await self.db.read(lambda c: self.presence.load(
            c.execute("SELECT id, dev, ts_start, ts_end FROM device_presence WHERE ts_end >= ?",
                      (int(time.time()) - 3600,)).fetchall(), time.time()))
        while True:
            now = time.time()
            try:
                last_arp, last_ph_hosts = await self._devices_step(now, last_arp, last_ph_hosts)
            except Exception:  # noqa: BLE001
                # Before, one error here ended the task without a word: for days no device was
                # saved and no DNS minute was counted, and nothing in the log said so.
                log.exception("Device update failed")
            self._persist_devices()
            self._sync_gaming_mac()
            if now - last_presence >= 60:
                last_presence = now
                try:
                    await self._presence_step(now)
                except Exception:  # noqa: BLE001 - presence is a view, the measurements go on
                    log.exception("Presence update failed")
            await asyncio.sleep(self.cfg.pihole.poll_interval if self.pihole else 30)

    async def _devices_step(self, now: float, last_arp: float, last_ph_hosts: float) -> tuple[float, float]:
        """One round of the device sources; returns the new (last_arp, last_ph_hosts)."""
        if now - last_arp > 30:
            for ip, mac in netinfo.arp_table().items():
                self.devices.observe(mac, ip=ip, source="arp", seen=now)
            if self.gateway:
                gm = netinfo.arp_table().get(self.gateway)
                if gm and gm != self.gateway_mac:
                    self.gateway_mac = gm
                    self.capture_command("router_macs", [gm])
            last_arp = now
        if self.pihole is not None and self.pihole_status.get("ok"):
            if now - last_ph_hosts > 60:
                await self._observe_pihole_hosts()
                last_ph_hosts = now
            rows = await asyncio.to_thread(self.pihole.poll_queries)
            if rows:
                self.db.enqueue_many(
                    "INSERT OR REPLACE INTO dns_queries(ts, client_ip, queries, blocked, top_domains) VALUES (?,?,?,?,?)",
                    rows)
            if self.pihole.error:
                self.pihole_status.update(ok=False, message=self.pihole.error)
        return last_arp, last_ph_hosts

    # ------------------------------------------------------------------ notifications
    async def _notify_loop(self) -> None:
        await asyncio.sleep(90)          # measurements first: right after a start every window is short
        last_events = time.time()
        while True:
            try:
                last_events = await self._notify_round(time.time(), last_events)
            except Exception:  # noqa: BLE001
                log.exception("Notification round failed")
            await asyncio.sleep(30)

    async def _notify_round(self, now: float, last_events: float) -> float:
        n = self.cfg.notify
        if not n.enabled:
            return now
        self.alerts.cooldown_s = n.cooldown_minutes * 60
        msgs: list[Message] = []
        a = self.alerts
        if n.router_loss:
            gw = next((t for t in self.hub.target_health() if t["kind"] == "gateway" and t["address"] == self.gateway), None)
            loss = gw["loss_pct"] if gw and gw["probes"] else None
            verdict = (self.link_verdict() or {}).get("text") or ""
            msgs += a.condition("router_loss", now, loss is not None and loss >= n.router_loss_pct,
                                "Packet loss to the router", f"{loss or 0:.1f} % in the last 2 minutes. {verdict}".strip(), 0)
        if n.internet_down:
            msgs += a.condition("internet_down", now, self.hub.internet_online() is False, "Internet down",
                                "No internet target answers pings.", n.internet_down_seconds)
        if n.pihole_down:
            light = overview.dns_light(self)
            down = light["level"] == "critical" or self.pi_health.get("pihole_active") is False
            msgs += a.condition("pihole_down", now, down, "Pi-hole does not answer",
                                f"{light['value']} - {light['detail']}".strip(" -"), 60)
        if n.pi_health:
            ph = self.pi_health
            msgs += a.condition("pi_health", now, ph.get("level") == "critical", "Raspberry Pi needs attention",
                                "; ".join(ph.get("notes") or []), 120)
        if n.line:
            ls = self.line_status or {}
            wan = (ls.get("wan") or {}).get("status")
            bad = ls.get("level") == "critical" or (wan is not None and wan.lower() != "connected")
            msgs += a.condition("line", now, bad, "Internet line problem",
                                "; ".join(ls.get("notes") or []) or f"FRITZ!Box connection state: {wan}", 0)
            evs = await self.db.read(lambda c: c.execute(
                "SELECT ts, kind, msg FROM fritz_events WHERE ts > ? AND kind IN ('dsl_down', 'disconnected') ORDER BY ts",
                (int(last_events),)).fetchall())
            for ts, kind, msg in evs:
                msgs.append(Message(f"fritz:{ts}", line.KIND_LABELS.get(kind, kind), msg, "default", "event"))
        if n.new_device:
            acked = await self.db.read(lambda c: repo.get_setting(c, presence.ACK_KEY, {}))
            known = await self.db.read(lambda c: set(repo.get_setting(c, "notified_devices", [])))
            for d in presence.new_devices(self.devices.all(), acked, now - 86400):
                if d["mac"] in known or d["mac"] in self._notified_devices:
                    continue
                self._notified_devices.add(d["mac"])
                msgs.append(Message(f"device:{d['mac']}", "New device in the network",
                                    f"{d['name']} ({d['ip'] or 'no IPv4'}, {d['mac']}{', ' + d['vendor'] if d.get('vendor') else ''})",
                                    "default", "event"))
            if self._notified_devices - known:
                done = sorted(known | self._notified_devices)[-500:]
                await self.db.write(lambda c: repo.set_setting(c, "notified_devices", done))
        for m in msgs:
            await self._send(m)
        return now

    async def _send(self, m: Message) -> dict:
        from .collectors import notify as nt
        res = await asyncio.to_thread(nt.deliver, self.cfg.notify, m.title, m.body, m.priority)
        self.notify_log.appendleft({"ts": time.time(), "key": m.key, "title": m.title, "body": m.body, "kind": m.kind,
                                    "result": res})
        for ch, err in res.items():
            if err:
                log.warning("Notification via %s failed: %s", ch, err)
        return res

    async def _presence_step(self, now: float) -> None:
        present = {self.devices.id_for(d.mac) for d in list(self.devices.by_mac.values()) if d.active}
        started, ended, flush = self.presence.step(now, present)
        open_rows = [(p["last"], p["row"]) for p in self.presence.open.values()] if flush else []

        def write(c):
            c.executemany("UPDATE device_presence SET ts_end=? WHERE id=?", [(end, row) for row, _dev, end in ended])
            if open_rows:
                c.executemany("UPDATE device_presence SET ts_end=? WHERE id=?", open_rows)
            return [(dev, c.execute("INSERT INTO device_presence(dev, ts_start, ts_end) VALUES (?,?,?)",
                                    (dev, int(now), int(now))).lastrowid) for dev in started]
        for dev, row_id in await self.db.write(write):
            self.presence.opened(dev, row_id, now)

    async def _backfill_loop(self) -> None:
        """Once after the start: fill gaps that Pi-hole's log can still answer (see analysis/backfill.py)."""
        await asyncio.sleep(120)        # the live pipeline first
        for name, step in (("presence", self._backfill_presence), ("DNS minutes", self._backfill_dns_minutes)):
            try:
                n = await step(time.time())
                if n:
                    log.info("Backfill %s: %d rows added from Pi-hole's log", name, n)
            except Exception:  # noqa: BLE001 - a gap that stays is no reason to stop anything else
                log.exception("Backfill %s failed", name)

    async def _backfill_presence(self, now: float) -> int:
        """Presence before the tracking started, from the hourly DNS counters per device (marked as such)."""
        def plan(c):
            if repo.get_setting(c, backfill.PRESENCE_KEY, None) is not None:
                return None, []
            first = c.execute("SELECT MIN(ts_start) FROM device_presence WHERE source IS NULL").fetchone()[0]
            if first is None:
                return None, []     # no live period yet: nothing to fill up to
            until = int(first) // 3600 * 3600
            rows = c.execute(
                """SELECT d.id, h.ts FROM dns_client_hourly h JOIN dns_clients k ON k.id = h.client
                   JOIN devices d ON d.mac = k.mac
                   WHERE k.basis = 'mac' AND h.queries > 0 AND h.ts >= ? AND h.ts < ?""",
                (until - backfill.PRESENCE_DAYS * 86400, until)).fetchall()
            return until, [tuple(r) for r in rows]
        until, hours = await self.db.read(plan)
        if until is None:
            return 0
        periods = backfill.presence_periods(hours)

        def write(c):
            c.executemany("INSERT INTO device_presence(dev, ts_start, ts_end, source) VALUES (?,?,?,'dns')", periods)
            repo.set_setting(c, backfill.PRESENCE_KEY, until)
        await self.db.write(write)
        return len(periods)

    async def _backfill_dns_minutes(self, now: float, ftl: FtlQueryLog | None = None) -> int:
        """DNS minutes (lag context) the service did not count, from Pi-hole's 91-day log.
        Hour by hour, only at load guard level 0, newest first."""
        ftl = ftl or FtlQueryLog(self.cfg.pihole.ftl_db)
        start = int(now - self.cfg.retention.detailed_days * 86400)
        end = int(self.started_at - 900) // 60 * 60     # from here on the live poll counts
        covered, checked = await self.db.read(lambda c: (
            {r[0] for r in c.execute("SELECT DISTINCT ts FROM dns_queries WHERE ts >= ? AND ts < ?", (start, end))},
            {h for h in repo.get_setting(c, backfill.CHECKED_KEY, []) if h >= start}))
        added = 0
        for h in reversed(backfill.hours_to_fill(covered, checked, start, end)):
            while self.loadguard.level > 0:
                await asyncio.sleep(30)
            t1 = min(h + 3600, end)
            rows = [r for r in backfill.minute_rows(await asyncio.to_thread(lambda: list(ftl.iter_range(h, t1))))
                    if r[0] not in covered]
            if h + 3600 <= end:
                checked.add(h)
            done = sorted(checked)

            def write(c, rows=rows, done=done):
                c.executemany("INSERT OR IGNORE INTO dns_queries(ts, client_ip, queries, blocked, top_domains) "
                              "VALUES (?,?,?,?,?)", rows)
                repo.set_setting(c, backfill.CHECKED_KEY, done)
            await self.db.write(write)
            added += len(rows)
            await asyncio.sleep(0.2 if rows else 0)    # breathing room for FTL after real work only
        return added

    async def _observe_pihole_hosts(self) -> None:
        hosts = await asyncio.to_thread(self.pihole.hosts)
        for h in hosts:
            self.devices.observe(h.mac, ip=h.ip, hostname=h.name, vendor=h.vendor, source="pihole",
                                 seen=h.last_query)
        for h in await asyncio.to_thread(read_dhcp_leases, self.cfg.pihole.dhcp_leases):
            self.devices.observe(h.mac, ip=h.ip, hostname=h.name, source="dhcp")

    async def refresh_device_names(self) -> dict:
        """Forget all learned host names and IPs and ask every source again, now.

        Aliases set by the user stay. Returns what changed, for the UI.
        """
        before = {m: (d.hostname, d.ip) for m, d in self.devices.by_mac.items()}
        self.devices.forget_names()
        asked = []
        if self.pihole is not None:
            await self._observe_pihole_hosts()
            asked += ["Pi-hole", "DHCP leases"]
        if self.fritz is not None:
            try:
                hosts = await asyncio.to_thread(self.fritz.host_list)
                self.fritz_hosts, self.fritz_hosts_at = hosts, time.time()
                asked.append("FRITZ!Box")
            except Exception as e:           # noqa: BLE001 - the other sources still count
                log.warning("Refreshing names: FRITZ!Box host list failed: %s", e)
                hosts = self.fritz_hosts
            for h in hosts:
                self.devices.observe(h.mac, ip=h.ip, hostname=h.name, interface=h.interface, source="fritzbox",
                                     fritz_active=h.active)
        if self.simulator is not None:
            from .simulation import DEMO_DEVICES
            for mac, (ip, name) in DEMO_DEVICES.items():
                self.devices.observe(mac, ip=ip, hostname=name, source="simulated")
            asked.append("demo devices")
        for ip, mac in netinfo.arp_table().items():
            self.devices.observe(mac, ip=ip, source="arp")
        changes = [{"mac": m, "before": before.get(m, (None, None))[0], "after": d.hostname,
                    "ip_before": before.get(m, (None, None))[1], "ip_after": d.ip}
                   for m, d in self.devices.by_mac.items()
                   if before.get(m, (None, None)) != (d.hostname, d.ip)]
        self._persist_devices()
        # The DNS pages keep their own copy of name and IP per client (dns_clients).
        rows = [(d.hostname, d.ip, f"mac:{m}") for m, d in self.devices.by_mac.items()]
        await self.db.write(lambda c: c.executemany(
            "UPDATE dns_clients SET name = ?, ip = COALESCE(?, ip) WHERE key = ?", rows))
        await self.db.flush()
        log.info("Device names refreshed from %s: %d changed", ", ".join(asked) or "no source", len(changes))
        return {"sources": asked, "changed": changes, "devices": len(self.devices.by_mac)}

    def _persist_devices(self) -> None:
        rows = self.devices.dirty_rows()
        if rows:
            self.db.enqueue_many(DeviceRegistry.UPSERT, rows)

    # ================================================================== per-second pipeline
    async def _finalize_loop(self) -> None:
        """Finalize seconds - and catch jumps of the system clock along the way.

        All time series hang on the wall clock. If NTP moves the clock by several
        seconds after boot or after a longer offline period, there would otherwise be
        gaps or duplicate timestamps, and the timeline would bend silently.
        So a jump is detected, logged and the started part is
        discarded - an honest gap is better than wrong measurements.
        """
        last_wall, last_mono = time.time(), time.monotonic()
        while True:
            await asyncio.sleep(0.25)
            now_wall, now_mono = time.time(), time.monotonic()
            drift = (now_wall - last_wall) - (now_mono - last_mono)
            if abs(drift) > CLOCK_JUMP_S:
                log.warning("System clock jumped by %+.1f s - discarding running seconds", drift)
                self.clock_jumps.append({"at": now_wall, "drift": round(drift, 2)})
                del self.clock_jumps[:-10]
                try:
                    self.hub.reset_pending()
                except Exception:  # pragma: no cover
                    log.exception("Reset after clock jump failed")
            last_wall, last_mono = now_wall, now_mono
            try:
                self.hub.finalize_due()
                self._drain_analysis()
            except Exception:  # pragma: no cover
                log.exception("Finalization failed")

    def _on_second(self, row: dict) -> None:
        ts = row["ts"]
        self.db.enqueue(repo.INSERT_MEASUREMENT, repo.measurement_params(1, row))
        self.db.enqueue_many(repo.INSERT_TARGET_MEAS, [
            repo.target_params(1, ts, tid, v) for tid, v in row["targets"].items()])
        devrows = [(1, ts, self.devices.id_for(mac), v[0], v[1]) for mac, v in row["devices"].items()
                   if v[0] or v[1]]
        if devrows:
            self.db.enqueue_many(repo.INSERT_DEVICE_TRAFFIC, devrows)
            for mac, v in row["devices"].items():
                if v[0] or v[1]:
                    d = self.devices.by_mac.get(mac)
                    if d is None or ts - d.last_seen > 30:
                        self.devices.observe(mac, source="capture", seen=ts)
        self.broadcaster.publish("tick", self.live_frame(row))
        self._analysis_q.append(row)
        self._drain_analysis()

    def _on_second_patched(self, row: dict) -> None:
        """Late traffic data: correct the database and update the UI."""
        ts = row["ts"]
        self.db.enqueue(repo.INSERT_MEASUREMENT, repo.measurement_params(1, row))
        devrows = [(1, ts, self.devices.id_for(mac), v[0], v[1]) for mac, v in row["devices"].items()
                   if v[0] or v[1]]
        if devrows:
            self.db.enqueue_many(repo.INSERT_DEVICE_TRAFFIC, devrows)
        if self.hub.last_finalized - ts <= 30:      # only for the currently visible seconds
            self.broadcaster.publish("tick_patch", self.live_frame(row))
        self._drain_analysis()

    def _drain_analysis(self, now: float | None = None) -> None:
        """The event engine and incident correlation only get a row once the
        traffic data is there (or it is certain that none will come)."""
        now = time.time() if now is None else now
        while self._analysis_q:
            row = self._analysis_q[0]
            # "Complete" means: capture data is there. TR-064 only delivers totals
            # without per-device assignment and is not enough for the root cause analysis.
            complete = (row.get("traffic_src") or "").startswith("capture") or not self.hub.capture_active(now)
            if not complete and now - row["ts"] < self.analysis_delay:
                break
            self._analysis_q.popleft()
            try:
                self.events.process(row)
                self.correlator.tick(row["ts"])
            except Exception:  # pragma: no cover
                log.exception("Evaluation of second %s failed", row["ts"])

    def analysis_lag(self) -> float:
        """How far does the evaluation lag behind the measurement (seconds)?"""
        return round(time.time() - self._analysis_q[0]["ts"], 1) if self._analysis_q else 0.0

    def live_frame(self, row: dict) -> dict:
        devs = sorted(row["devices"].items(), key=lambda kv: -(kv[1][0] + kv[1][1]))[:12]
        return {
            "ts": row["ts"],
            "m": {k: row.get(k) for k in ("rtt_avg", "rtt_min", "rtt_max", "gw_rtt", "jitter", "loss_pct",
                                         "down_bps", "up_bps", "traffic_src", "game_rtt", "game_pps",
                                         "game_gap_ms", "dns_ms", "probes", "lost")},
            "retrans_pct": _pct(row.get("retrans"), row.get("tcp_segs")),
            "devices": [{"mac": m, "name": self.devices.name_for_mac(m), "ip": self._ip_of(m),
                         "down_bps": v[0] * 8, "up_bps": v[1] * 8} for m, v in devs if v[0] or v[1]],
            "loss": self.hub.loss_windows(),
            "open_events": [e.to_dict() for e in self.events.open_events()],
            "incident": self.correlator.current.id if self.correlator.current else None,
            "gaming": self.gaming.to_dict() if self.gaming else None,
            "online": self.hub.internet_online(),
        }

    def _ip_of(self, mac: str) -> str | None:
        d = self.devices.by_mac.get(mac)
        return d.ip if d else None

    def _top_device_of_row(self, row: dict, direction: str) -> str | None:
        idx = 1 if direction == "up" else 0
        devs = row.get("devices") or {}
        if not devs:
            return None
        mac, v = max(devs.items(), key=lambda kv: kv[1][idx])
        return mac if v[idx] > 0 else None

    # ------------------------------------------------------------------ Events/Incidents
    def _event_params(self, ev: Event) -> tuple:
        return (ev.id, ev.type, ev.severity, ev.ts_start, ev.ts_end, ev.peak, ev.baseline, ev.target, ev.mac,
                json.dumps(ev.details), ev.incident_id)

    EVENT_SQL = ("INSERT OR REPLACE INTO events(id, type, severity, ts_start, ts_end, peak, baseline, target, mac, "
                 "details, incident_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)")
    INCIDENT_SQL = ("INSERT OR REPLACE INTO incidents(id, source, ts_start, ts_end, reported_at, title, cause, category, "
                    "confidence, analysis, session_id, pcap_protected) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)")

    def _event_started(self, ev: Event) -> None:
        self.correlator.event_started(ev)
        self.db.enqueue(self.EVENT_SQL, self._event_params(ev))
        self._remember_event(ev)
        self.broadcaster.publish("event", ev.to_dict())

    def _event_updated(self, ev: Event) -> None:
        self._remember_event(ev)

    def _event_ended(self, ev: Event) -> None:
        self.correlator.event_ended(ev)
        self.db.enqueue(self.EVENT_SQL, self._event_params(ev))
        self._remember_event(ev)
        self.broadcaster.publish("event", ev.to_dict())

    def _remember_event(self, ev: Event) -> None:
        d = ev.to_dict()
        for i in range(len(self.recent_events) - 1, max(-1, len(self.recent_events) - 50), -1):
            if self.recent_events[i]["id"] == ev.id:
                self.recent_events[i] = d
                return
        self.recent_events.append(d)

    def _incident_params(self, inc: Incident, protected: bool = False) -> tuple:
        return (inc.id, inc.source, inc.ts_start, inc.ts_end, inc.reported_at, inc.title, inc.cause, inc.category,
                inc.confidence, json.dumps(inc.analysis, default=str), inc.session_id, int(protected))

    def _incident_opened(self, inc: Incident) -> None:
        inc.title = "Ongoing incident"
        self.db.enqueue(self.INCIDENT_SQL, self._incident_params(inc))
        self._remember_incident(inc)
        self.broadcaster.publish("incident", inc.to_dict() | {"state": "open"})

    def _incident_closed(self, inc: Incident, events: list[Event]) -> None:
        protected = self._protect_pcap_for(inc, events)
        self.db.enqueue(self.INCIDENT_SQL, self._incident_params(inc, protected))
        for e in events:
            if e.incident_id is None:
                e.incident_id = inc.id          # link context events (e.g. HIGH_UPLOAD)
            if e.incident_id == inc.id:
                self.db.enqueue(self.EVENT_SQL, self._event_params(e))
                self._remember_event(e)
        self._remember_incident(inc)
        self.broadcaster.publish("incident", inc.to_dict() | {"state": "closed"})

    def _incident_dismissed(self, inc: Incident, events: list[Event], reason: str) -> None:
        """Not worth an incident (see correlation.dismiss_reason): the row written when it opened goes,
        its events are kept without an incident."""
        self.db.enqueue("DELETE FROM incidents WHERE id=?", (inc.id,))
        for e in events:
            if e.incident_id in (None, inc.id):
                e.incident_id = None
                self.db.enqueue(self.EVENT_SQL, self._event_params(e))
                self._remember_event(e)
        self.recent_incidents = deque((x for x in self.recent_incidents if x["id"] != inc.id), maxlen=200)
        self.dismissed_incidents[reason] = self.dismissed_incidents.get(reason, 0) + 1
        self.broadcaster.publish("incident", {"id": inc.id, "state": "dismissed", "reason": reason})

    def _protect_pcap_for(self, inc: Incident, events: list[Event]) -> bool:
        """Keep the capture for an automatically detected incident - or not.

        Every incident used to keep 50 MB files, for 90 days. With a dozen
        incidents a day that adds up to tens of gigabytes, although the
        settings say "5 × 50 MB". `protect_auto` limits what it is worth it for.
        """
        dc = self.cfg.deep_capture
        if not dc.enabled or self.capture_proc is None or dc.protect_auto == "none":
            return False
        if dc.protect_auto == "critical":
            critical = any(e.severity == "critical" for e in events) or inc.confidence == "high"
            if not critical:
                return False
        self.capture_command("protect", inc.ts_start - 30, (inc.ts_end or inc.ts_start) + 5, inc.id)
        return True

    def _remember_incident(self, inc: Incident) -> None:
        d = inc.to_dict()
        d["category_label"] = CATEGORY_LABELS.get(inc.category or "", inc.category)
        for i, x in enumerate(self.recent_incidents):
            if x["id"] == inc.id:
                self.recent_incidents[i] = d
                return
        self.recent_incidents.append(d)

    # ------------------------------------------------------------------ windows for analyses
    def rows_between(self, t0: float, t1: float) -> list[dict]:
        ring_start = self.hub.ring[0]["ts"] if self.hub.ring else None
        if ring_start is not None and t0 >= ring_start - 1:
            return self.hub.range(t0, t1)
        # (partly) older than the ring buffer → rebuild from the database, the ring adds the rest
        db_rows = self.db.read_sync(lambda c: _rows_from_db(c, int(t0), int(t1)))
        if ring_start is None:
            return db_rows
        return [r for r in db_rows if r["ts"] < ring_start] + self.hub.range(ring_start, t1)

    def build_window(self, t0: float, t1: float) -> Window:
        rows = self.rows_between(t0 - 30, t1 + 5)
        cd, cu, src = self.capacity_info()
        return Window(rows=rows, t0=int(t0), t1=int(t1), targets=dict(self.targets), cap_down=cd, cap_up=cu,
                      cap_source=src, thresholds=self.cfg.thresholds, device_label=self.devices.label,
                      gaming=self.gaming.to_dict() if self.gaming else None)

    def capacity_info(self) -> tuple[float | None, float | None, str | None]:
        c = self.cfg.capacity
        down = c.down_mbit * 1e6 if isinstance(c.down_mbit, (int, float)) else None
        up = c.up_mbit * 1e6 if isinstance(c.up_mbit, (int, float)) else None
        src = "config" if (down or up) else None
        if down is None and self.link_capacity[0]:
            down, src = self.link_capacity[0], src or "tr064"
        if up is None and self.link_capacity[1]:
            up, src = self.link_capacity[1], src or "tr064"
        return down, up, src

    def capacity(self) -> tuple[float | None, float | None]:
        d, u, _ = self.capacity_info()
        return d, u

    async def report_lag(self, window: int = 30) -> dict:
        """'I JUST HAD LAG' - waits for the current second to be finalized and analyzes."""
        reported = time.time()
        deadline = reported + 5
        while self.hub.last_finalized < int(reported) - 0.5 and time.time() < deadline:
            await asyncio.sleep(0.25)
        end = min(int(reported), self.hub.last_finalized or int(reported))
        # Wait for the (possibly buffered) traffic data of the time span - otherwise the
        # analysis would wrongly say "no traffic per device".
        traffic_deadline = reported + min(20.0, self.analysis_delay + 2)
        while time.time() < traffic_deadline and self.hub.capture_active():
            row = next((r for r in reversed(self.hub.ring) if r["ts"] == end), None)
            if row is None or (row.get("traffic_src") or "").startswith("capture"):
                break
            await asyncio.sleep(0.25)
        self._drain_analysis()
        events = list(self.recent_events)
        result = await asyncio.to_thread(
            analyze_user_report, end, self.rows_between, self.build_window, self.cfg.thresholds,
            self.devices.label, events, window)
        inc = Incident(id=self._next_id("incident"), source="user", ts_start=result["analysis_window"]["start"],
                       ts_end=end, reported_at=reported, cause=result["cause"], category=result["category"],
                       confidence=result["confidence"], analysis=result,
                       session_id=self.gaming.id if self.gaming else None)
        inc.title = "Lag reported"
        protected = False
        if self.cfg.deep_capture.enabled and self.capture_proc is not None:
            self.capture_command("protect", reported - 300, reported, inc.id)
            protected = True
        self.db.enqueue(self.INCIDENT_SQL, self._incident_params(inc, protected))
        self._remember_incident(inc)
        await self.db.flush()
        self.broadcaster.publish("incident", inc.to_dict() | {"state": "closed"})
        return inc.to_dict()

    # ================================================================== Gaming
    def _gaming_mac(self) -> str | None:
        ip = self.cfg.gaming_pc.ip
        return self.devices.mac_for_ip(ip) if ip else None

    def _sync_gaming_mac(self) -> None:
        mac = self._gaming_mac()
        if mac != getattr(self, "_sent_gaming_mac", None):
            self._sent_gaming_mac = mac
            self.capture_command("gaming_mac", mac)

    def _gaming_candidates(self, now: float, cands: list[dict]) -> None:
        mac = self.gaming.mac if self.gaming and self.gaming.mac else self._gaming_mac()
        sustained, best = self.gaming_detector.feed(now, mac, cands)
        if self.gaming is None:
            if sustained and self.cfg.gaming.auto_detect and mac:
                asyncio.ensure_future(self.start_gaming(auto=True))
            return
        if best and pick_server(self.gaming, best):
            self._set_game_target(self.gaming.server_ip)
            self.db.enqueue("UPDATE gaming_sessions SET server_ip=?, server_port=? WHERE id=?",
                            (self.gaming.server_ip, self.gaming.server_port, self.gaming.id))
        if self.gaming.auto_detected and self.gaming_detector.idle_for(now) > self.cfg.gaming.stop_after_idle:
            asyncio.ensure_future(self.stop_gaming())

    def _set_game_target(self, ip: str | None) -> None:
        self._remove_game_target()
        if not ip:
            return
        def _ensure(c):
            return repo.ensure_target(c, ip, "Game-Server", "game")
        tid = self.db.write_sync(_ensure)
        self._game_target_id = tid
        self._game_probe_stats = [0, 0]
        self.targets[tid] = {"address": ip, "name": "Game-Server", "kind": "game"}
        self.hub.set_target(TargetInfo(tid, ip, "game", "Game-Server"))
        if self.scheduler:
            self.scheduler.add_target(ProbeTarget(tid, ip, "game", "Game-Server", fast=True))

    def _remove_game_target(self) -> None:
        if self._game_target_id is None:
            return
        tid = self._game_target_id
        self._game_target_id = None
        self.targets.pop(tid, None)
        self.hub.remove_target(tid)
        if self.scheduler:
            self.scheduler.targets = [t for t in self.scheduler.targets if t.target_id != tid]

    async def start_gaming(self, auto: bool = False, device_ip: str | None = None) -> dict:
        if self.gaming:
            return self.gaming.to_dict()
        ip = device_ip or self.cfg.gaming_pc.ip
        mac = self.devices.mac_for_ip(ip) if ip else None
        sess = GamingSession(id=self._next_id("session"), ts_start=time.time(), mac=mac, device_ip=ip,
                             auto_detected=auto)
        self.gaming = sess
        if self.scheduler:
            self.scheduler.fast_mode = True
        if mac:
            self.capture_command("gaming_mac", mac)
        self.db.enqueue("INSERT INTO gaming_sessions(id, ts_start, mac, device_ip, auto_detected) VALUES (?,?,?,?,?)",
                        (sess.id, sess.ts_start, mac, ip, int(auto)))
        if self.simulator:
            self.simulator.gaming_started(sess)
        self.broadcaster.publish("gaming", sess.to_dict())
        log.info("Gaming session %s started (auto=%s, device %s)", sess.id, auto, ip)
        return sess.to_dict()

    async def stop_gaming(self) -> dict | None:
        sess = self.gaming
        if sess is None:
            return None
        self.gaming = None
        sess.ts_end = time.time()
        if self.scheduler:
            self.scheduler.fast_mode = False
        self._remove_game_target()
        await self.db.flush()
        t0, t1 = sess.ts_start, sess.ts_end
        rows = await asyncio.to_thread(self.rows_between, t0, t1)
        evs = [e for e in self.recent_events if t0 <= e["ts_start"] <= t1]
        incs = [i for i in self.recent_incidents if t0 <= i["ts_start"] <= t1 and i.get("category")]
        summary = summarize_session(rows, evs, incs)
        summary["server_icmp"] = sess.server_icmp
        self.db.enqueue("UPDATE gaming_sessions SET ts_end=?, server_ip=?, server_port=?, summary=? WHERE id=?",
                        (sess.ts_end, sess.server_ip, sess.server_port, json.dumps(summary), sess.id))
        await self.db.flush()
        out = sess.to_dict() | {"summary": summary}
        self.broadcaster.publish("gaming", None)
        return out

    # ================================================================== maintenance
    async def _flush_loop(self) -> None:
        while True:
            await asyncio.sleep(1.0)
            try:
                await self.db.flush()
            except Exception:
                log.exception("DB flush failed")

    async def _maintenance_loop(self) -> None:
        await asyncio.sleep(20)
        last_ret = 0.0
        while True:
            try:
                await self._aggregate()
                await self._bufferbloat_window()
                if time.time() - last_ret > 3600:
                    ret = self.cfg.retention
                    deleted = await self.db.write(lambda c: repo.apply_retention(c, time.time(), ret))
                    log.info("Retention: %s", {k: v for k, v in deleted.items() if v})
                    await self._cleanup_pcaps()
                    await self._write_daily()
                    await self._dns_usage_maintenance()
                    await self._check_db_size()
                    await self._auto_backup()
                    await self._ut1_refresh()
                    last_ret = time.time()
            except Exception:
                log.exception("Maintenance failed")
            await asyncio.sleep(60)

    @property
    def backup_dir(self):
        from pathlib import Path
        return Path(self.cfg.data_dir) / "backups"

    async def _auto_backup(self, force: bool = False) -> dict | None:
        """Weekly (by default) at the configured hour, only at load guard level 0."""
        from .database import backup as bk
        b = self.cfg.backup
        last = await self.db.read(lambda c: repo.get_setting(c, "last_backup", None))
        due = force or (b.enabled and (last is None or time.time() - last.get("ts", 0) >= b.interval_days * 86400 - 3600)
                        and time.localtime().tm_hour == b.hour and self.loadguard.level == 0)
        if not due:
            return None
        await self.db.flush()
        try:
            res = await asyncio.to_thread(bk.make_backup, self.db.path, self.backup_dir, self.yaml_path)
            res["removed"] = await asyncio.to_thread(bk.rotate, self.backup_dir, b.keep)
            res["ok"] = True
            log.info("Backup written: %s (%.0f MB, %s s)", res["path"], res["size"] / 1e6, res["seconds"])
        except Exception as e:  # noqa: BLE001
            res = {"ok": False, "ts": time.time(), "error": f"{type(e).__name__}: {e}"}
            log.error("Backup failed: %s", res["error"])
        await self.db.write(lambda c: repo.set_setting(c, "last_backup", res))
        return res

    UT1_URL = "https://dsi.ut-capitole.fr/blacklists/download/blacklists.tar.gz"
    UT1_MAX_BYTES = 300 * 1024 * 1024

    async def _ut1_refresh(self, force: bool = False) -> dict | None:
        """Monthly, at night, at load guard level 0: fetch the UT1 lists again and import them if they
        changed. The import (~80 s, ~400 MB) runs in its own low-priority process: in this one it
        would hold the interpreter lock that the per-second pipeline needs."""
        import json
        import subprocess
        import sys
        from pathlib import Path
        from .analysis.categories import UT1_META
        u = self.cfg.dns_usage
        meta_p = Path(self.cfg.data_dir) / UT1_META
        if not meta_p.exists() or not (u.ut1_auto_update or force):
            return None                      # never imported: the user did not opt in
        meta = json.loads(meta_p.read_text(encoding="utf-8"))
        last = await self.db.read(lambda c: repo.get_setting(c, "ut1_refresh", {}))
        checked = max(meta.get("imported_at") or 0, last.get("ts") or 0)
        due = force or (time.time() - checked >= u.ut1_update_days * 86400
                        and time.localtime().tm_hour == (self.cfg.backup.hour + 1) % 24 and self.loadguard.level == 0)
        if not due:
            return None
        archive = Path(self.cfg.data_dir) / "ut1-download.tar.gz"
        res: dict = {"ts": time.time(), "ok": False, "changed": False}
        try:
            sha = await asyncio.to_thread(self._download, self.UT1_URL, archive, self.UT1_MAX_BYTES)
            if sha == meta.get("sha256"):
                res.update(ok=True, note="unchanged")
            else:
                cmd = [sys.executable, "-m", "backend.dns_category_import", "--archive", str(archive),
                       "--data-dir", self.cfg.data_dir]
                if sys.platform != "win32":
                    cmd = ["nice", "-n", "15", *cmd]
                proc = await asyncio.create_subprocess_exec(
                    *cmd, cwd=str(Path(__file__).resolve().parent.parent),
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                out, _ = await asyncio.wait_for(proc.communicate(), timeout=1800)
                if proc.returncode != 0:
                    raise RuntimeError(out.decode("utf-8", "replace").strip().splitlines()[-1][:200] if out else "import failed")
                overrides = await self.db.read(lambda c: repo.get_setting(c, "dns_category_overrides", {}))
                self.reload_classifier(overrides)         # new fingerprint: activity minutes rebuild by themselves
                res.update(ok=True, changed=True)
                log.info("UT1 lists updated")
        except Exception as e:  # noqa: BLE001 - the old index stays in use
            res["error"] = f"{type(e).__name__}: {e}"
            log.error("UT1 refresh failed: %s", res["error"])
        finally:
            archive.unlink(missing_ok=True)
        await self.db.write(lambda c: repo.set_setting(c, "ut1_refresh", res))
        return res

    @staticmethod
    def _download(url: str, dst, max_bytes: int) -> str:
        """Streams to `dst`, refusing more than `max_bytes`; returns the SHA-256."""
        import hashlib
        import httpx
        h = hashlib.sha256()
        n = 0
        with httpx.stream("GET", url, timeout=60, follow_redirects=True) as r:
            r.raise_for_status()
            with open(dst, "wb") as f:
                for chunk in r.iter_bytes(1 << 20):
                    n += len(chunk)
                    if n > max_bytes:
                        raise OSError(f"download larger than {max_bytes // 1048576} MB - refused")
                    h.update(chunk)
                    f.write(chunk)
        return h.hexdigest()

    async def _dns_usage_maintenance(self) -> None:
        ing = self.dns_usage
        if ing is None or ing.last_ts is None:
            return
        # Only days that are over AND fully read: FTL writes with up to a minute of
        # delay, and during the backfill "today" of the reader is weeks ago.
        until = min(local_day(time.time()), local_day(ing.last_ts - 3600))
        top = self.cfg.dns_usage.top_domains_per_day
        folded = await self.db.write(lambda c: fold_completed_days(c, top, until))
        dropped = await self.db.write(delete_unused_domains)
        if folded or dropped:
            log.info("DNS usage: folded %s domain rows, removed %s unused domain names", folded, dropped)

    async def _write_daily(self) -> None:
        """Backfill completed days into `daily_stats` (about 200 bytes per day)."""
        written = await self.db.write(lambda c: daily.write_missing(c, time.time()))
        if written:
            log.info("Daily summary added: %s", ", ".join(written))

    async def _check_db_size(self) -> None:
        """Emergency brake against a full SD card.

        Deletion happens step by step and in separate transactions, because only
        after a commit does it become visible how much space has really been freed.
        The measure is the space used (`used`), not the file size - otherwise it would
        keep deleting although enough space has long been free.
        """
        limit_mb = self.cfg.retention.max_db_mb
        if not limit_mb:
            self.db_guard = None
            return
        max_bytes = limit_mb * 1_000_000
        size = await self.db.read(repo.db_size)
        self.db_guard = {"limit_bytes": max_bytes, **size, "acted": False, "deleted": {}}
        if size["used"] <= max_bytes:
            return

        log.warning("Database over the limit: %.0f MB used, %.0f MB allowed",
                    size["used"] / 1e6, max_bytes / 1e6)
        deleted: dict[str, int] = {}
        target = max_bytes * 0.9        # some headroom so that it does not delete every hour
        done = False
        for hours in repo.SIZE_GUARD_AGES:
            cut = time.time() - hours * 3600
            for name, sql in repo.SIZE_GUARD_STEPS:
                n = await self.db.write(
                    lambda c, s=sql, k=cut: c.execute(s, () if "?" not in s else (k,)).rowcount)
                if n > 0:
                    deleted[name] = deleted.get(name, 0) + n
                if (await self.db.read(repo.db_size))["used"] <= target:
                    done = True
                    break
            if done:
                break
        freed = await self.db.maintenance(repo.vacuum)
        after = await self.db.read(repo.db_size)
        self.db_guard = {"limit_bytes": max_bytes, **after, "acted": True, "deleted": deleted,
                         "freed_bytes": freed["freed"], "at": time.time()}
        log.warning("Size limit enforced: deleted %s, file %.0f → %.0f MB",
                    deleted, freed["before"] / 1e6, freed["after"] / 1e6)

    async def _bufferbloat_window(self) -> None:
        """Record latency under load for the last completed 10-minute window.

        1 s values are only kept for one day; this window is tiny and
        makes the history visible over weeks. It is only written if the window
        contained both quiet and saturated seconds - otherwise there would be nothing
        to compare.
        """
        b = bufferbloat.BUCKET
        ts = (int(time.time()) - b) // b * b
        if ts <= self._last_bloat:
            return
        self._last_bloat = ts
        cd, cu, _ = self.capacity_info()
        if not (cd and cu):
            return
        ring = list(self.hub.ring)
        rows = [r for r in ring if ts <= r["ts"] < ts + b]
        if not rows:
            return
        m = bufferbloat.measure(rows, cd, cu, idle_rows=ring)
        params = repo.bufferbloat_params(ts, m)
        if params:
            self.db.enqueue(repo.INSERT_BUFFERBLOAT, params)

    async def _aggregate(self) -> None:
        now = int(time.time())
        for src, dst in ((1, 10), (10, 60)):
            end = (now - 15) // dst * dst
            start = self._last_agg[dst] or (end - 3600) // dst * dst
            start = max(start, end - 7 * 86400)
            if end <= start:
                continue
            await self.db.write(lambda c, s=start, e=end, a=src, b=dst: repo.aggregate(c, a, b, s, e))
            self._last_agg[dst] = end

    def _protected_pcap_paths(self) -> list[str]:
        """Protected captures from the database - handed to the capture process."""
        try:
            return [r["path"] for r in self.db.read_sync(lambda c: repo.rows_to_dicts(
                c.execute("SELECT path FROM pcap_files WHERE protected=1")))]
        except Exception:  # pragma: no cover - must never prevent startup
            log.exception("Protected PCAP paths not readable")
            return []

    def pcap_usage(self) -> dict:
        """Actual space used by the pcap directory - measured, not calculated."""
        d = os.path.join(self.cfg.data_dir, "pcap")
        total = n = 0
        try:
            with os.scandir(d) as it:
                for e in it:
                    if e.is_file() and e.name.endswith(".pcap"):
                        total += e.stat().st_size
                        n += 1
        except OSError:
            return {"enabled": self.cfg.deep_capture.enabled, "files": 0, "bytes": 0,
                    "limit_bytes": self.cfg.deep_capture.max_total_mb * 1_000_000, "dir": d}
        return {"enabled": self.cfg.deep_capture.enabled, "files": n, "bytes": total,
                "limit_bytes": self.cfg.deep_capture.max_total_mb * 1_000_000, "dir": d}

    async def _cleanup_pcaps(self) -> None:
        """Remove old and orphaned captures.

        Three cases, of which only the first used to be covered:
        1. Protected files that have exceeded their retention time.
        2. Database rows without a file (after a crash or manual deletion).
        3. **Files without a database row** - these used to stay forever.
           That is exactly how another 250 MB piled up after every restart of the
           capture process that nobody deleted any more.
        """
        cutoff = time.time() - self.cfg.deep_capture.protected_days * 86400
        rows = await self.db.read(lambda c: repo.rows_to_dicts(
            c.execute("SELECT path FROM pcap_files WHERE protected=1 AND ts_end < ?", (cutoff,))))
        for r in rows:
            try:
                os.unlink(r["path"])
            except OSError:
                pass
        if rows:
            await self.db.write(lambda c: c.execute(
                "DELETE FROM pcap_files WHERE protected=1 AND ts_end < ?", (cutoff,)))
        if not self.cfg.deep_capture.enabled:
            # Deep Capture is off: the unprotected files are the remains of a
            # ring buffer that no longer exists - they would never go away otherwise,
            # because nobody rotates any more. Incident captures stay until protected_days.
            await self._drop_unprotected_pcaps()
        await self._reconcile_pcaps()

    async def _drop_unprotected_pcaps(self) -> None:
        rows = await self.db.read(lambda c: repo.rows_to_dicts(
            c.execute("SELECT path FROM pcap_files WHERE protected=0")))
        freed = 0
        for r in rows:
            try:
                freed += os.path.getsize(r["path"])
                os.unlink(r["path"])
            except OSError:
                pass
        if rows:
            await self.db.write(lambda c: c.execute("DELETE FROM pcap_files WHERE protected=0"))
            log.info("Deep Capture off: removed %d running captures (%.0f MB)", len(rows), freed / 1e6)

    async def _reconcile_pcaps(self) -> None:
        """Reconcile directory and database; remove orphans on both sides."""
        d = os.path.join(self.cfg.data_dir, "pcap")
        try:
            on_disk = {os.path.join(d, f) for f in os.listdir(d) if f.endswith(".pcap")}
        except OSError:
            return
        known = await self.db.read(lambda c: {r["path"] for r in c.execute("SELECT path FROM pcap_files")})
        missing = known - on_disk
        if missing:
            await self.db.write(lambda c: c.executemany(
                "DELETE FROM pcap_files WHERE path=?", [(p,) for p in missing]))
        # Orphaned files: only delete if no capture process is running right now that
        # still holds them in its ring - otherwise the file currently being written would vanish.
        # If the capture process is running, its ring knows every file (it adopts the
        # existing files on start) - then there is nothing to do here. If Deep Capture is off
        # or the process is stopped, leftovers would otherwise stay forever.
        orphans = on_disk - known
        if orphans and (self.capture_proc is None or not self.cfg.deep_capture.enabled):
            freed = 0
            for p in orphans:
                try:
                    freed += os.path.getsize(p)
                    os.unlink(p)
                except OSError:
                    pass
            log.warning("Removed %d orphaned PCAP files (%.0f MB)", len(orphans), freed / 1e6)

    async def _system_loop(self) -> None:
        last_health = 0.0
        while True:
            await asyncio.sleep(1)
            self.loadguard.sample()
            lvl_before = self.loadguard.level
            lvl = self.loadguard.evaluate()
            if lvl != lvl_before:
                log.warning("Load Guard: level %s → %s (%s)", lvl_before, lvl, self.loadguard.last)
                self.capture_command("level", lvl)
            # after the load guard's sample: the health snapshot reuses its CPU and memory values
            if time.time() - last_health >= 60:
                last_health = time.time()
                try:
                    await self._sample_health()
                except Exception:  # noqa: BLE001 - a missing sensor must not stop the load guard
                    log.exception("Pi health sample failed")

    async def _sample_health(self) -> None:
        route = netinfo.default_route()
        svc = "pihole-FTL" if self.cfg.pihole.enabled and not self.cfg.dev_mode else None
        h = await asyncio.to_thread(pi_health.read, self.cfg.data_dir, route.interface if route else None,
                                    self.loadguard.last, svc)
        await self.db.write(lambda c: c.execute(repo.INSERT_PI_HEALTH, repo.pi_health_params(h)))
        lk = h.get("link") or {}
        self._pi_recent.append({"ts": h["ts"], "boot_ts": h.get("boot_ts"), **{k: lk.get(k) for k in
                                ("carrier_changes", "rx_errors", "tx_errors")}})
        recent: dict = {}
        for d in pi_health.deltas(list(self._pi_recent))[1:]:
            for k, v in d.items():
                if k != "ts" and v:
                    recent[k] = recent.get(k, 0) + v
        level, notes = pi_health.assess(h, recent)
        self.pi_health = {**h, "level": level, "notes": notes, "recent": recent}

    def link_verdict(self) -> dict | None:
        th = self.hub.target_health()
        gw = next((t for t in th if t["kind"] == "gateway" and t["address"] == self.gateway), None)
        lan = next((t for t in th if t["kind"] == "lan"), None)
        return pi_health.link_verdict(gw, lan, self.cfg.thresholds.packet_loss_warning)

    # ================================================================== settings
    async def update_settings(self, patch: dict) -> dict:
        from .config import EDITABLE_SECTIONS, RESTART_SECTIONS, deep_merge
        bad = set(patch) - EDITABLE_SECTIONS
        if bad:
            raise ValueError(f"Not changeable: {', '.join(sorted(bad))}")
        new_password = False
        if "fritzbox" in patch:
            if patch["fritzbox"].get("password") in ("********", None):
                patch["fritzbox"].pop("password", None)
            else:
                new_password = True
        if "notify" in patch:
            from .config import NOTIFY_SECRETS
            for k in NOTIFY_SECRETS:            # the UI shows secrets masked; unchanged means keep
                if patch["notify"].get(k) == "********":
                    patch["notify"].pop(k)
        overrides = await self.db.read(lambda c: repo.get_setting(c, "config_overrides", {}))
        merged = deep_merge(overrides, patch)
        new_cfg = build_config(self.yaml_data, merged)   # validates (raises on errors)
        # The stored password only goes to the address it was entered for.
        # Otherwise any device on the LAN could point the address at its own server
        # and would receive the FRITZ!Box login response for offline guessing.
        if (self.cfg.fritzbox.password and not new_password
                and fritz_target(new_cfg) != fritz_target(self.cfg)):
            raise ValueError("The FRITZ!Box address is changing - please re-enter the FRITZ!Box password "
                             "as well.")
        await self.db.write(lambda c: repo.set_setting(c, "config_overrides", merged))
        old = self.cfg
        self.cfg = new_cfg
        # changes that take effect immediately
        self.events.t = new_cfg.thresholds
        self.loadguard.cfg = new_cfg.load_guard
        self.gaming_detector = GamingDetector(new_cfg.gaming.min_pps, new_cfg.gaming.min_seconds,
                                              new_cfg.gaming.stop_after_idle)
        if self.scheduler:
            self.scheduler.interval = new_cfg.probe.interval
            self.scheduler.fast_interval = new_cfg.probe.gaming_interval
        if "targets" in patch or "gateway" in patch or "lan_reference" in patch:
            self._init_network()
            await self._setup_targets()
        if new_cfg.deep_capture.enabled != old.deep_capture.enabled:
            self.capture_command("deep", new_cfg.deep_capture.enabled)
        self._sync_gaming_mac()
        restart = bool(set(patch) & RESTART_SECTIONS) and not self.cfg.dev_mode
        if restart:
            await self.restart_collectors()
        return {"restarted": restart}

    async def restart_collectors(self) -> None:
        await self._stop_collectors()
        for t in [t for t in self.tasks if t.get_name() in ("fritz", "dns-usage")]:
            t.cancel()
            self.tasks.remove(t)
        self.fritz = None
        self.fritz_status = {"enabled": False}
        self.dns_usage = None
        self._init_network()
        await self._start_collectors()

    # ================================================================== Status
    def status(self) -> dict:
        last = self.hub.ring[-1] if self.hub.ring else None
        cd, cu, csrc = self.capacity_info()
        return {
            "version": self.version,
            "dev_mode": self.cfg.dev_mode,
            "uptime": time.time() - self.started_at,
            "setup_done": self.setup_done,
            "now": time.time(),
            "last": self.live_frame(last) if last else None,
            "icmp": {"mode": self.prober.mode if self.prober else ("simulated" if self.simulator else None),
                     "error": self.prober.error if self.prober else None,
                     "kernel_timestamps": self.prober.kernel_ts if self.prober else None},
            "gateway": self.gateway,
            "pi_ip": self.pi_ip,
            "targets": self.hub.target_health(),
            "capture": self.capture_status,
            "fritzbox": {k: v for k, v in self.fritz_status.items()},
            "line": self.line_status,
            "pi": self.pi_health,
            "pihole": self.pihole_status,
            "dns_usage": self.dns_usage_status,
            "dns": self.dns.last if self.dns else {},
            "capacity": {"down_bps": cd, "up_bps": cu, "source": csrc},
            "system": self.loadguard.last,
            "capture_delay": self.capture_delay,
            "traffic_grace": self.hub.traffic_grace,
            "analysis_delay": self.analysis_delay,
            "analysis_lag": self.analysis_lag(),
            "db": self.db.stats,
            "gaming": self.gaming.to_dict() if self.gaming else None,
            "incident_open": self.correlator.current.to_dict() if self.correlator.current else None,
            "incidents_dismissed": self.dismissed_incidents,
            "alerts_active": self.alerts.active(),
        }


# ====================================================================== helpers
def _resolve_v4(host: str | None) -> str | None:
    """Host (IP, name or name:port) → IPv4 address, otherwise None."""
    if not host:
        return None
    name = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    try:
        import socket
        return socket.gethostbyname(name)
    except OSError:
        return None


def _pct(a, b) -> float | None:
    if a is None or not b:
        return None
    return round(100.0 * a / b, 2)


def _event_row(r) -> dict:
    d = dict(r)
    d["details"] = json.loads(d["details"] or "{}")
    d["label"] = EVENT_LABELS.get(d["type"], d["type"])
    return d


def _incident_row(r) -> dict:
    d = dict(r)
    d["analysis"] = json.loads(d["analysis"] or "{}")
    d["category_label"] = CATEGORY_LABELS.get(d.get("category") or "", d.get("category"))
    return d


def _rows_from_db(c, t0: int, t1: int) -> list[dict]:
    """Rebuilds 1 s rows from the database (for analyses outside the ring buffer).

    Only the two byte counters are stored per device; packets, UDP and
    LAN share are only available live and are carried as 0 here.
    No evaluation reads them - if that changed, there must not be a 0 here.
    """
    rows = {r["ts"]: {**repo.decode_row(r), "targets": {}, "devices": {}, "dns": [],
                      "gw_probes": 0, "gw_lost": 0}
            for r in c.execute("SELECT * FROM measurements WHERE res=1 AND ts BETWEEN ? AND ? ORDER BY ts", (t0, t1))}
    gw_ids = {r[0] for r in c.execute("SELECT id FROM targets WHERE kind='gateway'")}
    for r in c.execute("SELECT * FROM target_measurements WHERE res=1 AND ts BETWEEN ? AND ?", (t0, t1)):
        row = rows.get(r["ts"])
        if row is not None:
            row["targets"][r["target_id"]] = {"rtt": repo.dec(r["rtt_avg"], "rtt_avg"),
                                              "max": repo.dec(r["rtt_max"], "rtt_max"),
                                              "probes": r["probes"], "lost": r["lost"]}
            if r["target_id"] in gw_ids:
                row["gw_probes"] += r["probes"] or 0
                row["gw_lost"] += r["lost"] or 0
    q = ("SELECT t.ts, d.mac, t.rx_bytes, t.tx_bytes FROM device_traffic t "
         "JOIN devices d ON d.id = t.dev WHERE t.res=1 AND t.ts BETWEEN ? AND ?")
    for r in c.execute(q, (t0, t1)):
        row = rows.get(r["ts"])
        if row is not None:
            row["devices"][r["mac"]] = [r["rx_bytes"], r["tx_bytes"], 0, 0, 0, 0, 0]
    return [rows[k] for k in sorted(rows)]
