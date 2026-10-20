"""Orchestrierung aller Komponenten (läuft im Hauptprozess, asyncio)."""
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
from .analysis import bufferbloat, daily
from .analysis.correlation import Correlator, Incident, analyze_user_report
from .analysis.events import EVENT_LABELS, Event, EventEngine
from .analysis.gaming import ICMP_GIVE_UP_PROBES, GamingDetector, GamingSession, pick_server, summarize_session
from .analysis.metrics import MetricsHub, TargetInfo
from .analysis.root_cause import CATEGORY_LABELS, Window
from .collectors.devices import DeviceRegistry
from .collectors.dns import DnsProber
from .collectors.fritzbox import FritzClient, FritzError
from .collectors.pihole import PiholeReader
from .collectors.ping import IcmpProber, ProbeScheduler, ProbeTarget
from .config import Config, build_config, fritz_target, load_yaml
from .database import repository as repo
from .database.repository import Database
from .util import netinfo
from .util.loadguard import LoadGuard

log = logging.getLogger("nla.core")

# Ab dieser Abweichung zwischen Wanduhr und monotoner Uhr gilt die Systemzeit als gesprungen
# (NTP nach dem Boot, Sommerzeit auf Systemen ohne UTC-Uhr, Handstellung).
CLOCK_JUMP_S = 2.0


class Broadcaster:
    """Verteilt Live-Daten an alle SSE-Clients (je Client eine begrenzte Queue)."""

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
                pass  # langsamer Client verliert Frames, blockiert aber nichts


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
        self.pihole: PiholeReader | None = None
        self.pihole_status: dict = {"enabled": False}
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
        self.active_flows: deque[tuple[float, list]] = deque(maxlen=720)
        self.udp_candidates: list[dict] = []
        self.gaming: GamingSession | None = None
        self.gaming_detector = GamingDetector(self.cfg.gaming.min_pps, self.cfg.gaming.min_seconds,
                                              self.cfg.gaming.stop_after_idle)
        self._game_target_id: int | None = None
        self._game_probe_stats = [0, 0]
        self._cap_delays: deque[float] = deque(maxlen=60)
        self.capture_delay: float | None = None
        # Anzeige läuft sofort; die Auswertung wartet auf die (verspäteten) Traffic-Daten
        self._analysis_q: deque[dict] = deque()
        self.analysis_delay: float = 4.0
        self.display_grace_max: float = 3.0
        self._ids = {"event": 0, "incident": 0, "session": 0}
        self._last_agg = {10: 0, 60: 0}
        self._last_bloat = 0
        self.db_guard: dict | None = None      # Zustand der Größengrenze, für /api/status
        self.clock_jumps: list[dict] = []      # erkannte Sprünge der Systemuhr
        self.loop: asyncio.AbstractEventLoop | None = None
        self.simulator = None
        self.setup_done = False
        self.version = __version__

    # ================================================================== Start/Stopp
    async def start(self) -> None:
        self.loop = asyncio.get_running_loop()
        await self.db.init()
        overrides = await self.db.read(lambda c: repo.get_setting(c, "config_overrides", {}))
        if overrides:
            try:
                self.cfg = build_config(self.yaml_data, overrides)
            except Exception as e:  # ungültige Overrides dürfen den Start nicht verhindern
                log.error("Gespeicherte Einstellungen ungültig, werden ignoriert: %s", e)
        self.setup_done = await self.db.read(lambda c: repo.get_setting(c, "setup_done", False))
        await self.db.read(self._load_state)
        self._init_network()

        self.events = EventEngine(self.cfg.thresholds, self.capacity, lambda: self._next_id("event"),
                                  self._top_device_of_row, gaming_active_fn=lambda: self.gaming is not None)
        self.correlator = Correlator(self.build_window, lambda: self._next_id("incident"),
                                     self._incident_closed, self._incident_opened)
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
            self.tasks.append(asyncio.create_task(self.simulator.run(), name="simulator"))
        else:
            await self._start_collectors()

        self.tasks += [
            asyncio.create_task(self._finalize_loop(), name="finalize"),
            asyncio.create_task(self._flush_loop(), name="db-flush"),
            asyncio.create_task(self._maintenance_loop(), name="maintenance"),
            asyncio.create_task(self._system_loop(), name="system"),
            asyncio.create_task(self._devices_loop(), name="devices"),
        ]
        log.info("Network Lag Analyzer %s gestartet (dev_mode=%s, Daten: %s)",
                 self.version, self.cfg.dev_mode, self.cfg.data_dir)

    async def stop(self) -> None:
        now = time.time()
        if self.gaming:
            await self.stop_gaming()
        self._drain_analysis(now + 3600)          # Warteschlange leeren
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
        # offene Events/Sessions vom letzten Lauf schließen
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
            self.gateway = DEMO_GATEWAY      # nur Demo-Daten (RFC-5737-Bereich)

    async def _setup_targets(self) -> None:
        wanted: list[tuple[str, str | None, str]] = []
        if self.gateway:
            wanted.append((self.gateway, "Router", "gateway"))
        for t in self.cfg.targets:
            if t.address != self.gateway:
                wanted.append((t.address, t.name, "internet"))

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
        self._start_capture()

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
                                   "error": "Keine Traffic-Quelle konfiguriert (FRITZ!Box-Zugang, Port-Mirroring oder Pi als Gateway)"}
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
            # Damit der neue Prozess die Dateien des alten übernimmt, statt sie
            # herrenlos liegen zu lassen (das war die Hauptquelle des Wildwuchses).
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
        self.capture_proc = None          # verhindert Auto-Neustart beim gewollten Stopp
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
        """Capture-Prozess unerwartet beendet → Status melden und nach 30 s neu starten."""
        self.capture_status = {**self.capture_status, "state": "stopped",
                               "error": (self.capture_status.get("error") or "Capture-Prozess beendet") +
                               " – Neustart in 30 s"}
        log.error("Capture-Prozess beendet (exitcode %s), Neustart in 30 s",
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
        """Wie lange braucht ein Sekunden-Bin bis hierher? (FRITZ!Box puffert den Stream in Schüben.)

        Daraus wird die Wartezeit abgeleitet, die der MetricsHub den Traffic-Daten einräumt –
        sonst würden Sekunden ohne Traffic finalisiert und das Dashboard flackert.
        """
        delay = time.time() - (sec + 1)
        self._cap_delays.append(delay)
        if len(self._cap_delays) >= 5:
            worst = sorted(self._cap_delays)[int(len(self._cap_delays) * 0.9)]
            # Anzeige: höchstens kurz warten, damit Ping/Loss live bleiben
            grace = min(self.display_grace_max, max(1.0, round(worst + 0.5, 1)))
            # Auswertung: so lange warten, bis die Traffic-Daten wirklich da sind
            analysis = min(25.0, max(4.0, round(worst + 3.0, 1)))
            if abs(analysis - self.analysis_delay) >= 1.0:
                log.info("Router puffert den Mitschnitt ~%.1f s → Auswertung wartet %.1f s "
                         "(Anzeige %.1f s)", worst, analysis, grace)
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
            # Ohne Einschränkung auf protected=0: Der Ring meldet "delete" nur, wenn die
            # Datei tatsächlich weg ist – auch wenn sie wegen des Budgets geopfert wurde.
            # Sonst bliebe eine Datenbankzeile ohne Datei stehen.
            self.db.enqueue("DELETE FROM pcap_files WHERE path=?", (m["path"],))
        elif op == "adopted":
            log.info("PCAP: %d vorhandene Dateien übernommen (%.0f MB)",
                     m.get("files", 0), (m.get("bytes") or 0) / 1e6)
        elif op == "protect":
            for p in m.get("paths", []):
                self.db.enqueue("UPDATE pcap_files SET protected=1, incident_id=? WHERE path=?",
                                (m.get("incident_id"), p))

    # ------------------------------------------------------------------ Probes
    def _on_probe(self, target_id: int, send_ts: float, rtt: float | None) -> None:
        self.hub.add_probe(target_id, send_ts, rtt)
        if self.cfg.retention.ping_samples:
            # Einzelne Probes sind Rohdaten: rund 14 MB je Tag, die keine Auswertung liest.
            # Standardmäßig aus; nur für die Fehlersuche einschalten.
            self.db.enqueue(repo.INSERT_PING, (round(send_ts, 3), target_id, rtt, 0 if rtt is not None else 1))
        if target_id == self._game_target_id:
            self._game_probe_stats[0] += 1
            if rtt is not None:
                self._game_probe_stats[1] += 1
                if self.gaming:
                    self.gaming.server_icmp = "ok"
            elif self._game_probe_stats[0] >= ICMP_GIVE_UP_PROBES and self._game_probe_stats[1] == 0:
                # Server antwortet nicht auf ICMP → kein Verlust, sondern "nicht messbar"
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
            try:
                if not self.fritz_status.get("model"):
                    info = await asyncio.to_thread(fb.device_info)
                    self.fritz_status.update(model=info.get("NewModelName"), firmware=info.get("NewSoftwareVersion"))
                if now - last_cap > 600:
                    self.link_capacity = await asyncio.to_thread(fb.link_capacity)
                    last_cap = now
                # TR-064 liefert die WAN-Gesamtrate sofort. Der Mitschnitt kommt bei
                # manchen FRITZ!Boxen mehrere Sekunden verzögert – bis dahin füllt TR-064
                # die Lücke; die exakten Werte je Gerät werden später nachgetragen.
                down, up = await asyncio.to_thread(fb.wan_rates)
                self.hub.add_wan_rate(time.time(), down, up)
                if now - last_hosts > self.cfg.fritzbox.hostlist_interval:
                    hosts = await asyncio.to_thread(fb.host_list)
                    for h in hosts:
                        self.devices.observe(h.mac, ip=h.ip, hostname=h.name, interface=h.interface, source="fritzbox",
                                             seen=now if h.active else None, fritz_active=h.active)
                    last_hosts = now
                self.fritz_status.update(ok=True, error=None, last_ok=now)
            except (FritzError, Exception) as e:  # noqa: BLE001
                self.fritz_status.update(ok=False, error=f"{type(e).__name__}: {e}")
                await asyncio.sleep(10)
            await asyncio.sleep(self.cfg.fritzbox.poll_interval)

    # ------------------------------------------------------------------ Geräte / Pi-hole
    async def _devices_loop(self) -> None:
        last_ph_hosts = last_arp = 0.0
        while True:
            now = time.time()
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
                    hosts = await asyncio.to_thread(self.pihole.hosts)
                    for h in hosts:
                        self.devices.observe(h.mac, ip=h.ip, hostname=h.name, vendor=h.vendor, source="pihole",
                                             seen=h.last_query)
                    last_ph_hosts = now
                rows = await asyncio.to_thread(self.pihole.poll_queries)
                if rows:
                    self.db.enqueue_many(
                        "INSERT OR REPLACE INTO dns_queries(ts, client_ip, queries, blocked, top_domains) VALUES (?,?,?,?,?)",
                        rows)
                if self.pihole.error:
                    self.pihole_status.update(ok=False, message=self.pihole.error)
            self._persist_devices()
            self._sync_gaming_mac()
            await asyncio.sleep(self.cfg.pihole.poll_interval if self.pihole else 30)

    def _persist_devices(self) -> None:
        rows = self.devices.dirty_rows()
        if rows:
            self.db.enqueue_many(DeviceRegistry.UPSERT, rows)

    # ================================================================== Sekunden-Pipeline
    async def _finalize_loop(self) -> None:
        """Sekunden abschließen – und dabei Sprünge der Systemuhr abfangen.

        Alle Zeitreihen hängen an der Wanduhr. Stellt NTP die Uhr nach dem Boot
        oder nach längerer Offline-Zeit um mehrere Sekunden, entstünden sonst
        Lücken oder doppelte Zeitstempel, und die Timeline würde still verbiegen.
        Ein Sprung wird deshalb erkannt, protokolliert und der angefangene Teil
        verworfen – lieber eine ehrliche Lücke als falsche Messwerte.
        """
        last_wall, last_mono = time.time(), time.monotonic()
        while True:
            await asyncio.sleep(0.25)
            now_wall, now_mono = time.time(), time.monotonic()
            drift = (now_wall - last_wall) - (now_mono - last_mono)
            if abs(drift) > CLOCK_JUMP_S:
                log.warning("Sprung der Systemuhr um %+.1f s erkannt – laufende Sekunden werden verworfen", drift)
                self.clock_jumps.append({"at": now_wall, "drift": round(drift, 2)})
                del self.clock_jumps[:-10]
                try:
                    self.hub.reset_pending()
                except Exception:  # pragma: no cover
                    log.exception("Zurücksetzen nach Zeitsprung fehlgeschlagen")
            last_wall, last_mono = now_wall, now_mono
            try:
                self.hub.finalize_due()
                self._drain_analysis()
            except Exception:  # pragma: no cover
                log.exception("Finalisierung fehlgeschlagen")

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
        """Verspätet eingetroffene Traffic-Daten: Datenbank korrigieren und Oberfläche nachziehen."""
        ts = row["ts"]
        self.db.enqueue(repo.INSERT_MEASUREMENT, repo.measurement_params(1, row))
        devrows = [(1, ts, self.devices.id_for(mac), v[0], v[1]) for mac, v in row["devices"].items()
                   if v[0] or v[1]]
        if devrows:
            self.db.enqueue_many(repo.INSERT_DEVICE_TRAFFIC, devrows)
        if self.hub.last_finalized - ts <= 30:      # nur für die aktuell sichtbaren Sekunden
            self.broadcaster.publish("tick_patch", self.live_frame(row))
        self._drain_analysis()

    def _drain_analysis(self, now: float | None = None) -> None:
        """Event-Engine und Incident-Korrelation bekommen eine Zeile erst, wenn die
        Traffic-Daten vorliegen (oder feststeht, dass keine mehr kommen)."""
        now = time.time() if now is None else now
        while self._analysis_q:
            row = self._analysis_q[0]
            # "Vollständig" heißt: Mitschnittdaten liegen vor. TR-064 liefert nur Summen
            # ohne Geräte-Zuordnung und reicht für die Ursachenanalyse nicht aus.
            complete = (row.get("traffic_src") or "").startswith("capture") or not self.hub.capture_active(now)
            if not complete and now - row["ts"] < self.analysis_delay:
                break
            self._analysis_q.popleft()
            try:
                self.events.process(row)
                self.correlator.tick(row["ts"])
            except Exception:  # pragma: no cover
                log.exception("Auswertung der Sekunde %s fehlgeschlagen", row["ts"])

    def analysis_lag(self) -> float:
        """Wie weit hängt die Auswertung hinter der Messung (Sekunden)?"""
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
        inc.title = "Laufender Incident"
        self.db.enqueue(self.INCIDENT_SQL, self._incident_params(inc))
        self._remember_incident(inc)
        self.broadcaster.publish("incident", inc.to_dict() | {"state": "open"})

    def _incident_closed(self, inc: Incident, events: list[Event]) -> None:
        protected = self._protect_pcap_for(inc, events)
        self.db.enqueue(self.INCIDENT_SQL, self._incident_params(inc, protected))
        for e in events:
            if e.incident_id is None:
                e.incident_id = inc.id          # Kontext-Events (z. B. HIGH_UPLOAD) verknüpfen
            if e.incident_id == inc.id:
                self.db.enqueue(self.EVENT_SQL, self._event_params(e))
                self._remember_event(e)
        self._remember_incident(inc)
        self.broadcaster.publish("incident", inc.to_dict() | {"state": "closed"})

    def _protect_pcap_for(self, inc: Incident, events: list[Event]) -> bool:
        """Mitschnitt zu einem automatisch erkannten Incident festhalten – oder eben nicht.

        Jeder Incident hielt bisher 50-MB-Dateien fest, 90 Tage lang. Bei einem Dutzend
        Incidents am Tag summiert sich das auf zweistellige Gigabyte, obwohl in den
        Einstellungen „5 × 50 MB" steht. `protect_auto` begrenzt, wofür es sich lohnt.
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

    # ------------------------------------------------------------------ Fenster für Analysen
    def rows_between(self, t0: float, t1: float) -> list[dict]:
        ring_start = self.hub.ring[0]["ts"] if self.hub.ring else None
        if ring_start is not None and t0 >= ring_start - 1:
            return self.hub.range(t0, t1)
        # (teilweise) älter als der Ringpuffer → aus der Datenbank rekonstruieren, Ring ergänzt den Rest
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
        """'ICH HATTE GERADE LAG' – wartet auf die Finalisierung der aktuellen Sekunde und analysiert."""
        reported = time.time()
        deadline = reported + 5
        while self.hub.last_finalized < int(reported) - 0.5 and time.time() < deadline:
            await asyncio.sleep(0.25)
        end = min(int(reported), self.hub.last_finalized or int(reported))
        # Auf die (ggf. gepufferten) Traffic-Daten des Zeitraums warten – sonst stünde
        # fälschlich "kein Traffic pro Gerät" in der Analyse.
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
        inc.title = "Lag gemeldet"
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
        log.info("Gaming Session %s gestartet (auto=%s, Gerät %s)", sess.id, auto, ip)
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

    # ================================================================== Wartung
    async def _flush_loop(self) -> None:
        while True:
            await asyncio.sleep(1.0)
            try:
                await self.db.flush()
            except Exception:
                log.exception("DB-Flush fehlgeschlagen")

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
                    await self._check_db_size()
                    last_ret = time.time()
            except Exception:
                log.exception("Wartung fehlgeschlagen")
            await asyncio.sleep(60)

    async def _write_daily(self) -> None:
        """Abgeschlossene Tage in `daily_stats` nachtragen (rund 200 Byte je Tag)."""
        written = await self.db.write(lambda c: daily.write_missing(c, time.time()))
        if written:
            log.info("Tages-Zusammenfassung ergänzt: %s", ", ".join(written))

    async def _check_db_size(self) -> None:
        """Notbremse gegen eine volle SD-Karte.

        Gelöscht wird schrittweise und in eigenen Transaktionen, weil erst nach
        einem Commit sichtbar wird, wie viel Platz wirklich frei geworden ist.
        Maßstab ist der belegte Platz (`used`), nicht die Dateigröße – sonst würde
        weitergelöscht, obwohl längst genug frei ist.
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

        log.warning("Datenbank über der Grenze: %.0f MB belegt, erlaubt %.0f MB",
                    size["used"] / 1e6, max_bytes / 1e6)
        deleted: dict[str, int] = {}
        target = max_bytes * 0.9        # etwas Luft, damit nicht jede Stunde gelöscht wird
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
        log.warning("Größengrenze durchgesetzt: gelöscht %s, Datei %.0f → %.0f MB",
                    deleted, freed["before"] / 1e6, freed["after"] / 1e6)

    async def _bufferbloat_window(self) -> None:
        """Latenz unter Last für das letzte abgeschlossene 10-Minuten-Fenster festhalten.

        Die 1-s-Werte werden nur einen Tag aufbewahrt; dieses Fenster ist winzig und
        macht den Verlauf über Wochen sichtbar. Geschrieben wird nur, wenn das Fenster
        sowohl ruhige als auch ausgelastete Sekunden enthielt – sonst gäbe es nichts
        zu vergleichen.
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
        """Geschützte Mitschnitte aus der Datenbank – wird dem Capture-Prozess mitgegeben."""
        try:
            return [r["path"] for r in self.db.read_sync(lambda c: repo.rows_to_dicts(
                c.execute("SELECT path FROM pcap_files WHERE protected=1")))]
        except Exception:  # pragma: no cover - darf den Start nie verhindern
            log.exception("Geschützte PCAP-Pfade nicht lesbar")
            return []

    def pcap_usage(self) -> dict:
        """Tatsächlicher Platzverbrauch des pcap-Verzeichnisses – gemessen, nicht gerechnet."""
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
        """Alte und herrenlose Mitschnitte entfernen.

        Drei Fälle, von denen früher nur der erste abgedeckt war:
        1. Geschützte Dateien, die ihre Aufbewahrungszeit überschritten haben.
        2. Datenbankzeilen ohne Datei (nach einem Absturz oder manuellem Löschen).
        3. **Dateien ohne Datenbankzeile** – die blieben bisher für immer liegen.
           Genau so sammelten sich nach jedem Neustart des Capture-Prozesses
           weitere 250 MB an, die niemand mehr löschte.
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
            # Deep Capture ist aus: Die ungeschützten Dateien sind der Rest eines
            # Ringpuffers, den es nicht mehr gibt – sie wandern sonst nie weg, weil
            # niemand mehr rotiert. Incident-Mitschnitte bleiben bis protected_days.
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
            log.info("Deep Capture aus: %d laufende Mitschnitte entfernt (%.0f MB)", len(rows), freed / 1e6)

    async def _reconcile_pcaps(self) -> None:
        """Verzeichnis und Datenbank abgleichen; Verwaistes beidseitig entfernen."""
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
        # Herrenlose Dateien: nur löschen, wenn gerade kein Capture-Prozess läuft, der sie
        # noch in seinem Ring hält – sonst würde die aktuell beschriebene Datei verschwinden.
        # Läuft der Capture-Prozess, kennt sein Ring jede Datei (er übernimmt den
        # Bestand beim Start) – dann gibt es hier nichts zu tun. Ist Deep Capture aus
        # oder der Prozess gestoppt, bleiben Reste sonst für immer liegen.
        orphans = on_disk - known
        if orphans and (self.capture_proc is None or not self.cfg.deep_capture.enabled):
            freed = 0
            for p in orphans:
                try:
                    freed += os.path.getsize(p)
                    os.unlink(p)
                except OSError:
                    pass
            log.warning("%d herrenlose PCAP-Dateien entfernt (%.0f MB)", len(orphans), freed / 1e6)

    async def _system_loop(self) -> None:
        while True:
            await asyncio.sleep(1)
            self.loadguard.sample()
            lvl_before = self.loadguard.level
            lvl = self.loadguard.evaluate()
            if lvl != lvl_before:
                log.warning("Load Guard: Stufe %s → %s (%s)", lvl_before, lvl, self.loadguard.last)
                self.capture_command("level", lvl)

    # ================================================================== Einstellungen
    async def update_settings(self, patch: dict) -> dict:
        from .config import EDITABLE_SECTIONS, RESTART_SECTIONS, deep_merge
        bad = set(patch) - EDITABLE_SECTIONS
        if bad:
            raise ValueError(f"Nicht änderbar: {', '.join(sorted(bad))}")
        new_password = False
        if "fritzbox" in patch:
            if patch["fritzbox"].get("password") in ("********", None):
                patch["fritzbox"].pop("password", None)
            else:
                new_password = True
        overrides = await self.db.read(lambda c: repo.get_setting(c, "config_overrides", {}))
        merged = deep_merge(overrides, patch)
        new_cfg = build_config(self.yaml_data, merged)   # validiert (wirft bei Fehlern)
        # Das gespeicherte Passwort geht nur an die Adresse, für die es eingegeben wurde.
        # Sonst könnte jedes Gerät im LAN die Adresse auf einen eigenen Server umbiegen
        # und bekäme die Login-Antwort der FRITZ!Box zum Offline-Raten.
        if (self.cfg.fritzbox.password and not new_password
                and fritz_target(new_cfg) != fritz_target(self.cfg)):
            raise ValueError("Die FRITZ!Box-Adresse ändert sich – bitte das FRITZ!Box-Passwort "
                             "dabei neu eingeben.")
        await self.db.write(lambda c: repo.set_setting(c, "config_overrides", merged))
        old = self.cfg
        self.cfg = new_cfg
        # sofort wirksame Änderungen
        self.events.t = new_cfg.thresholds
        self.loadguard.cfg = new_cfg.load_guard
        self.gaming_detector = GamingDetector(new_cfg.gaming.min_pps, new_cfg.gaming.min_seconds,
                                              new_cfg.gaming.stop_after_idle)
        if self.scheduler:
            self.scheduler.interval = new_cfg.probe.interval
            self.scheduler.fast_interval = new_cfg.probe.gaming_interval
        if "targets" in patch or "gateway" in patch:
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
        for t in [t for t in self.tasks if t.get_name() == "fritz"]:
            t.cancel()
            self.tasks.remove(t)
        self.fritz = None
        self.fritz_status = {"enabled": False}
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
            "pihole": self.pihole_status,
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
        }


# ====================================================================== Hilfen
def _resolve_v4(host: str | None) -> str | None:
    """Host (IP, Name oder Name:Port) → IPv4-Adresse, sonst None."""
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
    """Rekonstruiert 1-s-Zeilen aus der Datenbank (für Analysen außerhalb des Ringpuffers).

    Gespeichert werden je Gerät nur die beiden Byte-Zähler; Pakete, UDP- und
    LAN-Anteil stehen nur live zur Verfügung und werden hier als 0 geführt.
    Keine Auswertung liest sie – wäre das anders, dürfte hier keine 0 stehen.
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
