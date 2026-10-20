"""Capture-Prozess: liest Pakete (FRITZ!Box-Stream oder AF_PACKET) und liefert Sekunden-Aggregate.

Läuft als eigener Prozess (multiprocessing), damit Paketparsing weder den GIL des
Hauptprozesses belegt (präzise ICMP-Zeitstempel) noch die Web-API ausbremst.

Nachrichten an den Hauptprozess (out_q):
    ("bin", sec, devices, glob)          Sekunden-Aggregat (auch leer = gemessen, 0)
    ("flows", [flow_tuple, ...])         abgeschlossene Flows
    ("active_flows", ts, [dict, ...])    aktuell aktivste Flows (alle 5 s)
    ("macip", {mac: ip})                 gelernte IPv4-Zuordnungen
    ("udp_candidates", ts, [dict, ...])  bidirektionale UDP-Flows (Game-Erkennung)
    ("status", {...})                    Zustand, Raten, Fehler
    ("pcap", {...})                      Deep-Capture-Datei angelegt/aktualisiert/gelöscht
Steuerung (ctrl_q):
    ("level", n) ("gaming_mac", mac) ("router_macs", [..]) ("deep", bool)
    ("protect", t0, t1, incident_id) ("stop",)
"""
from __future__ import annotations

import logging
import os
import queue
import socket
import struct
import time
from collections import deque
from pathlib import Path
from typing import Iterable

from .flows import PacketAnalyzer
from .pcapstream import LINKTYPE_ETHERNET, LINKTYPE_NAMES, PcapStreamParser, pcap_global_header, pcap_record

log = logging.getLogger("nla.capture")

ETH_P_ALL = 0x0003
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1


class PcapRing:
    """Ringpuffer aus pcap-Dateien (nur Header dank snaplen).

    Zwei Budgets, beide hart:

    * **Ring** – höchstens `max_files` laufende Dateien à `file_size`.
    * **Geschützte Dateien** – alles, was zu einem Incident gehört. Sie liegen
      außerhalb des Rings, damit sie nicht überschrieben werden, bekommen aber
      ein eigenes Budget aus `max_total`. Ist es voll, fällt die älteste
      geschützte Datei weg.

    Das Gesamtbudget ist der entscheidende Punkt: Ohne es wächst das Verzeichnis
    mit der Zahl der Incidents, nicht mit der Konfiguration – aus „5 × 50 MB"
    wurden so in der Praxis zweistellige Gigabyte.

    Beim Start wird das Verzeichnis eingelesen und alles Vorhandene übernommen.
    Sonst wären nach jedem Neustart des Capture-Prozesses die Dateien des
    vorherigen Laufs herrenlos: in keinem Ring, nirgends geschützt, und damit
    für immer auf der Platte.
    """

    def __init__(self, directory: str, max_files: int, file_size: int, emit,
                 max_total: int = 0, protected_paths: Iterable[str] = ()):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o750)
        self.max_files = max(1, max_files)
        self.file_size = file_size
        self.emit = emit
        # Budget nur für die geschützten Dateien: Gesamtgrenze minus dem, was der
        # laufende Ring im schlimmsten Fall belegt.
        ring_reserved = self.max_files * file_size
        self.max_total = max_total
        self.protected_budget = max(0, max_total - ring_reserved) if max_total else 0
        self.files: deque[dict] = deque()      # ungeschützt, älteste zuerst
        self.protected: list[dict] = []
        self.cur: dict | None = None
        self.fh = None
        self.linktype: int | None = None
        self.deleted_bytes = 0
        self._adopt(set(protected_paths or ()))

    # ----------------------------------------------------------------- Bestand
    def _adopt(self, protected_paths: set[str]) -> None:
        """Dateien aus einem früheren Lauf übernehmen, statt sie liegen zu lassen."""
        found = []
        for p in sorted(self.dir.glob("nla-*.pcap")):
            try:
                st = p.stat()
            except OSError:                                   # pragma: no cover
                continue
            found.append({"path": str(p), "ts_start": st.st_mtime, "ts_end": st.st_mtime,
                          "size": st.st_size, "protected": str(p) in protected_paths})
        found.sort(key=lambda f: f["ts_start"])
        for f in found:
            (self.protected if f["protected"] else self.files).append(f)
            # Jede übernommene Datei auch im Hauptprozess bekannt machen: Sonst bliebe
            # sie für die Datenbank unsichtbar und niemand wüsste, dass es sie gibt.
            self.emit(("pcap", {"op": "new", **f}))
        if found:
            log.info("PCAP-Verzeichnis übernommen: %d Dateien, %.0f MB (%d geschützt)",
                     len(found), sum(f["size"] for f in found) / 1e6, len(self.protected))
            self.emit(("pcap", {"op": "adopted", "files": len(found),
                                "bytes": sum(f["size"] for f in found)}))
        self._enforce_budget()

    def total_bytes(self) -> int:
        return sum(f["size"] for f in self.files) + sum(f["size"] for f in self.protected)

    def protected_bytes(self) -> int:
        return sum(f["size"] for f in self.protected)

    def stats(self) -> dict:
        return {"files": len(self.files), "protected": len(self.protected),
                "bytes": self.total_bytes(), "protected_bytes": self.protected_bytes(),
                "max_total": self.max_total, "protected_budget": self.protected_budget,
                "deleted_bytes": self.deleted_bytes}

    # ----------------------------------------------------------------- Schreiben
    def write(self, ts: float, data: bytes, orig_len: int, linktype: int) -> None:
        if self.fh is None or self.cur is None or self.cur["size"] >= self.file_size or linktype != self.linktype:
            self._rotate(ts, linktype)
        rec = pcap_record(ts, data, orig_len)
        self.fh.write(rec)
        self.cur["size"] += len(rec)
        self.cur["ts_end"] = ts

    def _rotate(self, ts: float, linktype: int) -> None:
        self._close_current()
        self.linktype = linktype
        name = time.strftime("nla-%Y%m%d-%H%M%S", time.localtime(ts)) + f"-{int(ts * 1000) % 1000:03d}.pcap"
        path = self.dir / name
        self.fh = open(path, "wb", buffering=1024 * 1024)
        os.chmod(path, 0o640)
        self.fh.write(pcap_global_header(linktype))
        self.cur = {"path": str(path), "ts_start": ts, "ts_end": ts, "size": 24, "protected": False}
        self.files.append(self.cur)
        self.emit(("pcap", {"op": "new", **self.cur}))
        self._enforce_budget()

    def _delete(self, f: dict) -> None:
        try:
            os.unlink(f["path"])
        except OSError:
            pass
        self.deleted_bytes += f["size"]
        self.emit(("pcap", {"op": "delete", "path": f["path"]}))

    def _enforce_budget(self) -> None:
        """Beide Grenzen durchsetzen. Die gerade beschriebene Datei bleibt immer."""
        while len(self.files) > self.max_files:
            old = self.files.popleft()
            if old is self.cur:                               # pragma: no cover - Ring zu klein
                self.files.appendleft(old)
                break
            self._delete(old)
        if not self.max_total:
            return
        # Geschützte Dateien: älteste zuerst opfern, bis das Budget wieder passt
        self.protected.sort(key=lambda f: f["ts_start"])
        while self.protected and self.protected_bytes() > self.protected_budget:
            self._delete(self.protected.pop(0))
        # Notnagel: Selbst ohne geschützte Dateien darf das Gesamtbudget nicht reißen
        while self.total_bytes() > self.max_total and len(self.files) > 1:
            old = self.files.popleft()
            if old is self.cur:                               # pragma: no cover
                self.files.appendleft(old)
                break
            self._delete(old)

    def _close_current(self) -> None:
        if self.fh is not None:
            self.fh.close()
            self.fh = None
            if self.cur:
                self.emit(("pcap", {"op": "update", **self.cur}))

    def flush(self) -> None:
        if self.fh is not None:
            self.fh.flush()
            if self.cur:
                self.emit(("pcap", {"op": "update", **self.cur}))

    def protect(self, t0: float, t1: float, incident_id: int | None) -> list[str]:
        paths = []
        self.flush()
        for f in list(self.files):
            if f["ts_start"] <= t1 and f["ts_end"] >= t0:
                f["protected"] = True
                paths.append(f["path"])
                if f is not self.cur:
                    self.files.remove(f)
                    self.protected.append(f)
        # Die laufende Datei wird sofort abgeschlossen und aus dem Ring genommen.
        # `cur` danach leeren: Sonst versucht ein zweiter protect()-Aufruf ohne Paket
        # dazwischen, dieselbe Datei erneut aus dem Ring zu entfernen – das warf einen
        # ValueError, der den Capture-Prozess beendete (der dann neu startete und
        # seine Dateien herrenlos zurückließ).
        if self.cur is not None and self.cur["protected"]:
            if self.cur in self.files:
                self.files.remove(self.cur)
                self.protected.append(self.cur)
            self._close_current()
            self.cur = None
        # Auch geschützte Dateien zählen bereits gegen ihr Budget
        self._enforce_budget()
        kept = [p for p in paths if os.path.exists(p)]
        self.emit(("pcap", {"op": "protect", "paths": kept, "incident_id": incident_id,
                            "stats": self.stats()}))
        return kept

    def close(self) -> None:
        self._close_current()


class CaptureWorker:
    def __init__(self, cfg: dict, out_q, ctrl_q):
        self.cfg = cfg
        self.out_q = out_q
        self.ctrl_q = ctrl_q
        c = cfg["capture"]
        self.analyzer = PacketAnalyzer(
            local_nets=cfg.get("local_networks") or [],
            router_macs=cfg.get("router_macs") or [],
            ignore_pair=tuple(cfg["ignore_pair"]) if cfg.get("ignore_pair") else None,
            gaming_mac=cfg.get("gaming_mac"),
            flow_idle_udp=c["flow_idle_udp"], flow_idle_tcp=c["flow_idle_tcp"],
            flow_min_bytes=c["flow_min_store_bytes"],
        )
        self.parser = PcapStreamParser(self._on_packet)
        self.running = True
        self.paused_until = 0.0
        self.ring: PcapRing | None = None
        self.deep_enabled = bool(cfg["deep_capture"]["enabled"])
        self._offsets: deque[tuple[float, float]] = deque()
        self._last_pkt_ts: float | None = None
        self._last_emit_sec: int | None = None
        self._last_tick = 0.0
        self._last_flows = 0.0
        self._last_cand = 0.0
        self._last_status = 0.0
        self._pkts_since = 0
        self._bytes_since = 0
        self._last_rate_t = time.time()
        self.state = "starting"
        self.error: str | None = None
        self.source = cfg["source"]
        self.lag = 0.0
        self.dropped = 0
        self.pps = 0.0
        self.stream_bps = 0.0
        self._last_data = time.time()

    # --------------------------------------------------------------- Ausgabe
    def emit(self, msg: tuple) -> None:
        try:
            self.out_q.put_nowait(msg)
            return
        except queue.Full:
            pass
        if msg[0] == "bin":
            # Sekunden-Bins sind die eigentlichen Messwerte: kurz warten statt verwerfen
            try:
                self.out_q.put(msg, timeout=0.5)
                return
            except queue.Full:
                pass
        self.dropped += 1   # Hauptprozess überlastet → Rest verwerfen, nie blockieren

    def _on_packet(self, ts: float, data: bytes, orig_len: int, linktype: int) -> None:
        self._last_pkt_ts = ts
        self._pkts_since += 1
        self.analyzer.process(ts, data, orig_len, linktype)
        if self.ring is not None:
            self.ring.write(ts + self.analyzer.clock_offset, data, orig_len, linktype)

    def _update_clock(self) -> None:
        """Offset zwischen Router-Uhr und Pi-Uhr: Minimum (Ankunft − Paketzeit) über 10 s."""
        if self._last_pkt_ts is None:
            return
        now = time.time()
        cand = now - self._last_pkt_ts
        self._offsets.append((now, cand))
        while self._offsets and now - self._offsets[0][0] > 10:
            self._offsets.popleft()
        off = min(c for _, c in self._offsets)
        self.analyzer.clock_offset = off
        self.lag = max(0.0, cand - off)

    def tick(self, force: bool = False) -> None:
        now = time.time()
        if not force and now - self._last_tick < 0.25:
            return
        self._last_tick = now
        self._update_clock()
        self._handle_ctrl()
        self._check_linktype()
        upto = int(now - 1.0)
        # Nur Sekunden ausgeben, die der Datenstrom tatsächlich abgedeckt hat
        if self._last_pkt_ts is not None:
            covered = int(self._last_pkt_ts + self.analyzer.clock_offset) - 1
            upto = min(upto, covered)
        stalled = now - self._last_data > 3
        if not stalled and upto > (self._last_emit_sec or 0):
            start = None if self._last_emit_sec is None else self._last_emit_sec + 1
            if start is not None and upto - start > 30:
                start = upto - 30
            for sec, b in self.analyzer.take_bins(upto, fill_from=start):
                self.emit(("bin", sec, b["dev"], b["g"]))
            self._last_emit_sec = upto
        if now - self._last_cand >= 1:
            self._last_cand = now
            cands = self.analyzer.udp_candidates()
            if cands:
                self.emit(("udp_candidates", now, cands))
        if now - self._last_flows >= 5:
            self._last_flows = now
            closed = self.analyzer.expire_flows(now)
            if closed:
                self.emit(("flows", closed))
            self.emit(("active_flows", now, self.analyzer.active_flows()))
            learned = self.analyzer.take_macip()
            if learned:
                self.emit(("macip", learned))
            if self.ring:
                self.ring.flush()
        if now - self._last_status >= 2:
            dt = now - self._last_rate_t
            self.pps = self._pkts_since / dt if dt > 0 else 0
            self.stream_bps = self._bytes_since * 8 / dt if dt > 0 else 0
            self._pkts_since = 0
            self._bytes_since = 0
            self._last_rate_t = now
            self._last_status = now
            self.emit_status()

    def _check_linktype(self) -> None:
        """Nur Ethernet lässt sich Geräten zuordnen – anderes Interface klar melden."""
        lt = self.parser.linktype
        if lt is None or lt == LINKTYPE_ETHERNET:
            return
        msg = (f"Interface liefert Linktype {lt} ({LINKTYPE_NAMES.get(lt, 'unbekannt')}) statt Ethernet – "
               "Traffic pro Gerät nicht möglich. Bitte das LAN-Interface wählen (meist '1-lan').")
        if self.error != msg:
            self.error = msg
            log.warning(msg)
            self.emit_status()

    def emit_status(self) -> None:
        router = [":".join(f"{x:02x}" for x in m) for m in self.analyzer.router_macs]
        try:
            import resource
            cpu = resource.getrusage(resource.RUSAGE_SELF)
            cpu_s = cpu.ru_utime + cpu.ru_stime
        except Exception:  # pragma: no cover
            cpu_s = None
        self.emit(("status", {
            "state": self.state, "source": self.source, "error": self.error, "pps": round(self.pps, 1),
            "stream_kbps": round(self.stream_bps / 1000, 1), "lag_s": round(self.lag, 2),
            "packets": self.analyzer.packets, "ignored": self.analyzer.ignored, "level": self.analyzer.level,
            "router_macs": router, "linktype": self.parser.linktype, "format": self.parser.format,
            "flows": len(self.analyzer.flows), "cpu_seconds": cpu_s, "deep_capture": self.ring is not None,
            "dropped": self.dropped,
            "ts": time.time(),
        }))

    def _handle_ctrl(self) -> None:
        while True:
            try:
                msg = self.ctrl_q.get_nowait()
            except queue.Empty:
                return
            kind = msg[0]
            if kind == "stop":
                self.running = False
            elif kind == "level":
                lvl = int(msg[1])
                if lvl >= 3:
                    self.paused_until = time.time() + 300
                    self.state = "paused"
                self.analyzer.level = min(lvl, 2)
            elif kind == "gaming_mac":
                self.analyzer.gaming_mac = msg[1]
            elif kind == "router_macs":
                if msg[1]:
                    self.analyzer.set_router_macs(msg[1])
            elif kind == "deep":
                self._set_deep(bool(msg[1]))
            elif kind == "protect" and self.ring:
                self.ring.protect(msg[1], msg[2], msg[3])

    def _set_deep(self, on: bool) -> None:
        self.deep_enabled = on
        if on and self.ring is None:
            dc = self.cfg["deep_capture"]
            self.ring = PcapRing(os.path.join(self.cfg["data_dir"], "pcap"), dc["max_files"],
                                 dc["file_size_mb"] * 1024 * 1024, self.emit,
                                 max_total=dc.get("max_total_mb", 0) * 1024 * 1024,
                                 protected_paths=self.cfg.get("protected_pcaps") or ())
        elif not on and self.ring is not None:
            self.ring.close()
            self.ring = None

    # --------------------------------------------------------------- Quellen
    def run(self) -> None:
        if self.deep_enabled:
            self._set_deep(True)
        backoff = 5.0
        while self.running:
            if time.time() < self.paused_until:
                self.state = "paused"
                self.tick(force=True)
                time.sleep(1)
                continue
            try:
                self.state = "connecting"
                self.error = None
                self.emit_status()
                if self.source == "fritzbox":
                    self._run_fritz()
                elif self.source == "local":
                    self._run_local()
                else:
                    self.state = "disabled"
                    self.emit_status()
                    return
                backoff = 5.0
            except Exception as e:  # noqa: BLE001 - jeder Fehler → Neuverbindung
                self.state = "error"
                self.error = f"{type(e).__name__}: {e}"
                log.warning("Capture-Fehler: %s", self.error)
                self.emit_status()
                t_end = time.time() + backoff
                while self.running and time.time() < t_end:
                    self._handle_ctrl()
                    time.sleep(0.5)
                backoff = min(backoff * 2, 120)
            # Parser für neuen Stream zurücksetzen (neuer pcap-Header)
            self.parser = PcapStreamParser(self._on_packet)
            self._last_pkt_ts = None
            self._offsets.clear()
        if self.ring:
            self.ring.close()

    def _run_fritz(self) -> None:
        import httpx
        from .fritzbox import FritzClient

        fb = self.cfg["fritzbox"]
        client = FritzClient(fb["host"], fb["username"], fb["password"], fb["tr064_port"])
        try:
            url = client.capture_url(fb["capture_interface"], fb["snaplen"])
            timeout = httpx.Timeout(connect=10, read=30, write=10, pool=10)
            with httpx.Client(timeout=timeout) as http:
                with http.stream("GET", url) as resp:
                    if resp.status_code != 200:
                        raise RuntimeError(f"FRITZ!Box-Mitschnitt: HTTP {resp.status_code} "
                                           "(Recht 'FRITZ!Box Einstellungen' und Interface prüfen)")
                    self.state = "running"
                    self.emit_status()
                    for chunk in resp.iter_raw(65536):
                        if not chunk:
                            continue
                        self._last_data = time.time()
                        self._bytes_since += len(chunk)
                        self.parser.feed(chunk)
                        self.tick()
                        if not self.running or time.time() < self.paused_until:
                            break
                    else:
                        raise RuntimeError("Mitschnitt-Stream von der FRITZ!Box beendet")
        finally:
            client.stop_capture(fb["capture_interface"], fb["snaplen"])
            client.logout()
            client.close()

    def _run_local(self) -> None:
        iface = self.cfg["capture"]["local_interface"]
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        try:
            s.bind((iface, 0))
            if self.cfg["capture"]["promiscuous"]:
                idx = socket.if_nametoindex(iface)
                mreq = struct.pack("iHH8s", idx, PACKET_MR_PROMISC, 0, b"")
                s.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, mreq)
            s.settimeout(0.5)
            self.state = "running"
            self.parser.linktype = 1
            self.emit_status()
            buf = bytearray(256)
            while self.running and time.time() >= self.paused_until:
                try:
                    n = s.recv_into(buf, 256, socket.MSG_TRUNC)
                except socket.timeout:
                    self.tick()
                    continue
                now = time.time()
                self._last_data = now
                self._bytes_since += min(n, 256)
                self._on_packet(now, bytes(buf[:min(n, 256)]), n, 1)
                self.tick()
        finally:
            s.close()


def run_capture_process(cfg: dict, out_q, ctrl_q) -> None:
    """Einstiegspunkt des Capture-Prozesses."""
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    try:
        os.nice(5)  # Pi-hole und ICMP-Messung haben Vorrang
    except OSError:
        pass
    import signal
    signal.signal(signal.SIGINT, signal.SIG_IGN)  # Beenden nur über ctrl_q / SIGTERM
    w = CaptureWorker(cfg, out_q, ctrl_q)
    signal.signal(signal.SIGTERM, lambda *_: setattr(w, "running", False))
    w.run()
