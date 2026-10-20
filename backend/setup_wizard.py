"""Setup-Wizard: prüft die tatsächliche Netzwerkarchitektur und zeigt ehrlich, was messbar ist.

Die Software darf keine Daten vortäuschen, die sie technisch nicht sehen kann.
Deshalb wird z. B. aktiv getestet, ob fremder Unicast-Traffic am Interface des Pi
ankommt (Port-Mirroring/Gateway), statt es anzunehmen.
"""
from __future__ import annotations

import asyncio
import socket
import struct
import time
from pathlib import Path

import httpx
import psutil

from .collectors.fritzbox import FritzClient, FritzError
from .collectors.pcapstream import LINKTYPE_ETHERNET, LINKTYPE_NAMES, PcapStreamParser
from .util import netinfo

ETH_P_ALL = 0x0003


def _check(name: str, ok: bool | None, detail: str, hint: str | None = None) -> dict:
    return {"name": name, "ok": ok, "detail": detail, "hint": hint}


async def target_rate_limit_check(core, probes: int = 12, spacing: float = 0.2) -> list[dict]:
    """Prüft je Ziel, ob es ICMP zuverlässig beantwortet – oder drosselt.

    Hintergrund: Öffentliche Resolver (1.1.1.1, 8.8.8.8, 9.9.9.9) sind Anycast und
    begrenzen ICMP. Gehen die Pings dicht hintereinander raus, verwirft die
    Gegenstelle einen Teil – was wie Paketverlust aussieht, aber keiner ist.
    Genau das erzeugte früher scheinbar konstante 33 % Verlust.

    Deshalb wird zweimal gemessen: einmal verteilt (so misst der Dienst wirklich)
    und einmal als Bündel. Verluste nur im Bündel = Drosselung, kein Netzproblem.
    """
    prober = getattr(core, "prober", None)
    if not prober or not prober.mode:
        return []
    out = []
    for tid, info in list(core.targets.items()):
        addr = info["address"]
        spread = await _ping_series(prober, tid, addr, probes, spacing)
        burst = await _ping_series(prober, tid, addr, probes, 0.005)
        s_loss = 100 * (probes - spread) / probes
        b_loss = 100 * (probes - burst) / probes
        detail = f"verteilt {100 - s_loss:.0f} % Antworten, als Bündel {100 - b_loss:.0f} %"
        if s_loss >= 30:
            out.append({"address": addr, "ok": False, "detail": detail,
                        "hint": "Das Ziel antwortet auch bei normalem Abstand kaum – "
                                "blockiert es ICMP? Dann als Ziel entfernen."})
        elif b_loss - s_loss >= 25:
            out.append({"address": addr, "ok": True, "detail": detail + " – drosselt ICMP",
                        "hint": "Kein Netzwerkproblem: Das Ziel begrenzt ICMP. Der Dienst verteilt "
                                "seine Pings über das Intervall, deshalb stört das hier nicht."})
        else:
            out.append({"address": addr, "ok": True, "detail": detail})
    return out


async def _ping_series(prober, target_id: int, addr: str, n: int, spacing: float) -> int:
    """Sendet n Pings und zählt die Antworten. Nutzt den laufenden Prober-Socket."""
    got = 0

    def on_result(tid, _send_ts, rtt):
        nonlocal got
        if tid == target_id and rtt is not None:
            got += 1

    prober.extra_callbacks.append(on_result)
    try:
        for _ in range(n):
            prober.send(target_id, addr)
            await asyncio.sleep(spacing)
        await asyncio.sleep(1.5)          # Nachzügler abwarten
    finally:
        prober.extra_callbacks.remove(on_result)
    return got


def sniff_foreign_unicast(iface: str, seconds: float = 2.0) -> dict:
    """Lauscht kurz am Interface: Kommen Unicast-Frames an, die nicht für den Pi bestimmt sind?

    Ja → Port-Mirroring aktiv oder Pi im Datenpfad. Nein → Pi sieht nur eigenen Traffic.
    """
    out = {"ok": False, "promisc": False, "packets": 0, "foreign": 0, "error": None}
    try:
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    except OSError as e:
        out["error"] = f"Raw-Socket nicht möglich ({e.strerror}) – CAP_NET_RAW fehlt"
        return out
    try:
        s.bind((iface, 0))
        try:
            idx = socket.if_nametoindex(iface)
            s.setsockopt(263, 1, struct.pack("iHH8s", idx, 1, 0, b""))
            out["promisc"] = True
        except OSError:
            out["promisc"] = False
        s.settimeout(0.2)
        end = time.time() + seconds
        while time.time() < end:
            try:
                data, addr = s.recvfrom(64)
            except socket.timeout:
                continue
            if addr[2] == socket.PACKET_OUTGOING:
                continue
            out["packets"] += 1
            # PACKET_OTHERHOST: Unicast-Frame an eine fremde MAC (nur bei Mirror/Hub/Bridge sichtbar)
            if addr[2] == socket.PACKET_OTHERHOST:
                out["foreign"] += 1
        out["ok"] = True
    except OSError as e:
        out["error"] = str(e)
    finally:
        s.close()
    return out


def fritz_capture_probe(host: str, user: str, pw: str, iface: str, snaplen: int, seconds: float = 3.0) -> dict:
    """Startet den FRITZ!Box-Mitschnitt für wenige Sekunden und prüft, ob Client-Traffic sichtbar ist."""
    res = {"ok": False, "packets": 0, "format": None, "linktype": None, "macs": 0, "error": None}
    fb = FritzClient(host, user, pw)
    macs: set[bytes] = set()

    def on_pkt(ts, data, orig, lt):
        res["packets"] += 1
        if len(data) >= 12:
            macs.add(data[6:12])
    parser = PcapStreamParser(on_pkt)
    try:
        url = fb.capture_url(iface, snaplen)
        with httpx.Client(timeout=httpx.Timeout(10, read=5)) as http:
            with http.stream("GET", url) as r:
                if r.status_code != 200:
                    res["error"] = f"HTTP {r.status_code}"
                    return res
                end = time.time() + seconds
                for chunk in r.iter_raw(65536):
                    parser.feed(chunk)
                    if time.time() > end:
                        break
        lt = parser.linktype
        res.update(ok=res["packets"] > 0 and lt == LINKTYPE_ETHERNET, format=parser.format, linktype=lt,
                   linktype_name=LINKTYPE_NAMES.get(lt, "unbekannt") if lt is not None else None, macs=len(macs))
        if res["packets"] == 0:
            res["error"] = "Keine Pakete empfangen (Interface-Name prüfen)"
        elif lt != LINKTYPE_ETHERNET:
            res["error"] = (f"Interface liefert Linktype {lt} ({res['linktype_name']}) statt Ethernet – "
                            "für Traffic pro Gerät das LAN-Interface wählen (meist '1-lan')")
    except (httpx.HTTPError, FritzError, Exception) as e:  # noqa: BLE001
        res["error"] = f"{type(e).__name__}: {e}"
    finally:
        fb.stop_capture(iface, snaplen)
        fb.logout()
        fb.close()
    return res


async def run_checks(core, deep: bool = True) -> dict:
    cfg = core.cfg
    checks: list[dict] = []
    route = netinfo.default_route()
    ifaces = netinfo.interface_addresses()
    primary = route.interface if route else None
    pi_ip = netinfo.primary_ipv4(primary)

    checks.append(_check("Interfaces", bool(ifaces), ", ".join(
        f"{n} ({', '.join(a['address'] for a in i['ipv4']) or 'keine IPv4'}{', up' if i['up'] else ', down'})"
        for n, i in ifaces.items() if n != "lo")))
    wifi = bool(primary and primary.startswith(("wlan", "wl")))
    checks.append(_check("IP-Adresse", pi_ip is not None, f"{pi_ip or 'keine'} über {primary or '?'}",
                         "Der Pi misst über WLAN – das erhöht Jitter/Latenz der Messung selbst. LAN-Kabel empfohlen."
                         if wifi else None))
    checks.append(_check("Default Gateway", route is not None, route.gateway if route else "keins gefunden"))
    is_gw = bool(route and pi_ip and route.gateway == pi_ip)
    fwd = netinfo.ip_forwarding()
    checks.append(_check("Raspberry Pi ist Gateway", is_gw or bool(fwd),
                         "Ja" if is_gw else f"Nein – Router ist {route.gateway if route else '?'}"))
    checks.append(_check("IP Forwarding aktiv", fwd, "aktiv" if fwd else "inaktiv"))

    # Pi-hole
    ph_dir = Path("/etc/pihole")
    ftl_running = any((p.info.get("name") or "").startswith("pihole-FTL") for p in psutil.process_iter(["name"]))
    ph_ok, ph_msg = (core.pihole.check() if core.pihole else (False, "Pi-hole-Integration deaktiviert"))
    checks.append(_check("Pi-hole vorhanden", ph_dir.exists() or ftl_running,
                         f"{'FTL läuft' if ftl_running else 'FTL-Prozess nicht gefunden'}; {ph_msg}",
                         None if ph_ok else "Service-Benutzer in Gruppe 'pihole' aufnehmen (install.sh erledigt das)."))

    # ICMP
    icmp_ok = bool(core.prober and core.prober.mode)
    pgr = netinfo.ping_group_range()
    checks.append(_check("ICMP-Messung", icmp_ok or bool(core.simulator),
                         f"Socket: {core.prober.mode if core.prober else 'simuliert'}; ping_group_range={pgr}",
                         core.prober.error if core.prober and core.prober.error else None))

    # Antworten die Ziele zuverlässig, oder drosseln sie ICMP?
    if deep and not core.simulator:
        rl = await target_rate_limit_check(core)
        for r in rl:
            checks.append(_check(f"Ziel {r['address']}", r["ok"], r["detail"], r.get("hint")))

    # Sichtbarkeit fremden Traffics am Pi
    sniff = {"ok": False, "error": "übersprungen"}
    if deep and primary and not core.simulator:
        sniff = await asyncio.to_thread(sniff_foreign_unicast, cfg.capture.local_interface
                                        if cfg.capture.local_interface in ifaces else primary)
    foreign = sniff.get("foreign", 0) > 0
    checks.append(_check("Fremder Client-Traffic am Pi sichtbar", foreign if sniff.get("ok") else None,
                         f"{sniff.get('packets', 0)} Pakete in 2 s, davon {sniff.get('foreign', 0)} fremde Unicast-Frames"
                         if sniff.get("ok") else f"nicht prüfbar: {sniff.get('error')}"))
    checks.append(_check("Promiscuous Mode verfügbar", sniff.get("promisc") if sniff.get("ok") else None,
                         "ja" if sniff.get("promisc") else "nein/unbekannt"))

    # Router-API
    fb_info = {"reachable": False}
    host = (route.gateway if route else None) if cfg.fritzbox.host == "auto" else cfg.fritzbox.host
    if host and not core.simulator:
        try:
            async with httpx.AsyncClient(timeout=4) as http:
                r = await http.get(f"http://{host}:{cfg.fritzbox.tr064_port}/tr64desc.xml")
                if r.status_code == 200:
                    import re
                    m = re.search(r"<modelName>([^<]+)</modelName>", r.text)
                    fb_info = {"reachable": True, "model": m.group(1) if m else "FRITZ!Box"}
        except httpx.HTTPError as e:
            fb_info = {"reachable": False, "error": str(e)}
    checks.append(_check("Router-API (FRITZ!Box TR-064)", fb_info.get("reachable"),
                         fb_info.get("model") or fb_info.get("error") or "nicht erreichbar",
                         None if fb_info.get("reachable") else
                         "FRITZ!Box: Heimnetz → Netzwerk → Netzwerkeinstellungen → 'Zugriff für Anwendungen zulassen'"))
    fb_login = None
    if cfg.fritzbox.enabled and cfg.fritzbox.password and host and not core.simulator:
        fb_login = await asyncio.to_thread(_fritz_login_test, host, cfg.fritzbox.username, cfg.fritzbox.password,
                                           cfg.fritzbox.tr064_port)
        checks.append(_check("FRITZ!Box-Login", fb_login["ok"], fb_login["detail"], fb_login.get("hint")))
    cap = core.capture_status
    cap_running = cap.get("state") == "running"
    per_device = cap_running or foreign or is_gw
    checks.append(_check("Port Mirroring notwendig", None if per_device else True,
                         "Nein – Traffic pro Gerät verfügbar" if per_device else
                         "Ja, oder FRITZ!Box-Mitschnitt aktivieren (empfohlen, keine Zusatzhardware)"))

    cd, cu, csrc = core.capacity_info()
    capabilities = [
        {"name": "Internet latency", "ok": icmp_ok or bool(core.simulator)},
        {"name": "Gateway latency", "ok": bool(core.gateway) and (icmp_ok or bool(core.simulator))},
        {"name": "Packet loss / jitter", "ok": icmp_ok or bool(core.simulator)},
        {"name": "DNS activity", "ok": bool(ph_ok)},
        {"name": "Pi-hole integration", "ok": bool(ph_ok)},
        {"name": "DNS health (Pi-hole + Upstream)", "ok": bool(core.dns) or bool(core.simulator)},
        {"name": "Traffic Raspberry Pi", "ok": True},
        {"name": "WAN total traffic (TR-064)", "ok": bool(core.fritz_status.get("ok")) or bool(core.simulator)},
        {"name": "Line capacity", "ok": cd is not None and cu is not None, "detail": csrc},
        {"name": "Traffic all LAN devices", "ok": per_device or bool(core.simulator),
         "detail": cap.get("source")},
        {"name": "TCP retransmissions", "ok": per_device or bool(core.simulator)},
        {"name": "Game flow analysis", "ok": per_device or bool(core.simulator)},
    ]
    hint = None
    if not per_device and not core.simulator:
        hint = ("Der Raspberry Pi befindet sich nicht im Datenpfad. Für vollständige Traffic-Analyse pro Gerät "
                "muss der Traffic über den Raspberry Pi laufen, der Router entsprechende Statistiken bereitstellen "
                "oder ein Managed Switch Port Mirroring zum Raspberry Pi verwenden. Empfehlung für FRITZ!Box: "
                "Zugangsdaten eintragen und den FRITZ!Box-Mitschnitt aktivieren.")
    return {"checks": checks, "capabilities": capabilities, "hint": hint, "pi_ip": pi_ip,
            "gateway": route.gateway if route else None, "interface": primary, "capture": cap,
            "fritzbox": fb_info | ({"login": fb_login} if fb_login else {}), "ts": time.time()}


def _fritz_login_test(host: str, user: str, pw: str, port: int) -> dict:
    fb = FritzClient(host, user, pw, port)
    try:
        fb.login(force=True)
        rights = fb.rights()
        admin = rights.get("BoxAdmin", 0) >= 2
        try:
            info = fb.device_info()
            tr = f"TR-064 ok ({info.get('NewModelName')}, FRITZ!OS {info.get('NewSoftwareVersion')})"
        except Exception as e:  # noqa: BLE001 – TR-064 ist optional, der Login zählt
            tr = (f"TR-064 nicht erreichbar ({type(e).__name__}) – nur für WAN-Gesamtrate/Linkrate nötig: "
                  "Heimnetz → Netzwerk → Netzwerkeinstellungen → 'Zugriff für Anwendungen zulassen'")
        # Der Login selbst ist das Kriterium; TR-064 und die Rechteabfrage sind Zusatzinformationen.
        return {"ok": True, "admin": admin, "detail": f"Login ok, Rechte: {rights or 'nicht abfragbar'}; {tr}",
                "hint": None if admin else ("Das Recht 'FRITZ!Box Einstellungen' konnte nicht bestätigt werden – "
                                            "falls der Mitschnitt fehlschlägt, dieses Recht für den Benutzer setzen.")}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "detail": f"{type(e).__name__}: {e}"}
    finally:
        fb.logout()
        fb.close()


async def test_fritz(core, host: str | None, user: str, pw: str, iface: str, snaplen: int) -> dict:
    route = netinfo.default_route()
    host = host if host and host != "auto" else (route.gateway if route else None)
    if not host:
        return {"ok": False, "error": "Kein Router gefunden"}
    login = await asyncio.to_thread(_fritz_login_test, host, user, pw, core.cfg.fritzbox.tr064_port)
    out = {"host": host, "login": login}
    if login["ok"]:
        cap = core.capture_status
        running = cap.get("state") == "running" and cap.get("source") == "fritzbox"
        if running:
            # Die FRITZ!Box erlaubt pro Interface nur EINEN Mitschnitt. Ein zweiter Test
            # würde keine Pakete bekommen und beim Beenden den laufenden Mitschnitt stoppen.
            out["capture"] = {
                "ok": True, "live": True, "packets": cap.get("packets"), "pps": cap.get("pps"),
                "format": cap.get("format"), "linktype": cap.get("linktype"),
                "linktype_name": LINKTYPE_NAMES.get(cap.get("linktype"), "unbekannt"),
                "macs": None, "error": None,
                "note": "Der Mitschnitt läuft bereits – Live-Werte des Dienstes statt eines zweiten Tests.",
            }
        else:
            out["capture"] = await asyncio.to_thread(fritz_capture_probe, host, user, pw, iface, snaplen)
            try:
                fb = FritzClient(host, user, pw)
                out["interfaces"] = await asyncio.to_thread(fb.discover_capture_interfaces)
                fb.close()
            except Exception:  # noqa: BLE001
                out["interfaces"] = []
    out["ok"] = bool(login["ok"] and out.get("capture", {}).get("ok"))
    return out
