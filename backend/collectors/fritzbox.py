"""FRITZ!Box-Anbindung: Login (SID), TR-064 (WAN-Raten, Linkrate, Hostliste), Mitschnitt-URL.

Voraussetzungen auf der FRITZ!Box:
* Heimnetz → Netzwerk → Netzwerkeinstellungen → "Zugriff für Anwendungen zulassen" (TR-064)
* Ein FRITZ!Box-Benutzer mit dem Recht "FRITZ!Box Einstellungen" (für den Paketmitschnitt)

Es werden ausschließlich lesende Aktionen ausgeführt. Der Mitschnitt enthält wegen
`snaplen` nur Paket-Header.
"""
from __future__ import annotations

import hashlib
import logging
import re
import threading
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from urllib.parse import quote

import httpx

log = logging.getLogger(__name__)

SOAP_ENV = (
    '<?xml version="1.0" encoding="utf-8"?>'
    '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
    's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
    '<s:Body><u:{action} xmlns:u="{service}">{args}</u:{action}></s:Body></s:Envelope>'
)

SVC_WAN_COMMON = "urn:dslforum-org:service:WANCommonInterfaceConfig:1"
SVC_HOSTS = "urn:dslforum-org:service:Hosts:1"
SVC_DEVICEINFO = "urn:dslforum-org:service:DeviceInfo:1"
DEFAULT_CONTROL = {
    SVC_WAN_COMMON: "/upnp/control/wancommonifconfig1",
    SVC_HOSTS: "/upnp/control/hosts",
    SVC_DEVICEINFO: "/upnp/control/deviceinfo",
}
IFACE_RE = re.compile(r"^[A-Za-z0-9_\-\.]{1,32}$")


class FritzError(Exception):
    pass


def compute_login_response(challenge: str, password: str) -> str:
    """Antwort auf die Login-Challenge (PBKDF2 ab FRITZ!OS 7.24, sonst MD5)."""
    if challenge.startswith("2$"):
        _, it1, salt1, it2, salt2 = challenge.split("$")
        h1 = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), bytes.fromhex(salt1), int(it1))
        h2 = hashlib.pbkdf2_hmac("sha256", h1, bytes.fromhex(salt2), int(it2))
        return f"{salt2}${h2.hex()}"
    # Altes Verfahren: Nicht-Latin-1-Zeichen werden durch "." ersetzt
    pw = "".join(c if ord(c) < 256 else "." for c in password)
    md5 = hashlib.md5(f"{challenge}-{pw}".encode("utf-16le")).hexdigest()
    return f"{challenge}-{md5}"


def _xml_text(root: ET.Element, tag: str) -> str | None:
    el = root.find(f".//{tag}")
    return el.text if el is not None else None


def _strip_ns(root: ET.Element) -> ET.Element:
    for el in root.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return root


@dataclass
class HostEntry:
    ip: str | None
    mac: str | None
    name: str | None
    active: bool
    interface: str | None


class FritzClient:
    """Synchroner Client (wird im Hauptprozess über Threads, im Capture-Prozess direkt genutzt)."""

    def __init__(self, host: str, username: str, password: str, tr064_port: int = 49000, timeout: float = 8.0):
        # "fritz.box", "192.168.178.1" oder "host:port" – der Port gilt nur für die Weboberfläche
        self.web_port: int | None = None
        if host.count(":") == 1 and host.rsplit(":", 1)[1].isdigit():
            host, port = host.rsplit(":", 1)
            self.web_port = int(port)
        self.host = host
        self.username = username
        self.password = password
        self.tr064_port = tr064_port
        self.timeout = timeout
        self._sid: str | None = None
        self._sid_time = 0.0
        self._control: dict[str, str] | None = None
        self._lock = threading.Lock()
        self._http = httpx.Client(timeout=timeout)
        self.model: str | None = None
        self.firmware: str | None = None

    def close(self) -> None:
        self._http.close()

    # ----------------------------------------------------------------- SID
    @property
    def base(self) -> str:
        return f"http://{self.host}" + (f":{self.web_port}" if self.web_port else "")

    def login(self, force: bool = False) -> str:
        with self._lock:
            if self._sid and not force and time.time() - self._sid_time < 600:
                return self._sid
            r = self._http.get(f"{self.base}/login_sid.lua", params={"version": "2"})
            r.raise_for_status()
            root = ET.fromstring(r.text)
            block = int(_xml_text(root, "BlockTime") or 0)
            if block > 0:
                raise FritzError(f"FRITZ!Box-Login gesperrt für {block} s (zu viele Fehlversuche)")
            challenge = _xml_text(root, "Challenge") or ""
            user = self.username
            if not user:
                last = root.find(".//User[@last='1']")
                user = last.text if last is not None and last.text else ""
            resp = compute_login_response(challenge, self.password)
            r = self._http.post(f"{self.base}/login_sid.lua", params={"version": "2"},
                                data={"username": user, "response": resp})
            r.raise_for_status()
            root = ET.fromstring(r.text)
            sid = _xml_text(root, "SID") or "0" * 16
            if set(sid) == {"0"}:
                raise FritzError("FRITZ!Box-Login fehlgeschlagen (Benutzer/Passwort prüfen)")
            self._sid, self._sid_time = sid, time.time()
            return sid

    def rights(self) -> dict[str, int]:
        """Rechte der aktuellen Session (z. B. {'BoxAdmin': 2})."""
        sid = self.login()
        r = self._http.get(f"{self.base}/login_sid.lua", params={"version": "2", "sid": sid})
        root = ET.fromstring(r.text)
        out: dict[str, int] = {}
        rights = root.find(".//Rights")
        if rights is not None:
            names = [e.text for e in rights.findall("Name")]
            accs = [e.text for e in rights.findall("Access")]
            for n, a in zip(names, accs):
                if n:
                    out[n] = int(a or 0)
        return out

    def logout(self) -> None:
        if self._sid:
            try:
                self._http.get(f"{self.base}/login_sid.lua", params={"version": "2", "logout": "1", "sid": self._sid})
            except httpx.HTTPError:
                pass
            self._sid = None

    # ----------------------------------------------------------------- TR-064
    def _load_control_urls(self) -> dict[str, str]:
        if self._control is not None:
            return self._control
        ctrl = dict(DEFAULT_CONTROL)
        try:
            r = self._http.get(f"http://{self.host}:{self.tr064_port}/tr64desc.xml")
            if r.status_code == 200:
                root = _strip_ns(ET.fromstring(r.content))
                for svc in root.iter("service"):
                    st = _xml_text(svc, "serviceType")
                    cu = _xml_text(svc, "controlURL")
                    if st and cu:
                        ctrl[st] = cu
                self.model = _xml_text(root, "modelName") or self.model
        except (httpx.HTTPError, ET.ParseError) as e:
            log.debug("tr64desc.xml nicht lesbar: %s", e)
        self._control = ctrl
        return ctrl

    def soap(self, service: str, action: str, args: dict[str, str] | None = None) -> dict[str, str]:
        ctrl = self._load_control_urls()
        url = f"http://{self.host}:{self.tr064_port}{ctrl.get(service, DEFAULT_CONTROL.get(service, ''))}"
        arg_xml = "".join(f"<{k}>{_xml_escape(v)}</{k}>" for k, v in (args or {}).items())
        body = SOAP_ENV.format(action=action, service=service, args=arg_xml)
        r = self._http.post(
            url, content=body.encode("utf-8"),
            headers={"Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{service}#{action}"'},
            auth=httpx.DigestAuth(self.username or "", self.password),
        )
        if r.status_code == 401:
            raise FritzError("TR-064: Anmeldung abgelehnt (401)")
        if r.status_code >= 400:
            raise FritzError(f"TR-064 {action}: HTTP {r.status_code}")
        root = _strip_ns(ET.fromstring(r.content))
        resp = root.find(f".//{action}Response")
        if resp is None:
            raise FritzError(f"TR-064 {action}: unerwartete Antwort")
        return {child.tag: (child.text or "") for child in resp}

    def device_info(self) -> dict[str, str]:
        d = self.soap(SVC_DEVICEINFO, "GetInfo")
        self.model = d.get("NewModelName") or self.model
        self.firmware = d.get("NewSoftwareVersion")
        return d

    def wan_rates(self) -> tuple[float, float]:
        """(download_bps, upload_bps) – von der FRITZ!Box gemittelte Gesamtrate."""
        d = self.soap(SVC_WAN_COMMON, "GetAddonInfos")
        down = float(d.get("NewByteReceiveRate") or 0) * 8
        up = float(d.get("NewByteSendRate") or 0) * 8
        return down, up

    def link_capacity(self) -> tuple[float | None, float | None]:
        """(down_bps, up_bps) Synchronisations-/Linkrate der WAN-Leitung."""
        d = self.soap(SVC_WAN_COMMON, "GetCommonLinkProperties")
        down = float(d.get("NewLayer1DownstreamMaxBitRate") or 0) or None
        up = float(d.get("NewLayer1UpstreamMaxBitRate") or 0) or None
        return down, up

    def host_list(self) -> list[HostEntry]:
        d = self.soap(SVC_HOSTS, "X_AVM-DE_GetHostListPath")
        path = d.get("NewX_AVM-DE_HostListPath")
        if not path:
            raise FritzError("Hostliste nicht verfügbar")
        r = self._http.get(f"http://{self.host}:{self.tr064_port}{path}")
        r.raise_for_status()
        root = ET.fromstring(r.content)
        out = []
        for item in root.iter("Item"):
            out.append(HostEntry(
                ip=_xml_text(item, "IPAddress") or None,
                mac=(_xml_text(item, "MACAddress") or "").lower() or None,
                name=_xml_text(item, "HostName") or None,
                active=(_xml_text(item, "Active") == "1"),
                interface=_xml_text(item, "InterfaceType") or None,
            ))
        return out

    # ----------------------------------------------------------------- Mitschnitt
    def capture_url(self, iface: str, snaplen: int, action: str = "Start") -> str:
        if not IFACE_RE.match(iface):
            raise FritzError("Ungültiger Interface-Name")
        sid = self.login()
        return (f"{self.base}/cgi-bin/capture_notimeout?ifaceorminor={quote(iface)}"
                f"&snaplen={int(snaplen)}&capture={action}&sid={sid}")

    def stop_capture(self, iface: str, snaplen: int) -> None:
        try:
            self._http.get(self.capture_url(iface, snaplen, "Stop"), timeout=5)
        except (httpx.HTTPError, FritzError):
            pass

    def discover_capture_interfaces(self) -> list[str]:
        """Best effort: liest die Mitschnitt-Seite und sucht Interface-Kennungen."""
        found: list[str] = []
        sid = self.login()
        pages = [
            ("GET", f"{self.base}/capture.lua", {"sid": sid}),
            ("POST", f"{self.base}/data.lua", {"sid": sid, "page": "cap", "xhr": "1", "xhrId": "all"}),
        ]
        for method, url, params in pages:
            try:
                r = (self._http.get(url, params=params) if method == "GET" else self._http.post(url, data=params))
                if r.status_code != 200:
                    continue
                for m in re.finditer(r'(?:ifaceorminor=|"(?:minor|ifacename|iface|name)"\s*:\s*")([0-9]+-[A-Za-z0-9_]+)', r.text):
                    if m.group(1) not in found:
                        found.append(m.group(1))
            except httpx.HTTPError:
                continue
        return found


def _xml_escape(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;").replace("'", "&apos;"))
