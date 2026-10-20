"""Inkrementeller Parser für libpcap- und pcapng-Datenströme (z. B. FRITZ!Box-Mitschnitt).

Der Parser puffert nur unvollständige Records; es werden keine Pakete kopiert,
die nicht verarbeitet werden. Unterstützt:
* pcap klassisch (Little/Big Endian, Mikro-/Nanosekunden)
* pcap "modified" (Magic 0xa1b2cd34) – von FRITZ!Box-Mitschnitten verwendet:
  identischer Dateikopf, aber 24 statt 16 Byte je Record-Header
  (zusätzlich ifindex, protocol, pkt_type, padding)
* pcapng (SHB, IDB, EPB, SPB)
"""
from __future__ import annotations

import struct
from typing import Callable

PacketCallback = Callable[[float, bytes, int, int], None]  # ts, data, orig_len, linktype

# Magic (Bytes im Datenstrom) → (Endianness, Zeitauflösung, Länge des Record-Headers)
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6, 16),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6, 16),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9, 16),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9, 16),
    b"\x34\xcd\xb2\xa1": ("<", 1e-6, 24),   # modified libpcap (u. a. FRITZ!Box)
    b"\xa1\xb2\xcd\x34": (">", 1e-6, 24),
}
PCAPNG_SHB = b"\x0a\x0d\x0d\x0a"

# Linktypes, die der Analyzer auswerten kann
LINKTYPE_ETHERNET = 1
LINKTYPE_NAMES = {0: "NULL", 1: "Ethernet", 101: "Raw IP", 113: "Linux cooked (SLL)", 276: "Linux cooked v2",
                  105: "IEEE 802.11", 51: "PPPoE", 9: "PPP", 12: "Raw IP"}


class PcapFormatError(Exception):
    pass


class PcapStreamParser:
    def __init__(self, on_packet: PacketCallback, max_caplen: int = 262144):
        self.on_packet = on_packet
        self.max_caplen = max_caplen
        self._buf = bytearray()
        self.format: str | None = None
        self.linktype: int | None = None
        self.global_header: bytes | None = None
        self._endian = "<"
        self._tsres = 1e-6
        self._rec_hdr = 16                              # 24 beim "modified"-Format
        self._ng_ifaces: list[tuple[int, float]] = []   # (linktype, tsres)
        self.packets = 0
        self.bytes_in = 0

    def feed(self, chunk: bytes) -> int:
        """Verarbeitet einen Datenblock, gibt die Anzahl erkannter Pakete zurück."""
        self.bytes_in += len(chunk)
        self._buf += chunk
        before = self.packets
        if self.format is None:
            if len(self._buf) < 4:
                return 0
            head = bytes(self._buf[:4])
            if head in PCAP_MAGICS:
                if len(self._buf) < 24:
                    return 0
                self._endian, self._tsres, self._rec_hdr = PCAP_MAGICS[head]
                self.linktype = struct.unpack_from(self._endian + "I", self._buf, 20)[0] & 0x0FFFFFFF
                self.global_header = bytes(self._buf[:24])
                self.format = "pcap" if self._rec_hdr == 16 else "pcap-modified"
                del self._buf[:24]
            elif head == PCAPNG_SHB:
                self.format = "pcapng"
            else:
                raise PcapFormatError(
                    f"Unbekanntes Mitschnitt-Format (Magic {head.hex()}). Unterstützt: pcap, "
                    "pcap-modified (a1b2cd34), pcapng")
        if self.format == "pcapng":
            self._parse_pcapng()
        else:
            self._parse_pcap()
        return self.packets - before

    # ------------------------------------------------------------------ pcap
    def _parse_pcap(self) -> None:
        buf = self._buf
        n = len(buf)
        pos = 0
        fmt = self._endian + "IIII"
        tsres = self._tsres
        lt = self.linktype or 1
        cb = self.on_packet
        unpack = struct.unpack_from
        hdr = self._rec_hdr          # 16 (klassisch) oder 24 ("modified": + ifindex/protocol/pkt_type/pad)
        mv = memoryview(buf)
        count = 0
        try:
            while n - pos >= hdr:
                sec, frac, incl, orig = unpack(fmt, buf, pos)
                if incl > self.max_caplen:
                    raise PcapFormatError(f"Ungültige Record-Länge {incl}")
                end = pos + hdr + incl
                if end > n:
                    break
                cb(sec + frac * tsres, bytes(mv[pos + hdr:end]), orig, lt)
                count += 1
                pos = end
        finally:
            mv.release()
        self.packets += count
        if pos:
            del buf[:pos]

    # ------------------------------------------------------------------ pcapng
    def _parse_pcapng(self) -> None:
        buf = self._buf
        pos = 0
        n = len(buf)
        while n - pos >= 12:
            btype = struct.unpack_from(self._endian + "I", buf, pos)[0]
            if bytes(buf[pos:pos + 4]) == PCAPNG_SHB:
                if n - pos < 12:
                    break
                bom = bytes(buf[pos + 8:pos + 12])
                self._endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
                self._ng_ifaces = []
            blen = struct.unpack_from(self._endian + "I", buf, pos + 4)[0]
            if blen < 12 or blen > self.max_caplen + 64:
                raise PcapFormatError(f"Ungültige pcapng-Blocklänge {blen}")
            if n - pos < blen:
                break
            body = pos + 8
            if btype == 0x00000001:  # IDB
                lt = struct.unpack_from(self._endian + "H", buf, body)[0]
                tsres = self._idb_tsres(buf, body + 8, pos + blen - 4)
                self._ng_ifaces.append((lt, tsres))
                if self.linktype is None:
                    self.linktype = lt
            elif btype == 0x00000006:  # EPB
                iface, tsh, tsl, cap, orig = struct.unpack_from(self._endian + "IIIII", buf, body)
                lt, tsres = self._ng_ifaces[iface] if iface < len(self._ng_ifaces) else (1, 1e-6)
                ts = ((tsh << 32) | tsl) * tsres
                d0 = body + 20
                self.on_packet(ts, bytes(buf[d0:d0 + cap]), orig, lt)
                self.packets += 1
            elif btype == 0x00000003:  # SPB (ohne Zeitstempel)
                orig = struct.unpack_from(self._endian + "I", buf, body)[0]
                lt, _ = self._ng_ifaces[0] if self._ng_ifaces else (1, 1e-6)
                cap = min(orig, blen - 16)
                import time as _t
                self.on_packet(_t.time(), bytes(buf[body + 4:body + 4 + cap]), orig, lt)
                self.packets += 1
            pos += blen
        if pos:
            del buf[:pos]

    def _idb_tsres(self, buf: bytearray, opt: int, end: int) -> float:
        while opt + 4 <= end:
            code, olen = struct.unpack_from(self._endian + "HH", buf, opt)
            if code == 0:
                break
            if code == 9 and olen >= 1:  # if_tsresol
                v = buf[opt + 4]
                return 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
            opt += 4 + ((olen + 3) & ~3)
        return 1e-6


def pcap_global_header(linktype: int, snaplen: int = 65535) -> bytes:
    return struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype)


def pcap_record(ts: float, data: bytes, orig_len: int) -> bytes:
    sec = int(ts)
    usec = int((ts - sec) * 1e6)
    return struct.pack("<IIII", sec, usec, len(data), orig_len) + data
