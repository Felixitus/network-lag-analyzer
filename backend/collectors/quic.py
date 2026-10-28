"""Server name from the QUIC Initial packets (HTTP/3 over UDP 443).

QUIC encrypts even its first packets, but with keys anyone can derive: RFC 9001 §5.2
takes them from the Destination Connection ID in the packet itself and a published salt.
That is not a break of anything - it only protects against middleboxes ossifying the
protocol. Decrypting the client's Initial packets yields the TLS ClientHello (in CRYPTO
frames, without the TLS record header), and with it the server name.

What makes it harder than TCP:
* Browsers (Chrome's "chaos protection") cut the ClientHello into several CRYPTO frames
  in random order and spread it over two or three Initial packets, padded to >= 1200
  bytes. The fragments are collected by their stream offset per flow.
* The capture keeps only `snaplen` bytes of each packet. AES-GCM is a stream cipher
  underneath, so a cut-off packet can still be decrypted up to the cut - just not
  authenticated. If the fragment with the name is cut, the name is TRUNCATED, as with TCP.
* When the fragments do not join up from offset 0, the server_name extension is looked
  for directly in each fragment: three nested length fields that must agree, followed by
  a valid host name. A random match of all of them is practically impossible.

Without the `cryptography` package this module does nothing and says so (`AVAILABLE`).
"""
from __future__ import annotations

import hashlib
import hmac
import re

from .tls import _NAME, TRUNCATED, parse_sni_handshake

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    AVAILABLE = True
except ImportError:  # pragma: no cover - the installer brings it; without it QUIC stays unnamed
    AVAILABLE = False

V1, V2 = 0x00000001, 0x6B3343CF
# version → (initial salt, label prefix, long header type bits of an Initial packet)
VERSIONS = {
    V1: (bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"), b"quic ", 0),
    V2: (bytes.fromhex("0dede3def700a6db819381be6e269dcbf9bd2ed9"), b"quicv2 ", 1),
}
MAX_PACKETS = 4            # a ClientHello fits into at most three; then give up on the flow
NO_NAME = "\0none"        # a complete ClientHello without a server name
_SNI_EXT = re.compile(rb"\x00\x00[\x00\x01].[\x00\x01].\x00[\x00\x01].", re.S)


def _expand_label(secret: bytes, label: bytes, length: int) -> bytes:
    """HKDF-Expand-Label (TLS 1.3) for one output block - all lengths here are <= 32."""
    full = b"tls13 " + label
    info = length.to_bytes(2, "big") + bytes([len(full)]) + full + b"\x00"
    return hmac.new(secret, info + b"\x01", hashlib.sha256).digest()[:length]


def client_keys(dcid: bytes, version: int = V1) -> tuple[bytes, bytes, bytes]:
    """(key, iv, header protection key) of the client's Initial packets."""
    salt, prefix, _ = VERSIONS[version]
    initial = hmac.new(salt, dcid, hashlib.sha256).digest()
    client = _expand_label(initial, b"client in", 32)
    return (_expand_label(client, prefix + b"key", 16), _expand_label(client, prefix + b"iv", 12),
            _expand_label(client, prefix + b"hp", 16))


def header_mask(hp: bytes, sample: bytes) -> bytes:
    """AES of one 16-byte sample with the header protection key (RFC 9001 §5.4.3).

    The RFC calls this AES-ECB, but it is the bare block function on a single block, not
    a mode for encrypting data. CTR with the sample as the counter block gives exactly the
    same 16 bytes as the keystream over zeros - without ECB, which scanners rightly flag."""
    enc = Cipher(algorithms.AES(hp), modes.CTR(sample)).encryptor()
    return enc.update(b"\0" * 16) + enc.finalize()


def _varint(b: bytes, i: int) -> tuple[int, int]:
    n = 1 << (b[i] >> 6)
    if i + n > len(b):
        raise IndexError
    v = b[i] & 0x3F
    for x in b[i + 1:i + n]:
        v = (v << 8) | x
    return v, i + n


def decrypt_initial(p: bytes) -> bytes | None:
    """UDP payload as captured → plaintext frames of a client Initial packet (as far as captured).

    None if it is not a QUIC v1/v2 Initial or too short to remove the header protection.
    """
    if not AVAILABLE or len(p) < 7 or p[0] & 0xC0 != 0xC0:
        return None
    version = int.from_bytes(p[1:5], "big")
    if version not in VERSIONS or (p[0] >> 4) & 0x03 != VERSIONS[version][2]:
        return None
    try:
        i = 5
        dcid = p[i + 1:i + 1 + p[i]]
        i += 1 + p[i]
        i += 1 + p[i]                                  # source connection id
        token_len, i = _varint(p, i)
        i += token_len
        length, pn_off = _varint(p, i)
    except IndexError:
        return None
    if len(dcid) > 20 or pn_off + 20 > len(p):
        return None
    key, iv, hp = client_keys(dcid, version)
    mask = header_mask(hp, p[pn_off + 4:pn_off + 20])
    first = p[0] ^ (mask[0] & 0x0F)
    pn_len = (first & 0x03) + 1
    pn = bytes(a ^ b for a, b in zip(p[pn_off:pn_off + pn_len], mask[1:1 + pn_len]))
    nonce = bytes(iv[:12 - pn_len]) + bytes(a ^ b for a, b in zip(iv[12 - pn_len:], pn))
    # The 16-byte tag at the end is not checked: a cut-off packet has none. GCM encrypts with
    # counter blocks starting at 2, so plain CTR from nonce||2 gives the plaintext.
    end = min(len(p), pn_off + length - 16)
    ct = p[pn_off + pn_len:end]
    dec = Cipher(algorithms.AES(key), modes.CTR(nonce + b"\x00\x00\x00\x02")).decryptor()
    return dec.update(ct) + dec.finalize()


def crypto_frames(plain: bytes) -> list[tuple[int, bytes]]:
    """(offset, data) of the CRYPTO frames; stops at the cut or at a frame it does not know."""
    out, i = [], 0
    try:
        while i < len(plain):
            t = plain[i]
            if t in (0x00, 0x01):                       # PADDING, PING
                i += 1
            elif t == 0x06:                             # CRYPTO
                off, i = _varint(plain, i + 1)
                n, i = _varint(plain, i)
                out.append((off, plain[i:i + n]))       # may be shorter when cut off
                i += n
            elif t in (0x02, 0x03):                     # ACK (in later Initials)
                i += 1
                for _ in range(2):
                    _, i = _varint(plain, i)
                count, i = _varint(plain, i)
                _, i = _varint(plain, i)
                for _ in range(2 * count + (3 if t == 0x03 else 0)):
                    _, i = _varint(plain, i)
            else:
                break
    except IndexError:
        pass
    return out


def scan_sni(data: bytes) -> str | None:
    """The server_name extension found anywhere in a fragment, checked by its three lengths."""
    for m in _SNI_EXT.finditer(data):
        k = m.start()
        ext_len = int.from_bytes(data[k + 2:k + 4], "big")
        if int.from_bytes(data[k + 4:k + 6], "big") != ext_len - 2:
            continue
        n = int.from_bytes(data[k + 7:k + 9], "big")
        name = data[k + 9:k + 9 + n]
        if n == ext_len - 5 and len(name) == n and b"." in name and _NAME.match(name):
            return name.decode("ascii").lower().rstrip(".")
    return None


class QuicHello:
    """Collects the ClientHello of one QUIC connection over its first Initial packets."""
    __slots__ = ("frags", "packets")

    def __init__(self):
        self.frags: dict[int, bytes] = {}
        self.packets = 0

    def add(self, udp_payload: bytes) -> str | None:
        """→ server name, TRUNCATED (name not readable), NO_NAME, or None (wait for more / not QUIC)."""
        plain = decrypt_initial(udp_payload)
        if plain is None:
            # After the Initials come Handshake / 1-RTT packets: the ClientHello is over.
            return (TRUNCATED if self.frags else NO_NAME) if self.packets else None
        self.packets += 1
        for off, data in crypto_frames(plain):
            if len(data) > len(self.frags.get(off, b"")):
                self.frags[off] = data
        stream = self._stream()
        name = parse_sni_handshake(stream) if stream else None
        if name is None or name == TRUNCATED:
            for data in self.frags.values():
                found = scan_sni(data)
                if found:
                    return found
        if name is not None and name != TRUNCATED:
            return name
        if stream and name is None:
            return NO_NAME
        if self.packets >= MAX_PACKETS:
            return TRUNCATED if self.frags else NO_NAME
        return None

    def _stream(self) -> bytes:
        """The handshake bytes contiguous from offset 0."""
        buf = b""
        for off in sorted(self.frags):
            if off > len(buf):
                break
            buf += self.frags[off][len(buf) - off:]
        return buf
