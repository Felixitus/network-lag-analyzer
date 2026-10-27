"""Server name (SNI) from the first packet of a TLS connection.

The ClientHello names the server in plain text - the one thing about an HTTPS connection
that is measured rather than guessed from DNS. It only works if the capture keeps
enough of each packet: the name often sits 200-500 bytes into the payload (browsers
shuffle the extensions), so with the default snaplen of 128 bytes it is cut off. Then
`parse_sni` says "truncated", and the UI can tell the user to raise the snaplen.

QUIC (HTTP/3 over UDP 443) encrypts its ClientHello; it is not covered.
"""
from __future__ import annotations

import re

TRUNCATED = "\0truncated"
_NAME = re.compile(rb"^[A-Za-z0-9._-]{1,253}$")


def parse_sni(p: bytes) -> str | None:
    """`p` = TCP payload as captured. → server name, TRUNCATED, or None (not a ClientHello / no SNI)."""
    # TLS record: type 22 (handshake), version 3.x; handshake type 1 (ClientHello)
    if len(p) < 6 or p[0] != 0x16 or p[1] != 0x03 or p[5] != 0x01:
        return None
    i = 5 + 4 + 2 + 32                   # handshake header, client version, random
    try:
        if len(p) < i + 1:
            return TRUNCATED
        i += 1 + p[i]                    # session id
        if len(p) < i + 2:
            return TRUNCATED
        i += 2 + int.from_bytes(p[i:i + 2], "big")      # cipher suites
        if len(p) < i + 1:
            return TRUNCATED
        i += 1 + p[i]                    # compression methods
        if len(p) < i + 2:
            return TRUNCATED
        end = i + 2 + int.from_bytes(p[i:i + 2], "big")
        i += 2
        while i + 4 <= end:
            if i + 4 > len(p):
                return TRUNCATED
            etype = int.from_bytes(p[i:i + 2], "big")
            elen = int.from_bytes(p[i + 2:i + 4], "big")
            i += 4
            if etype == 0:               # server_name
                if i + elen > len(p):
                    return TRUNCATED
                j = i + 2                # skip list length
                while j + 3 <= i + elen:
                    ntype = p[j]
                    nlen = int.from_bytes(p[j + 1:j + 3], "big")
                    name = p[j + 3:j + 3 + nlen]
                    if ntype == 0 and len(name) == nlen and _NAME.match(name):
                        return name.decode("ascii").lower().rstrip(".")
                    j += 3 + nlen
                return None
            i += elen
        return TRUNCATED if end > len(p) else None
    except IndexError:
        return TRUNCATED
