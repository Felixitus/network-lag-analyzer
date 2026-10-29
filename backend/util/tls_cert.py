"""Self-signed certificate for the optional HTTPS of the web UI (`server.https: true`).

Made once, on the Pi itself, and kept in the data directory: a new one at every start would
bring the browser warning back each time. The key never leaves the Pi. Delete both files to
get a new certificate, e.g. after the Pi got a new name or address.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import logging
import os
import socket

log = logging.getLogger("nla.tls")

CERT, KEY = "cert.pem", "key.pem"
DAYS = 3650


def ensure(directory: str, ips: list[str]) -> tuple[str, str, str]:
    """→ (cert path, key path, SHA-256 fingerprint), creating the pair when there is none."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    os.makedirs(directory, mode=0o700, exist_ok=True)
    cert_path, key_path = os.path.join(directory, CERT), os.path.join(directory, KEY)
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        host = socket.gethostname() or "raspberrypi"
        names: list[x509.GeneralName] = [x509.DNSName(host), x509.DNSName(f"{host}.local"), x509.DNSName("localhost")]
        for ip in dict.fromkeys(ips + ["127.0.0.1"]):
            try:
                names.append(x509.IPAddress(ipaddress.ip_address(ip)))
            except ValueError:
                continue
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host),
                             x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Network Lag Analyzer")])
        now = dt.datetime.now(dt.timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=DAYS))
                .add_extension(x509.SubjectAlternativeName(names), critical=False)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .sign(key, hashes.SHA256()))
        # The key first and only readable by the service: written with 0600 from the start
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
        with open(cert_path, "wb") as fh:
            fh.write(cert.public_bytes(serialization.Encoding.PEM))
        log.info("Created a self-signed certificate for %s", ", ".join(str(n.value) for n in names))
    with open(cert_path, "rb") as fh:
        cert = x509.load_pem_x509_certificate(fh.read())
    fp = cert.fingerprint(hashes.SHA256()).hex(":").upper()
    return cert_path, key_path, fp
