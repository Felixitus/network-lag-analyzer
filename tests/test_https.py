"""Optional HTTPS: a certificate the Pi makes once, cookies that then only travel encrypted."""
import os

import pytest
from starlette.responses import Response

pytest.importorskip("cryptography")
from cryptography import x509  # noqa: E402

from backend.api import auth  # noqa: E402
from backend.util import tls_cert  # noqa: E402


def test_the_certificate_is_made_once_and_names_the_pi(tmp_path):
    d = str(tmp_path / "tls")
    cert, key, fp = tls_cert.ensure(d, ["192.0.2.55"])
    with open(cert, "rb") as fh:
        c = x509.load_pem_x509_certificate(fh.read())
    san = c.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "192.0.2.55" in {str(ip) for ip in san.get_values_for_type(x509.IPAddress)}
    assert "localhost" in san.get_values_for_type(x509.DNSName)
    # a new one at every start would bring the browser warning back each time
    assert tls_cert.ensure(d, ["192.0.2.99"])[2] == fp
    if os.name != "nt":
        assert os.stat(key).st_mode & 0o777 == 0o600


def test_with_https_the_session_cookie_is_secure_and_without_it_is_not():
    r = Response()
    auth._set_cookie(r, "tok", 1, secure=True)
    assert "secure" in r.headers["set-cookie"].lower()
    r = Response()
    auth._set_cookie(r, "tok", 1)
    assert "secure" not in r.headers["set-cookie"].lower()


def test_links_in_notifications_follow_the_scheme(monkeypatch):
    from backend.core import Core

    class C:
        pi_ip = "192.0.2.55"
    c = C()
    c.cfg = type("Cfg", (), {})()
    c.cfg.server = type("S", (), {"host": "auto", "port": 8088, "https": True})()
    assert Core.ui_url(c, "#/line") == "https://192.0.2.55:8088/#/line"
    c.cfg.server.https = False
    assert Core.ui_url(c) == "http://192.0.2.55:8088/"
