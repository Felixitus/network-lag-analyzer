"""Device host names: stable source priority, newest Pi-hole row, refresh on demand."""
import os
import time

import pytest
from fastapi.testclient import TestClient

from backend.collectors.devices import DeviceRegistry
from backend.collectors.pihole import PiholeReader, read_dhcp_leases
from ftl_fake import MAC_A, MAC_B, T0, FakeFtl


def test_host_name_no_longer_flips_between_sources():
    reg = DeviceRegistry()
    reg.observe(MAC_A, ip="192.0.2.10", hostname="old-fritz-name", source="fritzbox")
    reg.observe(MAC_A, ip="192.0.2.10", hostname="laptop", source="pihole")
    reg.observe(MAC_A, ip="192.0.2.10", hostname="old-fritz-name", source="fritzbox")   # next FRITZ!Box poll
    assert reg.by_mac[MAC_A].hostname == "laptop"
    reg.observe(MAC_A, ip="192.0.2.10", hostname="laptop-new", source="dhcp")
    assert reg.by_mac[MAC_A].hostname == "laptop-new"


def test_forgetting_names_keeps_the_alias():
    reg = DeviceRegistry()
    reg.observe(MAC_A, ip="192.0.2.10", hostname="laptop", source="pihole")
    reg.rename(MAC_A, "Work laptop")
    reg.forget_names()
    d = reg.by_mac[MAC_A]
    assert (d.hostname, d.ip, d.custom_name) == (None, None, "Work laptop")
    assert d.display_name == "Work laptop"


def test_wrong_name_can_be_cleared_in_the_database(tmp_path):
    from backend.database.repository import Database
    db = Database(str(tmp_path / "x.sqlite3"))
    db.init_sync()
    reg = DeviceRegistry()
    reg.observe(MAC_A, ip="192.0.2.10", hostname="wrong", source="fritzbox")
    db.write_sync(lambda c: c.executemany(DeviceRegistry.UPSERT, reg.dirty_rows()))
    reg.forget_names()
    db.write_sync(lambda c: c.executemany(DeviceRegistry.UPSERT, reg.dirty_rows()))
    assert db.read_sync(lambda c: c.execute("SELECT hostname FROM devices").fetchone()[0]) is None
    db.close()


def test_pihole_hosts_use_the_newest_ip_and_name_of_a_device(tmp_path):
    ftl = FakeFtl(tmp_path / "ftl.db")
    ftl.device(MAC_A, ["192.0.2.5"], name="old-name", last_seen=T0 - 86400 * 20)
    nid = ftl.c.execute("SELECT id FROM network WHERE hwaddr=?", (MAC_A,)).fetchone()[0]
    ftl.c.execute("INSERT INTO network_addresses (network_id, ip, lastSeen, name) VALUES (?,?,?,?)",
                  (nid, "192.0.2.10", int(T0), "new-name"))
    ftl.c.execute("INSERT INTO network_addresses (network_id, ip, lastSeen, name) VALUES (?,?,?,?)",
                  (nid, "2001:db8::a", int(T0 + 10), None))
    ftl.device(MAC_B, ["192.0.2.11"])
    log = ftl.close()
    hosts = {h.mac: h for h in PiholeReader(log.db_path).hosts() if h.mac}
    assert (hosts[MAC_A].ip, hosts[MAC_A].name) == ("192.0.2.10", "new-name")   # not the IPv6, not the old row
    assert len(hosts) == 2


def test_dhcp_leases_are_read_and_odd_lines_skipped(tmp_path):
    p = tmp_path / "dhcp.leases"
    p.write_text(f"1792700000 {MAC_A.upper()} 192.0.2.10 laptop 01:02:00:00:00:00:0a\n"
                 f"1792700000 {MAC_B} 192.0.2.11 * *\n"
                 "duid 00:01:00:01:aa:bb\n"
                 "1792700000 1234 2001:db8::5 phone 00:01\n", encoding="utf-8")
    leases = read_dhcp_leases(str(p))
    assert [(h.mac, h.ip, h.name) for h in leases] == [(MAC_A, "192.0.2.10", "laptop"), (MAC_B, "192.0.2.11", None)]
    assert read_dhcp_leases(str(tmp_path / "missing")) == []


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    d = tmp_path_factory.mktemp("nla-names")
    os.environ["NLA_DEV_MODE"] = "1"
    os.environ["NLA_DATA_DIR"] = str(d)
    os.environ["NLA_CONFIG"] = str(d / "missing.yaml")
    from backend.api import create_app
    from backend.core import Core
    with TestClient(create_app(Core())) as c:
        c.get("/")
        time.sleep(0.5)
        yield c
    for k in ("NLA_DEV_MODE", "NLA_DATA_DIR", "NLA_CONFIG"):
        os.environ.pop(k, None)


def test_refresh_button_restores_current_names_and_keeps_aliases(client):
    hdr = {"X-CSRF-Token": client.cookies.get("nla_csrf")}
    core = client.app.state.core
    pc, laptop = "02:00:00:00:00:20", "02:00:00:00:00:33"
    core.devices.by_mac[pc].hostname = "stale-name"          # what drifted
    core.devices.by_mac[pc].ip = "192.0.2.250"
    assert client.patch(f"/api/devices/{laptop}", json={"custom_name": "Work laptop"}, headers=hdr).status_code == 200
    r = client.post("/api/devices/refresh-names", json={}, headers=hdr)
    assert r.status_code == 200
    res = r.json()
    ch = {c["mac"]: c for c in res["changed"]}
    assert ch[pc]["before"] == "stale-name" and ch[pc]["after"] == "Gaming-PC (Demo)"
    assert ch[pc]["ip_after"] == "192.0.2.20"
    assert core.devices.by_mac[laptop].custom_name == "Work laptop"
    assert "demo devices" in res["sources"]
    assert client.post("/api/devices/refresh-names", json={}).status_code == 403     # CSRF
