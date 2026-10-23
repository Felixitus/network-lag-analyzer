"""TR-064 against a FRITZ!Box that does not offer every action (FRITZ!OS 8 dropped GetAddonInfos)."""
import httpx
import pytest

from backend.collectors.fritzbox import FritzActionUnsupported, FritzClient, FritzError

FAULT_INVALID_ACTION = (
    '<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>'
    '<s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring><detail>'
    '<UPnPError xmlns="urn:dslforum-org:control-1-0"><errorCode>401</errorCode>'
    '<errorDescription>Invalid Action</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>')


def response(action, values):
    args = "".join(f"<{k}>{v}</{k}>" for k, v in values.items())
    return (f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>'
            f'<u:{action}Response xmlns:u="urn:x">{args}</u:{action}Response></s:Body></s:Envelope>')


def fake_box(addon_infos=True, utilization="1862,1689,3854"):
    calls = []

    def handler(request: httpx.Request):
        if request.url.path == "/tr64desc.xml":
            return httpx.Response(404)
        action = request.headers["SOAPAction"].strip('"').split("#")[1]
        calls.append(action)
        if action == "GetAddonInfos":
            if not addon_infos:
                return httpx.Response(500, content=FAULT_INVALID_ACTION)
            return httpx.Response(200, content=response(action, {"NewByteReceiveRate": "1000", "NewByteSendRate": "500"}))
        if action == "GetCommonLinkProperties":
            vals = {"NewLayer1DownstreamMaxBitRate": "55001000"}
            if utilization is not None:
                vals["NewX_AVM-DE_DownstreamCurrentUtilization"] = utilization
                vals["NewX_AVM-DE_UpstreamCurrentUtilization"] = "2314,2400"
            return httpx.Response(200, content=response(action, vals))
        return httpx.Response(500, content=FAULT_INVALID_ACTION)

    fb = FritzClient("192.0.2.1", "user", "secret")
    fb._http = httpx.Client(transport=httpx.MockTransport(handler))
    return fb, calls


def test_wan_rate_still_uses_getaddoninfos_where_the_box_has_it():
    fb, calls = fake_box()
    assert fb.wan_rates() == (8000.0, 4000.0)
    assert calls == ["GetAddonInfos"]


def test_fritzos_8_without_getaddoninfos_falls_back_to_the_link_utilization():
    fb, calls = fake_box(addon_infos=False)
    assert fb.wan_rates() == (1862 * 8.0, 2314 * 8.0)       # newest entry, bytes/s → bit/s
    assert fb.wan_rates() == (1862 * 8.0, 2314 * 8.0)
    assert calls.count("GetAddonInfos") == 1                  # not asked again every poll


def test_no_rate_at_all_is_an_error_not_zero():
    fb, _ = fake_box(addon_infos=False, utilization=None)
    with pytest.raises(FritzError, match="not available"):
        fb.wan_rates()


def test_soap_fault_names_the_upnp_error():
    fb, _ = fake_box()
    with pytest.raises(FritzActionUnsupported, match="UPnP error 401 Invalid Action"):
        fb.soap("urn:dslforum-org:service:WANCommonInterfaceConfig:1", "X_AVM-DE_GetOnlineMonitor")


class _BoxWithoutRates:
    def device_info(self):
        return {"NewModelName": "FRITZ!Box (test)", "NewSoftwareVersion": "8.02"}

    def link_capacity(self):
        return None, None

    def wan_rates(self):
        raise FritzActionUnsupported("TR-064 GetAddonInfos: HTTP 500 (UPnP error 401 Invalid Action)")

    def host_list(self):
        from backend.collectors.fritzbox import HostEntry
        return [HostEntry(ip="192.0.2.10", mac="02:00:00:00:00:0a", name="laptop", active=True, interface="802.11")]


def test_missing_wan_rate_does_not_block_the_host_list(tmp_path, monkeypatch):
    import asyncio
    monkeypatch.setenv("NLA_DEV_MODE", "1")
    monkeypatch.setenv("NLA_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("NLA_CONFIG", str(tmp_path / "missing.yaml"))
    from backend.core import Core
    core = Core()
    core.fritz = _BoxWithoutRates()
    core.fritz_status = {"enabled": True, "ok": None}

    async def one_round():
        try:
            await asyncio.wait_for(core._fritz_loop(), 0.5)
        except asyncio.TimeoutError:
            pass
    asyncio.run(one_round())
    assert core.fritz_hosts_at is not None and core.fritz_hosts[0].name == "laptop"
    assert core.fritz_status["ok"] is False and "GetAddonInfos" in core.fritz_status["error"]
