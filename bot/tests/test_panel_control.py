from urllib.parse import parse_qs

import httpx
import pytest
import respx

from vpn_manager.panels.client import PanelConfig, VpnUiClient


@pytest.mark.asyncio
@respx.mock
async def test_core_and_vpn_outbound_panel_routes_and_payloads():
    async with httpx.AsyncClient(cookies={"vpn-ui": "session"}) as http:
        api = VpnUiClient(
            PanelConfig("test", "https://panel.example", "admin", "secret", "vpn"), http
        )
        api._authenticated = True
        status = respx.get("https://panel.example/vpn/panel/core/status").mock(
            return_value=httpx.Response(200, json={"success": True, "obj": {"provisioned": True}})
        )
        catalog = respx.get("https://panel.example/vpn/panel/core/catalog").mock(
            return_value=httpx.Response(
                200,
                json={"success": True, "obj": {"cores": [{"name": "l2tp", "installed": False}]}},
            )
        )
        provision = respx.post("https://panel.example/vpn/panel/core/provision").mock(
            return_value=httpx.Response(200, json={"success": True, "obj": {"running": True}})
        )
        provision_status = respx.get("https://panel.example/vpn/panel/core/provision-status").mock(
            return_value=httpx.Response(200, json={"success": True, "obj": {"done": True}})
        )
        outbound_list = respx.post("https://panel.example/vpn/panel/xray/vpnoutbound/list").mock(
            return_value=httpx.Response(200, json={"success": True, "obj": [{"tag": "gre-egress"}]})
        )
        outbound_kinds = respx.post("https://panel.example/vpn/panel/xray/vpnoutbound/kinds").mock(
            return_value=httpx.Response(
                200, json={"success": True, "obj": [{"kind": "vpn:gre", "available": True}]}
            )
        )
        outbound_status = respx.post(
            "https://panel.example/vpn/panel/xray/vpnoutbound/status"
        ).mock(return_value=httpx.Response(200, json={"success": True, "obj": {"running": True}}))
        outbound_save = respx.post("https://panel.example/vpn/panel/xray/vpnoutbound/save").mock(
            return_value=httpx.Response(200, json={"success": True, "obj": {"iface": "gre0"}})
        )
        outbound_delete = respx.post(
            "https://panel.example/vpn/panel/xray/vpnoutbound/delete"
        ).mock(return_value=httpx.Response(200, json={"success": True}))

        assert (await api.core_status())["provisioned"] is True
        assert (await api.core_catalog())[0]["name"] == "l2tp"
        assert (await api.provision_cores(["l2tp", "l2tp", "radius"]))["running"] is True
        assert (await api.provision_status())["done"] is True
        assert (await api.vpn_outbound_list())[0]["tag"] == "gre-egress"
        assert (await api.vpn_outbound_kinds())[0]["kind"] == "vpn:gre"
        assert (await api.vpn_outbound_status("gre-egress"))["running"] is True
        assert (
            await api.vpn_outbound_save(tag="gre-egress", kind="vpn:gre", settings={"peer": "x"})
        )["iface"] == "gre0"
        await api.vpn_outbound_delete("gre-egress")

        for route in (
            status,
            catalog,
            provision,
            provision_status,
            outbound_list,
            outbound_kinds,
            outbound_status,
            outbound_save,
            outbound_delete,
        ):
            assert route.called
            assert route.calls.last.request.headers["X-Requested-With"] == "XMLHttpRequest"
        provision_form = parse_qs(provision.calls.last.request.content.decode())
        assert provision_form["cores"] == ["l2tp,radius"]
        save_form = parse_qs(outbound_save.calls.last.request.content.decode())
        assert save_form["enable"] == ["true"]
        assert save_form["settings"] == ['{"peer":"x"}']


@pytest.mark.asyncio
@respx.mock
async def test_certificate_generation_and_portless_gre_inbound():
    async with httpx.AsyncClient(cookies={"vpn-ui": "session"}) as http:
        api = VpnUiClient(
            PanelConfig("test", "https://panel.example", "admin", "secret", "vpn"), http
        )
        api._authenticated = True
        cert = respx.post("https://panel.example/vpn/panel/api/inbounds/generate-ocserv-cert").mock(
            return_value=httpx.Response(
                200, json={"success": True, "obj": {"certificate": "cert", "key": "key"}}
            )
        )
        gre_add = respx.post("https://panel.example/vpn/panel/api/inbounds/add").mock(
            return_value=httpx.Response(200, json={"success": True, "obj": {"id": 5}})
        )
        generated = await api.generate_inbound_certificate("openconnect")
        await api.create_inbound(
            remark="gre-main", protocol="gre", port=None, settings={"clients": []}
        )
        assert cert.called
        assert generated["certificate"] == "cert"
        form = parse_qs(gre_add.calls.last.request.content.decode())
        assert "port" not in form
        assert form["enable"] == ["true"]
