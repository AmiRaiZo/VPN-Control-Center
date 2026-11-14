from urllib.parse import parse_qs

import httpx
import pytest
import respx

from vpn_manager.panels.client import PanelConfig, VpnUiClient
from vpn_manager.panels.errors import (
    PanelAuthenticationError,
    PanelOperationError,
    PanelResponseError,
    PanelTwoFactorRequired,
)


def make_client(http: httpx.AsyncClient) -> VpnUiClient:
    return VpnUiClient(PanelConfig("test", "https://panel.example", "admin", "secret", "vpn"), http)


@pytest.mark.asyncio
@respx.mock
async def test_login_cookie_and_base_path():
    route = respx.post("https://panel.example/vpn/login").mock(
        return_value=httpx.Response(
            200, headers={"set-cookie": "vpn-ui=session; Path=/vpn"}, json={"success": True}
        )
    )
    async with httpx.AsyncClient() as http:
        api = make_client(http)
        await api.login()
        assert route.called and "vpn-ui" in http.cookies
        respx.get("https://panel.example/vpn/panel/api/inbounds/list").mock(
            return_value=httpx.Response(200, json={"success": True, "obj": []})
        )
        assert await api.health() == {"reachable": True, "inbounds": 0}


@pytest.mark.asyncio
@respx.mock
async def test_http_200_success_false_is_error():
    async with httpx.AsyncClient(cookies={"vpn-ui": "session"}) as http:
        api = make_client(http)
        api._authenticated = True
        respx.get("https://panel.example/vpn/panel/api/inbounds/list").mock(
            return_value=httpx.Response(200, json={"success": False, "msg": "denied"})
        )
        with pytest.raises(PanelOperationError, match="denied"):
            await api.list_inbounds()


@pytest.mark.asyncio
async def test_missing_session_is_rejected():
    async with httpx.AsyncClient() as http:
        with pytest.raises(PanelAuthenticationError):
            await make_client(http).list_inbounds()


@pytest.mark.asyncio
@respx.mock
async def test_non_json_is_rejected():
    async with httpx.AsyncClient(cookies={"vpn-ui": "session"}) as http:
        api = make_client(http)
        api._authenticated = True
        respx.get("https://panel.example/vpn/panel/api/inbounds/list").mock(
            return_value=httpx.Response(200, text="login", headers={"content-type": "text/html"})
        )
        with pytest.raises(PanelResponseError):
            await api.list_inbounds()


@pytest.mark.asyncio
@respx.mock
async def test_empty_404_invalidates_expired_panel_session():
    async with httpx.AsyncClient(cookies={"vpn-ui": "session"}) as http:
        api = make_client(http)
        api._authenticated = True
        respx.get("https://panel.example/vpn/panel/api/inbounds/list").mock(
            return_value=httpx.Response(404, content=b"")
        )
        with pytest.raises(PanelAuthenticationError, match="expired"):
            await api.list_inbounds()
        assert api._authenticated is False


def test_plain_http_rejected_by_default():
    with pytest.raises(ValueError):
        PanelConfig("bad", "http://panel.example", "admin", "secret")


def test_panel_config_repr_does_not_expose_password():
    config = PanelConfig("test", "https://panel.example", "admin", "very-secret")
    assert "very-secret" not in repr(config)


@pytest.mark.asyncio
@respx.mock
async def test_login_reports_two_factor_challenge_even_on_http_200():
    respx.post("https://panel.example/vpn/login").mock(
        return_value=httpx.Response(
            200, json={"success": False, "obj": {"twoFactorRequired": True}}
        )
    )
    async with httpx.AsyncClient() as http:
        with pytest.raises(PanelTwoFactorRequired):
            await make_client(http).login()


@pytest.mark.asyncio
@respx.mock
async def test_failed_relogin_cannot_reuse_stale_cookie():
    respx.post("https://panel.example/vpn/login").mock(
        return_value=httpx.Response(200, text="login page", headers={"content-type": "text/html"})
    )
    async with httpx.AsyncClient(cookies={"vpn-ui": "old-session"}) as http:
        api = make_client(http)
        api._authenticated = True
        with pytest.raises(PanelAuthenticationError, match="session cookie"):
            await api.login()
        assert "vpn-ui" not in http.cookies
        assert api._authenticated is False


@pytest.mark.asyncio
@respx.mock
async def test_add_client_posts_form_json_and_requires_explicit_enable():
    async with httpx.AsyncClient(cookies={"vpn-ui": "session"}) as http:
        api = make_client(http)
        api._authenticated = True
        route = respx.post("https://panel.example/vpn/panel/api/inbounds/addClient").mock(
            return_value=httpx.Response(200, json={"success": True, "obj": "ok"})
        )
        with pytest.raises(ValueError):
            await api.add_client(3, {"email": "a"})
        await api.add_client(3, {"email": "a", "enable": True})
        assert route.called
        assert route.calls.last.request.headers["content-type"].startswith(
            "application/x-www-form-urlencoded"
        )


@pytest.mark.asyncio
@respx.mock
async def test_client_identity_is_url_encoded_as_one_path_segment():
    async with httpx.AsyncClient(cookies={"vpn-ui": "session"}) as http:
        api = make_client(http)
        api._authenticated = True
        route = respx.post(
            "https://panel.example/vpn/panel/api/inbounds/3/delClient/a%2Fb%20c"
        ).mock(return_value=httpx.Response(200, json={"success": True}))
        await api.delete_client(3, "a/b c")
        assert route.called


@pytest.mark.asyncio
@respx.mock
async def test_add_client_sends_repeated_membership_ids():
    async with httpx.AsyncClient(cookies={"vpn-ui": "session"}) as http:
        api = make_client(http)
        api._authenticated = True
        route = respx.post("https://panel.example/vpn/panel/api/inbounds/addClient").mock(
            return_value=httpx.Response(200, json={"success": True, "obj": "ok"})
        )
        await api.add_client(
            3,
            {"email": "buyer@example.com", "enable": True},
            inbound_ids=[3, 7, 7],
        )
        form = parse_qs(route.calls.last.request.content.decode())
        assert form["inboundIds"] == ["3", "7"]
        assert form["id"] == ["3"]


@pytest.mark.asyncio
@respx.mock
async def test_inbound_crud_and_traffic_by_identity_use_documented_routes():
    async with httpx.AsyncClient(cookies={"vpn-ui": "session"}) as http:
        api = make_client(http)
        api._authenticated = True
        add = respx.post("https://panel.example/vpn/panel/api/inbounds/add").mock(
            return_value=httpx.Response(200, json={"success": True, "obj": {"id": 9}})
        )
        update = respx.post("https://panel.example/vpn/panel/api/inbounds/update/9").mock(
            return_value=httpx.Response(200, json={"success": True})
        )
        delete = respx.post("https://panel.example/vpn/panel/api/inbounds/del/9").mock(
            return_value=httpx.Response(200, json={"success": True})
        )
        traffic = respx.get(
            "https://panel.example/vpn/panel/api/inbounds/getClientTrafficsById/identity%2Fwith%20space"
        ).mock(return_value=httpx.Response(200, json={"success": True, "obj": {"up": 12}}))

        await api.create_inbound(
            remark="test", protocol="l2tp", port=1701, settings={"clients": []}
        )
        await api.update_inbound(9, remark="renamed", enable=False)
        await api.delete_inbound(9)
        result = await api.client_traffic_by_id("identity/with space")

        assert add.called and update.called and delete.called and traffic.called
        assert result == {"up": 12}
        form = parse_qs(update.calls.last.request.content.decode())
        assert form["enable"] == ["false"]


@pytest.mark.asyncio
@respx.mock
async def test_protocol_config_rendering_uses_documented_get_routes():
    async with httpx.AsyncClient(cookies={"vpn-ui": "session"}) as http:
        api = make_client(http)
        api._authenticated = True
        wg = respx.get(
            "https://panel.example/vpn/panel/api/inbounds/7/wgc-configs",
            params={"email": "buyer@example.com"},
        ).mock(
            return_value=httpx.Response(
                200,
                json={
                    "success": True,
                    "obj": [{"deviceIndex": 0, "config": "[Interface]\\nPrivateKey=x"}],
                },
            )
        )
        ovpn = respx.get("https://panel.example/vpn/panel/api/inbounds/8/ovpn/tcp").mock(
            return_value=httpx.Response(
                200,
                content=b"client\\nremote vpn.example 443",
                headers={"content-type": "application/x-openvpn-profile"},
            )
        )

        wg_files = await api.render_client_configs(7, "wg-c", "buyer@example.com")
        ovpn_files = await api.render_client_configs(
            8, "openvpn", "buyer@example.com", transport="tcp"
        )

        assert wg.called and wg_files[0]["filename"].endswith("device-0.conf")
        assert wg_files[0]["content"].startswith(b"[Interface]")
        assert ovpn.called and ovpn_files[0]["filename"].endswith(".ovpn")
        assert ovpn_files[0]["content"].startswith(b"client")


@pytest.mark.asyncio
@respx.mock
async def test_protocol_config_rendering_rejects_unknown_openvpn_transport():
    async with httpx.AsyncClient(cookies={"vpn-ui": "session"}) as http:
        api = make_client(http)
        api._authenticated = True
        with pytest.raises(ValueError, match="tcp or udp"):
            await api.render_client_configs(8, "openvpn", "buyer", transport="sctp")
