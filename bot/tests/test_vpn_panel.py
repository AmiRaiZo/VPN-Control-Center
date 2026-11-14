import httpx
import pytest
import respx

from vpn_manager.panels.errors import (
    PanelAuthenticationError,
    PanelOperationError,
    PanelResponseError,
)
from vpn_manager.panels.vpn_panel import VpnPanelClient, VpnPanelConfig


def make_client(http: httpx.AsyncClient) -> VpnPanelClient:
    return VpnPanelClient(
        VpnPanelConfig("main", "https://panel.example", "root", "secret", "control"), http
    )


@pytest.mark.asyncio
@respx.mock
async def test_login_requires_licensed_superadmin_and_uses_bearer_token():
    login = respx.post("https://panel.example/control/api/auth/login").mock(
        return_value=httpx.Response(
            200,
            json={
                "access_token": "signed-token",
                "username": "root",
                "role": "superadmin",
                "internal_license_required": False,
            },
        )
    )
    users = respx.get("https://panel.example/control/api/users").mock(
        return_value=httpx.Response(200, json=[])
    )
    async with httpx.AsyncClient() as http:
        api = make_client(http)
        result = await api.login()
        assert result["role"] == "superadmin"
        assert login.calls.last.request.headers["accept"] == "application/json"
        assert await api.list_users() == []
        assert users.calls.last.request.headers["Authorization"] == "Bearer signed-token"


@pytest.mark.asyncio
@respx.mock
@pytest.mark.parametrize(
    "login_payload",
    [
        {"access_token": "token", "role": "admin", "internal_license_required": False},
        {"access_token": "token", "role": "superadmin", "internal_license_required": True},
    ],
)
async def test_login_rejects_non_superadmin_or_locked_license(login_payload):
    respx.post("https://panel.example/control/api/auth/login").mock(
        return_value=httpx.Response(200, json=login_payload)
    )
    async with httpx.AsyncClient() as http:
        api = make_client(http)
        with pytest.raises(PanelAuthenticationError):
            await api.login()
        with pytest.raises(PanelAuthenticationError, match="login is required"):
            await api.list_users()


@pytest.mark.asyncio
async def test_api_operations_require_superadmin_login():
    async with httpx.AsyncClient() as http:
        api = make_client(http)
        with pytest.raises(PanelAuthenticationError, match="superadmin login"):
            await api.get_user(3)


@pytest.mark.asyncio
@respx.mock
async def test_user_management_uses_verified_routes_and_json_payloads():
    async with httpx.AsyncClient() as http:
        api = make_client(http)
        api._token = "root-token"
        base = "https://panel.example/control/api/users"
        get_one = respx.get(f"{base}/12").mock(
            return_value=httpx.Response(200, json={"id": 12, "username": "alice"})
        )
        create = respx.post(base).mock(
            return_value=httpx.Response(200, json={"id": 13, "username": "bob"})
        )
        update = respx.put(f"{base}/12").mock(
            return_value=httpx.Response(200, json={"id": 12, "is_active": False})
        )
        delete = respx.delete(f"{base}/12").mock(
            return_value=httpx.Response(200, json={"ok": True})
        )
        reset = respx.post(f"{base}/12/reset-usage").mock(
            return_value=httpx.Response(200, json={"ok": True})
        )
        disconnect = respx.post(f"{base}/12/disconnect").mock(
            return_value=httpx.Response(200, json={"ok": True, "closed_sessions": 2})
        )
        user = {
            "username": "bob",
            "password": "secret2",
            "enable_l2tp": True,
            "quota_gb": 25,
            "max_devices": 2,
            "expire_mode": "after_first_connect",
            "expire_after_days": 30,
            "is_active": True,
        }
        assert (await api.get_user(12))["username"] == "alice"
        assert (await api.create_user(user))["id"] == 13
        assert (await api.update_user(12, {"is_active": False}))["is_active"] is False
        assert await api.delete_user(12) == {"ok": True}
        assert await api.reset_user_usage(12) == {"ok": True}
        assert (await api.disconnect_user(12))["closed_sessions"] == 2

        assert all(route.called for route in (get_one, create, update, delete, reset, disconnect))
        assert create.calls.last.request.headers["Authorization"] == "Bearer root-token"
        assert create.calls.last.request.read() == httpx.Request(
            "POST", base, json=user
        ).read()


@pytest.mark.asyncio
@respx.mock
async def test_protocol_overview_uses_verified_dashboard_route():
    async with httpx.AsyncClient() as http:
        api = make_client(http)
        api._token = "root-token"
        route = respx.get(
            "https://panel.example/control/api/dashboard/protocol-overview"
        ).mock(return_value=httpx.Response(200, json={"servers": [{"id": "local"}]}))
        assert (await api.protocol_overview())["servers"][0]["id"] == "local"
        assert route.called


@pytest.mark.asyncio
@respx.mock
async def test_protocol_overview_maps_only_verified_protocol_services():
    async with httpx.AsyncClient() as http:
        api = make_client(http)
        api._token = "root-token"
        respx.get("https://panel.example/control/api/dashboard/protocol-overview").mock(
            return_value=httpx.Response(
                200,
                json={
                    "servers": [
                        {
                            "id": "local",
                            "name": "Main",
                            "status": "online",
                            "protocols": [
                                {
                                    "key": "l2tp",
                                    "label": "L2TP",
                                    "installed": True,
                                    "state": "running",
                                    "inbounds": 1,
                                    "listen": "0.0.0.0",
                                },
                                {
                                    "key": "vless",
                                    "label": "VLESS",
                                    "installed": True,
                                    "state": "stopped",
                                    "inbounds": 2,
                                },
                            ],
                        }
                    ]
                },
            )
        )
        rows = await api.list_inbounds()
        assert [(row["id"], row["protocol"], row["enable"]) for row in rows] == [
            (1, "l2tp", True),
            (8, "vless", False),
        ]


@pytest.mark.asyncio
@respx.mock
async def test_virtual_protocol_service_lists_users_by_protocol_flag():
    async with httpx.AsyncClient() as http:
        api = make_client(http)
        api._token = "root-token"
        respx.get("https://panel.example/control/api/users").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "id": 42,
                        "username": "alice",
                        "enable_l2tp": True,
                        "is_active": True,
                        "quota_bytes": 1024,
                        "used_bytes": 12,
                        "max_devices": 2,
                        "sub_link": "https://panel.example/sub/abc12345",
                    },
                    {"id": 43, "username": "bob", "enable_l2tp": False, "is_active": True},
                ],
            )
        )
        inbound = await api.get_inbound(1)
        clients = inbound["settings"]["clients"]
        assert len(clients) == 1
        assert clients[0]["email"] == "alice"
        assert clients[0]["vpn_panel_user_id"] == 42
        assert clients[0]["sub_token"] == "abc12345"


@pytest.mark.asyncio
@respx.mock
async def test_add_client_maps_to_real_vpn_panel_user_create_and_preserves_delivery_link():
    async with httpx.AsyncClient() as http:
        api = make_client(http)
        api._token = "root-token"
        create = respx.post("https://panel.example/control/api/users").mock(
            return_value=httpx.Response(
                200,
                json={"id": 77, "username": "buyer-123", "sub_link": "https://panel.example/sub/token12345"},
            )
        )
        client = {
            "email": "buyer-123",
            "password": "vpn-secret",
            "enable": True,
            "totalGB": 2 * 1024**3,
            "limitIp": 3,
            "expiryTime": 1790000000000,
            "comment": "sale order",
        }
        await api.add_client(1, client)
        body = create.calls.last.request.content
        import json

        data = json.loads(body)
        assert data["username"] == "buyer-123"
        assert data["password"] == "vpn-secret"
        assert data["enable_l2tp"] is True and data["enable_vless"] is False
        assert data["quota_gb"] == 2
        assert data["max_devices"] == 3
        assert data["server_targets"] == ["all"]
        assert client["vpn_panel_user_id"] == 77
        assert client["sub_token"] == "token12345"


@pytest.mark.asyncio
@respx.mock
async def test_update_client_does_not_overwrite_password_when_api_does_not_return_it():
    async with httpx.AsyncClient() as http:
        api = make_client(http)
        api._token = "root-token"
        respx.get("https://panel.example/control/api/users/77").mock(
            return_value=httpx.Response(
                200,
                json={"id": 77, "username": "buyer-123", "is_active": True, "enable_l2tp": True},
            )
        )
        update = respx.put("https://panel.example/control/api/users/77").mock(
            return_value=httpx.Response(200, json={"id": 77, "username": "buyer-123"})
        )
        await api.update_client(
            1,
            "buyer-123",
            {"vpn_panel_user_id": 77, "enable": False, "totalGB": 1024**3, "limitIp": 4, "expiryTime": 0},
        )
        import json

        body = json.loads(update.calls.last.request.content)
        assert "is_active" not in body
        assert body["enable_l2tp"] is False
        assert body["quota_gb"] == 1
        assert body["expire_date"] is None
        assert "password" not in body


@pytest.mark.asyncio
@respx.mock
async def test_traffic_is_reported_as_total_not_fabricated_upload_download_split():
    async with httpx.AsyncClient() as http:
        api = make_client(http)
        api._token = "root-token"
        respx.get("https://panel.example/control/api/users").mock(
            return_value=httpx.Response(200, json=[{"id": 9, "username": "alice", "used_bytes": 1234}])
        )
        assert await api.client_traffic("alice") == {
            "up": 0,
            "down": 1234,
            "total_bytes": 1234,
            "total_only": True,
        }


@pytest.mark.asyncio
@respx.mock
async def test_delete_client_disables_only_selected_protocol_when_other_protocols_remain():
    async with httpx.AsyncClient() as http:
        api = make_client(http)
        api._token = "root-token"
        respx.get("https://panel.example/control/api/users").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {
                        "id": 77,
                        "username": "multi-proto",
                        "is_active": True,
                        "enable_l2tp": True,
                        "enable_vless": True,
                    }
                ],
            )
        )
        update = respx.put("https://panel.example/control/api/users/77").mock(
            return_value=httpx.Response(200, json={"id": 77, "username": "multi-proto"})
        )
        result = await api.delete_client(1, "multi-proto")
        import json

        body = json.loads(update.calls.last.request.content)
        assert body == {"enable_l2tp": False, "is_active": True}
        assert result["id"] == 77


@pytest.mark.asyncio
@respx.mock
async def test_find_user_finds_account_even_when_service_protocol_flag_is_disabled():
    async with httpx.AsyncClient() as http:
        api = make_client(http)
        api._token = "root-token"
        respx.get("https://panel.example/control/api/users").mock(
            return_value=httpx.Response(
                200,
                json=[{"id": 77, "username": "renew-me", "is_active": True, "enable_l2tp": False}],
            )
        )
        found = await api.find_user("RENEW-ME")
        assert found is not None
        assert found["id"] == 77


@pytest.mark.asyncio
@respx.mock
async def test_virtual_protocol_service_does_not_include_accounts_without_its_protocol_flag():
    async with httpx.AsyncClient() as http:
        api = make_client(http)
        api._token = "root-token"
        respx.get("https://panel.example/control/api/users").mock(
            return_value=httpx.Response(
                200,
                json=[
                    {"id": 1, "username": "l2tp-only", "enable_l2tp": True, "is_active": True},
                    {"id": 2, "username": "vless-only", "enable_l2tp": False, "enable_vless": True, "is_active": True},
                ],
            )
        )
        clients = (await api.get_inbound(1))["settings"]["clients"]
        assert [row["email"] for row in clients] == ["l2tp-only"]


@pytest.mark.asyncio
@respx.mock
async def test_vpn_panel_config_download_uses_verified_public_subscription_route():
    async with httpx.AsyncClient() as http:
        api = make_client(http)
        api._token = "root-token"
        respx.get("https://panel.example/control/api/users").mock(
            return_value=httpx.Response(
                200,
                json=[{"id": 9, "username": "alice", "sub_link": "https://panel.example/sub/token99999"}],
            )
        )
        config = respx.get("https://panel.example/control/api/sub/token99999/xray-sub").mock(
            return_value=httpx.Response(200, content=b"dmxlc3M6Ly8=", headers={"content-type": "text/plain"})
        )
        files = await api.render_client_configs(8, "vless", "alice")
        assert config.called
        assert files == [{"filename": "alice-subscription.txt", "content": b"dmxlc3M6Ly8="}]


@pytest.mark.asyncio
@respx.mock
async def test_update_preserves_after_first_connect_expiry_and_global_active_flag():
    async with httpx.AsyncClient() as http:
        api = make_client(http)
        api._token = "root-token"
        respx.get("https://panel.example/control/api/users/77").mock(
            return_value=httpx.Response(200, json={"id": 77, "username": "buyer", "is_active": False})
        )
        update = respx.put("https://panel.example/control/api/users/77").mock(
            return_value=httpx.Response(200, json={"id": 77, "username": "buyer"})
        )
        await api.update_client(
            1,
            "buyer",
            {
                "vpn_panel_user_id": 77,
                "enable": False,
                "is_active": False,
                "totalGB": 0,
                "limitIp": 0,
                "expire_mode": "after_first_connect",
                "expire_after_days": 30,
            },
        )
        import json

        body = json.loads(update.calls.last.request.content)
        assert body["expire_mode"] == "after_first_connect"
        assert body["expire_after_days"] == 30
        assert "expire_date" not in body
        assert body["is_active"] is False


@pytest.mark.asyncio
@respx.mock
async def test_vless_creation_keeps_backend_password_private_from_customer_payload():
    async with httpx.AsyncClient() as http:
        api = make_client(http)
        api._token = "root-token"
        create = respx.post("https://panel.example/control/api/users").mock(
            return_value=httpx.Response(
                200,
                json={"id": 78, "username": "buyer-vless", "sub_link": "https://panel.example/sub/vless12345"},
            )
        )
        client = {
            "email": "buyer-vless",
            "id": "d0b5e8b7-3c13-4cc8-bd61-a9e7e1e5b99a",
            "enable": True,
            "totalGB": 0,
            "limitIp": 0,
        }
        await api.add_client(8, client)
        import json

        body = json.loads(create.calls.last.request.content)
        assert body["enable_vless"] is True
        assert len(body["password"]) >= 4
        assert "password" not in client
        assert client["vpn_panel_password"] == body["password"]


@pytest.mark.asyncio
@respx.mock
async def test_unauthorized_api_response_invalidates_token():
    respx.get("https://panel.example/control/api/users").mock(
        return_value=httpx.Response(403, json={"detail": "forbidden"})
    )
    async with httpx.AsyncClient() as http:
        api = make_client(http)
        api._token = "expired"
        with pytest.raises(PanelAuthenticationError, match="forbidden"):
            await api.list_users()
        assert api._token is None


@pytest.mark.asyncio
@respx.mock
async def test_api_error_is_reported_without_hiding_server_detail():
    respx.get("https://panel.example/control/api/users/4").mock(
        return_value=httpx.Response(404, json={"detail": "کاربر پیدا نشد"})
    )
    async with httpx.AsyncClient() as http:
        api = make_client(http)
        api._token = "valid"
        with pytest.raises(PanelOperationError, match="کاربر پیدا نشد"):
            await api.get_user(4)


@pytest.mark.asyncio
@respx.mock
async def test_list_users_rejects_non_list_payload():
    respx.get("https://panel.example/control/api/users").mock(
        return_value=httpx.Response(200, json={"users": []})
    )
    async with httpx.AsyncClient() as http:
        api = make_client(http)
        api._token = "valid"
        with pytest.raises(PanelResponseError, match="user list"):
            await api.list_users()


def test_config_rejects_insecure_or_ambiguous_urls_and_hides_password():
    with pytest.raises(ValueError):
        VpnPanelConfig("bad", "http://panel.example", "root", "secret")
    with pytest.raises(ValueError):
        VpnPanelConfig("bad", "https://panel.example/path?token=x", "root", "secret")
    config = VpnPanelConfig("main", "https://panel.example", "root", "very-secret")
    assert "very-secret" not in repr(config)
