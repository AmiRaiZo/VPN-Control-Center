import httpx
import pytest
import respx

from vpn_manager.panels import PanelConfig, PanelRegistry


@pytest.mark.asyncio
@respx.mock
async def test_panels_keep_independent_cookie_jars_and_health_is_isolated():
    respx.post("https://one.example/login").mock(
        return_value=httpx.Response(
            200, headers={"set-cookie": "vpn-ui=one; Path=/"}, json={"success": True}
        )
    )
    respx.post("https://two.example/login").mock(
        return_value=httpx.Response(
            200, headers={"set-cookie": "vpn-ui=two; Path=/"}, json={"success": True}
        )
    )
    respx.get("https://one.example/panel/api/inbounds/list").mock(
        return_value=httpx.Response(200, json={"success": True, "obj": []})
    )
    respx.get("https://two.example/panel/api/inbounds/list").mock(
        return_value=httpx.Response(503, json={"error": "unavailable"})
    )
    registry = PanelRegistry()
    one = await registry.add(
        "one", PanelConfig("one", "https://one.example", "admin", "secret-one")
    )
    two = await registry.add(
        "two", PanelConfig("two", "https://two.example", "admin", "secret-two")
    )
    await one.login()
    await two.login()
    assert one._http.cookies.get("vpn-ui") == "one"
    assert two._http.cookies.get("vpn-ui") == "two"
    assert await registry.health_all() == {
        "one": {"reachable": True, "inbounds": 0},
        "two": {"reachable": False, "error": "PanelResponseError"},
    }
    await registry.close()

