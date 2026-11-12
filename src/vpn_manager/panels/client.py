from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from .errors import (
    PanelAuthenticationError,
    PanelOperationError,
    PanelResponseError,
    PanelTransportError,
    PanelTwoFactorRequired,
)


@dataclass(frozen=True, slots=True)
class PanelConfig:
    name: str
    base_url: str
    username: str
    password: str = field(repr=False)
    base_path: str = ""
    verify_tls: bool = True
    timeout: float = 15.0

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        if parsed.scheme != "https" and self.verify_tls:
            raise ValueError("Panel URLs must use HTTPS when TLS verification is enabled")
        if not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Panel base_url must be absolute and contain no embedded credentials")
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")


class VpnUiClient:
    """Async adapter for the documented vpn-ui session-cookie API."""

    def __init__(self, config: PanelConfig, client: httpx.AsyncClient | None = None) -> None:
        self.config = config
        self._owns_client = client is None
        self._http = client or httpx.AsyncClient(
            timeout=httpx.Timeout(config.timeout), verify=config.verify_tls, follow_redirects=False
        )
        self._authenticated = False

    @property
    def root(self) -> str:
        prefix = self.config.base_path.strip("/")
        return (
            f"{self.config.base_url.rstrip('/')}/{prefix}"
            if prefix
            else self.config.base_url.rstrip("/")
        )

    @property
    def api_root(self) -> str:
        return f"{self.root}/panel/api"

    async def close(self) -> None:
        if self._owns_client:
            await self._http.aclose()

    async def login(self, two_factor_code: str | None = None) -> None:
        self._http.cookies.delete("vpn-ui")
        self._authenticated = False
        form = {"username": self.config.username, "password": self.config.password}
        if two_factor_code:
            form["twoFactorCode"] = two_factor_code
        try:
            response = await self._http.post(f"{self.root}/login", data=form)
        except httpx.HTTPError as exc:
            raise PanelTransportError("Could not reach VPN panel during login") from exc
        if response.status_code in (401, 403):
            raise PanelAuthenticationError("Panel rejected credentials or 2FA code")
        if response.is_error:
            raise PanelResponseError(f"Panel login returned HTTP {response.status_code}")
        if "application/json" in response.headers.get("content-type", ""):
            try:
                payload = response.json()
            except ValueError as exc:
                raise PanelResponseError("Panel login returned malformed JSON") from exc
            if isinstance(payload, dict) and payload.get("success") is False:
                obj = payload.get("obj") if isinstance(payload.get("obj"), dict) else {}
                if obj.get("twoFactorRequired"):
                    raise PanelTwoFactorRequired("Panel requires a two-factor authentication code")
                message = payload.get("msg") or payload.get("message") or "Panel login failed"
                raise PanelAuthenticationError(str(message)[:300])
        if "vpn-ui" not in self._http.cookies:
            raise PanelAuthenticationError("Login did not establish vpn-ui session cookie")
        self._authenticated = True

    async def logout(self) -> None:
        if self._authenticated:
            try:
                await self._http.get(f"{self.root}/logout")
            except httpx.HTTPError:
                pass
        self._http.cookies.delete("vpn-ui")
        self._authenticated = False

    async def _request(
        self,
        method: str,
        path: str,
        *,
        form: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        raw: bool = False,
    ) -> Any:
        if not self._authenticated or "vpn-ui" not in self._http.cookies:
            raise PanelAuthenticationError("Panel session is missing; login is required")
        try:
            response = await self._http.request(
                method,
                f"{self.api_root}/{path.lstrip('/')}",
                data=form,
                params=params,
                headers={"X-Requested-With": "XMLHttpRequest"},
            )
        except httpx.HTTPError as exc:
            raise PanelTransportError("VPN panel request failed") from exc
        # vpn-ui deliberately hides unauthenticated /panel/api routes behind an empty 404.
        # A route typo may also be 404, so only the documented empty-body shape invalidates the session.
        if response.status_code == 404 and not response.content:
            self._authenticated = False
            raise PanelAuthenticationError("Panel session expired; login is required again")
        if response.status_code in (401, 403):
            self._authenticated = False
            raise PanelAuthenticationError("Panel session expired or access was denied")
        if response.status_code >= 400:
            raise PanelResponseError(f"VPN panel returned HTTP {response.status_code}")
        if raw:
            return response
        if "application/json" not in response.headers.get("content-type", ""):
            raise PanelResponseError("Panel returned non-JSON content for a JSON API route")
        try:
            payload = response.json()
        except ValueError as exc:
            raise PanelResponseError("Panel returned malformed JSON") from exc
        if not isinstance(payload, dict):
            raise PanelResponseError("Panel returned unexpected JSON structure")
        if payload.get("success") is False:
            message = payload.get("msg") or payload.get("message") or "Panel operation failed"
            raise PanelOperationError(str(message)[:300])
        return payload

    async def health(self) -> dict[str, Any]:
        payload = await self._request("GET", "inbounds/list")
        if not isinstance(payload.get("obj"), list):
            raise PanelResponseError("inbounds/list returned no list")
        return {"reachable": True, "inbounds": len(payload["obj"])}

    async def list_inbounds(self) -> list[dict[str, Any]]:
        payload = await self._request("GET", "inbounds/list")
        if not isinstance(payload.get("obj"), list):
            raise PanelResponseError("inbounds/list returned no list")
        return payload["obj"]

    async def get_inbound(self, inbound_id: int) -> dict[str, Any]:
        payload = await self._request("GET", f"inbounds/get/{inbound_id}")
        if not isinstance(payload.get("obj"), dict):
            raise PanelResponseError("inbounds/get returned no object")
        return payload["obj"]

    async def add_client(self, inbound_id: int, client: dict[str, Any]) -> dict[str, Any]:
        if client.get("enable") is not True:
            raise ValueError("New vpn-ui clients must explicitly set enable=true")
        form = {
            "id": str(inbound_id),
            "settings": json.dumps({"clients": [client]}, separators=(",", ":")),
        }
        return await self._request("POST", "inbounds/addClient", form=form)

    async def update_client(
        self, inbound_id: int, client_identity: str, client: dict[str, Any]
    ) -> dict[str, Any]:
        form = {
            "id": str(inbound_id),
            "settings": json.dumps({"clients": [client]}, separators=(",", ":")),
        }
        identity = quote(client_identity, safe="")
        return await self._request("POST", f"inbounds/updateClient/{identity}", form=form)

    async def delete_client(self, inbound_id: int, client_identity: str) -> dict[str, Any]:
        identity = quote(client_identity, safe="")
        return await self._request("POST", f"inbounds/{inbound_id}/delClient/{identity}")

    async def client_traffic(self, email: str) -> dict[str, Any]:
        payload = await self._request("GET", f"inbounds/getClientTraffics/{quote(email, safe='')}")
        if not isinstance(payload.get("obj"), dict):
            raise PanelResponseError("Traffic endpoint returned no object")
        return payload["obj"]
