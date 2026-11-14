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

    async def _panel_request(
        self, method: str, path: str, *, form: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        if not self._authenticated or "vpn-ui" not in self._http.cookies:
            raise PanelAuthenticationError("Panel session is missing; login is required")
        try:
            response = await self._http.request(
                method,
                f"{self.root}/{path.lstrip('/')}",
                data=form,
                headers={"X-Requested-With": "XMLHttpRequest"},
            )
        except httpx.HTTPError as exc:
            raise PanelTransportError("VPN panel control request failed") from exc
        if response.status_code in (401, 403) or (
            response.status_code == 404 and not response.content
        ):
            self._authenticated = False
            raise PanelAuthenticationError("Panel session expired or access was denied")
        if response.status_code >= 400:
            raise PanelResponseError(f"VPN panel control returned HTTP {response.status_code}")
        if "application/json" not in response.headers.get("content-type", ""):
            raise PanelResponseError("Panel control returned non-JSON content")
        try:
            payload = response.json()
        except ValueError as exc:
            raise PanelResponseError("Panel control returned malformed JSON") from exc
        if not isinstance(payload, dict):
            raise PanelResponseError("Panel control returned unexpected JSON structure")
        if payload.get("success") is False:
            message = (
                payload.get("msg") or payload.get("message") or "Panel control operation failed"
            )
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

    async def add_client(
        self,
        inbound_id: int,
        client: dict[str, Any],
        *,
        inbound_ids: list[int] | None = None,
    ) -> dict[str, Any]:
        if client.get("enable") is not True:
            raise ValueError("New vpn-ui clients must explicitly set enable=true")
        form = {
            "id": str(inbound_id),
            "settings": json.dumps({"clients": [client]}, separators=(",", ":")),
        }
        if inbound_ids is not None:
            if inbound_id not in inbound_ids or any(item <= 0 for item in inbound_ids):
                raise ValueError("inbound_ids must include the target inbound and positive IDs")
            form["inboundIds"] = [str(item) for item in dict.fromkeys(inbound_ids)]
        return await self._request("POST", "inbounds/addClient", form=form)

    async def update_client(
        self,
        inbound_id: int,
        client_identity: str,
        client: dict[str, Any],
        *,
        inbound_ids: list[int] | None = None,
    ) -> dict[str, Any]:
        form = {
            "id": str(inbound_id),
            "settings": json.dumps({"clients": [client]}, separators=(",", ":")),
        }
        if inbound_ids is not None:
            if inbound_id not in inbound_ids or any(item <= 0 for item in inbound_ids):
                raise ValueError("inbound_ids must include the target inbound and positive IDs")
            form["inboundIds"] = [str(item) for item in dict.fromkeys(inbound_ids)]
        identity = quote(client_identity, safe="")
        return await self._request("POST", f"inbounds/updateClient/{identity}", form=form)

    async def delete_client(self, inbound_id: int, client_identity: str) -> dict[str, Any]:
        identity = quote(client_identity, safe="")
        return await self._request("POST", f"inbounds/{inbound_id}/delClient/{identity}")

    async def delete_client_by_email(self, inbound_id: int, email: str) -> dict[str, Any]:
        identity = quote(email, safe="")
        return await self._request("POST", f"inbounds/{inbound_id}/delClientByEmail/{identity}")

    async def client_traffic(self, email: str) -> dict[str, Any]:
        payload = await self._request("GET", f"inbounds/getClientTraffics/{quote(email, safe='')}")
        if not isinstance(payload.get("obj"), dict):
            raise PanelResponseError("Traffic endpoint returned no object")
        return payload["obj"]

    async def client_traffic_by_id(self, client_id: str) -> dict[str, Any]:
        payload = await self._request(
            "GET", f"inbounds/getClientTrafficsById/{quote(client_id, safe='')}"
        )
        if not isinstance(payload.get("obj"), dict):
            raise PanelResponseError("Traffic-by-id endpoint returned no object")
        return payload["obj"]

    async def render_client_configs(
        self, inbound_id: int, protocol: str, email: str, *, transport: str = "udp"
    ) -> list[dict[str, Any]]:
        """Render protocol-native client configuration using vpn-ui's documented routes."""
        protocol = protocol.lower()
        if protocol == "openvpn":
            if transport not in {"tcp", "udp"}:
                raise ValueError("OpenVPN transport must be tcp or udp")
            response = await self._request(
                "GET", f"inbounds/{inbound_id}/ovpn/{transport}", raw=True
            )
            if not response.content:
                raise PanelResponseError("OpenVPN config endpoint returned an empty profile")
            return [{"filename": f"{email}.ovpn", "content": response.content}]

        endpoint = {
            "wg-c": "wgc-configs",
            "awg": "awg-configs",
            "gre": "gre-configs",
            "ssh": "ssh-configs",
        }.get(protocol)
        if endpoint is None:
            return []
        payload = await self._request(
            "GET", f"inbounds/{inbound_id}/{endpoint}", params={"email": email}
        )
        rows = payload.get("obj")
        if isinstance(rows, dict):
            rows = [rows]
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise PanelResponseError(f"{endpoint} returned no configuration list")

        files: list[dict[str, Any]] = []
        for index, row in enumerate(rows):
            if protocol in {"wg-c", "awg"}:
                content = row.get("config")
                extension = "conf"
                suffix = f"device-{row.get('deviceIndex', index)}"
            elif protocol == "gre":
                content = row.get("config")
                extension = "txt"
                suffix = f"peer-{row.get('peerIndex', index)}"
            else:
                content = "\n".join(
                    str(row.get(key, ""))
                    for key in ("remark", "host", "port", "link", "plain", "singbox")
                    if row.get(key) not in (None, "")
                )
                extension = "txt"
                suffix = f"endpoint-{index}"
            if isinstance(content, str) and content.strip():
                files.append(
                    {
                        "filename": f"{protocol}-{email}-{suffix}.{extension}",
                        "content": content.encode("utf-8"),
                    }
                )
        if not files:
            raise PanelResponseError(f"{endpoint} returned no usable client configuration")
        return files

    async def create_inbound(
        self,
        *,
        remark: str,
        protocol: str,
        port: int | None,
        enable: bool = True,
        listen: str = "",
        settings: dict[str, Any] | None = None,
        stream_settings: dict[str, Any] | None = None,
        sniffing: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if protocol == "gre":
            if port is not None:
                raise ValueError("GRE inbounds do not use a port")
        elif port is None or not 1 <= port <= 65535:
            raise ValueError("Inbound port must be between 1 and 65535")
        form = {
            "remark": remark.strip(),
            "enable": str(enable).lower(),
            "listen": listen,
            "protocol": protocol,
            "settings": json.dumps(settings or {}, separators=(",", ":")),
            "streamSettings": json.dumps(stream_settings or {}, separators=(",", ":")),
            "sniffing": json.dumps(sniffing or {}, separators=(",", ":")),
        }
        if port is not None:
            form["port"] = str(port)
        return await self._request("POST", "inbounds/add", form=form)

    async def update_inbound(self, inbound_id: int, **fields: Any) -> dict[str, Any]:
        allowed = {"remark", "enable", "listen", "port", "protocol", "total", "expiryTime"}
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"Unsupported inbound fields: {', '.join(sorted(unknown))}")
        form = {
            key: str(value).lower() if isinstance(value, bool) else str(value)
            for key, value in fields.items()
        }
        return await self._request("POST", f"inbounds/update/{inbound_id}", form=form)

    async def delete_inbound(self, inbound_id: int) -> dict[str, Any]:
        return await self._request("POST", f"inbounds/del/{inbound_id}")

    async def generate_inbound_certificate(self, kind: str) -> dict[str, Any]:
        endpoints = {
            "openvpn": "inbounds/generate-openvpn-certs",
            "openconnect": "inbounds/generate-ocserv-cert",
            "sstp": "inbounds/generate-sstp-cert",
            "ikev2": "inbounds/generate-ikev2-cert",
        }
        if kind not in endpoints:
            raise ValueError("Certificate generation is not supported for this protocol")
        payload = await self._request("POST", endpoints[kind])
        if not isinstance(payload.get("obj"), dict):
            raise PanelResponseError("Certificate endpoint returned no certificate object")
        return payload["obj"]

    async def core_status(self) -> dict[str, Any]:
        payload = await self._panel_request("GET", "panel/core/status")
        return payload.get("obj", {})

    async def core_catalog(self) -> list[dict[str, Any]]:
        payload = await self._panel_request("GET", "panel/core/catalog")
        obj = payload.get("obj", {})
        cores = obj.get("cores", []) if isinstance(obj, dict) else []
        if not isinstance(cores, list):
            raise PanelResponseError("Core catalog returned no list")
        return cores

    async def provision_cores(self, cores: list[str]) -> dict[str, Any]:
        normalized = list(dict.fromkeys(item.strip() for item in cores if item.strip()))
        if not normalized:
            raise ValueError("At least one core must be selected")
        payload = await self._panel_request(
            "POST", "panel/core/provision", form={"cores": ",".join(normalized)}
        )
        return payload.get("obj", {})

    async def provision_status(self) -> dict[str, Any]:
        payload = await self._panel_request("GET", "panel/core/provision-status")
        return payload.get("obj", {})

    async def vpn_outbound_list(self) -> list[dict[str, Any]]:
        payload = await self._panel_request("POST", "panel/xray/vpnoutbound/list")
        rows = payload.get("obj", [])
        if not isinstance(rows, list):
            raise PanelResponseError("VPN outbound list returned no list")
        return rows

    async def vpn_outbound_kinds(self) -> list[dict[str, Any]]:
        payload = await self._panel_request("POST", "panel/xray/vpnoutbound/kinds")
        rows = payload.get("obj", [])
        if not isinstance(rows, list):
            raise PanelResponseError("VPN outbound kinds returned no list")
        return rows

    async def vpn_outbound_status(self, tag: str) -> dict[str, Any]:
        payload = await self._panel_request(
            "POST", "panel/xray/vpnoutbound/status", form={"tag": tag}
        )
        return payload.get("obj", {})

    async def vpn_outbound_delete(self, tag: str) -> dict[str, Any]:
        return await self._panel_request("POST", "panel/xray/vpnoutbound/delete", form={"tag": tag})

    async def vpn_outbound_save(
        self,
        *,
        tag: str,
        kind: str,
        settings: dict[str, Any],
        remark: str = "",
        via: str = "",
    ) -> dict[str, Any]:
        if not tag.strip() or not kind.strip():
            raise ValueError("VPN outbound tag and kind are required")
        payload = await self._panel_request(
            "POST",
            "panel/xray/vpnoutbound/save",
            form={
                "tag": tag.strip(),
                "kind": kind.strip(),
                "remark": remark.strip(),
                "enable": "true",
                "via": via.strip(),
                "settings": json.dumps(settings, separators=(",", ":")),
            },
        )
        return payload.get("obj", {})

    async def reset_client_traffic(self, inbound_id: int, email: str) -> dict[str, Any]:
        return await self._request(
            "POST",
            f"inbounds/{inbound_id}/resetClientTraffic/{quote(email, safe='')}",
        )
