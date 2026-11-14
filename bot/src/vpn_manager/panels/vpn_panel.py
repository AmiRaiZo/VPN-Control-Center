from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx

from .errors import (
    PanelAuthenticationError,
    PanelOperationError,
    PanelResponseError,
    PanelTransportError,
)

_VIRTUAL_PROTOCOLS = {
    1: "l2tp",
    2: "pptp",
    3: "openvpn",
    4: "sstp",
    5: "ikev2",
    6: "openconnect",
    7: "vmess",
    8: "vless",
}
_PROTOCOL_IDS = {value: key for key, value in _VIRTUAL_PROTOCOLS.items()}


@dataclass(frozen=True, slots=True)
class VpnPanelConfig:
    """Connection settings for the VPN Panel JSON API."""

    name: str
    base_url: str
    username: str
    password: str = field(repr=False)
    base_path: str = ""
    verify_tls: bool = True
    timeout: float = 20.0

    def __post_init__(self) -> None:
        parsed = urlsplit(self.base_url)
        if parsed.scheme not in {"http", "https"} or (parsed.scheme != "https" and self.verify_tls):
            raise ValueError("VPN Panel URLs must use HTTPS when TLS verification is enabled")
        if not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("VPN Panel base_url must be absolute and contain no credentials, query or fragment")
        if self.timeout <= 0:
            raise ValueError("timeout must be positive")


class VpnPanelClient:
    """Async client for the VPN Panel REST API; all operations require a licensed superadmin."""

    def __init__(self, config: VpnPanelConfig, client: httpx.AsyncClient | None = None) -> None:
        self.config = config
        self._owns_client = client is None
        self._http = client or httpx.AsyncClient(
            timeout=httpx.Timeout(config.timeout), verify=config.verify_tls, follow_redirects=False
        )
        self._token: str | None = None

    @property
    def root(self) -> str:
        prefix = self.config.base_path.strip("/")
        return f"{self.config.base_url.rstrip('/')}/{prefix}" if prefix else self.config.base_url.rstrip("/")

    async def close(self) -> None:
        self._token = None
        if self._owns_client:
            await self._http.aclose()

    async def login(self) -> dict[str, Any]:
        self._token = None
        try:
            response = await self._http.post(
                f"{self.root}/api/auth/login",
                json={"username": self.config.username, "password": self.config.password},
                headers={"Accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            raise PanelTransportError("Could not reach VPN Panel during login") from exc
        payload = self._json_object(response, "VPN Panel login")
        if response.status_code >= 400:
            raise PanelAuthenticationError(self._detail(payload, "VPN Panel login was rejected"))

        token = payload.get("access_token")
        if not isinstance(token, str) or not token.strip():
            raise PanelResponseError("VPN Panel login did not return an access token")
        if payload.get("role") != "superadmin":
            raise PanelAuthenticationError("VPN Panel access requires the superadmin role")
        if payload.get("internal_license_required") is not False:
            raise PanelAuthenticationError("VPN Panel superadmin license is missing or expired")

        self._token = token.strip()
        return payload

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        body: dict[str, Any] | None = None,
    ) -> Any:
        if not self._token:
            raise PanelAuthenticationError("VPN Panel session is missing; superadmin login is required")
        try:
            response = await self._http.request(
                method,
                f"{self.root}/{path.lstrip('/')}",
                params=params,
                json=body,
                headers={"Authorization": f"Bearer {self._token}", "Accept": "application/json"},
            )
        except httpx.HTTPError as exc:
            raise PanelTransportError("VPN Panel API request failed") from exc

        payload = self._json_value(response, "VPN Panel API")
        if response.status_code in {401, 403}:
            self._token = None
            detail = self._detail(payload, "VPN Panel session expired or access was denied")
            raise PanelAuthenticationError(detail)
        if response.status_code >= 400:
            detail = self._detail(payload, f"VPN Panel returned HTTP {response.status_code}")
            raise PanelOperationError(detail)
        return payload

    @staticmethod
    def _json_value(response: httpx.Response, context: str) -> Any:
        try:
            return response.json()
        except ValueError as exc:
            raise PanelResponseError(f"{context} returned malformed or non-JSON content") from exc

    @staticmethod
    def _json_object(response: httpx.Response, context: str) -> dict[str, Any]:
        payload = VpnPanelClient._json_value(response, context)
        if not isinstance(payload, dict):
            raise PanelResponseError(f"{context} returned an unexpected JSON structure")
        return payload

    @staticmethod
    def _detail(payload: Any, fallback: str) -> str:
        if not isinstance(payload, dict):
            return fallback
        detail = payload.get("detail") or payload.get("message") or fallback
        return str(detail)[:300]

    async def list_users(self) -> list[dict[str, Any]]:
        payload = await self._request("GET", "/api/users")
        if not isinstance(payload, list) or any(not isinstance(row, dict) for row in payload):
            raise PanelResponseError("VPN Panel user list returned an unexpected JSON structure")
        return payload

    async def get_user(self, user_id: int) -> dict[str, Any]:
        payload = await self._request("GET", f"/api/users/{int(user_id)}")
        return payload

    async def create_user(self, user: dict[str, Any]) -> dict[str, Any]:
        return await self._request("POST", "/api/users", body=user)

    async def update_user(self, user_id: int, changes: dict[str, Any]) -> dict[str, Any]:
        return await self._request("PUT", f"/api/users/{int(user_id)}", body=changes)

    async def delete_user(self, user_id: int) -> dict[str, Any]:
        return await self._request("DELETE", f"/api/users/{int(user_id)}")

    async def reset_user_usage(self, user_id: int) -> dict[str, Any]:
        return await self._request("POST", f"/api/users/{int(user_id)}/reset-usage")

    async def disconnect_user(self, user_id: int) -> dict[str, Any]:
        return await self._request("POST", f"/api/users/{int(user_id)}/disconnect")

    async def protocol_overview(self) -> dict[str, Any]:
        return await self._request("GET", "/api/dashboard/protocol-overview")

    async def list_inbounds(self) -> list[dict[str, Any]]:
        """Return protocol services as virtual rows; VPN Panel has no Xray inbounds API."""
        overview = await self.protocol_overview()
        servers = overview.get("servers")
        if not isinstance(servers, list):
            raise PanelResponseError("VPN Panel protocol overview has no servers list")
        by_protocol: dict[str, list[dict[str, Any]]] = {key: [] for key in _PROTOCOL_IDS}
        for server in servers:
            if not isinstance(server, dict):
                continue
            for item in server.get("protocols") or []:
                if not isinstance(item, dict):
                    continue
                key = str(item.get("key") or "").strip().lower()
                if key in by_protocol:
                    by_protocol[key].append({"server": server, **item})
        rows: list[dict[str, Any]] = []
        for virtual_id, protocol in _VIRTUAL_PROTOCOLS.items():
            entries = by_protocol[protocol]
            if not entries:
                continue
            installed_entries = [item for item in entries if bool(item.get("installed"))]
            running_entries = [
                item
                for item in installed_entries
                if str(item.get("state") or "").strip().lower()
                in {"running", "active", "online", "healthy", "ok"}
            ]
            label = str(entries[0].get("label") or protocol.upper())
            rows.append(
                {
                    "id": virtual_id,
                    "protocol": protocol,
                    "remark": label,
                    "enable": bool(running_entries),
                    "installed": bool(installed_entries),
                    "state": str(entries[0].get("state") or "unknown"),
                    "inbounds": sum(int(item.get("inbounds") or 0) for item in entries),
                    "listen": str(entries[0].get("listen") or ""),
                    "backend": str(entries[0].get("backend") or ""),
                    "servers": [
                        {
                            "id": item.get("server", {}).get("id"),
                            "name": item.get("server", {}).get("name"),
                            "status": item.get("server", {}).get("status"),
                            "state": item.get("state"),
                            "installed": bool(item.get("installed")),
                        }
                        for item in entries
                    ],
                }
            )
        return rows

    @staticmethod
    def _protocol_for_virtual_id(inbound_id: int) -> str:
        try:
            return _VIRTUAL_PROTOCOLS[int(inbound_id)]
        except (KeyError, TypeError, ValueError) as exc:
            raise PanelOperationError("Unknown VPN Panel virtual protocol service") from exc

    @staticmethod
    def _sub_token(user: dict[str, Any]) -> str | None:
        link = str(user.get("sub_link") or "").strip()
        if not link:
            return None
        token = urlsplit(link).path.rstrip("/").rsplit("/", 1)[-1]
        return token if re.fullmatch(r"[A-Za-z0-9_-]{8,256}", token) else None

    @classmethod
    def _client_row(cls, user: dict[str, Any], protocol: str) -> dict[str, Any]:
        username = str(user.get("username") or "")
        return {
            "email": username,
            "username": username,
            "id": str(user.get("xray_uuid") or username),
            "enable": bool(user.get("is_active")) and bool(user.get(f"enable_{protocol}")),
            "is_active": bool(user.get("is_active")),
            "totalGB": int(user.get("quota_bytes") or 0),
            "used_bytes": int(user.get("used_bytes") or 0),
            "limitIp": int(user.get("max_devices") or 0),
            "max_devices": int(user.get("max_devices") or 0),
            "expire_mode": user.get("expire_mode"),
            "expire_date": user.get("expire_date"),
            "expire_after_days": user.get("expire_after_days"),
            "first_connect_at": user.get("first_connect_at"),
            "sub_link": user.get("sub_link"),
            "sub_token": cls._sub_token(user),
            "vpn_panel_user_id": user.get("id"),
            "comment": user.get("note") or "",
            "protocol_enabled": bool(user.get(f"enable_{protocol}")),
        }

    async def get_inbound(self, inbound_id: int) -> dict[str, Any]:
        protocol = self._protocol_for_virtual_id(inbound_id)
        users = await self.list_users()
        # Keep each virtual protocol service isolated. Disabled users whose
        # protocol flag is off are found by provisioning.find_user() during a
        # renewal, rather than leaking as phantom rows into every other service.
        clients = [
            self._client_row(user, protocol)
            for user in users
            if bool(user.get(f"enable_{protocol}"))
        ]
        return {
            "id": int(inbound_id),
            "protocol": protocol,
            "remark": protocol.upper(),
            "enable": True,
            "settings": {"clients": clients},
        }

    async def find_user(self, username: str) -> dict[str, Any] | None:
        wanted = str(username or "").strip().casefold()
        if not wanted:
            return None
        for user in await self.list_users():
            if str(user.get("username") or "").casefold() == wanted:
                return user
        return None

    async def _find_user(self, identity: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        candidate_id = (payload or {}).get("vpn_panel_user_id")
        if candidate_id is not None:
            try:
                return await self.get_user(int(candidate_id))
            except (ValueError, TypeError):
                pass
        username = str(identity or (payload or {}).get("email") or "").strip()
        if not username:
            raise PanelOperationError("VPN Panel user identity is missing")
        user = await self.find_user(username)
        if user is not None:
            return user
        raise PanelOperationError("VPN Panel user was not found")

    @staticmethod
    def _expiry_fields(payload: dict[str, Any], *, default: bool = False) -> dict[str, Any]:
        if "expiryTime" in payload:
            expiry_ms = int(payload.get("expiryTime") or 0)
            if not expiry_ms:
                return {"expire_mode": "fixed", "expire_date": None}
            expiry = datetime.fromtimestamp(expiry_ms / 1000, UTC)
            return {"expire_mode": "fixed", "expire_date": expiry.date().isoformat()}
        if "expire_mode" in payload:
            result = {"expire_mode": payload["expire_mode"]}
            if "expire_date" in payload:
                result["expire_date"] = payload["expire_date"]
            if "expire_after_days" in payload:
                result["expire_after_days"] = payload["expire_after_days"]
            return result
        return {"expire_mode": "fixed", "expire_date": None} if default else {}

    @staticmethod
    def _quota_gb(payload: dict[str, Any]) -> float:
        return int(payload.get("totalGB") or 0) / (1024**3)

    async def add_client(
        self,
        inbound_id: int,
        client: dict[str, Any],
        *,
        inbound_ids: list[int] | None = None,
    ) -> dict[str, Any]:
        del inbound_ids  # A VPN Panel account is enabled on one protocol via its user flags.
        protocol = self._protocol_for_virtual_id(inbound_id)
        username = str(client.get("email") or client.get("username") or "").strip()
        password = str(
            client.get("password")
            or client.get("vpn_panel_password")
            or secrets.token_urlsafe(24)
        )
        if not username:
            raise ValueError("VPN Panel username is required")
        body = {
            "username": username,
            "password": password,
            **{f"enable_{key}": key == protocol for key in _PROTOCOL_IDS},
            "quota_gb": self._quota_gb(client),
            "max_devices": int(client.get("limitIp") or 0),
            "is_active": bool(client.get("enable", True)),
            "note": str(client.get("comment") or "")[:500],
            "server_targets": ["all"],
            **self._expiry_fields(client, default=True),
        }
        created = await self.create_user(body)
        if not isinstance(created, dict) or created.get("id") is None:
            raise PanelResponseError("VPN Panel create-user response did not include an ID")
        returned_username = str(created.get("username") or "").strip()
        if returned_username and returned_username.casefold() != username.casefold():
            raise PanelResponseError("VPN Panel created a user with an unexpected username")
        client["username"] = username
        if protocol in {"vmess", "vless"} and not client.get("password"):
            client["vpn_panel_password"] = password
        else:
            client["password"] = password
        client["vpn_panel_user_id"] = int(created["id"])
        client["is_active"] = bool(client.get("enable", True))
        client["sub_link"] = created.get("sub_link")
        client["sub_token"] = self._sub_token(created)
        return created

    async def update_client(self, inbound_id: int, identity: str, client: dict[str, Any]) -> dict[str, Any]:
        protocol = self._protocol_for_virtual_id(inbound_id)
        user = await self._find_user(identity, client)
        changes: dict[str, Any] = {
            f"enable_{protocol}": bool(
                client.get(
                    "protocol_enabled",
                    client.get("enable", user.get(f"enable_{protocol}", False)),
                )
            ),
            "quota_gb": self._quota_gb(client),
            "max_devices": int(client.get("limitIp", user.get("max_devices", 0)) or 0),
            **self._expiry_fields(client),
        }
        if "is_active" in client:
            changes["is_active"] = bool(client["is_active"])
        if client.get("password"):
            changes["password"] = str(client["password"])
        if "comment" in client:
            changes["note"] = str(client.get("comment") or "")[:500]
        updated = await self.update_user(int(user["id"]), changes)
        client["vpn_panel_user_id"] = int(user["id"])
        client["sub_link"] = updated.get("sub_link", user.get("sub_link"))
        client["sub_token"] = self._sub_token({"sub_link": client["sub_link"]})
        return updated

    async def delete_client(self, inbound_id: int, identity: str) -> dict[str, Any]:
        protocol = self._protocol_for_virtual_id(inbound_id)
        user = await self._find_user(identity)
        remaining_protocols = [
            key
            for key in _PROTOCOL_IDS
            if key != protocol and bool(user.get(f"enable_{key}"))
        ]
        if remaining_protocols:
            # The VPN Panel delete endpoint removes the whole account. Preserve
            # other protocol access by disabling only this service's flag.
            return await self.update_user(
                int(user["id"]),
                {f"enable_{protocol}": False, "is_active": bool(user.get("is_active", True))},
            )
        return await self.delete_user(int(user["id"]))

    async def client_traffic(self, identity: str) -> dict[str, Any]:
        user = await self._find_user(identity)
        total = int(user.get("used_bytes") or 0)
        return {"up": 0, "down": total, "total_bytes": total, "total_only": True}

    async def _public_config(self, token: str, endpoint: str, filename: str) -> dict[str, Any]:
        try:
            response = await self._http.get(f"{self.root}/api/sub/{token}/{endpoint}")
        except httpx.HTTPError as exc:
            raise PanelTransportError("VPN Panel subscription download failed") from exc
        if response.status_code >= 400:
            raise PanelOperationError(f"VPN Panel subscription download returned HTTP {response.status_code}")
        if not response.content or "text/html" in response.headers.get("content-type", "").lower():
            raise PanelResponseError("VPN Panel subscription endpoint returned no usable config")
        return {"filename": filename, "content": response.content}

    async def render_client_configs(
        self, inbound_id: int, protocol: str, email: str, *, transport: str = "udp"
    ) -> list[dict[str, Any]]:
        del transport  # The verified VPN Panel OpenVPN subscription endpoint selects its own profile.
        self._protocol_for_virtual_id(inbound_id)
        user = await self._find_user(email)
        token = self._sub_token(user)
        if not token:
            raise PanelResponseError("VPN Panel user has no public subscription token")
        if protocol == "openvpn":
            return [await self._public_config(token, "openvpn-config", f"{email}.ovpn")]
        if protocol in {"vmess", "vless"}:
            return [await self._public_config(token, "xray-sub", f"{email}-subscription.txt")]
        if protocol == "sstp":
            return [await self._public_config(token, "sstp-cert", f"{email}.crt")]
        return []
