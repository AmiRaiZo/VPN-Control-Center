from __future__ import annotations

import asyncio
from typing import Any

from vpn_manager.panels.client import PanelConfig, VpnUiClient
from vpn_manager.panels.errors import PanelError


class PanelRegistry:
    """Process-local panel client registry; each panel owns an isolated HTTP cookie jar."""

    def __init__(self) -> None:
        self._clients: dict[str, VpnUiClient] = {}
        self._lock = asyncio.Lock()

    async def add(self, panel_id: str, config: PanelConfig) -> VpnUiClient:
        if not panel_id.strip():
            raise ValueError("panel_id cannot be empty")
        async with self._lock:
            if panel_id in self._clients:
                raise ValueError("Panel is already registered")
            client = VpnUiClient(config)
            self._clients[panel_id] = client
            return client

    async def get(self, panel_id: str) -> VpnUiClient:
        async with self._lock:
            try:
                return self._clients[panel_id]
            except KeyError as exc:
                raise KeyError(f"Unknown panel id: {panel_id}") from exc

    async def remove(self, panel_id: str) -> None:
        async with self._lock:
            client = self._clients.pop(panel_id, None)
        if client is not None:
            await client.close()

    async def health_all(self) -> dict[str, dict[str, Any]]:
        async with self._lock:
            snapshot = tuple(self._clients.items())

        async def check(panel_id: str, client: VpnUiClient) -> tuple[str, dict[str, Any]]:
            try:
                return panel_id, await client.health()
            except PanelError as exc:
                return panel_id, {"reachable": False, "error": type(exc).__name__}

        results = await asyncio.gather(*(check(panel_id, client) for panel_id, client in snapshot))
        return dict(results)

    async def close(self) -> None:
        async with self._lock:
            clients = tuple(self._clients.values())
            self._clients.clear()
        await asyncio.gather(*(client.close() for client in clients))
