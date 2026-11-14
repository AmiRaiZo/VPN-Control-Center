"""Trusted client-IP extraction for browser/API requests behind local nginx.

Forwarding headers are accepted only when the immediate ASGI peer is a trusted
local/private reverse proxy.  Cloudflare's visitor-IP headers are accepted only
when the public upstream hop is inside Cloudflare's published proxy ranges.
This prevents a client connected directly to the API from spoofing
``X-Forwarded-For`` or ``CF-Connecting-IP`` to bypass a panel IP ban.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass

from fastapi import Request


_CLOUDFLARE_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        # IPv4 — https://www.cloudflare.com/ips-v4
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
        # IPv6 — https://www.cloudflare.com/ips-v6
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    )
)


def _normalise_ip(value: object) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    # ASGI normally gives a bare address. Brackets are tolerated for IPv6.
    candidate = raw.strip("[]")
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def _address(ip_text: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not ip_text:
        return None
    try:
        return ipaddress.ip_address(ip_text)
    except ValueError:
        return None


def _is_cloudflare(ip_text: str | None) -> bool:
    address = _address(ip_text)
    return bool(address and any(address in network for network in _CLOUDFLARE_NETWORKS))


def _trusted_local_proxy(ip_text: str | None) -> bool:
    address = _address(ip_text)
    if address is None:
        return False
    return bool(address.is_loopback or address.is_private or address.is_link_local)


def _trusted_forwarder(ip_text: str | None) -> bool:
    return _trusted_local_proxy(ip_text) or _is_cloudflare(ip_text)


def _header_ips(value: object) -> list[str]:
    result: list[str] = []
    for part in str(value or "").split(","):
        parsed = _normalise_ip(part)
        if parsed and parsed not in result:
            result.append(parsed)
    return result


def _first_valid(values: Iterable[object]) -> str | None:
    for value in values:
        parsed = _normalise_ip(value)
        if parsed:
            return parsed
    return None



@dataclass(frozen=True)
class ClientAddresses:
    """Trusted client address pair used by audit/security logs.

    ``ipv4`` is preferred whenever a trustworthy IPv4 address exists.  An IPv6
    address is retained separately so dual-stack visitors are not misreported.
    We never manufacture an IPv4 address from an unrelated proxy hop.
    """

    ipv4: str | None = None
    ipv6: str | None = None

    @property
    def primary(self) -> str:
        return self.ipv4 or self.ipv6 or "نامشخص"

    @property
    def all(self) -> tuple[str, ...]:
        return tuple(value for value in (self.ipv4, self.ipv6) if value)


def _split_addresses(values: Iterable[object]) -> ClientAddresses:
    ipv4 = None
    ipv6 = None
    for value in values:
        parsed = _normalise_ip(value)
        if not parsed:
            continue
        address = _address(parsed)
        if isinstance(address, ipaddress.IPv4Address):
            ipv4 = ipv4 or str(address)
            continue
        if isinstance(address, ipaddress.IPv6Address):
            if address.ipv4_mapped is not None:
                ipv4 = ipv4 or str(address.ipv4_mapped)
            else:
                ipv6 = ipv6 or str(address)
    return ClientAddresses(ipv4=ipv4, ipv6=ipv6)


def request_client_addresses(request: Request) -> ClientAddresses:
    peer = _normalise_ip(request.client.host if request.client else None)

    # The supported deployment has uvicorn behind local nginx. Do not trust any
    # forwarding header if somebody reaches the API directly from the internet.
    if not _trusted_local_proxy(peer):
        return _split_addresses((peer,))

    real_ip = _normalise_ip(request.headers.get("x-real-ip"))
    forwarded = _header_ips(request.headers.get("x-forwarded-for"))

    # Build the observed proxy path from left (visitor) to right (nearest public
    # upstream). nginx normally appends $remote_addr to X-Forwarded-For and also
    # writes it into X-Real-IP. Avoid duplicating that final hop.
    chain = list(forwarded)
    if real_ip and (not chain or chain[-1] != real_ip):
        chain.append(real_ip)

    upstream = real_ip or (chain[-1] if chain else None)

    # Cloudflare is the only supported public proxy for which two trustworthy
    # visitor-family headers can coexist.  CF-Pseudo-IPv4 is used only when the
    # observed upstream is really Cloudflare; CF-Connecting-IPv6 preserves the
    # native address when Pseudo IPv4 overwrite mode is enabled.
    if _is_cloudflare(upstream):
        cloudflare_values = []
        for header in (
            "cf-pseudo-ipv4",
            "cf-connecting-ip",
            "cf-connecting-ipv6",
            "true-client-ip",
        ):
            candidate = _normalise_ip(request.headers.get(header))
            if candidate and not _is_cloudflare(candidate):
                cloudflare_values.append(candidate)
        result = _split_addresses(cloudflare_values)
        if result.all:
            return result

    # Walk from the nearest hop backwards. Skip only known proxy hops. This also
    # defeats a client-supplied fake left-most X-Forwarded-For value because the
    # actual direct address appended by nginx is encountered first.
    for candidate in reversed(chain):
        if _trusted_forwarder(candidate):
            continue
        return _split_addresses((candidate,))

    # A LAN-only chain can consist entirely of private hops. Preserve the
    # left-most address as the best available visitor identity in that case.
    if forwarded:
        return _split_addresses((forwarded[0],))
    return _split_addresses((real_ip, peer))


def request_client_ip(request: Request) -> str:
    """Backward-compatible primary client address (IPv4 preferred)."""
    return request_client_addresses(request).primary
