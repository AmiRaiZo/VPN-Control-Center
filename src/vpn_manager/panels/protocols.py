"""Protocol identifiers verified against Sir-MmD/vpn-ui API reference (2026-11-12)."""

SUPPORTED_PANEL_PROTOCOLS = frozenset(
    {
        "l2tp",
        "pptp",
        "openvpn",
        "openconnect",
        "sstp",
        "ikev2",
        "wg-c",
        "awg",
        "gre",
        "mtproto",
        "ssh",
        "anytls",
        "tuic",
        "naive",
        "vmess",
        "vless",
        "trojan",
        "shadowsocks",
        "hysteria",
    }
)
IDENTITY_FIELDS = {
    "vmess": "id",
    "vless": "id",
    "tuic": "id",
    "trojan": "password",
    "anytls": "password",
    "naive": "password",
    "l2tp": "password",
    "pptp": "password",
    "openvpn": "password",
    "openconnect": "password",
    "sstp": "password",
    "ikev2": "password",
    "ssh": "id",
    "shadowsocks": "email",
    "wg-c": "id",
    "awg": "id",
    "gre": "id",
    "mtproto": "id",
    "hysteria": "auth",
}
TRAFFIC_UNIT_NOTE = "Client totalGB is bytes despite its name; expiryTime is Unix milliseconds."

