from datetime import UTC, datetime
from uuid import uuid4

from vpn_manager.panels.protocols import IDENTITY_FIELDS
from vpn_manager.provisioning import build_client_payload


def test_client_identity_map_matches_current_vpn_ui_api_contract():
    assert IDENTITY_FIELDS == {
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


def test_client_payload_uses_bytes_unix_milliseconds_and_enabled_flag():
    order_id = uuid4()
    expiry = datetime(2027, 1, 1, tzinfo=UTC)
    payload = build_client_payload(
        protocol="vless",
        telegram_id=12345,
        order_id=order_id,
        expires_at=expiry,
        traffic_limit_bytes=25 * 1024**3,
        device_limit=3,
    )
    assert payload["enable"] is True
    assert payload["totalGB"] == 25 * 1024**3
    assert payload["expiryTime"] == int(expiry.timestamp() * 1000)
    assert payload["limitIp"] == 3
    assert payload["id"]
    assert payload["email"].startswith("u12345-")
    assert "/" not in payload["subId"] and "%" not in payload["subId"]


def test_protocol_specific_client_credentials_are_populated():
    expiry = datetime(2027, 1, 1, tzinfo=UTC)
    for protocol, identity_key in IDENTITY_FIELDS.items():
        payload = build_client_payload(
            protocol=protocol,
            telegram_id=99,
            order_id=uuid4(),
            expires_at=expiry,
            traffic_limit_bytes=0,
            device_limit=1,
        )
        assert payload["enable"] is True
        assert payload["email"]
        assert payload["subId"]
        assert payload[identity_key]
        if protocol == "ssh":
            assert payload["id"].startswith("u99_")
        if protocol == "gre":
            assert payload["peers"]
        if protocol == "mtproto":
            assert payload["modeClassic"] and payload["modeSecure"] and payload["modeTls"]


def test_unknown_protocol_is_not_silently_provisioned():
    import pytest

    with pytest.raises(ValueError, match="پشتیبانی نشده"):
        build_client_payload(
            protocol="unknown",
            telegram_id=99,
            order_id=uuid4(),
            expires_at=datetime(2027, 1, 1, tzinfo=UTC),
            traffic_limit_bytes=0,
            device_limit=1,
        )
