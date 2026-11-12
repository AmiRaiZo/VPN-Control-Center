from types import SimpleNamespace

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from vpn_manager.security import panel_credentials


def test_panel_password_round_trip_uses_configured_fernet_key(monkeypatch):
    key = Fernet.generate_key().decode("ascii")
    monkeypatch.setattr(
        panel_credentials,
        "get_settings",
        lambda: SimpleNamespace(panel_credential_encryption_key=SecretStr(key)),
    )

    encrypted = panel_credentials.encrypt_panel_password("panel-secret-123")

    assert encrypted != "panel-secret-123"
    assert panel_credentials.decrypt_panel_password(encrypted) == "panel-secret-123"


def test_panel_password_encryption_requires_a_configured_key(monkeypatch):
    monkeypatch.setattr(
        panel_credentials,
        "get_settings",
        lambda: SimpleNamespace(panel_credential_encryption_key=None),
    )

    with pytest.raises(panel_credentials.PanelCredentialError, match="not configured"):
        panel_credentials.encrypt_panel_password("secret")


def test_invalid_encryption_key_is_reported_as_configuration_error(monkeypatch):
    monkeypatch.setattr(
        panel_credentials,
        "get_settings",
        lambda: SimpleNamespace(panel_credential_encryption_key=SecretStr("not-a-fernet-key")),
    )

    with pytest.raises(panel_credentials.PanelCredentialError, match="valid Fernet key"):
        panel_credentials.encrypt_panel_password("secret")


def test_decryption_does_not_hide_missing_key_configuration(monkeypatch):
    monkeypatch.setattr(
        panel_credentials,
        "get_settings",
        lambda: SimpleNamespace(panel_credential_encryption_key=None),
    )

    with pytest.raises(panel_credentials.PanelCredentialError, match="not configured"):
        panel_credentials.decrypt_panel_password("invalid-token")

