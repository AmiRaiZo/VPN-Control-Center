import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr, ValidationError

from vpn_manager.config import Settings, get_settings
from vpn_manager.security.panel_credentials import (
    PanelCredentialError,
    decrypt_panel_password,
    encrypt_panel_password,
)


def test_production_requires_nontrivial_app_secret():
    with pytest.raises(ValidationError, match="APP_SECRET_KEY"):
        Settings(_env_file=None, app_env="production", app_secret_key=SecretStr("short"))


def test_production_requires_valid_fernet_key():
    with pytest.raises(ValidationError, match="PANEL_CREDENTIAL_ENCRYPTION_KEY"):
        Settings(
            _env_file=None,
            app_env="production",
            app_secret_key=SecretStr("s" * 40),
            panel_credential_encryption_key=SecretStr("not-a-fernet-key"),
        )


def test_production_accepts_valid_secrets():
    settings = Settings(
        _env_file=None,
        app_env="production",
        app_secret_key=SecretStr("s" * 40),
        panel_credential_encryption_key=SecretStr(Fernet.generate_key().decode()),
    )
    assert settings.app_env == "production"


def test_panel_password_is_encrypted_and_round_trips(monkeypatch):
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("PANEL_CREDENTIAL_ENCRYPTION_KEY", key)
    get_settings.cache_clear()
    try:
        encrypted = encrypt_panel_password("router-admin-password")
        assert encrypted != "router-admin-password"
        assert decrypt_panel_password(encrypted) == "router-admin-password"
    finally:
        get_settings.cache_clear()


def test_panel_password_encryption_requires_key(monkeypatch):
    monkeypatch.delenv("PANEL_CREDENTIAL_ENCRYPTION_KEY", raising=False)
    monkeypatch.setenv("APP_ENV", "development")
    get_settings.cache_clear()
    try:
        with pytest.raises(PanelCredentialError, match="not configured"):
            encrypt_panel_password("password")
    finally:
        get_settings.cache_clear()
