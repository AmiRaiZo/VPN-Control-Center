import os
import sys
from io import StringIO
from pathlib import Path

import httpx
import pytest
import respx
from cryptography.fernet import Fernet

from vpn_manager.bot import configured_admin_ids
from vpn_manager.setup_bot import (
    main,
    normalize_admin_ids,
    read_stdin_credentials,
    save_bot_settings,
    verify_bot_token,
)

TOKEN = "123456:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi"


def test_setup_reads_two_lines_from_stdin_without_transforming_credentials():
    from io import StringIO

    assert read_stdin_credentials(StringIO(f"{TOKEN}\n12345, 67890\n")) == (
        TOKEN,
        "12345, 67890",
    )


def test_setup_rejects_incomplete_stdin_credentials():
    with pytest.raises(ValueError, match="admin Telegram ID"):
        read_stdin_credentials(StringIO(f"{TOKEN}\n"))


def test_admin_ids_are_numeric_positive_and_deduplicated():
    assert normalize_admin_ids("12345, 67890,12345") == "12345,67890"
    with pytest.raises(ValueError):
        normalize_admin_ids("123,abc")
    with pytest.raises(ValueError):
        normalize_admin_ids("0")


def test_bot_runtime_parses_admin_allowlist():
    assert configured_admin_ids("123, 456,123") == frozenset({123, 456})
    with pytest.raises(RuntimeError):
        configured_admin_ids("not-an-id")


@respx.mock
def test_token_is_verified_with_telegram_get_me():
    route = respx.get(f"https://api.telegram.org/bot{TOKEN}/getMe").mock(
        return_value=httpx.Response(
            200,
            json={"ok": True, "result": {"is_bot": True, "username": "sample_control_bot"}},
        )
    )
    assert verify_bot_token(TOKEN) == "sample_control_bot"
    assert route.called


def test_invalid_token_format_is_rejected_before_network_call():
    with pytest.raises(ValueError, match="format"):
        verify_bot_token("not-a-token")


def test_bot_settings_are_saved_without_overwriting_other_values(tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "APP_ENV=production\nBOT_TOKEN=old\nADMIN_TELEGRAM_IDS=1\n", encoding="utf-8"
    )
    save_bot_settings(env_file, TOKEN, "12345, 67890")
    saved = env_file.read_text(encoding="utf-8")
    assert "APP_ENV=production" in saved
    assert f"BOT_TOKEN={TOKEN}" in saved
    assert "ADMIN_TELEGRAM_IDS=12345,67890" in saved
    lines = dict(line.split("=", 1) for line in saved.splitlines() if "=" in line)
    assert len(lines["APP_SECRET_KEY"]) >= 32
    Fernet(lines["PANEL_CREDENTIAL_ENCRYPTION_KEY"].encode("ascii"))
    assert saved.count("BOT_TOKEN=") == 1
    if os.name == "posix":
        assert env_file.stat().st_mode & 0o777 == 0o600


def test_admin_id_can_be_updated_without_an_existing_bot_token(tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text("APP_ENV=production\nBOT_TOKEN=\nADMIN_TELEGRAM_IDS=\n", encoding="utf-8")

    save_bot_settings(env_file, None, "8166058529")

    saved = env_file.read_text(encoding="utf-8")
    assert "BOT_TOKEN=\n" in saved
    assert "ADMIN_TELEGRAM_IDS=8166058529\n" in saved
    assert "APP_ENV=production" in saved


def test_token_can_be_updated_without_an_existing_admin_id(tmp_path: Path):
    env_file = tmp_path / ".env"
    env_file.write_text("APP_ENV=production\nBOT_TOKEN=\nADMIN_TELEGRAM_IDS=\n", encoding="utf-8")

    save_bot_settings(env_file, TOKEN, None)

    saved = env_file.read_text(encoding="utf-8")
    assert f"BOT_TOKEN={TOKEN}\n" in saved
    assert "ADMIN_TELEGRAM_IDS=\n" in saved


def test_failed_single_field_update_does_not_modify_existing_env(tmp_path: Path):
    env_file = tmp_path / ".env"
    original = "APP_ENV=production\nBOT_TOKEN=\nADMIN_TELEGRAM_IDS=\n"
    env_file.write_text(original, encoding="utf-8")

    with pytest.raises(ValueError, match="Admin ID"):
        save_bot_settings(env_file, None, "not-a-number")

    assert env_file.read_text(encoding="utf-8") == original


def test_credential_updates_never_rotate_existing_application_or_encryption_keys(
    tmp_path: Path,
):
    env_file = tmp_path / ".env"
    app_secret = "existing-app-secret-value"
    encryption_key = "existing-encryption-key-value"
    env_file.write_text(
        f"APP_SECRET_KEY={app_secret}\n"
        f"PANEL_CREDENTIAL_ENCRYPTION_KEY={encryption_key}\n"
        "BOT_TOKEN=\nADMIN_TELEGRAM_IDS=\n",
        encoding="utf-8",
    )

    save_bot_settings(env_file, None, "8166058529")

    saved = dict(line.split("=", 1) for line in env_file.read_text(encoding="utf-8").splitlines())
    assert saved["APP_SECRET_KEY"] == app_secret
    assert saved["PANEL_CREDENTIAL_ENCRYPTION_KEY"] == encryption_key
    assert saved["ADMIN_TELEGRAM_IDS"] == "8166058529"


def test_setup_cli_updates_admin_id_independently_of_bot_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    env_file = tmp_path / ".env"
    env_file.write_text("BOT_TOKEN=\nADMIN_TELEGRAM_IDS=\n", encoding="utf-8")
    monkeypatch.setenv("VPN_MANAGER_ENV_FILE", str(env_file))
    monkeypatch.setattr(sys, "argv", ["setup_bot", "--set-admin-id"])
    monkeypatch.setattr(sys, "stdin", StringIO("8166058529\n"))

    main()

    saved = env_file.read_text(encoding="utf-8")
    assert "BOT_TOKEN=\n" in saved
    assert "ADMIN_TELEGRAM_IDS=8166058529\n" in saved


@respx.mock
def test_setup_cli_updates_token_independently_of_admin_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    env_file = tmp_path / ".env"
    env_file.write_text("BOT_TOKEN=\nADMIN_TELEGRAM_IDS=\n", encoding="utf-8")
    monkeypatch.setenv("VPN_MANAGER_ENV_FILE", str(env_file))
    monkeypatch.setattr(sys, "argv", ["setup_bot", "--set-token"])
    monkeypatch.setattr(sys, "stdin", StringIO(f"{TOKEN}\n"))
    route = respx.get(f"https://api.telegram.org/bot{TOKEN}/getMe").mock(
        return_value=httpx.Response(
            200,
            json={"ok": True, "result": {"is_bot": True, "username": "sample_control_bot"}},
        )
    )

    main()

    saved = env_file.read_text(encoding="utf-8")
    assert f"BOT_TOKEN={TOKEN}\n" in saved
    assert "ADMIN_TELEGRAM_IDS=\n" in saved
    assert route.called
