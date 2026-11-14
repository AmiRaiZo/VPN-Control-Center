from __future__ import annotations

import argparse
import getpass
import os
import re
import secrets
import sys
import tempfile
from pathlib import Path
from typing import TextIO

import httpx
from cryptography.fernet import Fernet

TOKEN_PATTERN = re.compile(r"^\d{5,}:[A-Za-z0-9_-]{20,}$")


def read_stdin_credentials(stream: TextIO | None = None) -> tuple[str, str]:
    """Read the two setup values from a pipe without echoing or logging the token."""
    source = stream or sys.stdin
    token_line = source.readline()
    if not token_line:
        raise ValueError("No bot token was received on the setup input stream.")
    admin_line = source.readline()
    if not admin_line:
        raise ValueError("No main admin Telegram ID was received on the setup input stream.")
    return token_line.rstrip("\r\n").strip(), admin_line.rstrip("\r\n").strip()


def normalize_admin_ids(value: str) -> str:
    parts = [part.strip() for part in value.split(",") if part.strip()]
    if not parts or any(not part.isdigit() or int(part) <= 0 for part in parts):
        raise ValueError("Telegram Admin ID must contain one or more positive numeric IDs.")
    return ",".join(dict.fromkeys(parts))


def verify_bot_token(token: str, *, client: httpx.Client | None = None) -> str:
    token = token.strip()
    if not TOKEN_PATTERN.fullmatch(token):
        raise ValueError("Bot token format is invalid. Copy the token from @BotFather.")
    owns_client = client is None
    http = client or httpx.Client(timeout=15.0, follow_redirects=False)
    try:
        response = http.get(f"https://api.telegram.org/bot{token}/getMe")
        response.raise_for_status()
        payload = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        raise ValueError("Could not verify the token with Telegram Bot API.") from exc
    finally:
        if owns_client:
            http.close()
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        raise ValueError("Telegram rejected this bot token.")
    result = payload.get("result")
    if not isinstance(result, dict) or not result.get("is_bot") or not result.get("username"):
        raise ValueError("Telegram returned an invalid bot identity.")
    return str(result["username"])


def save_bot_settings(env_file: Path, token: str | None, admin_ids: str | None) -> None:
    """Atomically update either or both credentials while preserving omitted values."""
    if token is None and admin_ids is None:
        raise ValueError("At least one credential must be provided.")
    if token is not None:
        token = token.strip()
        if not TOKEN_PATTERN.fullmatch(token):
            raise ValueError("Bot token format is invalid.")
    normalized_ids = normalize_admin_ids(admin_ids) if admin_ids is not None else None
    if not env_file.is_file():
        raise FileNotFoundError(f"Environment file does not exist: {env_file}")

    lines = env_file.read_text(encoding="utf-8").splitlines()
    existing_values: dict[str, str] = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if separator:
            existing_values[key] = value
    app_secret = existing_values.get("APP_SECRET_KEY", "")
    if not app_secret.strip():
        app_secret = secrets.token_urlsafe(48)
    encryption_key = existing_values.get("PANEL_CREDENTIAL_ENCRYPTION_KEY", "")
    if not encryption_key.strip():
        encryption_key = Fernet.generate_key().decode("ascii")
    replacements = {
        "APP_SECRET_KEY": app_secret,
        "PANEL_CREDENTIAL_ENCRYPTION_KEY": encryption_key,
    }
    if token is not None:
        replacements["BOT_TOKEN"] = token
    if normalized_ids is not None:
        replacements["ADMIN_TELEGRAM_IDS"] = normalized_ids
    seen: set[str] = set()
    output: list[str] = []
    for line in lines:
        key, separator, _ = line.partition("=")
        if separator and key in replacements:
            if key not in seen:
                output.append(f"{key}={replacements[key]}")
                seen.add(key)
        else:
            output.append(line)
    for key, value in replacements.items():
        if key not in seen:
            output.append(f"{key}={value}")

    env_file.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{env_file.name}.", dir=env_file.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(output).rstrip() + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, env_file)
    except Exception:
        Path(temporary_name).unlink(missing_ok=True)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description="Configure Telegram bot credentials.")
    update_mode = parser.add_mutually_exclusive_group()
    update_mode.add_argument(
        "--stdin",
        action="store_true",
        dest="stdin_credentials",
        help="Read token and admin ID as two lines from stdin; intended for the installer.",
    )
    update_mode.add_argument(
        "--set-admin-id",
        action="store_true",
        help="Read one admin ID from stdin and preserve the current bot token.",
    )
    update_mode.add_argument(
        "--set-token",
        action="store_true",
        help="Read one token from stdin, verify it, and preserve the current admin ID.",
    )
    args = parser.parse_args()
    env_file = Path(os.environ.get("VPN_MANAGER_ENV_FILE", ".env"))
    try:
        print("\nTelegram bot setup", flush=True)
        if args.set_admin_id:
            admin_line = sys.stdin.readline()
            if not admin_line:
                raise ValueError("No Super Admin ID was received on the setup input stream.")
            admin_ids = admin_line.rstrip("\r\n").strip()
            save_bot_settings(env_file, None, admin_ids)
            print("Super Admin ID saved securely.", flush=True)
            return
        if args.set_token:
            token_line = sys.stdin.readline()
            if not token_line:
                raise ValueError("No bot token was received on the setup input stream.")
            token = token_line.rstrip("\r\n").strip()
            print("Verifying the token with Telegram Bot API (timeout: 15 seconds)...", flush=True)
            username = verify_bot_token(token)
            save_bot_settings(env_file, token, None)
            print(f"Verified @{username}; bot token saved securely.", flush=True)
            return
        if args.stdin_credentials:
            token, admin_ids = read_stdin_credentials()
        else:
            token = getpass.getpass("Bot token (input hidden): ").strip()
            admin_ids = input("Main admin Telegram numeric ID: ").strip()
        admin_ids = normalize_admin_ids(admin_ids)
        print("Verifying the token with Telegram Bot API (timeout: 15 seconds)...", flush=True)
        username = verify_bot_token(token)
        save_bot_settings(env_file, token, admin_ids)
        print(f"Verified @{username}; credentials saved securely to {env_file}.", flush=True)
    except KeyboardInterrupt:
        raise SystemExit("Setup cancelled.") from None
    except (OSError, ValueError) as exc:
        raise SystemExit(f"Telegram bot setup failed: {exc}") from exc


if __name__ == "__main__":
    main()
