from __future__ import annotations

import getpass
import os
import re
import secrets
import tempfile
from pathlib import Path

import httpx
from cryptography.fernet import Fernet

TOKEN_PATTERN = re.compile(r"^\d{5,}:[A-Za-z0-9_-]{20,}$")


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


def save_bot_settings(env_file: Path, token: str, admin_ids: str) -> None:
    if not TOKEN_PATTERN.fullmatch(token):
        raise ValueError("Bot token format is invalid.")
    normalized_ids = normalize_admin_ids(admin_ids)
    if not env_file.is_file():
        raise FileNotFoundError(f"Environment file does not exist: {env_file}")

    lines = env_file.read_text(encoding="utf-8").splitlines()
    existing_values: dict[str, str] = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if separator:
            existing_values[key] = value
    app_secret = existing_values.get("APP_SECRET_KEY", "")
    if len(app_secret) < 32 or app_secret.startswith("replace-with-"):
        app_secret = secrets.token_urlsafe(48)
    encryption_key = existing_values.get("PANEL_CREDENTIAL_ENCRYPTION_KEY", "")
    try:
        Fernet(encryption_key.encode("ascii"))
    except (ValueError, UnicodeEncodeError):
        encryption_key = Fernet.generate_key().decode("ascii")
    replacements = {
        "BOT_TOKEN": token,
        "ADMIN_TELEGRAM_IDS": normalized_ids,
        "APP_SECRET_KEY": app_secret,
        "PANEL_CREDENTIAL_ENCRYPTION_KEY": encryption_key,
    }
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
    env_file = Path(os.environ.get("VPN_MANAGER_ENV_FILE", ".env"))
    print("\nTelegram bot setup")
    token = getpass.getpass("Bot token (input hidden): ").strip()
    admin_ids = input("Main admin Telegram numeric ID: ").strip()
    admin_ids = normalize_admin_ids(admin_ids)
    username = verify_bot_token(token)
    save_bot_settings(env_file, token, admin_ids)
    print(f"Verified @{username}; credentials saved securely to {env_file}.")


if __name__ == "__main__":
    main()

