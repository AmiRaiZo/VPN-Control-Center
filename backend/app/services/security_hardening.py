from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path

from app.config import Settings

_INSECURE_VALUES = {
    "",
    "change-me",
    "changeme",
    "default",
    "secret",
    "password",
    "test",
}


class SecurityConfigurationError(RuntimeError):
    pass


def secret_bytes(value: str, *, label: str) -> bytes:
    """Return exactly 32 bytes from a configured secret.

    Installers generate URL-safe base64 keys, but this parser also accepts a
    64-character hexadecimal value to keep older/custom deployments easy to
    migrate. Arbitrary strings are only accepted when they carry at least 32
    characters of entropy-bearing material; they are domain-separated before
    hashing so two settings with the same source string do not become the same
    cryptographic key.
    """
    raw = str(value or "").strip()
    if raw.lower() in _INSECURE_VALUES:
        raise SecurityConfigurationError(f"{label} is missing or uses an insecure placeholder")

    try:
        decoded = base64.urlsafe_b64decode(raw.encode("ascii"))
        if len(decoded) == 32:
            return decoded
    except Exception:
        pass

    if len(raw) == 64:
        try:
            decoded = bytes.fromhex(raw)
            if len(decoded) == 32:
                return decoded
        except ValueError:
            pass

    if len(raw) < 32:
        raise SecurityConfigurationError(f"{label} must contain at least 32 characters")
    return hashlib.sha256((label + "\0" + raw).encode("utf-8")).digest()


def parse_csv(value: str) -> list[str]:
    return [item.strip() for item in str(value or "").split(",") if item.strip()]


def validate_runtime_security(settings: Settings) -> None:
    """Fail startup before serving traffic when deployment secrets are unsafe."""
    if os.environ.get("VPN_PANEL_ALLOW_INSECURE_TEST_SETTINGS") == "1":
        return

    errors: list[str] = []
    for label, value in (
        ("JWT_SECRET", settings.JWT_SECRET),
        ("INTERNAL_API_TOKEN", settings.INTERNAL_API_TOKEN),
        ("DATA_ENCRYPTION_KEY", settings.DATA_ENCRYPTION_KEY),
    ):
        try:
            secret_bytes(value, label=label)
        except SecurityConfigurationError as exc:
            errors.append(str(exc))

    psk = str(settings.IPSEC_PSK or "").strip()
    if psk.lower() in _INSECURE_VALUES or len(psk) < 16:
        errors.append("IPSEC_PSK must be configured and contain at least 16 characters")

    origins = parse_csv(settings.CORS_ALLOWED_ORIGINS)
    if any(origin == "*" for origin in origins) and settings.CORS_ALLOW_CREDENTIALS:
        errors.append("CORS_ALLOWED_ORIGINS cannot contain '*' while credentials are enabled")

    if not settings.LICENSE_ALLOW_UNLICENSED_DEVELOPMENT:
        if not str(settings.LICENSE_SERVER_URL or "").strip():
            errors.append("LICENSE_SERVER_URL is required for a production license-only deployment")
        if not str(settings.LICENSE_API_KEY or "").strip():
            errors.append("LICENSE_API_KEY is required for a production license-only deployment")

    if errors:
        raise SecurityConfigurationError("; ".join(errors))


def ensure_private_file(path: str | Path) -> None:
    try:
        target = Path(path)
        if target.exists():
            target.chmod(0o600)
    except OSError:
        pass
