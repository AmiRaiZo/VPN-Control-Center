"""Authenticated encryption for panel passwords stored in the database."""

from cryptography.fernet import Fernet, InvalidToken

from vpn_manager.config import get_settings


class PanelCredentialError(ValueError):
    """Raised when the credential key is missing, invalid or cannot decrypt data."""


def _fernet() -> Fernet:
    configured_key = get_settings().panel_credential_encryption_key
    if configured_key is None:
        raise PanelCredentialError("PANEL_CREDENTIAL_ENCRYPTION_KEY is not configured")
    try:
        key = configured_key.get_secret_value().strip().encode("ascii")
        return Fernet(key)
    except (ValueError, TypeError, UnicodeError) as exc:
        raise PanelCredentialError(
            "PANEL_CREDENTIAL_ENCRYPTION_KEY must be a valid Fernet key"
        ) from exc


def encrypt_panel_password(password: str) -> str:
    if not password:
        raise ValueError("Panel password cannot be empty")
    return _fernet().encrypt(password.encode("utf-8")).decode("ascii")


def decrypt_panel_password(token: str) -> str:
    cipher = _fernet()
    try:
        return cipher.decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeError, ValueError) as exc:
        raise PanelCredentialError("Stored panel credential cannot be decrypted") from exc
