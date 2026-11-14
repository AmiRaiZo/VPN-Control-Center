from __future__ import annotations

import gzip
import io
import json
from typing import Any

from app.config import get_settings

LEGACY_ENCRYPTED_MAGIC = b"VPNPBK1\x00"


class BackupFormatError(ValueError):
    pass


def encode_json_backup(data: dict[str, Any]) -> bytes:
    """Encode a backup as plain UTF-8 JSON compressed with gzip.

    The document still carries the panel's internal SHA-256 integrity metadata,
    but it is deliberately not encrypted and requires no recovery key.
    """
    plain = json.dumps(data, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")
    return gzip.compress(plain, compresslevel=6, mtime=0)


def safe_gzip_decompress(raw: bytes, *, max_output_bytes: int) -> bytes:
    """Stream gzip data and stop before a gzip bomb can exhaust memory."""
    limit = max(1, int(max_output_bytes))
    output = bytearray()
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb") as stream:
            while True:
                chunk = stream.read(min(1024 * 1024, limit - len(output) + 1))
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > limit:
                    raise BackupFormatError("decompressed backup exceeds the configured safety limit")
    except BackupFormatError:
        raise
    except Exception as exc:
        raise BackupFormatError("gzip payload is invalid") from exc
    return bytes(output)


def decode_backup_bytes(raw: bytes) -> bytes:
    """Return bounded JSON bytes from a plain .json or .json.gz backup."""
    settings = get_settings()
    value = bytes(raw or b"")
    if len(value) > int(settings.BACKUP_MAX_COMPRESSED_BYTES):
        raise BackupFormatError("backup file exceeds the configured upload limit")
    if value.startswith(LEGACY_ENCRYPTED_MAGIC):
        raise BackupFormatError(
            "این فایل از قالب رمزگذاری‌شده قدیمی است؛ نسخه فعلی فقط بکاپ‌های بدون رمز .json یا .json.gz را می‌پذیرد"
        )
    if value[:2] == b"\x1f\x8b":
        value = safe_gzip_decompress(value, max_output_bytes=int(settings.BACKUP_MAX_DECOMPRESSED_BYTES))
    elif len(value) > int(settings.BACKUP_MAX_DECOMPRESSED_BYTES):
        raise BackupFormatError("backup JSON exceeds the configured safety limit")
    return value
