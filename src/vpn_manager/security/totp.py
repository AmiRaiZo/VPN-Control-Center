"""Small RFC 6238 TOTP generator (SHA-1, six digits, 30-second period)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import time


def totp_code(secret: str, *, timestamp: float | None = None) -> str:
    normalized = "".join(secret.strip().replace("-", "").split()).upper()
    if not normalized:
        raise ValueError("TOTP secret is empty")
    try:
        key = base64.b32decode(normalized + "=" * (-len(normalized) % 8), casefold=True)
    except Exception as exc:
        raise ValueError("TOTP secret must be a Base32 authenticator seed") from exc
    counter = int((time.time() if timestamp is None else timestamp) // 30)
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{binary % 1_000_000:06d}"

