from __future__ import annotations

import hashlib
import json
import secrets
import time
from typing import Any

from sqlalchemy.orm import Session

from app.models import Setting

_TTL_SECONDS = 75
_KEY_PREFIX = "node_handoff_"


def _ticket_key(ticket: str) -> str:
    digest = hashlib.sha256(str(ticket or "").encode("utf-8")).hexdigest()[:48]
    return _KEY_PREFIX + digest


def issue_handoff(db: Session, payload: dict[str, Any], ttl_seconds: int = _TTL_SECONDS) -> str:
    """Persist a short-lived, one-time handoff ticket in the shared database.

    Only a hash of the random ticket is stored as the Setting key. The value
    contains no password and no access token; the final admin JWT is created
    only after the browser consumes the ticket. This remains reliable when the
    backend uses multiple workers or restarts between issue and consume.
    """
    ticket = secrets.token_urlsafe(36)
    expires_at = time.time() + max(15, min(int(ttl_seconds), 180))
    row = Setting(
        key=_ticket_key(ticket),
        value=json.dumps({**payload, "expires_at": expires_at}, ensure_ascii=False, separators=(",", ":")),
    )
    db.merge(row)
    db.commit()
    return ticket


def consume_handoff(db: Session, ticket: str) -> dict[str, Any] | None:
    row = db.query(Setting).filter(Setting.key == _ticket_key(ticket)).first()
    if not row:
        return None
    raw = row.value or ""
    db.delete(row)
    db.commit()
    try:
        payload = json.loads(raw)
    except Exception:
        return None
    if not isinstance(payload, dict) or float(payload.get("expires_at") or 0) <= time.time():
        return None
    payload.pop("expires_at", None)
    return payload
