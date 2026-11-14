from __future__ import annotations

import hashlib
import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

from app.client_ip import request_client_ip

_LOCK = threading.RLock()
_EVENTS: dict[str, deque[float]] = defaultdict(deque)
_MAX_BUCKETS = 20000


def _identity(value: str | None) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return "-"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _prune(now: float) -> None:
    if len(_EVENTS) <= _MAX_BUCKETS:
        return
    stale = [key for key, events in _EVENTS.items() if not events or now - events[-1] > 3600]
    for key in stale[: max(1, len(_EVENTS) - _MAX_BUCKETS)]:
        _EVENTS.pop(key, None)


def enforce_rate_limit(
    request: Request,
    *,
    bucket: str,
    limit: int,
    window_seconds: int,
    identity: str | None = None,
) -> None:
    now = time.monotonic()
    ip = request_client_ip(request)
    key = f"{bucket}:{ip}:{_identity(identity)}"
    window = max(1, int(window_seconds))
    cap = max(1, int(limit))
    with _LOCK:
        events = _EVENTS[key]
        while events and now - events[0] >= window:
            events.popleft()
        if len(events) >= cap:
            retry_after = max(1, int(window - (now - events[0])))
            raise HTTPException(
                status_code=429,
                detail="درخواست‌های بیش از حد مجاز؛ کمی بعد دوباره تلاش کنید",
                headers={"Retry-After": str(retry_after)},
            )
        events.append(now)
        _prune(now)


def clear_rate_limit(request: Request, *, bucket: str, identity: str | None = None) -> None:
    ip = request_client_ip(request)
    key = f"{bucket}:{ip}:{_identity(identity)}"
    with _LOCK:
        _EVENTS.pop(key, None)
