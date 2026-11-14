"""Shared lifecycle helpers for VPN user accounts.

A successful, confirmed tunnel must start ``after_first_connect`` expiry exactly
once. Keeping this rule in one helper prevents traffic samplers, remote nodes,
and protocols without a synchronous connect hook from increasing usage while
the UI still shows «هنوز وصل نشده».
"""
from datetime import datetime, timedelta, timezone

from app.models import VpnUser


def _naive_utc(value: datetime) -> datetime:
    """Return a database-friendly naive UTC datetime."""
    if value.tzinfo is None:
        return value
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def refresh_after_first_expiry(user: VpnUser) -> bool:
    """Recalculate expiry from the confirmed first connection when applicable."""
    if user.expire_mode != "after_first_connect":
        return False

    expected = None
    if user.first_connect_at is not None and int(user.expire_after_days or 0) > 0:
        expected = _naive_utc(user.first_connect_at).date() + timedelta(days=int(user.expire_after_days))
    if user.expire_date == expected:
        return False
    user.expire_date = expected
    return True


def ensure_first_connect(user: VpnUser, connected_at: datetime | None = None) -> bool:
    """Merge a confirmed connection timestamp into ``user``.

    In multi-node deployments reports can arrive out of order, so the earliest
    confirmed timestamp wins. The caller owns the surrounding DB transaction.
    """
    stamp = _naive_utc(connected_at or datetime.utcnow())
    existing = _naive_utc(user.first_connect_at) if user.first_connect_at is not None else None
    changed = existing is None or stamp < existing
    if changed:
        user.first_connect_at = stamp
    expiry_changed = refresh_after_first_expiry(user)
    return changed or expiry_changed
