from __future__ import annotations

from datetime import date, timedelta
from typing import Iterable

GB = 1_073_741_824


def apply_bulk_increase(users: Iterable, *, quota_gb: float, days: int, reactivate: bool) -> dict[str, int]:
    """Mutate a group of VPN users using safe unlimited semantics.

    A zero quota or a missing expiry date means unlimited and is intentionally
    kept unlimited. Users waiting for their first connection receive extra
    ``expire_after_days`` instead of being converted to a fixed date.
    """
    users = list(users)
    add_bytes = int(max(0.0, float(quota_gb or 0)) * GB)
    add_days = max(0, int(days or 0))
    today = date.today()
    result = {
        "matched": len(users),
        "quota_updated": 0,
        "expiry_updated": 0,
        "reactivated": 0,
        "unlimited_quota_unchanged": 0,
        "unlimited_expiry_unchanged": 0,
    }

    for user in users:
        if add_bytes > 0:
            if int(user.quota_bytes or 0) == 0:
                result["unlimited_quota_unchanged"] += 1
            else:
                user.quota_bytes = int(user.quota_bytes or 0) + add_bytes
                result["quota_updated"] += 1

        if add_days > 0:
            if user.expire_mode == "after_first_connect" and user.first_connect_at is None:
                user.expire_after_days = int(user.expire_after_days or 0) + add_days
                result["expiry_updated"] += 1
            elif user.expire_date is None:
                result["unlimited_expiry_unchanged"] += 1
            else:
                user.expire_date = max(user.expire_date, today) + timedelta(days=add_days)
                result["expiry_updated"] += 1

        if reactivate and not user.is_active:
            expired = user.expire_date is not None and user.expire_date < today
            over_quota = int(user.quota_bytes or 0) > 0 and int(user.used_bytes or 0) >= int(user.quota_bytes or 0)
            if not expired and not over_quota:
                user.is_active = True
                result["reactivated"] += 1

    return result
