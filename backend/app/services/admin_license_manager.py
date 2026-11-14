from __future__ import annotations

import secrets
import string
from datetime import datetime, timedelta

from sqlalchemy import update
from sqlalchemy.orm import Session

from app.models import Admin, AdminAccessLicense, AdminRole, ConnectionLog, VpnUser, XrayUsageCounter
from app.services.server_targets import serialize_admin_targets, targets_for_admin_license

GB = 1_073_741_824
_CODE_ALPHABET = string.ascii_uppercase + string.digits


def generate_code(db: Session) -> str:
    """Generate a readable, uppercase and case-sensitive one-time key.

    New internal admin licenses use exactly four groups of five characters,
    for example: ``XQ5NU-2QKH7-87CAS-AH74S``.  The historical ``ADM-``
    prefix is intentionally no longer generated.
    """
    for _ in range(50):
        groups = ["".join(secrets.choice(_CODE_ALPHABET) for _ in range(5)) for _ in range(4)]
        code = "-".join(groups)
        if not db.query(AdminAccessLicense.id).filter(AdminAccessLicense.code == code).first():
            return code
    raise RuntimeError("ساخت کد یکتای لایسنس ناموفق بود")


def expiry_for(license_row: AdminAccessLicense, activated_at: datetime) -> datetime | None:
    if license_row.expire_mode == "fixed":
        return license_row.fixed_expire_at
    if license_row.duration_minutes:
        return activated_at + timedelta(minutes=max(1, int(license_row.duration_minutes)))
    return None


def is_expired(admin: Admin, now: datetime | None = None) -> bool:
    # لایسنس داخلی می‌تواند برای ادمین زیرمجموعه یا سوپرادمین صادر شود؛ هر
    # حسابی که واقعاً با لایسنس مدیریت می‌شود باید انقضای خودش را رعایت کند.
    if not bool(admin.managed_by_license):
        return False
    now = now or datetime.utcnow()
    return bool(admin.license_locked or (admin.subscription_expire_at and admin.subscription_expire_at <= now))


def remaining_seconds(admin: Admin, now: datetime | None = None) -> int | None:
    if not admin.subscription_expire_at:
        return None
    now = now or datetime.utcnow()
    return max(0, int((admin.subscription_expire_at - now).total_seconds()))


def _sync_auth_files(db: Session) -> None:
    # Best effort: DB state is authoritative. Individual optional protocols may
    # not be installed on every server.
    try:
        from app.services.vpn_manager import sync_chap_secrets, sync_ikev2_secrets, sync_openconnect_secrets
        sync_chap_secrets(db)
        sync_ikev2_secrets(db)
        sync_openconnect_secrets(db)
    except Exception:
        pass
    try:
        from app.services.xray_manager import sync_xray_users
        sync_xray_users(db, protocols=("vmess", "vless"), restart=True)
    except Exception:
        pass


def _disconnect_owned_users(db: Session, admin_id: int) -> None:
    users = db.query(VpnUser).filter(VpnUser.owner_admin_id == admin_id).all()
    try:
        from app.services.vpn_manager import (
            kill_ppp_session, kill_sstp_session, kill_openvpn_session,
            kill_ikev2_session, kill_openconnect_session,
        )
    except Exception:
        return
    for user in users:
        try: kill_ppp_session(db, user.username)
        except Exception: pass
        try: kill_sstp_session(db, user.username)
        except Exception: pass
        try: kill_openvpn_session(user.username)
        except Exception: pass
        try: kill_ikev2_session(db, user.username)
        except Exception: pass
        try: kill_openconnect_session(user.username)
        except Exception: pass
        try:
            from app.services.xray_manager import disconnect_xray_session
            disconnect_xray_session(db, user.username, protocol="vmess")
            disconnect_xray_session(db, user.username, protocol="vless")
        except Exception:
            pass


def lock_admin(db: Session, admin: Admin, *, disconnect: bool = True) -> bool:
    """Lock a licensed admin account once.

    For delegated admins the historical behavior is preserved: their owned VPN
    users are disabled as well. A licensed superadmin only loses panel access;
    expiring an operator account must not shut down every VPN user it may own.
    """
    if not bool(admin.managed_by_license):
        return False
    if admin.license_locked:
        return False
    admin.license_locked = True

    owned = []
    if admin.role == AdminRole.admin:
        owned = db.query(VpnUser).filter(VpnUser.owner_admin_id == admin.id).all()
        for user in owned:
            user.is_active = False
        if owned:
            db.query(ConnectionLog).filter(
                ConnectionLog.user_id.in_([u.id for u in owned]),
                ConnectionLog.is_online == True,  # noqa: E712
            ).update(
                {ConnectionLog.is_online: False, ConnectionLog.disconnect_time: datetime.utcnow()},
                synchronize_session=False,
            )

    db.commit()
    if admin.role == AdminRole.admin:
        _sync_auth_files(db)
        if disconnect:
            _disconnect_owned_users(db, admin.id)
    return True


def enforce_expirations(db: Session) -> int:
    now = datetime.utcnow()
    rows = db.query(Admin).filter(
        Admin.managed_by_license == True,  # noqa: E712
        Admin.license_locked == False,  # noqa: E712
        Admin.subscription_expire_at.isnot(None),
        Admin.subscription_expire_at <= now,
    ).all()
    changed = 0
    for admin in rows:
        if lock_admin(db, admin):
            changed += 1
    return changed


def _license_role(license_row: AdminAccessLicense) -> AdminRole:
    raw = getattr(license_row, "role", AdminRole.admin) or AdminRole.admin
    return raw if isinstance(raw, AdminRole) else AdminRole(str(raw))


def apply_license(db: Session, admin: Admin, license_row: AdminAccessLicense) -> Admin:
    """Replace an internal admin plan with a new one; limits never accumulate."""
    license_role = _license_role(license_row)
    if admin.role != license_role:
        expected = "سوپرادمین" if admin.role == AdminRole.superadmin else "ادمین زیرمجموعه"
        supplied = "سوپرادمین" if license_role == AdminRole.superadmin else "ادمین زیرمجموعه"
        raise ValueError(f"این حساب {expected} است اما این لایسنس برای {supplied} ساخته شده است")
    if license_row.code != license_row.code.upper():
        raise ValueError("ساختار کد لایسنس معتبر نیست")
    if not license_row.is_active:
        raise ValueError("این لایسنس غیرفعال است")
    if license_row.used_by_admin_id is not None:
        if license_row.used_by_admin_id == admin.id and admin.access_license_code == license_row.code:
            raise ValueError("این همان لایسنس فعال فعلی است")
        raise ValueError("این لایسنس قبلاً استفاده شده است")

    now = datetime.utcnow()
    expires = expiry_for(license_row, now)
    if expires is not None and expires <= now:
        raise ValueError("تاریخ این لایسنس گذشته است")

    if license_role == AdminRole.superadmin:
        # Superadmin permissions are implicit throughout the panel. Keep all
        # delegated-admin fields empty so no stale scope can accidentally leak
        # into a future role change.
        admin.permissions = None
        admin.see_all_users = False
        admin.server_targets = None
        admin.max_users = None
        admin.max_total_quota_bytes = None
    else:
        admin.permissions = license_row.permissions
        admin.see_all_users = bool(license_row.see_all_users)
        admin.server_targets = serialize_admin_targets(targets_for_admin_license(license_row))
        admin.max_users = license_row.max_users
        admin.max_total_quota_bytes = license_row.max_total_quota_bytes

    admin.subscription_expire_at = expires
    admin.subscription_expire_date = expires.date() if expires else None
    admin.managed_by_license = True
    admin.license_locked = False
    admin.license_activated_at = now
    admin.access_license_code = license_row.code
    # The license grants bot capability; the registering admin chooses whether
    # to bind a private Telegram account.  Never force or pre-bind an ID from
    # the license itself.
    if not bool(getattr(license_row, "telegram_bot_enabled", False)):
        admin.telegram_bot_enabled = False
        admin.telegram_user_id = None
    else:
        admin.telegram_bot_enabled = bool(getattr(admin, "telegram_user_id", None))
    admin.is_active = True

    # Claim the one-time license with a single conditional UPDATE. This is the
    # transaction boundary that prevents two simultaneous registration requests
    # from consuming the same code after both observed it as unused.
    claimed = db.execute(
        update(AdminAccessLicense)
        .where(
            AdminAccessLicense.id == license_row.id,
            AdminAccessLicense.used_by_admin_id.is_(None),
            AdminAccessLicense.is_active.is_(True),
        )
        .values(used_by_admin_id=admin.id, activated_at=now)
    )
    if int(claimed.rowcount or 0) != 1:
        db.rollback()
        raise ValueError("این لایسنس هم‌زمان توسط حساب دیگری استفاده شد؛ یک کد جدید وارد کنید")
    license_row.used_by_admin_id = admin.id
    license_row.activated_at = now

    # Renewal of a delegated admin keeps the previous behavior and re-enables
    # its owned users. A superadmin license only controls the operator account.
    if license_role == AdminRole.admin:
        owned = db.query(VpnUser).filter(VpnUser.owner_admin_id == admin.id).all()
        user_ids = [u.id for u in owned]
        for user in owned:
            user.used_bytes = 0
            user.is_active = True
        if user_ids:
            db.query(XrayUsageCounter).filter(XrayUsageCounter.user_id.in_(user_ids)).delete(synchronize_session=False)
            db.query(ConnectionLog).filter(ConnectionLog.user_id.in_(user_ids), ConnectionLog.is_online == True).update(  # noqa: E712
                {ConnectionLog.bytes_in: 0, ConnectionLog.bytes_out: 0}, synchronize_session=False
            )

    db.commit()
    db.refresh(admin)
    if license_role == AdminRole.admin:
        _sync_auth_files(db)
        try:
            from app.services.rate_limiter import reconcile_shared_rate_limits
            reconcile_shared_rate_limits(db, force=True)
        except Exception:
            pass
    return admin
