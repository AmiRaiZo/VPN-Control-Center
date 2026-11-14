from datetime import date
import secrets
from html import escape
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models import Admin, AdminRole, VpnUser, AdminAccessLicense, BannedIP, InternetBlockedIP, ConnectionLog, XrayUsageCounter, VpnNode, TelegramAdminGroup, TelegramGroupLinkCode
from app.schemas import AdminCreate, AdminUpdate, AdminOut, AdminPasswordSetRequest, AdminAccessLicenseCreate, AdminAccessLicenseOut, AdminInternalLicenseActivateRequest
from app.security import require_superadmin, hash_password, get_current_admin_allow_locked
from app.services.telegram_notifier import log_event
from app.services.admin_license_manager import generate_code, apply_license, is_expired
from app.services.server_targets import serialize_admin_targets, targets_for_admin, targets_for_admin_license, validate_admin_target_tokens, local_assignment_enabled
from app.services.vpn_manager import (
    sync_chap_secrets, kill_ppp_session, kill_openvpn_session, kill_ikev2_session,
    kill_openconnect_session, kill_sstp_session,
)
from app.services.cert_manager import revoke_client_cert
from app.services.xray_manager import sync_xray_users, disconnect_xray_session
from app.services.rate_limiter import reconcile_shared_rate_limits
from app.services.online_sessions import server_datetime_payload
from app.services.node_remote import encrypt_password, decrypt_password
from app.services.node_admin_handoff import issue_handoff

router = APIRouter(prefix="/api/admins", tags=["admins"])

GB = 1_073_741_824


def _usage_for(db: Session, admin_id: int) -> tuple[int, int]:
    """(تعداد یوزر ساخته‌شده توسط این ادمین, مجموع used_bytes واقعیِ یوزرهای او)
    توجه: عمداً quota_bytes (حجم تخصیص‌داده‌شده/فروخته‌شده) جمع زده نمی‌شود،
    چون صرفِ تنظیم حجم برای یک کاربر نباید سقف/پول حجمی ادمین را مصرف کند؛
    فقط مصرف واقعی (used_bytes) باید حساب شود."""
    used_users = db.query(VpnUser).filter(VpnUser.owner_admin_id == admin_id).count()
    used_quota = (
        db.query(func.coalesce(func.sum(VpnUser.used_bytes), 0))
        .filter(VpnUser.owner_admin_id == admin_id)
        .scalar()
    ) or 0
    return used_users, int(used_quota)


def _to_out(a: Admin, db: Session) -> AdminOut:
    perms = [p for p in (a.permissions or "").split(",") if p]
    used_users, used_quota = _usage_for(db, a.id)
    return AdminOut(
        id=a.id,
        username=a.username,
        role=a.role.value,
        permissions=perms,
        see_all_users=bool(a.see_all_users),
        server_targets=sorted(targets_for_admin(a), key=lambda item: (item != "local", item)),
        is_active=a.is_active,
        created_at=a.created_at,
        last_login_at=server_datetime_payload(db, a.last_login_at)[0] if a.last_login_at else None,
        last_login_at_display=server_datetime_payload(db, a.last_login_at)[1] if a.last_login_at else None,
        max_users=a.max_users,
        max_total_quota_gb=(a.max_total_quota_bytes / GB) if a.max_total_quota_bytes is not None else None,
        subscription_expire_date=a.subscription_expire_date,
        subscription_expire_at=getattr(a, "subscription_expire_at", None),
        managed_by_license=bool(getattr(a, "managed_by_license", False)),
        access_license_code=getattr(a, "access_license_code", None),
        license_locked=bool(getattr(a, "license_locked", False)),
        telegram_bot_enabled=bool(getattr(a, "telegram_bot_enabled", False)),
        telegram_user_id=getattr(a, "telegram_user_id", None),
        used_users=used_users,
        used_total_quota_gb=round(used_quota / GB, 3),
        subscription_expired=bool(is_expired(a) or (a.subscription_expire_date and a.subscription_expire_date < date.today())),
        credential_saved=bool(getattr(a, "password_vault_enc", None)),
    )


_ADMIN_AUDIT_LABELS = {
    "username": "نام کاربری",
    "password_hash": "رمز عبور",
    "role": "نقش",
    "permissions": "دسترسی‌ها",
    "see_all_users": "مشاهده اطلاعات کل پنل",
    "server_targets": "سرورهای مجاز",
    "max_users": "حداکثر تعداد کاربر",
    "max_total_quota_bytes": "سقف حجم کل",
    "subscription_expire_date": "انقضای اشتراک",
    "is_active": "وضعیت حساب",
    "telegram_bot_enabled": "ربات خصوصی",
    "telegram_user_id": "آیدی تلگرام",
}


def _admin_snapshot(row: Admin) -> dict:
    role = row.role.value if isinstance(row.role, AdminRole) else str(row.role)
    permissions = sorted(p for p in (row.permissions or "").split(",") if p)
    targets = sorted(targets_for_admin(row), key=lambda item: (item != "local", item))
    return {
        "username": row.username,
        "password_hash": row.password_hash,
        "role": role,
        "permissions": permissions,
        "see_all_users": bool(row.see_all_users),
        "server_targets": targets,
        "max_users": row.max_users,
        "max_total_quota_bytes": row.max_total_quota_bytes,
        "subscription_expire_date": row.subscription_expire_date,
        "is_active": bool(row.is_active),
        "telegram_bot_enabled": bool(getattr(row, "telegram_bot_enabled", False)),
        "telegram_user_id": getattr(row, "telegram_user_id", None),
    }


def _admin_audit_value(field: str, value, *, changed: bool = False) -> str:
    if field == "password_hash":
        return "تغییر کرد؛ مقدار رمز برای امنیت در لاگ ذخیره نمی‌شود" if changed else "تعیین شد؛ مقدار رمز برای امنیت در لاگ ذخیره نمی‌شود"
    if field in {"see_all_users", "is_active", "telegram_bot_enabled"}:
        return "فعال" if bool(value) else "غیرفعال"
    if field == "max_users":
        return "نامحدود" if value in (None, 0, "") else str(value)
    if field == "max_total_quota_bytes":
        return "نامحدود" if value in (None, 0, "") else f"{int(value) / GB:.2f} GB"
    if field in {"permissions", "server_targets"}:
        return "، ".join(str(item) for item in (value or [])) or "هیچ‌کدام"
    if value in (None, ""):
        return "—"
    return str(value)


def _admin_change_log(username: str, before: dict, after: dict, *, created: bool = False) -> str:
    lines = [f"👤 ادمین: <code>{escape(str(username or '-'))}</code>"]
    changes = []
    for field, label in _ADMIN_AUDIT_LABELS.items():
        old = before.get(field)
        new = after.get(field)
        if not created and old == new:
            continue
        if field == "password_hash":
            if not new or (not created and old == new):
                continue
            changes.append(f"• {label}: <b>{escape(_admin_audit_value(field, new, changed=not created))}</b>")
            continue
        if created:
            changes.append(f"• {label}: <b>{escape(_admin_audit_value(field, new))}</b>")
        else:
            changes.append(
                f"• {label}: <b>{escape(_admin_audit_value(field, old))}</b> ← "
                f"<b>{escape(_admin_audit_value(field, new))}</b>"
            )
    lines.extend(changes or ["• تغییری در مقدارهای قابل ثبت انجام نشد."])
    return "\n".join(lines)


@router.get("", response_model=list[AdminOut])
def list_admins(db: Session = Depends(get_db), admin: Admin = Depends(require_superadmin)):
    admins = db.query(Admin).order_by(Admin.created_at.asc()).all()
    return [_to_out(a, db) for a in admins]


@router.get("/server-targets")
def admin_server_targets(db: Session = Depends(get_db), admin: Admin = Depends(require_superadmin)):
    targets = [{
        "id": "local", "name": "سرور اصلی", "local": True,
        "enabled": bool(local_assignment_enabled(db)),
    }]
    for row in db.query(VpnNode).order_by(VpnNode.id).all():
        targets.append({
            "id": f"node:{row.id}", "node_id": row.id, "name": row.name,
            "local": False, "enabled": bool(row.enabled),
            "user_assignment_enabled": bool(getattr(row, "user_assignment_enabled", True)),
            "status": row.status or "unknown",
        })
    return {"targets": targets}


@router.post("", response_model=AdminOut)
def create_admin(payload: AdminCreate, db: Session = Depends(get_db), admin: Admin = Depends(require_superadmin)):
    # چک یکتا بودن یوزرنیم نسبت به حروف بزرگ/کوچک حساس است (کالیشن ستون
    # utf8mb4_bin)؛ یعنی "Ali" و "ali" دو حساب جدا محسوب می‌شوند.
    exists = db.query(Admin).filter(Admin.username == payload.username).first()
    if exists:
        raise HTTPException(400, "این نام کاربری قبلاً استفاده شده است")
    if payload.telegram_bot_enabled and not payload.telegram_user_id:
        raise HTTPException(400, "برای فعال‌سازی ربات آیدی عددی تلگرام الزامی است")
    _ensure_telegram_id_available(db, payload.telegram_user_id if payload.telegram_bot_enabled else None)

    is_subadmin = payload.role == "admin"
    new_admin = Admin(
        username=payload.username,
        password_hash=hash_password(payload.password),
        password_vault_enc=encrypt_password(payload.password),
        role=AdminRole(payload.role),
        permissions=",".join(payload.permissions) if is_subadmin else None,
        # فقط برای role=admin معنا دارد؛ superadmin همیشه به همه چیز دسترسی دارد
        see_all_users=payload.see_all_users if is_subadmin else False,
        server_targets=(serialize_admin_targets(validate_admin_target_tokens(db, payload.server_targets)) if is_subadmin else None),
        max_users=payload.max_users if is_subadmin else None,
        max_total_quota_bytes=(
            int(payload.max_total_quota_gb * GB)
            if (is_subadmin and payload.max_total_quota_gb is not None)
            else None
        ),
        subscription_expire_date=payload.subscription_expire_date if is_subadmin else None,
        telegram_bot_enabled=bool(payload.telegram_bot_enabled),
        telegram_user_id=payload.telegram_user_id if payload.telegram_bot_enabled else None,
        telegram_bot_opted_out=False,
        is_active=True,
    )
    db.add(new_admin)
    db.commit()
    db.refresh(new_admin)
    log_event("➕ ساخت ادمین جدید", _admin_change_log(new_admin.username, {}, _admin_snapshot(new_admin), created=True), actor=admin.username)
    return _to_out(new_admin, db)


def _license_out(row: AdminAccessLicense, db: Session) -> AdminAccessLicenseOut:
    username = None
    if row.used_by_admin_id:
        target = db.query(Admin).get(row.used_by_admin_id)
        username = target.username if target else None
    role_value = getattr(row, "role", AdminRole.admin) or AdminRole.admin
    if isinstance(role_value, AdminRole):
        role_value = role_value.value
    return AdminAccessLicenseOut(
        id=row.id, code=row.code, role=str(role_value),
        permissions=[p for p in (row.permissions or "").split(",") if p],
        see_all_users=bool(row.see_all_users),
        server_targets=sorted(targets_for_admin_license(row), key=lambda item: (item != "local", item)),
        max_users=row.max_users,
        max_total_quota_gb=(row.max_total_quota_bytes / GB) if row.max_total_quota_bytes is not None else None,
        expire_mode=row.expire_mode, duration_minutes=row.duration_minutes,
        fixed_expire_at=row.fixed_expire_at, is_active=bool(row.is_active),
        used_by_admin_id=row.used_by_admin_id, used_by_username=username,
        activated_at=row.activated_at,
        telegram_bot_enabled=bool(getattr(row, "telegram_bot_enabled", False)),
        telegram_user_id=getattr(row, "telegram_user_id", None),
        note=row.note, created_at=row.created_at,
    )


def _ensure_telegram_id_available(db: Session, telegram_user_id: int | None, *, exclude_admin_id: int | None = None, exclude_license_id: int | None = None) -> None:
    if not telegram_user_id:
        return
    admin_query = db.query(Admin).filter(Admin.telegram_user_id == int(telegram_user_id))
    if exclude_admin_id is not None:
        admin_query = admin_query.filter(Admin.id != int(exclude_admin_id))
    if admin_query.first():
        raise HTTPException(400, "این آیدی تلگرام قبلاً به ادمین دیگری متصل شده است")
    license_query = db.query(AdminAccessLicense).filter(
        AdminAccessLicense.telegram_user_id == int(telegram_user_id),
        AdminAccessLicense.is_active == True,  # noqa: E712
        AdminAccessLicense.used_by_admin_id.is_(None),
    )
    if exclude_license_id is not None:
        license_query = license_query.filter(AdminAccessLicense.id != int(exclude_license_id))
    if license_query.first():
        raise HTTPException(400, "این آیدی تلگرام روی یک لایسنس فعال دیگر رزرو شده است")


@router.get("/licenses", response_model=list[AdminAccessLicenseOut])
def list_internal_licenses(db: Session = Depends(get_db), admin: Admin = Depends(require_superadmin)):
    rows = db.query(AdminAccessLicense).order_by(AdminAccessLicense.created_at.desc()).all()
    return [_license_out(row, db) for row in rows]


@router.post("/licenses", response_model=AdminAccessLicenseOut)
def create_internal_license(payload: AdminAccessLicenseCreate, db: Session = Depends(get_db), admin: Admin = Depends(require_superadmin)):
    is_subadmin = payload.role == "admin"
    row = AdminAccessLicense(
        code=generate_code(db), role=AdminRole(payload.role),
        permissions=",".join(payload.permissions) if is_subadmin else "",
        see_all_users=payload.see_all_users if is_subadmin else False,
        server_targets=(serialize_admin_targets(validate_admin_target_tokens(db, payload.server_targets)) if is_subadmin else None),
        max_users=payload.max_users if is_subadmin else None,
        max_total_quota_bytes=(int(payload.max_total_quota_gb * GB) if (is_subadmin and payload.max_total_quota_gb is not None) else None),
        expire_mode=payload.expire_mode, duration_minutes=payload.duration_minutes if payload.expire_mode == "after_activation" else None,
        fixed_expire_at=payload.fixed_expire_at if payload.expire_mode == "fixed" else None,
        is_active=True, telegram_bot_enabled=bool(payload.telegram_bot_enabled),
        telegram_user_id=None, note=payload.note,
    )
    db.add(row); db.commit(); db.refresh(row)
    log_event("🪪 ساخت لایسنس داخلی ادمین", f"کد: {row.code}", actor=admin.username)
    return _license_out(row, db)


@router.put("/licenses/{license_id}", response_model=AdminAccessLicenseOut)
def update_internal_license(license_id: int, payload: AdminAccessLicenseCreate, db: Session = Depends(get_db), admin: Admin = Depends(require_superadmin)):
    row = db.query(AdminAccessLicense).get(license_id)
    if not row:
        raise HTTPException(404, "لایسنس پیدا نشد")
    if row.used_by_admin_id is not None:
        raise HTTPException(400, "لایسنس استفاده‌شده قابل تغییر نیست؛ برای تمدید یک کد جدید بسازید")
    is_subadmin = payload.role == "admin"
    row.role = AdminRole(payload.role)
    row.permissions = ",".join(payload.permissions) if is_subadmin else ""
    row.see_all_users = payload.see_all_users if is_subadmin else False
    row.server_targets = serialize_admin_targets(validate_admin_target_tokens(db, payload.server_targets)) if is_subadmin else None
    row.max_users = payload.max_users if is_subadmin else None
    row.max_total_quota_bytes = int(payload.max_total_quota_gb * GB) if (is_subadmin and payload.max_total_quota_gb is not None) else None
    row.expire_mode=payload.expire_mode
    row.duration_minutes=payload.duration_minutes if payload.expire_mode == "after_activation" else None
    row.fixed_expire_at=payload.fixed_expire_at if payload.expire_mode == "fixed" else None
    row.telegram_bot_enabled = bool(payload.telegram_bot_enabled)
    row.telegram_user_id = None
    row.note=payload.note
    db.commit(); db.refresh(row)
    return _license_out(row, db)


@router.delete("/licenses/{license_id}")
def delete_internal_license(license_id: int, db: Session = Depends(get_db), admin: Admin = Depends(require_superadmin)):
    row = db.query(AdminAccessLicense).get(license_id)
    if not row:
        raise HTTPException(404, "لایسنس پیدا نشد")
    if row.used_by_admin_id is not None:
        row.is_active = False
        db.commit()
        return {"ok": True, "disabled": True}
    db.delete(row); db.commit()
    return {"ok": True}


@router.get("/my-license")
def my_internal_license(admin: Admin = Depends(get_current_admin_allow_locked)):
    from app.services.admin_license_manager import remaining_seconds
    return {
        "managed": bool(getattr(admin, "managed_by_license", False)),
        "locked": bool(is_expired(admin)),
        "code": getattr(admin, "access_license_code", None),
        "expire_at": getattr(admin, "subscription_expire_at", None),
        "remaining_seconds": remaining_seconds(admin),
        "max_users": admin.max_users,
        "max_total_quota_gb": (admin.max_total_quota_bytes / GB) if admin.max_total_quota_bytes is not None else None,
    }


@router.post("/my-license/activate")
def activate_my_internal_license(payload: AdminInternalLicenseActivateRequest, db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin_allow_locked)):
    row = db.query(AdminAccessLicense).filter(AdminAccessLicense.code == payload.license_code).first()
    if not row:
        raise HTTPException(400, "کد لایسنس داخلی نامعتبر است؛ حروف بزرگ و کوچک مهم هستند")
    try:
        apply_license(db, admin, row)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    log_event("🔄 تمدید ادمین با لایسنس داخلی", f"یوزرنیم: {admin.username} | کد: {row.code}", actor=admin.username)
    return {"ok": True, "permissions": [p for p in (admin.permissions or "").split(",") if p]}


@router.get("/{admin_id}/credentials")
def reveal_admin_credentials(
    admin_id: int,
    response: Response,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_superadmin),
):
    """Reveal the currently managed credential to the superadmin.

    Passwords created before the credential vault existed cannot be recovered
    from bcrypt. Once that admin logs in, or the superadmin sets a new password,
    the encrypted vault is populated and this endpoint can reveal it.
    """
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    target = db.query(Admin).get(admin_id)
    if not target:
        raise HTTPException(404, "ادمین پیدا نشد")
    if target.role != AdminRole.admin:
        raise HTTPException(400, "نمایش رمز فقط برای ادمین‌های زیرمجموعه مجاز است")
    password = decrypt_password(getattr(target, "password_vault_enc", None))
    log_event(
        "👁 مشاهده اطلاعات ورود ادمین",
        f"👤 ادمین: <code>{escape(target.username)}</code>\n"
        f"• وضعیت رمز ذخیره‌شده: <b>{'موجود' if password else 'ناموجود؛ نیازمند ورود یا تعیین رمز جدید'}</b>",
        actor=admin.username,
    )
    return {
        "username": target.username,
        "password": password,
        "available": bool(password),
        "managed": bool(password),
    }


@router.put("/{admin_id}/password")
def set_admin_password(
    admin_id: int,
    payload: AdminPasswordSetRequest,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_superadmin),
):
    target = db.query(Admin).get(admin_id)
    if not target:
        raise HTTPException(404, "ادمین پیدا نشد")
    if target.role != AdminRole.admin:
        raise HTTPException(400, "تغییر مستقیم رمز فقط برای ادمین‌های زیرمجموعه مجاز است")
    target.password_hash = hash_password(payload.password)
    target.password_vault_enc = encrypt_password(payload.password)
    db.commit()
    log_event(
        "🔑 تعیین رمز ادمین زیرمجموعه",
        f"👤 ادمین: <code>{escape(target.username)}</code>\n"
        "• رمز توسط سوپرادمین تعیین و در خزانه رمزگذاری‌شده به‌روزرسانی شد.\n"
        "• مقدار خام رمز در لاگ تلگرام ذخیره نشد.",
        actor=admin.username,
    )
    return {"username": target.username, "password": payload.password, "available": True, "managed": True}


@router.post("/{admin_id}/open-panel")
def open_subadmin_panel(
    admin_id: int,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_superadmin),
):
    target = db.query(Admin).get(admin_id)
    if not target:
        raise HTTPException(404, "ادمین پیدا نشد")
    if target.role != AdminRole.admin:
        raise HTTPException(400, "ورود مستقیم فقط برای ادمین‌های زیرمجموعه مجاز است")
    if not target.is_active:
        raise HTTPException(400, "حساب ادمین غیرفعال است")
    ticket = issue_handoff(db, {
        "kind": "subadmin",
        "admin_id": target.id,
        "username": target.username,
        "issued_by": admin.username,
        "redirect_path": "/dashboard",
    }, ttl_seconds=90)
    log_event(
        "🚪 ساخت ورود مستقیم ادمین زیرمجموعه",
        f"👤 مقصد: <code>{escape(target.username)}</code>\n• لینک یک‌بارمصرف ساخته شد.",
        actor=admin.username,
    )
    return {"ok": True, "url": f"/api/auth/admin-handoff/consume?ticket={ticket}"}


@router.post("/{admin_id}/reset-password")
def reset_admin_password(
    admin_id: int,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_superadmin),
):
    """Generate a new admin password and reveal it exactly once.

    Existing passwords are intentionally non-recoverable because only a one-way
    password hash is stored. The returned plaintext exists only in this HTTP
    response and is never written to logs or the database.
    """
    target = db.query(Admin).get(admin_id)
    if not target:
        raise HTTPException(404, "ادمین پیدا نشد")

    # token_urlsafe produces ASCII accepted by the current password validator
    # and is strong enough for interactive panel authentication.
    new_password = secrets.token_urlsafe(12)
    target.password_hash = hash_password(new_password)
    target.password_vault_enc = encrypt_password(new_password)
    db.commit()
    db.refresh(target)
    log_event(
        "🔑 بازنشانی رمز ادمین",
        f"👤 ادمین: <code>{escape(target.username)}</code>\n• رمز جدید ساخته شد و فقط یک‌بار در پنل نمایش داده شد.",
        actor=admin.username,
    )
    return {
        "username": target.username,
        "password": new_password,
        "one_time": True,
    }


@router.put("/{admin_id}", response_model=AdminOut)
def update_admin(
    admin_id: int,
    payload: AdminUpdate,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_superadmin),
):
    target = db.query(Admin).get(admin_id)
    if not target:
        raise HTTPException(404, "ادمین پیدا نشد")
    audit_before = _admin_snapshot(target)

    if target.id == admin.id and payload.is_active is False:
        raise HTTPException(400, "نمی‌توانید حساب خودتان را غیرفعال کنید")
    if target.id == admin.id and payload.role and payload.role != "superadmin":
        raise HTTPException(400, "نمی‌توانید نقش خودتان را تغییر دهید")

    if payload.password:
        target.password_hash = hash_password(payload.password)
        target.password_vault_enc = encrypt_password(payload.password)
    if payload.role is not None:
        target.role = AdminRole(payload.role)
    if payload.permissions is not None:
        target.permissions = ",".join(payload.permissions)
    if payload.see_all_users is not None:
        target.see_all_users = payload.see_all_users
    if payload.server_targets is not None:
        target.server_targets = serialize_admin_targets(validate_admin_target_tokens(db, payload.server_targets))

    # سقف تعداد یوزر
    if payload.clear_max_users:
        target.max_users = None
    elif payload.max_users is not None:
        target.max_users = payload.max_users

    # سقف حجم کل (استخر مشترک بین یوزرهای این ادمین)
    if payload.clear_max_total_quota:
        target.max_total_quota_bytes = None
    elif payload.max_total_quota_gb is not None:
        target.max_total_quota_bytes = int(payload.max_total_quota_gb * GB)

    # تاریخ انقضای اشتراک این ادمین
    if payload.clear_subscription_expire_date:
        target.subscription_expire_date = None
    elif payload.subscription_expire_date is not None:
        target.subscription_expire_date = payload.subscription_expire_date

    if payload.is_active is not None:
        target.is_active = payload.is_active
    if payload.telegram_bot_enabled is not None:
        target.telegram_bot_enabled = bool(payload.telegram_bot_enabled)
        if not target.telegram_bot_enabled:
            target.telegram_user_id = None
            target.telegram_bot_opted_out = False
    if payload.clear_telegram_user_id:
        target.telegram_user_id = None
        target.telegram_bot_opted_out = False
    elif payload.telegram_user_id is not None:
        _ensure_telegram_id_available(db, payload.telegram_user_id, exclude_admin_id=target.id)
        target.telegram_user_id = payload.telegram_user_id
        target.telegram_bot_enabled = True
        target.telegram_bot_opted_out = False
        if getattr(target, "access_license_code", None):
            license_row = db.query(AdminAccessLicense).filter(
                AdminAccessLicense.code == target.access_license_code,
                AdminAccessLicense.used_by_admin_id == target.id,
            ).first()
            if license_row and bool(getattr(license_row, "telegram_bot_enabled", False)):
                if license_row.telegram_user_id not in (None, payload.telegram_user_id):
                    raise HTTPException(400, "لایسنس این حساب قبلاً به آیدی تلگرام دیگری متصل شده است")
                license_row.telegram_user_id = payload.telegram_user_id

    if target.role == AdminRole.admin and not (target.permissions or "").strip():
        raise HTTPException(400, "برای ادمین زیرمجموعه باید حداقل یک بخش دسترسی انتخاب شود")

    if target.role == AdminRole.superadmin:
        # این فیلدها فقط برای ادمین زیرمجموعه معنا دارند
        target.see_all_users = False
        target.max_users = None
        target.max_total_quota_bytes = None
        target.subscription_expire_date = None
        target.server_targets = None

    db.commit()
    db.refresh(target)
    log_event("✏️ ویرایش ادمین", _admin_change_log(target.username, audit_before, _admin_snapshot(target)), actor=admin.username)
    return _to_out(target, db)


@router.delete("/{admin_id}")
def delete_admin(
    admin_id: int,
    user_action: str = "transfer",
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_superadmin),
):
    """Delete a sub-admin and explicitly decide what happens to owned VPN users.

    ``transfer`` keeps every VPN user and moves ownership to the super-admin
    performing the deletion. ``delete`` permanently removes those VPN users,
    their online/history rows and Xray runtime counters before deleting the
    admin. The default remains ``transfer`` for backward compatibility with
    older frontends.
    """
    target = db.query(Admin).get(admin_id)
    if not target:
        raise HTTPException(404, "ادمین پیدا نشد")
    if target.id == admin.id:
        raise HTTPException(400, "نمی‌توانید حساب خودتان را حذف کنید")
    if user_action not in {"transfer", "delete"}:
        raise HTTPException(400, "نحوه برخورد با کاربران نامعتبر است")

    username = target.username
    owned_users = db.query(VpnUser).filter(VpnUser.owner_admin_id == target.id).all()
    owned_user_ids = [u.id for u in owned_users]
    owned_usernames = [u.username for u in owned_users]
    transferred_users = 0
    deleted_users = 0

    # Stop live sessions before deleting credentials. These are best-effort: a
    # missing/disabled protocol must not leave the database transaction half done.
    if user_action == "delete":
        for vpn_user in owned_users:
            for stopper in (
                lambda: kill_ppp_session(db, vpn_user.username),
                lambda: kill_sstp_session(db, vpn_user.username),
                lambda: kill_openvpn_session(vpn_user.username),
                lambda: kill_ikev2_session(db, vpn_user.username),
                lambda: kill_openconnect_session(vpn_user.username),
                lambda: disconnect_xray_session(db, vpn_user.username),
            ):
                try:
                    stopper()
                except Exception:
                    pass

    try:
        if user_action == "transfer":
            transferred_users = db.query(VpnUser).filter(
                VpnUser.owner_admin_id == target.id
            ).update(
                {VpnUser.owner_admin_id: admin.id},
                synchronize_session=False,
            )
        else:
            if owned_user_ids:
                db.query(XrayUsageCounter).filter(
                    XrayUsageCounter.user_id.in_(owned_user_ids)
                ).delete(synchronize_session=False)
                db.query(ConnectionLog).filter(
                    ConnectionLog.user_id.in_(owned_user_ids)
                ).delete(synchronize_session=False)
                deleted_users = db.query(VpnUser).filter(
                    VpnUser.id.in_(owned_user_ids)
                ).delete(synchronize_session=False)

        # Preserve audit/history rows, but detach every FK that points at the
        # admin being removed. Used internal licenses stay permanently disabled.
        db.query(AdminAccessLicense).filter(
            AdminAccessLicense.used_by_admin_id == target.id
        ).update(
            {
                AdminAccessLicense.used_by_admin_id: None,
                AdminAccessLicense.is_active: False,
            },
            synchronize_session=False,
        )
        db.query(BannedIP).filter(
            BannedIP.banned_by_admin_id == target.id
        ).update(
            {BannedIP.banned_by_admin_id: None},
            synchronize_session=False,
        )
        # Ownership-scoped security records must not become invisible or orphaned
        # after removing a delegated admin. Transfer their scope to the
        # superadmin performing the deletion, regardless of how VPN users are
        # handled.
        db.query(BannedIP).filter(
            BannedIP.owner_admin_id == target.id
        ).update(
            {BannedIP.owner_admin_id: admin.id},
            synchronize_session=False,
        )
        db.query(InternetBlockedIP).filter(
            InternetBlockedIP.owner_admin_id == target.id
        ).update(
            {InternetBlockedIP.owner_admin_id: admin.id},
            synchronize_session=False,
        )
        # Telegram groups are explicitly owned by this admin and must never
        # silently inherit superadmin scope after account deletion.
        db.query(TelegramGroupLinkCode).filter(
            TelegramGroupLinkCode.admin_id == target.id
        ).delete(synchronize_session=False)
        db.query(TelegramAdminGroup).filter(
            TelegramAdminGroup.admin_id == target.id
        ).delete(synchronize_session=False)

        db.delete(target)
        db.commit()
    except Exception as exc:
        db.rollback()
        raise HTTPException(
            500,
            "حذف ادمین کامل نشد و هیچ تغییری ذخیره نشد. "
            f"جزئیات دیتابیس: {str(exc)[:500]}",
        ) from exc

    # Refresh protocol credential stores only after the DB transaction succeeds.
    # A service-side warning is reported in the response but does not resurrect
    # deleted database rows.
    cleanup_warnings = []
    if user_action == "delete" and deleted_users:
        try:
            sync_chap_secrets(db)
        except Exception as exc:
            cleanup_warnings.append(f"PPP sync: {str(exc)[:180]}")
        try:
            sync_xray_users(db, protocols=("vmess", "vless"), restart=True)
        except Exception as exc:
            cleanup_warnings.append(f"Xray sync: {str(exc)[:180]}")
        try:
            reconcile_shared_rate_limits(db, force=True)
        except Exception as exc:
            cleanup_warnings.append(f"rate limits: {str(exc)[:180]}")
        for owned_username in owned_usernames:
            try:
                revoke_client_cert(owned_username)
            except Exception as exc:
                cleanup_warnings.append(f"cert {owned_username}: {str(exc)[:120]}")

    action_text = (
        f"انتقال کاربران به {admin.username}: {transferred_users}"
        if user_action == "transfer"
        else f"حذف کاربران متعلق به ادمین: {deleted_users}"
    )
    log_event(
        "🗑 حذف ادمین",
        f"یوزرنیم: {username} | {action_text}",
        actor=admin.username,
    )
    return {
        "ok": True,
        "user_action": user_action,
        "transferred_users": transferred_users,
        "deleted_users": deleted_users,
        "cleanup_warnings": cleanup_warnings,
    }
