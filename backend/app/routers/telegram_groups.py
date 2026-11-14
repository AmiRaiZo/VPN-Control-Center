from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Admin, AdminRole, TelegramAdminGroup, TelegramGroupLinkCode, TelegramGroupMemberRule
from app.security import get_current_admin
from app.services.telegram_groups import (
    admin_can_manage_group,
    create_link_code,
    normalize_access_mode,
    serialize_group,
    serialize_member_rule,
    upsert_member_rule,
    utcnow,
)
from app.services.telegram_notifier import call_telegram_api, get_telegram_config, log_event

router = APIRouter(prefix="/api/telegram-groups", tags=["telegram-groups"])


class TelegramGroupUpdate(BaseModel):
    is_active: bool | None = None
    control_enabled: bool | None = None
    access_mode: str | None = None


class TelegramGroupMemberRuleUpsert(BaseModel):
    telegram_user_id: int | str
    status: str
    display_name: str | None = None
    telegram_username: str | None = None
    note: str | None = None


def _bot_status(db: Session) -> dict:
    cfg = get_telegram_config(db)
    token = str(cfg.get("bot_token") or "")
    return {
        "configured": bool(token),
        "control_enabled": bool(cfg.get("control_enabled")),
        "available": bool(token and cfg.get("control_enabled")),
    }


def _require_group_access(db: Session, admin: Admin, group_id: int) -> TelegramAdminGroup:
    row = db.query(TelegramAdminGroup).filter(TelegramAdminGroup.id == int(group_id)).first()
    if not row:
        raise HTTPException(404, "گروه پیدا نشد")
    if not admin_can_manage_group(admin, row):
        raise HTTPException(403, "این گروه متعلق به حساب شما نیست")
    return row


@router.get("")
def list_my_telegram_groups(
    db: Session = Depends(get_db),
    admin: Admin = Depends(get_current_admin),
):
    rows = db.query(TelegramAdminGroup).filter(
        TelegramAdminGroup.admin_id == admin.id
    ).order_by(TelegramAdminGroup.created_at.desc()).all()
    return {
        "bot": _bot_status(db),
        "admin": {
            "id": admin.id,
            "username": admin.username,
            "role": admin.role.value,
            "telegram_bot_enabled": bool(getattr(admin, "telegram_bot_enabled", False)),
            "telegram_user_id": str(admin.telegram_user_id) if getattr(admin, "telegram_user_id", None) else None,
        },
        "groups": [serialize_group(row) for row in rows],
    }


@router.get("/all")
def list_all_telegram_groups(
    db: Session = Depends(get_db),
    admin: Admin = Depends(get_current_admin),
):
    if admin.role != AdminRole.superadmin:
        raise HTTPException(403, "دسترسی غیرمجاز")
    rows = db.query(TelegramAdminGroup).order_by(
        TelegramAdminGroup.admin_id.asc(), TelegramAdminGroup.created_at.desc()
    ).all()
    return {
        "bot": _bot_status(db),
        "groups": [serialize_group(row, include_owner=True) for row in rows],
    }


@router.post("/link-code")
def issue_telegram_group_link_code(
    db: Session = Depends(get_db),
    admin: Admin = Depends(get_current_admin),
):
    cfg = get_telegram_config(db)
    if not cfg.get("bot_token") or not cfg.get("control_enabled"):
        raise HTTPException(409, "ابتدا سوپرادمین باید توکن و ربات کنترل تلگرام را فعال کند")
    try:
        code, expires_at = create_link_code(db, admin)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    bot_username = None
    ok, result = call_telegram_api(
        str(cfg.get("bot_token") or ""), "getMe", timeout=8, max_attempts=1
    )
    if ok and isinstance(result, dict):
        bot_username = str(result.get("username") or "").strip() or None
    command = f"/connect {code}"
    command_with_username = f"/connect@{bot_username} {code}" if bot_username else command
    return {
        "ok": True,
        "code": code,
        "expires_at": expires_at,
        "expires_in_seconds": max(0, int((expires_at - utcnow()).total_seconds())),
        "command": command,
        "command_with_username": command_with_username,
        "bot_username": bot_username,
    }


@router.patch("/{group_id}")
def update_telegram_group(
    group_id: int,
    payload: TelegramGroupUpdate,
    db: Session = Depends(get_db),
    admin: Admin = Depends(get_current_admin),
):
    row = _require_group_access(db, admin, group_id)
    if payload.is_active is not None:
        row.is_active = bool(payload.is_active)
    if payload.control_enabled is not None:
        row.control_enabled = bool(payload.control_enabled)
    if payload.access_mode is not None:
        try:
            row.access_mode = normalize_access_mode(payload.access_mode)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
    db.commit()
    db.refresh(row)
    log_event(
        "⚙️ تغییر وضعیت گروه تلگرام",
        f"گروه: {row.title or row.chat_id} | chat_id={row.chat_id} | active={int(row.is_active)} | control={int(row.control_enabled)} | access={row.access_mode}",
        actor=admin.username,
    )
    return serialize_group(row, include_owner=admin.role == AdminRole.superadmin)


@router.get("/{group_id}/members")
def list_telegram_group_member_rules(
    group_id: int,
    db: Session = Depends(get_db),
    admin: Admin = Depends(get_current_admin),
):
    row = _require_group_access(db, admin, group_id)
    rules = db.query(TelegramGroupMemberRule).filter(
        TelegramGroupMemberRule.group_id == row.id
    ).order_by(
        TelegramGroupMemberRule.is_allowed.desc(),
        TelegramGroupMemberRule.updated_at.desc(),
    ).all()
    return {
        "group": serialize_group(row, include_owner=admin.role == AdminRole.superadmin),
        "rules": [serialize_member_rule(item) for item in rules],
    }


@router.put("/{group_id}/members")
def upsert_telegram_group_member_rule(
    group_id: int,
    payload: TelegramGroupMemberRuleUpsert,
    db: Session = Depends(get_db),
    admin: Admin = Depends(get_current_admin),
):
    group = _require_group_access(db, admin, group_id)
    status = str(payload.status or "").strip().lower()
    if status not in {"allow", "deny"}:
        raise HTTPException(400, "وضعیت باید allow یا deny باشد")
    try:
        rule = upsert_member_rule(
            db,
            group=group,
            telegram_user_id=payload.telegram_user_id,
            is_allowed=status == "allow",
            actor_admin_id=admin.id,
            display_name=payload.display_name,
            telegram_username=payload.telegram_username,
            note=payload.note,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    db.commit()
    db.refresh(rule)
    log_event(
        "👤 تغییر دسترسی عضو گروه تلگرام",
        f"گروه: {group.title or group.chat_id} | user_id={rule.telegram_user_id} | status={'allow' if rule.is_allowed else 'deny'}",
        actor=admin.username,
    )
    return serialize_member_rule(rule)


@router.delete("/{group_id}/members/{telegram_user_id}")
def delete_telegram_group_member_rule(
    group_id: int,
    telegram_user_id: int,
    db: Session = Depends(get_db),
    admin: Admin = Depends(get_current_admin),
):
    group = _require_group_access(db, admin, group_id)
    rule = db.query(TelegramGroupMemberRule).filter(
        TelegramGroupMemberRule.group_id == group.id,
        TelegramGroupMemberRule.telegram_user_id == int(telegram_user_id),
    ).first()
    if not rule:
        raise HTTPException(404, "قانون دسترسی این عضو پیدا نشد")
    db.delete(rule)
    db.commit()
    log_event(
        "🧹 حذف قانون دسترسی عضو گروه تلگرام",
        f"گروه: {group.title or group.chat_id} | user_id={telegram_user_id}",
        actor=admin.username,
    )
    return {"ok": True}


@router.post("/{group_id}/test")
def test_telegram_group(
    group_id: int,
    db: Session = Depends(get_db),
    admin: Admin = Depends(get_current_admin),
):
    row = _require_group_access(db, admin, group_id)
    cfg = get_telegram_config(db)
    token = str(cfg.get("bot_token") or "")
    if not token or not cfg.get("control_enabled"):
        raise HTTPException(409, "ربات کنترل تلگرام فعال یا تنظیم نشده است")
    ok, result = call_telegram_api(
        token,
        "sendMessage",
        data={
            "chat_id": str(row.chat_id),
            "parse_mode": "HTML",
            "text": (
                "✅ <b>اتصال این گروه به VPN Panel فعال است.</b>\n"
                f"ادمین پنل: <code>{admin.username}</code>\n"
                "دسترسی اعضای گروه مطابق حالت عمومی و فهرست مجاز/مسدود همین گروه بررسی می‌شود؛ عملیات با دسترسی‌های فعلی همین ادمین اجرا می‌شوند."
            ),
        },
        timeout=12,
        max_attempts=2,
    )
    if not ok:
        raise HTTPException(502, str(result))
    row.last_verified_at = utcnow()
    db.commit()
    return {"ok": True}


@router.delete("/{group_id}")
def delete_telegram_group(
    group_id: int,
    db: Session = Depends(get_db),
    admin: Admin = Depends(get_current_admin),
):
    row = _require_group_access(db, admin, group_id)
    title = row.title or str(row.chat_id)
    chat_id = row.chat_id
    db.delete(row)
    db.commit()
    log_event(
        "🗑 قطع اتصال گروه تلگرام",
        f"گروه: {title} | chat_id={chat_id}",
        actor=admin.username,
    )
    return {"ok": True}


@router.delete("/link-code/current")
def revoke_current_link_code(
    db: Session = Depends(get_db),
    admin: Admin = Depends(get_current_admin),
):
    count = db.query(TelegramGroupLinkCode).filter(
        TelegramGroupLinkCode.admin_id == admin.id,
        TelegramGroupLinkCode.used_at.is_(None),
    ).delete(synchronize_session=False)
    db.commit()
    return {"ok": True, "revoked": int(count or 0)}
