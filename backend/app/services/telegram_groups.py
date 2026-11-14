from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Admin, AdminRole, TelegramAdminGroup, TelegramGroupLinkCode, TelegramGroupMemberRule

LINK_CODE_TTL_MINUTES = 10
VALID_ACCESS_MODES = {"all_members", "allowlist_only"}
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def utcnow() -> datetime:
    return datetime.utcnow()


def normalize_link_code(value: str | None) -> str:
    return "".join(ch for ch in str(value or "").upper().strip() if ch.isalnum())


def hash_link_code(value: str | None) -> str:
    code = normalize_link_code(value)
    secret = str(get_settings().JWT_SECRET or "")
    return hashlib.sha256(f"telegram-group-link:{secret}:{code}".encode("utf-8")).hexdigest()



def normalize_access_mode(value: str | None) -> str:
    mode = str(value or "all_members").strip().lower()
    if mode not in VALID_ACCESS_MODES:
        raise ValueError("حالت دسترسی گروه معتبر نیست")
    return mode


def member_access_decision(
    db: Session,
    group: TelegramAdminGroup,
    telegram_user_id: int | str,
) -> tuple[bool, str]:
    """Return the effective per-member decision for a linked Telegram group.

    Explicit deny always wins. Explicit allow works in both modes. Without a
    rule, all_members allows access while allowlist_only denies access.
    """
    try:
        numeric = int(telegram_user_id)
    except (TypeError, ValueError):
        return False, "آیدی عددی تلگرام معتبر نیست"
    if numeric <= 0:
        return False, "آیدی عددی تلگرام معتبر نیست"
    rule = db.query(TelegramGroupMemberRule).filter(
        TelegramGroupMemberRule.group_id == int(group.id),
        TelegramGroupMemberRule.telegram_user_id == numeric,
    ).first()
    if rule is not None:
        if bool(rule.is_allowed):
            return True, ""
        return False, "دسترسی شما به ربات در این گروه توسط مدیر پنل مسدود شده است"
    if normalize_access_mode(getattr(group, "access_mode", None)) == "allowlist_only":
        return False, "آیدی عددی شما در فهرست افراد مجاز این گروه نیست"
    return True, ""


def serialize_member_rule(row: TelegramGroupMemberRule) -> dict[str, Any]:
    return {
        "id": row.id,
        "group_id": row.group_id,
        "telegram_user_id": str(row.telegram_user_id),
        "is_allowed": bool(row.is_allowed),
        "status": "allow" if bool(row.is_allowed) else "deny",
        "display_name": row.display_name,
        "telegram_username": row.telegram_username,
        "note": row.note,
        "last_seen_at": row.last_seen_at,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
    }


def upsert_member_rule(
    db: Session,
    *,
    group: TelegramAdminGroup,
    telegram_user_id: int | str,
    is_allowed: bool,
    actor_admin_id: int | None = None,
    display_name: str | None = None,
    telegram_username: str | None = None,
    note: str | None = None,
) -> TelegramGroupMemberRule:
    try:
        numeric = int(str(telegram_user_id).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError("آیدی عددی تلگرام معتبر نیست") from exc
    if numeric <= 0 or numeric > 9_223_372_036_854_775_807:
        raise ValueError("آیدی عددی تلگرام معتبر نیست")
    row = db.query(TelegramGroupMemberRule).filter(
        TelegramGroupMemberRule.group_id == int(group.id),
        TelegramGroupMemberRule.telegram_user_id == numeric,
    ).first()
    if not row:
        row = TelegramGroupMemberRule(
            group_id=int(group.id),
            telegram_user_id=numeric,
        )
        db.add(row)
    row.is_allowed = bool(is_allowed)
    row.created_by_admin_id = int(actor_admin_id) if actor_admin_id else None
    row.display_name = str(display_name or "").strip()[:255] or None
    row.telegram_username = str(telegram_username or "").strip().lstrip("@")[:255] or None
    row.note = str(note or "").strip()[:500] or None
    return row


def create_link_code(db: Session, admin: Admin, *, ttl_minutes: int = LINK_CODE_TTL_MINUTES) -> tuple[str, datetime]:
    if not bool(getattr(admin, "telegram_bot_enabled", False)):
        raise ValueError("دسترسی ربات تلگرام برای این حساب فعال نیست")
    now = utcnow()
    db.query(TelegramGroupLinkCode).filter(
        TelegramGroupLinkCode.admin_id == admin.id,
        TelegramGroupLinkCode.used_at.is_(None),
    ).delete(synchronize_session=False)
    expires_at = now + timedelta(minutes=max(2, min(30, int(ttl_minutes))))
    for _ in range(20):
        code = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(8))
        digest = hash_link_code(code)
        exists = db.query(TelegramGroupLinkCode.id).filter(TelegramGroupLinkCode.code_hash == digest).first()
        if exists:
            continue
        db.add(TelegramGroupLinkCode(
            admin_id=admin.id,
            code_hash=digest,
            expires_at=expires_at,
        ))
        db.commit()
        return code, expires_at
    raise RuntimeError("ساخت کد اتصال گروه ناموفق بود؛ دوباره تلاش کنید")


def resolve_link_code(db: Session, code: str) -> tuple[TelegramGroupLinkCode, Admin]:
    normalized = normalize_link_code(code)
    if len(normalized) != 8:
        raise ValueError("کد اتصال گروه باید ۸ کاراکتر باشد")
    row = db.query(TelegramGroupLinkCode).filter(
        TelegramGroupLinkCode.code_hash == hash_link_code(normalized),
        TelegramGroupLinkCode.used_at.is_(None),
    ).first()
    if not row:
        raise ValueError("کد اتصال گروه نامعتبر یا قبلاً استفاده شده است")
    if row.expires_at <= utcnow():
        raise ValueError("زمان کد اتصال تمام شده؛ از پنل کد جدید بسازید")
    admin = db.query(Admin).filter(Admin.id == row.admin_id).first()
    if not admin or not admin.is_active:
        raise ValueError("حساب پنل مربوط به این کد فعال نیست")
    if not bool(getattr(admin, "telegram_bot_enabled", False)):
        raise ValueError("دسترسی ربات برای این حساب غیرفعال شده است")
    return row, admin


def group_for_chat(db: Session, chat_id: int | str, *, active_only: bool = True) -> TelegramAdminGroup | None:
    try:
        numeric = int(chat_id)
    except (TypeError, ValueError):
        return None
    query = db.query(TelegramAdminGroup).filter(TelegramAdminGroup.chat_id == numeric)
    if active_only:
        query = query.filter(
            TelegramAdminGroup.is_active == True,  # noqa: E712
            TelegramAdminGroup.control_enabled == True,  # noqa: E712
        )
    return query.first()


def upsert_group(
    db: Session,
    *,
    admin: Admin,
    chat: dict[str, Any],
    linked_by_telegram_user_id: int,
) -> TelegramAdminGroup:
    chat_id = int(chat.get("id") or 0)
    if not chat_id:
        raise ValueError("آیدی عددی گروه از تلگرام دریافت نشد")
    chat_type = str(chat.get("type") or "")
    if chat_type not in {"group", "supergroup"}:
        raise ValueError("اتصال فقط داخل گروه یا سوپرگروه تلگرام انجام می‌شود")
    row = db.query(TelegramAdminGroup).filter(TelegramAdminGroup.chat_id == chat_id).first()
    if row and int(row.admin_id) != int(admin.id):
        owner = db.query(Admin).filter(Admin.id == row.admin_id).first()
        owner_name = owner.username if owner else "ادمین دیگری"
        raise ValueError(f"این گروه قبلاً به حساب {owner_name} متصل شده است")
    if not row:
        row = TelegramAdminGroup(
            admin_id=admin.id,
            chat_id=chat_id,
            linked_by_telegram_user_id=int(linked_by_telegram_user_id),
        )
        db.add(row)
    row.admin_id = admin.id
    row.title = str(chat.get("title") or "").strip()[:255] or None
    row.chat_type = chat_type
    row.chat_username = str(chat.get("username") or "").strip()[:255] or None
    row.linked_by_telegram_user_id = int(linked_by_telegram_user_id)
    row.control_enabled = True
    row.access_mode = normalize_access_mode(getattr(row, "access_mode", None))
    row.is_active = True
    row.last_verified_at = utcnow()
    return row


def serialize_group(row: TelegramAdminGroup, *, include_owner: bool = False) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": row.id,
        "chat_id": str(row.chat_id),
        "title": row.title or "گروه بدون نام",
        "chat_type": row.chat_type or "group",
        "chat_username": row.chat_username,
        "control_enabled": bool(row.control_enabled),
        "is_active": bool(row.is_active),
        "last_verified_at": row.last_verified_at,
        "last_used_at": row.last_used_at,
        "created_at": row.created_at,
        "access_mode": normalize_access_mode(getattr(row, "access_mode", None)),
        "member_rule_count": len(getattr(row, "member_rules", []) or []),
        "allowed_member_count": sum(1 for item in (getattr(row, "member_rules", []) or []) if bool(item.is_allowed)),
        "blocked_member_count": sum(1 for item in (getattr(row, "member_rules", []) or []) if not bool(item.is_allowed)),
    }
    if include_owner:
        owner = getattr(row, "admin", None)
        payload.update({
            "admin_id": row.admin_id,
            "admin_username": getattr(owner, "username", None),
            "admin_role": getattr(getattr(owner, "role", None), "value", str(getattr(owner, "role", ""))) or None,
        })
    return payload


def admin_can_manage_group(admin: Admin, row: TelegramAdminGroup) -> bool:
    return admin.role == AdminRole.superadmin or int(row.admin_id) == int(admin.id)
