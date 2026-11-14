"""Interactive Telegram control bot for VPN Panel.

The notifier module remains responsible for one-way logs/backups.  This module
adds an authenticated long-polling controller that can perform the day-to-day
panel operations from Telegram: user lifecycle, IP bans, protocol service
control, node/status inspection, node sync and immediate backups.

Security model
--------------
* The bot is disabled by default.
* Every update must come from the configured control chat.
* For group/channel control, one or more numeric Telegram user IDs are required.
* In a private chat, the chat owner is accepted automatically when the allowed
  user list is empty.
* Failed-login ban buttons are accepted only from configured controller users.
"""
from __future__ import annotations

import ast
import html
import ipaddress
import json
import logging
import math
import queue
import re
import secrets
import struct
import threading
import zlib
from contextvars import ContextVar
from pathlib import Path
from datetime import date, datetime, timedelta, timezone
from typing import Any

import qrcode
import requests
from pydantic import ValidationError
from sqlalchemy import func

from app.database import SessionLocal
from app.models import (
    Admin, AdminAccessLicense, AdminRole, BannedIP, ConnectionLog, InternetBlockedIP,
    Setting, TelegramAdminGroup, VpnNode, VpnUser,
)
from app.schemas import ADMIN_PERMISSION_TOKENS, AdminAccessLicenseCreate, VpnUserCreate
from app.security import (
    admin_can_access_protocol,
    can_view_all_users,
    ensure_user_protocols,
    hash_password,
)
from app.services.admin_license_manager import generate_code, is_expired
from app.services.node_manager import (
    build_multi_xray_profiles,
    openvpn_profile_nodes,
    public_node_list,
    sync_all_nodes_async,
    sync_global_controls_to_active_nodes_async,
)
from app.services.protocol_admin import control_protocol, get_protocol_runtime_summary
from app.services.server_targets import (
    admin_can_access_target,
    available_target_tokens,
    local_assignment_enabled,
    serialize_admin_targets,
    serialize_targets,
    targets_for_user,
    user_selected_for_local,
    validate_admin_target_tokens,
    validate_target_tokens,
)
from app.services.sub_link import build_sub_link
from app.services.online_sessions import server_datetime_payload
from app.services.telegram_media_layout import gif_dimensions_from_path, normalize_main_menu_gif_file
from app.services.telegram_groups import group_for_chat, member_access_decision, resolve_link_code, upsert_group, utcnow
from app.services.telegram_notifier import (
    KEY_CONTROL_TEXT_OVERRIDES,
    KEY_MEDIA_MAIN_MENU_FILE_ID,
    KEY_MEDIA_MAIN_MENU_FINGERPRINT,
    KEY_MEDIA_USER_CREATED_FILE_ID,
    KEY_MEDIA_USER_CREATED_FINGERPRINT,
    KEY_MEDIA_USER_DELETED_FILE_ID,
    KEY_MEDIA_USER_DELETED_FINGERPRINT,
    call_telegram_api,
    get_telegram_config,
    log_event,
    send_backup_to_telegram,
)
from app.services.vpn_manager import ban_ip, block_internet_ip, restore_internet_ip, unban_ip

logger = logging.getLogger("vpn-panel.telegram-controller")

_THREAD: threading.Thread | None = None
_SUPERVISOR_THREAD: threading.Thread | None = None
_SUPERVISOR_LOCK = threading.Lock()
_STOP = threading.Event()
_STATE_LOCK = threading.Lock()
_STATES: dict[tuple[str, int], dict[str, Any]] = {}
_MESSAGE_LOCK = threading.Lock()
_TRACKED_MESSAGES: dict[str, list[int]] = {}
_CLEANUP_QUEUE: queue.Queue[tuple[str, str, tuple[int, ...]]] = queue.Queue(maxsize=512)
_CLEANUP_WORKER: threading.Thread | None = None
_CLEANUP_WORKER_LOCK = threading.Lock()
_UPDATE_QUEUE: queue.Queue[tuple[dict, dict, str, bool]] = queue.Queue(maxsize=2048)
_UPDATE_WORKERS: list[threading.Thread] = []
_UPDATE_WORKER_LOCK = threading.Lock()
# Fixed striped locks keep per-chat ordering without leaking one Lock object for
# every Telegram user that has ever contacted the bot.
_UPDATE_ROUTE_LOCKS: tuple[threading.Lock, ...] = tuple(threading.Lock() for _ in range(64))
_MENU_PENDING_LOCK = threading.Lock()
_MENU_PENDING_KEYS: set[str] = set()
_CURRENT_ADMIN_ID: ContextVar[int | None] = ContextVar("telegram_current_admin_id", default=None)
_BOT_TEXT_CATALOG_CACHE: list[tuple[str, str]] | None = None

GB = 1_073_741_824
PROTOCOLS = ("l2tp", "pptp", "openvpn", "sstp", "ikev2", "openconnect", "vmess", "vless")
PROTOCOL_LABELS = {
    "l2tp": "L2TP/IPsec", "pptp": "PPTP", "openvpn": "OpenVPN",
    "sstp": "SSTP", "ikev2": "IKEv2", "openconnect": "OpenConnect",
    "vmess": "VMess", "vless": "VLESS", "ipsec": "IPsec",
}
ADMIN_PERMISSION_LABELS = {
    "dashboard:view": "داشبورد",
    "users:view": "مشاهده کاربران", "users:create": "ساخت کاربر",
    "users:edit": "ویرایش کاربر", "users:delete": "حذف کاربر",
    "users:disconnect": "قطع کاربر", "users:subscription": "لینک اشتراک",
    "online:view": "کاربران آنلاین", "online:disconnect": "قطع سشن آنلاین",
    "bans:view": "مشاهده بن‌ها", "bans:manage": "مدیریت بن‌ها",
    "license:view": "مشاهده لایسنس پنل",
    "protocols:view": "مشاهده پروتکل‌ها", "protocols:start_stop": "شروع/توقف پروتکل",
    "protocols:install": "نصب پروتکل", "protocols:logs": "لاگ پروتکل",
    "protocols:edit": "تنظیمات پروتکل",
    "settings:view": "مشاهده تنظیمات", "settings:manage": "مدیریت تنظیمات",
    "nodes:view": "مشاهده نودها", "nodes:manage": "مدیریت نودها",
    "nodes:ssh": "SSH نودها", "nodes:install": "نصب نود",
    "protocol:l2tp": "L2TP", "protocol:ipsec": "IPsec",
    "protocol:pptp": "PPTP", "protocol:openvpn": "OpenVPN",
    "protocol:openconnect": "OpenConnect", "protocol:sstp": "SSTP",
    "protocol:ikev2": "IKEv2", "protocol:vmess": "VMess",
    "protocol:vless": "VLESS",
}
PERSIAN_DIGITS = str.maketrans("۰۱۲۳۴۵۶۷۸۹٠١٢٣٤٥٦٧٨٩", "01234567890123456789")


def _allowed_protocol_keys(admin: Admin | None) -> tuple[str, ...]:
    return tuple(key for key in PROTOCOLS if admin_can_access_protocol(admin, key))


def _visible_protocol_rows(admin: Admin | None, rows: list[dict] | tuple[dict, ...] | None) -> list[dict]:
    visible: list[dict] = []
    for raw in rows or []:
        if not isinstance(raw, dict):
            continue
        key = str(raw.get("key") or "").strip().lower()
        if key and admin_can_access_protocol(admin, key):
            visible.append(dict(raw))
    return visible

# Free-form chat is intentionally silent. Only these exact words reopen the
# GIF/menu; button callbacks, active wizard inputs and supported slash commands
# continue to work normally.
MENU_TEXT_TRIGGERS = {"ربات", "منو", "استارت"}
SUPPORTED_COMMANDS = {
    "/start", "/menu", "/help", "/myid", "/chatid", "/cancel",
    "/status", "/users", "/user", "/create", "/ban", "/unban", "/bans",
    "/enable", "/disable", "/disconnect", "/reset", "/delete",
    "/password", "/quota", "/days", "/protocols", "/targets",
    "/protocol", "/protocol_status", "/protocols_status", "/nodes",
    "/sync_nodes", "/backup", "/admins",
}

_MEDIA_CACHE_KEYS = {
    "main_menu": (KEY_MEDIA_MAIN_MENU_FILE_ID, KEY_MEDIA_MAIN_MENU_FINGERPRINT),
    "user_created": (KEY_MEDIA_USER_CREATED_FILE_ID, KEY_MEDIA_USER_CREATED_FINGERPRINT),
    "user_deleted": (KEY_MEDIA_USER_DELETED_FILE_ID, KEY_MEDIA_USER_DELETED_FINGERPRINT),
}


def _e(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _public_error(exc: Exception) -> str:
    detail = getattr(exc, "detail", None)
    value = detail if detail not in (None, "") else str(exc)
    text = str(value or "عملیات ناموفق بود")
    # Keep bot alerts concise and never expose framework status prefixes, SQL,
    # file paths or internal stack details.
    return text[:400]


def _normalize_digits(value: str) -> str:
    return (value or "").translate(PERSIAN_DIGITS)


def _setting(db, key: str, default: str = "") -> str:
    row = db.query(Setting).filter(Setting.key == key).first()
    return str(row.value) if row and row.value is not None else default


def _set_setting(db, key: str, value: str) -> None:
    row = db.query(Setting).filter(Setting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(Setting(key=key, value=value))


def _control_text_overrides(cfg: dict) -> dict[str, str]:
    raw = cfg.get("control_text_overrides") or {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (TypeError, ValueError):
            raw = {}
    if not isinstance(raw, dict):
        return {}
    result: dict[str, str] = {}
    for source, replacement in raw.items():
        source_text = str(source or "").strip()
        replacement_text = str(replacement or "").strip()
        if source_text and replacement_text:
            result[source_text] = replacement_text
    return result


def _customize_text(cfg: dict, value: Any, *, html_mode: bool = False) -> str:
    text = str(value if value is not None else "")
    overrides = _control_text_overrides(cfg)
    if not text or not overrides:
        return text
    # One regex pass prevents chained replacements (A→B and B→C) from
    # unexpectedly rewriting a value twice. Longer phrases win over fragments.
    signature = tuple(sorted(overrides.items()))
    cache = cfg.get("_control_text_regex_cache")
    if not isinstance(cache, tuple) or len(cache) != 2 or cache[0] != signature:
        sources = sorted(overrides, key=len, reverse=True)
        cache = (signature, re.compile("|".join(re.escape(source) for source in sources)))
        cfg["_control_text_regex_cache"] = cache
    pattern = cache[1]
    return pattern.sub(
        lambda match: html.escape(overrides[match.group(0)], quote=False)
        if html_mode else overrides[match.group(0)],
        text,
    )


def _customize_markup(cfg: dict, markup: dict | None) -> dict | None:
    if markup is None:
        return None
    result = dict(markup)
    if "input_field_placeholder" in result:
        result["input_field_placeholder"] = _customize_text(cfg, result["input_field_placeholder"])[:64]
    for grid_key in ("inline_keyboard", "keyboard"):
        rows = result.get(grid_key)
        if not isinstance(rows, list):
            continue
        new_rows = []
        for row in rows:
            new_row = []
            for button in row if isinstance(row, list) else []:
                if isinstance(button, dict):
                    updated = dict(button)
                    if "text" in updated:
                        updated["text"] = _customize_text(cfg, updated["text"])[:64]
                    new_row.append(updated)
                else:
                    new_row.append(button)
            new_rows.append(new_row)
        result[grid_key] = new_rows
    return result


def _save_control_text_overrides(db, cfg: dict, overrides: dict[str, str]) -> None:
    cleaned = {
        str(source).strip(): str(replacement).strip()
        for source, replacement in overrides.items()
        if str(source).strip() and str(replacement).strip()
    }
    serialized = json.dumps(cleaned, ensure_ascii=False, separators=(",", ":"))
    # Setting.value is a MySQL TEXT column (about 64 KiB). Keep a safety margin
    # so Persian/emoji UTF-8 replacements can never overflow the row.
    if len(serialized.encode("utf-8")) > 60_000:
        raise ValueError("حجم مجموع تغییرات متن بیشتر از حد مجاز است؛ چند تغییر قدیمی را حذف کنید")
    _set_setting(db, KEY_CONTROL_TEXT_OVERRIDES, serialized)
    db.commit()
    cfg["control_text_overrides"] = cleaned
    cfg.pop("_control_text_regex_cache", None)


def _actor(db) -> Admin:
    """Return the exact panel admin linked to the current Telegram user.

    Never fall back to the first/main superadmin. That fallback caused every
    operation from an unbound Telegram account to be recorded and executed as
    the original panel owner.
    """
    requested_id = _CURRENT_ADMIN_ID.get()
    if not requested_id:
        raise ValueError("حساب تلگرام شما به هیچ حساب پنل متصل نیست")
    admin = db.query(Admin).filter(
        Admin.id == int(requested_id),
        Admin.is_active == True,  # noqa: E712
        Admin.telegram_bot_enabled == True,  # noqa: E712
    ).first()
    if not admin:
        raise ValueError("حساب متصل به ربات غیرفعال یا حذف شده است")
    if is_expired(admin):
        raise ValueError("اعتبار حساب ادمین متصل به ربات تمام شده است")
    return admin


def _permission_set(admin: Admin) -> set[str]:
    if admin.role == AdminRole.superadmin:
        return set(ADMIN_PERMISSION_TOKENS)
    return {token for token in (admin.permissions or "").split(",") if token}


def _has_permission(admin: Admin, token: str) -> bool:
    if admin.role == AdminRole.superadmin:
        return True
    permissions = _permission_set(admin)
    return token in permissions or token.split(":", 1)[0] in permissions


def _require_permission(db, token: str) -> Admin:
    admin = _actor(db)
    if not _has_permission(admin, token):
        raise ValueError("این عملیات در دسترسی‌های ادمین شما فعال نیست")
    return admin


def _bot_user_query(db):
    from app.security import can_view_all_users
    admin = _actor(db)
    query = db.query(VpnUser)
    if not can_view_all_users(admin):
        query = query.filter(VpnUser.owner_admin_id == admin.id)
    return query


def _bot_user_by_id(db, user_id: int) -> VpnUser | None:
    return _bot_user_query(db).filter(VpnUser.id == int(user_id)).first()


def _bot_user_by_username(db, username: str) -> VpnUser | None:
    return _bot_user_query(db).filter(VpnUser.username == username).first()


def _ensure_telegram_binding_available(db, telegram_user_id: int | None) -> None:
    if not telegram_user_id:
        return
    value = int(telegram_user_id)
    if db.query(Admin.id).filter(Admin.telegram_user_id == value).first():
        raise ValueError("این آیدی تلگرام قبلاً به ادمین دیگری متصل شده است")
    if db.query(AdminAccessLicense.id).filter(AdminAccessLicense.telegram_user_id == value).first():
        raise ValueError("این آیدی تلگرام قبلاً روی لایسنس دیگری ثبت شده است")


def _parse_allowed_ids(raw: str) -> set[int]:
    values: set[int] = set()
    for part in re.split(r"[,;\s]+", raw or ""):
        if not part:
            continue
        try:
            values.add(int(_normalize_digits(part)))
        except ValueError:
            continue
    return values


def _chat_matches(configured: str, chat: dict) -> bool:
    configured = str(configured or "").strip()
    if not configured:
        return False
    if configured.startswith("@"):
        return configured[1:].lower() == str(chat.get("username") or "").lower()
    return configured == str(chat.get("id") or "")


def _linked_admin_for_telegram_id(db, telegram_user_id: int) -> Admin | None:
    if not telegram_user_id:
        return None
    return db.query(Admin).filter(
        Admin.telegram_user_id == int(telegram_user_id),
        Admin.telegram_bot_enabled == True,  # noqa: E712
        Admin.is_active == True,  # noqa: E712
    ).first()


def _binding_intro_text(user_id: int) -> str:
    return "\n".join([
        "🔐 <b>حساب تلگرام شما هنوز به پنل متصل نیست</b>",
        f"آیدی عددی شما: <code>{int(user_id)}</code>",
        "",
        "ابتدا باید با لایسنس ادمین داخل پنل ثبت‌نام کرده باشی.",
        "اگر هنگام ثبت‌نام گزینه «فعلاً ربات تلگرام نمی‌خواهم» را زده‌ای، دکمه زیر را بزن و همان لایسنس ادمین را بفرست.",
        "هر لایسنس ربات‌دار فقط یک‌بار و فقط به یک آیدی عددی تلگرام متصل می‌شود.",
    ])


def _binding_intro_keyboard() -> dict:
    return {"inline_keyboard": [[
        {"text": "🔗 اتصال حساب با لایسنس ادمین", "callback_data": "bind:start"},
    ]]}


def _send_binding_required(cfg: dict, chat: dict, user: dict) -> None:
    user_id = int(user.get("id") or 0)
    chat_id = chat.get("id")
    if not user_id or not chat_id or str(chat.get("type") or "") != "private":
        return
    _send(cfg, chat_id, _binding_intro_text(user_id), _binding_intro_keyboard(), customize=False)


def _authorized(cfg: dict, update: dict, *, allow_log_callback: bool = False) -> tuple[bool, str, dict, dict]:
    """Resolve the panel actor for a Telegram update.

    A linked group is a shared workspace: every real member of that Telegram
    group may use the bot, while the panel permission ceiling is always the
    owner Admin attached to the group. Private chats still require a direct
    Telegram-to-admin binding.
    """
    _CURRENT_ADMIN_ID.set(None)
    callback = update.get("callback_query") or {}
    message = callback.get("message") or update.get("message") or {}
    chat = message.get("chat") or {}
    user = callback.get("from") or message.get("from") or {}
    if not cfg.get("control_enabled"):
        return False, "کنترل ربات در پنل غیرفعال است", chat, user

    user_id = int(user.get("id") or 0)
    if not user_id:
        return False, "آیدی عددی تلگرام دریافت نشد", chat, user

    db = SessionLocal()
    try:
        chat_type = str(chat.get("type") or "")

        # Per-admin group mode: the group itself is the authorization boundary.
        # No member needs a panel binding or Telegram administrator status.
        if chat_type in {"group", "supergroup"}:
            group = group_for_chat(db, chat.get("id"), active_only=False)
            if group:
                if not bool(group.is_active):
                    return False, "اتصال این گروه در پنل غیرفعال شده است", chat, user
                if not bool(group.control_enabled):
                    return False, "کنترل ربات در این گروه غیرفعال شده است", chat, user
                member_ok, member_reason = member_access_decision(db, group, user_id)
                if not member_ok:
                    return False, member_reason, chat, user
                owner = db.query(Admin).filter(
                    Admin.id == int(group.admin_id),
                    Admin.is_active == True,  # noqa: E712
                    Admin.telegram_bot_enabled == True,  # noqa: E712
                ).first()
                if not owner:
                    return False, "حساب پنل مالک این گروه غیرفعال یا حذف شده است", chat, user
                if is_expired(owner):
                    return False, "اعتبار حساب ادمین مالک این گروه تمام شده است", chat, user

                changed = False
                title = str(chat.get("title") or "").strip()[:255] or None
                username = str(chat.get("username") or "").strip()[:255] or None
                if group.title != title:
                    group.title = title
                    changed = True
                if group.chat_username != username:
                    group.chat_username = username
                    changed = True
                now = utcnow()
                if not group.last_used_at or (now - group.last_used_at).total_seconds() >= 300:
                    group.last_used_at = now
                    changed = True
                if changed:
                    db.commit()
                _CURRENT_ADMIN_ID.set(int(owner.id))
                return True, "", chat, user

        # Private chats and the legacy single control chat keep direct identity
        # binding, because they do not have the per-group owner boundary above.
        linked = _linked_admin_for_telegram_id(db, user_id)
        if not linked:
            return False, "telegram_account_unbound", chat, user
        if is_expired(linked):
            return False, "اعتبار حساب ادمین متصل به ربات تمام شده است", chat, user
        linked_id = int(linked.id)

        if chat_type == "private" and int(chat.get("id") or 0) == user_id:
            _CURRENT_ADMIN_ID.set(linked_id)
            return True, "", chat, user

        # Backward compatibility for the single legacy control/log chat.
        valid_chat = _chat_matches(cfg.get("control_chat_id", ""), chat)
        if allow_log_callback:
            valid_chat = valid_chat or _chat_matches(cfg.get("log_chat_id", ""), chat)
        if not valid_chat:
            return False, "این چت اجازه کنترل پنل را ندارد", chat, user

        allowed = _parse_allowed_ids(cfg.get("control_allowed_user_ids", ""))
        if allowed and user_id not in allowed:
            return False, "شناسه تلگرام شما در فهرست مجاز این چت نیست", chat, user

        _CURRENT_ADMIN_ID.set(linked_id)
        return True, "", chat, user
    finally:
        db.close()

def _is_control_chat(cfg: dict, chat_id: int | str) -> bool:
    configured = str(cfg.get("control_chat_id") or "").strip()
    if bool(configured) and configured == str(chat_id):
        return True
    try:
        numeric = int(chat_id)
    except (TypeError, ValueError):
        return False
    db = SessionLocal()
    try:
        if group_for_chat(db, numeric, active_only=True):
            return True
        return bool(db.query(Admin.id).filter(
            Admin.telegram_user_id == numeric,
            Admin.telegram_bot_enabled == True,  # noqa: E712
            Admin.is_active == True,  # noqa: E712
        ).first())
    finally:
        db.close()


def _tracked_message_ids(chat_id: int | str) -> list[int]:
    key = str(chat_id)
    with _MESSAGE_LOCK:
        cached = list(_TRACKED_MESSAGES.get(key) or [])
    if cached:
        return cached
    db = SessionLocal()
    try:
        try:
            raw = _setting(db, "telegram_control_message_ids", "{}")
        except Exception:
            return []
        try:
            mapping = json.loads(raw or "{}")
        except Exception:
            mapping = {}
        values = mapping.get(key) if isinstance(mapping, dict) else []
        result = [int(value) for value in (values or []) if str(value).isdigit()][-30:]
        with _MESSAGE_LOCK:
            _TRACKED_MESSAGES[key] = result
        return result
    finally:
        db.close()


def _store_tracked_message_ids(chat_id: int | str, values: list[int]) -> None:
    key = str(chat_id)
    cleaned = list(dict.fromkeys(int(value) for value in values if int(value) > 0))[-30:]
    with _MESSAGE_LOCK:
        _TRACKED_MESSAGES[key] = cleaned
    db = SessionLocal()
    try:
        raw = _setting(db, "telegram_control_message_ids", "{}")
        try:
            mapping = json.loads(raw or "{}")
        except Exception:
            mapping = {}
        if not isinstance(mapping, dict):
            mapping = {}
        mapping[key] = cleaned
        _set_setting(db, "telegram_control_message_ids", json.dumps(mapping, separators=(",", ":")))
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Could not persist Telegram controller message ids")
    finally:
        db.close()


def _cleanup_worker_loop() -> None:
    while True:
        try:
            bot_token, chat_id, message_ids = _CLEANUP_QUEUE.get(timeout=1.0)
        except queue.Empty:
            if _STOP.is_set() and _CLEANUP_QUEUE.empty():
                return
            continue
        try:
            for message_id in message_ids:
                ok, result = call_telegram_api(
                    bot_token,
                    "deleteMessage",
                    data={"chat_id": chat_id, "message_id": message_id},
                    timeout=6,
                    max_attempts=1,
                )
                if not ok and "message to delete not found" not in str(result).lower():
                    logger.debug("Telegram controller cleanup skipped message %s: %s", message_id, result)
        except Exception:
            logger.exception("Telegram controller background cleanup failed")
        finally:
            _CLEANUP_QUEUE.task_done()


def _ensure_cleanup_worker() -> None:
    global _CLEANUP_WORKER
    if _CLEANUP_WORKER and _CLEANUP_WORKER.is_alive():
        return
    with _CLEANUP_WORKER_LOCK:
        if _CLEANUP_WORKER and _CLEANUP_WORKER.is_alive():
            return
        _CLEANUP_WORKER = threading.Thread(
            target=_cleanup_worker_loop,
            name="telegram-control-cleanup",
            daemon=True,
        )
        _CLEANUP_WORKER.start()


def _queue_control_message_cleanup(cfg: dict, chat_id: int | str, message_ids: list[int]) -> None:
    if not _is_control_chat(cfg, chat_id):
        return
    cleaned = tuple(dict.fromkeys(int(value) for value in message_ids if int(value) > 0))
    if not cleaned:
        return
    _ensure_cleanup_worker()
    try:
        _CLEANUP_QUEUE.put_nowait((str(cfg.get("bot_token") or ""), str(chat_id), cleaned))
    except queue.Full:
        # Cleanup is cosmetic. Never block the polling/controller path merely to
        # delete old messages; a later cleanup pass will remove stale entries.
        logger.warning("Telegram cleanup queue is full; skipping %s stale messages", len(cleaned))


def _cleanup_control_messages(cfg: dict, chat_id: int | str, *, keep: set[int] | None = None) -> None:
    """Forget stale control messages immediately and delete them in background.

    Older releases deleted up to thirty Telegram messages synchronously before
    every menu response. One slow delete request could therefore stall the
    long-poll loop for minutes and make the whole bot look frozen. Tracking is
    updated synchronously, while network deletion is now best-effort and never
    delays the new menu/GIF or inline-button handling.
    """
    if not _is_control_chat(cfg, chat_id):
        return
    keep = {int(value) for value in (keep or set()) if int(value) > 0}
    current = _tracked_message_ids(chat_id)
    remaining = [message_id for message_id in current if message_id in keep]
    stale = [message_id for message_id in current if message_id not in keep]
    _store_tracked_message_ids(chat_id, remaining)
    _queue_control_message_cleanup(cfg, chat_id, stale)


def _remember_control_message(cfg: dict, chat_id: int | str, message_id: int | None) -> None:
    if not message_id or not _is_control_chat(cfg, chat_id):
        return
    current = _tracked_message_ids(chat_id)
    _store_tracked_message_ids(chat_id, [*current, int(message_id)])


def _send(
    cfg: dict,
    chat_id: int | str,
    text: str,
    keyboard: dict | None = None,
    reply_to: int | None = None,
    *,
    cleanup: bool = True,
    customize: bool = True,
) -> int | None:
    if cleanup:
        _cleanup_control_messages(cfg, chat_id)
    if customize:
        text = _customize_text(cfg, text, html_mode=True)
        keyboard = _customize_markup(cfg, keyboard)
    if len(text) > 4000:
        text = text[:4000] + "\n… (بریده شد)"
    data: dict[str, Any] = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": "true",
    }
    if keyboard is not None:
        data["reply_markup"] = json.dumps(keyboard, ensure_ascii=False, separators=(",", ":"))
    if reply_to is not None:
        data["reply_to_message_id"] = int(reply_to)
    ok, result = call_telegram_api(
        cfg["bot_token"], "sendMessage", data=data, timeout=10, max_attempts=2,
    )
    if not ok:
        logger.warning("Telegram controller send failed: %s", result)
        return None
    message_id = int(result.get("message_id") or 0) if isinstance(result, dict) else 0
    _remember_control_message(cfg, chat_id, message_id)
    return message_id or None


def _edit(cfg: dict, callback: dict, text: str, keyboard: dict | None = None) -> None:
    """Edit the message that owns an inline keyboard.

    Toggle selectors (protocols/servers) must visibly keep their selection
    state.  Editing the existing message avoids flooding the control chat with
    a new message for every tap.  If Telegram refuses the edit (for example an
    old message), fall back to a normal send so the operation never gets stuck.
    """
    message = callback.get("message") or {}
    chat = message.get("chat") or {}
    chat_id = chat.get("id")
    message_id = message.get("message_id")
    if not chat_id or not message_id:
        return
    original_text = text
    original_keyboard = keyboard
    text = _customize_text(cfg, text, html_mode=True)
    keyboard = _customize_markup(cfg, keyboard)
    _cleanup_control_messages(cfg, chat_id, keep={int(message_id)})
    _remember_control_message(cfg, chat_id, int(message_id))
    payload: dict[str, Any] = {
        "chat_id": chat_id,
        "message_id": message_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": "true",
    }
    if keyboard is not None:
        payload["reply_markup"] = json.dumps(keyboard, ensure_ascii=False, separators=(",", ":"))
    ok, err = call_telegram_api(cfg["bot_token"], "editMessageText", data=payload)
    if not ok and "message is not modified" not in str(err).lower():
        logger.warning("Telegram controller edit failed: %s", err)
        _send(cfg, chat_id, original_text, original_keyboard)


def _answer(cfg: dict, callback_id: str, text: str = "", alert: bool = False) -> None:
    text = _customize_text(cfg, text)
    call_telegram_api(
        cfg["bot_token"], "answerCallbackQuery",
        data={"callback_query_id": callback_id, "text": text[:180], "show_alert": "true" if alert else "false"},
        timeout=8,
        max_attempts=1,
    )


def _remove_keyboard(cfg: dict, callback: dict) -> None:
    message = callback.get("message") or {}
    chat = message.get("chat") or {}
    if not chat.get("id") or not message.get("message_id"):
        return
    call_telegram_api(
        cfg["bot_token"], "editMessageReplyMarkup",
        data={"chat_id": chat["id"], "message_id": message["message_id"], "reply_markup": json.dumps({"inline_keyboard": []})},
    )


def _force_reply() -> dict:
    return {"force_reply": True, "selective": True, "input_field_placeholder": "پاسخ را اینجا بنویسید…"}


def _cancel_keyboard(*, back: str = "menu:home", random_callback: str | None = None) -> dict:
    rows: list[list[dict[str, str]]] = []
    if random_callback:
        rows.append([{"text": "🎲 ساخت خودکار", "callback_data": random_callback}])
    rows.append([
        {"text": "❌ لغو", "callback_data": "flow:cancel"},
        {"text": "🔙 بازگشت", "callback_data": back},
    ])
    return {"inline_keyboard": rows}


def _menu_keyboard(admin: Admin | None = None) -> dict:
    if admin is None:
        # Resolve the linked private-chat admin automatically so every menu
        # response only exposes buttons allowed by that admin's panel license.
        # Legacy configured control-chat owners keep full superadmin behavior.
        requested_id = _CURRENT_ADMIN_ID.get()
        if requested_id:
            db = SessionLocal()
            try:
                admin = db.query(Admin).filter(
                    Admin.id == int(requested_id),
                    Admin.is_active == True,  # noqa: E712
                ).first()
                if admin and is_expired(admin):
                    admin = None
                elif admin is not None:
                    # Detach before closing the short-lived lookup session. All
                    # fields used by _menu_keyboard are scalar and already loaded.
                    db.expunge(admin)
            finally:
                db.close()
        if admin is None:
            return {"inline_keyboard": [[
                {"text": "🆔 اتصال حساب تلگرام", "callback_data": "bind:start"},
            ]]}
    rows: list[list[dict[str, str]]] = []
    def add(left, right=None):
        row = [left]
        if right is not None:
            row.append(right)
        rows.append(row)
    if _has_permission(admin, "dashboard:view"):
        add({"text": "📊 وضعیت پنل", "callback_data": "menu:status"}, {"text": "👥 کاربران", "callback_data": "menu:users"} if _has_permission(admin, "users:view") else None)
    elif _has_permission(admin, "users:view"):
        add({"text": "👥 کاربران", "callback_data": "menu:users"})
    if _has_permission(admin, "users:create") or _has_permission(admin, "online:view"):
        left = {"text": "➕ ساخت کاربر", "callback_data": "menu:create"} if _has_permission(admin, "users:create") else {"text": "🟢 کاربران آنلاین", "callback_data": "menu:online"}
        right = {"text": "🟢 کاربران آنلاین", "callback_data": "menu:online"} if _has_permission(admin, "online:view") and left["callback_data"] != "menu:online" else None
        add(left, right)
    if _has_permission(admin, "bans:view"):
        add({"text": "🚫 مدیریت آی‌پی‌ها", "callback_data": "menu:ips"}, {"text": "⛔ قطع اینترنت", "callback_data": "menu:internet"} if _has_permission(admin, "internet_blocks:view") else None)
    elif _has_permission(admin, "internet_blocks:view"):
        add({"text": "⛔ اینترنت قطع‌شده‌ها", "callback_data": "menu:internet"})
    if admin.role == AdminRole.superadmin:
        add({"text": "🛡 ادمین‌ها", "callback_data": "menu:admins"}, {"text": "🎫 ساخت و مدیریت لایسنس", "callback_data": "menu:licenses"})
    can_show_protocols = _has_permission(admin, "protocols:view") and bool(_allowed_protocol_keys(admin))
    can_show_nodes = _has_permission(admin, "nodes:view")
    if can_show_protocols or can_show_nodes:
        left = {"text": "🔌 پروتکل‌ها", "callback_data": "menu:protocols"} if can_show_protocols else {"text": "🖥 نودها", "callback_data": "menu:nodes"}
        right = {"text": "🖥 نودها", "callback_data": "menu:nodes"} if can_show_nodes and left["callback_data"] != "menu:nodes" else None
        add(left, right)
    if admin.role == AdminRole.superadmin:
        add({"text": "📦 بکاپ فوری", "callback_data": "menu:backup"}, {"text": "⬆️ بروزرسانی پنل", "callback_data": "menu:update"})
        add({"text": "✏️ متن‌ها و دکمه‌های ربات", "callback_data": "menu:bot_texts"})
    if _has_permission(admin, "license:view"):
        add({"text": "🔐 لایسنس خود پنل", "callback_data": "menu:panel_license"}, {"text": "⚙️ تنظیمات و ابزارها", "callback_data": "menu:tools"})
    if _has_permission(admin, "users:view"):
        add({"text": "🔎 مدیریت کاربر", "callback_data": "menu:user"}, {"text": "🔄 سینک نودها", "callback_data": "menu:syncnodes"} if _has_permission(admin, "nodes:manage") else None)
    add({"text": "📖 راهنمای دکمه‌ها", "callback_data": "menu:help"}, {"text": "🆔 شناسه تلگرام", "callback_data": "menu:myid"})
    return {"inline_keyboard": rows}


def _short_bot_text(value: str, limit: int = 42) -> str:
    compact = re.sub(r"\s+", " ", str(value or "")).strip()
    return compact if len(compact) <= limit else compact[: limit - 1] + "…"


def _looks_like_visible_bot_text(value: str) -> bool:
    text = str(value or "").strip()
    if not text or len(text) > 512:
        return False
    if text in MENU_TEXT_TRIGGERS or text.startswith(("bottext:", "menu:", "flow:", "bind:")):
        return False
    if re.fullmatch(r"[A-Za-z0-9_./:@-]+", text):
        return False
    return bool(re.search(r"[\u0600-\u06FF]|[\U0001F000-\U0001FAFF\u2600-\u27BF]", text))


def _bot_text_catalog() -> list[tuple[str, str]]:
    """Discover static user-visible Telegram labels/messages in this module."""
    global _BOT_TEXT_CATALOG_CACHE
    if _BOT_TEXT_CATALOG_CACHE is not None:
        return list(_BOT_TEXT_CATALOG_CACHE)
    try:
        source = Path(__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
    except Exception:
        logger.exception("Could not build Telegram text catalog")
        return []

    doc_nodes: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = getattr(node, "body", None) or []
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) and isinstance(body[0].value.value, str):
                doc_nodes.add(id(body[0].value))

    button_nodes: set[int] = set()
    button_values: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Dict):
            continue
        for key, value in zip(node.keys, node.values):
            if isinstance(key, ast.Constant) and key.value in {"text", "input_field_placeholder"}:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    button_nodes.add(id(value))
                    button_values.append(value.value)

    seen: set[str] = set()
    catalog: list[tuple[str, str]] = []

    def add(kind: str, raw: str) -> None:
        pieces = [part.strip() for part in re.split(r"\r?\n", str(raw or "")) if part.strip()]
        for piece in pieces:
            if not _looks_like_visible_bot_text(piece) or piece in seen:
                continue
            seen.add(piece)
            catalog.append((kind, piece))

    for value in button_values:
        add("button", value)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Constant) or not isinstance(node.value, str):
            continue
        if id(node) in doc_nodes or id(node) in button_nodes:
            continue
        add("text", node.value)

    catalog.sort(key=lambda item: (0 if item[0] == "button" else 1, item[1]))
    _BOT_TEXT_CATALOG_CACHE = catalog
    return list(catalog)


def _bot_text_manager_payload(cfg: dict) -> tuple[str, dict]:
    overrides = _control_text_overrides(cfg)
    catalog_count = len(_bot_text_catalog())
    body = "\n".join([
        "✏️ <b>مدیریت متن‌ها و دکمه‌های ربات</b>",
        "فهرست زیر مستقیماً از متن‌ها و دکمه‌های فعلی همین نسخه ساخته می‌شود.",
        "یک مورد را انتخاب کن، متن جدید را بفرست و در مرحله بعد تأیید کن.",
        f"\nموارد قابل انتخاب: <b>{catalog_count}</b>",
        f"تغییرات فعال: <b>{len(overrides)}</b>",
    ])
    keyboard = {"inline_keyboard": [
        [{"text": "📚 انتخاب از متن‌ها و دکمه‌های فعلی", "callback_data": "bottext:catalog:0"}],
        [{"text": "📋 مشاهده و حذف تغییرات", "callback_data": "bottext:list:0"}],
        [{"text": "♻️ بازگردانی همه متن‌ها", "callback_data": "bottext:reset"}],
        [{"text": "🏠 منوی اصلی", "callback_data": "menu:home"}],
    ]}
    return body, keyboard


def _bot_text_catalog_payload(cfg: dict, page: int = 0) -> tuple[str, dict]:
    items = _bot_text_catalog()
    if not items:
        return (
            "متن یا دکمه‌ای برای ویرایش پیدا نشد.",
            {"inline_keyboard": [[{"text": "🔙 بازگشت", "callback_data": "menu:bot_texts"}]]},
        )
    page_size = 8
    max_page = max(0, (len(items) - 1) // page_size)
    page = max(0, min(int(page), max_page))
    start = page * page_size
    visible = items[start:start + page_size]
    lines = [f"📚 <b>متن‌ها و دکمه‌های فعلی</b> — صفحه {page + 1}/{max_page + 1}"]
    rows: list[list[dict[str, str]]] = []
    for offset, (kind, source) in enumerate(visible):
        index = start + offset
        current = _customize_text(cfg, source)
        label = "دکمه" if kind == "button" else "متن"
        lines.append(f"\n<b>{index + 1}. {label}</b>\n{_e(_short_bot_text(current, 110))}")
        icon = "🔘" if kind == "button" else "💬"
        rows.append([{
            "text": f"{icon} {index + 1}: {_short_bot_text(current, 34)}",
            "callback_data": f"bottext:pick:{page}:{index}",
        }])
    nav: list[dict[str, str]] = []
    if page > 0:
        nav.append({"text": "◀️ قبلی", "callback_data": f"bottext:catalog:{page - 1}"})
    if page < max_page:
        nav.append({"text": "بعدی ▶️", "callback_data": f"bottext:catalog:{page + 1}"})
    if nav:
        rows.append(nav)
    rows.append([{"text": "🔙 بازگشت", "callback_data": "menu:bot_texts"}])
    return "\n".join(lines), {"inline_keyboard": rows}


def _bot_text_list_payload(cfg: dict, page: int = 0) -> tuple[str, dict]:
    items = sorted(_control_text_overrides(cfg).items(), key=lambda item: item[0])
    if not items:
        return (
            "📋 <b>تغییرات متن ربات</b>\nهنوز هیچ متن یا دکمه‌ای تغییر نکرده است.",
            {"inline_keyboard": [[{"text": "🔙 بازگشت", "callback_data": "menu:bot_texts"}]]},
        )
    page_size = 8
    max_page = max(0, (len(items) - 1) // page_size)
    page = max(0, min(int(page), max_page))
    start = page * page_size
    visible = items[start:start + page_size]
    lines = [f"📋 <b>تغییرات متن ربات</b> — صفحه {page + 1}/{max_page + 1}"]
    rows: list[list[dict[str, str]]] = []
    for offset, (source, replacement) in enumerate(visible):
        absolute_index = start + offset
        lines.append(
            f"\n<b>{absolute_index + 1}.</b> {_e(_short_bot_text(source, 70))}\n"
            f"↳ {_e(_short_bot_text(replacement, 70))}"
        )
        rows.append([{
            "text": f"🗑 حذف {absolute_index + 1}: {_short_bot_text(source, 24)}",
            "callback_data": f"bottext:delete:{page}:{absolute_index}",
        }])
    nav: list[dict[str, str]] = []
    if page > 0:
        nav.append({"text": "◀️ قبلی", "callback_data": f"bottext:list:{page - 1}"})
    if page < max_page:
        nav.append({"text": "بعدی ▶️", "callback_data": f"bottext:list:{page + 1}"})
    if nav:
        rows.append(nav)
    rows.append([{"text": "🔙 بازگشت", "callback_data": "menu:bot_texts"}])
    return "\n".join(lines), {"inline_keyboard": rows}


def _media_fingerprint(path: str) -> str:
    try:
        stat = Path(path).stat()
        return f"{stat.st_size}:{stat.st_mtime_ns}"
    except OSError:
        return ""


def _media_file(cfg: dict, slot: str) -> tuple[str, str, str] | None:
    path = str(cfg.get(f"media_{slot}_path") or "").strip()
    media_type = str(cfg.get(f"media_{slot}_type") or "").strip()
    if not path or media_type not in {"photo", "animation"} or not Path(path).is_file():
        return None
    if slot == "main_menu" and media_type == "animation" and Path(path).suffix.lower() == ".gif":
        # Also upgrades GIFs that were uploaded before v2.3.168.  The atomic
        # rewrite changes the fingerprint, so the stale Telegram file_id is
        # naturally invalidated and the corrected media is uploaded once.
        normalize_main_menu_gif_file(path)
    return path, media_type, _media_fingerprint(path)


def _extract_telegram_file_id(result: Any, media_type: str) -> str:
    if not isinstance(result, dict):
        return ""
    if media_type == "animation":
        animation = result.get("animation") or {}
        return str(animation.get("file_id") or "") if isinstance(animation, dict) else ""
    photos = result.get("photo") or []
    if isinstance(photos, list) and photos:
        candidate = photos[-1] if isinstance(photos[-1], dict) else {}
        return str(candidate.get("file_id") or "")
    return ""


def _cached_media_file_id_is_invalid(error: Any) -> bool:
    """Return true only when Telegram explicitly rejects the cached file id.

    A timeout, 429 or temporary Telegram outage must not trigger a large source
    file upload. Older code retried the cached send and then immediately began
    an upload for every kind of failure, which could keep the per-chat worker
    occupied for minutes after several menu requests.
    """
    text = str(error or "").strip().lower()
    invalid_markers = (
        "wrong file identifier",
        "wrong file id",
        "file identifier/http url specified",
        "failed to get http url content",
        "invalid file_id",
        "invalid file id",
    )
    return any(marker in text for marker in invalid_markers)


def _persist_media_cache(cfg: dict, slot: str, file_id: str, fingerprint: str) -> None:
    keys = _MEDIA_CACHE_KEYS.get(slot)
    if not keys:
        return
    file_id_key, fingerprint_key = keys
    db = SessionLocal()
    try:
        _set_setting(db, file_id_key, file_id)
        _set_setting(db, fingerprint_key, fingerprint)
        db.commit()
        cfg[f"media_{slot}_file_id"] = file_id
        cfg[f"media_{slot}_fingerprint"] = fingerprint
    except Exception:
        db.rollback()
        logger.exception("Could not persist Telegram media cache for %s", slot)
    finally:
        db.close()


def _send_media(
    cfg: dict, chat_id: int | str, slot: str, caption: str, keyboard: dict | None = None, *, cleanup: bool = True
) -> int | None:
    selected = _media_file(cfg, slot)
    if not selected:
        return None
    if cleanup:
        _cleanup_control_messages(cfg, chat_id)
    path, media_type, fingerprint = selected
    method = "sendAnimation" if media_type == "animation" else "sendPhoto"
    field = "animation" if media_type == "animation" else "photo"
    caption = _customize_text(cfg, caption, html_mode=True)
    keyboard = _customize_markup(cfg, keyboard)
    data: dict[str, Any] = {"chat_id": chat_id, "caption": caption[:1000], "parse_mode": "HTML"}
    if media_type == "animation":
        dimensions = gif_dimensions_from_path(path)
        if dimensions is not None:
            data["width"], data["height"] = dimensions
    if keyboard is not None:
        data["reply_markup"] = json.dumps(keyboard, ensure_ascii=False, separators=(",", ":"))

    cached_file_id = str(cfg.get(f"media_{slot}_file_id") or "").strip()
    cached_fingerprint = str(cfg.get(f"media_{slot}_fingerprint") or "").strip()
    cache_matches = bool(cached_file_id and cached_fingerprint == fingerprint)
    cache_invalid = False
    ok = False
    result: Any = ""
    if cache_matches:
        cached_data = dict(data)
        cached_data[field] = cached_file_id
        ok, result = call_telegram_api(
            cfg["bot_token"], method, data=cached_data, timeout=10, max_attempts=2,
        )
        if not ok:
            cache_invalid = _cached_media_file_id_is_invalid(result)
            if cache_invalid:
                # A bot-token change can invalidate a previously saved file_id.
                # Only this explicit Telegram rejection justifies re-uploading.
                _persist_media_cache(cfg, slot, "", "")
            else:
                # Do not turn a transient timeout/rate-limit into another large
                # upload. That double retry path was the remaining source of
                # multi-minute controller stalls after repeated menu requests.
                logger.warning("Telegram cached media send failed for %s: %s", slot, result)
                return 0

    if not ok and (not cache_matches or cache_invalid):
        with open(path, "rb") as handle:
            ok, result = call_telegram_api(
                cfg["bot_token"], method, data=data,
                files={field: (Path(path).name, handle)}, timeout=35, max_attempts=1,
            )
    if not ok:
        logger.warning("Telegram media send failed for %s: %s", slot, result)
        # Zero means media was configured but delivery still failed after the
        # built-in retry/backoff path. Callers must not silently downgrade to a
        # text-only message, which was the source of missing GIFs at scale.
        return 0
    file_id = _extract_telegram_file_id(result, media_type)
    if file_id and (file_id != cached_file_id or cached_fingerprint != fingerprint):
        _persist_media_cache(cfg, slot, file_id, fingerprint)
    message_id = int(result.get("message_id") or 0) if isinstance(result, dict) else 0
    _remember_control_message(cfg, chat_id, message_id)
    return message_id or 1


def _send_persistent_text(cfg: dict, chat_id: int | str, text: str) -> list[int]:
    """Send delivery text without adding it to the disposable control-message list.

    Credentials and configuration files are meant to remain in the chat so the
    administrator can forward them to the customer. Menu cleanup must therefore
    never delete these messages.
    """
    normalized = str(text or "").replace("\r\n", "\n").strip()
    if not normalized:
        return []
    chunks: list[str] = []
    current: list[str] = []
    current_len = 0
    for line in normalized.split("\n"):
        addition = len(line) + (1 if current else 0)
        if current and current_len + addition > 3900:
            chunks.append("\n".join(current))
            current = [line]
            current_len = len(line)
        else:
            current.append(line)
            current_len += addition
    if current:
        chunks.append("\n".join(current))

    sent: list[int] = []
    for chunk in chunks:
        ok, result = call_telegram_api(
            cfg["bot_token"],
            "sendMessage",
            data={
                "chat_id": chat_id,
                "text": chunk,
                "disable_web_page_preview": "true",
            },
            timeout=15,
            max_attempts=2,
        )
        if not ok:
            logger.warning("Telegram persistent text delivery failed: %s", result)
            continue
        if isinstance(result, dict) and result.get("message_id"):
            sent.append(int(result["message_id"]))
    return sent


def _send_document_bytes(
    cfg: dict,
    chat_id: int | str,
    filename: str,
    content: bytes | bytearray | memoryview | str,
    *,
    caption: str = "",
    mime_type: str = "application/octet-stream",
) -> bool:
    """Send an in-memory document and keep it permanently in the control chat."""
    payload = content.encode("utf-8") if isinstance(content, str) else bytes(content)
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", str(filename or "file")).strip("-._")[:120] or "file"
    data: dict[str, Any] = {"chat_id": chat_id}
    if caption:
        data.update({"caption": _customize_text(cfg, caption, html_mode=True)[:1000], "parse_mode": "HTML"})
    ok, result = call_telegram_api(
        cfg["bot_token"],
        "sendDocument",
        data=data,
        files={"document": (safe_name, payload, mime_type)},
        timeout=35,
        max_attempts=2,
    )
    if not ok:
        logger.warning("Telegram document delivery failed for %s: %s", safe_name, result)
        return False
    return True


def _send_main_menu(cfg: dict, chat_id: int | str, title: str = "🤖 <b>منوی کامل کنترل پنل</b>\nعملیات موردنظر را انتخاب کنید:") -> int | None:
    keyboard = _menu_keyboard()
    media_result = _send_media(cfg, chat_id, "main_menu", title, keyboard)
    if media_result is None:
        return _send(cfg, chat_id, title, keyboard)
    return media_result


def _user_keyboard(user: VpnUser, db=None) -> dict:
    admin = _actor(db) if db is not None else None
    toggle = "disable" if user.is_active else "enable"
    toggle_text = "⛔ غیرفعال‌کردن" if user.is_active else "✅ فعال‌کردن"
    rows = [
        [{"text": toggle_text, "callback_data": f"usr:{user.id}:{toggle}"}, {"text": "🔌 قطع اتصال", "callback_data": f"usr:{user.id}:disconnect"}],
        [{"text": "🔄 ریست حجم", "callback_data": f"usr:{user.id}:reset"}, {"text": "🗑 حذف", "callback_data": f"usr:{user.id}:delete"}],
        [{"text": "🔑 تغییر رمز", "callback_data": f"usr:{user.id}:edit_password"}, {"text": "📦 تغییر حجم", "callback_data": f"usr:{user.id}:edit_quota"}],
        [{"text": "📱 محدودیت دستگاه", "callback_data": f"usr:{user.id}:edit_devices"}, {"text": "⏳ تغییر اعتبار", "callback_data": f"usr:{user.id}:edit_days"}],
    ]
    scope_row = []
    if admin is None or _allowed_protocol_keys(admin):
        scope_row.append({"text": "🔌 انتخاب پروتکل‌ها", "callback_data": f"usr:{user.id}:edit_protocols"})
    if db is None or _target_options(db, admin):
        scope_row.append({"text": "🖥 انتخاب سرورها", "callback_data": f"usr:{user.id}:edit_targets"})
    if scope_row:
        rows.append(scope_row)
    delivery_row = [{"text": "📤 ارسال کانفیگ", "callback_data": f"usr:{user.id}:send_config"}]
    if bool(user.enable_openvpn) and (admin is None or admin_can_access_protocol(admin, "openvpn")):
        delivery_row.append({"text": "📁 فایل‌های OpenVPN", "callback_data": f"usr:{user.id}:openvpn_files"})
    rows.append(delivery_row)
    rows.extend([
        [{"text": "🔗 ارسال لینک و QR", "callback_data": f"usr:{user.id}:subscription"}],
        [{"text": "🔃 بروزرسانی", "callback_data": f"usr:{user.id}:show"}, {"text": "🔙 فهرست کاربران", "callback_data": "menu:users"}],
        [{"text": "🏠 منوی اصلی", "callback_data": "menu:home"}],
    ])
    return {"inline_keyboard": rows}


def _users_keyboard(db, search: str = "") -> dict:
    query = _bot_user_query(db)
    if search:
        query = query.filter(VpnUser.username.like(f"%{search}%"))
    rows = query.order_by(VpnUser.created_at.desc()).limit(20).all()
    buttons: list[list[dict[str, str]]] = []
    for user in rows:
        icon = "✅" if user.is_active else "⛔"
        buttons.append([{
            "text": f"{icon} {user.username} — {int(user.used_bytes or 0) / GB:.2f}GB",
            "callback_data": f"userpick:{user.id}",
        }])
    buttons.extend([
        [{"text": "🔎 جست‌وجوی کاربر", "callback_data": "menu:user"}, {"text": "➕ ساخت کاربر", "callback_data": "menu:create"}],
        [{"text": "🔃 بروزرسانی فهرست", "callback_data": "menu:users"}, {"text": "🏠 منوی اصلی", "callback_data": "menu:home"}],
    ])
    return {"inline_keyboard": buttons}


def _ip_menu_keyboard() -> dict:
    return {"inline_keyboard": [
        [{"text": "🚫 بن آی‌پی جدید", "callback_data": "menu:ban"}, {"text": "✅ رفع بن با واردکردن IP", "callback_data": "menu:unban"}],
        [{"text": "📋 فهرست آی‌پی‌های بن‌شده", "callback_data": "menu:bans"}],
        [{"text": "🏠 منوی اصلی", "callback_data": "menu:home"}],
    ]}


def _nodes_keyboard(db=None) -> dict:
    admin = _actor(db) if db is not None else None
    rows = []
    if admin is None or _has_permission(admin, "nodes:manage"):
        rows.append([{"text": "🔄 سینک نودهای مجاز", "callback_data": "menu:syncnodes"}, {"text": "🔃 بروزرسانی وضعیت", "callback_data": "menu:nodes"}])
    else:
        rows.append([{"text": "🔃 بروزرسانی وضعیت", "callback_data": "menu:nodes"}])
    rows.append([{"text": "🏠 منوی اصلی", "callback_data": "menu:home"}])
    return {"inline_keyboard": rows}


def _protocol_keyboard(rows: list[dict], *, server_id: str = "local", admin: Admin | None = None) -> dict:
    buttons = []
    for row in _visible_protocol_rows(admin, rows):
        key = str(row.get("key") or "")
        if not key:
            continue
        state = str(row.get("state") or row.get("health", {}).get("state") or "unknown").lower()
        icon = "🟢" if state == "active" else ("🟠" if state in {"activating", "deactivating"} else "🔴")
        prefix = "proto" if server_id == "local" else f"nproto:{server_id}"
        buttons.append([
            {"text": f"{icon} {PROTOCOL_LABELS.get(key, key)}", "callback_data": f"protosrv:{server_id}"},
            {"text": "▶️", "callback_data": f"{prefix}:{key}:start"},
            {"text": "⏹", "callback_data": f"{prefix}:{key}:stop"},
            {"text": "🔄", "callback_data": f"{prefix}:{key}:restart"},
        ])
    buttons.extend([
        [{"text": "🔙 انتخاب سرور", "callback_data": "menu:protocols"}],
        [{"text": "🏠 منوی اصلی", "callback_data": "menu:home"}],
    ])
    return {"inline_keyboard": buttons}


def _protocol_servers_payload(db) -> tuple[str, dict]:
    lines = ["🔌 <b>پروتکل‌های همه سرورها</b>", "سرور موردنظر را انتخاب کنید:"]
    buttons: list[list[dict[str, str]]] = []
    admin = _actor(db)
    nodes = db.query(VpnNode).filter(VpnNode.enabled == True).order_by(VpnNode.id).all()  # noqa: E712
    nodes = [node for node in nodes if admin_can_access_target(admin, f"node:{int(node.id)}")]
    if admin_can_access_target(admin, "local"):
        buttons = [[{"text": "🏠 سرور اصلی", "callback_data": "protosrv:local"}]]
    else:
        buttons = []
    for node in nodes:
        icon = "🟢" if node.status == "online" else "🔴"
        lines.append(f"{icon} {_e(node.name)} — {_e(node.status or 'unknown')}")
        buttons.append([{
            "text": f"{icon} {node.name}",
            "callback_data": f"protosrv:{int(node.id)}",
        }])
    if _has_permission(admin, "nodes:manage"):
        buttons.append([{"text": "🔄 سینک نودهای مجاز", "callback_data": "menu:syncnodes"}])
    buttons.append([{"text": "🏠 منوی اصلی", "callback_data": "menu:home"}])
    return "\n".join(lines), {"inline_keyboard": buttons}


def _node_protocol_rows(node: VpnNode) -> list[dict]:
    try:
        snapshot = json.loads(node.last_snapshot or "{}")
    except Exception:
        snapshot = {}
    rows = snapshot.get("protocol_statuses") if isinstance(snapshot, dict) else []
    if not isinstance(rows, list):
        rows = []
    normalized: list[dict] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        key = str(row.get("key") or "").lower()
        if key in set(PROTOCOLS) | {"ipsec"}:
            normalized.append(dict(row))
    return normalized


def _protocol_server_payload(db, server_id: str) -> tuple[str, dict]:
    admin = _actor(db)
    target_token = "local" if server_id == "local" else f"node:{int(server_id)}"
    if not admin_can_access_target(admin, target_token):
        raise ValueError("این سرور در محدوده دسترسی ادمین شما نیست")
    if server_id == "local":
        rows = get_protocol_runtime_summary(db, force=False)
        name = "سرور اصلی"
        status = "online"
    else:
        node = db.query(VpnNode).filter(VpnNode.id == int(server_id)).first()
        if not node:
            raise ValueError("نود پیدا نشد")
        rows = _node_protocol_rows(node)
        name = node.name
        status = node.status or "unknown"
    rows = _visible_protocol_rows(admin, rows)
    lines = [f"🔌 <b>پروتکل‌های {_e(name)}</b>", f"وضعیت سرور: <b>{_e(status)}</b>"]
    if not rows:
        lines.append("هنوز وضعیت پروتکل‌ها از این سرور دریافت نشده است؛ یک‌بار سینک نودها را بزنید.")
    for row in rows:
        key = str(row.get("key") or "")
        state = str(row.get("state") or row.get("health", {}).get("state") or "unknown")
        lines.append(f"• {_e(row.get('label') or PROTOCOL_LABELS.get(key, key))}: <b>{_e(state)}</b>")
    return "\n".join(lines), _protocol_keyboard(rows, server_id=server_id, admin=admin)


def _control_node_protocol(db, node_id: int, key: str, action: str) -> str:
    key = str(key or "").lower().strip()
    action = str(action or "").lower().strip()
    admin = _actor(db)
    if not admin_can_access_protocol(admin, key):
        raise ValueError("این گزینه در محدوده دسترسی حساب شما نیست")
    if key not in set(PROTOCOLS) | {"ipsec"}:
        raise ValueError("پروتکل نامعتبر است")
    if action not in {"start", "stop", "restart"}:
        raise ValueError("عملیات پروتکل نامعتبر است")
    if not admin_can_access_target(admin, f"node:{int(node_id)}"):
        raise ValueError("این سرور در محدوده دسترسی حساب شما نیست")
    node = db.query(VpnNode).filter(VpnNode.id == int(node_id)).first()
    if not node or not node.enabled:
        raise ValueError("نود فعال پیدا نشد")
    payload = {
        "method": "POST",
        "path": f"/api/settings/protocol-center/{key}/service/{action}",
        "params": {},
        "body": None,
    }
    try:
        response = requests.post(
            f"{node.api_url.rstrip('/')}/api/node-agent/protocol-proxy",
            headers={"X-Node-Token": node.api_token},
            json=payload,
            timeout=180,
            verify=bool(getattr(node, "verify_tls", True)),
        )
    except requests.RequestException as exc:
        raise ValueError(f"ارتباط با نود ناموفق بود: {exc}") from exc
    detail = response.text[-800:] if response.content else ""
    try:
        body = response.json()
        if isinstance(body, dict):
            detail = str(body.get("message") or body.get("detail") or detail)
    except Exception:
        pass
    if response.status_code in {404, 405, 501}:
        try:
            from app.routers.nodes import _direct_node_admin_response
            from app.schemas import NodeProtocolProxyRequest
            response = _direct_node_admin_response(node, NodeProtocolProxyRequest(**payload))
            detail = response.text[-800:] if getattr(response, "content", None) else ""
        except Exception as exc:
            raise ValueError(f"نود قدیمی است و مسیر جایگزین هم ناموفق بود: {exc}") from exc
    if response.status_code >= 400:
        raise ValueError(f"عملیات روی نود ناموفق بود: {detail or response.status_code}")
    sync_all_nodes_async()
    log_event(
        "🤖 کنترل پروتکل نود از ربات",
        f"نود: {node.name} | پروتکل: {key} | عملیات: {action}",
        actor=admin.username,
    )
    return f"✅ {PROTOCOL_LABELS.get(key, key)} روی نود {node.name}: {action}"



def _online_users_payload(db) -> tuple[str, dict]:
    # Reuse the same controller+node aggregation used by the web panel. This
    # fixes the old bot behavior that inspected only the controller's local
    # ConnectionLog table and therefore missed users connected through nodes.
    from app.routers.dashboard import online_users as dashboard_online_users

    groups = dashboard_online_users(db=db, admin=_actor(db))
    if not groups:
        return (
            "🟢 در حال حاضر کاربر آنلاینی ثبت نشده است.",
            {"inline_keyboard": [[
                {"text": "🔃 بروزرسانی", "callback_data": "menu:online"},
                {"text": "🏠 منوی اصلی", "callback_data": "menu:home"},
            ]]},
        )

    lines = ["🟢 <b>کاربران آنلاین در سرورهای مجاز این حساب</b>"]
    buttons: list[list[dict[str, str]]] = []
    total_sessions = 0
    for group in groups[:30]:
        if not isinstance(group, dict):
            continue
        username = str(group.get("username") or "?")
        user_id = int(group.get("user_id") or 0)
        sessions = [row for row in (group.get("sessions") or []) if isinstance(row, dict)]
        total_sessions += len(sessions)
        lines.append(f"\n👤 <code>{_e(username)}</code> — <b>{len(sessions)}</b> اتصال")
        for session in sessions[:8]:
            server_name = str(session.get("server_name") or ("سرور اصلی" if session.get("server_local") else "نود"))
            protocol = PROTOCOL_LABELS.get(str(session.get("protocol") or "").lower(), str(session.get("protocol") or "—"))
            ip_address = str(session.get("ip_address") or "—")
            lines.append(f"  • {_e(server_name)} | {_e(protocol)} | <code>{_e(ip_address)}</code>")
        if user_id:
            buttons.append([
                {"text": f"👤 مدیریت {username}", "callback_data": f"usr:{user_id}:show"},
                {"text": "🔌 قطع همه", "callback_data": f"onlinecut:{user_id}"},
            ])
    lines.insert(1, f"مجموع سشن‌ها: <b>{total_sessions}</b>")
    buttons.extend([
        [{"text": "🔃 بروزرسانی", "callback_data": "menu:online"}],
        [{"text": "🏠 منوی اصلی", "callback_data": "menu:home"}],
    ])
    return "\n".join(lines)[:3900], {"inline_keyboard": buttons[:35]}


def _disconnect_user_everywhere(db, user_id: int) -> tuple[int, list[str]]:
    from app.routers import users as users_router
    from app.routers.dashboard import online_users as dashboard_online_users

    admin = _actor(db)
    user = _bot_user_by_id(db, int(user_id))
    if not user:
        raise ValueError("کاربر پیدا نشد")
    groups = dashboard_online_users(db=db, admin=admin)
    target_group = next((row for row in groups if isinstance(row, dict) and int(row.get("user_id") or 0) == user.id), None)
    remote_sessions = []
    if target_group:
        remote_sessions = [
            row for row in (target_group.get("sessions") or [])
            if isinstance(row, dict) and not bool(row.get("server_local"))
        ]

    local_result = users_router.disconnect_user(user.id, db, admin)
    closed = int(local_result.get("closed_sessions") or 0)
    warnings: list[str] = []
    for session in remote_sessions:
        server_id = str(session.get("server_id") or "")
        session_id = int(session.get("id") or 0)
        if not server_id.startswith("node:") or not session_id:
            continue
        node_id = int(server_id.split(":", 1)[1])
        node = db.query(VpnNode).filter(VpnNode.id == node_id).first()
        if not node or not node.enabled:
            continue
        try:
            response = requests.post(
                f"{node.api_url.rstrip('/')}/api/node-agent/sessions/{session_id}/disconnect",
                headers={"X-Node-Token": node.api_token},
                timeout=45,
                verify=bool(getattr(node, "verify_tls", True)),
            )
            if response.status_code < 400:
                closed += 1
            else:
                warnings.append(f"{node.name}: {response.text[-160:]}")
        except requests.RequestException as exc:
            warnings.append(f"{node.name}: {exc}")
    sync_all_nodes_async()
    return closed, warnings


def _internet_blocks_payload(db) -> tuple[str, dict]:
    from app.security import can_view_all_users
    admin = _require_permission(db, "internet_blocks:view")
    query = db.query(InternetBlockedIP)
    if not can_view_all_users(admin):
        query = query.filter(InternetBlockedIP.owner_admin_id == admin.id)
    rows = query.order_by(InternetBlockedIP.created_at.desc()).limit(30).all()
    lines = ["⛔ <b>قطع اینترنت عمومی VPN</b>"]
    buttons: list[list[dict[str, str]]] = []
    if not rows:
        lines.append("هیچ آی‌پی در این فهرست نیست.")
    for row in rows:
        label = f"{row.ip_address}" + (f" — {row.username}" if row.username else "")
        lines.append(f"• <code>{_e(label)}</code>")
        buttons.append([{"text": f"✅ وصل مجدد {row.ip_address}", "callback_data": f"inet:restore:{row.ip_address}"}])
    buttons.extend([
        [{"text": "⛔ قطع اینترنت یک IP", "callback_data": "inet:ask"}],
        [{"text": "🔃 بروزرسانی", "callback_data": "menu:internet"}, {"text": "🏠 منوی اصلی", "callback_data": "menu:home"}],
    ])
    return "\n".join(lines), {"inline_keyboard": buttons}


def _admins_payload(db) -> tuple[str, dict]:
    rows = db.query(Admin).order_by(Admin.id.asc()).all()
    lines = ["🛡 <b>ادمین‌ها</b>"]
    buttons: list[list[dict[str, str]]] = []
    for row in rows:
        role = "سوپرادمین" if row.role == AdminRole.superadmin else "ادمین"
        _, login_display = server_datetime_payload(db, getattr(row, "last_login_at", None)) if getattr(row, "last_login_at", None) else (None, None)
        lines.append(f"{'✅' if row.is_active else '⛔'} <code>{_e(row.username)}</code> — {role} — آخرین ورود: {_e(login_display or 'بدون ورود')}")
        if row.role != AdminRole.superadmin:
            action = "disable" if row.is_active else "enable"
            label = "⛔ غیرفعال" if row.is_active else "✅ فعال"
            buttons.append([{"text": f"👤 {row.username}", "callback_data": f"admin:{row.id}:show"}, {"text": label, "callback_data": f"admin:{row.id}:{action}"}])
    buttons.extend([
        [{"text": "➕ ساخت ادمین زیرمجموعه", "callback_data": "admin:new"}],
        [{"text": "🎫 ساخت لایسنس ادمین", "callback_data": "license:new"}],
        [{"text": "🔃 بروزرسانی", "callback_data": "menu:admins"}, {"text": "🏠 منوی اصلی", "callback_data": "menu:home"}],
    ])
    return "\n".join(lines), {"inline_keyboard": buttons}


def _admin_permission_keyboard(selected: set[str]) -> dict:
    buttons: list[list[dict[str, str]]] = []
    row: list[dict[str, str]] = []
    for index, token in enumerate(ADMIN_PERMISSION_TOKENS):
        label = ADMIN_PERMISSION_LABELS.get(token, token)
        row.append({
            "text": f"{'✅' if token in selected else '⬜️'} {label}",
            "callback_data": f"adperm:{index}",
        })
        if len(row) == 2:
            buttons.append(row); row = []
    if row:
        buttons.append(row)
    buttons.extend([
        [{"text": "☑️ دسترسی کامل", "callback_data": "adperm:all"}, {"text": "🧹 پاک‌کردن", "callback_data": "adperm:none"}],
        [{"text": "✅ تأیید دسترسی‌ها", "callback_data": "adperm:confirm"}],
        [{"text": "❌ لغو", "callback_data": "flow:cancel"}],
    ])
    return {"inline_keyboard": buttons}


def _admin_target_keyboard(db, selected: set[str]) -> dict:
    buttons: list[list[dict[str, str]]] = []
    row: list[dict[str, str]] = []
    for token, label in _target_options(db):
        row.append({
            "text": f"{'✅' if token in selected else '⬜️'} {label}",
            "callback_data": f"adtgt:{token}",
        })
        if len(row) == 2:
            buttons.append(row); row = []
    if row:
        buttons.append(row)
    buttons.extend([
        [{"text": "☑️ همه سرورها", "callback_data": "adtgt:all"}, {"text": "🧹 پاک‌کردن", "callback_data": "adtgt:none"}],
        [{"text": "✅ تأیید سرورها", "callback_data": "adtgt:confirm"}],
        [{"text": "❌ لغو", "callback_data": "flow:cancel"}],
    ])
    return {"inline_keyboard": buttons}


def _admin_limit_keyboard(kind: str) -> dict:
    if kind == "users":
        options = [("10", "10"), ("50", "50"), ("100", "100"), ("نامحدود", "0")]
        prefix = "adusers"
    else:
        options = [("100 GB", "100"), ("500 GB", "500"), ("1000 GB", "1000"), ("نامحدود", "0")]
        prefix = "adquota"
    return {"inline_keyboard": [
        [{"text": label, "callback_data": f"{prefix}:{value}"} for label, value in options[:2]],
        [{"text": label, "callback_data": f"{prefix}:{value}"} for label, value in options[2:]],
        [{"text": "✍️ مقدار دلخواه", "callback_data": f"{prefix}:custom"}],
        [{"text": "❌ لغو", "callback_data": "flow:cancel"}],
    ]}


def _admin_expiry_keyboard() -> dict:
    return {"inline_keyboard": [
        [{"text": "بدون انقضا", "callback_data": "adexp:none"}],
        [{"text": "۳۰ روز", "callback_data": "adexp:30"}, {"text": "۹۰ روز", "callback_data": "adexp:90"}],
        [{"text": "۱۸۰ روز", "callback_data": "adexp:180"}, {"text": "۳۶۵ روز", "callback_data": "adexp:365"}],
        [{"text": "📅 تاریخ دقیق دلخواه", "callback_data": "adexp:custom"}],
        [{"text": "❌ لغو", "callback_data": "flow:cancel"}],
    ]}


def _admin_create_summary(data: dict) -> str:
    permissions = data.get("permissions") or []
    permission_labels = [ADMIN_PERMISSION_LABELS.get(token, token) for token in permissions]
    targets = data.get("targets") or []
    return "\n".join([
        "🛡 <b>تأیید ساخت ادمین زیرمجموعه</b>",
        f"نام کاربری: <code>{_e(data.get('username'))}</code>",
        f"رمز: <code>{_e(data.get('password'))}</code>",
        f"دسترسی به همه کاربران: <b>{'بله' if data.get('see_all_users') else 'خیر'}</b>",
        f"سرورها: <b>{_e('همه' if targets == ['all'] else '، '.join(targets))}</b>",
        f"حداکثر کاربر: <b>{data.get('max_users') or 'نامحدود'}</b>",
        f"سقف حجم کل: <b>{str(data.get('max_total_quota_gb')) + ' GB' if data.get('max_total_quota_gb') else 'نامحدود'}</b>",
        f"انقضا: <b>{_e(data.get('subscription_expire_date') or 'بدون انقضا')}</b>",
        f"ربات خصوصی: <b>{'فعال' if data.get('telegram_bot_enabled') else 'غیرفعال'}</b>",
        f"آیدی تلگرام: <code>{_e(data.get('telegram_user_id') or '—')}</code>",
        f"دسترسی‌ها ({len(permissions)}): {_e('، '.join(permission_labels[:12]))}{'…' if len(permission_labels) > 12 else ''}",
    ])


def _create_subadmin_from_data(db, data: dict) -> Admin:
    from app.schemas import AdminCreate

    payload = AdminCreate(
        username=str(data.get("username") or ""),
        password=str(data.get("password") or ""),
        role="admin",
        permissions=list(data.get("permissions") or []),
        see_all_users=bool(data.get("see_all_users")),
        server_targets=list(data.get("targets") or []),
        max_users=data.get("max_users"),
        max_total_quota_gb=data.get("max_total_quota_gb"),
        subscription_expire_date=(
            date.fromisoformat(str(data["subscription_expire_date"]))
            if data.get("subscription_expire_date") else None
        ),
        telegram_bot_enabled=bool(data.get("telegram_bot_enabled")),
        telegram_user_id=(int(data["telegram_user_id"]) if data.get("telegram_user_id") else None),
    )
    if db.query(Admin).filter(Admin.username == payload.username).first():
        raise ValueError("این نام کاربری ادمین قبلاً استفاده شده است")
    _ensure_telegram_binding_available(db, payload.telegram_user_id if payload.telegram_bot_enabled else None)
    targets = validate_admin_target_tokens(db, payload.server_targets)
    row = Admin(
        username=payload.username,
        password_hash=hash_password(payload.password),
        role=AdminRole.admin,
        permissions=",".join(payload.permissions),
        see_all_users=payload.see_all_users,
        server_targets=serialize_admin_targets(targets),
        max_users=payload.max_users,
        max_total_quota_bytes=(int(payload.max_total_quota_gb * GB) if payload.max_total_quota_gb is not None else None),
        subscription_expire_date=payload.subscription_expire_date,
        telegram_bot_enabled=bool(payload.telegram_bot_enabled),
        telegram_user_id=payload.telegram_user_id if payload.telegram_bot_enabled else None,
        is_active=True,
    )
    db.add(row); db.commit(); db.refresh(row)
    from app.routers.admins import _admin_change_log, _admin_snapshot
    log_event(
        "➕ ساخت ادمین از ربات",
        _admin_change_log(row.username, {}, _admin_snapshot(row), created=True),
        actor=_actor(db).username,
    )
    return row


def _admin_card(admin_row: Admin, db=None) -> tuple[str, dict]:
    permissions = [token for token in (admin_row.permissions or "").split(",") if token]
    targets = admin_row.server_targets or '["all"]'
    lines = [
        "🛡 <b>مشخصات ادمین</b>",
        f"نام کاربری: <code>{_e(admin_row.username)}</code>",
        f"نقش: <b>{_e(admin_row.role.value)}</b>",
        f"وضعیت: <b>{'فعال' if admin_row.is_active else 'غیرفعال'}</b>",
        f"آخرین ورود: <b>{_e((server_datetime_payload(db, getattr(admin_row, 'last_login_at', None))[1] if db is not None and getattr(admin_row, 'last_login_at', None) else 'بدون ورود'))}</b>",
        f"همه کاربران: <b>{'بله' if admin_row.see_all_users else 'خیر'}</b>",
        f"سرورها: <code>{_e(targets)}</code>",
        f"حداکثر کاربر: <b>{admin_row.max_users or 'نامحدود'}</b>",
        f"سقف حجم کل: <b>{(admin_row.max_total_quota_bytes / GB) if admin_row.max_total_quota_bytes is not None else 'نامحدود'}</b>",
        f"انقضا: <b>{_e(admin_row.subscription_expire_date or admin_row.subscription_expire_at or 'بدون انقضا')}</b>",
        f"ربات خصوصی: <b>{'فعال' if getattr(admin_row, 'telegram_bot_enabled', False) else 'غیرفعال'}</b>",
        f"آیدی تلگرام: <code>{_e(getattr(admin_row, 'telegram_user_id', None) or '—')}</code>",
        f"تعداد دسترسی‌ها: <b>{len(permissions)}</b>",
    ]
    keyboard = {"inline_keyboard": [
        [{"text": "⛔ غیرفعال" if admin_row.is_active else "✅ فعال", "callback_data": f"admin:{admin_row.id}:{'disable' if admin_row.is_active else 'enable'}"}],
        [{"text": "🔙 ادمین‌ها", "callback_data": "menu:admins"}, {"text": "🏠 منوی اصلی", "callback_data": "menu:home"}],
    ]}
    return "\n".join(lines), keyboard


def _license_status_label(row: AdminAccessLicense) -> str:
    if row.used_by_admin_id:
        return "استفاده‌شده"
    return "فعال" if row.is_active else "غیرفعال"


def _licenses_payload(db) -> tuple[str, dict]:
    rows = db.query(AdminAccessLicense).order_by(AdminAccessLicense.created_at.desc()).limit(30).all()
    lines = ["🎫 <b>لایسنس‌های داخلی ادمین</b>"]
    buttons: list[list[dict[str, str]]] = []
    if not rows:
        lines.append("هنوز لایسنسی ساخته نشده است.")
    for row in rows:
        role = "سوپرادمین" if row.role == AdminRole.superadmin else "ادمین"
        lines.append(f"• <code>{_e(row.code)}</code> — {role} — {_license_status_label(row)}")
        buttons.append([{"text": f"🎫 {row.code[:11]}…", "callback_data": f"license:{row.id}:show"}])
    buttons.extend([
        [{"text": "➕ ساخت لایسنس جدید", "callback_data": "license:new"}],
        [{"text": "🔃 بروزرسانی", "callback_data": "menu:licenses"}, {"text": "🏠 منوی اصلی", "callback_data": "menu:home"}],
    ])
    return "\n".join(lines), {"inline_keyboard": buttons}


def _license_card(row: AdminAccessLicense) -> tuple[str, dict]:
    role = "سوپرادمین" if row.role == AdminRole.superadmin else "ادمین"
    duration = "بدون مدت مشخص"
    if row.duration_minutes:
        minutes = int(row.duration_minutes)
        duration = f"{minutes // 1440} روز" if minutes % 1440 == 0 else f"{minutes} دقیقه"
    lines = [
        "🎫 <b>مشخصات لایسنس داخلی</b>",
        f"کد: <code>{_e(row.code)}</code>",
        f"نقش: <b>{role}</b>",
        f"وضعیت: <b>{_license_status_label(row)}</b>",
        f"اعتبار بعد از فعال‌سازی: <b>{_e(duration)}</b>",
        f"ربات خصوصی: <b>{'فعال' if getattr(row, 'telegram_bot_enabled', False) else 'غیرفعال'}</b>",
        f"آیدی تلگرام: <code>{_e(getattr(row, 'telegram_user_id', None) or '—')}</code>",
    ]
    if row.max_users:
        lines.append(f"حداکثر کاربر: <b>{row.max_users}</b>")
    if row.max_total_quota_bytes is not None:
        lines.append(f"سقف حجم کل: <b>{int(row.max_total_quota_bytes) / GB:g} GB</b>")
    if row.used_by_admin_id:
        lines.append(f"استفاده‌شده توسط ادمین ID: <code>{row.used_by_admin_id}</code>")
    keyboard: list[list[dict[str, str]]] = []
    if not row.used_by_admin_id:
        keyboard.append([{"text": "⛔ غیرفعال" if row.is_active else "✅ فعال", "callback_data": f"license:{row.id}:{'disable' if row.is_active else 'enable'}"}])
        keyboard.append([{"text": "🗑 حذف لایسنس", "callback_data": f"license:{row.id}:delete"}])
    keyboard.extend([[{"text": "🔙 فهرست لایسنس‌ها", "callback_data": "menu:licenses"}, {"text": "🏠 منوی اصلی", "callback_data": "menu:home"}]])
    return "\n".join(lines), {"inline_keyboard": keyboard}


def _license_role_keyboard() -> dict:
    return {"inline_keyboard": [
        [{"text": "👑 سوپرادمین کامل", "callback_data": "licrole:superadmin"}],
        [{"text": "🛡 ادمین زیرمجموعه", "callback_data": "licrole:admin"}],
        [{"text": "❌ لغو", "callback_data": "flow:cancel"}],
    ]}


def _license_permission_keyboard() -> dict:
    return {"inline_keyboard": [
        [{"text": "✅ دسترسی کامل ادمین", "callback_data": "licperm:full"}],
        [{"text": "👥 فقط کاربران و آنلاین‌ها", "callback_data": "licperm:users"}],
        [{"text": "🛠 کاربران + پروتکل‌ها + نودها", "callback_data": "licperm:operator"}],
        [{"text": "❌ لغو", "callback_data": "flow:cancel"}],
    ]}


def _license_limits_keyboard(kind: str) -> dict:
    if kind == "max_users":
        values = [("10", "10"), ("50", "50"), ("100", "100"), ("نامحدود", "0")]
        prefix = "licusers"
    else:
        values = [("100 GB", "100"), ("500 GB", "500"), ("1000 GB", "1000"), ("نامحدود", "0")]
        prefix = "licquota"
    return {"inline_keyboard": [
        [{"text": label, "callback_data": f"{prefix}:{value}"} for label, value in values[:2]],
        [{"text": label, "callback_data": f"{prefix}:{value}"} for label, value in values[2:]],
        [{"text": "✍️ مقدار دلخواه", "callback_data": f"{prefix}:custom"}],
        [{"text": "❌ لغو", "callback_data": "flow:cancel"}],
    ]}


def _license_duration_keyboard() -> dict:
    return {"inline_keyboard": [
        [{"text": "۱ روز", "callback_data": "licdays:1"}, {"text": "۷ روز", "callback_data": "licdays:7"}],
        [{"text": "۳۰ روز", "callback_data": "licdays:30"}, {"text": "۹۰ روز", "callback_data": "licdays:90"}],
        [{"text": "۱۸۰ روز", "callback_data": "licdays:180"}, {"text": "۳۶۵ روز", "callback_data": "licdays:365"}],
        [{"text": "✍️ تعداد روز دلخواه", "callback_data": "licdays:custom"}],
        [{"text": "❌ لغو", "callback_data": "flow:cancel"}],
    ]}


def _license_bot_keyboard() -> dict:
    return {"inline_keyboard": [
        [{"text": "✅ فعال‌سازی ربات خصوصی", "callback_data": "licbot:on"}],
        [{"text": "⛔ بدون دسترسی ربات", "callback_data": "licbot:off"}],
        [{"text": "❌ لغو", "callback_data": "flow:cancel"}],
    ]}


def _admin_bot_keyboard() -> dict:
    return {"inline_keyboard": [
        [{"text": "✅ فعال‌سازی ربات خصوصی", "callback_data": "adbot:on"}],
        [{"text": "⛔ بدون دسترسی ربات", "callback_data": "adbot:off"}],
        [{"text": "❌ لغو", "callback_data": "flow:cancel"}],
    ]}


def _license_target_keyboard(db, selected: set[str]) -> dict:
    buttons: list[list[dict[str, str]]] = []
    row: list[dict[str, str]] = []
    for token, label in _target_options(db):
        row.append({"text": f"{'✅' if token in selected else '⬜️'} {label}", "callback_data": f"lictgt:{token}"})
        if len(row) == 2:
            buttons.append(row); row = []
    if row:
        buttons.append(row)
    buttons.extend([
        [{"text": "☑️ همه سرورها", "callback_data": "lictgt:all"}, {"text": "🧹 پاک‌کردن", "callback_data": "lictgt:none"}],
        [{"text": "✅ تأیید سرورها", "callback_data": "lictgt:confirm"}, {"text": "❌ لغو", "callback_data": "flow:cancel"}],
    ])
    return {"inline_keyboard": buttons}


def _license_confirm_text(data: dict) -> str:
    role = "سوپرادمین" if data.get("role") == "superadmin" else "ادمین"
    targets = "همه" if data.get("targets") == ["all"] else "، ".join(data.get("targets") or [])
    max_users = data.get("max_users") or "نامحدود"
    max_quota = data.get("max_total_quota_gb") or "نامحدود"
    return "\n".join([
        "🎫 <b>تأیید ساخت لایسنس</b>",
        f"نقش: <b>{role}</b>",
        f"اعتبار: <b>{data.get('days')} روز بعد از فعال‌سازی</b>",
        f"سرورها: <b>{_e(targets or '—')}</b>",
        f"حداکثر کاربر: <b>{max_users}</b>",
        f"سقف حجم کل: <b>{max_quota}{' GB' if max_quota != 'نامحدود' else ''}</b>",
        f"ربات خصوصی: <b>{'فعال' if data.get('telegram_bot_enabled') else 'غیرفعال'}</b>",
        f"آیدی تلگرام: <b>{'هنگام ثبت‌نام دریافت می‌شود' if data.get('telegram_bot_enabled') else '—'}</b>",
    ])




def _create_internal_license_from_data(db, data: dict) -> AdminAccessLicense:
    role = str(data.get("role") or "admin")
    payload = AdminAccessLicenseCreate(
        role=role,
        permissions=list(data.get("permissions") or []),
        see_all_users=bool(data.get("see_all_users", False)),
        server_targets=list(data.get("targets") or ([] if role == "admin" else [])),
        max_users=(int(data["max_users"]) if data.get("max_users") else None),
        max_total_quota_gb=(float(data["max_total_quota_gb"]) if data.get("max_total_quota_gb") else None),
        expire_mode="after_activation",
        duration_minutes=max(1, int(data.get("days") or 30)) * 1440,
        telegram_bot_enabled=bool(data.get("telegram_bot_enabled")),
        telegram_user_id=None,
        note="ساخته‌شده از ربات تلگرام",
    )
    is_subadmin = payload.role == "admin"
    row = AdminAccessLicense(
        code=generate_code(db),
        role=AdminRole(payload.role),
        permissions=",".join(payload.permissions) if is_subadmin else "",
        see_all_users=payload.see_all_users if is_subadmin else False,
        server_targets=(serialize_admin_targets(validate_admin_target_tokens(db, payload.server_targets)) if is_subadmin else None),
        max_users=payload.max_users if is_subadmin else None,
        max_total_quota_bytes=(int(payload.max_total_quota_gb * GB) if (is_subadmin and payload.max_total_quota_gb is not None) else None),
        expire_mode="after_activation",
        duration_minutes=payload.duration_minutes,
        fixed_expire_at=None,
        is_active=True,
        telegram_bot_enabled=bool(payload.telegram_bot_enabled),
        telegram_user_id=None,
        note=payload.note,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    log_event("🪪 ساخت لایسنس داخلی ادمین از ربات", f"کد: {row.code}", actor=_actor(db).username)
    return row

def _update_keyboard() -> dict:
    return {"inline_keyboard": [
        [{"text": "🔎 بررسی نسخه جدید", "callback_data": "update:check"}, {"text": "📊 وضعیت آپدیت", "callback_data": "update:status"}],
        [{"text": "🧾 آخرین لاگ آپدیت", "callback_data": "update:log"}],
        [{"text": "🏠 منوی اصلی", "callback_data": "menu:home"}],
    ]}


def _panel_license_keyboard() -> dict:
    return {"inline_keyboard": [
        [{"text": "🔃 بروزرسانی وضعیت", "callback_data": "panellic:status"}],
        [{"text": "🔑 فعال‌سازی کد", "callback_data": "panellic:activate"}, {"text": "🗓 رزرو کد بعدی", "callback_data": "panellic:reserve"}],
        [{"text": "🏠 منوی اصلی", "callback_data": "menu:home"}],
    ]}


def _tools_keyboard(db=None) -> dict:
    admin = _actor(db) if db is not None else None
    rows: list[list[dict[str, str]]] = []
    quick: list[dict[str, str]] = []
    if admin is None or _has_permission(admin, "nodes:manage"):
        quick.append({"text": "🔄 سینک نودهای مجاز", "callback_data": "menu:syncnodes"})
    if admin is not None and admin.role == AdminRole.superadmin:
        quick.append({"text": "📦 بکاپ فوری", "callback_data": "menu:backup"})
    if quick:
        rows.append(quick)
    status_row: list[dict[str, str]] = []
    if admin is None or _has_permission(admin, "protocols:view"):
        status_row.append({"text": "🔌 وضعیت پروتکل‌های مجاز", "callback_data": "menu:protocols"})
    status_row.append({"text": "🆔 شناسه تلگرام", "callback_data": "menu:myid"})
    rows.append(status_row)
    rows.append([{"text": "🏠 منوی اصلی", "callback_data": "menu:home"}])
    return {"inline_keyboard": rows}

def _protocol_selector_keyboard(
    selected: set[str], *, mode: str, user_id: int | None = None, admin: Admin | None = None
) -> dict:
    """Checkbox-like selector containing only this admin's visible protocols."""
    prefix = "cproto" if mode == "create" else f"eproto:{int(user_id or 0)}"
    allowed = _allowed_protocol_keys(admin)
    selected = {key for key in selected if key in allowed}
    buttons: list[list[dict[str, str]]] = []
    row: list[dict[str, str]] = []
    for key in allowed:
        icon = "✅" if key in selected else "⬜️"
        row.append({"text": f"{icon} {PROTOCOL_LABELS[key]}", "callback_data": f"{prefix}:{key}"})
        if len(row) == 2:
            buttons.append(row)
            row = []
    if row:
        buttons.append(row)
    if len(allowed) > 1:
        buttons.append([
            {"text": "☑️ انتخاب همه", "callback_data": f"{prefix}:all"},
            {"text": "🧹 پاک‌کردن", "callback_data": f"{prefix}:none"},
        ])
    buttons.append([
        {"text": "✅ تأیید پروتکل‌ها", "callback_data": f"{prefix}:confirm"},
        {"text": "❌ لغو", "callback_data": "flow:cancel"},
    ])
    return {"inline_keyboard": buttons}


def _protocol_selector_text(selected: set[str], *, editing: str = "", admin: Admin | None = None) -> str:
    allowed = _allowed_protocol_keys(admin)
    chosen = "، ".join(PROTOCOL_LABELS[p] for p in allowed if p in selected) or "هیچ‌کدام"
    title = "🔌 <b>انتخاب پروتکل‌های کاربر</b>"
    if editing:
        title += f"\n👤 <code>{_e(editing)}</code>"
    if not allowed:
        return f"{title}\n\nهیچ گزینه‌ای در محدوده دسترسی این حساب فعال نیست."
    return f"{title}\n\nبا لمس هر دکمه، پروتکل انتخاب یا حذف می‌شود.\n\nانتخاب فعلی: <b>{_e(chosen)}</b>\nسپس دکمه «تأیید پروتکل‌ها» را بزنید."


def _target_options(db, admin: Admin | None = None) -> list[tuple[str, str]]:
    admin = admin or _actor(db)
    options: list[tuple[str, str]] = []
    if local_assignment_enabled(db) and admin_can_access_target(admin, "local"):
        options.append(("local", "سرور اصلی"))
    nodes = (
        db.query(VpnNode)
        .filter(VpnNode.enabled == True, VpnNode.user_assignment_enabled == True)  # noqa: E712
        .order_by(VpnNode.id.asc())
        .all()
    )
    options.extend(
        (f"node:{node.id}", node.name)
        for node in nodes
        if admin_can_access_target(admin, f"node:{int(node.id)}")
    )
    return options


def _target_selector_keyboard(
    db, selected: set[str], *, mode: str, user_id: int | None = None, admin: Admin | None = None
) -> dict:
    admin = admin or _actor(db)
    prefix = "ctgt" if mode == "create" else f"etgt:{int(user_id or 0)}"
    options = _target_options(db, admin)
    allowed_tokens = {token for token, _ in options}
    selected = {token for token in selected if token == "all" or token in allowed_tokens}
    buttons: list[list[dict[str, str]]] = []
    for token, label in options:
        checked = "all" in selected or token in selected
        buttons.append([{
            "text": f"{'✅' if checked else '⬜️'} {label}",
            "callback_data": f"{prefix}:{token}",
        }])
    if len(options) > 1:
        buttons.append([
            {"text": "🌐 همه سرورهای مجاز", "callback_data": f"{prefix}:all"},
            {"text": "🧹 پاک‌کردن", "callback_data": f"{prefix}:none"},
        ])
    buttons.append([
        {"text": "✅ تأیید سرورها", "callback_data": f"{prefix}:confirm"},
        {"text": "❌ لغو", "callback_data": "flow:cancel"},
    ])
    return {"inline_keyboard": buttons}


def _target_selector_text(
    db, selected: set[str], *, editing: str = "", admin: Admin | None = None
) -> str:
    admin = admin or _actor(db)
    labels = {token: label for token, label in _target_options(db, admin)}
    visible_selected = {token for token in selected if token == "all" or token in labels}
    if "all" in visible_selected:
        chosen = "همه سرورهای مجاز"
    else:
        chosen = "، ".join(labels[token] for token in sorted(visible_selected) if token in labels) or "هیچ‌کدام"
    title = "🖥 <b>انتخاب سرورهای کاربر</b>"
    if editing:
        title += f"\n👤 <code>{_e(editing)}</code>"
    if not labels:
        return f"{title}\n\nهیچ سروری در محدوده دسترسی این حساب فعال نیست."
    return f"{title}\n\nسرورهای موردنظر را دکمه‌ای انتخاب کنید.\n\nانتخاب فعلی: <b>{_e(chosen)}</b>\nسپس دکمه «تأیید سرورها» را بزنید."


def _create_quota_keyboard() -> dict:
    return {"inline_keyboard": [
        [
            {"text": "نامحدود", "callback_data": "create:quota:0"},
            {"text": "10 GB", "callback_data": "create:quota:10"},
            {"text": "20 GB", "callback_data": "create:quota:20"},
        ],
        [
            {"text": "50 GB", "callback_data": "create:quota:50"},
            {"text": "100 GB", "callback_data": "create:quota:100"},
            {"text": "✍️ مقدار دلخواه", "callback_data": "create:custom:quota"},
        ],
        [{"text": "❌ لغو", "callback_data": "flow:cancel"}],
    ]}


def _create_devices_keyboard() -> dict:
    return {"inline_keyboard": [
        [
            {"text": "1 دستگاه", "callback_data": "create:devices:1"},
            {"text": "2 دستگاه", "callback_data": "create:devices:2"},
            {"text": "3 دستگاه", "callback_data": "create:devices:3"},
        ],
        [
            {"text": "5 دستگاه", "callback_data": "create:devices:5"},
            {"text": "نامحدود", "callback_data": "create:devices:0"},
            {"text": "✍️ مقدار دلخواه", "callback_data": "create:custom:devices"},
        ],
        [{"text": "❌ لغو", "callback_data": "flow:cancel"}],
    ]}


def _create_days_keyboard() -> dict:
    return {"inline_keyboard": [
        [
            {"text": "7 روز", "callback_data": "create:days:7"},
            {"text": "15 روز", "callback_data": "create:days:15"},
            {"text": "30 روز", "callback_data": "create:days:30"},
        ],
        [
            {"text": "60 روز", "callback_data": "create:days:60"},
            {"text": "90 روز", "callback_data": "create:days:90"},
            {"text": "بدون انقضا", "callback_data": "create:days:0"},
        ],
        [{"text": "✍️ مقدار دلخواه", "callback_data": "create:custom:days"}, {"text": "❌ لغو", "callback_data": "flow:cancel"}],
    ]}


def _quota_edit_keyboard(user: VpnUser) -> dict:
    uid = user.id
    return {"inline_keyboard": [
        [
            {"text": "نامحدود", "callback_data": f"quota:set:{uid}:0"},
            {"text": "20 GB", "callback_data": f"quota:set:{uid}:20"},
            {"text": "50 GB", "callback_data": f"quota:set:{uid}:50"},
            {"text": "100 GB", "callback_data": f"quota:set:{uid}:100"},
        ],
        [
            {"text": "+10 GB", "callback_data": f"quota:add:{uid}:10"},
            {"text": "+20 GB", "callback_data": f"quota:add:{uid}:20"},
            {"text": "+50 GB", "callback_data": f"quota:add:{uid}:50"},
            {"text": "+100 GB", "callback_data": f"quota:add:{uid}:100"},
        ],
        [
            {"text": "✍️ تعیین مقدار دلخواه", "callback_data": f"quota:customset:{uid}"},
            {"text": "➕ افزودن مقدار دلخواه", "callback_data": f"quota:customadd:{uid}"},
        ],
        [{"text": "🔙 بازگشت به کاربر", "callback_data": f"usr:{uid}:show"}],
    ]}


def _devices_edit_keyboard(user: VpnUser) -> dict:
    uid = user.id
    return {"inline_keyboard": [
        [
            {"text": "1", "callback_data": f"devices:set:{uid}:1"},
            {"text": "2", "callback_data": f"devices:set:{uid}:2"},
            {"text": "3", "callback_data": f"devices:set:{uid}:3"},
            {"text": "5", "callback_data": f"devices:set:{uid}:5"},
            {"text": "نامحدود", "callback_data": f"devices:set:{uid}:0"},
        ],
        [{"text": "✍️ مقدار دلخواه", "callback_data": f"devices:custom:{uid}"}],
        [{"text": "🔙 بازگشت به کاربر", "callback_data": f"usr:{uid}:show"}],
    ]}


def _days_edit_keyboard(user: VpnUser) -> dict:
    uid = user.id
    return {"inline_keyboard": [
        [
            {"text": "بدون انقضا", "callback_data": f"days:set:{uid}:0"},
            {"text": "15 روز", "callback_data": f"days:set:{uid}:15"},
            {"text": "30 روز", "callback_data": f"days:set:{uid}:30"},
            {"text": "60 روز", "callback_data": f"days:set:{uid}:60"},
        ],
        [
            {"text": "+7 روز", "callback_data": f"days:add:{uid}:7"},
            {"text": "+15 روز", "callback_data": f"days:add:{uid}:15"},
            {"text": "+30 روز", "callback_data": f"days:add:{uid}:30"},
            {"text": "+90 روز", "callback_data": f"days:add:{uid}:90"},
        ],
        [
            {"text": "✍️ تعیین مقدار دلخواه", "callback_data": f"days:customset:{uid}"},
            {"text": "➕ افزودن مقدار دلخواه", "callback_data": f"days:customadd:{uid}"},
        ],
        [{"text": "🔙 بازگشت به کاربر", "callback_data": f"usr:{uid}:show"}],
    ]}


def _set_state(chat_id: int | str, user_id: int, state: dict[str, Any] | None) -> None:
    key = (str(chat_id), int(user_id))
    with _STATE_LOCK:
        if state is None:
            _STATES.pop(key, None)
        else:
            _STATES[key] = state


def _get_state(chat_id: int | str, user_id: int) -> dict[str, Any] | None:
    with _STATE_LOCK:
        state = _STATES.get((str(chat_id), int(user_id)))
        return dict(state) if state else None


def _valid_ipv4(raw: str) -> str:
    value = _normalize_digits(raw).strip()
    ip = ipaddress.ip_address(value)
    if ip.version != 4 or ip.is_unspecified or ip.is_multicast:
        raise ValueError("فقط IPv4 معتبر قابل استفاده است")
    return str(ip)


def _protocol_set(raw: str, admin: Admin | None = None) -> set[str]:
    value = _normalize_digits(raw).lower().replace("،", ",")
    aliases = {
        "oc": "openconnect", "open connect": "openconnect", "اوپن کانکت": "openconnect",
        "ovpn": "openvpn", "اوپن وی پی ان": "openvpn", "وی مس": "vmess", "وی لس": "vless",
    }
    for old, new in aliases.items():
        value = value.replace(old, new)
    if value.strip() in {"all", "همه", "تمام"}:
        return set(_allowed_protocol_keys(admin)) if admin is not None else set(PROTOCOLS)
    selected = {part.strip() for part in re.split(r"[,\s]+", value) if part.strip()}
    invalid = selected - set(PROTOCOLS)
    if invalid:
        raise ValueError("یک یا چند گزینه واردشده معتبر نیست")
    if admin is not None:
        allowed = set(_allowed_protocol_keys(admin))
        if not selected.issubset(allowed):
            raise ValueError("یک یا چند گزینه واردشده در محدوده دسترسی حساب شما نیست")
    if not selected:
        raise ValueError("حداقل یک پروتکل لازم است")
    return selected


def _targets(raw: str) -> list[str]:
    value = _normalize_digits(raw).lower().replace("،", ",").strip()
    if value in {"all", "همه", "تمام"}:
        return ["all"]
    result = [part.strip() for part in re.split(r"[,\s]+", value) if part.strip()]
    return result or ["all"]


def _parse_activity_stamp(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo is None else value.astimezone(timezone.utc).replace(tzinfo=None)
    try:
        stamp = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        return stamp if stamp.tzinfo is None else stamp.astimezone(timezone.utc).replace(tzinfo=None)
    except (TypeError, ValueError):
        return None


def _bot_user_activity(db, user: VpnUser, admin: Admin | None = None) -> tuple[bool, datetime | None]:
    """Merge local and node snapshots so Telegram shows fleet-wide activity."""
    admin = admin or _actor(db)
    online = db.query(ConnectionLog.id).filter(
        ConnectionLog.user_id == user.id,
        ConnectionLog.is_online == True,  # noqa: E712
        ConnectionLog.device_limit_blocked == False,  # noqa: E712
    ).first() is not None
    last = db.query(func.max(ConnectionLog.connect_time)).filter(ConnectionLog.user_id == user.id).scalar()
    for node in db.query(VpnNode).filter(VpnNode.enabled == True).all():  # noqa: E712
        if not admin_can_access_target(admin, f"node:{int(node.id)}") or not node.last_snapshot:
            continue
        try:
            snapshot = json.loads(node.last_snapshot or "{}")
        except (TypeError, ValueError):
            continue
        runtime = snapshot.get("user_runtime") if isinstance(snapshot.get("user_runtime"), dict) else {}
        item = runtime.get(user.username)
        if isinstance(item, dict):
            remote_last = _parse_activity_stamp(item.get("last_connection_at"))
            if remote_last and (last is None or remote_last > last):
                last = remote_last
            if node.status == "online":
                online = online or bool(item.get("is_online"))
        if node.status == "online" and not online:
            for group in snapshot.get("online_users") or []:
                if isinstance(group, dict) and str(group.get("username") or "") == user.username:
                    online = True
                    break
    return online, last


def _format_user(user: VpnUser, db, *, include_sub: bool = True) -> str:
    admin = _actor(db)
    allowed_protocols = _allowed_protocol_keys(admin)
    protocols = [PROTOCOL_LABELS[p] for p in allowed_protocols if bool(getattr(user, f"enable_{p}"))]
    quota = "نامحدود" if int(user.quota_bytes or 0) <= 0 else f"{user.quota_bytes / GB:.2f} GB"
    used = f"{int(user.used_bytes or 0) / GB:.2f} GB"
    expiry = "بدون انقضا"
    if user.expire_mode == "after_first_connect" and not user.first_connect_at:
        expiry = f"{user.expire_after_days or 0} روز بعد از اولین اتصال"
    elif user.expire_date:
        expiry = str(user.expire_date)
    online, last_connection = _bot_user_activity(db, user, admin)
    online_count = 1 if online else 0
    _, last_connection_display = server_datetime_payload(db, last_connection) if last_connection else (None, None)
    sub = build_sub_link(db, user.sub_token) if user.sub_token else None
    raw_targets = set(targets_for_user(user))
    target_labels = {token: label for token, label in _target_options(db, admin)}
    if "all" in raw_targets:
        visible_target_text = "همه سرورهای مجاز" if target_labels else "—"
    else:
        visible_target_text = "، ".join(
            target_labels[token] for token in sorted(raw_targets) if token in target_labels
        ) or "—"
    lines = [
        f"\u200f👤 نام کاربری: <code>{_e(user.username)}</code>",
        f"🔑 رمز: <code>{_e(user.password)}</code>",
        f"📌 وضعیت: {'فعال ✅' if user.is_active else 'غیرفعال ⛔'}",
        f"🟢 اتصال فعال: <b>{online_count}</b>",
        f"🕒 آخرین اتصال: <b>{'آنلاین' if online_count else _e(last_connection_display or 'هنوز متصل نشده')}</b>",
        f"📦 مصرف: <b>{used}</b> از <b>{quota}</b>",
        f"📱 حداکثر اتصال هم‌زمان: <b>{'نامحدود' if int(user.max_devices or 0) == 0 else int(user.max_devices or 0)}</b>",
        f"⏳ انقضا: <b>{_e(expiry)}</b>",
        f"🔌 پروتکل‌ها: {_e(', '.join(protocols) or '—')}",
        f"🖥 سرورها: <b>{_e(visible_target_text)}</b>",
    ]
    if include_sub and sub:
        safe_sub = _e(sub)
        lines.append(f'🔗 لینک اشتراک:\n<a href="{safe_sub}">{safe_sub}</a>')
    return "\n".join(lines)


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    """Build a standards-compliant PNG chunk without requiring Pillow."""
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF)
    )


def _subscription_qr_png(link: str, *, scale: int = 10, border: int = 6) -> bytes:
    """Return a compact, scanner-safe QR image for Telegram.

    Older releases rendered a heavy decorative 860x860 scene around the QR.
    Some Telegram clients downscaled it aggressively and the visual frame made
    the code look cropped.  This renderer keeps a generous white quiet zone,
    a thin orange frame and a neutral dark background; no text or decorative
    lines can overlap the QR modules.
    """
    if not link.startswith(("http://", "https://")):
        raise ValueError("لینک اشتراک معتبر نیست")

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_Q,
        box_size=1,
        border=0,
    )
    qr.add_data(link)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    modules = len(matrix)
    if not modules or any(len(row) != modules for row in matrix):
        raise ValueError("ساخت ماتریس QR ناموفق بود")

    canvas_size = 720
    quiet_modules = max(6, int(border))
    total_modules = modules + quiet_modules * 2
    module_scale = max(5, min(12, int(scale), 560 // total_modules))
    qr_size = total_modules * module_scale
    panel_padding = 22
    panel_size = qr_size + panel_padding * 2
    panel_left = (canvas_size - panel_size) // 2
    panel_top = (canvas_size - panel_size) // 2
    qr_left = panel_left + panel_padding
    qr_top = panel_top + panel_padding

    background = (11, 14, 19)
    panel = (255, 255, 255)
    orange = (255, 111, 0)
    black = (0, 0, 0)
    pixels = bytearray(background * (canvas_size * canvas_size))

    def fill_rect(left: int, top: int, right: int, bottom: int, color: tuple[int, int, int]) -> None:
        left = max(0, left); top = max(0, top)
        right = min(canvas_size, right); bottom = min(canvas_size, bottom)
        if right <= left or bottom <= top:
            return
        row = bytes(color) * (right - left)
        for y in range(top, bottom):
            offset = (y * canvas_size + left) * 3
            pixels[offset:offset + len(row)] = row

    # Orange frame stays outside the white quiet zone.
    fill_rect(panel_left - 5, panel_top - 5, panel_left + panel_size + 5, panel_top + panel_size + 5, orange)
    fill_rect(panel_left, panel_top, panel_left + panel_size, panel_top + panel_size, panel)

    for source_y, row in enumerate(matrix):
        for source_x, dark in enumerate(row):
            if not dark:
                continue
            module_x = source_x + quiet_modules
            module_y = source_y + quiet_modules
            left = qr_left + module_x * module_scale
            top = qr_top + module_y * module_scale
            fill_rect(left, top, left + module_scale, top + module_scale, black)

    raw = bytearray()
    row_bytes = canvas_size * 3
    for y in range(canvas_size):
        raw.append(0)
        start = y * row_bytes
        raw.extend(pixels[start:start + row_bytes])

    signature = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", canvas_size, canvas_size, 8, 2, 0, 0, 0)
    return signature + _png_chunk(b"IHDR", ihdr) + _png_chunk(b"IDAT", zlib.compress(bytes(raw), 9)) + _png_chunk(b"IEND", b"")


def _subscription_delivery_keyboard(user: VpnUser, link: str) -> dict:
    delivery_row = [{"text": "📤 ارسال کانفیگ", "callback_data": f"usr:{user.id}:send_config"}]
    if bool(user.enable_openvpn):
        delivery_row.append({"text": "📁 فایل‌های OpenVPN", "callback_data": f"usr:{user.id}:openvpn_files"})
    return {"inline_keyboard": [
        delivery_row,
        [{"text": "🌐 بازکردن لینک اشتراک", "url": link}],
        [
            {"text": "📋 کپی نام کاربری", "copy_text": {"text": user.username}},
            {"text": "📋 کپی لینک ساب", "copy_text": {"text": link}},
        ],
        [{"text": "👤 مدیریت کاربر", "callback_data": f"usr:{user.id}:show"}, {"text": "🏠 منوی اصلی", "callback_data": "menu:home"}],
    ]}


def _created_user_caption(user: VpnUser, db, link: str) -> str:
    admin = _actor(db)
    protocols = [
        PROTOCOL_LABELS[p]
        for p in PROTOCOLS
        if admin_can_access_protocol(admin, p) and bool(getattr(user, f"enable_{p}"))
    ]
    quota = "نامحدود" if int(user.quota_bytes or 0) <= 0 else f"{user.quota_bytes / GB:.2f} GB"
    expiry = "بدون انقضا"
    if user.expire_mode == "after_first_connect" and not user.first_connect_at:
        expiry = f"{user.expire_after_days or 0} روز بعد از اولین اتصال"
    elif user.expire_date:
        expiry = str(user.expire_date)
    try:
        labels = {token: label for token, label in _target_options(db, admin)}
        raw_targets = set(targets_for_user(user))
        if "all" in raw_targets:
            targets = "، ".join(labels.values()) or "—"
        else:
            targets = "، ".join(labels[token] for token in sorted(raw_targets) if token in labels) or "—"
    except Exception:
        targets = "—"
    safe_link = _e(link)
    lines = [
        "✅ <b>کاربر با موفقیت ساخته شد.</b>",
        f"‏👤 نام کاربری: <code>{_e(user.username)}</code>",
        f"🔑 رمز: <code>{_e(user.password)}</code>",
        f"📌 وضعیت: {'فعال ✅' if user.is_active else 'غیرفعال ⛔'}",
        f"📦 حجم: <b>{_e(quota)}</b>",
        f"📱 حداکثر اتصال هم‌زمان: <b>{'نامحدود' if int(user.max_devices or 0) == 0 else int(user.max_devices or 0)}</b>",
        f"⏳ انقضا: <b>{_e(expiry)}</b>",
        f"🔌 پروتکل‌ها: {_e('، '.join(protocols) or '—')}",
        f"🖥 سرورها: {_e(targets[:260])}",
        "",
        f'🔗 <a href="{safe_link}">بازکردن صفحه اشتراک</a>',
    ]
    return "\n".join(lines)


def _send_subscription_package(
    cfg: dict,
    chat_id: int | str,
    user: VpnUser,
    db,
    *,
    created: bool = False,
) -> bool:
    """Send one compact QR photo with the link as the caption's first line."""
    link = build_sub_link(db, user.sub_token) if user.sub_token else ""
    if not link:
        _send(cfg, chat_id, "⚠️ لینک اشتراک این کاربر ساخته نشده است.", _user_keyboard(user, db))
        return False

    try:
        safe_link = _e(link)
        png = _subscription_qr_png(link)
        filename = re.sub(r"[^A-Za-z0-9_.-]+", "_", user.username or "user")[:64] + "-subscription-qr.png"
        caption = (
            _created_user_caption(user, db, link)
            if created
            else (
                f'<a href="{safe_link}">{safe_link}</a>\n\n'
                f"🔗 <b>لینک اشتراک {_e(user.username)}</b>\n"
                "QR را اسکن کنید تا همین لینک مستقیماً در مرورگر باز شود."
            )
        )
        _cleanup_control_messages(cfg, chat_id)
        if created:
            _send_media(
                cfg, chat_id, "user_created",
                f"✅ <b>کاربر {_e(user.username)} با موفقیت ساخته شد.</b>",
                cleanup=False,
            )
        data: dict[str, Any] = {
            "chat_id": chat_id,
            "caption": _customize_text(cfg, caption, html_mode=True),
            "parse_mode": "HTML",
            "reply_markup": json.dumps(
                _customize_markup(cfg, _subscription_delivery_keyboard(user, link)),
                ensure_ascii=False,
                separators=(",", ":"),
            ),
        }
        ok, result = call_telegram_api(
            cfg["bot_token"],
            "sendPhoto",
            data=data,
            files={"photo": (filename, png, "image/png")},
            timeout=30,
            max_attempts=2,
        )
        if not ok:
            logger.warning("Telegram subscription QR send failed for user %s: %s", user.username, result)
            _send(cfg, chat_id, f"⚠️ ارسال QR ناموفق بود: {_e(result)}", _user_keyboard(user, db))
            return False
        message_id = int(result.get("message_id") or 0) if isinstance(result, dict) else 0
        _remember_control_message(cfg, chat_id, message_id)
        return True
    except Exception as exc:
        logger.exception("Subscription QR generation failed for user %s", user.username)
        _send(cfg, chat_id, f"⚠️ ساخت یا ارسال QR ناموفق بود: {_e(exc)}", _user_keyboard(user, db))
        return False


def _delivery_target_token(node: dict) -> str:
    if bool(node.get("local")):
        return "local"
    try:
        return f"node:{int(node.get('id'))}"
    except (TypeError, ValueError):
        return ""


def _delivery_target_key(node: dict) -> str:
    if bool(node.get("local")):
        return "local"
    try:
        return f"node-{int(node.get('id'))}"
    except (TypeError, ValueError):
        return ""


def _safe_delivery_name(value: Any, fallback: str = "user") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip()).strip("-._")
    return cleaned[:80] or fallback


def _visible_delivery_nodes(db, user: VpnUser) -> list[dict]:
    admin = _actor(db)
    result: list[dict] = []
    for node in public_node_list(db, user):
        token = _delivery_target_token(node)
        if token and admin_can_access_target(admin, token):
            result.append(node)
    return result


def _connection_package_text(user: VpnUser, db) -> str:
    """Build the same effective credentials shown by the public sub page.

    Only protocols that are both enabled for the user and available on one of
    the user's selected servers are rendered.  This prevents a disabled L2TP,
    SSTP, Xray, etc. section from leaking into the Telegram package.
    """
    admin = _actor(db)
    nodes = _visible_delivery_nodes(db, user)
    xray_profiles = [
        item for item in build_multi_xray_profiles(db, user)
        if admin_can_access_protocol(admin, str(item.get("protocol") or ""))
    ]
    xray_map: dict[tuple[str, str], list[str]] = {}
    for item in xray_profiles:
        node_id = str(item.get("node_id"))
        protocol = str(item.get("protocol") or "").lower()
        uri = str(item.get("uri") or "").strip()
        if protocol and uri:
            xray_map.setdefault((node_id, protocol), []).append(uri)

    status = "فعال" if user.is_active else "غیرفعال"
    quota = "نامحدود" if int(user.quota_bytes or 0) <= 0 else f"{user.quota_bytes / GB:.2f} GB"
    expiry = "بدون انقضا"
    if user.expire_mode == "after_first_connect" and not user.first_connect_at:
        expiry = f"{user.expire_after_days or 0} روز پس از اولین اتصال"
    elif user.expire_date:
        expiry = str(user.expire_date)

    lines = [
        f"اطلاعات اتصال کاربر {user.username}",
        "=" * 34,
        f"نام کاربری: {user.username}",
        f"رمز عبور: {user.password}",
        f"وضعیت: {status}",
        f"حجم: {quota}",
        f"حداکثر اتصال هم‌زمان: {'نامحدود' if int(user.max_devices or 0) == 0 else int(user.max_devices or 0)}",
        f"انقضا: {expiry}",
    ]
    sub_link = build_sub_link(db, user.sub_token) if user.sub_token else ""
    if sub_link:
        lines.append(f"لینک اشتراک: {sub_link}")

    delivered_protocols: set[str] = set()
    visible_node_count = 0
    for node in nodes:
        protocols = node.get("protocols") or {}
        node_id = str(node.get("id"))
        enabled: list[str] = []
        for key in PROTOCOLS:
            item = protocols.get(key) or {}
            if not admin_can_access_protocol(admin, key):
                continue
            if key in {"vmess", "vless"}:
                if xray_map.get((node_id, key)):
                    enabled.append(key)
                continue
            if bool(item.get("enabled")):
                enabled.append(key)
        if not enabled:
            continue

        visible_node_count += 1
        node_name = str(node.get("name") or ("سرور اصلی" if node.get("local") else "Node"))
        lines.extend(["", f"سرور: {node_name}", "-" * 28])
        for key in enabled:
            item = protocols.get(key) or {}
            address = str(item.get("server_address") or node.get("display_address") or node.get("address") or "").strip()
            delivered_protocols.add(key)
            if key == "l2tp":
                lines.extend([
                    "L2TP/IPsec:",
                    f"  Server: {address}",
                    f"  Port: {int(item.get('port') or 1701)}",
                    f"  IPsec PSK: {str(item.get('ipsec_psk') or node.get('ipsec_psk') or '').strip()}",
                ])
            elif key == "pptp":
                lines.extend(["PPTP:", f"  Server: {address}", f"  Port: {int(item.get('port') or 1723)}"])
            elif key == "openvpn":
                listeners = [
                    f"{address}:{int(item.get('udp_port') or 1194)}/UDP",
                    f"{address}:{int(item.get('tcp_port') or 1194)}/TCP",
                ]
                for extra in item.get("extra_ports") or []:
                    if bool(extra.get("active", True)):
                        proto = "TCP" if str(extra.get("protocol") or "").lower().startswith("tcp") else "UDP"
                        try:
                            listeners.append(f"{address}:{int(extra.get('port'))}/{proto}")
                        except (TypeError, ValueError):
                            pass
                lines.extend(["OpenVPN:", "  فایل‌های آماده در ادامه ارسال می‌شوند.", f"  Listeners: {', '.join(dict.fromkeys(listeners))}"])
            elif key == "sstp":
                lines.extend([
                    "SSTP:",
                    f"  Server: {address}",
                    f"  Port: {int(item.get('port') or 4433)}",
                    f"  Auth mode: {user.sstp_auth_mode or 'password'}",
                    "  گواهی سرور در ادامه ارسال می‌شود.",
                ])
            elif key == "ikev2":
                ports = item.get("ports") or [500, 4500]
                lines.extend(["IKEv2:", f"  Server: {address}", f"  Ports: {', '.join(str(v) for v in ports)}"])
            elif key == "openconnect":
                lines.extend(["OpenConnect:", f"  Server: {address}", f"  Port: {int(item.get('port') or 8443)}"])
            elif key in {"vmess", "vless"}:
                lines.append(f"{key.upper()}:")
                for uri in xray_map.get((node_id, key), []):
                    lines.append(f"  {uri}")

    # Some local snapshots use a string/None id for the controller while Xray
    # profiles can expose a different local marker.  Preserve any unmatched URI
    # rather than silently dropping a valid enabled profile.
    rendered_uris = "\n".join(lines)
    unmatched = [item for item in xray_profiles if str(item.get("uri") or "") not in rendered_uris]
    if unmatched:
        lines.extend(["", "پروفایل‌های Xray:", "-" * 28])
        for item in unmatched:
            protocol = str(item.get("protocol") or "").lower()
            delivered_protocols.add(protocol)
            lines.append(f"{item.get('label') or protocol.upper()}: {item.get('uri')}")

    requested = {
        key for key in PROTOCOLS
        if bool(getattr(user, f"enable_{key}", False)) and admin_can_access_protocol(admin, key)
    }
    missing = sorted(requested - delivered_protocols)
    if visible_node_count == 0:
        lines.extend(["", "هشدار: هیچ سرور فعال و قابل‌دسترسی برای این کاربر پیدا نشد."])
    elif missing:
        lines.extend([
            "",
            "در حال آماده‌سازی/فاقد سرور آماده: " + "، ".join(PROTOCOL_LABELS.get(key, key) for key in missing),
        ])
    return "\n".join(lines).strip() + "\n"


def _http_exception_detail(exc: Exception) -> str:
    detail = getattr(exc, "detail", None)
    return str(detail if detail is not None else exc)


def _send_openvpn_files(cfg: dict, chat_id: int | str, user: VpnUser, db) -> tuple[int, list[str]]:
    """Send canonical OpenVPN files exactly like the public subscription page."""
    if not bool(user.enable_openvpn):
        return 0, ["OpenVPN برای این کاربر غیرفعال است."]
    admin = _actor(db)
    if not admin_can_access_protocol(admin, "openvpn"):
        return 0, ["حساب شما دسترسی ارسال فایل OpenVPN را ندارد."]

    from app.routers import sub as sub_router

    available = [
        node for node in openvpn_profile_nodes(db, user, require_shared_pki=False)
        if admin_can_access_target(admin, _delivery_target_token(node))
    ]
    ready = [
        node for node in openvpn_profile_nodes(db, user, require_shared_pki=True)
        if admin_can_access_target(admin, _delivery_target_token(node))
    ]
    if not ready:
        if available:
            sync_all_nodes_async()
            return 0, ["فایل‌های OpenVPN هنوز با نودها همگام نشده‌اند؛ همگام‌سازی شروع شد و چند ثانیه دیگر دوباره امتحان کنید."]
        return 0, ["هیچ سرور OpenVPN فعال و انتخاب‌شده‌ای برای این کاربر وجود ندارد."]

    sent = 0
    warnings: list[str] = []
    safe_user = _safe_delivery_name(user.username)
    all_targets_ready = len(ready) == len(available)
    if not all_targets_ready:
        sync_all_nodes_async()
        warnings.append(
            f"{len(available) - len(ready)} سرور OpenVPN هنوز همگام نشده است؛ "
            "فایل‌های آماده ارسال شدند و ساخت فایل ترکیبی تا تکمیل همگام‌سازی انجام نشد."
        )

    # The combined profile is useful only when two or more servers are assigned
    # and every assigned target has acknowledged the canonical PKI/user state.
    if len(ready) > 1 and all_targets_ready:
        try:
            response = sub_router.download_sub_openvpn_config(user.sub_token, db)
            if _send_document_bytes(
                cfg,
                chat_id,
                f"ALL-{safe_user}.ovpn",
                response.body,
                caption=f"🌐 <b>OpenVPN همه سرورها</b> — <code>{_e(user.username)}</code>",
                mime_type="application/x-openvpn-profile",
            ):
                sent += 1
            else:
                warnings.append("ارسال فایل ترکیبی OpenVPN در تلگرام ناموفق بود.")
        except Exception as exc:
            warnings.append("فایل ترکیبی OpenVPN: " + _http_exception_detail(exc))

    for node in ready:
        target_key = sub_router._openvpn_target_key(node)
        if not target_key:
            continue
        node_name = str(node.get("name") or ("Main" if node.get("local") else target_key))
        safe_node = sub_router._safe_download_name(node_name, target_key)
        try:
            response = sub_router.download_sub_openvpn_config_for_target(target_key, user.sub_token, db)
            if _send_document_bytes(
                cfg,
                chat_id,
                f"{safe_user}-{safe_node}.ovpn",
                response.body,
                caption=f"🖥 <b>{_e(node_name)}</b> — <code>{_e(user.username)}</code>",
                mime_type="application/x-openvpn-profile",
            ):
                sent += 1
            else:
                warnings.append(f"ارسال فایل OpenVPN سرور {node_name} در تلگرام ناموفق بود.")
        except Exception as exc:
            warnings.append(f"OpenVPN سرور {node_name}: {_http_exception_detail(exc)}")
    return sent, warnings


def _send_sstp_certificates(cfg: dict, chat_id: int | str, user: VpnUser, db) -> tuple[int, list[str]]:
    if not bool(user.enable_sstp):
        return 0, []
    admin = _actor(db)
    if not admin_can_access_protocol(admin, "sstp"):
        return 0, []
    from app.routers import sub as sub_router

    sent = 0
    warnings: list[str] = []
    safe_user = _safe_delivery_name(user.username)
    for node in _visible_delivery_nodes(db, user):
        item = (node.get("protocols") or {}).get("sstp") or {}
        if not bool(item.get("enabled")):
            continue
        target_key = _delivery_target_key(node)
        if not target_key:
            continue
        node_name = str(node.get("name") or ("Main" if node.get("local") else target_key))
        safe_node = _safe_delivery_name(node_name, target_key)
        try:
            response = sub_router.download_sub_sstp_cert(user.sub_token, db, target_key=target_key)
            if _send_document_bytes(
                cfg,
                chat_id,
                f"{safe_user}-{safe_node}-SSTP.cer",
                response.body,
                caption=f"🔐 <b>گواهی SSTP { _e(node_name) }</b>",
                mime_type="application/x-x509-ca-cert",
            ):
                sent += 1
            else:
                warnings.append(f"ارسال گواهی SSTP سرور {node_name} ناموفق بود.")
        except Exception as exc:
            warnings.append(f"گواهی SSTP سرور {node_name}: {_http_exception_detail(exc)}")
    return sent, warnings


def _send_full_config_package(cfg: dict, chat_id: int | str, user: VpnUser, db) -> None:
    text = _connection_package_text(user, db)
    _send_persistent_text(cfg, chat_id, text)
    safe_user = _safe_delivery_name(user.username)
    _send_document_bytes(
        cfg,
        chat_id,
        f"{safe_user}-CONNECTION-INFO.txt",
        "\ufeff" + text,
        caption=f"📄 <b>اطلاعات کامل اتصال</b> — <code>{_e(user.username)}</code>",
        mime_type="text/plain; charset=utf-8",
    )

    warnings: list[str] = []
    _sstp_count, sstp_warnings = _send_sstp_certificates(cfg, chat_id, user, db)
    warnings.extend(sstp_warnings)
    if bool(user.enable_openvpn):
        _ovpn_count, ovpn_warnings = _send_openvpn_files(cfg, chat_id, user, db)
        warnings.extend(ovpn_warnings)
    if warnings:
        _send_persistent_text(cfg, chat_id, "هشدارهای ارسال:\n- " + "\n- ".join(warnings))


def _status_text(db) -> str:
    admin = _actor(db)
    scoped_users = _bot_user_query(db)
    total = scoped_users.count()
    active = scoped_users.filter(VpnUser.is_active == True).count()  # noqa: E712
    try:
        from app.routers.dashboard import online_users as dashboard_online_users
        online = len(dashboard_online_users(db=db, admin=admin))
    except Exception:
        scoped_user_ids = [row[0] for row in scoped_users.with_entities(VpnUser.id).all()]
        online = 0 if not scoped_user_ids else (
            db.query(func.count(func.distinct(ConnectionLog.user_id))).filter(
                ConnectionLog.user_id.in_(scoped_user_ids),
                ConnectionLog.is_online == True,  # noqa: E712
                ConnectionLog.device_limit_blocked == False,  # noqa: E712
            ).scalar() or 0
        )
    usage = scoped_users.with_entities(func.coalesce(func.sum(VpnUser.used_bytes), 0)).scalar() or 0
    lines = [
        "📊 <b>وضعیت پنل</b>",
        f"👥 کاربران: <b>{total}</b> (فعال: {active})",
        f"🟢 کاربران آنلاین: <b>{online}</b>",
        f"📊 مصرف ثبت‌شده: <b>{int(usage) / GB:.2f} GB</b>",
    ]
    if _has_permission(admin, "nodes:view"):
        scoped_nodes = [
            node for node in db.query(VpnNode).all()
            if admin_can_access_target(admin, f"node:{int(node.id)}")
        ]
        online_nodes = sum(1 for node in scoped_nodes if node.enabled and node.status == "online")
        lines.append(f"🖥 سرورهای مجاز: <b>{online_nodes}/{len(scoped_nodes)}</b> آنلاین")
    if _has_permission(admin, "bans:view"):
        bans_query = db.query(BannedIP)
        if not can_view_all_users(admin):
            bans_query = bans_query.filter(BannedIP.owner_admin_id == admin.id)
        lines.append(f"🚫 آی‌پی‌های بن‌شده: <b>{bans_query.count()}</b>")
    lines.append(f"🕒 زمان سرور: <code>{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</code>")
    return "\n".join(lines)


def _list_users_text(db, search: str = "") -> str:
    query = _bot_user_query(db)
    if search:
        query = query.filter(VpnUser.username.like(f"%{search}%"))
    rows = query.order_by(VpnUser.created_at.desc()).limit(20).all()
    if not rows:
        return "کاربری پیدا نشد."
    lines = ["👥 <b>آخرین کاربران</b>"]
    admin = _actor(db)
    for user in rows:
        icon = "✅" if user.is_active else "⛔"
        online, last = _bot_user_activity(db, user, admin)
        _, display = server_datetime_payload(db, last) if last else (None, None)
        activity = "آنلاین" if online else (display or "بدون اتصال")
        lines.append(f"{icon} <code>{_e(user.username)}</code> — {int(user.used_bytes or 0) / GB:.2f}GB — 🕒 {_e(activity)}")
    lines.append("\nبرای مشاهده و مدیریت، روی دکمه همان کاربر بزنید.")
    return "\n".join(lines)


def _nodes_text(db) -> str:
    admin = _actor(db)
    rows = [node for node in db.query(VpnNode).order_by(VpnNode.id).all() if admin_can_access_target(admin, f"node:{int(node.id)}")]
    lines = ["🖥 <b>نودهای پنل</b>"]
    if not rows:
        lines.append("هیچ سروری در محدوده دسترسی این حساب نیست.")
    for node in rows:
        icon = "🟢" if node.status == "online" and node.enabled else "🔴"
        lines.append(f"{icon} <b>{_e(node.name)}</b> — <code>node:{node.id}</code> — {_e(node.status)}")
        if node.last_error:
            lines.append(f"   ⚠️ {_e(str(node.last_error)[:180])}")
    return "\n".join(lines)


def _bans_text(db) -> tuple[str, dict]:
    from app.security import can_view_all_users
    admin = _require_permission(db, "bans:view")
    query = db.query(BannedIP)
    if not can_view_all_users(admin):
        query = query.filter(BannedIP.owner_admin_id == admin.id)
    rows = query.order_by(BannedIP.created_at.desc()).limit(30).all()
    lines = ["🚫 <b>آی‌پی‌های بن‌شده</b>"]
    keyboard = []
    if not rows:
        lines.append("لیست بن خالی است.")
    for row in rows:
        lines.append(f"• <code>{_e(row.ip_address)}</code> — {_e(row.reason or '-')}")
        keyboard.append([{"text": f"✅ رفع بن {row.ip_address}", "callback_data": f"unbanip:{row.ip_address}"}])
    keyboard.append([{"text": "🚫 بن آی‌پی جدید", "callback_data": "menu:ban"}, {"text": "🔙 مدیریت آی‌پی‌ها", "callback_data": "menu:ips"}])
    keyboard.append([{"text": "🏠 منوی اصلی", "callback_data": "menu:home"}])
    return "\n".join(lines), {"inline_keyboard": keyboard}


def _create_user(db, data: dict[str, Any]) -> VpnUser:
    from app.routers.users import _check_admin_limits, _schedule_user_post_update_sync

    admin = _actor(db)
    protocols = set(data["protocols"])
    days = int(data.get("days") or 0)
    payload = VpnUserCreate(
        username=data["username"], password=data["password"],
        quota_gb=float(data.get("quota_gb") or 0), max_devices=int(data.get("max_devices") or 0),
        expire_mode="after_first_connect" if days > 0 else "fixed",
        expire_after_days=days if days > 0 else None, expire_date=None,
        is_active=True, note="ساخته‌شده از ربات تلگرام",
        server_targets=list(data.get("targets") or ["all"]),
        **{f"enable_{p}": p in protocols for p in PROTOCOLS},
    )
    if _bot_user_by_username(db, payload.username):
        raise ValueError("این نام کاربری قبلاً ثبت شده است")
    _check_admin_limits(db, admin, int(payload.quota_gb * GB), True)
    ensure_user_protocols(admin, protocols)
    normalized_targets = validate_target_tokens(db, payload.server_targets, admin)
    user = VpnUser(
        username=payload.username, password=payload.password,
        openvpn_auth_mode=payload.openvpn_auth_mode, sstp_auth_mode=payload.sstp_auth_mode,
        quota_bytes=int(payload.quota_gb * GB), used_bytes=0,
        max_devices=payload.max_devices, speed_limit_mbps=0,
        download_limit_mbps=payload.download_limit_mbps or payload.speed_limit_mbps,
        upload_limit_mbps=payload.upload_limit_mbps or payload.speed_limit_mbps,
        expire_mode=payload.expire_mode, expire_date=payload.expire_date,
        expire_after_days=payload.expire_after_days, is_active=True,
        note=payload.note, server_targets=serialize_targets(normalized_targets),
        owner_admin_id=admin.id, sub_token=secrets.token_urlsafe(24),
        **{f"enable_{p}": p in protocols for p in PROTOCOLS},
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    _schedule_user_post_update_sync(
        user.id,
        sync_xray=bool((user.enable_vmess or user.enable_vless) and local_assignment_enabled(db) and user_selected_for_local(user)),
    )
    log_event("🤖 ساخت یوزر از ربات تلگرام", f"یوزرنیم: {user.username} | حجم: {payload.quota_gb}GB", actor=admin.username)
    return user


def _ban(db, raw_ip: str, reason: str = "بن از ربات تلگرام") -> tuple[bool, str]:
    ip = _valid_ipv4(raw_ip)
    existing = db.query(BannedIP).filter(BannedIP.ip_address == ip).first()
    if existing:
        return False, f"آی‌پی {ip} از قبل بن شده است."
    admin = _actor(db)
    ban_ip(db, ip, reason, admin.id, owner_admin_id=admin.id)
    sync_global_controls_to_active_nodes_async()
    log_event("🚫 بن آی‌پی از ربات", f"آی‌پی: {ip} | دلیل: {reason}", actor=admin.username)
    return True, f"✅ آی‌پی <code>{ip}</code> بن شد و دیگر پنل/VPN برای آن باز نمی‌شود."


def _unban(db, raw_ip: str) -> tuple[bool, str]:
    ip = _valid_ipv4(raw_ip)
    if not unban_ip(db, ip):
        return False, f"آی‌پی {ip} در لیست بن نبود."
    sync_global_controls_to_active_nodes_async(force_unban_ips=[ip])
    admin = _actor(db)
    log_event("✅ رفع بن آی‌پی از ربات", f"آی‌پی: {ip}", actor=admin.username)
    return True, f"✅ بن آی‌پی <code>{ip}</code برداشته شد."


def _control_protocol(db, key: str, action: str) -> str:
    key = key.lower().strip()
    action = action.lower().strip()
    admin = _actor(db)
    if not admin_can_access_protocol(admin, key):
        raise ValueError("این گزینه در محدوده دسترسی حساب شما نیست")
    if key not in set(PROTOCOLS) | {"ipsec"}:
        raise ValueError("پروتکل نامعتبر است")
    if action not in {"start", "stop", "restart"}:
        raise ValueError("عملیات باید start، stop یا restart باشد")

    enabled_keys = set(PROTOCOLS) - {"openconnect"}
    if key in enabled_keys and action in {"start", "restart"}:
        _set_setting(db, f"{key}_enabled", "1")
        db.commit()
        if key in {"vmess", "vless"}:
            from app.services.xray_manager import sync_xray_users
            sync_xray_users(db, protocols=[key], restart=False)
    ok, output = control_protocol(key, action, db)
    if not ok:
        raise ValueError(f"عملیات ناموفق بود: {str(output)[-500:]}")
    if key in enabled_keys and action == "stop":
        _set_setting(db, f"{key}_enabled", "0")
        db.commit()
    log_event("🤖 کنترل پروتکل از ربات", f"پروتکل: {key} | عملیات: {action}", actor=admin.username)
    return f"✅ عملیات <b>{_e(action)}</b> برای <b>{_e(PROTOCOL_LABELS.get(key, key))}</b> انجام شد."


def _random_username(db) -> str:
    for _ in range(30):
        candidate = f"user-{secrets.randbelow(900000) + 100000}"
        if not _bot_user_by_username(db, candidate):
            return candidate
    raise ValueError("ساخت نام کاربری خودکار ناموفق بود؛ دوباره تلاش کنید")


def _random_password() -> str:
    # URL-safe ASCII, long enough for every supported VPN backend.
    return secrets.token_urlsafe(10)


def _create_summary(data: dict[str, Any]) -> str:
    protocols = "، ".join(PROTOCOL_LABELS[p] for p in PROTOCOLS if p in set(data.get("protocols") or []))
    targets = "همه سرورها" if "all" in set(data.get("targets") or []) else "، ".join(data.get("targets") or [])
    quota = "نامحدود" if float(data.get("quota_gb") or 0) == 0 else f"{data['quota_gb']} GB"
    devices = "نامحدود" if int(data.get("max_devices") or 0) == 0 else str(data["max_devices"])
    days = "بدون انقضا" if int(data.get("days") or 0) == 0 else f"{data['days']} روز بعد از اولین اتصال"
    return (
        "✅ <b>تأیید نهایی ساخت کاربر</b>\n\n"
        f"👤 نام کاربری: <code>{_e(data['username'])}</code>\n"
        f"🔑 رمز: <code>{_e(data['password'])}</code>\n"
        f"📦 حجم: <b>{_e(quota)}</b>\n"
        f"📱 حداکثر اتصال هم‌زمان: <b>{_e(devices)}</b>\n"
        f"⏳ اعتبار: <b>{_e(days)}</b>\n"
        f"🔌 پروتکل‌ها: <b>{_e(protocols)}</b>\n"
        f"🖥 سرورها: <b>{_e(targets)}</b>"
    )


def _create_confirm_keyboard() -> dict:
    return {"inline_keyboard": [
        [{"text": "✅ ساخت کاربر", "callback_data": "create:confirm"}],
        [
            {"text": "🔌 ویرایش پروتکل‌ها", "callback_data": "create:edit_protocols"},
            {"text": "🖥 ویرایش سرورها", "callback_data": "create:edit_targets"},
        ],
        [{"text": "❌ لغو", "callback_data": "flow:cancel"}],
    ]}


def _apply_user_days(user: VpnUser, value: int, *, add: bool = False) -> None:
    if value < 0 or value > 3650:
        raise ValueError("تعداد روز باید بین 0 تا 3650 باشد")
    if add:
        if value == 0:
            return
        if user.expire_mode == "after_first_connect" and not user.first_connect_at:
            user.expire_after_days = int(user.expire_after_days or 0) + value
        else:
            user.expire_mode = "fixed"
            user.expire_date = (user.expire_date or date.today()) + timedelta(days=value)
            user.expire_after_days = None
        return
    if value == 0:
        user.expire_mode = "fixed"
        user.expire_date = None
        user.expire_after_days = None
    elif user.first_connect_at:
        user.expire_mode = "fixed"
        user.expire_date = date.today() + timedelta(days=value)
        user.expire_after_days = None
    else:
        user.expire_mode = "after_first_connect"
        user.expire_after_days = value
        user.expire_date = None


def _schedule_user_sync(user: VpnUser, *, xray: bool = True) -> None:
    from app.routers.users import _schedule_user_post_update_sync
    _schedule_user_post_update_sync(user.id, sync_xray=xray)


def _start_create_wizard(cfg: dict, chat_id: int | str, user_id: int) -> None:
    _set_state(chat_id, user_id, {"flow": "create", "step": "username", "data": {}})
    _send(
        cfg,
        chat_id,
        "➕ <b>ساخت کاربر جدید</b>\n\nنام کاربری انگلیسی را بنویسید یا دکمه «ساخت خودکار» را بزنید.",
        _cancel_keyboard(random_callback="create:auto_username"),
    )


def _wizard_message(cfg: dict, chat_id: int | str, user_id: int, text: str) -> bool:
    state = _get_state(chat_id, user_id)
    if not state:
        return False
    flow, step, data = state.get("flow"), state.get("step"), state.get("data", {})
    raw_text = str(text or "").strip()
    text = _normalize_digits(text).strip()
    try:
        if flow == "bot_text_override":
            db = SessionLocal()
            try:
                _require_superadmin(db)
                if step != "replacement":
                    return False
                if not raw_text or len(raw_text) > 512:
                    raise ValueError("متن جدید باید بین ۱ تا ۵۱۲ کاراکتر باشد")
                if "<" in raw_text or ">" in raw_text:
                    raise ValueError("برای جلوگیری از خراب‌شدن قالب پیام، از علامت‌های < و > استفاده نکنید")
                source = str(data.get("source") or "").strip()
                if not source:
                    raise ValueError("متن انتخاب‌شده منقضی شده؛ دوباره آن را از فهرست انتخاب کنید")
                data["replacement"] = raw_text
                state["step"] = "confirm"
                state["data"] = data
                _set_state(chat_id, user_id, state)
                current = _customize_text(cfg, source)
                _send(
                    cfg,
                    chat_id,
                    "✏️ <b>پیش‌نمایش تغییر</b>\n\n"
                    f"متن فعلی:\n<code>{_e(current)}</code>\n\n"
                    f"متن جدید:\n<code>{_e(raw_text)}</code>\n\n"
                    "برای ذخیره، تأیید را بزنید.",
                    {"inline_keyboard": [[
                        {"text": "✅ تأیید و ذخیره", "callback_data": "bottext:confirm"},
                        {"text": "❌ انصراف", "callback_data": "bottext:cancel_edit"},
                    ]]},
                    customize=False,
                )
                return True
            finally:
                db.close()
        if flow == "ask_ban":
            _set_state(chat_id, user_id, None)
            db = SessionLocal()
            try:
                _, msg = _ban(db, text)
            finally:
                db.close()
            _send(cfg, chat_id, msg, _menu_keyboard())
            return True
        if flow == "ask_unban":
            _set_state(chat_id, user_id, None)
            db = SessionLocal()
            try:
                _, msg = _unban(db, text)
            finally:
                db.close()
            _send(cfg, chat_id, msg, _menu_keyboard())
            return True
        if flow == "ask_internet_block":
            _set_state(chat_id, user_id, None)
            ip = str(ipaddress.ip_address(text))
            db = SessionLocal()
            try:
                if db.query(InternetBlockedIP).filter(InternetBlockedIP.ip_address == ip).first():
                    raise ValueError("این آی‌پی از قبل قطع شده است")
                actor = _actor(db)
                block_internet_ip(
                    db,
                    ip,
                    reason="قطع از ربات تلگرام",
                    admin_id=actor.id,
                    admin_username=actor.username,
                    owner_admin_id=actor.id,
                )
                sync_global_controls_to_active_nodes_async()
            finally:
                db.close()
            _send(cfg, chat_id, f"⛔ اینترنت VPN برای <code>{_e(ip)}</code> قطع شد.", _menu_keyboard())
            return True
        if flow == "panel_license_input":
            action = str(state.get("action") or "")
            _set_state(chat_id, user_id, None)
            db = SessionLocal()
            try:
                from app.services import license_manager
                if action == "activate":
                    result = license_manager.activate_license(db, text)
                    status = result.get("status") or "unknown"
                    if status not in {"active", "expiring_soon"}:
                        raise ValueError(f"فعال‌سازی انجام نشد: {status}")
                    message = "✅ لایسنس پنل فعال شد."
                elif action == "reserve":
                    license_manager.add_reserved_license(db, text)
                    message = "✅ کد برای لایسنس بعدی رزرو شد."
                else:
                    raise ValueError("عملیات لایسنس نامعتبر است")
            finally:
                db.close()
            _send(cfg, chat_id, message, _panel_license_keyboard())
            return True
        if flow == "license_create":
            if step == "telegram_id":
                value = int(_normalize_digits(text))
                if value <= 0:
                    raise ValueError("آیدی عددی تلگرام معتبر نیست")
                db = SessionLocal()
                try:
                    _ensure_telegram_binding_available(db, value)
                finally:
                    db.close()
                data["telegram_user_id"] = value
                data["telegram_bot_enabled"] = True
                state["step"] = "confirm"
                state["data"] = data
                _set_state(chat_id, user_id, state)
                _send(cfg, chat_id, _license_confirm_text(data), {"inline_keyboard": [[
                    {"text": "✅ ساخت لایسنس", "callback_data": "license:create_confirm"},
                    {"text": "❌ لغو", "callback_data": "flow:cancel"},
                ]]})
                return True
            if step not in {"max_users_custom", "quota_custom", "days_custom"}:
                return False
            value = int(float(text))
            if value < 0:
                raise ValueError("مقدار نمی‌تواند منفی باشد")
            if step == "max_users_custom":
                if value > 1_000_000:
                    raise ValueError("حداکثر کاربر معتبر نیست")
                data["max_users"] = value or None
                state["step"] = "quota"
                state["data"] = data
                _set_state(chat_id, user_id, state)
                _send(cfg, chat_id, "📦 سقف حجم کل ادمین را انتخاب کنید.", _license_limits_keyboard("quota"))
                return True
            if step == "quota_custom":
                if value > 10_000_000:
                    raise ValueError("حجم معتبر نیست")
                data["max_total_quota_gb"] = value or None
                state["step"] = "days"
                state["data"] = data
                _set_state(chat_id, user_id, state)
                _send(cfg, chat_id, "⏳ مدت اعتبار لایسنس بعد از فعال‌سازی را انتخاب کنید.", _license_duration_keyboard())
                return True
            if value < 1 or value > 3650:
                raise ValueError("تعداد روز باید بین ۱ تا ۳۶۵۰ باشد")
            data["days"] = value
            state["step"] = "bot"
            state["data"] = data
            _set_state(chat_id, user_id, state)
            _send(cfg, chat_id, "🤖 آیا دسترسی خصوصی ربات برای این لایسنس فعال شود؟", _license_bot_keyboard())
            return True
        if flow == "admin_create":
            if step == "telegram_id":
                value = int(_normalize_digits(text))
                if value <= 0:
                    raise ValueError("آیدی عددی تلگرام معتبر نیست")
                db = SessionLocal()
                try:
                    _ensure_telegram_binding_available(db, value)
                finally:
                    db.close()
                data["telegram_user_id"] = value
                data["telegram_bot_enabled"] = True
                state["step"] = "confirm"
                state["data"] = data
                _set_state(chat_id, user_id, state)
                _send(cfg, chat_id, _admin_create_summary(data), {"inline_keyboard": [[
                    {"text": "✅ ساخت ادمین", "callback_data": "admin:create_confirm"},
                    {"text": "❌ لغو", "callback_data": "flow:cancel"},
                ]]})
                return True
            if step == "username":
                if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", text):
                    raise ValueError("نام کاربری ادمین باید ۳ تا ۶۴ کاراکتر انگلیسی باشد")
                data["username"] = text
                state["step"] = "password"
                state["data"] = data
                _set_state(chat_id, user_id, state)
                _send(cfg, chat_id, "🔑 رمز ادمین را بنویسید؛ حداقل ۶ کاراکتر انگلیسی.", _cancel_keyboard(back="menu:admins"))
                return True
            if step == "password":
                if len(text) < 6 or any(ord(ch) > 127 for ch in text):
                    raise ValueError("رمز باید حداقل ۶ کاراکتر و فقط انگلیسی باشد")
                data["password"] = text
                data["permissions"] = []
                state["step"] = "permissions"
                state["data"] = data
                _set_state(chat_id, user_id, state)
                _send(cfg, chat_id, "🧩 دسترسی‌های ادمین را دقیقاً انتخاب و سپس تأیید کنید.", _admin_permission_keyboard(set()))
                return True
            if step == "max_users_custom":
                value = int(float(text))
                if value < 0 or value > 1_000_000:
                    raise ValueError("حداکثر کاربر معتبر نیست")
                data["max_users"] = value or None
                state["step"] = "quota"; state["data"] = data; _set_state(chat_id, user_id, state)
                _send(cfg, chat_id, "📦 سقف حجم کل ادمین را انتخاب کنید.", _admin_limit_keyboard("quota"))
                return True
            if step == "quota_custom":
                value = float(text)
                if value < 0 or value > 10_000_000:
                    raise ValueError("حجم معتبر نیست")
                data["max_total_quota_gb"] = value or None
                state["step"] = "expiry"; state["data"] = data; _set_state(chat_id, user_id, state)
                _send(cfg, chat_id, "📅 تاریخ انقضای ادمین را انتخاب کنید.", _admin_expiry_keyboard())
                return True
            if step == "expiry_custom":
                try:
                    selected_date = date.fromisoformat(text)
                except ValueError as exc:
                    raise ValueError("تاریخ را به شکل YYYY-MM-DD وارد کنید") from exc
                if selected_date < date.today():
                    raise ValueError("تاریخ انقضا نمی‌تواند گذشته باشد")
                data["subscription_expire_date"] = selected_date.isoformat()
                state["step"] = "confirm"; state["data"] = data; _set_state(chat_id, user_id, state)
                _send(cfg, chat_id, _admin_create_summary(data), {"inline_keyboard": [[
                    {"text": "✅ ساخت ادمین", "callback_data": "admin:create_confirm"},
                    {"text": "❌ لغو", "callback_data": "flow:cancel"},
                ]]})
                return True
            if step in {"permissions", "see_all_users", "targets", "max_users", "quota", "expiry", "confirm"}:
                _send(cfg, chat_id, "برای این مرحله از دکمه‌های زیر پیام استفاده کنید.")
                return True
            return False
        if flow == "ask_user":
            _set_state(chat_id, user_id, None)
            db = SessionLocal()
            try:
                user = _bot_user_by_username(db, text)
                if user:
                    body, keyboard = _format_user(user, db), _user_keyboard(user, db)
                else:
                    matches = _bot_user_query(db).filter(VpnUser.username.like(f"%{text}%")).limit(20).all()
                    if not matches:
                        raise ValueError("کاربر پیدا نشد")
                    body, keyboard = _list_users_text(db, text), _users_keyboard(db, text)
            finally:
                db.close()
            _send(cfg, chat_id, body, keyboard)
            return True
        if flow == "edit_user":
            db = SessionLocal()
            try:
                user = _bot_user_by_id(db, int(state.get("user_id") or 0))
                if not user:
                    raise ValueError("کاربر پیدا نشد")
                mode = str(state.get("mode") or "set")
                if step == "password":
                    if len(text) < 4 or any(ord(ch) > 127 for ch in text):
                        raise ValueError("رمز باید حداقل ۴ کاراکتر و فقط انگلیسی باشد")
                    VpnUserCreate(username=user.username, password=text, enable_l2tp=True)
                    user.password = text
                    db.commit()
                    _schedule_user_sync(user, xray=False)
                    message = "✅ رمز کاربر تغییر کرد."
                    audit_detail = "🔑 عملیات: تغییر رمز عبور"
                elif step == "quota":
                    value = float(text)
                    if value < 0 or value > 1_000_000:
                        raise ValueError("حجم معتبر نیست")
                    if mode == "add":
                        user.quota_bytes = max(0, int(user.quota_bytes or 0) + int(value * GB))
                    else:
                        user.quota_bytes = int(value * GB)
                    db.commit()
                    message = "✅ حجم کاربر بروزرسانی شد."
                    audit_detail = f"📦 حجم جدید: {user.quota_bytes / GB:g} GB ({'افزایش' if mode == 'add' else 'تنظیم'})"
                elif step == "devices":
                    value = int(text)
                    if value < 0 or value > 10000:
                        raise ValueError("تعداد اتصال هم‌زمان معتبر نیست")
                    user.max_devices = value
                    db.commit()
                    _schedule_user_sync(user, xray=True)
                    message = "✅ محدودیت دستگاه بروزرسانی شد."
                    audit_detail = f"📱 حداکثر اتصال جدید: {'نامحدود' if value == 0 else value}"
                elif step == "days":
                    value = int(text)
                    _apply_user_days(user, value, add=(mode == "add"))
                    db.commit()
                    sync_all_nodes_async()
                    message = "✅ اعتبار کاربر بروزرسانی شد."
                    audit_detail = f"⏳ اعتبار: {value} روز ({'افزایش' if mode == 'add' else 'تنظیم'})"
                else:
                    return False
                log_event("🤖 ویرایش کاربر از ربات", f"👤 کاربر: <code>{user.username}</code>\n{audit_detail}", actor=_actor(db).username)
                _set_state(chat_id, user_id, None)
                db.refresh(user)
                body = f"{message}\n\n{_format_user(user, db)}"
                keyboard = _user_keyboard(user, db)
            finally:
                db.close()
            _send(cfg, chat_id, body, keyboard)
            return True
        if flow != "create":
            return False

        if step == "username":
            # Pydantic validates this again at final creation; reject obvious bad input early.
            if not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", text):
                raise ValueError("نام کاربری باید ۳ تا ۶۴ کاراکتر و فقط شامل حروف/عدد انگلیسی، نقطه، خط تیره یا زیرخط باشد")
            data["username"] = text
            state["step"] = "password"
            prompt = "🔑 رمز کاربر را بنویسید یا دکمه «ساخت خودکار» را بزنید."
            keyboard = _cancel_keyboard(random_callback="create:auto_password")
        elif step == "password":
            if len(text) < 4 or any(ord(ch) > 127 for ch in text):
                raise ValueError("رمز باید حداقل ۴ کاراکتر و فقط انگلیسی باشد")
            data["password"] = text
            state["step"] = "quota"
            prompt = "📦 حجم کاربر را انتخاب کنید یا مقدار دلخواه را به گیگ بنویسید."
            keyboard = _create_quota_keyboard()
        elif step == "quota":
            quota = float(text)
            if quota < 0 or quota > 1_000_000:
                raise ValueError("حجم معتبر نیست")
            data["quota_gb"] = quota
            state["step"] = "devices"
            prompt = "📱 حداکثر تعداد اتصال هم‌زمان را انتخاب کنید."
            keyboard = _create_devices_keyboard()
        elif step == "devices":
            devices = int(text)
            if devices < 0 or devices > 10000:
                raise ValueError("تعداد اتصال هم‌زمان معتبر نیست")
            data["max_devices"] = devices
            state["step"] = "days"
            prompt = "⏳ مدت اعتبار بعد از اولین اتصال را انتخاب کنید."
            keyboard = _create_days_keyboard()
        elif step == "days":
            days = int(text)
            if days < 0 or days > 3650:
                raise ValueError("تعداد روز باید بین 0 تا 3650 باشد")
            data["days"] = days
            data["protocols"] = []
            state["step"] = "protocols_buttons"
            state["data"] = data
            _set_state(chat_id, user_id, state)
            selected: set[str] = set()
            _send(cfg, chat_id, _protocol_selector_text(selected, admin=_actor(db)), _protocol_selector_keyboard(selected, mode="create", admin=_actor(db)))
            return True
        elif step in {"protocols_buttons", "targets_buttons", "confirm"}:
            _send(cfg, chat_id, "برای این مرحله از دکمه‌های زیر پیام استفاده کنید.")
            return True
        else:
            raise ValueError("مرحله ساخت نامعتبر شد؛ دوباره از دکمه ساخت کاربر شروع کنید")

        state["data"] = data
        _set_state(chat_id, user_id, state)
        _send(cfg, chat_id, prompt, keyboard)
        return True
    except (ValueError, TypeError, ValidationError) as exc:
        _send(cfg, chat_id, f"❌ {_e(exc)}\nمقدار درست را دوباره وارد کنید یا دکمه لغو را بزنید.", _cancel_keyboard())
        return True


def _natural_ip_action(text: str) -> tuple[str, str] | None:
    normalized = _normalize_digits(text).lower()
    match = re.search(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)", normalized)
    if not match:
        return None
    ip = match.group(0)
    if re.search(r"رفع\s*بن|رفع\s*مسدود|آنبن|انبن|unban", normalized):
        return "unban", ip
    if re.search(r"(?:^|\s)بن(?:ش)?\s*کن|مسدود(?:ش)?\s*کن|\bban\b", normalized):
        return "ban", ip
    return None


def _require_superadmin(db) -> Admin:
    admin = _actor(db)
    if admin.role != AdminRole.superadmin:
        raise ValueError("این بخش فقط برای سوپرادمین فعال است")
    return admin


def _guard_callback_permission(db, data: str) -> None:
    super_only = (
        "menu:admins", "menu:licenses", "menu:backup", "menu:update", "menu:bot_texts",
        "admin:", "adperm:", "adsee:", "adtgt:", "adusers:", "adquota:", "adexp:",
        "license:", "licrole:", "licperm:", "lictgt:", "licusers:", "licquota:", "licdays:", "licbot:",
        "update:", "panellic:", "bottext:",
    )
    if data in super_only or any(data.startswith(prefix) for prefix in super_only if prefix.endswith(":")):
        _require_superadmin(db)
        return
    if data.startswith("usr:"):
        action = data.rsplit(":", 1)[-1]
        permission = {
            "show": "users:view", "enable": "users:edit", "disable": "users:edit",
            "reset": "users:edit", "edit_password": "users:edit", "edit_quota": "users:edit",
            "edit_devices": "users:edit", "edit_days": "users:edit", "edit_protocols": "users:edit",
            "edit_targets": "users:edit", "disconnect": "users:disconnect", "delete": "users:delete",
            "subscription": "users:subscription",
        }.get(action, "users:view")
        _require_permission(db, permission)
        return
    checks = [
        (("menu:users", "menu:user", "userpick:"), "users:view"),
        (("menu:create", "create:", "cproto:", "ctgt:"), "users:create"),
        (("menu:online",), "online:view"),
        (("onlinecut:",), "online:disconnect"),
        (("menu:ips", "menu:bans"), "bans:view"),
        (("menu:ban", "menu:unban", "banip:", "unbanip:", "inet:"), "bans:manage"),
        (("menu:protocols", "protosrv:"), "protocols:view"),
        (("proto:", "nproto:"), "protocols:start_stop"),
        (("menu:nodes",), "nodes:view"),
        (("menu:syncnodes",), "nodes:manage"),
        (("menu:panel_license",), "license:view"),
    ]
    for prefixes, permission in checks:
        if any(data == prefix or data.startswith(prefix) for prefix in prefixes):
            _require_permission(db, permission)
            return


def _guard_command_permission(db, command: str) -> None:
    if command in {"/admins", "/backup"}:
        _require_superadmin(db); return
    mapping = {
        "/status": "dashboard:view", "/users": "users:view", "/user": "users:view",
        "/create": "users:create", "/enable": "users:edit", "/disable": "users:edit",
        "/disconnect": "users:disconnect", "/reset": "users:edit", "/delete": "users:delete",
        "/password": "users:edit", "/quota": "users:edit", "/days": "users:edit",
        "/protocols": "users:edit", "/targets": "users:edit",
        "/ban": "bans:manage", "/unban": "bans:manage", "/bans": "bans:view",
        "/protocol": "protocols:start_stop", "/protocol_status": "protocols:view", "/protocols_status": "protocols:view",
        "/nodes": "nodes:view", "/sync_nodes": "nodes:manage",
    }
    permission = mapping.get(command)
    if permission:
        _require_permission(db, permission)


def _help_text(admin: Admin) -> str:
    lines = [
        "📖 <b>راهنمای ربات پنل</b>",
        "",
        "فقط با نوشتن یکی از کلمات <b>ربات</b>، <b>منو</b> یا <b>استارت</b> منوی اصلی دوباره ارسال می‌شود.",
        "",
    ]
    if _has_permission(admin, "users:view"):
        lines.append("• کاربران: مشاهده و مدیریت حساب‌های در محدوده شما")
    if _has_permission(admin, "users:create"):
        lines.append("• ساخت کاربر: فقط با پروتکل‌ها و سرورهای مجاز حساب شما")
    if _has_permission(admin, "online:view"):
        lines.append("• آنلاین‌ها: فقط اتصال‌های پروتکل‌ها و سرورهای مجاز")
    if _has_permission(admin, "bans:view"):
        lines.append("• آی‌پی‌ها: مشاهده یا مدیریت طبق سطح دسترسی")
    if _has_permission(admin, "protocols:view") and _allowed_protocol_keys(admin):
        lines.append("• پروتکل‌ها: مشاهده و کنترل گزینه‌های فعال در لایسنس شما")
    if _has_permission(admin, "nodes:view"):
        lines.append("• سرورها: فقط نودهای اختصاص‌یافته به حساب شما")
    if admin.role == AdminRole.superadmin:
        lines.extend([
            "• مدیریت ادمین‌ها و لایسنس‌های داخلی",
            "• بکاپ، بروزرسانی و سفارشی‌سازی متن‌های ربات",
        ])
    lines.extend(["", "گزینه‌های خارج از محدوده این حساب در منوها، پاسخ‌ها و خطاها نمایش داده نمی‌شوند."])
    return "\n".join(lines)


def _handle_command(cfg: dict, chat_id: int | str, user_id: int, text: str) -> None:
    parts = text.strip().split()
    command = parts[0].split("@", 1)[0].lower()
    args = parts[1:]
    db = SessionLocal()
    try:
        if command not in {"/start", "/menu", "/help", "/myid", "/chatid", "/cancel"}:
            _guard_command_permission(db, command)
        if command in {"/start", "/menu"}:
            _set_state(chat_id, user_id, None)
            _send_main_menu(cfg, chat_id, "🤖 <b>ربات کنترل VPN Panel آماده است.</b>\nعملیات موردنظر را انتخاب کنید:")
            return
        if command == "/help":
            _send(cfg, chat_id, _help_text(_actor(db)), _menu_keyboard())
            return
        if command in {"/myid", "/chatid"}:
            _send(
                cfg, chat_id,
                f"👤 شناسه عددی شما: <code>{user_id}</code>\n💬 شناسه این چت: <code>{_e(chat_id)}</code>",
                _menu_keyboard(),
            )
            return
        if command == "/cancel":
            _set_state(chat_id, user_id, None)
            _send(cfg, chat_id, "عملیات لغو شد.", _menu_keyboard())
            return
        if command == "/status":
            _send(cfg, chat_id, _status_text(db), _menu_keyboard())
            return
        if command == "/users":
            _send(cfg, chat_id, _list_users_text(db, " ".join(args)))
            return
        if command == "/user":
            if not args:
                raise ValueError("فرمت: /user username")
            user = _bot_user_by_username(db, args[0])
            if not user:
                raise ValueError("کاربر پیدا نشد")
            _send(cfg, chat_id, _format_user(user, db), _user_keyboard(user, db))
            return
        if command == "/create":
            if not args:
                db.close()
                _start_create_wizard(cfg, chat_id, user_id)
                return
            if len(args) < 6:
                raise ValueError("فرمت: /create USER PASS QUOTA DEVICES DAYS PROTOCOLS [TARGETS]")
            data = {
                "username": args[0], "password": args[1], "quota_gb": float(_normalize_digits(args[2])),
                "max_devices": int(_normalize_digits(args[3])), "days": int(_normalize_digits(args[4])),
                "protocols": sorted(_protocol_set(args[5], _actor(db))), "targets": _targets(args[6] if len(args) > 6 else "all"),
            }
            user = _create_user(db, data)
            _send_subscription_package(cfg, chat_id, user, db, created=True)
            return
        if command in {"/ban", "/unban"}:
            if not args:
                raise ValueError(f"فرمت: {command} IP")
            _, msg = _ban(db, args[0]) if command == "/ban" else _unban(db, args[0])
            _send(cfg, chat_id, msg, _menu_keyboard())
            return
        if command == "/bans":
            body, keyboard = _bans_text(db)
            _send(cfg, chat_id, body, keyboard)
            return
        if command in {"/enable", "/disable", "/disconnect", "/reset", "/delete"}:
            if not args:
                raise ValueError(f"فرمت: {command} username")
            user = _bot_user_by_username(db, args[0])
            if not user:
                raise ValueError("کاربر پیدا نشد")
            from app.routers import users as users_router
            admin = _actor(db)
            if command == "/enable":
                user.is_active = True; db.commit(); users_router._schedule_user_post_update_sync(user.id, sync_xray=True)
                msg = "✅ کاربر فعال شد."
            elif command == "/disable":
                user.is_active = False; db.commit(); users_router._schedule_user_post_update_sync(user.id, sync_xray=True)
                msg = "⛔ کاربر غیرفعال شد."
            elif command == "/disconnect":
                result = users_router.disconnect_user(user.id, db, admin)
                msg = f"🔌 اتصال‌های کاربر قطع شد ({result.get('closed_sessions', 0)} سشن)."
            elif command == "/reset":
                users_router.reset_usage(user.id, db, admin); msg = "🔄 حجم مصرفی صفر شد."
            else:
                users_router.delete_user(user.id, db, admin); msg = "🗑 کاربر حذف شد."
            command_labels = {"/enable": "فعال‌سازی", "/disable": "غیرفعال‌سازی", "/disconnect": "قطع اتصال‌ها", "/reset": "صفرکردن حجم", "/delete": "حذف کامل"}
            log_event("🤖 عملیات کاربر از ربات", f"👤 کاربر: <code>{args[0]}</code>\n🛠 عملیات: <b>{command_labels.get(command, command)}</b>\n📌 نتیجه: {msg}", actor=admin.username)
            _send(cfg, chat_id, msg, _menu_keyboard())
            return
        if command == "/password":
            if len(args) < 2:
                raise ValueError("فرمت: /password username NEWPASS")
            user = _bot_user_by_username(db, args[0])
            if not user:
                raise ValueError("کاربر پیدا نشد")
            # Reuse schema validator to keep the same panel rules.
            VpnUserCreate(username=user.username, password=args[1], enable_l2tp=True)
            user.password = args[1]; db.commit()
            from app.routers.users import _schedule_user_post_update_sync
            _schedule_user_post_update_sync(user.id, sync_xray=False)
            log_event("🤖 تغییر رمز کاربر از ربات", f"👤 کاربر: <code>{user.username}</code>\n🔑 عملیات: تغییر رمز عبور", actor=_actor(db).username)
            _send(cfg, chat_id, f"✅ رمز <code>{_e(user.username)}</code> تغییر کرد.")
            return
        if command == "/quota":
            if len(args) < 2:
                raise ValueError("فرمت: /quota username 100 یا +20")
            user = _bot_user_by_username(db, args[0])
            if not user:
                raise ValueError("کاربر پیدا نشد")
            raw = _normalize_digits(args[1])
            value = float(raw.lstrip("+"))
            new_gb = (user.quota_bytes / GB + value) if raw.startswith("+") else value
            if new_gb < 0:
                raise ValueError("حجم منفی معتبر نیست")
            user.quota_bytes = int(new_gb * GB); db.commit(); sync_all_nodes_async()
            log_event("🤖 تغییر حجم کاربر از ربات", f"👤 کاربر: <code>{user.username}</code>\n📦 حجم جدید: <b>{new_gb:g} GB</b>", actor=_actor(db).username)
            _send(cfg, chat_id, f"✅ حجم کاربر روی <b>{new_gb:g} GB</b> تنظیم شد.")
            return
        if command == "/days":
            if len(args) < 2:
                raise ValueError("فرمت: /days username 30 یا +10")
            user = _bot_user_by_username(db, args[0])
            if not user:
                raise ValueError("کاربر پیدا نشد")
            raw = _normalize_digits(args[1])
            value = int(raw.lstrip("+"))
            if value < 0 or value > 3650:
                raise ValueError("روز معتبر نیست")
            if raw.startswith("+"):
                if user.expire_mode == "after_first_connect" and not user.first_connect_at:
                    user.expire_after_days = int(user.expire_after_days or 0) + value
                else:
                    user.expire_mode = "fixed"
                    user.expire_date = (user.expire_date or date.today()) + timedelta(days=value)
            elif value == 0:
                user.expire_mode = "fixed"; user.expire_date = None; user.expire_after_days = None
            elif user.first_connect_at:
                user.expire_mode = "fixed"; user.expire_date = date.today() + timedelta(days=value); user.expire_after_days = None
            else:
                user.expire_mode = "after_first_connect"; user.expire_after_days = value; user.expire_date = None
            db.commit(); sync_all_nodes_async()
            log_event("🤖 تغییر اعتبار کاربر از ربات", f"👤 کاربر: <code>{user.username}</code>\n⏳ مقدار درخواست: <b>{raw} روز</b>", actor=_actor(db).username)
            _send(cfg, chat_id, "✅ زمان انقضای کاربر بروزرسانی شد.")
            return
        if command in {"/protocols", "/targets"}:
            if len(args) < 2:
                raise ValueError(f"فرمت: {command} username VALUE")
            user = _bot_user_by_username(db, args[0])
            if not user:
                raise ValueError("کاربر پیدا نشد")
            if command == "/protocols":
                admin = _actor(db)
                selected = _protocol_set(" ".join(args[1:]), admin)
                ensure_user_protocols(admin, selected)
                for p in _allowed_protocol_keys(admin):
                    setattr(user, f"enable_{p}", p in selected)
                db.commit()
                from app.routers.users import _schedule_user_post_update_sync
                _schedule_user_post_update_sync(user.id, sync_xray=True)
                log_event("🤖 تغییر پروتکل‌های کاربر از ربات", f"👤 کاربر: <code>{user.username}</code>\n🔌 پروتکل‌های جدید: <b>{', '.join(sorted(selected))}</b>", actor=admin.username)
                msg = "✅ پروتکل‌های کاربر تغییر کرد."
            else:
                admin = _actor(db)
                selected_targets = validate_target_tokens(db, _targets(" ".join(args[1:])), admin)
                user.server_targets = serialize_targets(selected_targets); db.commit(); sync_all_nodes_async()
                log_event("🤖 تغییر سرورهای کاربر از ربات", f"👤 کاربر: <code>{user.username}</code>\n🖥 سرورهای جدید: <b>{', '.join(selected_targets)}</b>", actor=admin.username)
                msg = "✅ سرورهای کاربر تغییر کرد."
            _send(cfg, chat_id, msg)
            return
        if command == "/protocol":
            if len(args) < 2:
                raise ValueError("فرمت: /protocol vmess restart")
            _send(cfg, chat_id, _control_protocol(db, args[0], args[1]))
            return
        if command in {"/protocol_status", "/protocols_status"}:
            admin = _actor(db)
            rows = _visible_protocol_rows(admin, get_protocol_runtime_summary(db, force=False))
            lines = ["🔌 <b>وضعیت پروتکل‌های مجاز</b>"]
            for row in rows:
                state = row.get("state") or "unknown"
                icon = "🟢" if state == "active" else "🔴"
                lines.append(f"{icon} {_e(row.get('label') or row.get('key'))}: <code>{_e(state)}</code>")
            _send(cfg, chat_id, "\n".join(lines), _protocol_keyboard(rows, admin=admin))
            return
        if command == "/nodes":
            _send(cfg, chat_id, _nodes_text(db), _menu_keyboard())
            return
        if command == "/sync_nodes":
            sync_all_nodes_async(); _send(cfg, chat_id, "🔄 همگام‌سازی همه نودها شروع شد.", _menu_keyboard())
            return
        if command == "/backup":
            ok, err = send_backup_to_telegram(db=db, manual=True)
            if not ok:
                raise ValueError(err)
            _send(cfg, chat_id, "✅ بکاپ کامل ساخته و به کانال بکاپ ارسال شد.", _menu_keyboard())
            return
        if command == "/admins":
            rows = db.query(Admin).order_by(Admin.id).all()
            lines = ["🛡 <b>ادمین‌ها</b>"] + [f"{'✅' if a.is_active else '⛔'} <code>{_e(a.username)}</code> — {_e(a.role.value)} — آخرین ورود: {_e(server_datetime_payload(db, getattr(a, 'last_login_at', None))[1] if getattr(a, 'last_login_at', None) else 'بدون ورود')}" for a in rows]
            _send(cfg, chat_id, "\n".join(lines))
            return
        raise ValueError("فرمان شناخته نشد. /help را بزنید.")
    except (ValueError, TypeError, ValidationError) as exc:
        _send(cfg, chat_id, f"❌ {_e(_public_error(exc))}")
    except Exception as exc:
        logger.exception("Telegram command failed: %s", text)
        _send(cfg, chat_id, f"❌ اجرای فرمان ناموفق بود: {_e(_public_error(exc))}")
    finally:
        try:
            db.close()
        except Exception:
            pass


def _resolve_bindable_telegram_license(db, code: str, telegram_user_id: int) -> tuple[AdminAccessLicense, Admin]:
    code = str(code or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9-]{8,64}", code):
        raise ValueError("کد لایسنس ادمین معتبر نیست؛ حروف بزرگ و کوچک مهم هستند")
    row = db.query(AdminAccessLicense).filter(AdminAccessLicense.code == code).first()
    if not row or not row.is_active:
        raise ValueError("لایسنس ادمین نامعتبر یا غیرفعال است")
    if not bool(getattr(row, "telegram_bot_enabled", False)):
        raise ValueError("قابلیت ربات برای این لایسنس فعال نشده است")
    if row.used_by_admin_id is None:
        raise ValueError("ابتدا با همین لایسنس داخل پنل ثبت‌نام کن و گزینه «فعلاً ربات تلگرام نمی‌خواهم» را بزن")

    admin = db.query(Admin).filter(Admin.id == int(row.used_by_admin_id)).first()
    if not admin or not admin.is_active:
        raise ValueError("حساب پنلی که با این لایسنس ساخته شده فعال نیست")
    if admin.access_license_code != row.code:
        raise ValueError("این لایسنس دیگر لایسنس فعال حساب ثبت‌شده نیست")
    if is_expired(admin):
        raise ValueError("اعتبار حساب پنلی این لایسنس تمام شده است")

    requested_id = int(telegram_user_id)
    admin_bound = int(admin.telegram_user_id) if admin.telegram_user_id is not None else None
    license_bound = int(row.telegram_user_id) if row.telegram_user_id is not None else None
    if admin_bound == requested_id and license_bound in (None, requested_id):
        return row, admin
    if admin_bound not in (None, requested_id) or license_bound not in (None, requested_id):
        raise ValueError("این لایسنس قبلاً به آیدی عددی تلگرام دیگری متصل شده است")
    if not bool(getattr(admin, "telegram_bot_opted_out", False)):
        raise ValueError("اتصال بعدی فقط برای حسابی مجاز است که هنگام ثبت‌نام گزینه «فعلاً ربات تلگرام نمی‌خواهم» را زده باشد")

    other_admin = db.query(Admin.id).filter(
        Admin.telegram_user_id == requested_id,
        Admin.id != admin.id,
    ).first()
    if other_admin:
        raise ValueError("این آیدی عددی تلگرام قبلاً به حساب پنل دیگری متصل شده است")
    other_license = db.query(AdminAccessLicense.id).filter(
        AdminAccessLicense.telegram_user_id == requested_id,
        AdminAccessLicense.id != row.id,
    ).first()
    if other_license:
        raise ValueError("این آیدی عددی تلگرام قبلاً روی لایسنس دیگری ثبت شده است")
    return row, admin



def _group_link_code_from_text(text: str) -> str | None:
    normalized = _normalize_digits(str(text or "").strip())
    if not normalized.startswith("/connect"):
        return None
    parts = normalized.split()
    command = parts[0].split("@", 1)[0].lower()
    if command == "/connect" and len(parts) >= 2:
        return parts[1]
    # Compatibility with a copied /connect_CODE command.
    if command.startswith("/connect_"):
        return command.split("_", 1)[1]
    return ""


def _handle_group_link_message(cfg: dict, chat: dict, user: dict, text: str) -> bool:
    code = _group_link_code_from_text(text)
    if code is None:
        return False
    chat_id = chat.get("id")
    user_id = int(user.get("id") or 0)
    chat_type = str(chat.get("type") or "")
    if chat_type not in {"group", "supergroup"} or not chat_id:
        if chat_type == "private" and chat_id:
            _send(cfg, chat_id, "این فرمان را داخل گروهی بفرست که می‌خواهی به حساب پنل متصل شود.", customize=False)
        return True
    if not cfg.get("control_enabled") or not cfg.get("bot_token"):
        _send(cfg, chat_id, "❌ ربات کنترل تلگرام هنوز توسط سوپرادمین فعال نشده است.", customize=False)
        return True
    if not code:
        _send(cfg, chat_id, "❌ کد اتصال وارد نشده است. از صفحه «گروه‌های من» یک کد جدید بساز.", customize=False)
        return True

    db = SessionLocal()
    try:
        # The one-time code was issued from an authenticated panel session.
        # Whoever can post it inside the target group may complete the binding;
        # neither the sender nor the panel owner has to be a Telegram admin.
        link_row, admin = resolve_link_code(db, code)

        group = upsert_group(
            db,
            admin=admin,
            chat=chat,
            linked_by_telegram_user_id=user_id,
        )
        link_row.used_at = utcnow()
        db.commit()
        db.refresh(group)
        _CURRENT_ADMIN_ID.set(int(admin.id))
        log_event(
            "🔗 اتصال گروه تلگرام به ادمین",
            f"ادمین: {admin.username} | گروه: {group.title or group.chat_id} | chat_id={group.chat_id}",
            actor=admin.username,
        )
        _send(
            cfg,
            chat_id,
            "✅ <b>گروه با موفقیت به پنل متصل شد.</b>\n"
            f"ادمین پنل: <code>{_e(admin.username)}</code>\n"
            "از این لحظه همه اعضای این گروه می‌توانند از منوها و دکمه‌های ربات استفاده کنند.\n"
            "تمام عملیات فقط در محدوده کاربران، سرورها، پروتکل‌ها و دسترسی‌های فعلی همین ادمین اجرا می‌شود.\n"
            "هیچ‌کدام از اعضا لازم نیست ادمین گروه یا متصل به حساب پنل باشند.",
            _menu_keyboard(admin),
            customize=False,
        )
    except (ValueError, TypeError) as exc:
        db.rollback()
        _send(cfg, chat_id, f"❌ {_e(_public_error(exc))}", customize=False)
    except Exception as exc:
        db.rollback()
        logger.exception("Telegram group binding failed")
        _send(cfg, chat_id, f"❌ اتصال گروه ناموفق بود: {_e(_public_error(exc))}", customize=False)
    finally:
        db.close()
    return True

def _handle_binding_message(cfg: dict, chat: dict, user: dict, text: str) -> bool:
    chat_id = chat.get("id")
    user_id = int(user.get("id") or 0)
    if not chat_id or not user_id or str(chat.get("type") or "") != "private" or int(chat_id) != user_id:
        return False
    state = _get_state(chat_id, user_id)
    if not state or state.get("flow") != "bind_telegram":
        return False
    if state.get("step") != "license":
        return True

    code = str(text or "").strip()
    db = SessionLocal()
    try:
        row, admin = _resolve_bindable_telegram_license(db, code, user_id)
        if int(admin.telegram_user_id or 0) == user_id and bool(admin.telegram_bot_enabled):
            _CURRENT_ADMIN_ID.set(int(admin.id))
            _set_state(chat_id, user_id, None)
            _send(cfg, chat_id, "✅ این حساب از قبل به تلگرام شما متصل است.", _menu_keyboard(admin), customize=False)
            return True
        _set_state(chat_id, user_id, {
            "flow": "bind_telegram",
            "step": "confirm",
            "data": {"license_id": int(row.id), "admin_id": int(admin.id), "code": row.code},
        })
        role_label = "سوپرادمین" if admin.role == AdminRole.superadmin else "ادمین"
        _send(
            cfg,
            chat_id,
            "🔗 <b>تأیید اتصال حساب</b>\n\n"
            f"حساب پنل: <code>{_e(admin.username)}</code>\n"
            f"نقش: <b>{role_label}</b>\n"
            f"آیدی تلگرام: <code>{user_id}</code>\n\n"
            "پس از تأیید، تمام عملیات ربات دقیقاً با همین حساب پنل ثبت و اجرا می‌شود.",
            {"inline_keyboard": [[
                {"text": "✅ تأیید اتصال", "callback_data": "bind:confirm"},
                {"text": "❌ انصراف", "callback_data": "bind:cancel"},
            ]]},
            customize=False,
        )
    except (ValueError, TypeError) as exc:
        _send(
            cfg,
            chat_id,
            f"❌ {_e(exc)}\n\nلایسنس ادمین را دوباره بفرست یا انصراف را بزن.",
            {"inline_keyboard": [[{"text": "❌ انصراف", "callback_data": "bind:cancel"}]]},
            customize=False,
        )
    finally:
        db.close()
    return True


def _handle_binding_callback(cfg: dict, update: dict) -> None:
    callback = update.get("callback_query") or {}
    data = str(callback.get("data") or "")
    callback_id = str(callback.get("id") or "")
    message = callback.get("message") or {}
    chat = message.get("chat") or {}
    user = callback.get("from") or {}
    chat_id = chat.get("id")
    user_id = int(user.get("id") or 0)

    if not cfg.get("control_enabled"):
        _answer(cfg, callback_id, "کنترل ربات در پنل غیرفعال است", alert=True)
        return
    if not chat_id or not user_id or str(chat.get("type") or "") != "private" or int(chat_id) != user_id:
        _answer(cfg, callback_id, "اتصال حساب فقط در گفت‌وگوی خصوصی ربات انجام می‌شود", alert=True)
        return
    if data == "bind:cancel":
        _set_state(chat_id, user_id, None)
        _answer(cfg, callback_id, "لغو شد")
        _send_binding_required(cfg, chat, user)
        return
    if data == "bind:start":
        db = SessionLocal()
        try:
            linked = _linked_admin_for_telegram_id(db, user_id)
            if linked and not is_expired(linked):
                _CURRENT_ADMIN_ID.set(int(linked.id))
                _set_state(chat_id, user_id, None)
                _answer(cfg, callback_id, "حساب شما متصل است")
                _send_main_menu(cfg, chat_id)
                return
        finally:
            db.close()
        _set_state(chat_id, user_id, {"flow": "bind_telegram", "step": "license", "data": {}})
        _answer(cfg, callback_id)
        _send(
            cfg,
            chat_id,
            "🎫 <b>لایسنس ادمین را بفرست</b>\n\n"
            "حساب باید قبلاً داخل پنل با همین لایسنس ثبت شده باشد و هنگام ثبت‌نام گزینه «فعلاً ربات تلگرام نمی‌خواهم» انتخاب شده باشد.",
            {"inline_keyboard": [[{"text": "❌ انصراف", "callback_data": "bind:cancel"}]]},
            customize=False,
        )
        return
    if data != "bind:confirm":
        _answer(cfg, callback_id, "درخواست اتصال نامعتبر است", alert=True)
        return

    state = _get_state(chat_id, user_id)
    if not state or state.get("flow") != "bind_telegram" or state.get("step") != "confirm":
        _answer(cfg, callback_id, "مرحله اتصال منقضی شده؛ دوباره شروع کن", alert=True)
        return
    code = str((state.get("data") or {}).get("code") or "")
    db = SessionLocal()
    try:
        row, admin = _resolve_bindable_telegram_license(db, code, user_id)
        admin.telegram_user_id = user_id
        admin.telegram_bot_enabled = True
        admin.telegram_bot_opted_out = False
        row.telegram_user_id = user_id
        db.commit()
        db.refresh(admin)
        _CURRENT_ADMIN_ID.set(int(admin.id))
        _set_state(chat_id, user_id, None)
        log_event(
            "🔗 اتصال حساب تلگرام به ادمین",
            f"یوزرنیم: {admin.username} | Telegram ID: {user_id} | License: {row.code}",
            actor=admin.username,
        )
        _answer(cfg, callback_id, "حساب با موفقیت متصل شد", alert=True)
        _send(
            cfg,
            chat_id,
            f"✅ حساب تلگرام به <code>{_e(admin.username)}</code> متصل شد.\nاز این لحظه همه عملیات با نام همین حساب ثبت می‌شود.",
            _menu_keyboard(admin),
            customize=False,
        )
    except Exception as exc:
        db.rollback()
        logger.exception("Telegram account binding failed")
        _answer(cfg, callback_id, _public_error(exc)[:180], alert=True)
    finally:
        db.close()


def _handle_callback(cfg: dict, update: dict) -> None:
    callback = update.get("callback_query") or {}
    data = str(callback.get("data") or "")
    if data.startswith("bind:"):
        _handle_binding_callback(cfg, update)
        return
    allow_log = data.startswith("banip:")
    ok, reason, chat, user = _authorized(cfg, update, allow_log_callback=allow_log)
    if not ok:
        message = "ابتدا حساب پنل خود را با لایسنس ادمین به تلگرام متصل کن" if reason == "telegram_account_unbound" else reason
        _answer(cfg, str(callback.get("id") or ""), message, alert=True)
        return
    chat_id, user_id = chat.get("id"), int(user.get("id") or 0)
    callback_id = str(callback.get("id") or "")
    db = SessionLocal()
    try:
        _guard_callback_permission(db, data)
        if data.startswith("banip:"):
            _, msg = _ban(db, data.split(":", 1)[1], "ورود ناموفق به پنل")
            _answer(cfg, callback_id, re.sub(r"<[^>]+>", "", msg), alert=True)
            _remove_keyboard(cfg, callback)
            return
        if data.startswith("unbanip:"):
            _, msg = _unban(db, data.split(":", 1)[1])
            _answer(cfg, callback_id, re.sub(r"<[^>]+>", "", msg), alert=True)
            _remove_keyboard(cfg, callback)
            return
        if data.startswith("menu:"):
            # Navigating away from a form always cancels the old pending input;
            # otherwise a later ordinary message could be consumed by a stale
            # username/IP/value prompt.
            _set_state(chat_id, user_id, None)
        if data == "flow:cancel" or data == "create:cancel":
            _set_state(chat_id, user_id, None)
            _answer(cfg, callback_id, "لغو شد")
            _remove_keyboard(cfg, callback)
            _send(cfg, chat_id, "عملیات لغو شد.", _menu_keyboard())
            return
        if data == "menu:home":
            _set_state(chat_id, user_id, None)
            _answer(cfg, callback_id)
            _send_main_menu(cfg, chat_id, "🏠 <b>منوی اصلی</b>")
            return
        if data == "menu:status":
            _answer(cfg, callback_id)
            _send(cfg, chat_id, _status_text(db), _menu_keyboard())
            return
        if data == "menu:users":
            _answer(cfg, callback_id)
            _send(cfg, chat_id, _list_users_text(db), _users_keyboard(db))
            return
        if data.startswith("userpick:"):
            vpn_user = _bot_user_by_id(db, int(data.split(":", 1)[1]))
            if not vpn_user:
                raise ValueError("کاربر پیدا نشد")
            _answer(cfg, callback_id)
            _send(cfg, chat_id, _format_user(vpn_user, db), _user_keyboard(vpn_user, db))
            return
        if data == "menu:create":
            _answer(cfg, callback_id)
            db.close()
            _start_create_wizard(cfg, chat_id, user_id)
            return
        if data == "menu:user":
            _answer(cfg, callback_id)
            _set_state(chat_id, user_id, {"flow": "ask_user"})
            _send(cfg, chat_id, "🔎 نام کاربری موردنظر را بنویسید.", _cancel_keyboard(back="menu:users"))
            return
        if data == "menu:ips":
            _answer(cfg, callback_id)
            _send(cfg, chat_id, "🚫 <b>مدیریت آی‌پی‌ها</b>\nعملیات موردنظر را انتخاب کنید.", _ip_menu_keyboard())
            return
        if data == "menu:ban":
            _answer(cfg, callback_id)
            _set_state(chat_id, user_id, {"flow": "ask_ban"})
            _send(cfg, chat_id, "🚫 آی‌پی موردنظر برای بن را بنویسید.", _cancel_keyboard(back="menu:ips"))
            return
        if data == "menu:unban":
            _answer(cfg, callback_id)
            _set_state(chat_id, user_id, {"flow": "ask_unban"})
            _send(cfg, chat_id, "✅ آی‌پی موردنظر برای رفع بن را بنویسید.", _cancel_keyboard(back="menu:ips"))
            return
        if data == "menu:bans":
            body, keyboard = _bans_text(db)
            _answer(cfg, callback_id)
            _send(cfg, chat_id, body, keyboard)
            return
        if data == "menu:admins":
            body, keyboard = _admins_payload(db)
            _answer(cfg, callback_id)
            _send(cfg, chat_id, body, keyboard)
            return
        if data == "menu:nodes":
            _answer(cfg, callback_id)
            _send(cfg, chat_id, _nodes_text(db), _nodes_keyboard(db))
            return
        if data == "menu:syncnodes":
            sync_all_nodes_async()
            _answer(cfg, callback_id, "سینک شروع شد")
            _send(cfg, chat_id, "🔄 همگام‌سازی نودها شروع شد.", _nodes_keyboard(db))
            return
        if data == "menu:backup":
            _answer(cfg, callback_id, "در حال ساخت بکاپ…")
            ok_backup, err = send_backup_to_telegram(db=db, manual=True)
            if not ok_backup:
                raise ValueError(err)
            _send(cfg, chat_id, "✅ بکاپ کامل به کانال بکاپ ارسال شد.", _menu_keyboard())
            return
        if data == "menu:help":
            _answer(cfg, callback_id)
            _send(cfg, chat_id, _help_text(_actor(db)), _menu_keyboard())
            return
        if data == "menu:myid":
            _answer(cfg, callback_id)
            _send(
                cfg,
                chat_id,
                f"👤 شناسه عددی شما: <code>{user_id}</code>\n💬 شناسه این چت: <code>{_e(chat_id)}</code>",
                _menu_keyboard(),
            )
            return
        if data == "menu:protocols":
            body, keyboard = _protocol_servers_payload(db)
            _answer(cfg, callback_id)
            _send(cfg, chat_id, body, keyboard)
            return
        if data.startswith("protosrv:"):
            server_id = data.split(":", 1)[1]
            body, keyboard = _protocol_server_payload(db, server_id)
            _answer(cfg, callback_id)
            _send(cfg, chat_id, body, keyboard)
            return

        if data == "menu:online":
            body, keyboard = _online_users_payload(db)
            _answer(cfg, callback_id)
            _send(cfg, chat_id, body, keyboard)
            return
        if data == "menu:internet":
            body, keyboard = _internet_blocks_payload(db)
            _answer(cfg, callback_id)
            _send(cfg, chat_id, body, keyboard)
            return
        if data == "menu:licenses":
            body, keyboard = _licenses_payload(db)
            _answer(cfg, callback_id)
            _send(cfg, chat_id, body, keyboard)
            return
        if data == "menu:update":
            from app.services import update_manager
            status = update_manager.get_status()
            _answer(cfg, callback_id)
            _send(cfg, chat_id, f"⬆️ <b>بروزرسانی پنل</b>\nنسخه فعلی: <code>{_e(status.get('current_version') or '—')}</code>\nوضعیت: <b>{_e(status.get('state') or 'idle')}</b>\n{_e(status.get('message') or '')}", _update_keyboard())
            return
        if data == "menu:panel_license":
            from app.services import license_manager
            result = license_manager.get_status(db, include_queue_details=True)
            _answer(cfg, callback_id)
            _send(cfg, chat_id, "\n".join([
                "🔐 <b>لایسنس خود پنل</b>",
                f"وضعیت: <b>{_e(result.get('status') or 'unknown')}</b>",
                f"کد: <code>{_e(result.get('key_masked') or result.get('key') or '—')}</code>",
                f"انقضا: <b>{_e(result.get('expires_at') or result.get('expiry') or '—')}</b>",
            ]), _panel_license_keyboard())
            return
        if data == "menu:tools":
            _answer(cfg, callback_id)
            _send(cfg, chat_id, "⚙️ <b>تنظیمات و ابزارهای مدیریتی</b>\nفقط ابزارهای مجاز این حساب نمایش داده می‌شوند.", _tools_keyboard(db))
            return
        if data == "menu:bot_texts":
            _require_superadmin(db)
            body, keyboard = _bot_text_manager_payload(cfg)
            _answer(cfg, callback_id)
            _send(cfg, chat_id, body, keyboard)
            return
        if data == "bottext:add":
            data = "bottext:catalog:0"
        if data.startswith("bottext:catalog:"):
            _require_superadmin(db)
            try:
                page = int(data.rsplit(":", 1)[1])
            except (TypeError, ValueError):
                page = 0
            body, keyboard = _bot_text_catalog_payload(cfg, page)
            _answer(cfg, callback_id)
            _send(cfg, chat_id, body, keyboard, customize=False)
            return
        if data.startswith("bottext:pick:"):
            _require_superadmin(db)
            parts = data.split(":")
            if len(parts) != 4:
                raise ValueError("انتخاب متن معتبر نیست")
            page, index = int(parts[2]), int(parts[3])
            items = _bot_text_catalog()
            if index < 0 or index >= len(items):
                raise ValueError("این متن دیگر در فهرست وجود ندارد")
            kind, source = items[index]
            current = _customize_text(cfg, source)
            _set_state(chat_id, user_id, {
                "flow": "bot_text_override",
                "step": "replacement",
                "data": {"source": source, "page": page, "kind": kind},
            })
            _answer(cfg, callback_id)
            _send(
                cfg,
                chat_id,
                f"✏️ <b>{'نام دکمه' if kind == 'button' else 'متن'} انتخاب شد</b>\n\n"
                f"مقدار فعلی:\n<code>{_e(current)}</code>\n\n"
                "حالا فقط متن جدید را بفرست.",
                {"inline_keyboard": [[{"text": "❌ انصراف", "callback_data": "bottext:cancel_edit"}]]},
                customize=False,
            )
            return
        if data == "bottext:cancel_edit":
            state = _get_state(chat_id, user_id) or {}
            page = int((state.get("data") or {}).get("page") or 0)
            _set_state(chat_id, user_id, None)
            body, keyboard = _bot_text_catalog_payload(cfg, page)
            _answer(cfg, callback_id, "لغو شد")
            _send(cfg, chat_id, body, keyboard, customize=False)
            return
        if data == "bottext:confirm":
            _require_superadmin(db)
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "bot_text_override" or state.get("step") != "confirm":
                raise ValueError("مرحله تأیید متن منقضی شده است")
            state_data = state.get("data") or {}
            source = str(state_data.get("source") or "").strip()
            replacement = str(state_data.get("replacement") or "").strip()
            page = int(state_data.get("page") or 0)
            if not source or not replacement:
                raise ValueError("متن قبلی یا جدید ثبت نشده است")
            overrides = _control_text_overrides(cfg)
            overrides[source] = replacement
            if len(overrides) > 500:
                raise ValueError("حداکثر ۵۰۰ تغییر متن قابل ذخیره است")
            _save_control_text_overrides(db, cfg, overrides)
            _set_state(chat_id, user_id, None)
            body, keyboard = _bot_text_catalog_payload(cfg, page)
            _answer(cfg, callback_id, "متن ذخیره شد", alert=True)
            _send(
                cfg,
                chat_id,
                f"✅ تغییر ذخیره شد.\n\nاز: <code>{_e(source)}</code>\nبه: <code>{_e(replacement)}</code>\n\n{body}",
                keyboard,
                customize=False,
            )
            return
        if data.startswith("bottext:list:"):
            _require_superadmin(db)
            try:
                page = int(data.rsplit(":", 1)[1])
            except (TypeError, ValueError):
                page = 0
            body, keyboard = _bot_text_list_payload(cfg, page)
            _answer(cfg, callback_id)
            _send(cfg, chat_id, body, keyboard, customize=False)
            return
        if data.startswith("bottext:delete:"):
            _require_superadmin(db)
            parts = data.split(":")
            if len(parts) != 4:
                raise ValueError("درخواست حذف متن معتبر نیست")
            page = int(parts[2])
            index = int(parts[3])
            overrides = _control_text_overrides(cfg)
            items = sorted(overrides.items(), key=lambda item: item[0])
            if index < 0 or index >= len(items):
                raise ValueError("این تغییر دیگر وجود ندارد")
            source, _replacement = items[index]
            overrides.pop(source, None)
            _save_control_text_overrides(db, cfg, overrides)
            body, keyboard = _bot_text_list_payload(cfg, page)
            _answer(cfg, callback_id, "تغییر حذف شد")
            _send(cfg, chat_id, "✅ تغییر انتخاب‌شده حذف شد.\n\n" + body, keyboard, customize=False)
            return
        if data == "bottext:reset":
            _require_superadmin(db)
            _answer(cfg, callback_id)
            _send(cfg, chat_id, "⚠️ همه متن‌ها و نام دکمه‌ها به حالت پیش‌فرض برگردند؟", {"inline_keyboard": [[
                {"text": "✅ بله، بازگردانی همه", "callback_data": "bottext:reset_confirm"},
                {"text": "❌ انصراف", "callback_data": "menu:bot_texts"},
            ]]})
            return
        if data == "bottext:reset_confirm":
            _require_superadmin(db)
            _save_control_text_overrides(db, cfg, {})
            body, keyboard = _bot_text_manager_payload(cfg)
            _answer(cfg, callback_id, "همه متن‌ها بازگردانی شد")
            _send(cfg, chat_id, "✅ همه متن‌ها و دکمه‌های ربات به حالت پیش‌فرض برگشت.\n\n" + body, keyboard)
            return

        if data == "inet:ask":
            _set_state(chat_id, user_id, {"flow": "ask_internet_block"})
            _answer(cfg, callback_id)
            _send(cfg, chat_id, "⛔ آی‌پی عمومی را برای قطع دسترسی VPN بنویسید.", _cancel_keyboard(back="menu:internet"))
            return
        if data.startswith("inet:restore:"):
            ip = str(ipaddress.ip_address(data.split(":", 2)[2]))
            actor = _require_permission(db, "internet_blocks:view")
            row = db.query(InternetBlockedIP).filter(InternetBlockedIP.ip_address == ip).first()
            if not row:
                raise ValueError("این آی‌پی در فهرست قطع اینترنت نیست")
            from app.security import can_view_all_users
            if not can_view_all_users(actor) and row.owner_admin_id != actor.id:
                raise ValueError("به این رکورد دسترسی ندارید")
            restore_internet_ip(db, ip)
            sync_global_controls_to_active_nodes_async(force_restore_ips=[ip])
            _answer(cfg, callback_id, "اینترنت وصل شد", alert=True)
            body, keyboard = _internet_blocks_payload(db)
            _edit(cfg, callback, body, keyboard)
            return

        if data == "admin:new":
            _set_state(chat_id, user_id, {
                "flow": "admin_create",
                "step": "username",
                "data": {
                    "permissions": [],
                    "see_all_users": False,
                    "targets": [],
                    "max_users": None,
                    "max_total_quota_gb": None,
                    "subscription_expire_date": None,
                },
            })
            _answer(cfg, callback_id)
            _send(cfg, chat_id, "➕ <b>ساخت ادمین زیرمجموعه</b>\nنام کاربری انگلیسی را بنویسید.", _cancel_keyboard(back="menu:admins"))
            return
        if data.startswith("adperm:"):
            action = data.split(":", 1)[1]
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "admin_create" or state.get("step") != "permissions":
                raise ValueError("مرحله انتخاب دسترسی منقضی شده است")
            selected = set(state["data"].get("permissions") or [])
            if action == "all":
                selected = set(ADMIN_PERMISSION_TOKENS)
            elif action == "none":
                selected = set()
            elif action == "confirm":
                if not selected:
                    raise ValueError("حداقل یک دسترسی را انتخاب کنید")
                state["data"]["permissions"] = [token for token in ADMIN_PERMISSION_TOKENS if token in selected]
                state["step"] = "see_all_users"
                _set_state(chat_id, user_id, state)
                _answer(cfg, callback_id)
                _edit(cfg, callback, "👥 آیا این ادمین همه کاربران پنل را ببیند یا فقط کاربران خودش را؟", {"inline_keyboard": [[
                    {"text": "🌐 همه کاربران", "callback_data": "adsee:yes"},
                    {"text": "👤 فقط کاربران خودش", "callback_data": "adsee:no"},
                ], [{"text": "❌ لغو", "callback_data": "flow:cancel"}]]})
                return
            else:
                try:
                    token = ADMIN_PERMISSION_TOKENS[int(action)]
                except (ValueError, IndexError) as exc:
                    raise ValueError("دکمه دسترسی نامعتبر است") from exc
                selected.symmetric_difference_update({token})
            state["data"]["permissions"] = [token for token in ADMIN_PERMISSION_TOKENS if token in selected]
            _set_state(chat_id, user_id, state)
            _answer(cfg, callback_id)
            _edit(cfg, callback, "🧩 دسترسی‌های ادمین را انتخاب و سپس تأیید کنید.", _admin_permission_keyboard(selected))
            return
        if data.startswith("adsee:"):
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "admin_create" or state.get("step") != "see_all_users":
                raise ValueError("مرحله ساخت ادمین منقضی شده است")
            state["data"]["see_all_users"] = data.endswith(":yes")
            state["step"] = "targets"
            _set_state(chat_id, user_id, state)
            _answer(cfg, callback_id)
            _edit(cfg, callback, "🖥 سرورهای قابل مدیریت برای این ادمین را انتخاب کنید.", _admin_target_keyboard(db, set()))
            return
        if data.startswith("adtgt:"):
            action = data.split(":", 1)[1]
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "admin_create" or state.get("step") != "targets":
                raise ValueError("مرحله انتخاب سرور منقضی شده است")
            selected = set(state["data"].get("targets") or [])
            if action == "all":
                selected = {"all"}
            elif action == "none":
                selected = set()
            elif action == "confirm":
                if not selected:
                    raise ValueError("حداقل یک سرور را انتخاب کنید")
                state["data"]["targets"] = sorted(selected)
                state["step"] = "max_users"
                _set_state(chat_id, user_id, state)
                _answer(cfg, callback_id)
                _edit(cfg, callback, "👥 حداکثر تعداد کاربر قابل ساخت را انتخاب کنید.", _admin_limit_keyboard("users"))
                return
            else:
                valid = {token for token, _label in _target_options(db)}
                if action not in valid:
                    raise ValueError("سرور نامعتبر است")
                if "all" in selected:
                    selected = set()
                selected.symmetric_difference_update({action})
            state["data"]["targets"] = sorted(selected)
            _set_state(chat_id, user_id, state)
            _answer(cfg, callback_id)
            _edit(cfg, callback, "🖥 سرورها را انتخاب و سپس تأیید کنید.", _admin_target_keyboard(db, selected))
            return
        if data.startswith("adusers:"):
            value = data.split(":", 1)[1]
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "admin_create" or state.get("step") != "max_users":
                raise ValueError("مرحله ساخت ادمین منقضی شده است")
            if value == "custom":
                state["step"] = "max_users_custom"; _set_state(chat_id, user_id, state)
                _answer(cfg, callback_id); _send(cfg, chat_id, "✍️ حداکثر تعداد کاربر را بنویسید؛ 0 یعنی نامحدود.", _cancel_keyboard(back="menu:admins")); return
            state["data"]["max_users"] = int(value) or None
            state["step"] = "quota"; _set_state(chat_id, user_id, state)
            _answer(cfg, callback_id); _edit(cfg, callback, "📦 سقف حجم کل ادمین را انتخاب کنید.", _admin_limit_keyboard("quota")); return
        if data.startswith("adquota:"):
            value = data.split(":", 1)[1]
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "admin_create" or state.get("step") != "quota":
                raise ValueError("مرحله ساخت ادمین منقضی شده است")
            if value == "custom":
                state["step"] = "quota_custom"; _set_state(chat_id, user_id, state)
                _answer(cfg, callback_id); _send(cfg, chat_id, "✍️ سقف حجم کل را به گیگ بنویسید؛ 0 یعنی نامحدود.", _cancel_keyboard(back="menu:admins")); return
            state["data"]["max_total_quota_gb"] = int(value) or None
            state["step"] = "expiry"; _set_state(chat_id, user_id, state)
            _answer(cfg, callback_id); _edit(cfg, callback, "📅 تاریخ انقضای ادمین را انتخاب کنید.", _admin_expiry_keyboard()); return
        if data.startswith("adexp:"):
            value = data.split(":", 1)[1]
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "admin_create" or state.get("step") != "expiry":
                raise ValueError("مرحله ساخت ادمین منقضی شده است")
            if value == "custom":
                state["step"] = "expiry_custom"; _set_state(chat_id, user_id, state)
                _answer(cfg, callback_id); _send(cfg, chat_id, "📅 تاریخ دقیق را به شکل YYYY-MM-DD بنویسید.", _cancel_keyboard(back="menu:admins")); return
            state["data"]["subscription_expire_date"] = None if value == "none" else (date.today() + timedelta(days=int(value))).isoformat()
            state["step"] = "bot"; _set_state(chat_id, user_id, state)
            _answer(cfg, callback_id); _edit(cfg, callback, "🤖 آیا دسترسی خصوصی ربات برای این ادمین فعال شود؟", _admin_bot_keyboard()); return
        if data.startswith("adbot:"):
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "admin_create" or state.get("step") != "bot":
                raise ValueError("مرحله فعال‌سازی ربات منقضی شده است")
            enabled = data.endswith(":on")
            state["data"]["telegram_bot_enabled"] = enabled
            if enabled:
                state["step"] = "telegram_id"
                _set_state(chat_id, user_id, state)
                _answer(cfg, callback_id)
                _send(cfg, chat_id, "🆔 آیدی عددی تلگرام این ادمین را بنویسید.", _cancel_keyboard(back="menu:admins"))
            else:
                state["data"]["telegram_user_id"] = None
                state["step"] = "confirm"
                _set_state(chat_id, user_id, state)
                _answer(cfg, callback_id)
                _edit(cfg, callback, _admin_create_summary(state["data"]), {"inline_keyboard": [[{"text": "✅ ساخت ادمین", "callback_data": "admin:create_confirm"}, {"text": "❌ لغو", "callback_data": "flow:cancel"}]]})
            return
        if data == "admin:create_confirm":
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "admin_create" or state.get("step") != "confirm":
                raise ValueError("مرحله ساخت ادمین منقضی شده است")
            admin_row = _create_subadmin_from_data(db, state["data"])
            _set_state(chat_id, user_id, None)
            _answer(cfg, callback_id, "ادمین ساخته شد", alert=True)
            body, keyboard = _admin_card(admin_row, db)
            _edit(cfg, callback, "✅ ادمین با موفقیت ساخته شد.\n\n" + body, keyboard)
            return
        if data.startswith("admin:"):
            _, raw_id, action = data.split(":", 2)
            admin_row = db.query(Admin).filter(Admin.id == int(raw_id)).first()
            if not admin_row:
                raise ValueError("ادمین پیدا نشد")
            if action == "show":
                body, keyboard = _admin_card(admin_row, db)
                _answer(cfg, callback_id)
                _send(cfg, chat_id, body, keyboard)
                return
            if admin_row.role == AdminRole.superadmin:
                raise ValueError("وضعیت سوپرادمین اصلی از ربات تغییر داده نمی‌شود")
            if action not in {"enable", "disable"}:
                raise ValueError("عملیات ادمین نامعتبر است")
            from app.routers.admins import _admin_change_log, _admin_snapshot
            audit_before = _admin_snapshot(admin_row)
            admin_row.is_active = action == "enable"
            db.commit()
            db.refresh(admin_row)
            log_event(
                "✏️ ویرایش ادمین از ربات",
                _admin_change_log(admin_row.username, audit_before, _admin_snapshot(admin_row)),
                actor=_actor(db).username,
            )
            _answer(cfg, callback_id, "وضعیت ادمین تغییر کرد", alert=True)
            body, keyboard = _admins_payload(db)
            _edit(cfg, callback, body, keyboard)
            return

        if data == "license:new":
            _set_state(chat_id, user_id, {"flow": "license_create", "step": "role", "data": {}})
            _answer(cfg, callback_id)
            _send(cfg, chat_id, "🎫 نوع حسابی که این لایسنس می‌سازد را انتخاب کنید.", _license_role_keyboard())
            return
        if data.startswith("licrole:"):
            role = data.split(":", 1)[1]
            if role not in {"admin", "superadmin"}:
                raise ValueError("نقش نامعتبر است")
            state = {"flow": "license_create", "step": "permissions" if role == "admin" else "days", "data": {"role": role}}
            _set_state(chat_id, user_id, state)
            _answer(cfg, callback_id)
            if role == "admin":
                _edit(cfg, callback, "🧩 سطح دسترسی ادمین زیرمجموعه را انتخاب کنید.", _license_permission_keyboard())
            else:
                state["data"].update({"permissions": [], "targets": [], "max_users": None, "max_total_quota_gb": None})
                _set_state(chat_id, user_id, state)
                _edit(cfg, callback, "⏳ مدت اعتبار لایسنس سوپرادمین را انتخاب کنید.", _license_duration_keyboard())
            return
        if data.startswith("licperm:"):
            preset = data.split(":", 1)[1]
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "license_create" or state.get("step") != "permissions":
                raise ValueError("مرحله ساخت لایسنس منقضی شده است")
            if preset == "full":
                permissions = list(ADMIN_PERMISSION_TOKENS)
            elif preset == "users":
                permissions = [p for p in ADMIN_PERMISSION_TOKENS if p.startswith(("dashboard:", "users:", "online:", "bans:"))]
            elif preset == "operator":
                permissions = [p for p in ADMIN_PERMISSION_TOKENS if p.startswith(("dashboard:", "users:", "online:", "bans:", "protocols:", "nodes:"))]
            else:
                raise ValueError("سطح دسترسی نامعتبر است")
            state["data"].update({"permissions": permissions, "see_all_users": False, "targets": []})
            state["step"] = "targets"
            _set_state(chat_id, user_id, state)
            _answer(cfg, callback_id)
            _edit(cfg, callback, "🖥 سرورهایی که این ادمین می‌تواند مدیریت کند انتخاب کنید.", _license_target_keyboard(db, set()))
            return
        if data.startswith("lictgt:"):
            action = data.split(":", 1)[1]
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "license_create" or state.get("step") != "targets":
                raise ValueError("مرحله انتخاب سرور منقضی شده است")
            selected = set(state["data"].get("targets") or [])
            if action == "all": selected = {"all"}
            elif action == "none": selected = set()
            elif action == "confirm":
                if not selected:
                    raise ValueError("حداقل یک سرور را انتخاب کنید")
                state["data"]["targets"] = sorted(selected)
                state["step"] = "max_users"
                _set_state(chat_id, user_id, state)
                _answer(cfg, callback_id)
                _edit(cfg, callback, "👥 حداکثر تعداد کاربر این ادمین را انتخاب کنید.", _license_limits_keyboard("max_users"))
                return
            else:
                if "all" in selected: selected = set()
                selected.symmetric_difference_update({action})
            state["data"]["targets"] = sorted(selected)
            _set_state(chat_id, user_id, state)
            _answer(cfg, callback_id)
            _edit(cfg, callback, "🖥 سرورهای مجاز را انتخاب و سپس تأیید کنید.", _license_target_keyboard(db, selected))
            return
        if data.startswith("licusers:"):
            value = data.split(":", 1)[1]
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "license_create" or state.get("step") != "max_users":
                raise ValueError("مرحله ساخت لایسنس منقضی شده است")
            if value == "custom":
                state["step"] = "max_users_custom"; _set_state(chat_id, user_id, state)
                _answer(cfg, callback_id); _send(cfg, chat_id, "✍️ حداکثر تعداد کاربر را بنویسید؛ 0 یعنی نامحدود.", _cancel_keyboard(back="menu:licenses")); return
            state["data"]["max_users"] = int(value) or None
            state["step"] = "quota"; _set_state(chat_id, user_id, state)
            _answer(cfg, callback_id); _edit(cfg, callback, "📦 سقف حجم کل ادمین را انتخاب کنید.", _license_limits_keyboard("quota")); return
        if data.startswith("licquota:"):
            value = data.split(":", 1)[1]
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "license_create" or state.get("step") != "quota":
                raise ValueError("مرحله ساخت لایسنس منقضی شده است")
            if value == "custom":
                state["step"] = "quota_custom"; _set_state(chat_id, user_id, state)
                _answer(cfg, callback_id); _send(cfg, chat_id, "✍️ سقف حجم کل را به گیگ بنویسید؛ 0 یعنی نامحدود.", _cancel_keyboard(back="menu:licenses")); return
            state["data"]["max_total_quota_gb"] = int(value) or None
            state["step"] = "days"; _set_state(chat_id, user_id, state)
            _answer(cfg, callback_id); _edit(cfg, callback, "⏳ مدت اعتبار لایسنس را انتخاب کنید.", _license_duration_keyboard()); return
        if data.startswith("licdays:"):
            value = data.split(":", 1)[1]
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "license_create" or state.get("step") != "days":
                raise ValueError("مرحله ساخت لایسنس منقضی شده است")
            if value == "custom":
                state["step"] = "days_custom"; _set_state(chat_id, user_id, state)
                _answer(cfg, callback_id); _send(cfg, chat_id, "✍️ تعداد روز اعتبار بعد از فعال‌سازی را بنویسید.", _cancel_keyboard(back="menu:licenses")); return
            state["data"]["days"] = int(value)
            state["step"] = "bot"; _set_state(chat_id, user_id, state)
            _answer(cfg, callback_id); _edit(cfg, callback, "🤖 آیا دسترسی خصوصی ربات برای این لایسنس فعال شود؟", _license_bot_keyboard()); return
        if data.startswith("licbot:"):
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "license_create" or state.get("step") != "bot":
                raise ValueError("مرحله فعال‌سازی ربات منقضی شده است")
            enabled = data.endswith(":on")
            state["data"]["telegram_bot_enabled"] = enabled
            # A license only grants bot capability. The eventual owner enters
            # their own numeric Telegram ID during registration, or opts out.
            state["data"]["telegram_user_id"] = None
            state["step"] = "confirm"
            _set_state(chat_id, user_id, state)
            _answer(cfg, callback_id)
            _edit(cfg, callback, _license_confirm_text(state["data"]), {"inline_keyboard": [[{"text": "✅ ساخت لایسنس", "callback_data": "license:create_confirm"}, {"text": "❌ لغو", "callback_data": "flow:cancel"}]]})
            return
        if data == "license:create_confirm":
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "license_create" or state.get("step") != "confirm":
                raise ValueError("مرحله ساخت لایسنس منقضی شده است")
            row = _create_internal_license_from_data(db, state["data"])
            _set_state(chat_id, user_id, None)
            _answer(cfg, callback_id, "لایسنس ساخته شد", alert=True)
            body, keyboard = _license_card(row)
            _edit(cfg, callback, "✅ لایسنس با موفقیت ساخته شد.\n\n" + body, keyboard)
            return
        if data.startswith("license:"):
            _, raw_id, action = data.split(":", 2)
            row = db.query(AdminAccessLicense).filter(AdminAccessLicense.id == int(raw_id)).first()
            if not row: raise ValueError("لایسنس پیدا نشد")
            if action == "show":
                body, keyboard = _license_card(row); _answer(cfg, callback_id); _send(cfg, chat_id, body, keyboard); return
            if row.used_by_admin_id: raise ValueError("لایسنس استفاده‌شده قابل تغییر نیست")
            if action in {"enable", "disable"}:
                row.is_active = action == "enable"; db.commit(); _answer(cfg, callback_id, "وضعیت تغییر کرد", alert=True); body, keyboard = _license_card(row); _edit(cfg, callback, body, keyboard); return
            if action == "delete":
                _answer(cfg, callback_id)
                _send(cfg, chat_id, f"⚠️ لایسنس <code>{_e(row.code)}</code> حذف شود؟", {"inline_keyboard": [[{"text": "🗑 بله، حذف", "callback_data": f"license:{row.id}:delete_confirm"}, {"text": "انصراف", "callback_data": f"license:{row.id}:show"}]]}); return
            if action == "delete_confirm":
                db.delete(row); db.commit(); _answer(cfg, callback_id, "حذف شد", alert=True); body, keyboard = _licenses_payload(db); _edit(cfg, callback, body, keyboard); return
            raise ValueError("عملیات لایسنس نامعتبر است")

        if data.startswith("update:"):
            from app.services import update_manager
            action = data.split(":", 1)[1]
            if action == "check":
                result = update_manager.check_latest(db)
                body = "\n".join(["⬆️ <b>بررسی بروزرسانی</b>", f"نسخه فعلی: <code>{_e(result.get('current_version'))}</code>", f"آخرین نسخه: <code>{_e(result.get('latest_version'))}</code>", f"نسخه جدید: <b>{'بله' if result.get('update_available') else 'خیر'}</b>", _e(result.get('notes') or '')])
                keyboard = _update_keyboard()
                if result.get("update_available"):
                    keyboard["inline_keyboard"].insert(1, [{"text": "⚠️ دریافت و اعمال آپدیت", "callback_data": "update:start_confirm"}])
                _answer(cfg, callback_id); _edit(cfg, callback, body, keyboard); return
            if action == "start_confirm":
                _answer(cfg, callback_id)
                _send(cfg, chat_id, "⚠️ هنگام آپدیت ممکن است API چند ثانیه ری‌استارت شود. ادامه می‌دهید؟", {"inline_keyboard": [[{"text": "✅ بله، شروع کن", "callback_data": "update:start"}, {"text": "انصراف", "callback_data": "menu:update"}]]}); return
            if action == "start":
                result = update_manager.start_update(db)
                _answer(cfg, callback_id, "آپدیت شروع شد", alert=True)
                _edit(cfg, callback, "🔄 <b>وضعیت آپدیت</b>\nدرصد: <b>1%</b>\nوضعیت: <b>در حال اجرا</b>\nاین پیام از این لحظه خودکار به‌روزرسانی می‌شود.", _update_keyboard())
                message = callback.get("message") or {}
                if message.get("message_id"):
                    update_manager.register_telegram_watch(chat_id, int(message["message_id"]), actor=_actor(db).username)
                return
            if action == "status":
                result = update_manager.get_status()
                _answer(cfg, callback_id)
                _edit(cfg, callback, f"📊 <b>وضعیت آپدیت</b>\nدرصد: <b>{result.get('percent', 0)}%</b>\nوضعیت: <b>{_e(result.get('state'))}</b>\n{_e(result.get('message') or '')}" + ("\nاین پیام خودکار به‌روزرسانی می‌شود." if result.get("state") == "running" else ""), _update_keyboard())
                message = callback.get("message") or {}
                if result.get("state") == "running" and message.get("message_id"):
                    update_manager.register_telegram_watch(chat_id, int(message["message_id"]), actor=_actor(db).username)
                return
            if action == "log":
                log = update_manager.get_log().get("log") or "لاگی ثبت نشده است."
                _answer(cfg, callback_id); _send(cfg, chat_id, f"🧾 <b>انتهای لاگ آپدیت</b>\n<pre>{_e(log[-3500:])}</pre>", _update_keyboard()); return
            raise ValueError("عملیات آپدیت نامعتبر است")

        if data.startswith("panellic:"):
            from app.services import license_manager
            action = data.split(":", 1)[1]
            if action == "status":
                result = license_manager.get_status(db, include_queue_details=True)
                _answer(cfg, callback_id); _edit(cfg, callback, f"🔐 <b>وضعیت لایسنس پنل</b>\nوضعیت: <b>{_e(result.get('status'))}</b>\nکد: <code>{_e(result.get('key_masked') or '—')}</code>\nانقضا: <b>{_e(result.get('expires_at') or '—')}</b>", _panel_license_keyboard()); return
            if action in {"activate", "reserve"}:
                _set_state(chat_id, user_id, {"flow": "panel_license_input", "action": action})
                _answer(cfg, callback_id)
                _send(cfg, chat_id, "🔑 کد لایسنس را بنویسید.", _cancel_keyboard(back="menu:panel_license")); return
            raise ValueError("عملیات لایسنس پنل نامعتبر است")

        # Create-user wizard: arbitrary text values are still accepted, while
        # all choices and navigation are exposed as inline buttons.
        if data == "create:auto_username":
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "create" or state.get("step") != "username":
                raise ValueError("مرحله ساخت منقضی شده است")
            state["data"]["username"] = _random_username(db)
            state["step"] = "password"
            _set_state(chat_id, user_id, state)
            _answer(cfg, callback_id, "نام کاربری ساخته شد")
            _edit(cfg, callback, f"👤 نام کاربری خودکار: <code>{_e(state['data']['username'])}</code>\n\n🔑 رمز را بنویسید یا خودکار بسازید.", _cancel_keyboard(random_callback="create:auto_password"))
            return
        if data == "create:auto_password":
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "create" or state.get("step") != "password":
                raise ValueError("مرحله ساخت منقضی شده است")
            state["data"]["password"] = _random_password()
            state["step"] = "quota"
            _set_state(chat_id, user_id, state)
            _answer(cfg, callback_id, "رمز ساخته شد")
            _edit(cfg, callback, f"🔑 رمز خودکار: <code>{_e(state['data']['password'])}</code>\n\n📦 حجم کاربر را انتخاب کنید.", _create_quota_keyboard())
            return
        if data.startswith("create:custom:"):
            step = data.rsplit(":", 1)[1]
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "create" or state.get("step") != step:
                raise ValueError("مرحله ساخت منقضی شده است")
            labels = {"quota": "حجم به گیگ (0 یعنی نامحدود)", "devices": "حداکثر اتصال هم‌زمان (0 یعنی نامحدود)", "days": "تعداد روز (0 یعنی بدون انقضا)"}
            _answer(cfg, callback_id)
            _send(cfg, chat_id, f"✍️ {labels[step]} را بنویسید.", _cancel_keyboard())
            return
        if data.startswith("create:quota:") or data.startswith("create:devices:") or data.startswith("create:days:"):
            _, step, raw_value = data.split(":", 2)
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "create" or state.get("step") != step:
                raise ValueError("مرحله ساخت منقضی شده است")
            value = int(raw_value)
            if step == "quota":
                state["data"]["quota_gb"] = value
                state["step"] = "devices"
                text_out, keyboard = "📱 حداکثر تعداد اتصال هم‌زمان را انتخاب کنید.", _create_devices_keyboard()
            elif step == "devices":
                state["data"]["max_devices"] = value
                state["step"] = "days"
                text_out, keyboard = "⏳ مدت اعتبار بعد از اولین اتصال را انتخاب کنید.", _create_days_keyboard()
            else:
                state["data"]["days"] = value
                state["data"]["protocols"] = []
                state["step"] = "protocols_buttons"
                selected_protocols: set[str] = set()
                text_out = _protocol_selector_text(selected_protocols, admin=_actor(db))
                keyboard = _protocol_selector_keyboard(selected_protocols, mode="create", admin=_actor(db))
            _set_state(chat_id, user_id, state)
            _answer(cfg, callback_id)
            _edit(cfg, callback, text_out, keyboard)
            return
        if data.startswith("cproto:"):
            action = data.split(":", 1)[1]
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "create" or state.get("step") != "protocols_buttons":
                raise ValueError("انتخاب پروتکل منقضی شده است")
            admin = _actor(db)
            allowed_protocols = set(_allowed_protocol_keys(admin))
            selected = set(state.get("data", {}).get("protocols") or []) & allowed_protocols
            if action == "all":
                selected = set(allowed_protocols)
            elif action == "none":
                selected = set()
            elif action == "confirm":
                if not selected:
                    raise ValueError("حداقل یک پروتکل را انتخاب کنید")
                state["data"]["protocols"] = sorted(selected)
                state["data"]["targets"] = []
                state["step"] = "targets_buttons"
                _set_state(chat_id, user_id, state)
                _answer(cfg, callback_id, "پروتکل‌ها تأیید شد")
                _edit(cfg, callback, _target_selector_text(db, set(), admin=_actor(db)), _target_selector_keyboard(db, set(), mode="create", admin=_actor(db)))
                return
            elif action in allowed_protocols:
                selected.symmetric_difference_update({action})
            elif action in PROTOCOLS:
                raise ValueError("این گزینه در محدوده دسترسی حساب شما نیست")
            else:
                raise ValueError("دکمه پروتکل نامعتبر است")
            state["data"]["protocols"] = sorted(selected)
            _set_state(chat_id, user_id, state)
            _answer(cfg, callback_id)
            _edit(cfg, callback, _protocol_selector_text(selected, admin=_actor(db)), _protocol_selector_keyboard(selected, mode="create", admin=_actor(db)))
            return
        if data.startswith("ctgt:"):
            action = data.split(":", 1)[1]
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "create" or state.get("step") != "targets_buttons":
                raise ValueError("انتخاب سرور منقضی شده است")
            selected = set(state.get("data", {}).get("targets") or [])
            if action == "all":
                selected = {"all"}
            elif action == "none":
                selected = set()
            elif action == "confirm":
                if not selected:
                    raise ValueError("حداقل یک سرور را انتخاب کنید")
                selected_targets = validate_target_tokens(db, selected, _actor(db))
                state["data"]["targets"] = selected_targets
                state["step"] = "confirm"
                _set_state(chat_id, user_id, state)
                _answer(cfg, callback_id, "سرورها تأیید شد")
                _edit(cfg, callback, _create_summary(state["data"]), _create_confirm_keyboard())
                return
            else:
                if action == "local" or action.startswith("node:"):
                    allowed_targets = {token for token, _ in _target_options(db, _actor(db))}
                    if action not in allowed_targets:
                        raise ValueError("این گزینه در محدوده دسترسی حساب شما نیست")
                    if "all" in selected:
                        selected = set()
                    selected.symmetric_difference_update({action})
                else:
                    raise ValueError("دکمه سرور نامعتبر است")
            state["data"]["targets"] = sorted(selected)
            _set_state(chat_id, user_id, state)
            _answer(cfg, callback_id)
            _edit(cfg, callback, _target_selector_text(db, selected, admin=_actor(db)), _target_selector_keyboard(db, selected, mode="create", admin=_actor(db)))
            return
        if data == "create:edit_protocols":
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "create" or state.get("step") != "confirm":
                raise ValueError("اطلاعات ساخت منقضی شده است")
            state["step"] = "protocols_buttons"
            selected = set(state["data"].get("protocols") or [])
            _set_state(chat_id, user_id, state)
            _answer(cfg, callback_id)
            _edit(cfg, callback, _protocol_selector_text(selected, admin=_actor(db)), _protocol_selector_keyboard(selected, mode="create", admin=_actor(db)))
            return
        if data == "create:edit_targets":
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "create" or state.get("step") != "confirm":
                raise ValueError("اطلاعات ساخت منقضی شده است")
            state["step"] = "targets_buttons"
            selected = set(state["data"].get("targets") or [])
            _set_state(chat_id, user_id, state)
            _answer(cfg, callback_id)
            _edit(cfg, callback, _target_selector_text(db, selected, admin=_actor(db)), _target_selector_keyboard(db, selected, mode="create", admin=_actor(db)))
            return
        if data == "create:confirm":
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "create" or state.get("step") != "confirm":
                raise ValueError("اطلاعات ساخت منقضی شده؛ دوباره از دکمه ساخت کاربر شروع کنید")
            created = _create_user(db, state["data"])
            _set_state(chat_id, user_id, None)
            _answer(cfg, callback_id, "کاربر ساخته شد")
            _remove_keyboard(cfg, callback)
            _send_subscription_package(cfg, chat_id, created, db, created=True)
            return

        # User-edit button flows.
        if data.startswith("quota:"):
            _, mode, raw_id, *rest = data.split(":")
            vpn_user = _bot_user_by_id(db, int(raw_id))
            if not vpn_user:
                raise ValueError("کاربر پیدا نشد")
            if mode in {"customset", "customadd"}:
                _set_state(chat_id, user_id, {"flow": "edit_user", "step": "quota", "mode": "add" if mode == "customadd" else "set", "user_id": vpn_user.id})
                _answer(cfg, callback_id)
                _send(cfg, chat_id, "📦 مقدار حجم را به گیگ بنویسید.", _cancel_keyboard(back=f"usr:{vpn_user.id}:show"))
                return
            value = float(rest[0])
            if mode == "add":
                vpn_user.quota_bytes = max(0, int(vpn_user.quota_bytes or 0) + int(value * GB))
            elif mode == "set":
                vpn_user.quota_bytes = int(value * GB)
            else:
                raise ValueError("عملیات حجم نامعتبر است")
            db.commit()
            sync_all_nodes_async()
            log_event("🤖 تغییر حجم کاربر از ربات", f"👤 کاربر: <code>{vpn_user.username}</code>\n📦 حجم جدید: <b>{vpn_user.quota_bytes / GB:g} GB</b> ({'افزایش' if mode == 'add' else 'تنظیم'})", actor=_actor(db).username)
            _answer(cfg, callback_id, "حجم بروزرسانی شد", alert=True)
            _send(cfg, chat_id, _format_user(vpn_user, db), _user_keyboard(vpn_user, db))
            return
        if data.startswith("devices:"):
            _, mode, raw_id, *rest = data.split(":")
            vpn_user = _bot_user_by_id(db, int(raw_id))
            if not vpn_user:
                raise ValueError("کاربر پیدا نشد")
            if mode == "custom":
                _set_state(chat_id, user_id, {"flow": "edit_user", "step": "devices", "mode": "set", "user_id": vpn_user.id})
                _answer(cfg, callback_id)
                _send(cfg, chat_id, "📱 حداکثر تعداد اتصال هم‌زمان را بنویسید؛ 0 یعنی نامحدود.", _cancel_keyboard(back=f"usr:{vpn_user.id}:show"))
                return
            value = int(rest[0])
            if value < 0 or value > 10000:
                raise ValueError("تعداد اتصال هم‌زمان معتبر نیست")
            vpn_user.max_devices = value
            db.commit()
            _schedule_user_sync(vpn_user, xray=True)
            log_event("🤖 تغییر محدودیت کاربر از ربات", f"👤 کاربر: <code>{vpn_user.username}</code>\n📱 حداکثر اتصال جدید: <b>{'نامحدود' if value == 0 else value}</b>", actor=_actor(db).username)
            _answer(cfg, callback_id, "محدودیت دستگاه بروزرسانی شد", alert=True)
            _send(cfg, chat_id, _format_user(vpn_user, db), _user_keyboard(vpn_user, db))
            return
        if data.startswith("days:"):
            _, mode, raw_id, *rest = data.split(":")
            vpn_user = _bot_user_by_id(db, int(raw_id))
            if not vpn_user:
                raise ValueError("کاربر پیدا نشد")
            if mode in {"customset", "customadd"}:
                _set_state(chat_id, user_id, {"flow": "edit_user", "step": "days", "mode": "add" if mode == "customadd" else "set", "user_id": vpn_user.id})
                _answer(cfg, callback_id)
                _send(cfg, chat_id, "⏳ تعداد روز را بنویسید؛ 0 یعنی بدون انقضا.", _cancel_keyboard(back=f"usr:{vpn_user.id}:show"))
                return
            days_value = int(rest[0])
            _apply_user_days(vpn_user, days_value, add=(mode == "add"))
            db.commit()
            sync_all_nodes_async()
            log_event("🤖 تغییر اعتبار کاربر از ربات", f"👤 کاربر: <code>{vpn_user.username}</code>\n⏳ اعتبار: <b>{days_value} روز</b> ({'افزایش' if mode == 'add' else 'تنظیم'})", actor=_actor(db).username)
            _answer(cfg, callback_id, "اعتبار بروزرسانی شد", alert=True)
            _send(cfg, chat_id, _format_user(vpn_user, db), _user_keyboard(vpn_user, db))
            return
        if data.startswith("eproto:"):
            _, raw_id, action = data.split(":", 2)
            vpn_user = _bot_user_by_id(db, int(raw_id))
            if not vpn_user:
                raise ValueError("کاربر پیدا نشد")
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "edit_protocols" or int(state.get("user_id") or 0) != vpn_user.id:
                selected = {p for p in PROTOCOLS if bool(getattr(vpn_user, f"enable_{p}"))}
                state = {"flow": "edit_protocols", "user_id": vpn_user.id, "protocols": sorted(selected)}
            admin = _actor(db)
            allowed_protocols = set(_allowed_protocol_keys(admin))
            selected = set(state.get("protocols") or []) & allowed_protocols
            if action == "all":
                selected = set(allowed_protocols)
            elif action == "none":
                selected = set()
            elif action == "confirm":
                if not selected:
                    raise ValueError("حداقل یک پروتکل را انتخاب کنید")
                ensure_user_protocols(_actor(db), selected)
                for protocol in allowed_protocols:
                    setattr(vpn_user, f"enable_{protocol}", protocol in selected)
                db.commit()
                _schedule_user_sync(vpn_user, xray=True)
                log_event("🤖 تغییر پروتکل‌های کاربر از ربات", f"👤 کاربر: <code>{vpn_user.username}</code>\n🔌 پروتکل‌های جدید: <b>{', '.join(sorted(selected))}</b>", actor=_actor(db).username)
                _set_state(chat_id, user_id, None)
                _answer(cfg, callback_id, "پروتکل‌ها ذخیره شد", alert=True)
                _edit(cfg, callback, "✅ پروتکل‌های کاربر ذخیره شد.\n\n" + _format_user(vpn_user, db), _user_keyboard(vpn_user, db))
                return
            elif action in allowed_protocols:
                selected.symmetric_difference_update({action})
            elif action in PROTOCOLS:
                raise ValueError("این گزینه در محدوده دسترسی حساب شما نیست")
            else:
                raise ValueError("دکمه پروتکل نامعتبر است")
            state["protocols"] = sorted(selected)
            _set_state(chat_id, user_id, state)
            _answer(cfg, callback_id)
            _edit(cfg, callback, _protocol_selector_text(selected, editing=vpn_user.username, admin=_actor(db)), _protocol_selector_keyboard(selected, mode="edit", user_id=vpn_user.id, admin=_actor(db)))
            return
        if data.startswith("etgt:"):
            _, raw_id, action = data.split(":", 2)
            vpn_user = _bot_user_by_id(db, int(raw_id))
            if not vpn_user:
                raise ValueError("کاربر پیدا نشد")
            state = _get_state(chat_id, user_id)
            if not state or state.get("flow") != "edit_targets" or int(state.get("user_id") or 0) != vpn_user.id:
                selected = set(targets_for_user(vpn_user))
                state = {"flow": "edit_targets", "user_id": vpn_user.id, "targets": sorted(selected)}
            selected = set(state.get("targets") or [])
            if action == "all":
                selected = {"all"}
            elif action == "none":
                selected = set()
            elif action == "confirm":
                if not selected:
                    raise ValueError("حداقل یک سرور را انتخاب کنید")
                normalized = validate_target_tokens(db, selected, _actor(db))
                vpn_user.server_targets = serialize_targets(normalized)
                db.commit()
                sync_all_nodes_async()
                log_event("🤖 تغییر سرورهای کاربر از ربات", f"👤 کاربر: <code>{vpn_user.username}</code>\n🖥 سرورهای جدید: <b>{', '.join(normalized)}</b>", actor=_actor(db).username)
                _set_state(chat_id, user_id, None)
                _answer(cfg, callback_id, "سرورها ذخیره شد", alert=True)
                _edit(cfg, callback, "✅ سرورهای کاربر ذخیره شد.\n\n" + _format_user(vpn_user, db), _user_keyboard(vpn_user, db))
                return
            else:
                if action == "local" or action.startswith("node:"):
                    allowed_targets = {token for token, _ in _target_options(db, _actor(db))}
                    if action not in allowed_targets:
                        raise ValueError("این گزینه در محدوده دسترسی حساب شما نیست")
                    if "all" in selected:
                        selected = set()
                    selected.symmetric_difference_update({action})
                else:
                    raise ValueError("دکمه سرور نامعتبر است")
            state["targets"] = sorted(selected)
            _set_state(chat_id, user_id, state)
            _answer(cfg, callback_id)
            _edit(cfg, callback, _target_selector_text(db, selected, editing=vpn_user.username, admin=_actor(db)), _target_selector_keyboard(db, selected, mode="edit", user_id=vpn_user.id, admin=_actor(db)))
            return
        if data.startswith("onlinecut:"):
            target_id = int(data.split(":", 1)[1])
            closed, warnings = _disconnect_user_everywhere(db, target_id)
            message = f"✅ {closed} اتصال در سرور اصلی و نودها قطع شد."
            if warnings:
                message += "\n⚠️ " + _e(" | ".join(warnings)[:600])
            _answer(cfg, callback_id, f"{closed} اتصال قطع شد", alert=True)
            body, keyboard = _online_users_payload(db)
            _edit(cfg, callback, message + "\n\n" + body, keyboard)
            return
        if data.startswith("usr:"):
            _, raw_id, action = data.split(":", 2)
            vpn_user = _bot_user_by_id(db, int(raw_id))
            if not vpn_user:
                raise ValueError("کاربر پیدا نشد")
            from app.routers import users as users_router
            admin = _actor(db)
            if action == "show":
                _set_state(chat_id, user_id, None)
                _answer(cfg, callback_id)
                _send(cfg, chat_id, _format_user(vpn_user, db), _user_keyboard(vpn_user, db))
                return
            if action == "subscription":
                _set_state(chat_id, user_id, None)
                _answer(cfg, callback_id, "در حال ارسال لینک و QR")
                _send_subscription_package(cfg, chat_id, vpn_user, db)
                return
            if action == "send_config":
                _require_permission(db, "users:subscription")
                _set_state(chat_id, user_id, None)
                _answer(cfg, callback_id, "در حال آماده‌سازی کانفیگ‌ها")
                _send_full_config_package(cfg, chat_id, vpn_user, db)
                return
            if action == "openvpn_files":
                _require_permission(db, "users:subscription")
                if not bool(vpn_user.enable_openvpn):
                    raise ValueError("OpenVPN برای این کاربر غیرفعال است")
                _set_state(chat_id, user_id, None)
                _answer(cfg, callback_id, "در حال آماده‌سازی فایل‌های OpenVPN")
                sent, warnings = _send_openvpn_files(cfg, chat_id, vpn_user, db)
                if warnings:
                    _send_persistent_text(cfg, chat_id, "هشدارهای OpenVPN:\n- " + "\n- ".join(warnings))
                elif sent:
                    _send_persistent_text(cfg, chat_id, f"{sent} فایل OpenVPN برای {vpn_user.username} ارسال شد.")
                return
            if action == "edit_password":
                _set_state(chat_id, user_id, {"flow": "edit_user", "step": "password", "mode": "set", "user_id": vpn_user.id})
                _answer(cfg, callback_id)
                _send(cfg, chat_id, f"🔑 رمز جدید <code>{_e(vpn_user.username)}</code> را بنویسید.", {"inline_keyboard": [
                    [{"text": "🎲 رمز قوی خودکار", "callback_data": f"usr:{vpn_user.id}:random_password"}],
                    [{"text": "🔙 بازگشت", "callback_data": f"usr:{vpn_user.id}:show"}],
                ]})
                return
            if action == "random_password":
                vpn_user.password = _random_password()
                db.commit()
                _schedule_user_sync(vpn_user, xray=False)
                log_event("🤖 تغییر رمز کاربر از ربات", f"👤 کاربر: <code>{vpn_user.username}</code>\n🔑 عملیات: ساخت رمز تصادفی جدید", actor=admin.username)
                _set_state(chat_id, user_id, None)
                _answer(cfg, callback_id, "رمز تغییر کرد", alert=True)
                _send(cfg, chat_id, "✅ رمز جدید ساخته شد.\n\n" + _format_user(vpn_user, db), _user_keyboard(vpn_user, db))
                return
            if action == "edit_quota":
                _answer(cfg, callback_id)
                _send(cfg, chat_id, f"📦 حجم <code>{_e(vpn_user.username)}</code> را تعیین یا افزایش دهید.", _quota_edit_keyboard(vpn_user))
                return
            if action == "edit_devices":
                _answer(cfg, callback_id)
                _send(cfg, chat_id, f"📱 حداکثر اتصال هم‌زمان <code>{_e(vpn_user.username)}</code> را انتخاب کنید.", _devices_edit_keyboard(vpn_user))
                return
            if action == "edit_days":
                _answer(cfg, callback_id)
                _send(cfg, chat_id, f"⏳ اعتبار <code>{_e(vpn_user.username)}</code> را تعیین یا افزایش دهید.", _days_edit_keyboard(vpn_user))
                return
            if action == "edit_protocols":
                selected = {p for p in PROTOCOLS if bool(getattr(vpn_user, f"enable_{p}"))}
                _set_state(chat_id, user_id, {"flow": "edit_protocols", "user_id": vpn_user.id, "protocols": sorted(selected)})
                _answer(cfg, callback_id)
                _send(cfg, chat_id, _protocol_selector_text(selected, editing=vpn_user.username, admin=_actor(db)), _protocol_selector_keyboard(selected, mode="edit", user_id=vpn_user.id, admin=_actor(db)))
                return
            if action == "edit_targets":
                selected = set(targets_for_user(vpn_user))
                _set_state(chat_id, user_id, {"flow": "edit_targets", "user_id": vpn_user.id, "targets": sorted(selected)})
                _answer(cfg, callback_id)
                _send(cfg, chat_id, _target_selector_text(db, selected, editing=vpn_user.username, admin=_actor(db)), _target_selector_keyboard(db, selected, mode="edit", user_id=vpn_user.id, admin=_actor(db)))
                return
            if action == "enable":
                vpn_user.is_active = True
                db.commit()
                users_router._schedule_user_post_update_sync(vpn_user.id, sync_xray=True)
                msg = "کاربر فعال شد"
            elif action == "disable":
                vpn_user.is_active = False
                db.commit()
                users_router._schedule_user_post_update_sync(vpn_user.id, sync_xray=True)
                msg = "کاربر غیرفعال شد"
            elif action == "disconnect":
                result = users_router.disconnect_user(vpn_user.id, db, admin)
                msg = f"{result.get('closed_sessions', 0)} سشن قطع شد"
            elif action == "reset":
                users_router.reset_usage(vpn_user.id, db, admin)
                msg = "حجم صفر شد"
            elif action == "delete":
                _answer(cfg, callback_id)
                _send(cfg, chat_id, f"⚠️ کاربر <code>{_e(vpn_user.username)}</code> حذف شود؟", {"inline_keyboard": [[
                    {"text": "بله، حذف کن", "callback_data": f"usr:{vpn_user.id}:delete_confirm"},
                    {"text": "انصراف", "callback_data": f"usr:{vpn_user.id}:show"},
                ]]})
                return
            elif action == "delete_confirm":
                username = vpn_user.username
                users_router.delete_user(vpn_user.id, db, admin)
                msg = f"کاربر {username} حذف شد"
            else:
                raise ValueError("عملیات کاربر نامعتبر است")
            action_labels = {
                "enable": "فعال‌سازی کاربر",
                "disable": "غیرفعال‌سازی کاربر",
                "disconnect": "قطع همه اتصال‌های فعال",
                "reset": "صفرکردن حجم مصرفی",
                "delete_confirm": "حذف کامل کاربر",
            }
            target_username = username if action == "delete_confirm" else vpn_user.username
            log_event(
                "🤖 عملیات کاربر از ربات",
                f"👤 کاربر: <code>{target_username}</code>\n"
                f"🛠 عملیات: <b>{action_labels.get(action, action)}</b>\n"
                f"📌 نتیجه: {msg}",
                actor=admin.username,
            )
            _answer(cfg, callback_id, msg, alert=True)
            _remove_keyboard(cfg, callback)
            if action == "delete_confirm":
                caption = f"🗑 <b>کاربر {_e(username)} با موفقیت حذف شد.</b>"
                media_result = _send_media(cfg, chat_id, "user_deleted", caption, _menu_keyboard())
                if media_result is None:
                    _send(cfg, chat_id, caption, _menu_keyboard())
            else:
                _send(cfg, chat_id, f"✅ {msg}", _user_keyboard(vpn_user, db))
            return
        if data.startswith("nproto:"):
            _, raw_node_id, key, action = data.split(":", 3)
            msg = _control_node_protocol(db, int(raw_node_id), key, action)
            _answer(cfg, callback_id, re.sub(r"<[^>]+>", "", msg), alert=True)
            body, keyboard = _protocol_server_payload(db, raw_node_id)
            _edit(cfg, callback, body + "\n\n" + _e(msg), keyboard)
            return
        if data.startswith("proto:"):
            _, key, action = data.split(":", 2)
            msg = _control_protocol(db, key, action)
            _answer(cfg, callback_id, re.sub(r"<[^>]+>", "", msg), alert=True)
            body, keyboard = _protocol_server_payload(db, "local")
            _edit(cfg, callback, body + "\n\n" + msg, keyboard)
            return
        raise ValueError("دکمه نامعتبر یا منقضی شده است")
    except Exception as exc:
        logger.exception("Telegram callback failed: %s", data)
        _answer(cfg, callback_id, _public_error(exc)[:180], alert=True)
    finally:
        try:
            db.close()
        except Exception:
            pass


def _handle_message(cfg: dict, update: dict) -> None:
    message = update.get("message") or {}
    chat = message.get("chat") or {}
    user = message.get("from") or {}
    text = str(message.get("text") or "").strip()
    if not text:
        return
    chat_id = chat.get("id")
    user_id = int(user.get("id") or 0)
    if _handle_group_link_message(cfg, chat, user, text):
        return
    if _handle_binding_message(cfg, chat, user, text):
        return

    normalized_text = re.sub(r"\s+", " ", _normalize_digits(text).strip().lower())
    command = normalized_text.split()[0].split("@", 1)[0] if normalized_text.startswith("/") else ""
    ok, reason, chat, user = _authorized(cfg, update)
    if not ok:
        if reason == "telegram_account_unbound":
            if normalized_text in MENU_TEXT_TRIGGERS or command in {"/start", "/menu", "/myid"}:
                _send_binding_required(cfg, chat, user)
            return
        own_private = str(chat.get("type") or "") == "private" and int(chat.get("id") or 0) == int(user.get("id") or 0)
        if own_private or _is_control_chat(cfg, chat.get("id")):
            _send(cfg, chat.get("id"), f"⛔ {_e(reason)}")
        return

    chat_id, user_id = chat.get("id"), int(user.get("id") or 0)
    if normalized_text in MENU_TEXT_TRIGGERS:
        _set_state(chat_id, user_id, None)
        _send_main_menu(cfg, chat_id)
        return
    if command == "/cancel":
        _set_state(chat_id, user_id, None)
        _send(cfg, chat_id, "عملیات لغو شد.", _menu_keyboard())
        return
    if not text.startswith("/") and _wizard_message(cfg, chat_id, user_id, text):
        return
    if command:
        if command in SUPPORTED_COMMANDS:
            _handle_command(cfg, chat_id, user_id, text)
        return
    return


def handle_update(cfg: dict, update: dict) -> None:
    _CURRENT_ADMIN_ID.set(None)
    if update.get("callback_query"):
        _handle_callback(cfg, update)
    elif update.get("message"):
        _handle_message(cfg, update)


def _update_route_key(update: dict) -> str:
    callback = update.get("callback_query") or {}
    message = callback.get("message") or update.get("message") or {}
    chat = message.get("chat") or {}
    chat_id = chat.get("id")
    return str(chat_id) if chat_id is not None else f"update:{update.get('update_id', '')}"


def _is_menu_bootstrap_update(update: dict) -> bool:
    if update.get("callback_query"):
        return False
    message = update.get("message") or {}
    text = str(message.get("text") or "").strip()
    if not text:
        return False
    normalized = re.sub(r"\s+", " ", _normalize_digits(text).strip().lower())
    if normalized in MENU_TEXT_TRIGGERS:
        return True
    command = normalized.split()[0].split("@", 1)[0] if normalized.startswith("/") else ""
    return command in {"/start", "/menu"}


def _update_key_lock(key: str) -> threading.Lock:
    return _UPDATE_ROUTE_LOCKS[hash(str(key)) % len(_UPDATE_ROUTE_LOCKS)]


def _update_worker_loop() -> None:
    while True:
        try:
            cfg, update, key, menu_bootstrap = _UPDATE_QUEUE.get(timeout=1.0)
        except queue.Empty:
            if _STOP.is_set() and _UPDATE_QUEUE.empty():
                return
            continue
        try:
            # Preserve update order inside one control chat while allowing a
            # slow Telegram request in one chat to never freeze every other bot
            # user or the getUpdates long-poll loop.
            with _update_key_lock(key):
                handle_update(cfg, update)
        except Exception:
            logger.exception("Unhandled queued Telegram update failure")
        finally:
            if menu_bootstrap:
                with _MENU_PENDING_LOCK:
                    _MENU_PENDING_KEYS.discard(key)
            _UPDATE_QUEUE.task_done()


def _ensure_update_workers(count: int = 12) -> None:
    with _UPDATE_WORKER_LOCK:
        alive = [worker for worker in _UPDATE_WORKERS if worker.is_alive()]
        _UPDATE_WORKERS[:] = alive
        while len(_UPDATE_WORKERS) < count:
            worker = threading.Thread(
                target=_update_worker_loop,
                name=f"telegram-control-worker-{len(_UPDATE_WORKERS) + 1}",
                daemon=True,
            )
            worker.start()
            _UPDATE_WORKERS.append(worker)


def _enqueue_update(cfg: dict, update: dict) -> None:
    key = _update_route_key(update)
    menu_bootstrap = _is_menu_bootstrap_update(update)
    if menu_bootstrap:
        with _MENU_PENDING_LOCK:
            if key in _MENU_PENDING_KEYS:
                # Repeated "menu/start" messages while the same GIF is already
                # queued are duplicates. Coalescing them prevents a long backlog
                # that used to delay all following inline-button callbacks.
                return
            _MENU_PENDING_KEYS.add(key)

    item = (dict(cfg), dict(update), key, menu_bootstrap)
    try:
        _UPDATE_QUEUE.put(item, timeout=1.0)
    except queue.Full:
        if menu_bootstrap:
            with _MENU_PENDING_LOCK:
                _MENU_PENDING_KEYS.discard(key)
        # Never execute network/database work inside the long-poll thread. A
        # synchronous fallback here was able to freeze getUpdates for minutes.
        logger.warning("Telegram update queue is full; dropping update %s so polling stays alive", update.get("update_id"))


def _poll_loop() -> None:
    current_token = ""
    current_command_signature = ""
    offset: int | None = None
    while not _STOP.is_set():
        db = SessionLocal()
        try:
            cfg = get_telegram_config(db)
        except Exception:
            logger.exception("Unable to load Telegram controller config")
            cfg = {}
        finally:
            db.close()

        token = str(cfg.get("bot_token") or "")
        if not cfg.get("control_enabled") or not token:
            current_token = ""
            current_command_signature = ""
            offset = None
            _STOP.wait(2.0)
            continue

        token_changed = token != current_token
        if token_changed:
            current_token = token
            current_command_signature = ""
            offset = None
            # Long polling and webhooks are mutually exclusive. Drop commands
            # accumulated while the controller was disabled so a restart cannot
            # unexpectedly execute an old destructive action.
            call_telegram_api(token, "deleteWebhook", data={"drop_pending_updates": "true"}, timeout=8, max_attempts=1)

        # The controller is intentionally button-first. Keep only the two
        # bootstrap commands Telegram needs to reopen the inline menu. Reapply
        # them whenever a superadmin changes a visible bot text, not just when
        # the token changes.
        commands = [
            {"command": "start", "description": _customize_text(cfg, "بازکردن منوی دکمه‌ای پنل")[:256]},
            {"command": "menu", "description": _customize_text(cfg, "نمایش دوباره منوی دکمه‌ای")[:256]},
            {"command": "connect", "description": _customize_text(cfg, "اتصال امن این گروه به حساب پنل")[:256]},
        ]
        command_signature = json.dumps(commands, ensure_ascii=False, separators=(",", ":"))
        if command_signature != current_command_signature:
            commands_ok, commands_result = call_telegram_api(
                token, "setMyCommands", data={"commands": command_signature}, timeout=8, max_attempts=1,
            )
            if commands_ok:
                current_command_signature = command_signature
            else:
                logger.warning("Telegram setMyCommands failed: %s", commands_result)

        payload = {"timeout": 25, "allowed_updates": json.dumps(["message", "callback_query"])}
        if offset is not None:
            payload["offset"] = offset
        ok, result = call_telegram_api(token, "getUpdates", data=payload, timeout=35, max_attempts=1)
        if not ok:
            logger.warning("Telegram getUpdates failed: %s", result)
            _STOP.wait(3.0)
            continue
        for update in result or []:
            try:
                offset = max(int(update.get("update_id") or 0) + 1, offset or 0)
                # Reloading config once per poll is enough; this local snapshot
                # keeps authorization consistent throughout a single update.
                _enqueue_update(cfg, update)
            except Exception:
                logger.exception("Unhandled Telegram update failure")


def _start_poll_thread_locked() -> threading.Thread:
    global _THREAD
    if _THREAD and _THREAD.is_alive():
        return _THREAD
    _THREAD = threading.Thread(target=_poll_loop, name="telegram-control-bot", daemon=True)
    _THREAD.start()
    return _THREAD


def _controller_supervisor_loop() -> None:
    while not _STOP.wait(5.0):
        try:
            _ensure_update_workers()
            _ensure_cleanup_worker()
            with _SUPERVISOR_LOCK:
                if not _THREAD or not _THREAD.is_alive():
                    logger.error("Telegram polling thread stopped unexpectedly; restarting it")
                    _start_poll_thread_locked()
        except Exception:
            logger.exception("Telegram controller supervisor recovery failed")


def start_telegram_controller() -> threading.Thread:
    global _SUPERVISOR_THREAD
    _STOP.clear()
    _ensure_update_workers()
    _ensure_cleanup_worker()
    with _SUPERVISOR_LOCK:
        thread = _start_poll_thread_locked()
        if not _SUPERVISOR_THREAD or not _SUPERVISOR_THREAD.is_alive():
            _SUPERVISOR_THREAD = threading.Thread(
                target=_controller_supervisor_loop,
                name="telegram-control-supervisor",
                daemon=True,
            )
            _SUPERVISOR_THREAD.start()
        return thread


def stop_telegram_controller() -> None:
    _STOP.set()
