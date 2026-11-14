"""
اتصال به تلگرام برای دو کار مستقل:
  1) «کانال لاگ»: هر اتفاق داخل پنل (لاگین، ساخت/ویرایش/حذف یوزر و ادمین،
     تغییر تنظیمات، مسدودسازی آی‌پی، وارد/خارج کردن بکاپ و ...) به‌صورت یک
     پیام متنی برای این کانال/چت ارسال می‌شود.
  2) «کانال بکاپ»: هر روز در ساعت انتخاب‌شده‌ی پنل یک فایل بکاپ کامل (همان خروجی
     /api/backup/export?include_settings=true) به‌صورت سند برای این
     کانال/چت ارسال می‌شود - تا اگر سرور از دست رفت، یک نسخه‌ی تازه همیشه
     در تلگرام موجود باشد.

هر دو کاملاً اختیاری‌اند و تا وقتی توکن ربات و chat_id مربوطه تنظیم نشده
باشد، هیچ درخواستی به تلگرام زده نمی‌شود. ارسال پیام‌های لاگ در یک ترد جدا
(fire-and-forget) انجام می‌شود تا کند بودن/در دسترس نبودن تلگرام هیچ‌وقت
باعث کند شدن یا شکست خوردن درخواست‌های اصلی پنل نشود.
"""
import json
import logging
import queue
import socket
import threading
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import Setting
from app.services.jalali_time import format_jalali_datetime, jalali_filename_stamp
from app.services.node_remote import decrypt_password, encrypt_password

logger = logging.getLogger("vpn-panel.telegram")

# اگر به هر دلیلی (مثلاً بعد از آپدیت دستی فایل‌ها بدون اجرای دوباره‌ی
# `pip install -r requirements.txt`) پکیج requests روی سرور نصب نباشد، کل
# بک‌اند نباید بالا نیاید - چون هر router دیگری (auth/users/admins/...) هم
# از این ماژول ایمپورت می‌کند. به‌جای crash کردن کل پنل، فقط قابلیت تلگرام
# غیرفعال می‌ماند و در لاگ سرور یک هشدار واضح ثبت می‌شود.
try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    requests = None
    _REQUESTS_AVAILABLE = False
    logger.warning(
        "پکیج 'requests' نصب نیست - اعلان/بکاپ تلگرام غیرفعال می‌ماند. "
        "برای فعال‌سازی: cd /opt/vpn-panel/backend && source venv/bin/activate && "
        "pip install -r requirements.txt && sudo systemctl restart vpn-panel-api"
    )

TELEGRAM_API = "https://api.telegram.org/bot{token}/{method}"
_REQUEST_TIMEOUT = 15
_DOCUMENT_REQUEST_TIMEOUT = 180

# کلیدهای ذخیره‌شده در جدول settings (همان جدول key/value عمومی پنل)
KEY_BOT_TOKEN = "telegram_bot_token"
KEY_LOG_CHAT_ID = "telegram_log_chat_id"
KEY_LOG_ENABLED = "telegram_log_enabled"
KEY_BACKUP_CHAT_ID = "telegram_backup_chat_id"
KEY_BACKUP_ENABLED = "telegram_backup_enabled"
KEY_BACKUP_INTERVAL_HOURS = "telegram_backup_interval_hours"
KEY_BACKUP_DAILY_HOUR = "telegram_backup_daily_hour"
KEY_BACKUP_LAST_SCHEDULED_DATE = "telegram_backup_last_scheduled_date"
KEY_BACKUP_LAST_SENT_AT = "telegram_backup_last_sent_at"
KEY_BACKUP_LAST_HEALTH_COMPLETE = "telegram_backup_last_health_complete"
KEY_BACKUP_LAST_HEALTH_WARNINGS = "telegram_backup_last_health_warnings"
KEY_BACKUP_SERVER_PASSWORD = "telegram_backup_server_password_enc"
KEY_SYSTEM_TIMEZONE = "system_timezone"
KEY_CONTROL_ENABLED = "telegram_control_enabled"
KEY_CONTROL_CHAT_ID = "telegram_control_chat_id"
KEY_CONTROL_ALLOWED_USER_IDS = "telegram_control_allowed_user_ids"
KEY_MEDIA_MAIN_MENU_PATH = "telegram_media_main_menu_path"
KEY_MEDIA_MAIN_MENU_TYPE = "telegram_media_main_menu_type"
KEY_MEDIA_MAIN_MENU_FILE_ID = "telegram_media_main_menu_file_id"
KEY_MEDIA_MAIN_MENU_FINGERPRINT = "telegram_media_main_menu_fingerprint"
KEY_MEDIA_USER_CREATED_PATH = "telegram_media_user_created_path"
KEY_MEDIA_USER_CREATED_TYPE = "telegram_media_user_created_type"
KEY_MEDIA_USER_CREATED_FILE_ID = "telegram_media_user_created_file_id"
KEY_MEDIA_USER_CREATED_FINGERPRINT = "telegram_media_user_created_fingerprint"
KEY_MEDIA_USER_DELETED_PATH = "telegram_media_user_deleted_path"
KEY_MEDIA_USER_DELETED_TYPE = "telegram_media_user_deleted_type"
KEY_MEDIA_USER_DELETED_FILE_ID = "telegram_media_user_deleted_file_id"
KEY_MEDIA_USER_DELETED_FINGERPRINT = "telegram_media_user_deleted_fingerprint"
KEY_CONTROL_TEXT_OVERRIDES = "telegram_control_text_overrides"

# پیام‌های «اتصال/قطع اتصال کاربر» به‌خاطر تعدادشان می‌توانند کانال لاگ
# اصلی را خیلی زود شلوغ کنند. این دو کلید مستقل از KEY_LOG_ENABLED/
# KEY_LOG_CHAT_ID هستند:
#   - KEY_CONN_LOG_ENABLED: سوییچ روشن/خاموش جدا، فقط برای همین پیام‌ها
#     (پیش‌فرض روشن، یعنی رفتار قبل از این تغییر حفظ می‌شود).
#   - KEY_CONN_LOG_CHAT_ID: اگر خالی باشد، این پیام‌ها همچنان به همان کانال
#     لاگ اصلی (KEY_LOG_CHAT_ID) می‌روند؛ اگر مقدار داشته باشد، این پیام‌ها
#     از کانال لاگ اصلی جدا شده و فقط به این چت/کانال ارسال می‌شوند.
KEY_CONN_LOG_CHAT_ID = "telegram_conn_log_chat_id"
KEY_CONN_LOG_ENABLED = "telegram_conn_log_enabled"

DEFAULT_BACKUP_INTERVAL_HOURS = 6
DEFAULT_BACKUP_DAILY_HOUR = 6

_SEND_PACE_LOCK = threading.Lock()
_LAST_SEND_AT: dict[str, float] = {}
_LAST_CHAT_SEND_AT: dict[tuple[str, str], float] = {}
_MIN_SEND_INTERVAL = 0.04  # 25 sends/sec per bot, below Telegram's global burst ceiling.
_MIN_CHAT_SEND_INTERVAL = 1.05  # Telegram recommends no more than ~1 message/sec per chat.
_RETRYABLE_SEND_METHODS = {
    "sendMessage", "sendPhoto", "sendAnimation", "sendVideo", "sendDocument",
    "sendMediaGroup", "forwardMessage", "copyMessage",
}

# Fire-and-forget Telegram logging used to create one daemon thread per event.
# When Telegram was slow/unreachable, every thread kept a SQLAlchemy session
# alive during retries. Repeated watchdog alerts could therefore exhaust the
# MySQL pool and leave /api/auth/login waiting indefinitely. A bounded queue
# and a single delivery worker make logging strictly non-blocking and keep at
# most one short-lived DB session active while configuration is read.
_LOG_QUEUE: queue.Queue[dict] = queue.Queue(maxsize=512)
_LOG_WORKER_LOCK = threading.Lock()
_LOG_WORKER_STARTED = False
_LOG_DROP_WARN_AT = 0.0
_LOG_SEND_TIMEOUT_SECONDS = 6
_LOG_SEND_MAX_ATTEMPTS = 2


def _get(db: Session, key: str):
    row = db.query(Setting).filter(Setting.key == key).first()
    return row.value if row else None


def _set(db: Session, key: str, value):
    row = db.query(Setting).filter(Setting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(Setting(key=key, value=value))


def _json_list(value) -> list[str]:
    try:
        parsed = json.loads(value or "[]")
    except (TypeError, ValueError):
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item) for item in parsed if str(item).strip()]


def _json_object(value) -> dict:
    try:
        parsed = json.loads(value or "{}")
    except (TypeError, ValueError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    result: dict[str, str] = {}
    for key, item in parsed.items():
        source = str(key or "").strip()
        replacement = str(item or "").strip()
        if source and replacement:
            result[source] = replacement
    return result


def get_telegram_config(db: Session) -> dict:
    backup_server_password = decrypt_password(_get(db, KEY_BACKUP_SERVER_PASSWORD)) or ""
    legacy_interval = int(_get(db, KEY_BACKUP_INTERVAL_HOURS) or DEFAULT_BACKUP_INTERVAL_HOURS)
    daily_hour_raw = _get(db, KEY_BACKUP_DAILY_HOUR)
    try:
        backup_daily_hour = int(daily_hour_raw) if daily_hour_raw not in (None, "") else legacy_interval
    except (TypeError, ValueError):
        backup_daily_hour = DEFAULT_BACKUP_DAILY_HOUR
    backup_daily_hour = max(0, min(23, backup_daily_hour))
    _, backup_timezone = _configured_backup_now(db)
    return {
        "bot_token": _get(db, KEY_BOT_TOKEN) or "",
        "log_chat_id": _get(db, KEY_LOG_CHAT_ID) or "",
        "log_enabled": (_get(db, KEY_LOG_ENABLED) or "0") == "1",
        "conn_log_chat_id": _get(db, KEY_CONN_LOG_CHAT_ID) or "",
        # پیش‌فرض "1" (روشن) تا رفتار نصب‌های قبلی که این کلید را ندارند تغییر نکند.
        "conn_log_enabled": (_get(db, KEY_CONN_LOG_ENABLED) or "1") == "1",
        "backup_chat_id": _get(db, KEY_BACKUP_CHAT_ID) or "",
        "backup_enabled": (_get(db, KEY_BACKUP_ENABLED) or "0") == "1",
        # Kept for compatibility with an old frontend during the one restart
        # in which the backend has already upgraded but the tab has not.
        "backup_interval_hours": backup_daily_hour,
        "backup_daily_hour": backup_daily_hour,
        "backup_timezone": backup_timezone,
        "backup_last_sent_at": _get(db, KEY_BACKUP_LAST_SENT_AT),
        "backup_last_scheduled_date": _get(db, KEY_BACKUP_LAST_SCHEDULED_DATE),
        "backup_last_health_complete": (_get(db, KEY_BACKUP_LAST_HEALTH_COMPLETE) or "1") == "1",
        "backup_last_health_warnings": _json_list(_get(db, KEY_BACKUP_LAST_HEALTH_WARNINGS)),
        # This endpoint is superadmin-only. Returning the decrypted value keeps
        # the field populated after save/reload so the owner can verify what
        # will be added to the Telegram backup caption.
        "backup_server_password": backup_server_password,
        "backup_server_password_configured": bool(backup_server_password),
        "control_enabled": (_get(db, KEY_CONTROL_ENABLED) or "0") == "1",
        "control_chat_id": _get(db, KEY_CONTROL_CHAT_ID) or "",
        "control_allowed_user_ids": _get(db, KEY_CONTROL_ALLOWED_USER_IDS) or "",
        "media_main_menu_path": _get(db, KEY_MEDIA_MAIN_MENU_PATH) or "",
        "media_main_menu_type": _get(db, KEY_MEDIA_MAIN_MENU_TYPE) or "",
        "media_main_menu_file_id": _get(db, KEY_MEDIA_MAIN_MENU_FILE_ID) or "",
        "media_main_menu_fingerprint": _get(db, KEY_MEDIA_MAIN_MENU_FINGERPRINT) or "",
        "media_user_created_path": _get(db, KEY_MEDIA_USER_CREATED_PATH) or "",
        "media_user_created_type": _get(db, KEY_MEDIA_USER_CREATED_TYPE) or "",
        "media_user_created_file_id": _get(db, KEY_MEDIA_USER_CREATED_FILE_ID) or "",
        "media_user_created_fingerprint": _get(db, KEY_MEDIA_USER_CREATED_FINGERPRINT) or "",
        "media_user_deleted_path": _get(db, KEY_MEDIA_USER_DELETED_PATH) or "",
        "media_user_deleted_type": _get(db, KEY_MEDIA_USER_DELETED_TYPE) or "",
        "media_user_deleted_file_id": _get(db, KEY_MEDIA_USER_DELETED_FILE_ID) or "",
        "media_user_deleted_fingerprint": _get(db, KEY_MEDIA_USER_DELETED_FINGERPRINT) or "",
        "control_text_overrides": _json_object(_get(db, KEY_CONTROL_TEXT_OVERRIDES)),
    }


def set_telegram_config(
    db: Session,
    bot_token: str | None = None,
    log_chat_id: str | None = None,
    log_enabled: bool | None = None,
    conn_log_chat_id: str | None = None,
    conn_log_enabled: bool | None = None,
    backup_chat_id: str | None = None,
    backup_enabled: bool | None = None,
    backup_interval_hours: int | None = None,
    backup_daily_hour: int | None = None,
    backup_server_password: str | None = None,
    clear_backup_server_password: bool = False,
    control_enabled: bool | None = None,
    control_chat_id: str | None = None,
    control_allowed_user_ids: str | None = None,
) -> None:
    if bot_token is not None:
        _set(db, KEY_BOT_TOKEN, bot_token.strip())
    if log_chat_id is not None:
        _set(db, KEY_LOG_CHAT_ID, log_chat_id.strip())
    if log_enabled is not None:
        _set(db, KEY_LOG_ENABLED, "1" if log_enabled else "0")
    if conn_log_chat_id is not None:
        _set(db, KEY_CONN_LOG_CHAT_ID, conn_log_chat_id.strip())
    if conn_log_enabled is not None:
        _set(db, KEY_CONN_LOG_ENABLED, "1" if conn_log_enabled else "0")
    if backup_chat_id is not None:
        _set(db, KEY_BACKUP_CHAT_ID, backup_chat_id.strip())
    if backup_enabled is not None:
        _set(db, KEY_BACKUP_ENABLED, "1" if backup_enabled else "0")
    selected_daily_hour = backup_daily_hour
    if selected_daily_hour is None and backup_interval_hours is not None:
        # Compatibility for a tab loaded from the previous build: its old
        # field is interpreted as an hour-of-day, not as an interval.
        selected_daily_hour = backup_interval_hours
    if selected_daily_hour is not None:
        normalized_hour = max(0, min(23, int(selected_daily_hour)))
        _set(db, KEY_BACKUP_DAILY_HOUR, str(normalized_hour))
        _set(db, KEY_BACKUP_INTERVAL_HOURS, str(normalized_hour))
    if control_enabled is not None:
        _set(db, KEY_CONTROL_ENABLED, "1" if control_enabled else "0")
    if control_chat_id is not None:
        _set(db, KEY_CONTROL_CHAT_ID, control_chat_id.strip())
    if control_allowed_user_ids is not None:
        cleaned_ids = ",".join(part.strip() for part in control_allowed_user_ids.replace(";", ",").split(",") if part.strip())
        _set(db, KEY_CONTROL_ALLOWED_USER_IDS, cleaned_ids)
    if clear_backup_server_password:
        _set(db, KEY_BACKUP_SERVER_PASSWORD, "")
    elif backup_server_password is not None and backup_server_password.strip():
        _set(db, KEY_BACKUP_SERVER_PASSWORD, encrypt_password(backup_server_password.strip()) or "")
    db.commit()


# ---------- ارسال خام به API تلگرام ----------
def call_telegram_api(
    bot_token: str,
    method: str,
    data: dict | None = None,
    files: dict | None = None,
    timeout: int = _REQUEST_TIMEOUT,
    max_attempts: int | None = None,
) -> tuple[bool, dict | str]:
    """Call Telegram Bot API and return the decoded result payload.

    Keeping this wrapper public lets the control-bot poller use getUpdates,
    answerCallbackQuery and editMessageReplyMarkup without duplicating token,
    timeout and error handling.
    """
    if not _REQUESTS_AVAILABLE:
        return False, "پکیج 'requests' روی سرور نصب نیست - از راهنمای README برای نصب استفاده کنید"
    if not bot_token:
        return False, "توکن ربات تنظیم نشده"
    url = TELEGRAM_API.format(token=bot_token, method=method)
    default_attempts = 6 if method in _RETRYABLE_SEND_METHODS else (3 if method != "getUpdates" else 1)
    attempts = max(1, int(max_attempts)) if max_attempts is not None else default_attempts
    last_error = "خطای ناشناخته تلگرام"

    def _rewind_uploads() -> None:
        for value in (files or {}).values():
            body = value[1] if isinstance(value, tuple) and len(value) > 1 else value
            if hasattr(body, "seek"):
                try:
                    body.seek(0)
                except (OSError, ValueError):
                    pass

    def _pace_send() -> None:
        if method not in _RETRYABLE_SEND_METHODS:
            return
        chat_id = str((data or {}).get("chat_id") or "").strip()
        chat_key = (bot_token, chat_id) if chat_id else None
        # Do not hold the shared lock while sleeping: unrelated chats can still
        # progress while one busy private/group chat is being rate-limited.
        while True:
            with _SEND_PACE_LOCK:
                now = time.monotonic()
                global_wait = _MIN_SEND_INTERVAL - (now - _LAST_SEND_AT.get(bot_token, 0.0))
                chat_wait = 0.0
                if chat_key is not None:
                    chat_wait = _MIN_CHAT_SEND_INTERVAL - (now - _LAST_CHAT_SEND_AT.get(chat_key, 0.0))
                wait_for = max(global_wait, chat_wait)
                if wait_for <= 0:
                    _LAST_SEND_AT[bot_token] = now
                    if chat_key is not None:
                        _LAST_CHAT_SEND_AT[chat_key] = now
                    # Private bot use can touch thousands of unique chats. Keep
                    # the pacing map bounded so long-running workers do not
                    # slowly consume memory and eventually become unstable.
                    if len(_LAST_CHAT_SEND_AT) > 5000:
                        stale_before = now - 600.0
                        stale_keys = [
                            key for key, sent_at in _LAST_CHAT_SEND_AT.items()
                            if sent_at < stale_before
                        ]
                        for stale_key in stale_keys[:2500]:
                            _LAST_CHAT_SEND_AT.pop(stale_key, None)
                    return
            time.sleep(min(max(wait_for, 0.01), _MIN_CHAT_SEND_INTERVAL))

    for attempt in range(attempts):
        resp = None
        try:
            _pace_send()
            _rewind_uploads()
            resp = requests.post(url, data=data, files=files, timeout=timeout)
            payload = resp.json()
            if payload.get("ok"):
                return True, payload.get("result")

            last_error = payload.get("description") or f"خطای تلگرام (HTTP {resp.status_code})"
            parameters = payload.get("parameters") if isinstance(payload, dict) else None
            try:
                retry_after = int((parameters or {}).get("retry_after") or 0) if isinstance(parameters, dict) else 0
            except (TypeError, ValueError):
                retry_after = 0
            error_code = int(payload.get("error_code") or 0) if isinstance(payload, dict) else 0
            retryable = error_code == 429 or resp.status_code == 429 or resp.status_code >= 500
            if not retryable or attempt >= attempts - 1:
                return False, last_error
            delay = min(30.0, float(retry_after) + 0.25) if retry_after else min(8.0, 0.5 * (2 ** attempt))
            time.sleep(max(0.25, delay))
        except requests.RequestException as exc:
            last_error = f"اتصال به تلگرام ناموفق بود: {exc}"
            if attempt >= attempts - 1:
                return False, last_error
            time.sleep(min(8.0, 0.5 * (2 ** attempt)))
        except ValueError:
            status = getattr(resp, "status_code", "?")
            last_error = f"پاسخ نامعتبر از تلگرام (HTTP {status})"
            if attempt >= attempts - 1 or (isinstance(status, int) and status < 500):
                return False, last_error
            time.sleep(min(8.0, 0.5 * (2 ** attempt)))
    return False, last_error


def _call_telegram(bot_token: str, method: str, data: dict | None = None, files: dict | None = None, timeout: int = _REQUEST_TIMEOUT) -> tuple[bool, str]:
    ok, result = call_telegram_api(bot_token, method, data=data, files=files, timeout=timeout)
    return ok, "ok" if ok else str(result)


def send_text(
    bot_token: str,
    chat_id: str | int,
    text: str,
    reply_markup: dict | None = None,
    reply_to_message_id: int | None = None,
    *,
    timeout: int = _REQUEST_TIMEOUT,
    max_attempts: int | None = None,
) -> tuple[bool, str]:
    # هر پیام تلگرام حداکثر ۴۰۹۶ کاراکتر است؛ برای این‌که یک متن خیلی طولانی
    # (مثلاً یک لاگ خطا با traceback) کل ارسال را fail نکند، بریده می‌شود.
    if len(text) > 4000:
        text = text[:4000] + "\n… (بریده شد)"
    data = {"chat_id": chat_id, "text": text, "parse_mode": "HTML"}
    if reply_markup is not None:
        data["reply_markup"] = json.dumps(reply_markup, ensure_ascii=False, separators=(",", ":"))
    if reply_to_message_id is not None:
        data["reply_to_message_id"] = int(reply_to_message_id)
    ok, result = call_telegram_api(
        bot_token,
        "sendMessage",
        data=data,
        timeout=timeout,
        max_attempts=max_attempts,
    )
    return ok, "ok" if ok else str(result)


def send_document(bot_token: str, chat_id: str, filename: str, content_bytes: bytes, caption: str = "") -> tuple[bool, str]:
    mime = "application/gzip" if filename.endswith(".gz") else "application/json"
    files = {"document": (filename, content_bytes, mime)}
    data = {"chat_id": chat_id, "caption": caption[:1024]}
    # Full cluster backups contain certificates and node-local snapshots; a
    # normal 15-second API timeout can abort a valid upload on a slow uplink.
    return _call_telegram(
        bot_token, "sendDocument", data=data, files=files, timeout=_DOCUMENT_REQUEST_TIMEOUT
    )


# ---------- کانال لاگ ----------
def _format_log_message(event_type: str, text: str, actor: str | None) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    header = f"🛰 <b>{event_type}</b>"
    lines = [header, text]
    if actor:
        lines.append(f"👤 ادمین: <code>{actor}</code>")
    lines.append(f"🕒 {now}")
    return "\n".join(lines)


def send_log_event_now(
    event_type: str,
    text: str,
    actor: str | None = None,
    db: Session | None = None,
    reply_markup: dict | None = None,
) -> tuple[bool, str]:
    """Send one log-channel event synchronously and report delivery status.

    This is reserved for durable workflows such as panel updates where a
    transient Telegram failure must be retried by the scheduler instead of
    being silently lost in a fire-and-forget thread.
    """
    own_db = db is None
    session = db or SessionLocal()
    try:
        cfg = get_telegram_config(session)
        if not cfg["log_enabled"] or not cfg["bot_token"] or not cfg["log_chat_id"]:
            return True, "log channel disabled"
        message = _format_log_message(event_type, text, actor)
        return send_text(
            cfg["bot_token"],
            cfg["log_chat_id"],
            message,
            reply_markup=reply_markup,
        )
    except Exception as exc:
        logger.exception("خطای غیرمنتظره هنگام ارسال همگام لاگ تلگرام")
        return False, str(exc)
    finally:
        if own_db:
            session.close()


def _load_log_delivery(task: dict) -> tuple[dict, str | int | None, dict | None]:
    """Read Telegram routing from DB, then release the connection immediately."""
    session = SessionLocal()
    try:
        cfg = dict(get_telegram_config(session))
    finally:
        session.close()

    kind = str(task.get("kind") or "log")
    if kind == "connection":
        if not cfg.get("conn_log_enabled") or not cfg.get("bot_token"):
            return cfg, None, None
        return cfg, cfg.get("conn_log_chat_id") or cfg.get("log_chat_id"), None

    if not cfg.get("log_enabled") or not cfg.get("bot_token") or not cfg.get("log_chat_id"):
        return cfg, None, None
    # Notifications are informational now; bans are managed in the panel UI.
    return cfg, cfg.get("log_chat_id"), None


def _deliver_queued_log(task: dict) -> None:
    cfg, chat_id, markup = _load_log_delivery(task)
    if not chat_id:
        return
    message = _format_log_message(
        str(task.get("event_type") or "رویداد پنل"),
        str(task.get("text") or ""),
        task.get("actor"),
    )
    ok, err = send_text(
        cfg.get("bot_token") or "",
        chat_id,
        message,
        reply_markup=markup,
        timeout=_LOG_SEND_TIMEOUT_SECONDS,
        max_attempts=_LOG_SEND_MAX_ATTEMPTS,
    )
    if not ok:
        logger.warning("ارسال لاگ تلگرام ناموفق بود: %s", err)


def _log_worker() -> None:
    while True:
        task = _LOG_QUEUE.get()
        try:
            _deliver_queued_log(task)
        except Exception:
            logger.exception("خطای غیرمنتظره در صف ارسال لاگ تلگرام")
        finally:
            _LOG_QUEUE.task_done()


def _ensure_log_worker() -> None:
    global _LOG_WORKER_STARTED
    if _LOG_WORKER_STARTED:
        return
    with _LOG_WORKER_LOCK:
        if _LOG_WORKER_STARTED:
            return
        threading.Thread(target=_log_worker, name="vpn-panel-telegram-log", daemon=True).start()
        _LOG_WORKER_STARTED = True


def _enqueue_log(task: dict) -> None:
    global _LOG_DROP_WARN_AT
    _ensure_log_worker()
    try:
        _LOG_QUEUE.put_nowait(task)
    except queue.Full:
        # Logging must never delay or fail a panel operation. Keep the warning
        # itself rate-limited so a full queue cannot create another log storm.
        now = time.monotonic()
        if now - _LOG_DROP_WARN_AT >= 60:
            _LOG_DROP_WARN_AT = now
            logger.warning("صف لاگ تلگرام پر است؛ یک اعلان کم‌اهمیت حذف شد")


def log_event(
    event_type: str,
    text: str,
    actor: str | None = None,
    db: Session | None = None,
    reply_markup: dict | None = None,
) -> None:
    """Queue one log without sharing the request's SQLAlchemy session."""
    del db  # a request-bound Session must never cross into a background worker
    _enqueue_log({
        "kind": "log",
        "event_type": event_type,
        "text": text,
        "actor": actor,
        "reply_markup": reply_markup,
    })

def log_failed_login(event_type: str, text: str, ip_address: str) -> None:
    _enqueue_log({
        "kind": "failed_login",
        "event_type": event_type,
        "text": text,
        "ip_address": ip_address,
    })


def log_connection_event(event_type: str, text: str, db: Session | None = None) -> None:
    del db
    _enqueue_log({
        "kind": "connection",
        "event_type": event_type,
        "text": text,
    })


def _configured_backup_now(db: Session) -> tuple[datetime, str]:
    """Return the current time in the timezone selected inside the panel.

    The backup worker must not trust the process-local timezone because a
    long-running process can retain an older TZ after the host timezone is
    changed. Reading the persisted panel setting keeps Telegram captions and
    filenames identical to the server-time card.
    """
    timezone_name = str(_get(db, KEY_SYSTEM_TIMEZONE) or "").strip()
    if not timezone_name:
        try:
            from app.services.system_time import current_timezone
            timezone_name = str(current_timezone() or "").strip()
        except Exception:
            timezone_name = ""

    if timezone_name:
        try:
            return datetime.now(ZoneInfo(timezone_name)), timezone_name
        except (ZoneInfoNotFoundError, ValueError):
            logger.warning("منطقه زمانی ذخیره‌شده برای بکاپ معتبر نیست: %s", timezone_name)

    fallback = datetime.now().astimezone()
    fallback_name = getattr(fallback.tzinfo, "key", None) or str(fallback.tzinfo or "UTC")
    return fallback, fallback_name


# ---------- کانال بکاپ ----------
def send_backup_to_telegram(db: Session | None = None, manual: bool = False) -> tuple[bool, str]:
    """یک بکاپ کامل (شامل تنظیمات) می‌سازد و به کانال بکاپ تلگرام می‌فرستد.
    از build_full_backup_payload در backup.py استفاده می‌کند تا دقیقاً همان
    فرمتی که از صفحه‌ی «بکاپ کامل» دانلود می‌شود تولید شود."""
    # ایمپورت داخل تابع برای جلوگیری از import چرخه‌ای (backup.py هم از این
    # ماژول برای اعلان استفاده می‌کند).
    from app.routers.backup import build_full_backup_payload

    own_db = db is None
    session = db or SessionLocal()
    try:
        cfg = get_telegram_config(session)
        if not cfg["bot_token"] or not cfg["backup_chat_id"]:
            return False, "توکن ربات یا آیدی کانال بکاپ تنظیم نشده"

        from app.services.backup_codec import encode_json_backup
        data = build_full_backup_payload(session, include_cluster_nodes=True)
        content = encode_json_backup(data)
        now_local, backup_timezone = _configured_backup_now(session)
        filename = f"vpn-panel-backup-{jalali_filename_stamp(now_local)}.json.gz"
        health = data.get("backup_health") or {}
        backup_complete = bool(health.get("complete", True))
        backup_warnings = [str(item).strip() for item in (health.get("warnings") or []) if str(item).strip()]
        backup_repairs = [str(item).strip() for item in (health.get("repairs") or []) if str(item).strip()]
        node_summary = data.get("node_backup_summary") or {}
        _set(session, KEY_BACKUP_LAST_HEALTH_COMPLETE, "1" if backup_complete else "0")
        _set(session, KEY_BACKUP_LAST_HEALTH_WARNINGS, json.dumps(backup_warnings, ensure_ascii=False))
        session.commit()
        caption_lines = [
            "📦 بکاپ دستی پنل" if manual else "📦 بکاپ خودکار دوره‌ای پنل",
            f"🗓 تاریخ شمسی: {format_jalali_datetime(now_local)}",
            f"🌐 منطقه زمانی: {backup_timezone}",
            f"🖥 سرور: {socket.gethostname()}",
        ]
        # The owner explicitly controls this optional value from the
        # superadmin-only Telegram settings page. Linux cannot reveal the
        # current plaintext root password, so it must be entered once there.
        # Keep it near the top of the caption so Telegram's 1024-char caption
        # limit cannot trim it after long health warnings.
        server_password = " ".join(str(cfg.get("backup_server_password") or "").split())
        if server_password:
            caption_lines.append(f"🔑 رمز root سرور: {server_password[:512]}")
        caption_lines.extend([
            f"ادمین‌ها: {len(data.get('admins', []))} | یوزرها: {len(data.get('vpn_users', []))}",
            f"🧩 بکاپ نودها: {int(node_summary.get('collected') or 0)} از {int(node_summary.get('registered') or 0)} نود ثبت‌شده",
            "✅ سلامت بکاپ: کامل، فشرده و قابل بازیابی مستقیم" if backup_complete
            else "⚠️ سلامت بکاپ: ناقص/کاهش‌یافته است؛ بخشی از اطلاعات بازیابی کامل نیست",
            "📄 قالب فایل: JSON فشرده‌شده با Gzip، بدون رمزگذاری و بدون کلید بازیابی",
        ])
        if backup_repairs:
            caption_lines.append(f"🛠 ترمیم خودکار قبل از بکاپ: {len(backup_repairs)} مورد")
        if not backup_complete:
            for warning in backup_warnings[:2]:
                compact = " ".join(warning.split())
                caption_lines.append(f"• {compact[:190]}{'…' if len(compact) > 190 else ''}")
            if len(backup_warnings) > 2:
                caption_lines.append(f"• و {len(backup_warnings) - 2} هشدار دیگر داخل فایل بکاپ")
        caption = "\n".join(caption_lines)
        ok, err = send_document(cfg["bot_token"], cfg["backup_chat_id"], filename, content, caption)
        if ok:
            _set(session, KEY_BACKUP_LAST_SENT_AT, datetime.utcnow().isoformat())
            if not manual:
                _set(session, KEY_BACKUP_LAST_SCHEDULED_DATE, now_local.date().isoformat())
            session.commit()
        return ok, err
    finally:
        if own_db:
            session.close()


def maybe_send_scheduled_backup() -> None:
    """Send one automatic backup per panel-local day at the selected hour.

    The job itself runs once a minute so changing the hour or timezone in the
    panel takes effect without restarting the API. If the API was briefly down
    at HH:00, the first check later in that same hour/day still sends the
    missed backup exactly once.
    """
    db = SessionLocal()
    try:
        cfg = get_telegram_config(db)
        if not cfg["backup_enabled"] or not cfg["bot_token"] or not cfg["backup_chat_id"]:
            return

        now_local, _ = _configured_backup_now(db)
        daily_hour = max(0, min(23, int(cfg.get("backup_daily_hour", DEFAULT_BACKUP_DAILY_HOUR))))
        if now_local.hour < daily_hour:
            return

        today = now_local.date().isoformat()
        if str(cfg.get("backup_last_scheduled_date") or "") == today:
            return

        # Migration guard: before v2.3.245 there was no scheduled-date key.
        # If a backup already went out today at/after the configured hour,
        # do not duplicate it during the first minute after upgrading.
        last_sent = cfg.get("backup_last_sent_at")
        if not cfg.get("backup_last_scheduled_date") and last_sent:
            try:
                last_dt = datetime.fromisoformat(str(last_sent).replace("Z", "+00:00"))
                if last_dt.tzinfo is None:
                    last_dt = last_dt.replace(tzinfo=timezone.utc)
                last_local = last_dt.astimezone(now_local.tzinfo)
            except (TypeError, ValueError):
                last_dt = None
                last_local = None
            if last_local is not None and last_local.date() == now_local.date() and last_local.hour >= daily_hour:
                _set(db, KEY_BACKUP_LAST_SCHEDULED_DATE, today)
                db.commit()
                return

        ok, err = send_backup_to_telegram(db=db, manual=False)
        if not ok:
            logger.warning("ارسال خودکار بکاپ به تلگرام ناموفق بود: %s", err)
    except Exception:
        logger.exception("خطای غیرمنتظره در job بکاپ خودکار تلگرام")
    finally:
        db.close()
