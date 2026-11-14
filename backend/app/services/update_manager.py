"""
آپدیت پنل از طریق پنل لایسنس (دکمه‌ی «آپدیت» در صفحه‌ی بکاپ).

منطق کلی:
- پنل لایسنس یک پکیج zip از کل پروژه (backend + frontend + install/*.sh) به
  همراه یک شماره‌ی ورژن نگه می‌دارد (همان مکانیزمی که نصب یک‌خطی از آن استفاده
  می‌کند - /api/updates/latest و /api/updates/download - اما این‌بار برای یک
  پنل از قبل نصب‌شده، نه نصب تازه).
- اجرای واقعی آپدیت با اسکریپت install/update_from_license.sh انجام می‌شود که
  پکیج را دانلود، استخراج و install/update.sh را روی آن اجرا می‌کند - یعنی
  دقیقاً همان مسیر امنی که آپدیت دستی از قبل استفاده می‌کرد (دیتابیس،
  سرتیفیکیت‌های OpenVPN، PSK مشترک L2TP/IPsec، دامنه/SSL و تمام تنظیمات دیگر
  دست‌نخورده می‌مانند).
- این اسکریپت با systemd-run به‌عنوان یک واحد systemd کاملاً جدا و مستقل
  (vpn-panel-update) اجرا می‌شود - نه به‌عنوان زیرپردازه‌ی مستقیم uvicorn.
  دلیل: خودِ update.sh در میانه‌ی کار «systemctl stop vpn-panel-api» را صدا
  می‌زند تا بک‌اند جدید را جایگزین کند؛ اگر اسکریپت آپدیت زیرپردازه‌ی مستقیم
  همین سرویس بود، آن دستور stop می‌توانست کل درخت پردازه (شامل خودِ اسکریپت
  در حال آپدیت) را هم بکشد و آپدیت نصفه بماند. با systemd-run، آپدیت در
  cgroup/واحد systemd کاملاً جدای خودش اجرا می‌شود و از قطع/ری‌استارت
  vpn-panel-api در امان است.
- پیشرفت (درصد) در فایل update-progress.json نوشته می‌شود که خودِ این ماژول
  می‌خواند و به فرانت‌اند برمی‌گرداند. در بازه‌ای که خودِ بک‌اند پایین است
  (چند ده ثانیه، حین اجرای update.sh)، درخواست‌های فرانت‌اند به این endpoint
  طبیعتاً fail می‌شوند - فرانت‌اند این حالت را جدا از «آپدیت شکست خورد» در نظر
  می‌گیرد و به تلاش دوباره ادامه می‌دهد تا بک‌اند بالا بیاید.
"""

import html
import json
import os
import subprocess
import uuid
import shutil
import re
from datetime import datetime, timezone
from pathlib import Path

import requests
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.config import get_settings
from app.services.license_manager import get_license_key

settings = get_settings()

INSTALL_DIR = Path("/opt/vpn-panel")
VERSION_FILE = INSTALL_DIR / "VERSION"
PROGRESS_FILE = INSTALL_DIR / "update-progress.json"
UPDATE_SCRIPT = INSTALL_DIR / "scripts" / "update_from_license.sh"
UPDATE_LOG_FILE = INSTALL_DIR / "update.log"
TELEGRAM_WATCH_FILE = INSTALL_DIR / "update-telegram-watch.json"
UPDATE_NOTIFY_FILE = INSTALL_DIR / "update-notification-state.json"
UPDATE_ENV_DIR = Path("/run/vpn-panel")
UNIT_PREFIX = "vpn-panel-update"
LAST_APPLIED_PACKAGE_SHA_FILE = INSTALL_DIR / ".last-applied-package.sha256"
BACKEND_MAIN_FILE = INSTALL_DIR / "backend" / "app" / "main.py"
FRONTEND_INDEX_FILE = INSTALL_DIR / "frontend" / "dist" / "index.html"
PANEL_VERSION_PATTERN = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
BACKEND_CODE_VERSION_PATTERN = re.compile(r'FastAPI\([^\n]*?version=["\']([^"\']+)["\']')
FRONTEND_CODE_VERSION_PATTERN = re.compile(r'<meta\s+name=["\']vpn-panel-ui-version["\']\s+content=["\']([^"\']+)["\']', re.IGNORECASE)


def _read_log(max_chars: int = 30000) -> str:
    try:
        content = UPDATE_LOG_FILE.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    return content[-max_chars:]


def get_log() -> dict:
    """Return the complete update console output, capped to protect the API."""
    return {"log": _read_log(1_000_000), "path": str(UPDATE_LOG_FILE)}


def get_current_version() -> str | None:
    try:
        v = VERSION_FILE.read_text(encoding="utf-8").strip()
        return v or None
    except OSError:
        return None


def get_installed_code_version() -> str | None:
    """Read the immutable build version embedded in the installed code.

    ``/opt/vpn-panel/VERSION`` is the owner-controlled display label and may be
    synchronized from the license console.  The backend/frontend build marker
    remains tied to the actual ZIP contents, so it can bootstrap package
    identity on installations created before the SHA marker existed.
    """
    try:
        source = BACKEND_MAIN_FILE.read_text(encoding="utf-8", errors="replace")
        match = BACKEND_CODE_VERSION_PATTERN.search(source)
        if match:
            normalized = _normalize_panel_version(match.group(1))
            if normalized:
                return normalized
    except OSError:
        pass
    try:
        source = FRONTEND_INDEX_FILE.read_text(encoding="utf-8", errors="replace")
        match = FRONTEND_CODE_VERSION_PATTERN.search(source)
        if match:
            return _normalize_panel_version(match.group(1))
    except OSError:
        pass
    return None


def _write_current_version(version: str) -> None:
    normalized = _normalize_panel_version(version)
    if not normalized:
        return
    VERSION_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = VERSION_FILE.with_name(f"{VERSION_FILE.name}.tmp.{os.getpid()}")
    tmp.write_text(normalized + "\n", encoding="utf-8")
    os.chmod(tmp, 0o644)
    os.replace(tmp, VERSION_FILE)


def _normalize_panel_version(value: object) -> str | None:
    version = str(value or "").strip()
    return version if PANEL_VERSION_PATTERN.fullmatch(version) else None


def _numeric_version_parts(value: object) -> tuple[int, ...] | None:
    """Return comparable numeric parts for ordinary release labels.

    The license console intentionally accepts short labels such as ``2.7`` as
    well as build labels such as ``2.3.243``.  Treat trailing zero components
    as equivalent, so ``2.7`` and ``2.7.0`` do not create a fake update.
    """
    version = _normalize_panel_version(value)
    if not version or not re.fullmatch(r"[vV]?\d+(?:\.\d+)*", version):
        return None
    parts = [int(part) for part in version.lstrip("vV").split(".")]
    while len(parts) > 1 and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def is_published_version_newer(latest: object, current: object) -> bool:
    """Return whether the published label is newer than the installed label.

    Numeric labels are ordered component-by-component.  For custom labels that
    cannot be ordered safely, a different label is treated as a new release,
    while an identical label is never considered an update.
    """
    latest_version = _normalize_panel_version(latest)
    current_version = _normalize_panel_version(current)
    if not latest_version or not current_version or latest_version == current_version:
        return False
    latest_parts = _numeric_version_parts(latest_version)
    current_parts = _numeric_version_parts(current_version)
    if latest_parts is not None and current_parts is not None:
        return latest_parts > current_parts
    return latest_version != current_version


def _normalize_sha256(value: object) -> str | None:
    digest = str(value or "").strip().lower()
    return digest if SHA256_PATTERN.fullmatch(digest) else None


def get_last_applied_package_sha256() -> str | None:
    try:
        return _normalize_sha256(LAST_APPLIED_PACKAGE_SHA_FILE.read_text(encoding="utf-8"))
    except OSError:
        return None


def _remember_applied_package_sha256(digest: str) -> None:
    normalized = _normalize_sha256(digest)
    if not normalized:
        return
    LAST_APPLIED_PACKAGE_SHA_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = LAST_APPLIED_PACKAGE_SHA_FILE.with_name(f"{LAST_APPLIED_PACKAGE_SHA_FILE.name}.tmp.{os.getpid()}")
    tmp.write_text(normalized + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, LAST_APPLIED_PACKAGE_SHA_FILE)


def sync_published_release_label(version: object, sha256: object = None) -> dict:
    """Persist the license-console display label on this server.

    Package identity remains SHA-256 based. This helper is used by a
    controller to synchronize a managed node after it proves that the node has
    the same package bytes as the currently published release.
    """
    normalized_version = _normalize_panel_version(version)
    if not normalized_version:
        raise ValueError("invalid published version label")
    _write_current_version(normalized_version)
    normalized_sha = _normalize_sha256(sha256)
    if normalized_sha:
        _remember_applied_package_sha256(normalized_sha)
    return {
        "ok": True,
        "current_version": normalized_version,
        "installed_sha256": normalized_sha or get_last_applied_package_sha256(),
    }


def _read_json_file(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError, TypeError):
        return {}


def _atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    os.replace(tmp, path)


def _write_update_environment(run_id: str, values: dict[str, str]) -> Path:
    """Write update secrets to a root-only EnvironmentFile, never argv."""
    UPDATE_ENV_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(UPDATE_ENV_DIR, 0o700)
    path = UPDATE_ENV_DIR / f"update-{run_id}.env"
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}")
    lines = []
    for name, raw_value in values.items():
        value = str(raw_value)
        if "\x00" in value or "\n" in value or "\r" in value:
            raise ValueError(f"Invalid update environment value: {name}")
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'{name}="{escaped}"')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
        os.replace(tmp, path)
    except Exception:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise
    return path


def register_telegram_watch(chat_id: int | str, message_id: int, actor: str | None = None) -> None:
    """Persist the Telegram message that should show live update progress.

    The file lives outside the deployed code tree, so the watcher survives the
    API restart that happens halfway through an update. The scheduler resumes
    editing the same message as soon as the new API process is healthy.
    """
    status = get_status()
    payload = {
        "chat_id": str(chat_id),
        "message_id": int(message_id),
        "actor": str(actor or "").strip() or None,
        "run_id": status.get("run_id"),
        "last_signature": "",
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }
    _atomic_write_json(TELEGRAM_WATCH_FILE, payload)


def _update_keyboard_for_state(state: str) -> dict:
    rows: list[list[dict[str, str]]] = []
    if state not in {"running"}:
        rows.append([{
            "text": "🔎 بررسی نسخه جدید",
            "callback_data": "update:check",
        }])
    rows.append([{
        "text": "🧾 آخرین لاگ آپدیت",
        "callback_data": "update:log",
    }])
    rows.append([{
        "text": "🏠 منوی اصلی",
        "callback_data": "menu:home",
    }])
    return {"inline_keyboard": rows}


def _status_text(status: dict) -> str:
    state = str(status.get("state") or "idle")
    labels = {
        "idle": "آماده",
        "running": "در حال اجرا",
        "success": "موفق",
        "failed": "ناموفق",
    }
    icon = {"running": "🔄", "success": "✅", "failed": "❌"}.get(state, "📊")
    percent = max(0, min(100, int(status.get("percent") or 0)))
    message = html.escape(str(status.get("message") or ""))
    version = html.escape(str(status.get("current_version") or "—"))
    lines = [
        f"{icon} <b>وضعیت آپدیت</b>",
        f"درصد: <b>{percent}%</b>",
        f"وضعیت: <b>{labels.get(state, html.escape(state))}</b>",
        f"نسخه پنل: <code>{version}</code>",
    ]
    if message:
        lines.append(message)
    if state == "running":
        lines.append("این پیام خودکار به‌روزرسانی می‌شود؛ نیازی به زدن دوباره دکمه وضعیت نیست.")
    return "\n".join(lines)


def process_update_notifications(db: Session) -> dict:
    """Edit the tracked Telegram progress message and emit one terminal log.

    This function is intentionally cheap and idempotent. It is called by a
    two-second scheduler job and can safely run before, during, and after API
    restarts.
    """
    status = get_status()
    state = str(status.get("state") or "idle")
    run_id = str(status.get("run_id") or "").strip()

    watch = _read_json_file(TELEGRAM_WATCH_FILE)
    if watch and state in {"running", "success", "failed"}:
        watch_run = str(watch.get("run_id") or "").strip()
        # A watch created just before the runner wrote its first status may not
        # yet have a run id. Bind it once, but never let an old watch attach to
        # a later update.
        if not watch_run and run_id:
            watch["run_id"] = run_id
            watch_run = run_id
        if not watch_run or not run_id or watch_run == run_id:
            signature = f"{run_id}:{state}:{status.get('percent', 0)}:{status.get('message', '')}"
            if signature != str(watch.get("last_signature") or ""):
                try:
                    from app.services.telegram_notifier import call_telegram_api, get_telegram_config
                    cfg = get_telegram_config(db)
                    if cfg.get("bot_token") and watch.get("chat_id") and watch.get("message_id"):
                        payload = {
                            "chat_id": watch["chat_id"],
                            "message_id": int(watch["message_id"]),
                            "text": _status_text(status),
                            "parse_mode": "HTML",
                            "disable_web_page_preview": "true",
                            "reply_markup": json.dumps(_update_keyboard_for_state(state), ensure_ascii=False, separators=(",", ":")),
                        }
                        ok, result = call_telegram_api(
                            cfg["bot_token"], "editMessageText", data=payload, timeout=8, max_attempts=2
                        )
                        # "message is not modified" is harmless; any other hard
                        # failure is kept for the next scheduler tick.
                        if ok or "message is not modified" in str(result).lower():
                            watch["last_signature"] = signature
                            watch["updated_at"] = datetime.now(timezone.utc).isoformat()
                            _atomic_write_json(TELEGRAM_WATCH_FILE, watch)
                except Exception:
                    # Notification failures must never affect the update itself.
                    pass

    # A run_id is mandatory for terminal logging. This prevents a stale success
    # file left by an old release from generating a fake completion alert at
    # every API startup.
    if state in {"success", "failed"} and run_id:
        terminal_key = f"{run_id}:{state}"
        notified = _read_json_file(UPDATE_NOTIFY_FILE)
        if str(notified.get("terminal_key") or "") != terminal_key:
            try:
                from app.services.telegram_notifier import send_log_event_now
                tail = _read_log(5000)
                if state == "success":
                    event = "✅ آپدیت پنل با موفقیت تمام شد"
                    detail = (
                        f"نسخه فعال: {status.get('current_version') or 'نامشخص'}\n"
                        f"نتیجه: {status.get('message') or 'آپدیت با موفقیت تکمیل شد.'}"
                    )
                else:
                    event = "❌ آپدیت پنل ناموفق بود"
                    last_lines = "\n".join([line for line in tail.splitlines() if line.strip()][-8:])
                    detail = (
                        f"خطا: {status.get('message') or 'خطای نامشخص'}"
                        + (f"\nانتهای لاگ:\n{last_lines}" if last_lines else "")
                    )
                watch_actor = None
                if watch and str(watch.get("run_id") or "").strip() == run_id:
                    watch_actor = watch.get("actor")
                delivered, delivery_error = send_log_event_now(
                    event,
                    detail,
                    actor=watch_actor,
                    db=db,
                )
                # Persist the terminal key only after Telegram accepted the
                # message (or the log channel is intentionally disabled). A
                # transient network/429 failure is retried on the next tick.
                if delivered:
                    _atomic_write_json(UPDATE_NOTIFY_FILE, {
                        "terminal_key": terminal_key,
                        "state": state,
                        "run_id": run_id,
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                    })
                else:
                    return {**status, "notification_error": str(delivery_error)}
            except Exception:
                pass
    return status


def _require_license_configured(db: Session) -> str:
    if not settings.LICENSE_SERVER_URL or not settings.LICENSE_API_KEY:
        raise HTTPException(400, "سرویس آپدیت روی این پنل تنظیم نشده است.")
    key = get_license_key(db)
    if not key:
        raise HTTPException(400, "هنوز هیچ کد لایسنسی روی این پنل فعال نشده است.")
    return key


def check_latest(db: Session) -> dict:
    """Fetch the license-console release without mutating installed metadata.

    The license-console version is a display label and can be changed
    independently from the ZIP build version.  The published ZIP SHA-256 is
    therefore the primary update signal whenever both sides have it.  This
    prevents labels such as ``3.6`` (installed) and ``2.3`` (published) from
    incorrectly hiding a genuinely different package.  Merely checking for an
    update must never rewrite ``VERSION``; that file changes only after a
    successful install.
    """
    key = _require_license_configured(db)
    url = settings.LICENSE_SERVER_URL.rstrip("/") + "/api/updates/latest"
    try:
        r = requests.get(
            url,
            params={"key": key},
            headers={"x-api-key": settings.LICENSE_API_KEY},
            timeout=10,
        )
    except requests.RequestException:
        raise HTTPException(502, "ارتباط با سرویس آپدیت برقرار نشد.")

    if r.status_code == 404:
        raise HTTPException(404, "هنوز هیچ نسخه‌ی جدیدی برای آپدیت منتشر نشده است.")
    if r.status_code in (401, 403):
        raise HTTPException(403, "این پنل مجاز به دریافت آپدیت نیست (لایسنس نامعتبر یا کلید API نادرست).")
    if not r.ok:
        raise HTTPException(502, "بررسی آپدیت با خطا مواجه شد.")

    try:
        latest = r.json()
    except ValueError:
        raise HTTPException(502, "پاسخ نامعتبر از سرویس آپدیت.")

    current_raw = get_current_version()
    current = _normalize_panel_version(current_raw) or current_raw
    installed_code_version = get_installed_code_version()
    reported_version = str(latest.get("version") or "").strip() or None
    latest_version = _normalize_panel_version(reported_version)
    package_version = _normalize_panel_version(
        latest.get("package_version") or latest.get("archive_version")
    )
    latest_sha256 = _normalize_sha256(latest.get("sha256"))
    installed_sha256 = get_last_applied_package_sha256()

    comparison_basis = "none"
    if latest_sha256 and installed_sha256:
        update_available = latest_sha256 != installed_sha256
        comparison_basis = "package-sha256"
    elif package_version and installed_code_version:
        update_available = package_version != installed_code_version
        comparison_basis = "package-version"
    elif latest_version and current:
        update_available = is_published_version_newer(latest_version, current)
        comparison_basis = "license-version-fallback"
    elif latest_version and installed_code_version:
        update_available = is_published_version_newer(latest_version, installed_code_version)
        comparison_basis = "license-version-vs-code-fallback"
    elif latest_version:
        # No installed version metadata exists. Offer the valid published
        # release once so a successful install can establish the baseline.
        update_available = True
        comparison_basis = "license-version-unbound"
    elif latest_sha256:
        update_available = True
        comparison_basis = "sha256-unbound-fallback"
    else:
        update_available = False

    return {
        "current_version": current,
        "latest_version": latest_version or current,
        "reported_version": reported_version,
        "package_version": package_version,
        "installed_code_version": installed_code_version,
        "update_available": update_available,
        "comparison_basis": comparison_basis,
        "latest_sha256": latest_sha256,
        "installed_sha256": installed_sha256,
        "notes": latest.get("notes"),
        "published_at": latest.get("published_at"),
        "size_bytes": latest.get("size_bytes"),
    }


def _unit_active(unit_name: str | None = None) -> bool:
    if not unit_name:
        progress = _read_json_file(PROGRESS_FILE)
        unit_name = str(progress.get("unit_name") or "").strip()
    if not unit_name:
        unit_name = f"{UNIT_PREFIX}.service"
    r = subprocess.run(
        ["systemctl", "is-active", unit_name],
        capture_output=True, text=True,
    )
    return r.stdout.strip() in {"active", "activating", "reloading"}


def _launch_update_unit(cmd: list[str]) -> subprocess.CompletedProcess:
    """Start the detached updater with compatibility fallbacks.

    Some supported distributions ship a systemd-run that does not understand
    ``--collect``. Try the leak-free modern form first and retry without only
    for that exact option error. The caller uses a unique unit name per run, so
    stale transient units can never block a later update with "unit exists".
    """
    result = subprocess.run(cmd, capture_output=True, text=True)
    combined = f"{result.stdout}\n{result.stderr}".lower()
    if result.returncode != 0 and "--collect" in combined and any(
        marker in combined for marker in ("unrecognized option", "unknown option", "invalid option")
    ):
        result = subprocess.run([part for part in cmd if part != "--collect"], capture_output=True, text=True)
    return result


def start_update(db: Session) -> dict:
    key = _require_license_configured(db)

    latest = check_latest(db)
    if not latest.get("update_available"):
        raise HTTPException(
            400,
            f"این سرور همین الان نسخه‌ی {latest.get('current_version') or 'فعلی'} را دارد که آخرین نسخه‌ی موجود است؛ نیازی به آپدیت نیست.",
        )

    if not UPDATE_SCRIPT.exists():
        raise HTTPException(
            500,
            "اسکریپت آپدیت روی این سرور پیدا نشد "
            f"({UPDATE_SCRIPT}). یک‌بار آپدیت دستی (sudo bash install/update.sh) لازم است تا این اسکریپت مستقر شود.",
        )
    if not shutil.which("systemd-run"):
        raise HTTPException(500, "ابزار systemd-run روی سرور پیدا نشد و آپدیت امن قابل اجرا نیست.")
    syntax = subprocess.run(["/bin/bash", "-n", str(UPDATE_SCRIPT)], capture_output=True, text=True)
    if syntax.returncode != 0:
        detail = syntax.stderr.strip()[:500] or "ساختار اسکریپت نامعتبر است"
        raise HTTPException(500, f"اسکریپت آپدیت خراب است: {detail}")

    current_progress = _read_json_file(PROGRESS_FILE)
    active_unit = str(current_progress.get("unit_name") or "").strip()
    if _unit_active(active_unit):
        # Idempotent start: callers (including the controller's node console)
        # may retry while the node API restarts. Re-attach to the existing run
        # instead of turning a healthy in-progress update into a 409 failure.
        status = get_status()
        return {
            "ok": True,
            "already_running": True,
            "run_id": status.get("run_id") or current_progress.get("run_id"),
            "unit_name": status.get("unit_name") or active_unit,
            "status": status,
        }

    run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:10]}"
    unit_name = f"{UNIT_PREFIX}-{uuid.uuid4().hex[:12]}.service"
    try:
        _atomic_write_json(PROGRESS_FILE, {
            "percent": 1,
            "state": "running",
            "message": "در حال شروع آپدیت...",
            "run_id": run_id,
            "unit_name": unit_name,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
        # Prevent the live console from briefly showing the previous update.
        UPDATE_LOG_FILE.write_text("", encoding="utf-8")
    except OSError:
        pass

    cmd = [
        "systemd-run",
        f"--unit={unit_name}",
        "--collect",
        "--property=RuntimeMaxSec=1200",
        "--property=TimeoutStopSec=45",
        "--property=KillMode=control-group",
    ]
    try:
        update_env_file = _write_update_environment(run_id, {
            "LICENSE_SERVER_URL": settings.LICENSE_SERVER_URL,
            "LICENSE_API_KEY": settings.LICENSE_API_KEY,
            "LICENSE_KEY": key,
        })
    except (OSError, ValueError) as exc:
        raise HTTPException(500, f"ساخت محیط امن آپدیت ناموفق بود: {exc}")
    cmd.extend([
        f"--property=EnvironmentFile={update_env_file}",
        f"--setenv=VPN_PANEL_UPDATE_ENV_FILE={update_env_file}",
        f"--setenv=UPDATE_RUN_ID={run_id}",
        f"--setenv=UPDATE_SYSTEMD_UNIT={unit_name}",
        "/bin/bash", str(UPDATE_SCRIPT),
    ])
    result = _launch_update_unit(cmd)
    if result.returncode != 0:
        try:
            update_env_file.unlink()
        except OSError:
            pass
        detail = result.stderr.strip()[:300] or result.stdout.strip()[:300] or "خطای نامشخص"
        try:
            _atomic_write_json(PROGRESS_FILE, {
                "percent": 1,
                "state": "failed",
                "message": f"شروع آپدیت ناموفق بود: {detail}",
                "run_id": run_id,
                "unit_name": unit_name,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            })
        except OSError:
            pass
        raise HTTPException(500, f"شروع آپدیت ناموفق بود: {detail}")

    return {"ok": True, "run_id": run_id, "unit_name": unit_name}


def get_status() -> dict:
    if not PROGRESS_FILE.exists():
        return {"percent": 0, "state": "idle", "message": ""}
    try:
        data = json.loads(PROGRESS_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"percent": 0, "state": "idle", "message": ""}

    # اگر فایل می‌گوید «در حال اجراست» ولی خودِ واحد systemd دیگر فعال نیست
    # (مثلاً کرش بی‌صدا/غیرمنتظره)، آپدیت را failed اعلام می‌کنیم تا فرانت‌اند
    # برای همیشه روی نوار پیشرفت گیر نکند.
    if data.get("state") == "running" and not _unit_active(str(data.get("unit_name") or "").strip()):
        # A transient systemd unit can disappear a fraction of a second before
        # the final atomic progress write is observed. Give that tiny race a
        # short grace period instead of reporting a false failure.
        age_seconds = 999.0
        try:
            updated = datetime.fromisoformat(str(data.get("updated_at") or "").replace("Z", "+00:00"))
            if updated.tzinfo is None:
                updated = updated.replace(tzinfo=timezone.utc)
            age_seconds = (datetime.now(timezone.utc) - updated).total_seconds()
        except Exception:
            pass
        if age_seconds > 8:
            detail = ""
            try:
                lines = UPDATE_LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
                detail = next((line.strip() for line in reversed(lines) if line.strip()), "")
            except OSError:
                pass
            data = {
                "percent": data.get("percent", 1),
                "state": "failed",
                "message": f"پردازه‌ی آپدیت متوقف شد{': ' + detail[:260] if detail else ''}. لاگ کامل: /opt/vpn-panel/update.log",
                "run_id": data.get("run_id"),
                "unit_name": data.get("unit_name"),
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            try:
                _atomic_write_json(PROGRESS_FILE, data)
            except OSError:
                pass

    result = {
        "percent": data.get("percent", 0),
        "state": data.get("state", "idle"),
        "message": data.get("message", ""),
        "run_id": data.get("run_id"),
        "unit_name": data.get("unit_name"),
        "updated_at": data.get("updated_at"),
        "current_version": get_current_version(),
        # The update modal is a live CMD-style console, so return a rolling
        # tail during running, success, and failure—not only after a failure.
        "log_tail": _read_log(30000),
        "log_path": str(UPDATE_LOG_FILE),
    }
    return result
