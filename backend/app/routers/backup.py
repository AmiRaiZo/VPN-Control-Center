import gzip
import hashlib
import json
import uuid
import os
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from datetime import datetime, date, timezone

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Response, Query
from sqlalchemy.orm import Session
from starlette.responses import FileResponse

from app.database import get_db, SessionLocal
from app.config import get_settings
from app.models import (
    Admin,
    AdminRole,
    AdminAccessLicense,
    VpnUser,
    VpnUserSubAlias,
    BannedIP,
    InternetBlockedIP,
    Setting,
    OpenvpnExtraPort,
    VpnNode,
    ReservedLicense,
    ConnectionLog,
    XrayUsageCounter,
    TelegramAdminGroup,
    TelegramGroupLinkCode,
    TelegramGroupMemberRule,
)
from app.security import require_superadmin
from app.services.vpn_manager import (
    sync_chap_secrets, ban_ip, block_internet_ip, get_ipsec_psk, set_ipsec_psk,
    control_protocol_service, sync_openvpn_extra_ports, apply_vpn_protocol_settings,
)
from app.services.cert_manager import (
    generate_client_cert, CertError, read_client_cert, write_client_cert,  # noqa: F401 - restore-test patch point
    export_pki_bundle, import_pki_bundle, validate_pki_bundle,
    ensure_controller_openvpn_pki, repair_or_generate_client_cert,
    export_client_cert_backup_record,
)
from app.services import update_manager
from app.services.node_remote import decrypt_password, encrypt_password
from app.services.runtime_backup import (
    export_runtime_bundle, import_runtime_bundle, restart_restored_runtime,
)
from app.services.backup_codec import BackupFormatError, decode_backup_bytes, encode_json_backup

router = APIRouter(prefix="/api/backup", tags=["backup"])


_BACKUP_JOB_DIR = Path("/var/lib/vpn-panel/backup-jobs")
_BACKUP_JOB_LOCK = threading.Lock()
_BACKUP_JOB_RETENTION_SECONDS = 6 * 60 * 60


def _backup_job_paths(job_id: str) -> tuple[Path, Path]:
    safe = str(job_id or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{32}", safe):
        raise HTTPException(404, "شناسه عملیات بکاپ معتبر نیست")
    return _BACKUP_JOB_DIR / f"{safe}.json", _BACKUP_JOB_DIR / f"{safe}.json.gz"


def _write_backup_job(job_id: str, payload: dict) -> None:
    meta_path, _ = _backup_job_paths(job_id)
    _BACKUP_JOB_DIR.mkdir(parents=True, exist_ok=True)
    tmp = meta_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, meta_path)


def _read_backup_job(job_id: str) -> dict:
    meta_path, _ = _backup_job_paths(job_id)
    try:
        return json.loads(meta_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise HTTPException(404, "عملیات بکاپ پیدا نشد یا منقضی شده است") from exc
    except (OSError, json.JSONDecodeError) as exc:
        raise HTTPException(500, "وضعیت عملیات بکاپ قابل خواندن نیست") from exc


def _cleanup_backup_jobs() -> None:
    try:
        _BACKUP_JOB_DIR.mkdir(parents=True, exist_ok=True)
        cutoff = time.time() - _BACKUP_JOB_RETENTION_SECONDS
        for path in _BACKUP_JOB_DIR.iterdir():
            try:
                if path.is_file() and path.stat().st_mtime < cutoff:
                    path.unlink(missing_ok=True)
            except OSError:
                continue
    except OSError:
        pass


def _run_backup_job(job_id: str, include_settings: bool, actor_username: str) -> None:
    meta_path, data_path = _backup_job_paths(job_id)
    db = SessionLocal()
    try:
        _write_backup_job(job_id, {
            "job_id": job_id,
            "state": "running",
            "percent": 8,
            "message": "در حال جمع‌آوری اطلاعات پنل و نودها...",
            "started_at": datetime.utcnow().isoformat(),
            "include_settings": bool(include_settings),
        })
        data = build_backup_payload(
            db,
            include_settings=include_settings,
            include_cluster_nodes=include_settings,
        )
        _write_backup_job(job_id, {
            "job_id": job_id,
            "state": "running",
            "percent": 88,
            "message": "در حال فشرده‌سازی و اعتبارسنجی فایل بکاپ...",
            "started_at": datetime.utcnow().isoformat(),
            "include_settings": bool(include_settings),
        })
        content = encode_json_backup(data)
        tmp_data = data_path.with_suffix(".tmp")
        tmp_data.write_bytes(content)
        os.chmod(tmp_data, 0o600)
        os.replace(tmp_data, data_path)
        suffix = "with-settings-" if include_settings else ""
        filename = f"vpn-panel-backup-{suffix}{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.json.gz"
        complete = bool((data.get("backup_health") or {}).get("complete", True))
        _write_backup_job(job_id, {
            "job_id": job_id,
            "state": "success",
            "percent": 100,
            "message": "فایل بکاپ آماده دانلود است.",
            "filename": filename,
            "complete": complete,
            "format_version": BACKUP_FORMAT_VERSION,
            "size": len(content),
            "finished_at": datetime.utcnow().isoformat(),
            "include_settings": bool(include_settings),
        })
        try:
            from app.services.telegram_notifier import log_event
            log_event(
                "بکاپ دستی بدون رمز گرفته شد",
                f"نوع: {'کامل (با تنظیمات)' if include_settings else 'بدون تنظیمات'}",
                actor=actor_username,
            )
        except Exception:
            pass
    except Exception as exc:
        try:
            data_path.unlink(missing_ok=True)
        except OSError:
            pass
        _write_backup_job(job_id, {
            "job_id": job_id,
            "state": "failed",
            "percent": 100,
            "message": str(exc)[:1200] or "ساخت بکاپ ناموفق بود",
            "finished_at": datetime.utcnow().isoformat(),
            "include_settings": bool(include_settings),
        })
    finally:
        db.close()


# اگر ساختار بکاپ در آینده تغییر کند این عدد را بالا می‌بریم تا هنگام
# وارد کردن یک فایل قدیمی/ناسازگار، پیام روشن بدهیم به‌جای خطای نامشخص.
# نسخه‌ی ۴: لایسنس‌های داخلی ادمین و وضعیت دقیق طرح ادمین‌های زیرمجموعه را نیز نگه می‌دارد.
# نسخه‌ی ۳: علاوه بر دیتای نسخه‌ی ۲، فلگ‌ها و UUID پایدار VMess/VLESS و
# metadata تنظیمات Xray را به‌صورت backward-compatible نگه می‌دارد. نسخه‌های
# ۱ و ۲ همچنان قابل واردکردن‌اند.
# نسخه‌ی ۲: علاوه بر دیتای قبلی، PKI کامل OpenVPN (برای این‌که فایل‌های
# .ovpn قدیمی بعد از انتقال به سرور دیگر هم کار کنند)، PSK مشترک L2TP/IPsec،
# و (اختیاری، فقط در «بکاپ کامل») تنظیمات پنل + پورت‌های اضافه‌ی OpenVPN را
# هم شامل می‌شود. فایل‌های بکاپ نسخه‌ی ۱ (بدون این فیلدها) همچنان قابل وارد
# کردن‌اند - همه‌ی فیلدهای تازه اختیاری‌اند.
BACKUP_FORMAT_VERSION = 11


def _iso(v):
    if v is None:
        return None
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    return v



def _parse_datetime(value):
    if not value:
        return None
    if isinstance(value, datetime):
        parsed = value
    else:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed

def _parse_date(value):
    if not value or isinstance(value, date):
        return value
    try:
        return date.fromisoformat(str(value)[:10])
    except (ValueError, TypeError):
        return None


def _safe_int(value, default=0, *, minimum=None, maximum=None):
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = int(default)
    if minimum is not None:
        parsed = max(int(minimum), parsed)
    if maximum is not None:
        parsed = min(int(maximum), parsed)
    return parsed


def _canonical_backup_bytes(data: dict) -> bytes:
    """Return deterministic bytes for backup integrity verification.

    The integrity object itself is excluded so the hash can be embedded in the
    same JSON document. Sorting keys makes the check independent of pretty
    printing, whitespace, or object key order.
    """
    payload = dict(data)
    payload.pop("integrity", None)
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")


_COUNTED_SECTIONS = (
    "admins", "admin_access_licenses", "telegram_admin_groups", "telegram_group_member_rules", "vpn_users", "sub_aliases",
    "banned_ips", "internet_blocks", "reserved_licenses", "vpn_nodes",
    "openvpn_extra_ports", "cluster_nodes",
)


def _verify_section_counts(data: dict) -> bool:
    counts = data.get("counts")
    if not isinstance(counts, dict):
        return False
    version = _safe_int(data.get("version"), 0)
    keys = _COUNTED_SECTIONS
    if version < 11:
        keys = tuple(key for key in keys if key != "telegram_group_member_rules")
    if version < 10:
        keys = tuple(key for key in keys if key != "telegram_admin_groups")
    if version < 9:
        keys = tuple(key for key in keys if key != "cluster_nodes")
    for key in keys:
        section = data.get(key, [])
        if not isinstance(section, list):
            return False
        if _safe_int(counts.get(key), -1) != len(section):
            return False
    return True


def _attach_integrity(data: dict) -> dict:
    data["integrity"] = {
        "algorithm": "sha256",
        "payload_sha256": hashlib.sha256(_canonical_backup_bytes(data)).hexdigest(),
    }
    return data


def _verify_integrity(data: dict) -> bool:
    integrity = data.get("integrity")
    if not isinstance(integrity, dict):
        return False
    if str(integrity.get("algorithm") or "").lower() != "sha256":
        return False
    expected = str(integrity.get("payload_sha256") or "").strip().lower()
    if len(expected) != 64:
        return False
    actual = hashlib.sha256(_canonical_backup_bytes(data)).hexdigest()
    return actual == expected


def _rewrite_server_targets(value, node_id_map: dict[int, int]):
    """Rewrite portable ``node:<old-id>`` scope tokens after node import.

    Version 8 stores each node's source database id. On a fresh server the new
    ids can differ (especially when nodes had previously been deleted), so raw
    ids must never be copied unchanged into user/admin scopes.
    """
    if not value or not node_id_map:
        return value
    try:
        parsed = json.loads(value) if isinstance(value, str) else value
    except (TypeError, ValueError, json.JSONDecodeError):
        return value
    if not isinstance(parsed, list):
        return value
    changed = False
    rewritten = []
    for token in parsed:
        raw = str(token or "")
        if raw.startswith("node:"):
            try:
                old_id = int(raw.split(":", 1)[1])
            except (TypeError, ValueError):
                rewritten.append(token)
                continue
            new_id = node_id_map.get(old_id)
            if new_id is not None:
                rewritten.append(f"node:{new_id}")
                changed = changed or new_id != old_id
                continue
        rewritten.append(token)
    if isinstance(value, str):
        return json.dumps(rewritten, ensure_ascii=False, separators=(",", ":")) if changed else value
    return rewritten


def _get_setting(db: Session, key: str):
    row = db.query(Setting).filter(Setting.key == key).first()
    return row.value if row else None


def _set_setting(db: Session, key: str, value):
    row = db.query(Setting).filter(Setting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(Setting(key=key, value=value))


# وضعیت و لاگ SSL فقط زمانی عیناً برمی‌گردند که «بکاپ کامل نسخه ۹»
# فایل‌های واقعی TLS/runtime را هم همراه داشته باشد و restore در حالت replace
# اجرا شود. برای بکاپ‌های قدیمی/داده‌ای، وضعیت active عمداً reset می‌شود تا
# پنل درباره وجود گواهی روی سرور مقصد اطلاعات گمراه‌کننده نشان ندهد.
_SETTINGS_STATUS_KEYS = {"domain_ssl_status", "sub_domain_status", "xray_sub_domain_status", "vpn_domain_status"}
_SETTINGS_LOG_KEYS = {"domain_ssl_log", "sub_domain_log", "xray_sub_domain_log", "vpn_domain_log"}
_SENSITIVE_SETTINGS_KEYS = {"telegram_backup_server_password_enc", "node_ssh_password_enc"}


# ---------- خروجی گرفتن ----------
# دو نوع بکاپ:
#   1) داده‌ای (include_settings=false): ادمین‌ها، کاربران VPN، هش/رمزها،
#      محدودیت‌ها، حجم مصرف‌شده، پروتکل‌های مجاز، توکن اشتراک، UUIDهای Xray،
#      لیست‌های امنیتی و PKI/PSK قابل‌حمل. این نوع برای جایگزینی کامل پنل نیست.
#   2) کامل (include_settings=true): همه موارد بالا + تمام تنظیمات دیتابیس،
#      نودها و اعتبارنامه‌های قابل‌حمل آن‌ها، تنظیمات/گواهی‌های واقعی سرویس‌ها،
#      دامنه و پورت‌ها، برندینگ و (در خروجی پنل/تلگرام) بکاپ محلی همه نودها.
#
# بازیابی دقیق با restore_mode=replace وضعیت فعلی پنل مقصد را پاک می‌کند و
# همان شناسه‌ها و رمزها را برمی‌گرداند. فایل .env و رمز اتصال دیتابیس مقصد
# عمداً جایگزین نمی‌شوند؛ این‌ها متعلق به نصب مقصد هستند، نه هویت کلاینت VPN.
# تداوم اتصال فایل‌های قدیمی فقط وقتی ممکن است که endpoint عمومی قبلی (دامنه
# یا IP خام) و پورت‌ها همچنان به سرور بازیابی‌شده برسند.
#
# PKI کامل OpenVPN، کلید خصوصی CA و فایل‌های TLS/daemon نیز داخل بکاپ کامل
# ذخیره می‌شوند؛ بنابراین با ثابت‌ماندن endpoint عمومی، فایل‌های قبلی کاربران
# بدون دانلود مجدد قابل استفاده می‌مانند.

_OPENVPN_EXTRA_CONFIG_RE = re.compile(
    r"^/etc/openvpn/server/server-extra-(tcp|udp)-(\d+)\.conf$"
)
_OPENVPN_EXTRA_DROPIN_RE = re.compile(
    r"^/etc/systemd/system/openvpn-server@server-extra-(tcp|udp)-(\d+)\.service\.d(?:/.*)?$"
)


def _reclassify_rebuildable_node_runtime_warnings(payload: dict) -> tuple[dict, list[str]]:
    """Turn legacy false-positive extra-listener warnings into advisories.

    Builds before the complete OpenVPN runtime-root allowlist could export the
    node database row for an extra OpenVPN listener, then reject the generated
    ``server-extra-*.conf`` file as being outside the safe boundary.  Those
    files are deterministic build artifacts: restore imports the exact
    ``openvpn_extra_ports`` rows and ``sync_openvpn_extra_ports`` recreates the
    config and systemd drop-in.  Keeping the warning as fatal made a verified
    all-node backup look incomplete even though every piece of source data
    required for exact regeneration was already embedded.

    Only warnings whose protocol/port pair exists in this same node backup are
    reclassified.  Any unrelated warning remains blocking.  The nested backup
    integrity is recalculated after the health metadata is normalized so a
    later node restore can verify and import it normally.
    """
    if not isinstance(payload, dict):
        return payload, []
    health = payload.get("backup_health")
    if not isinstance(health, dict):
        return payload, []

    backed_up_ports: set[tuple[str, int]] = set()
    for row in payload.get("openvpn_extra_ports") or []:
        if not isinstance(row, dict):
            continue
        proto = str(row.get("protocol") or "").strip().lower()
        port = _safe_int(row.get("port"), 0, minimum=0, maximum=65535)
        if proto in {"tcp", "udp"} and port:
            backed_up_ports.add((proto, port))

    original_warnings = [
        str(item).strip() for item in (health.get("warnings") or [])
        if str(item).strip()
    ]
    if not original_warnings or not backed_up_ports:
        return payload, []

    rebuildable: list[str] = []
    blocking: list[str] = []
    boundary_markers = (
        "خارج از محدوده امن",
        "outside the safe",
        "outside safe",
    )
    for warning in original_warnings:
        if not any(marker in warning.lower() for marker in boundary_markers):
            blocking.append(warning)
            continue
        pair = None
        for token in warning.replace("(", " ").replace(")", " ").split():
            candidate = token.strip("؛،,:.[]{}'\"")
            match = _OPENVPN_EXTRA_CONFIG_RE.fullmatch(candidate)
            if not match:
                match = _OPENVPN_EXTRA_DROPIN_RE.fullmatch(candidate)
            if match:
                pair = (match.group(1), int(match.group(2)))
                break
        if pair and pair in backed_up_ports:
            rebuildable.append(warning)
        else:
            blocking.append(warning)

    if not rebuildable:
        return payload, []

    advisories = [
        str(item).strip() for item in (health.get("advisories") or [])
        if str(item).strip()
    ]
    for warning in rebuildable:
        compact = " ".join(warning.split())
        advisories.append(
            "هشدار قدیمی فایل تولیدی OpenVPN به وضعیت اطلاع‌رسانی تبدیل شد؛ "
            "رکورد پورت/پروتکل داخل همین بکاپ موجود است و فایل هنگام بازیابی "
            f"دوباره ساخته می‌شود: {compact}"
        )

    health["warnings"] = blocking
    health["advisories"] = advisories
    health["complete"] = not blocking
    health["rebuildable_runtime_warnings"] = len(rebuildable)
    payload["backup_health"] = health

    scope = payload.get("backup_scope")
    if not isinstance(scope, dict):
        scope = {}
    scope["openvpn_extra_listener_source_rows"] = True
    scope["openvpn_extra_listener_configs_rebuilt_on_restore"] = True
    payload["backup_scope"] = scope

    # We changed nested health metadata after validating the node response.
    # Re-sign the embedded document so restore_nodes can verify it later.
    payload = _attach_integrity(payload)
    return payload, rebuildable


def _collect_cluster_node_backups(db: Session) -> tuple[list[dict], list[str]]:
    """Collect a verified full backup from every registered node.

    Every node is attempted independently with bounded retries. Collection is
    concurrent, so one offline server does not make a fleet backup wait for all
    other node timeouts serially. The controller registration rows are already
    stored in ``vpn_nodes``; this section adds each node's exact local settings,
    certificates and runtime files.
    """
    rows = db.query(VpnNode).order_by(VpnNode.id).all()
    nodes = [
        {
            "id": int(node.id),
            "name": str(node.name or f"node-{node.id}"),
            "api_url": str(node.api_url or "").strip(),
            "api_token": str(node.api_token or "").strip(),
            "verify_tls": bool(getattr(node, "verify_tls", True)),
            "enabled": bool(getattr(node, "enabled", True)),
            "status": getattr(node, "status", None),
        }
        for node in rows
    ]
    if not nodes:
        return [], []

    def fetch_node(node: dict) -> tuple[dict | None, str | None]:
        node_name = node["name"]
        base_url = node["api_url"].rstrip("/")
        token = node["api_token"]
        if not base_url or not token:
            return None, (
                f"دریافت بکاپ کامل از نود «{node_name}» ممکن نبود: آدرس API یا توکن نود ثبت نشده است."
            )
        endpoint = f"{base_url}/api/node-agent/backup/export"
        last_error: Exception | None = None
        for attempt in range(1, 4):
            try:
                response = requests.get(
                    endpoint,
                    headers={"X-Node-Token": token},
                    timeout=(10, 90),
                    verify=node["verify_tls"],
                )
                response.raise_for_status()
                payload = response.json()
                if not isinstance(payload, dict) or payload.get("type") != "vpn-panel-backup":
                    raise ValueError("پاسخ نود فرمت بکاپ معتبر نداشت")
                if not bool(payload.get("includes_settings")) or not isinstance(payload.get("settings"), dict):
                    raise ValueError("نود بکاپ کاملِ شامل تنظیمات برنگرداند")
                scope = payload.get("backup_scope") or {}
                runtime_identity = payload.get("runtime_identity") or {}
                if payload.get("backup_kind") != "full":
                    raise ValueError("نود خروجی data-only برگرداند، نه بکاپ کامل")
                if not bool(scope.get("database_configuration")) or not bool(scope.get("exact_protocol_configuration_files")):
                    raise ValueError("بکاپ نود پوشش کامل تنظیمات دیتابیس/پروتکل را اعلام نکرد")
                if not isinstance(runtime_identity, dict) or not isinstance(runtime_identity.get("entries"), list):
                    raise ValueError("فایل‌های runtime/config نود در بکاپ کامل وجود نداشت")
                version = _safe_int(payload.get("version"), 0)
                if version >= 8 and (not _verify_integrity(payload) or not _verify_section_counts(payload)):
                    raise ValueError("کنترل صحت بکاپ نود ناموفق بود")
                payload, rebuildable_runtime_warnings = _reclassify_rebuildable_node_runtime_warnings(payload)
                health = payload.get("backup_health") or {}
                runtime_entries = (payload.get("runtime_identity") or {}).get("entries") or []
                item = {
                    "source_id": node["id"],
                    "name": node_name,
                    "api_url": node["api_url"],
                    "enabled": node["enabled"],
                    "status": node["status"],
                    "collected_at": datetime.now(timezone.utc).isoformat(),
                    "coverage": {
                        "full_backup_verified": True,
                        "backup_health_complete": bool(health.get("complete", True)),
                        "settings_rows": len(payload.get("settings") or {}),
                        "runtime_entries": len(runtime_entries),
                        "vpn_users": len(payload.get("vpn_users") or []),
                        "openvpn_pki_included": bool(payload.get("openvpn_pki")),
                        "ipsec_psk_included": payload.get("ipsec_psk") is not None,
                        "rebuildable_runtime_warnings_reclassified": len(rebuildable_runtime_warnings),
                        "openvpn_extra_listener_rows": len(payload.get("openvpn_extra_ports") or []),
                    },
                    "backup": payload,
                }
                warning = None
                if not bool(health.get("complete", True)):
                    node_warnings = [str(entry) for entry in (health.get("warnings") or []) if str(entry).strip()]
                    detail = f" علت: {node_warnings[0]}" if node_warnings else ""
                    warning = f"بکاپ محلی نود «{node_name}» با هشدار ساخته شد.{detail}"
                return item, warning
            except Exception as exc:
                last_error = exc
                status_code = getattr(getattr(exc, "response", None), "status_code", None)
                if status_code in {400, 401, 403, 404}:
                    break
                if attempt < 3:
                    time.sleep(0.6 * attempt)
        return None, f"دریافت بکاپ کامل از نود «{node_name}» پس از ۳ تلاش ناموفق بود: {last_error}"

    collected: list[dict] = []
    warnings: list[str] = []
    with ThreadPoolExecutor(max_workers=min(8, len(nodes)), thread_name_prefix="vpn-backup-node") as pool:
        futures = [pool.submit(fetch_node, node) for node in nodes]
        for future in as_completed(futures):
            try:
                item, warning = future.result()
            except Exception as exc:  # defensive: worker already converts normal errors
                item, warning = None, f"خطای غیرمنتظره هنگام دریافت بکاپ نود: {exc}"
            if item is not None:
                collected.append(item)
            if warning:
                warnings.append(warning)
    collected.sort(key=lambda item: int(item.get("source_id") or 0))
    return collected, warnings


def build_backup_payload(db: Session, include_settings: bool, include_cluster_nodes: bool = False) -> dict:
    """منطق واقعی ساخت دیتای بکاپ - جدا از خودِ endpoint تا هم export_backup
    و هم ارسال خودکار/دستی بکاپ به کانال تلگرام (app.services.telegram_notifier)
    از همین یک نسخه استفاده کنند و هیچ‌وقت از هم عقب نیفتند."""
    admins = db.query(Admin).order_by(Admin.id).all()
    users = db.query(VpnUser).order_by(VpnUser.id).all()
    bans = db.query(BannedIP).order_by(BannedIP.id).all()
    internet_blocks = db.query(InternetBlockedIP).order_by(InternetBlockedIP.id).all()
    admin_licenses = db.query(AdminAccessLicense).order_by(AdminAccessLicense.id).all()
    telegram_groups = db.query(TelegramAdminGroup).order_by(TelegramAdminGroup.id).all()
    telegram_member_rules = db.query(TelegramGroupMemberRule).order_by(TelegramGroupMemberRule.id).all()
    reserved_licenses = db.query(ReservedLicense).order_by(ReservedLicense.order, ReservedLicense.id).all()
    admin_username_by_id = {a.id: a.username for a in admins}
    vpn_username_by_id = {u.id: u.username for u in users}
    group_chat_id_by_id = {row.id: row.chat_id for row in telegram_groups}

    data = {
        "type": "vpn-panel-backup",
        "version": BACKUP_FORMAT_VERSION,
        "includes_settings": include_settings,
        "backup_kind": "full" if include_settings else "data_only",
        "exported_at": datetime.utcnow().isoformat(),
        "backup_scope": {
            "database_configuration": bool(include_settings),
            "vpn_identity_and_credentials": True,
            "openvpn_pki": True,
            "ipsec_psk": True,
            "deployment_environment_file": False,
            "domain_tls_certificates": bool(include_settings),
            "exact_protocol_configuration_files": bool(include_settings),
            "branding_assets": bool(include_settings),
            "cluster_node_local_backups": bool(include_settings and include_cluster_nodes),
            "runtime_sessions": False,
            "connection_history": False,
            "xray_counter_baselines": False,
        },
        "backup_health": {
            "complete": True,
            "warnings": [],
            "repairs": [],
            "advisories": [],
            "post_restore_actions": [
                "برای اتصال بدون دریافت فایل جدید، دامنه/آدرس و همه پورت‌های عمومی باید همان مقادیر قبلی باقی بمانند.",
                "اگر فایل‌های کاربران با IP خام ساخته شده‌اند، IP عمومی قبلی باید روی مقصد حفظ یا به مقصد NAT شود.",
                "پس از انتقال به IP جدید، وضعیت لایسنس‌های اصلی و رزروشده باید دوباره بررسی شود.",
            ],
        },
        "admins": [
            {
                "username": a.username,
                "password_hash": a.password_hash,
                "role": a.role.value if hasattr(a.role, "value") else a.role,
                "permissions": a.permissions,
                "see_all_users": a.see_all_users,
                "server_targets": getattr(a, "server_targets", None),
                "max_users": a.max_users,
                "max_total_quota_bytes": a.max_total_quota_bytes,
                "subscription_expire_date": _iso(a.subscription_expire_date),
                "subscription_expire_at": _iso(getattr(a, "subscription_expire_at", None)),
                "managed_by_license": bool(getattr(a, "managed_by_license", False)),
                "access_license_code": getattr(a, "access_license_code", None),
                "license_activated_at": _iso(getattr(a, "license_activated_at", None)),
                "license_locked": bool(getattr(a, "license_locked", False)),
                "telegram_bot_enabled": bool(getattr(a, "telegram_bot_enabled", False)),
                "telegram_user_id": getattr(a, "telegram_user_id", None),
                "telegram_bot_opted_out": bool(getattr(a, "telegram_bot_opted_out", False)),
                "is_active": a.is_active,
                "created_at": _iso(a.created_at),
            }
            for a in admins
        ],
        "telegram_admin_groups": [
            {
                "owner_admin_username": admin_username_by_id.get(row.admin_id),
                "chat_id": str(row.chat_id),
                "title": row.title,
                "chat_type": row.chat_type,
                "chat_username": row.chat_username,
                "control_enabled": bool(row.control_enabled),
                "access_mode": str(getattr(row, "access_mode", "all_members") or "all_members"),
                "is_active": bool(row.is_active),
                "linked_by_telegram_user_id": str(row.linked_by_telegram_user_id),
                "last_verified_at": _iso(row.last_verified_at),
                "last_used_at": _iso(row.last_used_at),
                "created_at": _iso(row.created_at),
            }
            for row in telegram_groups
            if admin_username_by_id.get(row.admin_id)
        ],
        "telegram_group_member_rules": [
            {
                "group_chat_id": str(group_chat_id_by_id.get(row.group_id) or ""),
                "telegram_user_id": str(row.telegram_user_id),
                "is_allowed": bool(row.is_allowed),
                "display_name": row.display_name,
                "telegram_username": row.telegram_username,
                "note": row.note,
                "created_by_admin_username": admin_username_by_id.get(row.created_by_admin_id),
                "last_seen_at": _iso(row.last_seen_at),
                "created_at": _iso(row.created_at),
                "updated_at": _iso(row.updated_at),
            }
            for row in telegram_member_rules
            if group_chat_id_by_id.get(row.group_id)
        ],
        "admin_access_licenses": [
            {
                "code": row.code,
                "role": (row.role.value if isinstance(getattr(row, "role", AdminRole.admin), AdminRole) else str(getattr(row, "role", "admin") or "admin")),
                "permissions": row.permissions,
                "see_all_users": row.see_all_users,
                "server_targets": getattr(row, "server_targets", None),
                "max_users": row.max_users,
                "max_total_quota_bytes": row.max_total_quota_bytes,
                "expire_mode": row.expire_mode,
                "duration_minutes": row.duration_minutes,
                "fixed_expire_at": _iso(row.fixed_expire_at),
                "is_active": row.is_active,
                "used_by_username": admin_username_by_id.get(row.used_by_admin_id),
                "activated_at": _iso(row.activated_at),
                "telegram_bot_enabled": bool(getattr(row, "telegram_bot_enabled", False)),
                "telegram_user_id": getattr(row, "telegram_user_id", None),
                "note": row.note,
                "created_at": _iso(row.created_at),
            }
            for row in admin_licenses
        ],
        "sub_aliases": [
            {"username": vpn_username_by_id.get(alias.user_id), "token": alias.token, "created_at": _iso(alias.created_at)}
            for alias in db.query(VpnUserSubAlias).order_by(VpnUserSubAlias.id).all()
            if vpn_username_by_id.get(alias.user_id)
        ],
        "vpn_users": [
            {
                "username": u.username,
                "password": u.password,
                "sub_token": u.sub_token,
                "owner_admin_username": u.owner_admin.username if u.owner_admin else None,
                "enable_l2tp": u.enable_l2tp,
                "enable_pptp": u.enable_pptp,
                "enable_openvpn": u.enable_openvpn,
                "enable_sstp": u.enable_sstp,
                "enable_ikev2": u.enable_ikev2,
                "enable_openconnect": u.enable_openconnect,
                "enable_vmess": u.enable_vmess,
                "enable_vless": u.enable_vless,
                "xray_uuid": u.xray_uuid,
                "openvpn_auth_mode": u.openvpn_auth_mode,
                "sstp_auth_mode": u.sstp_auth_mode,
                "quota_bytes": u.quota_bytes,
                "used_bytes": u.used_bytes,
                "max_devices": u.max_devices,
                "speed_limit_mbps": u.speed_limit_mbps,
                "download_limit_mbps": u.download_limit_mbps,
                "upload_limit_mbps": u.upload_limit_mbps,
                "expire_mode": u.expire_mode,
                "expire_after_days": u.expire_after_days,
                "first_connect_at": _iso(u.first_connect_at),
                "expire_date": _iso(u.expire_date),
                "is_active": u.is_active,
                "note": u.note,
                "server_targets": u.server_targets,
                "vmess_internet_blocked": bool(getattr(u, "vmess_internet_blocked", False)),
                "vless_internet_blocked": bool(getattr(u, "vless_internet_blocked", False)),
                "node_managed": bool(getattr(u, "node_managed", False)),
                "node_source": getattr(u, "node_source", None),
                "created_at": _iso(u.created_at),
                "updated_at": _iso(u.updated_at),
            }
            for u in users
        ],
        "banned_ips": [
            {
                "ip_address": b.ip_address,
                "reason": b.reason,
                "banned_by_admin_username": b.banned_by_admin.username if b.banned_by_admin else None,
                "owner_admin_username": admin_username_by_id.get(getattr(b, "owner_admin_id", None)),
                "created_at": _iso(b.created_at),
            }
            for b in bans
        ],
        "internet_blocks": [
            {
                "ip_address": b.ip_address,
                "user_id": b.user_id,
                "username": b.username,
                "protocol": b.protocol,
                "reason": b.reason,
                "blocked_by_admin_username": b.blocked_by_username,
                "owner_admin_username": admin_username_by_id.get(getattr(b, "owner_admin_id", None)),
                "created_at": _iso(b.created_at),
            }
            for b in internet_blocks
        ],
        "reserved_licenses": [
            {
                "key": row.key,
                "order": row.order,
                "added_at": _iso(row.added_at),
                "reserved_ip": row.reserved_ip,
            }
            for row in reserved_licenses
        ],
    }

    # ---- PKI کامل OpenVPN (CA + سرتیفیکیت/کلید سرور + dh/ta/CRL) ----
    if not include_settings:
        data["backup_health"]["complete"] = False
        data["backup_health"]["warnings"].append(
            "این خروجی از نوع «بدون تنظیمات» است و نودها، تنظیمات پنل و رمزهای قابل‌انتقال را ندارد؛ "
            "برای بازیابی کامل پس از خرابی سرور، بکاپ کامل یا بکاپ تلگرام را استفاده کنید."
        )

    openvpn_users = [u for u in users if bool(u.enable_openvpn)]
    pki = export_pki_bundle()
    pki_valid, pki_detail = validate_pki_bundle(pki)
    # A main controller is the canonical PKI owner. Older upgrades could have a
    # healthy node PKI but no local controller copy; adopt it before backup so
    # the archive contains the same CA/tls-auth identity used by all nodes.
    runtime_settings = get_settings()
    local_easyrsa = Path(runtime_settings.EASYRSA_DIR) / "easyrsa"
    if (
        not pki_valid
        and openvpn_users
        and str(runtime_settings.SERVER_ROLE or "main").lower() != "node"
        and local_easyrsa.is_file()
    ):
        try:
            pki = ensure_controller_openvpn_pki(db)
            pki_valid, pki_detail = validate_pki_bundle(pki)
            if pki_valid:
                data["backup_health"]["repairs"].append(
                    "PKI اصلی OpenVPN قبل از ساخت بکاپ روی کنترلر آماده/بازیابی شد."
                )
        except Exception as exc:
            pki_detail = f"{pki_detail}; controller_prepare_failed:{exc}"

    if pki_valid:
        data["openvpn_pki"] = pki

        # Self-heal safe missing-certificate cases before declaring the backup
        # degraded. This creates a first certificate for users that never
        # downloaded an OpenVPN profile and recovers an accidentally removed
        # issued cert from EasyRSA's certs_by_serial archive. It never revokes a
        # still-active certificate merely because its private key is missing.
        user_certs = {}
        client_records = {}
        missing_user_certs = []
        for u in openvpn_users:
            try:
                cert, repair_status = repair_or_generate_client_cert(u.username)
                user_certs[u.username] = {"cert": cert[0], "key": cert[1]}
                if repair_status == "generated":
                    data["backup_health"]["repairs"].append(
                        f"سرتیفیکیت و کلید OpenVPN کاربر «{u.username}» پیش از بکاپ ساخته شد."
                    )
                elif repair_status == "recovered":
                    data["backup_health"]["repairs"].append(
                        f"سرتیفیکیت OpenVPN کاربر «{u.username}» از آرشیو داخلی EasyRSA بازیابی شد."
                    )
            except Exception as exc:
                # A client private key is not required by the OpenVPN server.
                # When EasyRSA still has an active serial, the canonical PKI,
                # index and CRL in this full backup preserve every already
                # downloaded .ovpn profile after restore.  Record that state as
                # an advisory instead of falsely marking the entire server/node
                # backup incomplete.  A later explicit profile download can
                # safely revoke the old serial and issue a replacement.
                record = export_client_cert_backup_record(u.username)
                if record and record.get("serial") and bool(record.get("existing_profiles_remain_valid")):
                    client_records[u.username] = record
                    data["backup_health"]["advisories"].append(
                        f"نسخهٔ سروری کلید خصوصی OpenVPN کاربر «{u.username}» موجود نیست؛ "
                        "پروفایل‌های نصب‌شده با PKI بکاپ‌شده معتبر می‌مانند و فقط برای دانلود دوباره باید پروفایل تازه صادر شود."
                    )
                else:
                    missing_user_certs.append((u.username, str(exc)))
        if user_certs:
            data["openvpn_user_certs"] = user_certs
        if client_records:
            data["openvpn_client_records"] = client_records
        if missing_user_certs:
            data["backup_health"]["complete"] = False
            details = "؛ ".join(
                f"{username}: {reason[-260:]}" for username, reason in missing_user_certs[:5]
            )
            extra = f"؛ و {len(missing_user_certs) - 5} کاربر دیگر" if len(missing_user_certs) > 5 else ""
            data["backup_health"]["warnings"].append(
                "هویت OpenVPN بعضی کاربران نه در فایل‌های کاربری و نه در رکورد فعال EasyRSA پیدا نشد: "
                f"{details}{extra}. این وضعیت واقعاً نیازمند صدور پروفایل جدید است."
            )
    elif openvpn_users:
        data["backup_health"]["complete"] = False
        data["backup_health"]["warnings"].append(
            "PKI اصلی OpenVPN در زمان ساخت بکاپ معتبر/کامل نبود "
            f"({pki_detail})؛ بازیابی کاربران ممکن است انجام شود، اما فایل‌های .ovpn قبلی قابل تضمین نیستند."
        )

    # ---- PSK مشترک L2TP/IPsec (سطح پروتکل، مستقل از هر کاربر) ----
    psk = get_ipsec_psk()
    if psk is not None:
        data["ipsec_psk"] = psk
    elif any(bool(u.enable_l2tp) for u in users):
        data["backup_health"]["complete"] = False
        data["backup_health"]["warnings"].append(
            "رمز مشترک L2TP/IPsec در زمان ساخت بکاپ خوانده نشد و باید پس از بازیابی دستی تنظیم شود."
        )

    if include_settings:
        settings_rows = db.query(Setting).all()
        data["settings"] = {s.key: s.value for s in settings_rows if s.key not in _SENSITIVE_SETTINGS_KEYS}
        extra_ports = db.query(OpenvpnExtraPort).order_by(OpenvpnExtraPort.id).all()
        data["openvpn_extra_ports"] = [
            {"port": p.port, "protocol": p.protocol, "is_active": p.is_active, "created_at": _iso(p.created_at)} for p in extra_ports
        ]
        data["vpn_nodes"] = []
        for n in db.query(VpnNode).order_by(VpnNode.id).all():
            ssh_password_enc = getattr(n, "ssh_password_enc", None)
            panel_password_enc = getattr(n, "panel_admin_password_enc", None)
            ssh_password = decrypt_password(ssh_password_enc)
            panel_password = decrypt_password(panel_password_enc)
            if ssh_password_enc and not ssh_password:
                data["backup_health"]["complete"] = False
                data["backup_health"]["warnings"].append(
                    f"رمز SSH ذخیره‌شده برای نود «{n.name}» قابل رمزگشایی نبود و وارد بکاپ نشد."
                )
            if panel_password_enc and not panel_password:
                data["backup_health"]["complete"] = False
                data["backup_health"]["warnings"].append(
                    f"رمز مدیریت پنل نود «{n.name}» قابل رمزگشایی نبود و وارد بکاپ نشد."
                )
            data["vpn_nodes"].append({
                "source_id": n.id,
                "name": n.name,
                "api_url": n.api_url,
                "api_token": n.api_token,
                "enabled": n.enabled,
                "verify_tls": getattr(n, "verify_tls", True),
                "weight": n.weight,
                "ssh_host": getattr(n, "ssh_host", None),
                "ssh_port": getattr(n, "ssh_port", 22),
                "ssh_username": getattr(n, "ssh_username", None),
                # Encrypted database values are tied to JWT_SECRET. Export the
                # portable plaintext only inside the already-sensitive full
                # backup, then re-encrypt under the destination secret.
                "ssh_password": ssh_password,
                "panel_admin_username": getattr(n, "panel_admin_username", None),
                "panel_admin_password": panel_password,
                "remote_admin_enabled": bool(getattr(n, "remote_admin_enabled", False)),
                "user_assignment_enabled": bool(getattr(n, "user_assignment_enabled", True)),
                "node_panel_enabled": bool(getattr(n, "node_panel_enabled", True)),
                "status": n.status,
                "last_seen_at": _iso(getattr(n, "last_seen_at", None)),
                "last_error": getattr(n, "last_error", None),
                "last_snapshot": n.last_snapshot,
                "protocol_domains": getattr(n, "protocol_domains", None),
                "created_at": _iso(getattr(n, "created_at", None)),
                "updated_at": _iso(getattr(n, "updated_at", None)),
            })
        portable_secrets = {}
        backup_server_password_enc = _get_setting(db, "telegram_backup_server_password_enc")
        backup_server_password = decrypt_password(backup_server_password_enc)
        if backup_server_password:
            portable_secrets["telegram_backup_server_password"] = backup_server_password
        elif backup_server_password_enc:
            data["backup_health"]["complete"] = False
            data["backup_health"]["warnings"].append(
                "رمز سرور ذخیره‌شده برای پیام بکاپ تلگرام قابل رمزگشایی نبود و وارد بکاپ نشد."
            )
        node_ssh_password_enc = _get_setting(db, "node_ssh_password_enc")
        node_ssh_password = decrypt_password(node_ssh_password_enc)
        if node_ssh_password:
            portable_secrets["node_ssh_password"] = node_ssh_password
        elif node_ssh_password_enc:
            data["backup_health"]["complete"] = False
            data["backup_health"]["warnings"].append(
                "رمز SSH محلی نود قابل رمزگشایی نبود و وارد بکاپ نشد."
            )
        if portable_secrets:
            data["portable_secrets"] = portable_secrets
        data["server_identity"] = {
            key: data["settings"].get(key)
            for key in (
                "domain", "sub_domain", "xray_sub_domain", "vpn_domain",
                "l2tp_server_address", "pptp_server_address",
                "sstp_server_address", "openconnect_server_address",
                "vmess_server_address", "vless_server_address",
                "panel_port", "sub_domain_port", "xray_sub_domain_port",
            )
            if data["settings"].get(key) not in (None, "")
        }

        runtime_bundle, runtime_warnings = export_runtime_bundle()
        data["runtime_identity"] = runtime_bundle
        if runtime_warnings:
            data["backup_health"]["complete"] = False
            data["backup_health"]["warnings"].extend(runtime_warnings)

        data["xray_metadata"] = {
            "format": 1,
            "protocols": {
                proto: {key: value for key, value in data["settings"].items() if key.startswith(proto + "_")}
                for proto in ("vmess", "vless")
            },
            "private_tls_keys_included": any(
                str(entry.get("path") or "").startswith("/etc/vpn-panel/xray/")
                and str(entry.get("path") or "").endswith((".key", "/key.pem", "/privkey.pem"))
                for entry in runtime_bundle.get("entries", [])
            ),
        }

        data["cluster_nodes"] = []
        registered_node_count = db.query(VpnNode).count()
        data["node_backup_summary"] = {
            "registered": registered_node_count,
            "collected": 0,
            "missing": registered_node_count if include_cluster_nodes else 0,
            "all_registered_nodes_requested": bool(include_cluster_nodes),
        }
        if include_cluster_nodes:
            cluster_nodes, cluster_warnings = _collect_cluster_node_backups(db)
            data["cluster_nodes"] = cluster_nodes
            data["node_backup_summary"].update({
                "collected": len(cluster_nodes),
                "verified_full": sum(1 for item in cluster_nodes if bool((item.get("coverage") or {}).get("full_backup_verified"))),
                "settings_rows": sum(int((item.get("coverage") or {}).get("settings_rows") or 0) for item in cluster_nodes),
                "runtime_entries": sum(int((item.get("coverage") or {}).get("runtime_entries") or 0) for item in cluster_nodes),
                "missing": max(0, registered_node_count - len(cluster_nodes)),
            })
            if cluster_warnings or len(cluster_nodes) != registered_node_count:
                data["backup_health"]["complete"] = False
                data["backup_health"]["warnings"].extend(cluster_warnings)
                if len(cluster_nodes) != registered_node_count and not cluster_warnings:
                    data["backup_health"]["warnings"].append(
                        f"از {registered_node_count} نود ثبت‌شده فقط {len(cluster_nodes)} بکاپ کامل دریافت شد."
                    )

    data["counts"] = {
        "admins": len(data.get("admins", [])),
        "admin_access_licenses": len(data.get("admin_access_licenses", [])),
        "telegram_admin_groups": len(data.get("telegram_admin_groups", [])),
        "telegram_group_member_rules": len(data.get("telegram_group_member_rules", [])),
        "vpn_users": len(data.get("vpn_users", [])),
        "sub_aliases": len(data.get("sub_aliases", [])),
        "banned_ips": len(data.get("banned_ips", [])),
        "internet_blocks": len(data.get("internet_blocks", [])),
        "reserved_licenses": len(data.get("reserved_licenses", [])),
        "vpn_nodes": len(data.get("vpn_nodes", [])),
        "openvpn_extra_ports": len(data.get("openvpn_extra_ports", [])),
        "cluster_nodes": len(data.get("cluster_nodes", [])),
    }
    return _attach_integrity(data)


def build_full_backup_payload(db: Session, include_cluster_nodes: bool = False) -> dict:
    """Build a complete local or cluster disaster-recovery backup.

    API/Telegram callers enable ``include_cluster_nodes``. Tests and a node
    agent's own export keep it disabled to avoid recursive controller calls.
    """
    return build_backup_payload(
        db, include_settings=True, include_cluster_nodes=include_cluster_nodes
    )



@router.post("/export/start")
def start_export_backup(
    include_settings: bool = Query(True),
    admin: Admin = Depends(require_superadmin),
):
    """Start backup generation outside the proxy request lifetime.

    Full controller backups can legitimately take longer than a reverse
    proxy's 120-second read timeout while unreachable nodes are collected.
    The browser polls this short endpoint and downloads only after the file is
    complete, so a slow node can no longer turn a healthy backup into HTTP 524.
    """
    _cleanup_backup_jobs()
    job_id = uuid.uuid4().hex
    _write_backup_job(job_id, {
        "job_id": job_id,
        "state": "queued",
        "percent": 1,
        "message": "عملیات بکاپ در صف اجرا قرار گرفت.",
        "include_settings": bool(include_settings),
        "started_at": datetime.utcnow().isoformat(),
    })
    thread = threading.Thread(
        target=_run_backup_job,
        args=(job_id, bool(include_settings), str(admin.username or "admin")),
        name=f"vpn-panel-backup-{job_id[:8]}",
        daemon=True,
    )
    thread.start()
    return {"job_id": job_id, "state": "queued", "percent": 1}


@router.get("/export/status/{job_id}")
def export_backup_status(
    job_id: str,
    admin: Admin = Depends(require_superadmin),
):
    return _read_backup_job(job_id)


@router.get("/export/download/{job_id}")
def download_export_backup(
    job_id: str,
    admin: Admin = Depends(require_superadmin),
):
    meta = _read_backup_job(job_id)
    if meta.get("state") != "success":
        raise HTTPException(409, meta.get("message") or "فایل بکاپ هنوز آماده نیست")
    _, data_path = _backup_job_paths(job_id)
    if not data_path.is_file():
        raise HTTPException(404, "فایل نهایی بکاپ پیدا نشد")
    return FileResponse(
        path=str(data_path),
        media_type="application/gzip",
        filename=str(meta.get("filename") or f"vpn-panel-backup-{job_id}.json.gz"),
        headers={
            "X-Backup-Complete": "true" if bool(meta.get("complete", True)) else "false",
            "X-Backup-Format-Version": str(meta.get("format_version") or BACKUP_FORMAT_VERSION),
            "X-Backup-Encrypted": "no",
            "X-Backup-Compression": "gzip",
            "Cache-Control": "no-store",
        },
    )


@router.get("/export")
def export_backup(
    include_settings: bool = Query(True, description="پیش‌فرض true است: تمام تنظیمات پنل و بکاپ محلی همه نودهای ثبت‌شده ضمیمه می‌شود"),
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_superadmin),
):
    data = build_backup_payload(db, include_settings, include_cluster_nodes=include_settings)

    suffix = "with-settings-" if include_settings else ""
    filename = f"vpn-panel-backup-{suffix}{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.json.gz"
    backup_content = encode_json_backup(data)

    from app.services.telegram_notifier import log_event
    log_event("بکاپ دستی بدون رمز گرفته شد", f"نوع: {'کامل (با تنظیمات)' if include_settings else 'بدون تنظیمات'}", actor=admin.username)

    backup_complete = bool((data.get("backup_health") or {}).get("complete", True))
    return Response(
        content=backup_content,
        media_type="application/gzip",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Backup-Complete": "true" if backup_complete else "false",
            "X-Backup-Format-Version": str(BACKUP_FORMAT_VERSION),
            "X-Backup-Encrypted": "no",
            "X-Backup-Compression": "gzip",
        },
    )


# ---------- وارد کردن ----------
# استراتژی روی برخورد نام‌های تکراری: «رد کردن، نه بازنویسی». اگر یوزرنیم یک
# ادمین یا کاربر VPN از قبل روی این سرور وجود داشته باشد، آن آیتم را دست‌نخورده
# رد می‌کنیم (تا مثلاً پسورد/دسترسیِ فعلیِ خودِ ادمینی که همین الان با آن
# لاگین کرده، با یک بکاپ قدیمی بازنویسی نشود) و در پاسخ گزارش می‌دهیم؛ خرابی
# یک ردیف باعث متوقف‌شدن کل عملیات نمی‌شود.
#
# فایل بکاپ خودش تعیین می‌کند وارد کردنش چه کاری انجام می‌دهد: اگر PKI/PSK
# در آن باشد (هر دو نوع بکاپ) بازیابی می‌شود؛ اگر تنظیمات هم در آن باشد
# (فقط بکاپ نوع «کامل») آن‌ها هم بازیابی می‌شوند - نیازی به پارامتر جدا نیست.
@router.post("/import")
def import_backup(
    file: UploadFile = File(...),
    restore_mode: str = Query("merge", description="merge یا replace"),
    restore_nodes: bool = Query(True, description="بازیابی بکاپ محلی نودهای ضمیمه‌شده"),
    allow_degraded: bool = Query(False, description="اجازه بازیابی دقیق از بکاپی که با هشدار ناقص علامت خورده"),
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_superadmin),
):
    actor_username = str(getattr(admin, "username", None) or "restore")
    # When called directly by tests or the authenticated Node Agent, FastAPI's
    # Query default object is not resolved. Normalize it to the API default.
    if not isinstance(restore_mode, str):
        restore_mode = "merge"
    if not isinstance(restore_nodes, bool):
        restore_nodes = True
    if not isinstance(allow_degraded, bool):
        allow_degraded = False
    restore_mode = str(restore_mode or "merge").strip().lower()
    if restore_mode not in {"merge", "replace"}:
        raise HTTPException(400, "حالت بازیابی فقط می‌تواند merge یا replace باشد")
    settings = get_settings()
    try:
        raw = file.file.read(int(settings.BACKUP_MAX_COMPRESSED_BYTES) + 1)
        if len(raw) > int(settings.BACKUP_MAX_COMPRESSED_BYTES):
            raise BackupFormatError("backup file exceeds the configured upload limit")
        decoded = decode_backup_bytes(raw)
        data = json.loads(decoded.decode("utf-8"))
    except BackupFormatError as exc:
        raise HTTPException(400, f"فایل بکاپ قابل خواندن/اعتبارسنجی نیست: {exc}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as exc:
        raise HTTPException(400, "فایل بکاپ معتبر نیست (JSON خراب است)") from exc

    if not isinstance(data, dict) or data.get("type") != "vpn-panel-backup":
        raise HTTPException(400, "این فایل یک بکاپ معتبر پنل نیست")
    backup_version = _safe_int(data.get("version"), 0)
    if backup_version <= 0:
        raise HTTPException(400, "نسخه‌ی فایل بکاپ مشخص نیست یا معتبر نیست")
    if backup_version > BACKUP_FORMAT_VERSION:
        raise HTTPException(400, "این بکاپ با نسخه‌ی جدیدتری از پنل گرفته شده و با این نسخه سازگار نیست")
    if backup_version >= 8 and (not _verify_integrity(data) or not _verify_section_counts(data)):
        raise HTTPException(
            400,
            "صحت فایل بکاپ تایید نشد؛ فایل ناقص/خراب است یا محتوا با هش و شمارش ثبت‌شده هم‌خوان نیست",
        )
    if restore_mode == "replace" and not bool(data.get("includes_settings")):
        raise HTTPException(400, "بازیابی دقیق فقط با فایل «بکاپ کامل» مجاز است؛ بکاپ بدون تنظیمات برای جایگزینی کل پنل کافی نیست")
    if restore_mode == "replace" and not allow_degraded:
        health = data.get("backup_health") or {}
        if health.get("complete") is False:
            warnings = [str(item) for item in (health.get("warnings") or []) if str(item).strip()]
            detail = " | ".join(warnings[:3])
            suffix = f" جزئیات: {detail}" if detail else ""
            raise HTTPException(400, "بازیابی دقیق از بکاپ ناقص/کاهش‌یافته متوقف شد." + suffix)
    if restore_mode == "replace":
        restorable_superadmins = [
            item for item in (data.get("admins") or [])
            if str(item.get("role") or "") == AdminRole.superadmin.value
            and bool(item.get("is_active", True))
            and bool(str(item.get("username") or "").strip())
            and bool(str(item.get("password_hash") or "").strip())
        ]
        if not restorable_superadmins:
            raise HTTPException(400, "بازیابی دقیق رد شد: فایل بکاپ ادمین اصلی فعال و قابل ورود ندارد")

    if restore_mode == "replace":
        # Exact disaster recovery intentionally replaces the current panel
        # state. Delete dependants first so restored usernames, password
        # hashes, subscription tokens and Xray UUIDs never collide with the
        # bootstrap/default rows of a fresh installation.
        try:
            for model in (
                ConnectionLog, XrayUsageCounter, VpnUserSubAlias,
                InternetBlockedIP, BannedIP, TelegramGroupLinkCode, TelegramGroupMemberRule, TelegramAdminGroup,
                AdminAccessLicense, VpnUser, VpnNode, ReservedLicense, OpenvpnExtraPort,
                Setting, Admin,
            ):
                db.query(model).delete(synchronize_session=False)
            db.commit()
            db.expire_all()
        except Exception as exc:
            db.rollback()
            raise HTTPException(500, f"پاک‌سازی امن دیتابیس قبل از بازیابی دقیق ناموفق بود: {exc}") from exc

    result = {
        "backup_encrypted": False,
        "plain_gzip_backup": True,
        "integrity_verified": backup_version >= 8,
        "restore_mode": restore_mode,
        "login_reset_required": restore_mode == "replace",
        "runtime_files_restored": 0,
        "nodes_restored": 0,
        "nodes_restore_failed": 0,
        "admins_imported": 0, "admins_skipped": 0,
        "admin_licenses_imported": 0, "admin_licenses_skipped": 0,
        "telegram_groups_imported": 0, "telegram_groups_skipped": 0,
        "telegram_group_member_rules_imported": 0, "telegram_group_member_rules_skipped": 0,
        "users_imported": 0, "users_skipped": 0,
        "sub_aliases_imported": 0, "sub_aliases_skipped": 0,
        "banned_ips_imported": 0, "banned_ips_skipped": 0,
        "internet_blocks_imported": 0, "internet_blocks_skipped": 0,
        "openvpn_ports_imported": 0, "openvpn_ports_skipped": 0,
        "nodes_imported": 0, "nodes_skipped": 0,
        "reserved_licenses_imported": 0, "reserved_licenses_skipped": 0,
        "settings_imported": 0,
        "pki_restored": False,
        "ipsec_psk_restored": False,
        "cert_errors": [],
        "openvpn_profiles_preserved_without_server_key": [],
        "warnings": [],
    }
    backup_health = data.get("backup_health") or {}
    has_runtime_identity = bool((data.get("runtime_identity") or {}).get("entries"))
    if backup_health and not bool(backup_health.get("complete", True)):
        result["warnings"].append("این فایل با وضعیت «بکاپ ناقص/کاهش‌یافته» ساخته شده است.")
        result["warnings"].extend(str(msg) for msg in (backup_health.get("warnings") or []) if msg)

    # --- نودها باید قبل از ادمین‌ها/یوزرها وارد شوند ---
    # server_targets در چند جدول شامل node:<id> است. شناسه‌های دیتابیس روی
    # سرور مقصد لزوماً برابر مبدا نیستند، بنابراین نسخه ۸ source_id را نگه
    # می‌دارد و این نگاشت همه‌ی scopeها را به id تازه بازنویسی می‌کند.
    node_id_map: dict[int, int] = {}
    existing_nodes = db.query(VpnNode).all()
    nodes_by_name = {row.name: row for row in existing_nodes}
    nodes_by_url = {str(row.api_url or "").rstrip("/"): row for row in existing_nodes}
    for item in data.get("vpn_nodes", []):
        name = str(item.get("name") or "").strip()
        url = str(item.get("api_url") or "").strip().rstrip("/")
        token = str(item.get("api_token") or "").strip()
        try:
            source_id = int(item.get("source_id")) if item.get("source_id") is not None else None
        except (TypeError, ValueError):
            source_id = None
        existing = nodes_by_name.get(name) or nodes_by_url.get(url)
        if existing:
            result["nodes_skipped"] += 1
            if source_id is not None:
                node_id_map[source_id] = existing.id
            continue
        if not name or not url or not token:
            result["nodes_skipped"] += 1
            continue
        row = VpnNode(
            name=name,
            api_url=url,
            api_token=token,
            enabled=bool(item.get("enabled", True)),
            verify_tls=bool(item.get("verify_tls", True)),
            weight=_safe_int(item.get("weight"), 100, minimum=1),
            ssh_host=item.get("ssh_host") or None,
            ssh_port=_safe_int(item.get("ssh_port"), 22, minimum=1, maximum=65535),
            ssh_username=item.get("ssh_username") or None,
            ssh_password_enc=encrypt_password(item.get("ssh_password") or None),
            panel_admin_username=item.get("panel_admin_username") or None,
            panel_admin_password_enc=encrypt_password(item.get("panel_admin_password") or None),
            remote_admin_enabled=bool(item.get("remote_admin_enabled", False)),
            user_assignment_enabled=bool(item.get("user_assignment_enabled", True)),
            node_panel_enabled=bool(item.get("node_panel_enabled", True)),
            protocol_domains=item.get("protocol_domains"),
            status="unknown",
            last_seen_at=None,
            last_error=None,
            last_snapshot=item.get("last_snapshot"),
            created_at=_parse_datetime(item.get("created_at")) or datetime.utcnow(),
            updated_at=_parse_datetime(item.get("updated_at")) or datetime.utcnow(),
        )
        db.add(row)
        db.flush()
        nodes_by_name[name] = row
        nodes_by_url[url] = row
        if source_id is not None:
            node_id_map[source_id] = row.id
        result["nodes_imported"] += 1
    db.commit()

    if data.get("vpn_nodes") and backup_version < 8:
        result["warnings"].append(
            "این بکاپ قدیمی شناسه‌ی مبدا نودها را ندارد؛ محدوده‌های server_targets "
            "ممکن است بعد از انتقال به سرور دیگری نیاز به بررسی دستی داشته باشند."
        )

    # --- ادمین‌ها ---
    # نگاشت یوزرنیم -> ردیف Admin تازه‌ساخته‌شده، برای وصل‌کردن owner_admin_id
    # یوزرهای VPN در مرحله‌ی بعد (چون id قدیمی روی سرور مقصد معنا ندارد).
    admin_by_username: dict[str, Admin] = {a.username: a for a in db.query(Admin).all()}

    for a in data.get("admins", []):
        username = (a.get("username") or "").strip()
        if not username:
            continue
        if username in admin_by_username:
            result["admins_skipped"] += 1
            continue
        role = a.get("role") or "admin"
        if role not in (AdminRole.superadmin.value, AdminRole.admin.value):
            role = "admin"
        row = Admin(
            username=username,
            password_hash=a.get("password_hash") or "",
            role=AdminRole(role),
            permissions=a.get("permissions"),
            see_all_users=bool(a.get("see_all_users") or False),
            server_targets=_rewrite_server_targets(a.get("server_targets"), node_id_map),
            max_users=a.get("max_users"),
            max_total_quota_bytes=a.get("max_total_quota_bytes"),
            subscription_expire_date=_parse_date(a.get("subscription_expire_date")),
            subscription_expire_at=_parse_datetime(a.get("subscription_expire_at")),
            managed_by_license=bool(a.get("managed_by_license", False)),
            access_license_code=a.get("access_license_code") or None,
            license_activated_at=_parse_datetime(a.get("license_activated_at")),
            license_locked=bool(a.get("license_locked", False)),
            telegram_bot_enabled=bool(a.get("telegram_bot_enabled", False)),
            telegram_user_id=(int(a["telegram_user_id"]) if a.get("telegram_user_id") else None),
            telegram_bot_opted_out=bool(a.get("telegram_bot_opted_out", False)),
            is_active=a.get("is_active", True),
            created_at=_parse_datetime(a.get("created_at")) or datetime.utcnow(),
        )
        db.add(row)
        db.flush()  # برای گرفتن id تازه بدون commit کامل
        admin_by_username[username] = row
        result["admins_imported"] += 1

    db.commit()

    # --- گروه‌های تلگرام متعلق به هر ادمین ---
    # کدهای اتصال یک‌بارمصرف عمداً بکاپ نمی‌شوند. فقط اتصال‌های تأییدشده
    # بازیابی می‌شوند و مجوزهای زنده همیشه از ردیف Admin مقصد خوانده می‌شود.
    existing_group_chat_ids = {int(row.chat_id) for row in db.query(TelegramAdminGroup).all()}
    restored_groups_by_chat_id = {int(row.chat_id): row for row in db.query(TelegramAdminGroup).all()}
    for item in data.get("telegram_admin_groups", []):
        owner = admin_by_username.get(str(item.get("owner_admin_username") or "").strip())
        try:
            chat_id = int(str(item.get("chat_id") or "").strip())
            linked_by = int(str(item.get("linked_by_telegram_user_id") or "").strip())
        except (TypeError, ValueError):
            result["telegram_groups_skipped"] += 1
            continue
        if not owner or not chat_id or not linked_by or chat_id in existing_group_chat_ids:
            result["telegram_groups_skipped"] += 1
            continue
        row = TelegramAdminGroup(
            admin_id=owner.id,
            chat_id=chat_id,
            title=(str(item.get("title") or "").strip()[:255] or None),
            chat_type=(str(item.get("chat_type") or "group").strip()[:32] or "group"),
            chat_username=(str(item.get("chat_username") or "").strip()[:255] or None),
            control_enabled=bool(item.get("control_enabled", True)),
            access_mode=(str(item.get("access_mode") or "all_members").strip() if str(item.get("access_mode") or "all_members").strip() in {"all_members", "allowlist_only"} else "all_members"),
            is_active=bool(item.get("is_active", True)),
            linked_by_telegram_user_id=linked_by,
            last_verified_at=_parse_datetime(item.get("last_verified_at")),
            last_used_at=_parse_datetime(item.get("last_used_at")),
            created_at=_parse_datetime(item.get("created_at")) or datetime.utcnow(),
        )
        db.add(row)
        existing_group_chat_ids.add(chat_id)
        restored_groups_by_chat_id[chat_id] = row
        result["telegram_groups_imported"] += 1
    db.commit()

    # --- قوانین مجاز/مسدود اعضای گروه‌های تلگرام ---
    existing_member_rule_keys = {
        (int(row.group_id), int(row.telegram_user_id))
        for row in db.query(TelegramGroupMemberRule).all()
    }
    for item in data.get("telegram_group_member_rules", []):
        try:
            group_chat_id = int(str(item.get("group_chat_id") or "").strip())
            telegram_user_id = int(str(item.get("telegram_user_id") or "").strip())
        except (TypeError, ValueError):
            result["telegram_group_member_rules_skipped"] += 1
            continue
        group = restored_groups_by_chat_id.get(group_chat_id)
        if not group or telegram_user_id <= 0 or (int(group.id), telegram_user_id) in existing_member_rule_keys:
            result["telegram_group_member_rules_skipped"] += 1
            continue
        creator = admin_by_username.get(str(item.get("created_by_admin_username") or "").strip())
        row = TelegramGroupMemberRule(
            group_id=group.id,
            telegram_user_id=telegram_user_id,
            is_allowed=bool(item.get("is_allowed", False)),
            display_name=(str(item.get("display_name") or "").strip()[:255] or None),
            telegram_username=(str(item.get("telegram_username") or "").strip().lstrip("@")[:255] or None),
            note=(str(item.get("note") or "").strip()[:500] or None),
            created_by_admin_id=(creator.id if creator else None),
            last_seen_at=_parse_datetime(item.get("last_seen_at")),
            created_at=_parse_datetime(item.get("created_at")) or datetime.utcnow(),
            updated_at=_parse_datetime(item.get("updated_at")) or datetime.utcnow(),
        )
        db.add(row)
        existing_member_rule_keys.add((int(group.id), telegram_user_id))
        result["telegram_group_member_rules_imported"] += 1
    db.commit()

    # --- لایسنس‌های داخلی ادمین ---
    existing_license_codes = {row.code for row in db.query(AdminAccessLicense.code).all()}
    for item in data.get("admin_access_licenses", []):
        code = (item.get("code") or "").strip()
        if not code or code in existing_license_codes:
            result["admin_licenses_skipped"] += 1
            continue
        used_by = admin_by_username.get(item.get("used_by_username"))
        raw_role = item.get("role") or "admin"
        try:
            license_role = AdminRole(raw_role)
        except Exception:
            license_role = AdminRole.admin
        row = AdminAccessLicense(
            code=code, role=license_role, permissions=item.get("permissions") or "",
            see_all_users=bool(item.get("see_all_users", False)),
            server_targets=_rewrite_server_targets(item.get("server_targets"), node_id_map), max_users=item.get("max_users"),
            max_total_quota_bytes=item.get("max_total_quota_bytes"), expire_mode=item.get("expire_mode") or "after_activation",
            duration_minutes=item.get("duration_minutes"), fixed_expire_at=_parse_datetime(item.get("fixed_expire_at")),
            is_active=bool(item.get("is_active", True)), used_by_admin_id=used_by.id if used_by else None,
            activated_at=_parse_datetime(item.get("activated_at")),
            telegram_bot_enabled=bool(item.get("telegram_bot_enabled", False)),
            telegram_user_id=(int(item["telegram_user_id"]) if item.get("telegram_user_id") else None),
            note=item.get("note"), created_at=_parse_datetime(item.get("created_at")) or datetime.utcnow(),
        )
        db.add(row)
        existing_license_codes.add(code)
        result["admin_licenses_imported"] += 1
    db.commit()

    # --- یوزرهای VPN ---
    existing_usernames = {u.username for u in db.query(VpnUser.username).all()}
    existing_xray_uuids = {u.xray_uuid for u in db.query(VpnUser.xray_uuid).all() if u.xray_uuid}
    existing_sub_tokens = {u.sub_token for u in db.query(VpnUser.sub_token).all() if u.sub_token}
    existing_alias_tokens_before_import = {row.token for row in db.query(VpnUserSubAlias.token).all()}
    imported_openvpn_users = []

    for u in data.get("vpn_users", []):
        username = (u.get("username") or "").strip()
        if not username:
            continue
        if username in existing_usernames:
            result["users_skipped"] += 1
            continue

        owner_username = u.get("owner_admin_username")
        owner = admin_by_username.get(owner_username) if owner_username else None
        candidate_sub_token = str(u.get("sub_token") or "").strip() or None
        if candidate_sub_token and (
            candidate_sub_token in existing_sub_tokens
            or candidate_sub_token in existing_alias_tokens_before_import
        ):
            original_sub_token = candidate_sub_token
            candidate_sub_token = uuid.uuid4().hex
            while candidate_sub_token in existing_sub_tokens or candidate_sub_token in existing_alias_tokens_before_import:
                candidate_sub_token = uuid.uuid4().hex
            result["warnings"].append(
                f"توکن اشتراک کاربر «{username}» روی مقصد تکراری بود و توکن تازه ساخته شد؛ "
                f"لینک قدیمی «{original_sub_token}» به‌علت مالک فعلی قابل انتقال نبود."
            )
        candidate_uuid = (u.get("xray_uuid") or "").strip()
        try:
            candidate_uuid = str(uuid.UUID(candidate_uuid)) if candidate_uuid else str(uuid.uuid4())
        except (ValueError, AttributeError):
            candidate_uuid = str(uuid.uuid4())
        if candidate_uuid in existing_xray_uuids:
            candidate_uuid = str(uuid.uuid4())
        existing_xray_uuids.add(candidate_uuid)

        row = VpnUser(
            username=username,
            password=u.get("password") or "",
            sub_token=candidate_sub_token,
            owner_admin_id=owner.id if owner else None,
            enable_l2tp=u.get("enable_l2tp", True),
            enable_pptp=u.get("enable_pptp", True),
            enable_openvpn=u.get("enable_openvpn", True),
            enable_sstp=u.get("enable_sstp", True),
            enable_ikev2=u.get("enable_ikev2", True),
            enable_openconnect=u.get("enable_openconnect", False),
            enable_vmess=u.get("enable_vmess", False),
            enable_vless=u.get("enable_vless", False),
            vmess_internet_blocked=bool(u.get("vmess_internet_blocked", False)),
            vless_internet_blocked=bool(u.get("vless_internet_blocked", False)),
            xray_uuid=candidate_uuid,
            openvpn_auth_mode=u.get("openvpn_auth_mode") or "cert_only",
            sstp_auth_mode=u.get("sstp_auth_mode") or "password_only",
            quota_bytes=u.get("quota_bytes") or 0,
            used_bytes=u.get("used_bytes") or 0,
            max_devices=1 if u.get("max_devices") is None else _safe_int(u.get("max_devices"), 1, minimum=0),
            speed_limit_mbps=u.get("speed_limit_mbps", 0) or 0,
            download_limit_mbps=u.get("download_limit_mbps", u.get("speed_limit_mbps", 0)) or 0,
            upload_limit_mbps=u.get("upload_limit_mbps", u.get("speed_limit_mbps", 0)) or 0,
            expire_mode=u.get("expire_mode") or "fixed",
            expire_after_days=u.get("expire_after_days"),
            first_connect_at=_parse_datetime(u.get("first_connect_at")),
            expire_date=_parse_date(u.get("expire_date")),
            is_active=u.get("is_active", True),
            note=u.get("note"),
            server_targets=_rewrite_server_targets(u.get("server_targets"), node_id_map),
            created_at=_parse_datetime(u.get("created_at")) or datetime.utcnow(),
            updated_at=_parse_datetime(u.get("updated_at")) or datetime.utcnow(),
            node_managed=bool(u.get("node_managed", False)),
            node_source=u.get("node_source"),
        )
        db.add(row)
        existing_usernames.add(username)
        if candidate_sub_token:
            existing_sub_tokens.add(candidate_sub_token)
        result["users_imported"] += 1
        if row.enable_openvpn:
            imported_openvpn_users.append(username)

    db.commit()

    # --- لینک‌های ساب قدیمی و فعلی ---
    # This also runs for users that were skipped because they already existed,
    # so restoring a backup can repair old customer URLs without replacing the
    # current account or password.
    vpn_by_username = {row.username: row for row in db.query(VpnUser).all()}
    existing_alias_tokens = {row.token for row in db.query(VpnUserSubAlias).all()}
    alias_items = list(data.get("sub_aliases") or [])
    for row in vpn_by_username.values():
        if row.sub_token:
            alias_items.append({"username": row.username, "token": row.sub_token})
    for item in alias_items:
        username = str(item.get("username") or "").strip()
        token = str(item.get("token") or "").strip()
        user_row = vpn_by_username.get(username)
        if not user_row or not token or token in existing_alias_tokens:
            result["sub_aliases_skipped"] += 1
            continue
        current_owner = db.query(VpnUser).filter(VpnUser.sub_token == token).first()
        if current_owner and current_owner.id != user_row.id:
            result["sub_aliases_skipped"] += 1
            continue
        db.add(VpnUserSubAlias(
            user_id=user_row.id, token=token,
            created_at=_parse_datetime(item.get("created_at")) or datetime.utcnow(),
        ))
        existing_alias_tokens.add(token)
        result["sub_aliases_imported"] += 1
    db.commit()

    # --- آی‌پی‌های مسدود ---
    existing_ips = {b.ip_address for b in db.query(BannedIP.ip_address).all()}
    for b in data.get("banned_ips", []):
        ip = (b.get("ip_address") or "").strip()
        if not ip:
            continue
        if ip in existing_ips:
            result["banned_ips_skipped"] += 1
            continue
        by_username = b.get("banned_by_admin_username")
        by_admin = admin_by_username.get(by_username) if by_username else None
        owner_username = b.get("owner_admin_username")
        owner_admin = admin_by_username.get(owner_username) if owner_username else by_admin
        restored_ban = ban_ip(
            db, ip, b.get("reason"), by_admin.id if by_admin else None,
            owner_admin_id=owner_admin.id if owner_admin else None,
        )
        restored_ban.created_at = _parse_datetime(b.get("created_at")) or restored_ban.created_at
        db.commit()
        existing_ips.add(ip)
        result["banned_ips_imported"] += 1

    # --- اینترنت قطع‌شده‌ها (موقت و مستقل از بن امنیتی) ---
    existing_cut_ips = {row[0] for row in db.query(InternetBlockedIP.ip_address).all()}
    for item in data.get("internet_blocks", []):
        ip = str(item.get("ip_address") or "").strip()
        if not ip or ip in existing_cut_ips:
            result["internet_blocks_skipped"] += 1
            continue
        username = str(item.get("username") or "").strip() or None
        user_row = vpn_by_username.get(username) if username else None
        by_username = str(item.get("blocked_by_admin_username") or "").strip() or None
        by_admin = admin_by_username.get(by_username) if by_username else None
        restored_cut = block_internet_ip(
            db,
            ip,
            user=user_row,
            username=username,
            protocol=item.get("protocol"),
            reason=item.get("reason"),
            admin_id=by_admin.id if by_admin else None,
            admin_username=by_username,
            owner_admin_id=(admin_by_username.get(str(item.get("owner_admin_username") or "").strip()).id
                            if str(item.get("owner_admin_username") or "").strip() in admin_by_username
                            else (user_row.owner_admin_id if user_row else (by_admin.id if by_admin else None))),
        )
        restored_cut.created_at = _parse_datetime(item.get("created_at")) or restored_cut.created_at
        db.commit()
        existing_cut_ips.add(ip)
        result["internet_blocks_imported"] += 1

    # --- لایسنس‌های رزروشده برای فعال‌سازی بعدی ---
    existing_reserved_keys = {row.key for row in db.query(ReservedLicense.key).all()}
    for item in data.get("reserved_licenses", []):
        key = str(item.get("key") or "").strip()
        if not key or key in existing_reserved_keys:
            result["reserved_licenses_skipped"] += 1
            continue
        db.add(ReservedLicense(
            key=key,
            order=_safe_int(item.get("order"), 0, minimum=0),
            added_at=_parse_datetime(item.get("added_at")) or datetime.utcnow(),
            reserved_ip=item.get("reserved_ip") or None,
        ))
        existing_reserved_keys.add(key)
        result["reserved_licenses_imported"] += 1
    db.commit()

    # --- PKI کامل OpenVPN (باید قبل از ساخت/نوشتن هر سرتیفیکیت کاربری اجرا
    # شود، چون CA/index.txt سرور مقصد را با CA سرور مبدا یکی می‌کند) ---
    pki_bundle = data.get("openvpn_pki")
    if pki_bundle:
        try:
            pki_warnings = import_pki_bundle(pki_bundle)
            result["warnings"].extend(pki_warnings)
            result["pki_restored"] = True
            # سرویس‌های OpenVPN باید با CA/سرتیفیکیت جدید بالا بیایند، وگرنه
            # تا ری‌استارت بعدی دستی همچنان CA قدیمی خودشان را نگه می‌دارند.
            for key in ("openvpn_udp", "openvpn_tcp"):
                ok, log = control_protocol_service(key, "restart")
                if not ok:
                    result["warnings"].append(f"ری‌استارت سرویس {key} بعد از بازیابی PKI ناموفق بود: {log[-300:]}")
        except Exception as e:
            result["cert_errors"].append(f"بازیابی PKI ناموفق بود: {e}")

    # --- PSK مشترک L2TP/IPsec ---
    if data.get("ipsec_psk") is not None:
        try:
            set_ipsec_psk(data["ipsec_psk"])
            result["ipsec_psk_restored"] = True
        except Exception as e:
            result["warnings"].append(f"بازیابی PSK مشترک L2TP/IPsec ناموفق بود: {e}")

    # --- هم‌گام‌سازی با سرویس‌های واقعی روی این سرور ---
    # chap-secrets (L2TP/PPTP) با همه‌ی کاربران فعلی دیتابیس بازنویسی می‌شود.
    # برای هر کاربر OpenVPN تازه‌واردشده: اگر سرتیفیکیت خودِ همان کاربر در
    # بکاپ بود (و PKI هم بازیابی شد)، همان عیناً نوشته می‌شود - یعنی همان
    # فایل .ovpn قدیمی که قبلاً دست کاربر بوده معتبر می‌ماند. در غیر این
    # صورت (کاربر بدون سرتیفیکیت در بکاپ، یا بکاپ اصلاً PKI نداشت) مثل قبل
    # یک سرتیفیکیت تازه با CA همین سرور ساخته می‌شود.
    user_certs = data.get("openvpn_user_certs") or {}
    client_records = data.get("openvpn_client_records") or {}
    if result["users_imported"] > 0:
        try:
            sync_chap_secrets(db)
        except Exception as e:
            result["cert_errors"].append(f"همگام‌سازی L2TP/PPTP ناموفق بود: {e}")

        for username in imported_openvpn_users:
            cert_data = user_certs.get(username) if pki_bundle else None
            try:
                if cert_data and cert_data.get("cert") and cert_data.get("key"):
                    write_client_cert(username, cert_data["cert"], cert_data["key"])
                elif pki_bundle and isinstance(client_records.get(username), dict) and client_records[username].get("serial"):
                    # The restored PKI/index/CRL is the authoritative server
                    # identity. Existing client profiles contain their own
                    # private key and continue working; do not attempt to issue
                    # a duplicate CN merely because the old server no longer
                    # had a convenience copy of that client-owned key.
                    result["openvpn_profiles_preserved_without_server_key"].append(username)
                else:
                    generate_client_cert(username)
            except CertError as e:
                result["cert_errors"].append(f"ساخت سرتیفیکیت OpenVPN برای «{username}» ناموفق بود: {e}")
            except Exception as e:
                result["cert_errors"].append(f"نوشتن سرتیفیکیت OpenVPN برای «{username}» ناموفق بود: {e}")

    # --- تنظیمات (فقط اگر بکاپ از نوع «کامل» بوده) ---
    settings_data = data.get("settings")
    if settings_data:
        for key, value in settings_data.items():
            if key in _SETTINGS_STATUS_KEYS and not (restore_mode == "replace" and has_runtime_identity):
                _set_setting(db, key, "not_configured")
                continue
            if key in _SETTINGS_LOG_KEYS and not (restore_mode == "replace" and has_runtime_identity):
                continue  # بکاپ قدیمی فایل‌های TLS متناظر را نداشت
            _set_setting(db, key, value)
            result["settings_imported"] += 1
        db.commit()

        portable_secrets = data.get("portable_secrets") or {}
        backup_server_password = portable_secrets.get("telegram_backup_server_password")
        if backup_server_password:
            _set_setting(
                db,
                "telegram_backup_server_password_enc",
                encrypt_password(str(backup_server_password)) or "",
            )
        node_ssh_password = portable_secrets.get("node_ssh_password")
        if node_ssh_password:
            _set_setting(
                db,
                "node_ssh_password_enc",
                encrypt_password(str(node_ssh_password)) or "",
            )
        if backup_server_password or node_ssh_password:
            db.commit()
        if not (restore_mode == "replace" and has_runtime_identity):
            result["warnings"].append(
                "این بکاپ فایل‌های کامل TLS/پروتکل را نداشت؛ وضعیت SSL روی مقصد بازنشانی شد و ممکن است نیاز به صدور مجدد گواهی باشد."
            )

        # --- پورت‌های اضافه‌ی OpenVPN ---
        existing_ports = {
            (p.port, p.protocol) for p in db.query(OpenvpnExtraPort).all()
        }
        for p in data.get("openvpn_extra_ports", []):
            port = _safe_int(p.get("port"), 0, minimum=0, maximum=65535)
            proto = str(p.get("protocol") or "").lower()
            if not port or proto not in ("tcp", "udp"):
                continue
            if (port, proto) in existing_ports:
                result["openvpn_ports_skipped"] += 1
                continue
            # بکاپ‌های قدیمی‌تر این کلید را نداشتند - پیش‌فرض فعال، مطابق
            # رفتار قبل از اضافه‌شدن مفهوم استخر/توگل.
            db.add(OpenvpnExtraPort(
                port=port, protocol=proto, is_active=p.get("is_active", True),
                created_at=_parse_datetime(p.get("created_at")) or datetime.utcnow(),
            ))
            existing_ports.add((port, proto))
            result["openvpn_ports_imported"] += 1
        db.commit()

        # --- اعمال زنده‌ی پورت/فعال‌بودن پروتکل‌ها روی این سرور، مطابق
        # همان مقادیری که همین الان در تنظیمات نوشته شد (نه دامنه‌ی
        # اختصاصی پروتکل‌ها - چون آن هم به تایید DNS جدید نیاز دارد و اینجا
        # عمداً "" پاس داده می‌شود، دقیقاً مثل زمانی که آن دامنه فعال نیست) ---
        def _bool(key, default):
            v = _get_setting(db, key)
            return (v == "1") if v is not None else default

        def _int(key, default):
            v = _get_setting(db, key)
            try:
                return int(v) if v is not None else default
            except (TypeError, ValueError):
                return default

        def _text(key, default, preserve_blank=False):
            v = _get_setting(db, key)
            if v is None or (v == "" and not preserve_blank):
                return default
            return v

        ok, log = apply_vpn_protocol_settings(
            _bool("l2tp_enabled", True), _int("l2tp_port", 1701),
            _bool("pptp_enabled", True),
            _bool("openvpn_enabled", True), _int("openvpn_udp_port", 1194), _int("openvpn_tcp_port", 1194),
            "",
            _int("l2tp_mtu", 1400), _int("l2tp_mru", 1400),
            _bool("sstp_enabled", True), _int("sstp_port", 4433),
            _bool("ikev2_enabled", True),
            _int("openconnect_port", 8443),
            _text("openconnect_dns1", "8.8.8.8"),
            _text("openconnect_dns2", "1.1.1.1", True),
            _text("openvpn_dns1", "1.1.1.1"),
            _text("openvpn_dns2", "8.8.8.8", True),
        )
        if not ok:
            result["warnings"].append(f"اعمال پورت/وضعیت پروتکل‌ها ناموفق بود: {log[-500:]}")

        ok, log = sync_openvpn_extra_ports(
            [
                (p.port, p.protocol)
                for p in db.query(OpenvpnExtraPort)
                .filter(OpenvpnExtraPort.is_active == True)  # noqa: E712
                .order_by(OpenvpnExtraPort.port)
                .all()
            ],
            _int("openvpn_udp_port", 1194), _int("openvpn_tcp_port", 1194),
        )
        if not ok:
            result["warnings"].append(f"هم‌گام‌سازی پورت‌های اضافه‌ی OpenVPN ناموفق بود: {log[-500:]}")

    # Restore the exact daemon/TLS/branding identity after generic setting
    # application so generated defaults cannot overwrite the backed-up files.
    if has_runtime_identity:
        try:
            restored_count, runtime_warnings = import_runtime_bundle(data.get("runtime_identity"), replace_existing=(restore_mode == "replace"))
            result["runtime_files_restored"] = restored_count
            result["warnings"].extend(runtime_warnings)
            result["warnings"].extend(restart_restored_runtime())
        except Exception as exc:
            result["warnings"].append(f"بازیابی فایل‌های دقیق تنظیمات/گواهی‌های سرور ناموفق بود: {exc}")

    if result["users_imported"] > 0 or settings_data or has_runtime_identity:
        try:
            # Rebuild credential stores from the restored DB after file restore.
            sync_chap_secrets(db)
        except Exception as e:
            result["cert_errors"].append(f"همگام‌سازی نهایی رمزهای پروتکل‌ها ناموفق بود: {e}")
        try:
            from app.services.xray_manager import sync_xray_users
            sync_xray_users(db, protocols=("vmess", "vless"), restart=True)
        except Exception as e:
            result["warnings"].append(f"همگام‌سازی VMess/VLESS بعد از بازیابی انجام نشد: {e}")

    # Push each embedded node-local backup back to the matching restored node.
    if restore_nodes and data.get("cluster_nodes"):
        nodes_by_id = {row.id: row for row in db.query(VpnNode).all()}
        nodes_by_name = {row.name: row for row in nodes_by_id.values()}
        nodes_by_url = {str(row.api_url or "").rstrip("/"): row for row in nodes_by_id.values()}
        for item in data.get("cluster_nodes") or []:
            node = None
            try:
                source_id = int(item.get("source_id")) if item.get("source_id") is not None else None
            except (TypeError, ValueError):
                source_id = None
            if source_id is not None and source_id in node_id_map:
                node = nodes_by_id.get(node_id_map[source_id])
            node = node or nodes_by_name.get(str(item.get("name") or ""))
            node = node or nodes_by_url.get(str(item.get("api_url") or "").rstrip("/"))
            inner = item.get("backup")
            if not node or not isinstance(inner, dict):
                result["nodes_restore_failed"] += 1
                result["warnings"].append(f"بکاپ محلی نود «{item.get('name') or 'نامشخص'}» به نود مقصد نگاشت نشد.")
                continue
            try:
                response = requests.post(
                    f"{node.api_url.rstrip('/')}/api/node-agent/backup/import",
                    params={"restore_mode": "replace", "restore_nodes": "false"},
                    data=gzip.compress(json.dumps(inner, ensure_ascii=False, separators=(",", ":")).encode("utf-8"), compresslevel=6),
                    headers={
                        "X-Node-Token": node.api_token,
                        "Content-Type": "application/json",
                        "Content-Encoding": "gzip",
                    },
                    timeout=240,
                    verify=bool(getattr(node, "verify_tls", True)),
                )
                response.raise_for_status()
                body = response.json()
                if not bool(body.get("ok")):
                    raise ValueError(body.get("detail") or "پاسخ بازیابی نود موفق نبود")
                result["nodes_restored"] += 1
            except Exception as exc:
                result["nodes_restore_failed"] += 1
                result["warnings"].append(f"بازیابی کامل نود «{node.name}» ناموفق بود: {exc}")
        try:
            from app.services.node_manager import sync_all_nodes_async
            sync_all_nodes_async()
        except Exception as exc:
            result["warnings"].append(f"شروع همگام‌سازی نهایی نودها ناموفق بود: {exc}")

    from app.services.telegram_notifier import log_event
    log_event(
        "وارد کردن فایل بکاپ",
        f"ادمین‌ها: +{result['admins_imported']} | یوزرها: +{result['users_imported']} | "
        f"آی‌پی‌های مسدود: +{result['banned_ips_imported']} | "
        f"اینترنت قطع‌شده‌ها: +{result['internet_blocks_imported']}"
        + (" | ⚠ با خطا/هشدار" if (result["cert_errors"] or result["warnings"]) else ""),
        actor=actor_username,
    )

    return {"ok": True, **result}


# ---------- کانال لاگ و کانال بکاپ تلگرام ----------
# تنظیمات این دو کاملاً مستقل از هم‌اند و هر کدام جدا فعال/غیرفعال می‌شوند:
#   - کانال لاگ: هر اتفاق داخل پنل (لاگین، ساخت/ویرایش/حذف یوزر یا ادمین،
#     تغییر تنظیمات، مسدودسازی آی‌پی، گرفتن/وارد کردن بکاپ و ...) به‌محض وقوع
#     به این چت/کانال ارسال می‌شود.
#   - کانال بکاپ: هر «تعیین تایم» (پیش‌فرض هر ۶ ساعت) یک فایل بکاپ کامل
#     (شامل تنظیمات) خودکار برای این چت/کانال فرستاده می‌شود؛ جدا از این،
#     همین‌جا یک دکمه‌ی «ارسال بکاپ همین الان» هم برای تست/بکاپ فوری هست.
from pydantic import BaseModel as _BaseModel, Field as _Field

from app.services import telegram_notifier as _tg
from app.services.telegram_media_layout import normalize_main_menu_gif_bytes


class TelegramSettingsIn(_BaseModel):
    bot_token: str | None = None
    log_chat_id: str | None = None
    log_enabled: bool | None = None
    conn_log_chat_id: str | None = None
    conn_log_enabled: bool | None = None
    backup_chat_id: str | None = None
    backup_enabled: bool | None = None
    backup_interval_hours: int | None = _Field(default=None, ge=1, le=168)
    backup_daily_hour: int | None = _Field(default=None, ge=0, le=23)
    backup_server_password: str | None = _Field(default=None, max_length=512)
    clear_backup_server_password: bool = False
    control_enabled: bool | None = None
    control_chat_id: str | None = _Field(default=None, max_length=128)
    control_allowed_user_ids: str | None = _Field(default=None, max_length=1024)


@router.get("/telegram-settings")
def get_telegram_settings(db: Session = Depends(get_db), admin: Admin = Depends(require_superadmin)):
    return _tg.get_telegram_config(db)


@router.post("/telegram-settings")
def save_telegram_settings(
    payload: TelegramSettingsIn,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_superadmin),
):
    current = _tg.get_telegram_config(db)
    next_token = payload.bot_token.strip() if payload.bot_token is not None else current["bot_token"]
    next_control_chat = payload.control_chat_id.strip() if payload.control_chat_id is not None else current.get("control_chat_id", "")
    if payload.control_enabled is True and not next_token:
        raise HTTPException(400, "برای فعال‌کردن ربات کنترل، توکن ربات لازم است")
    if payload.control_enabled is True and not next_control_chat:
        raise HTTPException(400, "برای فعال‌کردن ربات کنترل، شناسه چت کنترل لازم است")

    _tg.set_telegram_config(
        db,
        bot_token=payload.bot_token,
        log_chat_id=payload.log_chat_id,
        log_enabled=payload.log_enabled,
        conn_log_chat_id=payload.conn_log_chat_id,
        conn_log_enabled=payload.conn_log_enabled,
        backup_chat_id=payload.backup_chat_id,
        backup_enabled=payload.backup_enabled,
        backup_interval_hours=payload.backup_interval_hours,
        backup_daily_hour=payload.backup_daily_hour,
        backup_server_password=payload.backup_server_password,
        clear_backup_server_password=payload.clear_backup_server_password,
        control_enabled=payload.control_enabled,
        control_chat_id=payload.control_chat_id,
        control_allowed_user_ids=payload.control_allowed_user_ids,
    )
    return _tg.get_telegram_config(db)



_TELEGRAM_MEDIA_DIR = Path(os.environ.get("VPN_PANEL_TELEGRAM_MEDIA_DIR", "/opt/vpn-panel/data/telegram-media"))
_TELEGRAM_MEDIA_SLOTS = {
    "main_menu": (
        _tg.KEY_MEDIA_MAIN_MENU_PATH, _tg.KEY_MEDIA_MAIN_MENU_TYPE,
        _tg.KEY_MEDIA_MAIN_MENU_FILE_ID, _tg.KEY_MEDIA_MAIN_MENU_FINGERPRINT,
    ),
    "user_created": (
        _tg.KEY_MEDIA_USER_CREATED_PATH, _tg.KEY_MEDIA_USER_CREATED_TYPE,
        _tg.KEY_MEDIA_USER_CREATED_FILE_ID, _tg.KEY_MEDIA_USER_CREATED_FINGERPRINT,
    ),
    "user_deleted": (
        _tg.KEY_MEDIA_USER_DELETED_PATH, _tg.KEY_MEDIA_USER_DELETED_TYPE,
        _tg.KEY_MEDIA_USER_DELETED_FILE_ID, _tg.KEY_MEDIA_USER_DELETED_FINGERPRINT,
    ),
}
_TELEGRAM_MEDIA_MIMES = {
    "image/jpeg": ("photo", ".jpg"),
    "image/png": ("photo", ".png"),
    "image/webp": ("photo", ".webp"),
    "image/gif": ("animation", ".gif"),
    "video/mp4": ("animation", ".mp4"),
}


def _media_slot(slot: str):
    value = _TELEGRAM_MEDIA_SLOTS.get(str(slot or "").strip().lower())
    if not value:
        raise HTTPException(404, "نوع رسانه تلگرام معتبر نیست")
    return value


@router.post("/telegram-settings/media/{slot}")
async def upload_telegram_media(
    slot: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_superadmin),
):
    path_key, type_key, file_id_key, fingerprint_key = _media_slot(slot)
    mime = str(file.content_type or "").lower()
    if mime not in _TELEGRAM_MEDIA_MIMES:
        raise HTTPException(400, "فقط JPG، PNG، WEBP، GIF یا MP4 مجاز است")
    media_type, suffix = _TELEGRAM_MEDIA_MIMES[mime]
    content = await file.read(20 * 1024 * 1024 + 1)
    if not content:
        raise HTTPException(400, "فایل خالی است")
    if len(content) > 20 * 1024 * 1024:
        raise HTTPException(413, "حجم فایل بیشتر از ۲۰ مگابایت است")
    if str(slot or "").strip().lower() == "main_menu" and mime == "image/gif":
        content = normalize_main_menu_gif_bytes(content)
    _TELEGRAM_MEDIA_DIR.mkdir(parents=True, exist_ok=True)
    target = _TELEGRAM_MEDIA_DIR / f"{slot}{suffix}"
    for candidate in _TELEGRAM_MEDIA_DIR.glob(f"{slot}.*"):
        try:
            candidate.unlink()
        except OSError:
            pass
    target.write_bytes(content)
    os.chmod(target, 0o640)
    for key, value in (
        (path_key, str(target)), (type_key, media_type),
        (file_id_key, ""), (fingerprint_key, ""),
    ):
        row = db.query(Setting).filter(Setting.key == key).first()
        if row:
            row.value = value
        else:
            db.add(Setting(key=key, value=value))
    db.commit()
    return _tg.get_telegram_config(db)


@router.delete("/telegram-settings/media/{slot}")
def delete_telegram_media(
    slot: str,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_superadmin),
):
    path_key, type_key, file_id_key, fingerprint_key = _media_slot(slot)
    current = db.query(Setting).filter(Setting.key == path_key).first()
    if current and current.value:
        try:
            Path(current.value).unlink(missing_ok=True)
        except OSError:
            pass
    for key in (path_key, type_key, file_id_key, fingerprint_key):
        row = db.query(Setting).filter(Setting.key == key).first()
        if row:
            row.value = ""
    db.commit()
    return _tg.get_telegram_config(db)


@router.post("/telegram-settings/test-log")
def test_telegram_log(db: Session = Depends(get_db), admin: Admin = Depends(require_superadmin)):
    cfg = _tg.get_telegram_config(db)
    if not cfg["bot_token"] or not cfg["log_chat_id"]:
        raise HTTPException(400, "اول توکن ربات و آیدی کانال لاگ را ذخیره کنید")
    ok, err = _tg.send_text(
        cfg["bot_token"], cfg["log_chat_id"],
        "✅ این یک پیام تستی از پنل VPN است. کانال لاگ درست تنظیم شده.",
    )
    if not ok:
        raise HTTPException(400, f"ارسال پیام تست ناموفق بود: {err}")
    return {"ok": True}


@router.post("/telegram-settings/test-conn-log")
def test_telegram_conn_log(db: Session = Depends(get_db), admin: Admin = Depends(require_superadmin)):
    cfg = _tg.get_telegram_config(db)
    chat_id = cfg["conn_log_chat_id"] or cfg["log_chat_id"]
    if not cfg["bot_token"] or not chat_id:
        raise HTTPException(400, "اول توکن ربات و آیدی کانال اتصالات (یا کانال لاگ اصلی) را ذخیره کنید")
    ok, err = _tg.send_text(
        cfg["bot_token"], chat_id,
        "✅ این یک پیام تستی از پنل VPN است. کانال لاگِ اتصال/قطع‌اتصال درست تنظیم شده.",
    )
    if not ok:
        raise HTTPException(400, f"ارسال پیام تست ناموفق بود: {err}")
    return {"ok": True}




@router.post("/telegram-settings/test-control")
def test_telegram_control(db: Session = Depends(get_db), admin: Admin = Depends(require_superadmin)):
    cfg = _tg.get_telegram_config(db)
    if not cfg["bot_token"]:
        raise HTTPException(400, "اول توکن ربات را ذخیره کنید")
    chat_id = cfg.get("control_chat_id")
    if not chat_id and bool(getattr(admin, "telegram_bot_enabled", False)) and getattr(admin, "telegram_user_id", None):
        chat_id = str(admin.telegram_user_id)
    if not chat_id:
        linked = (
            db.query(Admin)
            .filter(
                Admin.telegram_bot_enabled == True,  # noqa: E712
                Admin.telegram_user_id.isnot(None),
                Admin.is_active == True,  # noqa: E712
            )
            .order_by(Admin.role.asc(), Admin.id.asc())
            .first()
        )
        if linked:
            chat_id = str(linked.telegram_user_id)
    if not chat_id:
        raise HTTPException(400, "آیدی چت کنترل یا آیدی عددی تلگرام یک ادمین فعال را ثبت کنید")
    ok, err = _tg.send_text(
        cfg["bot_token"],
        chat_id,
        "✅ پیام تست اعلان تلگرام VPN Panel؛ ارسال پیام مستقیم فعال است.\n"
        "مدیریت فروش و سرویس‌ها از ربات مستقل VPN Control Center انجام می‌شود.",
    )
    if not ok:
        raise HTTPException(400, f"ارسال پیام تست اعلان ناموفق بود: {err}")
    return {"ok": True}


@router.post("/telegram-settings/send-backup-now")
def send_backup_now(db: Session = Depends(get_db), admin: Admin = Depends(require_superadmin)):
    cfg = _tg.get_telegram_config(db)
    if not cfg["bot_token"] or not cfg["backup_chat_id"]:
        raise HTTPException(400, "اول توکن ربات و آیدی کانال بکاپ را ذخیره کنید")
    ok, err = _tg.send_backup_to_telegram(db=db, manual=True)
    if not ok:
        raise HTTPException(400, f"ارسال بکاپ ناموفق بود: {err}")
    latest = _tg.get_telegram_config(db)
    return {
        "ok": True,
        "sent_at": latest["backup_last_sent_at"],
        "backup_complete": latest.get("backup_last_health_complete", True),
        "warnings": latest.get("backup_last_health_warnings", []),
    }


# ---------- آپدیت پنل از طریق سرور لایسنس ----------
# جدا از بکاپ/وارد کردن بالا: این بخش کل نصب پنل (بک‌اند + فرانت‌اند +
# اسکریپت‌های install) را از پنل لایسنس می‌گیرد و روی سرور اعمال می‌کند - بدون
# دست زدن به دیتابیس، کاربرها، سرتیفیکیت‌های OpenVPN، PSK مشترک L2TP/IPsec یا
# دامنه/SSL. منطق واقعی در app.services.update_manager است؛ این‌جا فقط سه
# endpoint نازک برای فرانت‌اند (بررسی نسخه، شروع آپدیت، وضعیت لحظه‌ای).

@router.get("/update/check")
def check_for_update(db: Session = Depends(get_db), admin: Admin = Depends(require_superadmin)):
    return update_manager.check_latest(db)


@router.post("/update/start")
def start_panel_update(db: Session = Depends(get_db), admin: Admin = Depends(require_superadmin)):
    result = update_manager.start_update(db)
    from app.services.telegram_notifier import log_event
    log_event("شروع آپدیت پنل از سرور لایسنس", "", actor=admin.username)
    return result


@router.get("/update/status")
def panel_update_status(admin: Admin = Depends(require_superadmin)):
    return update_manager.get_status()


@router.get("/update/log")
def panel_update_log(admin: Admin = Depends(require_superadmin)):
    return update_manager.get_log()
