import secrets
import re
import json
import logging
import threading
from datetime import date, datetime, timedelta, timezone
from fastapi import APIRouter, Depends, HTTPException, Response, Request
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db, SessionLocal
from app.models import VpnUser, VpnUserSubAlias, ConnectionLog, Admin, AdminRole, Setting, XrayUsageCounter, VpnNode
from app.schemas import VpnUserCreate, VpnUserUpdate, VpnUserOut, BulkUserIncreaseRequest, BulkUserIncreaseResult, SubAliasRequest
from app.security import require_permission, can_view_all_users, ensure_user_protocols, admin_can_access_protocol
from app.services.vpn_manager import (
    sync_chap_secrets, kill_ppp_session, kill_openvpn_session, kill_single_ppp_session, build_client_ovpn,
    ban_ip, block_internet_ip, kill_ikev2_session, kill_openconnect_session, kill_sstp_session,
    kill_single_sstp_session, kill_single_openvpn_session,
    kill_single_ikev2_session, kill_single_openconnect_session,
)
from app.services.cert_manager import (
    generate_client_cert, get_client_profile_credentials,
    revoke_client_cert, ensure_controller_openvpn_pki, CertError,
)
from app.services.sub_link import build_sub_link
from app.services.telegram_notifier import log_event
from app.services.xray_manager import (
    sync_xray_users, disconnect_xray_session, build_uri, set_xray_internet_block,
)
from app.services.rate_limiter import apply_session_limits, reconcile_shared_rate_limits
from app.services.bulk_users import apply_bulk_increase
from app.services.node_manager import sync_all_nodes_async, sync_global_controls_to_active_nodes_async, openvpn_remotes
from app.services.server_targets import serialize_targets, validate_target_tokens, user_selected_for_local, available_target_tokens, local_assignment_enabled, admin_can_access_target, targets_for_user, globally_assignable_tokens
from app.services.online_sessions import refresh_local_ppp_presence, server_datetime_payload

router = APIRouter(prefix="/api/users", tags=["users"])
logger = logging.getLogger("vpn-panel.users")

GB = 1_073_741_824


_USER_UPDATE_SYNC_LOCK = threading.Lock()


def _run_user_post_update_sync(user_id: int, *, sync_xray: bool) -> None:
    """Apply daemon/firewall side effects after the HTTP response is sent.

    User edits used to block until PPP files, certificates, nftables and Xray
    restarts had all completed. On small servers this routinely kept the edit
    modal open for 20-30 seconds. The database is already authoritative after
    commit, so slow service reconciliation is serialized in a daemon thread
    with its own SQLAlchemy session. Periodic reconcilers remain the fallback
    if the process is restarted before this best-effort worker finishes.
    """
    with _USER_UPDATE_SYNC_LOCK:
        db = SessionLocal()
        try:
            user = db.query(VpnUser).filter(VpnUser.id == user_id).first()
            if not user:
                return

            sessions = (
                db.query(ConnectionLog)
                .filter(ConnectionLog.user_id == user.id, ConnectionLog.is_online == True)  # noqa: E712
                .all()
            )
            for active_session in sessions:
                try:
                    apply_session_limits(user, active_session)
                except Exception as exc:
                    logger.exception(
                        "Session-limit sync failed after updating %s (%s): %s",
                        user.username, active_session.id, exc,
                    )

            try:
                sync_chap_secrets(db)
            except Exception as exc:
                logger.exception("PPP sync failed after updating %s: %s", user.username, exc)

            if user.enable_openvpn:
                try:
                    generate_client_cert(user.username)
                except CertError as exc:
                    logger.exception("OpenVPN certificate failed after updating %s: %s", user.username, exc)

            if sync_xray:
                try:
                    sync_xray_users(db, protocols=("vmess", "vless"), restart=True)
                except Exception as exc:
                    if user.enable_vmess or user.enable_vless:
                        logger.exception("Xray sync failed after updating %s: %s", user.username, exc)

            try:
                reconcile_shared_rate_limits(db, force=True)
            except Exception as exc:
                logger.exception("Rate-limit sync failed after updating %s: %s", user.username, exc)

            if not user.is_active or not local_assignment_enabled(db) or not user_selected_for_local(user):
                kill_ppp_session(db, user.username)
                kill_sstp_session(db, user.username)
                kill_openvpn_session(user.username)
                kill_ikev2_session(db, user.username)
                kill_openconnect_session(user.username)
                disconnect_xray_session(db, user.username)
        except Exception as exc:
            logger.exception("Background user reconciliation failed for id=%s: %s", user_id, exc)
        finally:
            db.close()

        sync_all_nodes_async()


def _schedule_user_post_update_sync(user_id: int, *, sync_xray: bool) -> None:
    threading.Thread(
        target=_run_user_post_update_sync,
        kwargs={"user_id": user_id, "sync_xray": sync_xray},
        daemon=True,
        name=f"vpn-user-sync-{user_id}",
    ).start()


def _ensure_sub_token(u: VpnUser, db: Session) -> None:
    """کاربرهایی که پیش از اضافه‌شدن قابلیت لینک اشتراک ساخته شده‌اند، ستون
    sub_token خالی دارند؛ همین‌جا (اولین‌بار که دیده می‌شوند) برایشان یک
    توکن یکتا ساخته و ذخیره می‌شود تا لینک اشتراک همیشه در دسترس باشد."""
    if u.sub_token:
        return
    u.sub_token = secrets.token_urlsafe(24)
    db.commit()
    db.refresh(u)


def _request_origin(request: Request | None) -> str | None:
    if request is None:
        return None
    proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "http").split(",", 1)[0].strip().lower()
    host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc).split(",", 1)[0].strip()
    if proto not in {"http", "https"} or not host or not re.fullmatch(r"[A-Za-z0-9.\-:\[\]]+", host):
        return None
    return f"{proto}://{host}"


USER_PROTOCOL_KEYS = ("l2tp", "pptp", "openvpn", "sstp", "ikev2", "openconnect", "vmess", "vless")



def _parse_utc_stamp(value):
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo is None else value.astimezone(timezone.utc).replace(tzinfo=None)
    try:
        raw = str(value).strip().replace("Z", "+00:00")
        stamp = datetime.fromisoformat(raw)
        if stamp.tzinfo is not None:
            stamp = stamp.astimezone(timezone.utc).replace(tzinfo=None)
        return stamp
    except Exception:
        return None


def _user_activity_map(db: Session, admin: Admin, users: list[VpnUser]) -> dict[str, dict]:
    result = {u.username: {"online": False, "last": None} for u in users}
    by_id = {int(u.id): u for u in users}
    ids = list(by_id)
    if ids:
        for user_id, stamp in (db.query(ConnectionLog.user_id, func.max(ConnectionLog.connect_time)).filter(ConnectionLog.user_id.in_(ids)).group_by(ConnectionLog.user_id).all()):
            user = by_id.get(int(user_id))
            if user:
                result[user.username]["last"] = stamp
        for user_id, in db.query(ConnectionLog.user_id).filter(ConnectionLog.user_id.in_(ids), ConnectionLog.is_online == True, ConnectionLog.device_limit_blocked == False).distinct().all():  # noqa: E712
            user = by_id.get(int(user_id))
            if user:
                result[user.username]["online"] = True
    for node in db.query(VpnNode).filter(VpnNode.enabled == True).all():  # noqa: E712
        if not admin_can_access_target(admin, f"node:{int(node.id)}") or not node.last_snapshot:
            continue
        try:
            snap = json.loads(node.last_snapshot or "{}")
        except Exception:
            continue
        # A node can remain marked online for a short period after its agent
        # stops reporting. Never surface stale cached sessions as "online" in
        # the users table; this was the reason the connection column sometimes
        # disagreed with the live-sessions page.
        if not isinstance(snap, dict) or not _node_snapshot_is_fresh(snap, max_age_seconds=20.0):
            continue
        runtime = snap.get("user_runtime") if isinstance(snap.get("user_runtime"), dict) else {}
        for username, item in runtime.items():
            if username not in result or not isinstance(item, dict):
                continue
            remote = _parse_utc_stamp(item.get("last_connection_at"))
            if remote and (result[username]["last"] is None or remote > result[username]["last"]):
                result[username]["last"] = remote
            if node.status == "online" and bool(item.get("is_online")):
                result[username]["online"] = True
        if node.status == "online":
            for group in snap.get("online_users") or []:
                username = str(group.get("username") or "") if isinstance(group, dict) else ""
                if username in result:
                    result[username]["online"] = True
    return result

def _to_out(u: VpnUser, db: Session, request: Request | None = None, admin: Admin | None = None, activity: dict | None = None) -> VpnUserOut:
    _ensure_sub_token(u, db)
    activity = activity or ({u.username: {"online": False, "last": None}} if admin is None else _user_activity_map(db, admin, [u]))
    state = activity.get(u.username, {})
    online = bool(state.get("online"))
    is_expired = u.expire_date is not None and u.expire_date < date.today()
    expire_pending = u.expire_mode == "after_first_connect" and u.first_connect_at is None
    usage_percent = (u.used_bytes / u.quota_bytes * 100) if u.quota_bytes > 0 else 0
    out = VpnUserOut.model_validate(u)
    out.is_online = online
    last_stamp = state.get("last")
    if last_stamp:
        out.last_connection_at, out.last_connection_at_display = server_datetime_payload(db, last_stamp)
    out.is_expired = is_expired
    out.expire_pending = expire_pending
    out.usage_percent = round(min(usage_percent, 100), 1)
    out.owner_admin_username = u.owner_admin.username if u.owner_admin else None
    origin = _request_origin(request)
    # دامنه مستقل اشتراک همیشه اولویت دارد؛ دامنه پنل فقط fallback است.
    configured_sub_link = build_sub_link(db, u.sub_token, request_origin=origin) if u.sub_token else None
    out.sub_link = configured_sub_link or (f"{origin}/sub/{u.sub_token}" if origin and u.sub_token else None)

    if admin is not None and admin.role != AdminRole.superadmin:
        # Do not reveal protocols outside the delegated admin's license scope,
        # even through raw API responses or users that were previously edited
        # by a higher-level administrator.
        for protocol in USER_PROTOCOL_KEYS:
            if not admin_can_access_protocol(admin, protocol):
                setattr(out, f"enable_{protocol}", False)

        visible_targets = set(available_target_tokens(db, admin))
        raw_targets = set(targets_for_user(u))
        if "all" in raw_targets:
            # "all" is safe as a UI shorthand: the server-target endpoint only
            # returns this admin's own visible targets. Hidden node names/IDs are
            # never serialized to the delegated client.
            out.server_targets = ["all"] if visible_targets else []
        else:
            out.server_targets = sorted(raw_targets & visible_targets)
    return out


def _node_snapshot_is_fresh(snapshot: dict, max_age_seconds: float = 12.0) -> bool:
    raw = snapshot.get("generated_at")
    if not raw:
        return True
    try:
        stamp = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        if stamp.tzinfo is not None:
            stamp = stamp.astimezone(timezone.utc).replace(tzinfo=None)
        return (datetime.utcnow() - stamp).total_seconds() <= max_age_seconds
    except Exception:
        return False


def _remote_online_usernames(db: Session, admin: Admin) -> set[str]:
    """Return users with at least one live session on an accessible online node.

    The users table previously checked only this controller's ConnectionLog
    rows, while the online-users page also merged Node Agent snapshots. That
    made a user connected through a node appear without the green presence dot.
    Ignore snapshots from nodes already marked offline so an old cached session
    cannot keep a disconnected user online in either view.
    """
    usernames: set[str] = set()
    nodes = (
        db.query(VpnNode)
        .filter(VpnNode.enabled == True, VpnNode.status == "online")  # noqa: E712
        .all()
    )
    for node in nodes:
        token = f"node:{int(node.id)}"
        if not admin_can_access_target(admin, token) or not node.last_snapshot:
            continue
        try:
            snapshot = json.loads(node.last_snapshot)
        except Exception:
            continue
        if not isinstance(snapshot, dict) or not _node_snapshot_is_fresh(snapshot):
            continue
        for group in snapshot.get("online_users") or []:
            if not isinstance(group, dict):
                continue
            sessions = group.get("sessions") or []
            has_visible_session = any(
                isinstance(session, dict) and not bool(session.get("device_limit_blocked"))
                for session in sessions
            )
            username = str(group.get("username") or "").strip()
            if username and has_visible_session:
                usernames.add(username)
    return usernames


def _owned_query(db: Session, admin: Admin):
    """کوئری پایه‌ی یوزرهای VPN که این ادمین اجازه‌ی دیدن آن‌ها را دارد:
    superadmin و ادمین‌های see_all_users همه را می‌بینند، بقیه فقط یوزرهایی
    که owner_admin_id آن‌ها خودشان هستند."""
    q = db.query(VpnUser)
    if not can_view_all_users(admin):
        q = q.filter(VpnUser.owner_admin_id == admin.id)
    return q


def _get_owned_user(db: Session, admin: Admin, user_id: int) -> VpnUser:
    u = _owned_query(db, admin).filter(VpnUser.id == user_id).first()
    if not u:
        raise HTTPException(404, "کاربر پیدا نشد")
    return u


def _check_admin_limits(db: Session, admin: Admin, extra_quota_bytes: int, is_new_user: bool) -> None:
    """سقف‌های تعیین‌شده توسط superadmin برای این ادمین زیرمجموعه را چک می‌کند:
    تاریخ انقضای اشتراک خودش، حداکثر تعداد یوزر، و حداکثر مجموع حجم بین
    یوزرهایش. superadmin هیچ سقفی ندارد. extra_quota_bytes یعنی چقدر حجم
    جدید/اضافه در حال تخصیص است (برای ساخت یوزر جدید = quota کامل کاربر جدید؛
    برای افزایش quota یک یوزر موجود = فقط میزان افزایش)."""
    if admin.role != AdminRole.admin:
        return

    exact_expire = getattr(admin, 'subscription_expire_at', None)
    if bool(getattr(admin, 'license_locked', False)) or (exact_expire and exact_expire <= datetime.utcnow()) or (not exact_expire and admin.subscription_expire_date and admin.subscription_expire_date < date.today()):
        raise HTTPException(423, "اشتراک مدیریتی شما منقضی شده است؛ لایسنس داخلی جدید را فعال کنید")

    if is_new_user and admin.max_users is not None:
        current_count = db.query(VpnUser).filter(VpnUser.owner_admin_id == admin.id).count()
        if current_count >= admin.max_users:
            raise HTTPException(
                400,
                f"به سقف مجاز تعداد کاربر رسیده‌اید ({admin.max_users} کاربر)",
            )

    if admin.max_total_quota_bytes is not None:
        # مبنای سقف حجم کل ادمین، مصرف *واقعی* (used_bytes) کاربرانش است، نه
        # مجموع quota_bytes ای که برایشان تنظیم شده. یعنی صرفِ اینکه ادمین
        # برای یک کاربر مثلاً ۱۰۰ گیگ حجم تعیین کند ولی آن کاربر هنوز مصرفی
        # نداشته باشد، چیزی از سقف/پول حجمی ادمین کم نمی‌کند؛ فقط وقتی کاربران
        # واقعاً ترافیک مصرف کنند این سقف پر می‌شود. بنابراین extra_quota_bytes
        # (حجم تازه‌تخصیص‌یافته) در این چک لحاظ نمی‌شود و صرفاً بررسی می‌شود که
        # مصرف واقعیِ فعلیِ مجموع کاربران از سقف رد نشده باشد.
        used = (
            db.query(func.coalesce(func.sum(VpnUser.used_bytes), 0))
            .filter(VpnUser.owner_admin_id == admin.id)
            .scalar()
        ) or 0
        if int(used) >= admin.max_total_quota_bytes:
            raise HTTPException(
                400,
                "مصرف واقعی کل کاربران شما به سقف مجاز حجم رسیده است؛ برای افزایش این سقف با ادمین اصلی تماس بگیرید",
            )


@router.get("", response_model=list[VpnUserOut])
def list_users(request: Request, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("users:view", "users"))):
    # Validate pppd/interface state immediately so a missed ip-down hook cannot
    # leave the green presence dot visible until a later scheduler pass.
    refresh_local_ppp_presence(db)
    users = _owned_query(db, admin).order_by(VpnUser.created_at.desc()).all()
    activity = _user_activity_map(db, admin, users)
    return [_to_out(u, db, request, admin, activity) for u in users]


@router.get("/server-targets")
def user_server_targets(
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("users:view", "users")),
):
    role_row = db.query(Setting).filter(Setting.key == "server_role").first()
    local_name = "سرور اصلی" if not role_row or role_row.value != "node" else "این سرور"
    allowed = set(available_target_tokens(db, admin))
    targets = []
    if "local" in allowed:
        targets.append({
            "id": "local", "name": local_name, "local": True,
            "status": "online", "enabled": True,
        })
    for row in db.query(VpnNode).filter(VpnNode.enabled == True, VpnNode.user_assignment_enabled == True).order_by(VpnNode.id).all():  # noqa: E712
        token = f"node:{row.id}"
        if token not in allowed:
            continue
        targets.append({
            "id": token, "node_id": row.id, "name": row.name, "local": False,
            "status": row.status or "unknown", "enabled": True,
        })
    return {"targets": targets}




@router.post("/bulk-increase", response_model=BulkUserIncreaseResult)
def bulk_increase_users(
    payload: BulkUserIncreaseRequest,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("users:edit", "users")),
):
    """Add quota and/or service days to a selected group of owned users."""
    query = _owned_query(db, admin)
    if payload.scope == "active":
        query = query.filter(VpnUser.is_active == True)  # noqa: E712
    elif payload.scope == "inactive":
        query = query.filter(VpnUser.is_active == False)  # noqa: E712
    elif payload.scope == "created_range":
        start = datetime.combine(payload.created_from, datetime.min.time())
        end = datetime.combine(payload.created_to + timedelta(days=1), datetime.min.time())
        query = query.filter(VpnUser.created_at >= start, VpnUser.created_at < end)

    users = query.order_by(VpnUser.id).all()
    if not users:
        raise HTTPException(404, "هیچ کاربری با فیلتر انتخاب‌شده پیدا نشد")

    add_bytes = int(payload.quota_gb * GB)
    if add_bytes > 0:
        _check_admin_limits(db, admin, extra_quota_bytes=add_bytes * len(users), is_new_user=False)

    result = apply_bulk_increase(
        users, quota_gb=payload.quota_gb, days=payload.days, reactivate=payload.reactivate
    )
    db.commit()

    if result["reactivated"]:
        try:
            sync_chap_secrets(db)
        except Exception as exc:
            raise HTTPException(500, f"افزایش اعمال شد اما همگام‌سازی کاربران PPP ناموفق بود: {exc}")
        try:
            sync_xray_users(db, protocols=("vmess", "vless"), restart=True)
        except Exception as exc:
            raise HTTPException(500, f"افزایش اعمال شد اما همگام‌سازی Xray ناموفق بود: {exc}")

    reconcile_shared_rate_limits(db, force=True)
    sync_all_nodes_async()
    log_event(
        "📈 افزایش گروهی کاربران",
        f"فیلتر: {payload.scope} | کاربران: {len(users)} | حجم افزوده: {payload.quota_gb}GB | روز افزوده: {payload.days} | فعال‌شده: {result['reactivated']}",
        actor=admin.username,
    )
    return BulkUserIncreaseResult(**result)


@router.post("/{user_id}/sub-alias")
def add_legacy_sub_alias(
    user_id: int,
    payload: SubAliasRequest,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("users:subscription", "users")),
):
    u = _get_owned_user(db, admin, user_id)
    raw = payload.token_or_url.strip()
    # Accept either a bare token or the complete old /sub/<token> URL.
    match = re.search(r"/sub/([^/?#]+)", raw)
    token = match.group(1) if match else raw
    token = token.strip()
    if not re.fullmatch(r"[A-Za-z0-9_\-]{8,128}", token):
        raise HTTPException(400, "توکن لینک قدیمی معتبر نیست")
    current_owner = db.query(VpnUser).filter(VpnUser.sub_token == token).first()
    if current_owner and current_owner.id != u.id:
        raise HTTPException(409, "این توکن در حال حاضر متعلق به کاربر دیگری است")
    existing = db.query(VpnUserSubAlias).filter(VpnUserSubAlias.token == token).first()
    if existing and existing.user_id != u.id:
        raise HTTPException(409, "این لینک قدیمی قبلاً برای کاربر دیگری ثبت شده است")
    if not existing:
        db.add(VpnUserSubAlias(user_id=u.id, token=token))
        db.commit()
    return {"ok": True, "token": token, "username": u.username}


@router.get("/{user_id}", response_model=VpnUserOut)
def get_user(user_id: int, request: Request, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("users:view", "users"))):
    u = _get_owned_user(db, admin, user_id)
    return _to_out(u, db, request, admin)



_AUDIT_FIELDS = {
    "password": "رمز عبور", "quota_bytes": "حجم", "max_devices": "حداکثر اتصال",
    "download_limit_mbps": "سرعت دانلود", "upload_limit_mbps": "سرعت آپلود",
    "expire_mode": "نوع انقضا", "expire_date": "تاریخ انقضا", "expire_after_days": "روزهای اعتبار",
    "is_active": "وضعیت حساب", "note": "یادداشت", "server_targets": "سرورها",
    "openvpn_auth_mode": "احراز OpenVPN", "sstp_auth_mode": "احراز SSTP",
}

def _audit_value(field, value):
    if field == "password": return "تغییر کرد"
    if field == "quota_bytes": return "نامحدود" if int(value or 0) <= 0 else f"{int(value)/GB:.2f} GB"
    if field in {"download_limit_mbps", "upload_limit_mbps"}: return "نامحدود" if int(value or 0) <= 0 else f"{int(value)} Mbps"
    if field == "max_devices": return "نامحدود" if int(value or 0) == 0 else str(int(value))
    if field == "is_active": return "فعال" if value else "غیرفعال"
    if value in (None, ""): return "—"
    return str(value)

def _user_snapshot(user):
    fields = set(_AUDIT_FIELDS) | {f"enable_{p}" for p in USER_PROTOCOL_KEYS}
    return {field: getattr(user, field, None) for field in fields}

def _user_change_log(username, before, after):
    lines = [f"👤 کاربر: <code>{username}</code>"]
    changes = []
    for field, label in _AUDIT_FIELDS.items():
        # Authentication-mode defaults exist in the database even when the
        # related protocol is disabled.  Do not claim OpenVPN/SSTP changed for
        # a VLESS-only (or any unrelated) user.
        if field == "openvpn_auth_mode" and not (before.get("enable_openvpn") or after.get("enable_openvpn")):
            continue
        if field == "sstp_auth_mode" and not (before.get("enable_sstp") or after.get("enable_sstp")):
            continue
        if before.get(field) != after.get(field):
            changes.append(f"• {label}: <b>{_audit_value(field, before.get(field))}</b> ← <b>{_audit_value(field, after.get(field))}</b>")
    enabled_before = {p for p in USER_PROTOCOL_KEYS if before.get(f"enable_{p}")}
    enabled_after = {p for p in USER_PROTOCOL_KEYS if after.get(f"enable_{p}")}
    if enabled_before != enabled_after:
        added = sorted(enabled_after - enabled_before); removed = sorted(enabled_before - enabled_after)
        if added: changes.append("• پروتکل فعال شد: <b>" + ", ".join(added) + "</b>")
        if removed: changes.append("• پروتکل غیرفعال شد: <b>" + ", ".join(removed) + "</b>")
    lines.extend(changes or ["• تغییری در مقدارهای قابل ثبت انجام نشد."])
    return "\n".join(lines)

@router.post("", response_model=VpnUserOut)
def create_user(payload: VpnUserCreate, request: Request, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("users:create", "users"))):
    if db.query(VpnUser).filter(VpnUser.username == payload.username).first():
        raise HTTPException(400, "این نام کاربری قبلاً ثبت شده است")

    _check_admin_limits(db, admin, extra_quota_bytes=int(payload.quota_gb * GB), is_new_user=True)
    ensure_user_protocols(admin, {
        name for name in ("l2tp", "pptp", "openvpn", "sstp", "ikev2", "openconnect", "vmess", "vless")
        if bool(getattr(payload, f"enable_{name}"))
    })

    try:
        normalized_targets = validate_target_tokens(db, payload.server_targets, admin)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    u = VpnUser(
        username=payload.username,
        password=payload.password,
        enable_l2tp=payload.enable_l2tp,
        enable_pptp=payload.enable_pptp,
        enable_openvpn=payload.enable_openvpn,
        enable_sstp=payload.enable_sstp,
        enable_ikev2=payload.enable_ikev2,
        enable_openconnect=payload.enable_openconnect,
        enable_vmess=payload.enable_vmess,
        enable_vless=payload.enable_vless,
        openvpn_auth_mode=payload.openvpn_auth_mode,
        sstp_auth_mode=payload.sstp_auth_mode,
        quota_bytes=int(payload.quota_gb * GB),
        max_devices=payload.max_devices,
        speed_limit_mbps=0,
        download_limit_mbps=payload.download_limit_mbps or payload.speed_limit_mbps,
        upload_limit_mbps=payload.upload_limit_mbps or payload.speed_limit_mbps,
        expire_mode=payload.expire_mode,
        expire_date=payload.expire_date,          # فقط برای حالت fixed معنا دارد
        expire_after_days=payload.expire_after_days,  # فقط برای after_first_connect
        is_active=payload.is_active,
        note=payload.note,
        server_targets=serialize_targets(normalized_targets),
        owner_admin_id=admin.id,
        sub_token=secrets.token_urlsafe(24),
    )
    db.add(u)
    db.commit()
    db.refresh(u)

    # Build the HTTP response before starting any daemon or remote-node work.
    # This ordering matters on small servers: once a reconciliation thread starts,
    # package/service operations can consume CPU or database connections and make
    # an otherwise completed create request appear frozen in the browser.
    out = _to_out(u, db, request, admin)
    _schedule_user_post_update_sync(
        u.id,
        sync_xray=bool((u.enable_vmess or u.enable_vless) and local_assignment_enabled(db) and user_selected_for_local(u)),
    )
    log_event("➕ ساخت یوزر VPN", _user_change_log(u.username, {}, _user_snapshot(u)), actor=admin.username)
    return out


@router.put("/{user_id}", response_model=VpnUserOut)
def update_user(user_id: int, payload: VpnUserUpdate, request: Request, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("users:edit", "users"))):
    u = _get_owned_user(db, admin, user_id)
    audit_before = _user_snapshot(u)
    previous_xray_state = (bool(u.enable_vmess), bool(u.enable_vless), bool(u.is_active))
    previous_local_selected = local_assignment_enabled(db) and user_selected_for_local(u)

    data = payload.model_dump(exclude_unset=True)
    if "server_targets" in data:
        try:
            selected_targets = set(validate_target_tokens(db, data["server_targets"], admin))
            if admin.role == AdminRole.superadmin:
                data["server_targets"] = serialize_targets(selected_targets)
            else:
                # A delegated admin may change only the visible part of a
                # user's server assignment. Existing hidden assignments stay
                # intact and are never returned to the browser.
                existing_targets = set(targets_for_user(u))
                if "all" in existing_targets:
                    existing_targets = set(globally_assignable_tokens(db))
                hidden_existing = {
                    token for token in existing_targets
                    if not admin_can_access_target(admin, token)
                }
                if "all" in selected_targets:
                    selected_targets = set(available_target_tokens(db, admin))
                data["server_targets"] = serialize_targets(hidden_existing | selected_targets)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
    # سازگاری با نسخه‌ای که فقط یک speed_limit_mbps داشت. اگر کلاینت قدیمی
    # همان فیلد را بفرستد، روی هر دو جهت اعمال می‌شود.
    if "speed_limit_mbps" in data:
        legacy_speed = int(data.pop("speed_limit_mbps") or 0)
        data.setdefault("download_limit_mbps", legacy_speed)
        data.setdefault("upload_limit_mbps", legacy_speed)
    if "download_limit_mbps" in data or "upload_limit_mbps" in data:
        data["speed_limit_mbps"] = 0

    if "quota_gb" in data:
        new_quota_bytes = int(data.pop("quota_gb") * GB)
        delta = new_quota_bytes - u.quota_bytes
        if delta > 0:
            _check_admin_limits(db, admin, extra_quota_bytes=delta, is_new_user=False)
        u.quota_bytes = new_quota_bytes

    # Ignore protocol fields outside this admin's scope. This prevents a
    # masked UI (where hidden protocols are intentionally absent) from
    # accidentally disabling transports assigned by a higher-level admin.
    if admin.role != AdminRole.superadmin:
        for protocol in USER_PROTOCOL_KEYS:
            if not admin_can_access_protocol(admin, protocol):
                data.pop(f"enable_{protocol}", None)

    # وضعیت نهایی پروتکل‌ها بعد از اعمال این تغییرات (فیلدهایی که در payload
    # نیامده‌اند همان مقدار فعلی کاربر را حفظ می‌کنند) - باید حداقل یکی روشن
    # بماند، وگرنه کاربر بدون هیچ پروتکلی قابل اتصال ذخیره می‌شود.
    effective_protocols = {
        "enable_l2tp": data.get("enable_l2tp", u.enable_l2tp),
        "enable_pptp": data.get("enable_pptp", u.enable_pptp),
        "enable_openvpn": data.get("enable_openvpn", u.enable_openvpn),
        "enable_sstp": data.get("enable_sstp", u.enable_sstp),
        "enable_ikev2": data.get("enable_ikev2", u.enable_ikev2),
        "enable_openconnect": data.get("enable_openconnect", u.enable_openconnect),
        "enable_vmess": data.get("enable_vmess", u.enable_vmess),
        "enable_vless": data.get("enable_vless", u.enable_vless),
    }
    if not any(effective_protocols.values()):
        raise HTTPException(400, "باید حداقل یکی از پروتکل‌ها برای کاربر فعال باشد")
    # A delegated admin may keep protocols that were already assigned by a
    # higher-level admin, but may only add protocols included in their own scope.
    ensure_user_protocols(admin, {
        field.removeprefix("enable_")
        for field, enabled in effective_protocols.items()
        if enabled and not bool(getattr(u, field))
    })

    for field, value in data.items():
        setattr(u, field, value)

    # اگر حالت انقضا "بعد از اولین اتصال" است، تاریخ انقضا را از روی
    # first_connect_at (اگر قبلاً وصل شده) و expire_after_days دوباره محاسبه کن
    if u.expire_mode == "after_first_connect":
        if u.first_connect_at:
            u.expire_date = (u.first_connect_at.date() + timedelta(days=u.expire_after_days))
        else:
            u.expire_date = None

    db.commit()
    db.refresh(u)

    # Return immediately after the durable database commit. Slow daemon,
    # certificate, firewall and node reconciliation continues in a serialized
    # background worker, so desktop and mobile edit dialogs do not freeze for
    # 20-30 seconds. Xray is restarted only when its access/active state really
    # changed; quota, note, expiry and speed edits do not interrupt VMess/VLESS.
    current_xray_state = (bool(u.enable_vmess), bool(u.enable_vless), bool(u.is_active))
    current_local_selected = local_assignment_enabled(db) and user_selected_for_local(u)

    # Serialize the durable result first, then launch reconciliation. This keeps
    # the edit response independent from a busy Xray/PPP/node worker and makes
    # the modal close immediately after the database commit.
    out = _to_out(u, db, request, admin)
    _schedule_user_post_update_sync(
        u.id,
        sync_xray=(
            current_xray_state != previous_xray_state
            or current_local_selected != previous_local_selected
        ),
    )

    log_event("✏️ ویرایش یوزر VPN", _user_change_log(u.username, audit_before, _user_snapshot(u)), actor=admin.username)
    return out


@router.delete("/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("users:delete", "users"))):
    u = _get_owned_user(db, admin, user_id)
    username = u.username

    kill_ppp_session(db, u.username)
    kill_sstp_session(db, u.username)
    kill_openvpn_session(u.username)
    kill_ikev2_session(db, u.username)
    kill_openconnect_session(u.username)
    disconnect_xray_session(db, u.username)

    db.query(XrayUsageCounter).filter(XrayUsageCounter.user_id == u.id).delete()
    db.query(ConnectionLog).filter(ConnectionLog.user_id == u.id).delete()
    db.delete(u)
    db.commit()
    sync_chap_secrets(db)
    try:
        sync_xray_users(db, protocols=("vmess", "vless"), restart=True)
    except Exception:
        pass
    reconcile_shared_rate_limits(db, force=True)
    revoke_client_cert(u.username)
    sync_all_nodes_async()
    log_event("🗑 حذف یوزر VPN", f"👤 کاربر: <code>{username}</code>\n• حساب و تمام نشست‌ها و اطلاعات اتصال حذف شد.", actor=admin.username)
    return {"ok": True}


@router.post("/{user_id}/reset-usage")
def reset_usage(user_id: int, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("users:edit", "users"))):
    u = _get_owned_user(db, admin, user_id)
    u.used_bytes = 0
    db.commit()
    sync_all_nodes_async()
    log_event("🔄 ریست حجم مصرفی", f"👤 کاربر: <code>{u.username}</code>\n• مصرف ثبت‌شده به صفر تغییر کرد.", actor=admin.username)
    return {"ok": True}


@router.post("/{user_id}/disconnect")
def disconnect_user(user_id: int, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("users:disconnect", "online"))):
    """Disconnect every active transport for one account across all nine protocols.

    Daemon-specific termination remains best-effort because a protocol may be
    disabled or not installed on this node. The database is closed immediately
    so the panel never leaves ghost-online rows while the daemon hooks catch up.
    """
    u = _get_owned_user(db, admin, user_id)
    kill_ppp_session(db, u.username)
    kill_sstp_session(db, u.username)
    kill_openvpn_session(u.username)
    kill_ikev2_session(db, u.username)
    kill_openconnect_session(u.username)
    disconnect_xray_session(db, u.username)

    now = datetime.utcnow()
    active_rows = (
        db.query(ConnectionLog)
        .filter(ConnectionLog.user_id == u.id, ConnectionLog.is_online == True)  # noqa: E712
        .all()
    )
    for row in active_rows:
        row.is_online = False
        row.disconnect_time = row.disconnect_time or now
    if active_rows:
        db.commit()
    log_event("🔌 قطع اجباری اتصال", f"👤 کاربر: <code>{u.username}</code>\n• تعداد نشست‌های بسته‌شده: <b>{len(active_rows)}</b>", actor=admin.username)
    return {"ok": True, "closed_sessions": len(active_rows)}


@router.post("/sessions/{session_id}/disconnect")
def disconnect_session(session_id: int, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("online:disconnect", "online"))):
    """قطع دقیقاً یک سشن/آی‌پی مشخص، بدون قطع بقیه‌ی اتصال‌های هم‌زمان همان
    کاربر (برخلاف /{user_id}/disconnect که همه را قطع می‌کند)."""
    log = (
        db.query(ConnectionLog)
        .join(VpnUser, VpnUser.id == ConnectionLog.user_id)
        .filter(ConnectionLog.id == session_id)
        .first()
    )
    if not log:
        raise HTTPException(404, "اتصال پیدا نشد")
    # دسترسی را با همان منطق _get_owned_user چک می‌کنیم (ادمین زیرمجموعه فقط به کاربران خودش دسترسی دارد)
    _get_owned_user(db, admin, log.user_id)

    result = True
    if log.protocol in ("l2tp", "pptp"):
        result = kill_single_ppp_session(db, log)
    elif log.protocol == "sstp":
        result = kill_single_sstp_session(db, log)
    elif log.protocol == "openvpn":
        result = kill_single_openvpn_session(db, log)
    elif log.protocol == "ikev2":
        result = kill_single_ikev2_session(db, log)
    elif log.protocol == "openconnect":
        result = kill_single_openconnect_session(db, log)
    elif log.protocol in {"vmess", "vless"}:
        # برای Xray «قطع» یعنی تونل Connected بماند ولی اینترنت همان پروتکل
        # در سطح fwmark/nftables مسدود شود. این رفتار هم قابل‌اعتمادتر است،
        # هم باعث ایجاد سشن یتیم/تکراری بعد از reconnect نمی‌شود.
        try:
            set_xray_internet_block(db, log.user, log.protocol, True)
            # Push the same block flag to every enabled node immediately. The
            # full sync runs outside the request so one slow node cannot freeze
            # the confirmation dialog.
            sync_all_nodes_async()
        except RuntimeError as exc:
            raise HTTPException(status_code=500, detail=str(exc))
        return {"ok": True, "internet_blocked": True, "transport_connected": True}
    return {"ok": True, "daemon_acknowledged": bool(result)}


@router.post("/sessions/{session_id}/internet-block")
def block_session_public_ip_in_all_protocols(
    session_id: int,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("online:disconnect", "online")),
):
    """Cut the session's public IP across all nine VPN protocols.

    The temporary firewall record is global by public IP: a VMess session can
    therefore also block VLESS/OpenVPN/PPTP/etc. attempts from the same IP,
    and vice versa. The record is restored from the dedicated panel section.
    """
    log = (
        db.query(ConnectionLog)
        .join(VpnUser, VpnUser.id == ConnectionLog.user_id)
        .filter(ConnectionLog.id == session_id)
        .first()
    )
    if not log:
        raise HTTPException(404, "اتصال پیدا نشد")
    user = _get_owned_user(db, admin, log.user_id)
    if not log.ip_address:
        raise HTTPException(400, "آی‌پی پابلیک این اتصال مشخص نیست")

    record = block_internet_ip(
        db,
        log.ip_address,
        user=user,
        protocol=log.protocol,
        reason=f"قطع اینترنت از صفحه کاربران آنلاین ({user.username})",
        admin_id=admin.id,
        admin_username=admin.username,
    )
    sync_global_controls_to_active_nodes_async()
    log_event(
        "⛔ قطع اینترنت آی‌پی در همه پروتکل‌ها",
        f"کاربر: {user.username} | آی‌پی: {log.ip_address} | پروتکل مبدا: {log.protocol}",
        actor=admin.username,
    )
    return {
        "ok": True,
        "ip_address": record.ip_address,
        "username": record.username,
        "all_protocols_blocked": True,
    }


@router.post("/sessions/{session_id}/restore")
def restore_xray_session_internet(
    session_id: int,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("online:disconnect", "online")),
):
    log = (
        db.query(ConnectionLog)
        .join(VpnUser, VpnUser.id == ConnectionLog.user_id)
        .filter(ConnectionLog.id == session_id)
        .first()
    )
    if not log:
        raise HTTPException(404, "اتصال پیدا نشد")
    _get_owned_user(db, admin, log.user_id)
    if log.protocol not in {"vmess", "vless"}:
        raise HTTPException(400, "این عملیات فقط برای VMess/VLESS است")
    try:
        set_xray_internet_block(db, log.user, log.protocol, False)
        sync_all_nodes_async()
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    return {"ok": True, "internet_blocked": False, "transport_connected": True}


@router.post("/sessions/{session_id}/ban-ip")
def ban_session_ip(session_id: int, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("bans:manage", "online"))):
    """مسدود کردن آی‌پی پابلیک همین سشن مشخص: هم بلافاصله قطع می‌شود، هم
    دیگر با هیچ یوزرنیم/پسورد یا سرتیفیکیتی از همان آی‌پی نمی‌تواند دوباره
    وصل شود (ثبت در دیتابیس + قانون iptables، نگاه کنید به vpn_manager.ban_ip)."""
    log = (
        db.query(ConnectionLog)
        .join(VpnUser, VpnUser.id == ConnectionLog.user_id)
        .filter(ConnectionLog.id == session_id)
        .first()
    )
    if not log:
        raise HTTPException(404, "اتصال پیدا نشد")
    _get_owned_user(db, admin, log.user_id)

    if not log.ip_address:
        raise HTTPException(400, "آی‌پی این اتصال مشخص نیست")

    ban_ip(
        db, log.ip_address,
        f"مسدود شده از صفحه‌ی کاربران آنلاین (کاربر: {log.user.username if log.user else '?'})",
        admin.id, owner_admin_id=(log.user.owner_admin_id if log.user and log.user.owner_admin_id is not None else admin.id),
    )
    sync_global_controls_to_active_nodes_async()
    log_event("🚫 مسدودسازی آی‌پی (از صفحه‌ی آنلاین)", f"آی‌پی: {log.ip_address} | کاربر: {log.user.username if log.user else '?'}", actor=admin.username)
    return {"ok": True, "ip_address": log.ip_address}


def _setting(db: Session, key: str):
    row = db.query(Setting).filter(Setting.key == key).first()
    return row.value if row else None


@router.get("/{user_id}/xray-links")
def get_user_xray_links(user_id: int, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("users:subscription", "users"))):
    u = _get_owned_user(db, admin, user_id)
    return {"vmess": build_uri(db, u, "vmess"), "vless": build_uri(db, u, "vless")}


def _safe_openvpn_filename(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip()).strip("-._")
    return cleaned[:80] or "user"


@router.get("/{user_id}/openvpn-config")
def download_openvpn_config(user_id: int, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("users:subscription", "users"))):
    u = _get_owned_user(db, admin, user_id)
    if not u.enable_openvpn:
        raise HTTPException(400, "OpenVPN برای این کاربر غیرفعال است")

    try:
        ensure_controller_openvpn_pki(db, allow_generate=False)
    except CertError as exc:
        raise HTTPException(503, f"PKI مشترک OpenVPN آماده نیست: {exc}") from exc

    available_remotes = openvpn_remotes(db, u)
    all_remotes = openvpn_remotes(db, u, require_shared_pki=True)
    if not all_remotes:
        if available_remotes:
            sync_all_nodes_async()
            raise HTTPException(503, "کلید مشترک OpenVPN در حال همگام‌سازی با نودهاست؛ چند ثانیه بعد دوباره دانلود کنید")
        raise HTTPException(503, "هیچ سرور OpenVPN فعالی در حالت Node انتخاب‌شده وجود ندارد")
    server_address, first_port, first_proto = all_remotes[0]
    udp_port = first_port if first_proto == "udp" else next((p for h, p, proto in all_remotes if h == server_address and proto == "udp"), first_port)
    tcp_port = first_port if first_proto == "tcp" else next((p for h, p, proto in all_remotes if h == server_address and proto == "tcp"), first_port)

    try:
        cert_pem, key_pem, credential_status = get_client_profile_credentials(u.username)
        if credential_status in {"generated", "reissued"}:
            sync_all_nodes_async()
    except CertError as exc:
        raise HTTPException(500, f"ساخت سرتیفیکیت اختصاصی این کاربر ناموفق بود: {exc}") from exc

    try:
        content = build_client_ovpn(
            u.username, server_address, udp_port, tcp_port, cert_pem, key_pem,
            extra_ports=[],
            auth_mode=u.openvpn_auth_mode, password=u.password,
            additional_remotes=all_remotes,
            profile_name=f"ALL-{_safe_openvpn_filename(u.username)}",
        )
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(500, str(exc)) from exc

    return Response(
        content=content,
        media_type="application/x-openvpn-profile",
        headers={"Content-Disposition": f'attachment; filename="ALL-{_safe_openvpn_filename(u.username)}.ovpn"'},
    )
