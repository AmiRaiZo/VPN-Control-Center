from datetime import date, datetime, timezone
import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db
from app.models import VpnUser, Admin, AdminRole, VpnNode, Setting
from app.schemas import DashboardSummary, OnlineUserOut, SystemStats
from app.security import require_permission, can_view_all_users, ensure_protocol_permission, admin_can_access_protocol
from app.services.system_stats import get_system_stats
from app.services.scheduler import refresh_xray_presence_if_stale
from app.services.online_sessions import (
    normalize_client_platform,
    serialize_local_online_users,
    server_datetime_payload,
)
from app.services.server_targets import admin_can_access_target

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

GB = 1_073_741_824


def _node_snapshot_is_fresh(snapshot: dict, max_age_seconds: float = 12.0) -> bool:
    raw = snapshot.get("generated_at")
    if not raw:
        return True
    try:
        stamp = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        if stamp.tzinfo is not None:
            # generated_at is UTC. Converting it to the host's local timezone
            # and then dropping tzinfo makes a Tehran controller see an old
            # node snapshot as 3:30 *in the future*, so ghost sessions stay
            # visible for hours. Compare like-for-like naive UTC values.
            stamp = stamp.astimezone(timezone.utc).replace(tzinfo=None)
        return (datetime.utcnow() - stamp).total_seconds() <= max_age_seconds
    except Exception:
        return False


def _scoped(db: Session, admin: Admin):
    q = db.query(VpnUser)
    if not can_view_all_users(admin):
        q = q.filter(VpnUser.owner_admin_id == admin.id)
    return q


@router.get("/summary", response_model=DashboardSummary)
def summary(db: Session = Depends(get_db), admin: Admin = Depends(require_permission("dashboard"))):
    # Keep this endpoint sub-second. Session reconciliation is already run by
    # the background scheduler and by /online-users where exact live state is
    # required; doing shell/network probes here made every dashboard open slow.
    total = _scoped(db, admin).count()
    active = _scoped(db, admin).filter(VpnUser.is_active == True).count()  # noqa: E712
    expired = (
        _scoped(db, admin)
        .filter(VpnUser.expire_date.isnot(None), VpnUser.expire_date < date.today())
        .count()
    )
    over_quota = (
        _scoped(db, admin)
        .filter(VpnUser.quota_bytes > 0, VpnUser.used_bytes >= VpnUser.quota_bytes)
        .count()
    )
    # The controller database only contains local ConnectionLog rows.  Remote
    # node sessions live inside each node's fresh health snapshot, so counting
    # ConnectionLog directly made the dashboard show zero while the Recent
    # Connections table correctly displayed live node sessions.  Reuse the
    # same lightweight merger as /online-users so every dashboard widget has
    # one source of truth without running shell probes in this endpoint.
    online_groups = _collect_online_users(db, admin, refresh_presence=False)
    online = len(online_groups)
    online_connections = sum(int(group.get("session_count") or 0) for group in online_groups)

    total_used_bytes = (
        _scoped(db, admin)
        .with_entities(func.coalesce(func.sum(VpnUser.used_bytes), 0))
        .scalar()
    ) or 0

    # سقف/مصرف خود ادمینی که این داشبورد را باز کرده - فقط برای ادمین
    # زیرمجموعه‌ای که حداقل یکی از سقف‌ها/تاریخ انقضا برایش تنظیم شده باشد؛
    # superadmin و ادمینی که هیچ سقفی ندارد، این مقادیر None می‌مانند.
    admin_max_users = None
    admin_used_users = 0
    admin_max_total_quota_gb = None
    admin_used_total_quota_gb = 0
    admin_subscription_expire_date = None
    admin_subscription_expire_at = None
    admin_subscription_remaining_seconds = None
    admin_subscription_expired = False
    admin_managed_by_license = False
    admin_license_locked = False

    if admin.role == AdminRole.admin:
        admin_used_users = db.query(VpnUser).filter(VpnUser.owner_admin_id == admin.id).count()
        # مبنای مصرفِ سقفِ کلیِ حجم ادمین: مجموع used_bytes واقعی یوزرهایش،
        # نه quota_bytes (حجمی که فقط تخصیص داده شده ولی لزوماً مصرف نشده).
        used_quota = (
            db.query(func.coalesce(func.sum(VpnUser.used_bytes), 0))
            .filter(VpnUser.owner_admin_id == admin.id)
            .scalar()
        ) or 0
        admin_used_total_quota_gb = round(int(used_quota) / GB, 3)
        admin_max_users = admin.max_users
        admin_max_total_quota_gb = (
            admin.max_total_quota_bytes / GB if admin.max_total_quota_bytes is not None else None
        )

    # تاریخ لایسنس برای ادمین زیرمجموعه و سوپرادمینی که با لایسنس داخلی ساخته
    # شده نمایش داده می‌شود. سوپرادمین دستی همچنان مثل قبل هیچ کارت اشتراکی ندارد.
    if admin.role == AdminRole.admin or bool(getattr(admin, "managed_by_license", False)):
        admin_subscription_expire_date = admin.subscription_expire_date
        admin_subscription_expire_at = getattr(admin, "subscription_expire_at", None)
        if admin_subscription_expire_at:
            admin_subscription_remaining_seconds = max(0, int((admin_subscription_expire_at - datetime.utcnow()).total_seconds()))
        admin_managed_by_license = bool(getattr(admin, "managed_by_license", False))
        admin_license_locked = bool(getattr(admin, "license_locked", False))
        admin_subscription_expired = bool(
            admin_license_locked
            or (admin_subscription_expire_at and admin_subscription_expire_at <= datetime.utcnow())
            or (not admin_subscription_expire_at and admin.subscription_expire_date and admin.subscription_expire_date < date.today())
        )

    return DashboardSummary(
        total_users=total,
        active_users=active,
        online_users=online,
        online_connections=online_connections,
        expired_users=expired,
        quota_exceeded_users=over_quota,
        total_used_bytes=int(total_used_bytes),
        system=SystemStats(**get_system_stats()),
        admin_max_users=admin_max_users,
        admin_used_users=admin_used_users,
        admin_max_total_quota_gb=admin_max_total_quota_gb,
        admin_used_total_quota_gb=admin_used_total_quota_gb,
        admin_subscription_expire_date=admin_subscription_expire_date,
        admin_subscription_expire_at=admin_subscription_expire_at,
        admin_subscription_remaining_seconds=admin_subscription_remaining_seconds,
        admin_subscription_expired=admin_subscription_expired,
        admin_managed_by_license=admin_managed_by_license,
        admin_license_locked=admin_license_locked,
    )


@router.get("/system", response_model=SystemStats)
def system_stats(admin: Admin = Depends(require_permission("dashboard"))):
    return SystemStats(**get_system_stats())


def _visible_protocol_statuses(rows: list[dict], admin: Admin) -> list[dict]:
    visible: list[dict] = []
    for raw in rows or []:
        if not isinstance(raw, dict) or not raw.get("key"):
            continue
        try:
            ensure_protocol_permission(admin, str(raw["key"]), "view")
        except HTTPException:
            continue
        visible.append(dict(raw))
    return visible


@router.get("/protocol-overview")
def protocol_overview(
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("protocols:view", "settings")),
):
    """Return dashboard protocol health for the main host and every node.

    The old dashboard always queried ``/settings/protocol-center`` locally, so
    the controller displayed its own daemons even when users were actually
    provisioned on nodes.  Node Agent health snapshots now publish the same
    compact runtime rows and this endpoint exposes them with a server selector.
    """
    from app.services.node_manager import build_local_snapshot, effective_server_role

    servers: list[dict] = []
    if admin_can_access_target(admin, "local"):
        local_snapshot = build_local_snapshot(db)
        local_is_node = effective_server_role(db) == "node"
        local_name_row = db.query(Setting).filter(Setting.key == "node_name").first()
        local_name = (str(local_name_row.value or "").strip() if local_name_row else "")
        servers.append({
            "id": "local",
            "name": local_name or ("این نود" if local_is_node else "سرور اصلی"),
            "local": True,
            "node": local_is_node,
            "status": "online",
            "version": local_snapshot.get("version"),
            "generated_at": local_snapshot.get("generated_at"),
            "protocols": _visible_protocol_statuses(local_snapshot.get("protocol_statuses") or [], admin),
        })

    for node in db.query(VpnNode).filter(VpnNode.enabled == True).order_by(VpnNode.id).all():  # noqa: E712
        token = f"node:{int(node.id)}"
        if not admin_can_access_target(admin, token):
            continue
        snapshot: dict = {}
        if node.last_snapshot:
            try:
                parsed = json.loads(node.last_snapshot)
                if isinstance(parsed, dict):
                    snapshot = parsed
            except Exception:
                snapshot = {}
        servers.append({
            "id": token,
            "node_id": int(node.id),
            "name": node.name,
            "local": False,
            "node": True,
            "status": node.status or "unknown",
            "version": snapshot.get("version"),
            "generated_at": snapshot.get("generated_at"),
            "last_error": node.last_error or "",
            "protocols": _visible_protocol_statuses(snapshot.get("protocol_statuses") or [], admin),
        })

    preferred = next((row["id"] for row in servers if row.get("node") and row.get("status") == "online" and row.get("protocols")), None)
    if preferred is None:
        preferred = next((row["id"] for row in servers if row.get("protocols")), "local")
    return {"servers": servers, "preferred_server_id": preferred}


def _collect_online_users(db: Session, admin: Admin, *, refresh_presence: bool) -> list[dict]:
    """Merge visible local and remote-node sessions into one stable payload.

    Both the dashboard summary and the Online Users endpoint use this helper.
    The summary path intentionally skips live Xray probing and reads the latest
    scheduler/node snapshots only; the dedicated Online Users path may refresh
    lightweight Xray presence before serializing.
    """
    if refresh_presence:
        refresh_xray_presence_if_stale(max_age_seconds=5.5)
    db.expire_all()

    local_role = db.query(Setting).filter(Setting.key == "server_role").first()
    local_name = "این سرور" if local_role and str(local_role.value or "").lower() == "node" else "سرور اصلی"
    local_groups = serialize_local_online_users(
        db, admin, server_id="local", server_name=local_name, server_local=True
    )

    controller_users = {user.username: user for user in _scoped(db, admin).all()}
    merged: dict[str, dict] = {}

    def consume(group: dict) -> None:
        username = str(group.get("username") or "?")
        controller_user = controller_users.get(username)
        if controller_user is None:
            return
        target = merged.setdefault(username, {
            "user_id": int(controller_user.id),
            "username": username,
            "session_count": 0,
            "used_bytes": int(controller_user.used_bytes or 0),
            "quota_bytes": int(controller_user.quota_bytes or 0),
            "sessions": [],
        })
        seen_keys = {str(item.get("session_key") or "") for item in target["sessions"]}
        for raw in group.get("sessions") or []:
            if not isinstance(raw, dict):
                continue
            protocol = str(raw.get("protocol") or "").strip().lower()
            if protocol and not admin_can_access_protocol(admin, protocol):
                continue
            session = dict(raw)
            session["platform"] = normalize_client_platform(
                session.get("protocol"), session.get("platform")
            )
            session_key = str(session.get("session_key") or "")
            if session_key and session_key in seen_keys:
                continue
            target["sessions"].append(session)
            if session_key:
                seen_keys.add(session_key)
        target["session_count"] = len(target["sessions"])

    for group in local_groups:
        consume(group)

    nodes = db.query(VpnNode).filter(VpnNode.enabled == True, VpnNode.status == "online").order_by(VpnNode.id).all()  # noqa: E712
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
            patched = dict(group)
            patched_sessions = []
            for raw in group.get("sessions") or []:
                if not isinstance(raw, dict):
                    continue
                session = dict(raw)
                session_id = int(session.get("id") or 0)
                session.update({
                    "session_key": f"node:{int(node.id)}:{session_id}",
                    "server_id": token,
                    "server_name": node.name,
                    "server_local": False,
                })
                # A node may run in UTC (or have a different local timezone).
                # Its preformatted display string must never override the
                # timezone selected on the controller panel. The canonical
                # connect_time is UTC, so render it again using this panel's
                # system_timezone before returning the merged payload.
                try:
                    raw_connect_time = str(session.get("connect_time") or "")
                    parsed_connect_time = datetime.fromisoformat(
                        raw_connect_time.replace("Z", "+00:00")
                    )
                    normalized_iso, normalized_display = server_datetime_payload(
                        db, parsed_connect_time
                    )
                    if normalized_iso:
                        session["connect_time"] = normalized_iso
                    if normalized_display:
                        session["connect_time_display"] = normalized_display
                except Exception:
                    session.pop("connect_time_display", None)
                patched_sessions.append(session)
            patched["sessions"] = patched_sessions
            consume(patched)

    result = list(merged.values())
    for group in result:
        group["sessions"].sort(key=lambda item: str(item.get("connect_time") or ""), reverse=True)
        group["session_count"] = len(group["sessions"])
    result.sort(key=lambda item: (item["sessions"][0].get("connect_time") if item["sessions"] else ""), reverse=True)
    return result


@router.get("/online-users", response_model=list[OnlineUserOut])
def online_users(db: Session = Depends(get_db), admin: Admin = Depends(require_permission("online"))):
    return _collect_online_users(db, admin, refresh_presence=True)
