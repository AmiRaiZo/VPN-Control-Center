from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from zoneinfo import ZoneInfo

from sqlalchemy.orm import Session, joinedload

from app.models import Admin, ConnectionLog, Setting, VpnUser
from app.security import can_view_all_users
from app.services.jalali_time import format_jalali_datetime
from app.services.system_time import current_timezone

XRAY_PROTOCOLS = {"vmess", "vless"}
DUX28_L2TP_SIGNATURES = {"openwrt", "xelerance.com", "xl2tpd"}


def normalize_client_platform(protocol: str | None, value: str | None) -> str | None:
    """Return the device label shown by the panel.

    DUX28's embedded xl2tpd firmware reports generic implementation strings
    (usually ``OpenWrt`` or ``xelerance.com``) instead of its product model.
    Normalize existing rows too, so the current session is corrected without
    requiring the router to reconnect after the panel update.
    """
    raw = str(value or "").strip()
    if not raw:
        return None
    compact = raw.lower().replace("_", "").replace("-", "").replace(" ", "")
    if str(protocol or "").strip().lower() == "l2tp" and (
        raw.lower() in DUX28_L2TP_SIGNATURES or compact == "dux28"
    ):
        return "DUX28"
    return raw


def refresh_local_ppp_presence(db: Session) -> int:
    """Retire dead PPP rows immediately before serving live UI data."""
    from app.services.vpn_manager import reconcile_ppp_sessions

    try:
        return int(reconcile_ppp_sessions(db) or 0)
    except Exception:
        # This is a safety-net probe; a transient failure must not break the
        # users page or leave its request transaction unusable.
        db.rollback()
        return 0


def _configured_server_timezone(db: Session) -> ZoneInfo:
    """Return the timezone selected in Settings, independently of browser TZ.

    ConnectionLog timestamps are stored as naive UTC.  The old API returned the
    same naive value and JavaScript interpreted it as browser-local time, so the
    Online Users table ignored the timezone configured on the server.
    """
    name = ""
    try:
        row = db.query(Setting).filter(Setting.key == "system_timezone").first()
        name = str(row.value or "").strip() if row else ""
    except Exception:
        name = ""
    if not name:
        try:
            name = str(current_timezone() or "").strip()
        except Exception:
            name = ""
    try:
        return ZoneInfo(name or "UTC")
    except Exception:
        return ZoneInfo("UTC")


def _connection_time_payload(value: datetime | None, zone: ZoneInfo) -> tuple[str, str]:
    stamp = value or datetime.utcnow()
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    else:
        stamp = stamp.astimezone(timezone.utc)
    local_stamp = stamp.astimezone(zone)
    return stamp.isoformat().replace("+00:00", "Z"), format_jalali_datetime(local_stamp).replace(" - ", "، ")



def server_datetime_payload(db: Session, value: datetime | None) -> tuple[str | None, str | None]:
    """Serialize a naive UTC database timestamp using the server-selected timezone."""
    if value is None:
        return None, None
    return _connection_time_payload(value, _configured_server_timezone(db))

def serialize_local_online_users(
    db: Session,
    admin: Admin | None = None,
    *,
    server_id: str = "local",
    server_name: str = "سرور اصلی",
    server_local: bool = True,
) -> list[dict[str, Any]]:
    """Return a stable JSON-ready online-session snapshot.

    The same serializer is used by the controller UI and Node Agent health
    snapshots, preventing the main panel and nodes from disagreeing about which
    sessions are visible. Xray rows are deduplicated by exact protocol/public IP
    because one client may open several TCP streams.
    """
    refresh_local_ppp_presence(db)
    query = (
        db.query(ConnectionLog)
        .options(joinedload(ConnectionLog.user))
        .join(VpnUser, VpnUser.id == ConnectionLog.user_id)
        .filter(ConnectionLog.is_online == True, ConnectionLog.device_limit_blocked == False)  # noqa: E712
    )
    if admin is not None and not can_view_all_users(admin):
        query = query.filter(VpnUser.owner_admin_id == admin.id)
    raw_sessions = query.order_by(ConnectionLog.connect_time.desc()).all()
    server_zone = _configured_server_timezone(db)

    def _stamp(value) -> float:
        return value.timestamp() if value else 0.0

    def _xray_rank(session: ConnectionLog) -> tuple:
        transferred = int(session.bytes_in or 0) + int(session.bytes_out or 0)
        return (
            1 if transferred > 0 else 0,
            _stamp(getattr(session, "last_activity_at", None)),
            _stamp(getattr(session, "protocol_evidence_at", None)),
            transferred,
            _stamp(session.connect_time),
            1 if str(session.protocol) == "vmess" else 0,
        )

    # A single public endpoint is one visible Xray device even when a buggy or
    # stale sibling VMess/VLESS observation exists.  Pick the protocol with the
    # strongest current traffic/evidence instead of showing two contradictory
    # rows (or the wrong VLESS label while the client is really on VMess).
    best_xray_by_device: dict[tuple[int, str], ConnectionLog] = {}
    for session in raw_sessions:
        if session.protocol not in XRAY_PROTOCOLS:
            continue
        public_identity = (session.ip_address or "").strip() or f"unknown:{int(session.id)}"
        key = (int(session.user_id), public_identity)
        previous = best_xray_by_device.get(key)
        if previous is None or _xray_rank(session) > _xray_rank(previous):
            best_xray_by_device[key] = session

    selected_xray_ids = {int(session.id) for session in best_xray_by_device.values()}
    sessions: list[ConnectionLog] = []
    for session in raw_sessions:
        if session.protocol in XRAY_PROTOCOLS and int(session.id) not in selected_xray_ids:
            continue
        sessions.append(session)

    grouped: dict[str, list[ConnectionLog]] = {}
    for session in sessions:
        username = session.user.username if session.user else "?"
        grouped.setdefault(username, []).append(session)

    result: list[dict[str, Any]] = []
    for username, user_sessions in grouped.items():
        first = user_sessions[0]
        user = first.user
        payload_sessions: list[dict[str, Any]] = []
        for session in user_sessions:
            connect_time_iso, connect_time_display = _connection_time_payload(session.connect_time, server_zone)
            payload_sessions.append({
                "id": int(session.id),
                "session_key": f"{server_id}:{int(session.id)}",
                "cluster_session_key": str(getattr(session, "cluster_session_key", "") or "") or None,
                "server_id": server_id,
                "server_name": server_name,
                "server_local": bool(server_local),
                "protocol": str(session.protocol),
                "platform": normalize_client_platform(session.protocol, session.platform),
                "client_info": session.client_info or None,
                "connect_time": connect_time_iso,
                "connect_time_display": connect_time_display,
                "session_bytes": int(session.bytes_in or 0) + int(session.bytes_out or 0),
                "ip_address": session.ip_address or None,
                "source_port": int(getattr(session, "source_port", 0) or 0) or None,
                "tunnel_ip": str(getattr(session, "tunnel_ip", "") or "") or None,
                "presence_state": str(getattr(session, "presence_state", "active") or "active"),
                "last_seen_at": session.last_seen_at.isoformat() if getattr(session, "last_seen_at", None) else None,
                "last_activity_at": session.last_activity_at.isoformat() if getattr(session, "last_activity_at", None) else None,
                "internet_blocked": bool(
                    session.protocol in XRAY_PROTOCOLS
                    and user
                    and getattr(user, f"{session.protocol}_internet_blocked", False)
                ),
                "device_limit_blocked": bool(
                    session.protocol in XRAY_PROTOCOLS
                    and getattr(session, "device_limit_blocked", False)
                ),
            })
        result.append({
            "user_id": int(first.user_id),
            "username": username,
            "session_count": len(payload_sessions),
            "used_bytes": int(user.used_bytes or 0) if user else 0,
            "quota_bytes": int(user.quota_bytes or 0) if user else 0,
            "sessions": payload_sessions,
        })
    return result
