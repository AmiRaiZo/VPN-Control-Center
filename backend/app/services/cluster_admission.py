from __future__ import annotations

import hashlib
import hmac
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

import requests
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import (
    ClusterAdmissionReservation,
    ConnectionLog,
    Setting,
    VpnNode,
    VpnUser,
)

logger = logging.getLogger("vpn-panel.cluster-admission")

# Reservations only bridge client-connect until the next two-second node
# presence publication. A short TTL prevents a lost disconnect/release request
# from rejecting an immediate reconnect for half a minute.
RESERVATION_TTL_SECONDS = 8
NODE_SNAPSHOT_MAX_AGE_SECONDS = 6
XRAY_PROTOCOLS = {"vmess", "vless"}
RECONNECT_HANDOVER_PROTOCOLS = {"l2tp", "pptp", "openvpn"}


@dataclass(frozen=True)
class ClusterAdmissionDecision:
    allowed: bool
    session_key: str
    replaces_session_key: str | None = None
    active_count: int = 0
    max_devices: int = 0
    reason: str | None = None


def _setting(db: Session, key: str, default: str = "") -> str:
    row = db.query(Setting).filter(Setting.key == key).first()
    return str(row.value if row and row.value is not None else default)


def _normalize_ip(value: str | None) -> str | None:
    value = str(value or "").strip().lower()
    return value if value and value not in {"unknown", "-", "none"} else None


def _parse_time(value, default: datetime | None = None) -> datetime:
    if isinstance(value, datetime):
        stamp = value
    else:
        try:
            stamp = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
        except Exception:
            stamp = default or datetime.utcnow()
    if stamp.tzinfo is not None:
        stamp = stamp.astimezone(timezone.utc).replace(tzinfo=None)
    return stamp


def build_cluster_session_key(
    username: str,
    protocol: str,
    *,
    pid: int | None = None,
    interface: str | None = None,
    tunnel_ip: str | None = None,
    source_port: int | None = None,
    public_ip: str | None = None,
) -> str:
    """Build a stable lifecycle key for one local tunnel hook.

    Exact hook retries produce the same key, while a new PPP process or a new
    OpenVPN pool address gets a different key. Xray deliberately collapses raw
    TCP streams to protocol+public-IP, matching its local max-device semantics.
    """
    proto = str(protocol or "").strip().lower()
    ip = _normalize_ip(public_ip) or "unknown"
    if proto in XRAY_PROTOCOLS:
        identity = f"xray|{username}|{proto}|{ip}"
    elif proto == "openvpn" and ip != "unknown" and int(source_port or 0) > 0:
        # trusted_ip:trusted_port is the exact TLS transport endpoint. It stays
        # stable for one live tunnel and changes on a real reconnect, even when
        # OpenVPN immediately reuses the same pool address.
        identity = f"hook|{username}|{proto}|peer:{ip}:{int(source_port)}"
    elif int(pid or 0) > 1:
        identity = f"hook|{username}|{proto}|pid:{int(pid)}"
    elif str(tunnel_ip or "").strip():
        identity = f"hook|{username}|{proto}|tun:{str(tunnel_ip).strip()}"
    elif str(interface or "").strip():
        identity = f"hook|{username}|{proto}|if:{str(interface).strip()}|ip:{ip}"
    else:
        identity = f"hook|{username}|{proto}|ip:{ip}"
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()


def build_xray_cluster_session_key(username: str, protocol: str, public_ip: str | None) -> str:
    return build_cluster_session_key(
        username,
        protocol,
        public_ip=public_ip,
    )


def _snapshot_fresh(node: VpnNode, snapshot: dict, now: datetime) -> bool:
    generated = snapshot.get("generated_at")
    if generated:
        stamp = _parse_time(generated, now - timedelta(days=365))
    else:
        stamp = getattr(node, "last_seen_at", None) or now - timedelta(days=365)
    return (now - stamp).total_seconds() <= NODE_SNAPSHOT_MAX_AGE_SECONDS


def _slot(
    *,
    server_key: str,
    session_key: str,
    protocol: str,
    public_ip: str | None,
    connect_time: datetime,
    source: str,
    source_port: int | None = None,
    tunnel_ip: str | None = None,
) -> dict:
    return {
        "server_key": str(server_key),
        "session_key": str(session_key),
        "protocol": str(protocol or "").lower(),
        "public_ip": _normalize_ip(public_ip),
        "connect_time": _parse_time(connect_time),
        "source": source,
        "source_port": int(source_port or 0) or None,
        "tunnel_ip": str(tunnel_ip or "").strip() or None,
    }


def _active_cluster_slots(db: Session, username: str, now: datetime) -> list[dict]:
    slots: dict[tuple[str, str], dict] = {}

    user = db.query(VpnUser).filter(VpnUser.username == username).first()
    if user:
        rows = db.query(ConnectionLog).filter(
            ConnectionLog.user_id == int(user.id),
            ConnectionLog.is_online == True,  # noqa: E712
            ConnectionLog.device_limit_blocked == False,  # noqa: E712
        ).all()
        for row in rows:
            protocol = str(row.protocol or "").lower()
            if protocol in XRAY_PROTOCOLS:
                session_key = build_xray_cluster_session_key(username, protocol, row.ip_address)
            else:
                session_key = str(getattr(row, "cluster_session_key", "") or "").strip()
                if not session_key:
                    session_key = f"legacy-local:{int(row.id or 0)}"
            item = _slot(
                server_key="local",
                session_key=session_key,
                protocol=protocol,
                public_ip=row.ip_address,
                connect_time=row.connect_time or now,
                source="local-log",
                source_port=getattr(row, "source_port", None),
                tunnel_ip=getattr(row, "tunnel_ip", None),
            )
            slots[(item["server_key"], item["session_key"])] = item

    nodes = db.query(VpnNode).filter(
        VpnNode.enabled == True,  # noqa: E712
        VpnNode.status == "online",
    ).all()
    for node in nodes:
        try:
            snapshot = json.loads(node.last_snapshot or "{}")
        except Exception:
            continue
        if not isinstance(snapshot, dict) or not _snapshot_fresh(node, snapshot, now):
            continue
        server_key = f"node:{int(node.id)}"
        for group in snapshot.get("online_users") or []:
            if not isinstance(group, dict) or str(group.get("username") or "") != username:
                continue
            for raw in group.get("sessions") or []:
                if not isinstance(raw, dict):
                    continue
                protocol = str(raw.get("protocol") or "").lower()
                public_ip = raw.get("ip_address")
                if protocol in XRAY_PROTOCOLS:
                    session_key = build_xray_cluster_session_key(username, protocol, public_ip)
                else:
                    session_key = str(raw.get("cluster_session_key") or "").strip()
                    if not session_key:
                        session_key = f"legacy-node:{int(node.id)}:{int(raw.get('id') or 0)}"
                item = _slot(
                    server_key=server_key,
                    session_key=session_key,
                    protocol=protocol,
                    public_ip=public_ip,
                    connect_time=_parse_time(raw.get("connect_time"), now),
                    source="node-snapshot",
                    source_port=raw.get("source_port"),
                    tunnel_ip=raw.get("tunnel_ip"),
                )
                slots[(server_key, session_key)] = item

    return list(slots.values())


def _clean_reservations(db: Session, now: datetime) -> None:
    db.query(ClusterAdmissionReservation).filter(
        ClusterAdmissionReservation.expires_at < now
    ).delete(synchronize_session=False)
    db.flush()


def _reservation_slots(db: Session, username: str) -> tuple[list[dict], list[ClusterAdmissionReservation]]:
    rows = db.query(ClusterAdmissionReservation).filter(
        ClusterAdmissionReservation.username == username
    ).all()
    slots = [
        _slot(
            server_key=row.server_key,
            session_key=row.session_key,
            protocol=row.protocol,
            public_ip=row.ip_address,
            connect_time=row.connect_time,
            source="reservation",
        )
        for row in rows
    ]
    return slots, rows


def _upsert_reservation(
    db: Session,
    *,
    username: str,
    server_key: str,
    session_key: str,
    protocol: str,
    public_ip: str | None,
    connect_time: datetime,
    replaces_session_key: str | None,
    now: datetime,
) -> ClusterAdmissionReservation:
    row = db.query(ClusterAdmissionReservation).filter(
        ClusterAdmissionReservation.server_key == server_key,
        ClusterAdmissionReservation.session_key == session_key,
    ).first()
    if row is None:
        row = ClusterAdmissionReservation(
            username=username,
            server_key=server_key,
            session_key=session_key,
        )
        db.add(row)
    row.username = username
    row.protocol = str(protocol or "").lower()
    row.ip_address = _normalize_ip(public_ip)
    row.connect_time = _parse_time(connect_time, now)
    row.replaces_session_key = replaces_session_key
    row.last_seen_at = now
    row.expires_at = now + timedelta(seconds=RESERVATION_TTL_SECONDS)
    db.flush()
    return row


def reserve_on_controller(
    db: Session,
    *,
    username: str,
    server_key: str,
    session_key: str,
    protocol: str,
    public_ip: str | None,
    connect_time: datetime | None = None,
    source_port: int | None = None,
    tunnel_ip: str | None = None,
) -> ClusterAdmissionDecision:
    """Atomically reserve one account slot across the controller and all nodes."""
    now = datetime.utcnow()
    protocol = str(protocol or "").lower()
    public_ip = _normalize_ip(public_ip)
    incoming_time = _parse_time(connect_time, now)

    user = (
        db.query(VpnUser)
        .filter(VpnUser.username == username)
        .with_for_update()
        .first()
    )
    if user is None:
        return ClusterAdmissionDecision(False, session_key, reason="user_not_found")

    _clean_reservations(db, now)
    active_slots = _active_cluster_slots(db, username, now)
    reservation_slots, reservation_rows = _reservation_slots(db, username)

    # A reconnect reservation temporarily replaces one still-visible old
    # snapshot row. Ignore that old row until the node publishes its new state.
    replacement_targets = {
        (row.server_key, row.replaces_session_key)
        for row in reservation_rows
        if row.replaces_session_key
    }
    merged: dict[tuple[str, str], dict] = {}
    for item in active_slots + reservation_slots:
        key = (item["server_key"], item["session_key"])
        if key in replacement_targets:
            continue
        previous = merged.get(key)
        if (
            previous is None
            or item["connect_time"] < previous["connect_time"]
            or (
                item["connect_time"] == previous["connect_time"]
                and item["source"] == "reservation"
                and previous["source"] != "reservation"
            )
        ):
            merged[key] = item

    incoming_identity = (str(server_key), str(session_key))
    incoming_was_reserved = any(
        row.server_key == str(server_key) and row.session_key == str(session_key)
        for row in reservation_rows
    )
    # Re-evaluate the incoming identity instead of automatically trusting a
    # stale active snapshot. This lets Xray candidates that appeared just before
    # central admission still be denied correctly when the fleet cap is full.
    existing = merged.pop(incoming_identity, None)
    if existing is not None and existing["connect_time"] < incoming_time:
        incoming_time = existing["connect_time"]

    limit = max(0, int(user.max_devices or 0))
    replaces_session_key: str | None = None

    # A replacement tunnel from the same server, protocol and public endpoint
    # must not consume a second slot while the previous row is still visible.
    # This includes OpenVPN ping-restart: the old client can remain in status for
    # a few seconds after the replacement has already reached client-connect.
    # Different servers, protocols and public endpoints remain independent.
    if limit > 0 and len(merged) >= limit and protocol in RECONNECT_HANDOVER_PROTOCOLS and public_ip:
        matching = [
            item for item in merged.values()
            if item["server_key"] == str(server_key)
            and item["protocol"] == protocol
            and item["public_ip"] == public_ip
        ]
        if len(matching) == 1:
            old = matching[0]
            replaces_session_key = old["session_key"]
            incoming_time = min(incoming_time, old["connect_time"])
            merged.pop((old["server_key"], old["session_key"]), None)

    incoming = _slot(
        server_key=str(server_key),
        session_key=str(session_key),
        protocol=protocol,
        public_ip=public_ip,
        connect_time=incoming_time,
        source="reservation" if incoming_was_reserved else "incoming",
        source_port=source_port,
        tunnel_ip=tunnel_ip,
    )
    candidates = list(merged.values()) + [incoming]
    candidates.sort(key=lambda item: (
        item["connect_time"],
        0 if item["source"] == "reservation" else 1,
        item["server_key"],
        item["session_key"],
    ))

    if limit > 0:
        admitted = {
            (item["server_key"], item["session_key"])
            for item in candidates[:limit]
        }
        allowed = incoming_identity in admitted
    else:
        allowed = True

    if not allowed:
        db.query(ClusterAdmissionReservation).filter(
            ClusterAdmissionReservation.server_key == str(server_key),
            ClusterAdmissionReservation.session_key == str(session_key),
        ).delete(synchronize_session=False)
        db.flush()
        return ClusterAdmissionDecision(
            False,
            session_key,
            active_count=len(merged),
            max_devices=limit,
            reason="max_devices_reached_all_protocols",
        )

    _upsert_reservation(
        db,
        username=username,
        server_key=str(server_key),
        session_key=str(session_key),
        protocol=protocol,
        public_ip=public_ip,
        connect_time=incoming_time,
        replaces_session_key=replaces_session_key,
        now=now,
    )
    return ClusterAdmissionDecision(
        True,
        session_key,
        replaces_session_key=replaces_session_key,
        active_count=min(len(candidates), limit or len(candidates)),
        max_devices=limit,
    )


def release_on_controller(db: Session, *, server_key: str, session_key: str) -> int:
    deleted = db.query(ClusterAdmissionReservation).filter(
        ClusterAdmissionReservation.server_key == str(server_key),
        ClusterAdmissionReservation.session_key == str(session_key),
    ).delete(synchronize_session=False)
    db.flush()
    return int(deleted or 0)


def release_missing_xray_on_controller(
    db: Session,
    *,
    server_key: str,
    active_session_keys: Iterable[str],
) -> int:
    active = {str(value) for value in active_session_keys if str(value)}
    rows = db.query(ClusterAdmissionReservation).filter(
        ClusterAdmissionReservation.server_key == str(server_key),
        ClusterAdmissionReservation.protocol.in_(sorted(XRAY_PROTOCOLS)),
    ).all()
    removed = 0
    for row in rows:
        if row.session_key not in active:
            db.delete(row)
            removed += 1
    if removed:
        db.flush()
    return removed


def registered_node_from_token(db: Session, token: str | None) -> VpnNode | None:
    supplied = str(token or "")
    if not supplied:
        return None
    for node in db.query(VpnNode).filter(VpnNode.enabled == True).all():  # noqa: E712
        expected = str(node.api_token or "")
        if expected and hmac.compare_digest(supplied, expected):
            return node
    return None


def _node_controller_config(db: Session) -> tuple[str, bool]:
    url = _setting(db, "node_controller_url").strip().rstrip("/")
    verify_raw = _setting(db, "node_controller_verify_tls", "1").strip().lower()
    verify_tls = verify_raw not in {"0", "false", "no", "off"}
    if not url:
        env = Path("/var/lib/vpn-panel/node-registration.env")
        try:
            values: dict[str, str] = {}
            for line in env.read_text(encoding="utf-8", errors="ignore").splitlines():
                if "=" not in line or line.lstrip().startswith("#"):
                    continue
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip().strip("'\"")
            url = values.get("CONTROLLER_URL", "").strip().rstrip("/")
            verify_tls = values.get("CONTROLLER_VERIFY_TLS", "1").strip().lower() not in {
                "0", "false", "no", "off"
            }
        except Exception:
            pass
    if url.endswith("/api"):
        url = url[:-4]
    return url, verify_tls


def _local_node_token(db: Session) -> str:
    from app.services.node_manager import get_or_create_agent_token
    return get_or_create_agent_token(db)


def reserve_cluster_session(
    db: Session,
    *,
    user: VpnUser,
    protocol: str,
    public_ip: str | None,
    pid: int | None,
    interface: str | None,
    tunnel_ip: str | None,
    source_port: int | None = None,
    connect_time: datetime,
) -> ClusterAdmissionDecision:
    from app.services.node_manager import is_node_installation

    session_key = build_cluster_session_key(
        user.username,
        protocol,
        pid=pid,
        interface=interface,
        tunnel_ip=tunnel_ip,
        source_port=source_port,
        public_ip=public_ip,
    )
    if not is_node_installation(db):
        return reserve_on_controller(
            db,
            username=user.username,
            server_key="local",
            session_key=session_key,
            protocol=protocol,
            public_ip=public_ip,
            connect_time=connect_time,
            source_port=source_port,
            tunnel_ip=tunnel_ip,
        )

    if int(user.max_devices or 0) == 0:
        return ClusterAdmissionDecision(True, session_key, max_devices=0)

    controller_url, verify_tls = _node_controller_config(db)
    if not controller_url:
        # This is infrastructure unavailability, not an authoritative account
        # denial. Hook callers translate 5xx into a temporary fail-open and the
        # controller/scheduler reconciles the session when connectivity returns.
        raise HTTPException(status_code=503, detail="cluster_admission_unavailable")
    try:
        response = requests.post(
            f"{controller_url}/api/node-agent/admission/reserve",
            headers={"X-Node-Token": _local_node_token(db)},
            json={
                "username": user.username,
                "protocol": str(protocol or "").lower(),
                "ip_address": public_ip,
                "session_key": session_key,
                "connect_time": connect_time.isoformat() + "Z",
                "source_port": int(source_port or 0) or None,
                "tunnel_ip": str(tunnel_ip or "").strip() or None,
            },
            timeout=(1.0, 2.0),
            verify=verify_tls,
        )
        data = response.json() if response.content else {}
        if response.status_code == 403:
            raise HTTPException(status_code=403, detail=str(data.get("detail") or "max_devices_reached_all_nodes"))
        response.raise_for_status()
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("cluster admission controller unavailable: %s", exc)
        # A controller timeout must not be misreported as bad credentials or
        # disconnect every protocol on the node. 503 is intentionally handled
        # as temporary by admission_guard.sh; once the controller is reachable,
        # the normal snapshots/reservations reconcile the authenticated tunnel.
        raise HTTPException(status_code=503, detail="cluster_admission_unavailable") from exc
    return ClusterAdmissionDecision(
        bool(data.get("allowed", True)),
        session_key,
        replaces_session_key=str(data.get("replaces_session_key") or "") or None,
        active_count=int(data.get("active_count") or 0),
        max_devices=int(data.get("max_devices") or 0),
        reason=data.get("reason"),
    )


def release_cluster_session(db: Session, *, session_key: str) -> None:
    from app.services.node_manager import is_node_installation

    if not session_key:
        return
    if not is_node_installation(db):
        release_on_controller(db, server_key="local", session_key=session_key)
        return
    controller_url, verify_tls = _node_controller_config(db)
    if not controller_url:
        return
    try:
        requests.post(
            f"{controller_url}/api/node-agent/admission/release",
            headers={"X-Node-Token": _local_node_token(db)},
            json={"session_key": session_key},
            timeout=(0.8, 1.5),
            verify=verify_tls,
        )
    except Exception:
        # Reservation TTL and the controller's fresh node snapshot make release
        # loss self-healing; disconnect hooks must never be delayed or failed.
        return


def reconcile_cluster_xray_candidates(
    db: Session,
    candidates: list[dict],
) -> set[str]:
    """Return session keys denied by the fleet-wide budget.

    Remote nodes use one authenticated batch request every presence pass. The
    batch also releases Xray reservations no longer present on that node.
    """
    from app.services.node_manager import is_node_installation

    active_keys = [str(item.get("session_key") or "") for item in candidates]
    denied: set[str] = set()
    if not is_node_installation(db):
        release_missing_xray_on_controller(db, server_key="local", active_session_keys=active_keys)
        for item in candidates:
            decision = reserve_on_controller(
                db,
                username=str(item.get("username") or ""),
                server_key="local",
                session_key=str(item.get("session_key") or ""),
                protocol=str(item.get("protocol") or ""),
                public_ip=item.get("ip_address"),
                connect_time=_parse_time(item.get("connect_time"), datetime.utcnow()),
            )
            if not decision.allowed:
                denied.add(decision.session_key)
        return denied

    finite = [item for item in candidates if int(item.get("max_devices") or 0) > 0]
    if not finite:
        return denied
    controller_url, verify_tls = _node_controller_config(db)
    if not controller_url:
        logger.warning("cluster Xray admission controller is not configured; preserving live sessions")
        return set()
    try:
        response = requests.post(
            f"{controller_url}/api/node-agent/admission/xray-batch",
            headers={"X-Node-Token": _local_node_token(db)},
            json={"candidates": finite, "active_session_keys": active_keys},
            timeout=(1.0, 3.0),
            verify=verify_tls,
        )
        response.raise_for_status()
        data = response.json() if response.content else {}
        return {str(value) for value in data.get("denied_session_keys") or []}
    except Exception as exc:
        # Do not mass-disconnect every VMess/VLESS user because one controller
        # request timed out. Existing authenticated streams stay up; the next
        # successful batch re-applies the fleet-wide device budget.
        logger.warning("cluster Xray admission unavailable; preserving live sessions: %s", exc)
        return set()
