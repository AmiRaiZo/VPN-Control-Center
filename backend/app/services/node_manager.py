from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import uuid
from datetime import datetime
from pathlib import Path
from typing import Iterable
from urllib.parse import quote

import requests
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.config import get_settings
from app.database import SessionLocal
from app.models import BannedIP, ConnectionLog, InternetBlockedIP, OpenvpnExtraPort, Setting, VpnNode, VpnUser, XrayUsageCounter
from app.services.server_targets import endpoint_selected_for_user, user_selected_for_node, set_local_assignment_enabled
from app.services.user_lifecycle import ensure_first_connect, refresh_after_first_expiry

logger = logging.getLogger("vpn-panel.nodes")

NODE_MODE_KEY = "node_routing_mode"
NODE_AGENT_TOKEN_KEY = "node_agent_token"
NODE_CONTROLLER_ID_KEY = "node_controller_id"
NODE_MODES = {"local_only", "nodes_only", "all"}
NODE_PANEL_ENABLED_KEY = "node_panel_enabled"


TEMPORARY_NODE_ROLE_KEY = "node_temporary_main_mode"
TEMPORARY_NODE_ROLE_STARTED_KEY = "node_temporary_main_started_at"
DEPLOYMENT_ROLE_KEY = "deployment_role"
NODE_REGISTRATION_ENV = Path("/var/lib/vpn-panel/node-registration.env")
PANEL_ENV = Path("/opt/vpn-panel/panel.env")


_NODE_HEALTH_FAILURE_LOCK = threading.Lock()
_NODE_HEALTH_FAILURES: dict[int, int] = {}
_LOCAL_SNAPSHOT_CACHE_LOCK = threading.Lock()
_LOCAL_SNAPSHOT_CACHE: dict[str, object] = {"generated_at": 0.0, "snapshot": None}
_LOCAL_PRESENCE_CACHE_LOCK = threading.Lock()
_LOCAL_PRESENCE_CACHE: dict[str, object] = {"generated_at": 0.0, "snapshot": None}
_PROTOCOL_DOMAIN_CACHE_LOCK = threading.Lock()
_PROTOCOL_DOMAIN_CACHE: dict[tuple[str, str], tuple[float, bool]] = {}


def invalidate_local_snapshot_cache() -> None:
    """Discard a node snapshot immediately after a local session transition.

    The controller polls a node every four seconds, while the node health
    endpoint normally reuses a full snapshot for up to eight seconds.  Without
    explicit invalidation, a correctly processed PPP disconnect could
    therefore remain visible on the controller until that old snapshot aged
    out.  Connection/disconnection paths call this helper after their database
    transaction commits, so the next controller poll observes current state.
    """
    with _LOCAL_SNAPSHOT_CACHE_LOCK:
        _LOCAL_SNAPSHOT_CACHE["generated_at"] = 0.0
        _LOCAL_SNAPSHOT_CACHE["snapshot"] = None
    with _LOCAL_PRESENCE_CACHE_LOCK:
        _LOCAL_PRESENCE_CACHE["generated_at"] = 0.0
        _LOCAL_PRESENCE_CACHE["snapshot"] = None


def _protocol_domain_points_directly(domain: str, public_ip: str, *, ttl_seconds: float = 60.0) -> bool:
    """Return True only when the protocol domain resolves directly to this host.

    VPN transports such as OpenVPN and L2TP cannot traverse a normal CDN/HTTP
    reverse proxy.  A domain can become proxied after it was originally saved,
    leaving ``vpn_domain_status=active`` stale.  Cache DNS briefly so node health
    snapshots remain cheap while still falling back to the raw IP within a minute.
    """
    domain = str(domain or "").strip().rstrip(".")
    public_ip = str(public_ip or "").strip()
    if not domain or not public_ip:
        return False
    key = (domain.lower(), public_ip)
    now = time.monotonic()
    with _PROTOCOL_DOMAIN_CACHE_LOCK:
        cached = _PROTOCOL_DOMAIN_CACHE.get(key)
        if cached and now - cached[0] <= max(10.0, float(ttl_seconds)):
            return bool(cached[1])
    direct = False
    try:
        addresses = {
            item[4][0] for item in socket.getaddrinfo(domain, None, socket.AF_INET, socket.SOCK_STREAM)
            if item and item[4]
        }
        direct = public_ip in addresses
    except OSError:
        direct = False
    with _PROTOCOL_DOMAIN_CACHE_LOCK:
        _PROTOCOL_DOMAIN_CACHE[key] = (now, direct)
    return direct


def _node_health_failure_count(node_id: int, *, reset: bool = False) -> int:
    """Track consecutive controller-side probe failures without polluting UI state.

    A public node endpoint may occasionally need more than the controller read
    timeout while the node is sampling protocol runtime.  Persisting that one
    timeout in ``last_error`` made an online card flash red and then heal on the
    next cycle.  The counter deliberately lives in process memory: it only
    gates transient display/status changes and is safe to reset after an API
    restart.
    """
    key = int(node_id or 0)
    with _NODE_HEALTH_FAILURE_LOCK:
        if reset:
            _NODE_HEALTH_FAILURES.pop(key, None)
            return 0
        value = int(_NODE_HEALTH_FAILURES.get(key, 0) or 0) + 1
        _NODE_HEALTH_FAILURES[key] = value
        return value


def build_local_ping(db: Session) -> dict:
    """Return a cheap authenticated liveness response for controller fallback."""
    return {
        "status": "ok",
        "version": _read_version(),
        "public_address": _public_address(db),
        "server_role": effective_server_role(db),
        "panel_server_role": panel_ui_server_role(db),
        "node_panel_enabled": node_panel_enabled(db),
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }


def build_cached_local_snapshot(db: Session, *, max_age_seconds: float = 8.0, force: bool = False) -> dict:
    """Build the expensive Node Agent snapshot at most once per short window.

    The controller polls all nodes frequently so Online Users remains live. A
    full snapshot also reads protocol runtime, usage and sessions; rebuilding it
    for every four-second request can briefly saturate a small VPS and cause a
    false read timeout.  Serving an immutable copy for a few seconds removes
    that burst while keeping remote presence suitably fresh.
    """
    now = time.monotonic()
    with _LOCAL_SNAPSHOT_CACHE_LOCK:
        generated_at = float(_LOCAL_SNAPSHOT_CACHE.get("generated_at") or 0.0)
        cached = _LOCAL_SNAPSHOT_CACHE.get("snapshot")
        if not force and isinstance(cached, dict) and now - generated_at <= max(1.0, float(max_age_seconds)):
            return json.loads(json.dumps(cached, ensure_ascii=False))
        snapshot = build_local_snapshot(db)
        _LOCAL_SNAPSHOT_CACHE["generated_at"] = now
        _LOCAL_SNAPSHOT_CACHE["snapshot"] = snapshot
        return json.loads(json.dumps(snapshot, ensure_ascii=False))



def build_cached_local_presence(db: Session, *, max_age_seconds: float = 1.0, force: bool = False) -> dict:
    """Return only live sessions for the controller's two-second poll.

    Full node health inspects protocol runtime, settings and usage and should not
    run twice per second. This small endpoint reads the already-reconciled
    ConnectionLog rows and is invalidated immediately by connect/disconnect
    hooks, so fleet-wide max_devices decisions stop seeing ghost sessions.
    """
    now = time.monotonic()
    with _LOCAL_PRESENCE_CACHE_LOCK:
        generated_at = float(_LOCAL_PRESENCE_CACHE.get("generated_at") or 0.0)
        cached = _LOCAL_PRESENCE_CACHE.get("snapshot")
        if not force and isinstance(cached, dict) and now - generated_at <= max(0.25, float(max_age_seconds)):
            return json.loads(json.dumps(cached, ensure_ascii=False))
        from app.services.online_sessions import serialize_local_online_users

        node_name = _get(db, "node_name", "Node").strip() or "Node"
        online_users = serialize_local_online_users(
            db, None, server_id="local", server_name=node_name, server_local=True
        )
        snapshot = {
            "status": "ok",
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "online_users": online_users,
        }
        _LOCAL_PRESENCE_CACHE["generated_at"] = now
        _LOCAL_PRESENCE_CACHE["snapshot"] = snapshot
        return json.loads(json.dumps(snapshot, ensure_ascii=False))

def _env_value(path: Path, key: str) -> str:
    try:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            if not line or line.lstrip().startswith("#") or "=" not in line:
                continue
            name, value = line.split("=", 1)
            if name.strip() == key:
                return value.strip().strip("\"\'")
    except Exception:
        pass
    return ""


def is_node_installation(db: Session) -> bool:
    """Return the durable deployment identity of this host.

    ``server_role`` was historically toggled during legacy updates, so it is
    not safe as the only source of UI identity.  Controller registration and
    the immutable deployment marker survive API restarts and browser handoffs.
    """
    deployment_role = _get(db, DEPLOYMENT_ROLE_KEY).strip().lower()
    if deployment_role == "node":
        return True
    if deployment_role == "main":
        return False

    if NODE_REGISTRATION_ENV.is_file():
        controller = _env_value(NODE_REGISTRATION_ENV, "CONTROLLER_URL")
        node_name = _env_value(NODE_REGISTRATION_ENV, "NODE_NAME")
        node_url = _env_value(NODE_REGISTRATION_ENV, "NODE_PUBLIC_URL")
        if controller and (node_name or node_url):
            return True

    panel_role = _env_value(PANEL_ENV, "DEPLOYMENT_ROLE") or _env_value(PANEL_ENV, "SERVER_ROLE")
    if panel_role.strip().lower() == "node":
        return True

    controller_url = _get(db, "node_controller_url").strip()
    controller_token = _get(db, "node_controller_token").strip()
    node_name = _get(db, "node_name").strip()
    node_public_url = _get(db, "node_public_url").strip()
    return bool(controller_url and controller_token and (node_name or node_public_url))


def effective_server_role(db: Session) -> str:
    """Return the authoritative deployment role.

    An explicit ``deployment_role`` is the durable source of truth. Older
    releases evaluated a stale ``server_role=node`` with OR semantics, so an
    administrator could deliberately convert a host to ``main`` and see it
    revert to the node UI after the next API restart.
    """
    deployment_role = _get(db, DEPLOYMENT_ROLE_KEY).strip().lower()
    if deployment_role in {"main", "node"}:
        return deployment_role

    raw = _get(db, "server_role", "main").strip().lower()
    if raw == "node":
        return "node"
    # Legacy nodes may have server_role=main after an interrupted central
    # update but still carry registration markers. Preserve that recovery path
    # only when no explicit deployment_role exists.
    return "node" if is_node_installation(db) else "main"


def node_panel_enabled(db: Session) -> bool:
    """Whether a node should render the restricted node-specific UI.

    This setting is deliberately independent from the durable deployment role:
    disabling the node panel changes only the local web-panel experience while
    the host remains registered and operational as a controller-managed node.
    """
    if not is_node_installation(db):
        return False
    raw = _get(db, NODE_PANEL_ENABLED_KEY, "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def panel_ui_server_role(db: Session) -> str:
    return "node" if effective_server_role(db) == "node" and node_panel_enabled(db) else "main"


def set_local_node_panel_enabled(db: Session, enabled: bool) -> bool:
    _set(db, NODE_PANEL_ENABLED_KEY, "1" if enabled else "0")
    db.commit()
    return bool(enabled)


def ensure_deployment_identity(db: Session) -> bool:
    """Normalize all role markers without overriding an explicit conversion."""
    role = effective_server_role(db)
    changed = False
    if role == "node":
        if _get(db, DEPLOYMENT_ROLE_KEY).strip().lower() != "node":
            _set(db, DEPLOYMENT_ROLE_KEY, "node")
            changed = True
        if _get(db, "server_role", "main").strip().lower() != "node":
            _set(db, "server_role", "node")
            changed = True
        if _get(db, "local_services_mode", "1").strip() != "1":
            _set(db, "local_services_mode", "1")
            changed = True
    else:
        # Explicit main mode wins over every stale node marker. This is what
        # makes a Node -> full-controller conversion durable across restarts.
        if _get(db, DEPLOYMENT_ROLE_KEY).strip().lower() != "main":
            _set(db, DEPLOYMENT_ROLE_KEY, "main")
            changed = True
        if _get(db, "server_role", "main").strip().lower() != "main":
            _set(db, "server_role", "main")
            changed = True
        if _get(db, NODE_PANEL_ENABLED_KEY, "0").strip().lower() not in {"0", "false", "no", "off"}:
            _set(db, NODE_PANEL_ENABLED_KEY, "0")
            changed = True
        if _get(db, TEMPORARY_NODE_ROLE_KEY, "0").strip().lower() not in {"0", "false", "no", "off", ""}:
            _set(db, TEMPORARY_NODE_ROLE_KEY, "0")
            changed = True
        if _get(db, TEMPORARY_NODE_ROLE_STARTED_KEY).strip():
            _set(db, TEMPORARY_NODE_ROLE_STARTED_KEY, "")
            changed = True
    if changed:
        db.commit()
    return changed


def repair_orphaned_node_role(db: Session) -> bool:
    """Restore only genuinely interrupted temporary node updates.

    ``deployment_role=main`` means the conversion was deliberate and must never
    be undone by an old temporary marker or a stale ``server_role`` value.
    """
    deployment_role = _get(db, DEPLOYMENT_ROLE_KEY).strip().lower()
    if deployment_role == "main":
        changed = False
        if _get(db, "server_role", "main").strip().lower() != "main":
            _set(db, "server_role", "main")
            changed = True
        if _get(db, TEMPORARY_NODE_ROLE_KEY, "0").strip().lower() not in {"0", "false", "no", "off", ""}:
            _set(db, TEMPORARY_NODE_ROLE_KEY, "0")
            changed = True
        if _get(db, TEMPORARY_NODE_ROLE_STARTED_KEY).strip():
            _set(db, TEMPORARY_NODE_ROLE_STARTED_KEY, "")
            changed = True
        if changed:
            db.commit()
        return changed

    raw_role = _get(db, "server_role", "main").strip().lower()
    if raw_role == "node":
        return ensure_deployment_identity(db)

    temporary = _get(db, TEMPORARY_NODE_ROLE_KEY, "0").strip().lower() in {
        "1", "true", "yes", "on"
    }
    if not temporary and not is_node_installation(db):
        return False

    _set(db, DEPLOYMENT_ROLE_KEY, "node")
    _set(db, "server_role", "node")
    _set(db, "local_services_mode", "1")
    _set(db, TEMPORARY_NODE_ROLE_KEY, "0")
    _set(db, TEMPORARY_NODE_ROLE_STARTED_KEY, "")
    db.commit()
    logger.warning("Recovered durable node deployment identity after an interrupted update")
    return True


def _get(db: Session, key: str, default: str = "") -> str:
    row = db.query(Setting).filter(Setting.key == key).first()
    return (row.value if row and row.value is not None else default)


def _set(db: Session, key: str, value: str) -> None:
    row = db.query(Setting).filter(Setting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(Setting(key=key, value=value))


def get_node_mode(db: Session) -> str:
    mode = _get(db, NODE_MODE_KEY, "local_only")
    return mode if mode in NODE_MODES else "local_only"


def set_node_mode(db: Session, mode: str) -> str:
    if mode not in NODE_MODES:
        raise ValueError("حالت نود نامعتبر است")
    _set(db, NODE_MODE_KEY, mode)
    db.commit()
    return mode


def get_or_create_agent_token(db: Session, regenerate: bool = False) -> str:
    token = _get(db, NODE_AGENT_TOKEN_KEY)
    if regenerate or not token:
        token = secrets.token_urlsafe(36)
        _set(db, NODE_AGENT_TOKEN_KEY, token)
        db.commit()
    return token


def verify_agent_token(db: Session, supplied: str | None) -> bool:
    if not supplied:
        return False
    expected = get_or_create_agent_token(db)
    return hmac.compare_digest(expected, supplied)


def get_or_create_controller_id(db: Session) -> str:
    value = _get(db, NODE_CONTROLLER_ID_KEY)
    if not value:
        value = uuid.uuid4().hex
        _set(db, NODE_CONTROLLER_ID_KEY, value)
        db.commit()
    return value


def _bool(db: Session, key: str, default: bool = False) -> bool:
    raw = _get(db, key, "1" if default else "0").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _int(db: Session, key: str, default: int) -> int:
    try:
        value = int(_get(db, key, str(default)))
        return value if 1 <= value <= 65535 else default
    except (TypeError, ValueError):
        return default


def _public_address(db: Session) -> str:
    raw_ip = str(get_settings().PUBLIC_SERVER_IP or "").strip()
    vpn_domain = _get(db, "vpn_domain").strip()
    if vpn_domain and _get(db, "vpn_domain_status") == "active":
        if _protocol_domain_points_directly(vpn_domain, raw_ip):
            return vpn_domain
        logger.warning(
            "protocol domain is stale/proxied; publishing raw IP instead: domain=%s public_ip=%s",
            vpn_domain, raw_ip,
        )
    return raw_ip


def build_local_snapshot(db: Session) -> dict:
    """Small, stable public capability snapshot consumed by a controller."""
    from app.services.xray_manager import get_protocol_settings
    from app.services.protocol_admin import get_protocol_runtime_summary
    from app.services.vpn_manager import get_ipsec_psk

    address = _public_address(db)
    ikev2_ssl_domain = _get(db, "ikev2_ssl_domain").strip()
    ikev2_address = (
        ikev2_ssl_domain
        if ikev2_ssl_domain and _get(db, "ikev2_ssl_status") == "active"
        else get_settings().PUBLIC_SERVER_IP
    )
    ipsec_psk = get_ipsec_psk()
    protocols: dict[str, dict] = {
        "l2tp": {
            "enabled": _bool(db, "l2tp_enabled", True),
            "server_address": address,
            "port": _int(db, "l2tp_port", 1701),
            # L2TP/IPsec PSK is server-local.  Nodes can deliberately keep a
            # local override, so the controller must not substitute its own
            # PSK when rendering a node-specific subscription card.
            "ipsec_psk": ipsec_psk,
        },
        "pptp": {
            "enabled": _bool(db, "pptp_enabled", True),
            "server_address": address,
            "port": _int(db, "pptp_port", 1723),
        },
        "sstp": {
            "enabled": _bool(db, "sstp_enabled", False),
            "server_address": address,
            "port": _int(db, "sstp_port", 4433),
        },
        "ikev2": {
            "enabled": _bool(db, "ikev2_enabled", False),
            "server_address": ikev2_address,
            "ports": [500, 4500],
        },
        "openconnect": {
            "enabled": _bool(db, "openconnect_enabled", False),
            "server_address": address,
            "port": _int(db, "openconnect_port", 8443),
        },
        "openvpn": {
            "enabled": _bool(db, "openvpn_enabled", True),
            "server_address": address,
            "udp_port": _int(db, "openvpn_udp_port", 1194),
            "tcp_port": _int(db, "openvpn_tcp_port", 1194),
            "extra_ports": [
                {"port": int(row.port), "protocol": row.protocol, "active": bool(row.is_active)}
                for row in db.query(OpenvpnExtraPort).order_by(OpenvpnExtraPort.id).all()
            ],
        },
    }
    for protocol in ("vmess", "vless"):
        try:
            item = get_protocol_settings(db, protocol)
        except Exception:
            item = {"enabled": False}
        item = dict(item or {})
        item["enabled"] = bool(item.get("enabled"))
        item["server_address"] = item.get("server_address") or address
        protocols[protocol] = item

    from app.services.online_sessions import serialize_local_online_users
    node_name = _get(db, "node_name", "Node").strip() or "Node"
    online_users = serialize_local_online_users(
        db, None, server_id="local", server_name=node_name, server_local=True
    )
    online = sum(int(group.get("session_count") or 0) for group in online_users)
    managed_users = db.query(VpnUser).filter(VpnUser.node_managed == True).all()  # noqa: E712
    usage_totals = {row.username: int(row.used_bytes or 0) for row in managed_users}
    # Runtime lifecycle state is node-owned evidence, not controller config.
    # Sending it back prevents the controller from showing traffic while still
    # claiming the account has never connected.
    managed_ids = [int(row.id) for row in managed_users]
    latest_connections = {}
    if managed_ids:
        for user_id, stamp in (
            db.query(ConnectionLog.user_id, func.max(ConnectionLog.connect_time))
            .filter(ConnectionLog.user_id.in_(managed_ids))
            .group_by(ConnectionLog.user_id)
            .all()
        ):
            latest_connections[int(user_id)] = stamp
    online_names = {str(item.get("username") or "") for item in online_users}
    user_runtime = {
        row.username: {
            "first_connect_at": row.first_connect_at.isoformat() if row.first_connect_at else None,
            "expire_date": row.expire_date.isoformat() if row.expire_date else None,
            "last_connection_at": latest_connections.get(int(row.id)).isoformat() + "Z" if latest_connections.get(int(row.id)) else None,
            "is_online": row.username in online_names,
        }
        for row in managed_users
    }
    return {
        "status": "ok",
        "server_role": effective_server_role(db),
        "panel_server_role": panel_ui_server_role(db),
        "node_panel_enabled": node_panel_enabled(db),
        "version": _read_version(),
        "public_address": address,
        # Keep a top-level copy for old controllers while the canonical source
        # for new subscription pages is protocols.l2tp.ipsec_psk.
        "ipsec_psk": ipsec_psk,
        "protocols": protocols,
        # Actual daemon/listener/config health for the controller dashboard.
        # This is intentionally separate from ``protocols`` above, whose
        # values describe provisioning settings rather than service runtime.
        "protocol_statuses": get_protocol_runtime_summary(db),
        "online_sessions": int(online),
        "online_users": online_users,
        "usage_totals": usage_totals,
        "user_runtime": user_runtime,
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }


def _read_version() -> str:
    try:
        from pathlib import Path
        return Path("/opt/vpn-panel/VERSION").read_text().strip() or "unknown"
    except Exception:
        return "unknown"


def _node_out_snapshot(node: VpnNode) -> dict | None:
    if not node.last_snapshot:
        return None
    try:
        value = json.loads(node.last_snapshot)
        return value if isinstance(value, dict) else None
    except Exception:
        return None


def _node_protocol_domains(node: VpnNode) -> dict[str, str]:
    raw = getattr(node, "protocol_domains", None)
    if not raw:
        return {}
    try:
        value = json.loads(raw) if isinstance(raw, str) else raw
    except Exception:
        return {}
    if not isinstance(value, dict):
        return {}
    allowed = {"l2tp", "pptp", "openvpn", "openconnect", "sstp", "ikev2", "vmess", "vless"}
    return {str(k): str(v).strip() for k, v in value.items() if k in allowed and str(v or "").strip()}


def _apply_protocol_domain_overrides(snapshot: dict, node: VpnNode) -> dict:
    overrides = _node_protocol_domains(node)
    if not overrides:
        return snapshot
    result = dict(snapshot)
    protocols = {key: dict(value or {}) for key, value in (result.get("protocols") or {}).items()}
    for protocol, domain in overrides.items():
        item = dict(protocols.get(protocol) or {})
        item["server_address"] = domain
        protocols[protocol] = item
    result["protocols"] = protocols
    result["protocol_domains"] = overrides
    return result


def node_to_dict(node: VpnNode) -> dict:
    return {
        "id": node.id,
        "name": node.name,
        "api_url": node.api_url,
        "enabled": bool(node.enabled),
        "user_assignment_enabled": bool(getattr(node, "user_assignment_enabled", True)),
        "node_panel_enabled": bool(getattr(node, "node_panel_enabled", True)),
        "protocol_domains": _node_protocol_domains(node),
        "verify_tls": bool(getattr(node, "verify_tls", True)),
        "weight": int(node.weight or 100),
        "ssh_host": getattr(node, "ssh_host", None),
        "ssh_port": int(getattr(node, "ssh_port", 22) or 22),
        "ssh_username": getattr(node, "ssh_username", None),
        "ssh_password_saved": bool(getattr(node, "ssh_password_enc", None)),
        "panel_admin_username": getattr(node, "panel_admin_username", None),
        "panel_admin_password_saved": bool(getattr(node, "panel_admin_password_enc", None)),
        "remote_admin_enabled": bool(getattr(node, "remote_admin_enabled", False)),
        "status": node.status or "unknown",
        "last_seen_at": node.last_seen_at,
        "last_error": node.last_error,
        "snapshot": _node_out_snapshot(node),
        "created_at": node.created_at,
    }



def set_remote_node_panel_enabled(node: VpnNode, enabled: bool, timeout: int = 12) -> bool:
    """Apply the controller's node-panel UI preference on the remote node."""
    response = requests.post(
        f"{node.api_url.rstrip('/')}/api/node-agent/panel-mode",
        headers={"X-Node-Token": node.api_token},
        json={"enabled": bool(enabled)},
        timeout=timeout,
        verify=bool(getattr(node, "verify_tls", True)),
    )
    response.raise_for_status()
    data = response.json()
    return bool(data.get("ok"))


def set_remote_node_role(node: VpnNode, role: str, timeout: int = 12) -> bool:
    """Tell a registered server to enter or leave restricted node mode.

    The call is best-effort so toggling a temporarily-offline node never makes
    the controller transaction fail.  The next successful edit/sync can retry.
    """
    if role not in {"main", "node"}:
        raise ValueError("invalid node role")
    response = requests.post(
        f"{node.api_url.rstrip('/')}/api/node-agent/role",
        headers={"X-Node-Token": node.api_token},
        json={"role": role},
        timeout=timeout,
        verify=bool(getattr(node, "verify_tls", True)),
    )
    response.raise_for_status()
    data = response.json()
    return bool(data.get("ok"))

def _node_request_error(exc: Exception, url: str) -> str:
    response = getattr(exc, "response", None)
    status = getattr(response, "status_code", None)
    if status == 521:
        return (
            f"Cloudflare HTTP 521 برای {url}: وب‌سرور مبدا نود روی پورت این URL پاسخ نمی‌دهد. "
            "معمولاً آدرس نود روی https/443 ثبت شده ولی Nginx پنل هنوز روی پورت HTTP دیگری مثل 8080 است، "
            "یا پورت 443 در فایروال/دیتاسنتر بسته است."
        )
    if status:
        detail = ""
        try:
            body = response.json()
            detail = str(body.get("detail") or body.get("message") or "") if isinstance(body, dict) else ""
        except Exception:
            detail = (getattr(response, "text", "") or "").strip()[:300]
        suffix = f": {detail}" if detail else ""
        return f"نود در {url} پاسخ HTTP {status} داد{suffix}"
    if isinstance(exc, requests.exceptions.SSLError):
        return f"گواهی HTTPS نود در {url} معتبر نیست یا با دامنه تطابق ندارد: {exc}"
    if isinstance(exc, requests.exceptions.ConnectTimeout):
        return f"مهلت اتصال به {url} تمام شد؛ پورت نود یا فایروال در دسترس نیست."
    if isinstance(exc, requests.exceptions.ConnectionError):
        return f"اتصال به وب‌سرور نود در {url} برقرار نشد: {exc}"
    return f"بررسی سلامت نود در {url} ناموفق بود: {exc}"


def probe_node_presence(api_url: str, api_token: str, verify_tls: bool = True, timeout: float = 2.0) -> dict:
    response = requests.get(
        f"{api_url.rstrip('/')}/api/node-agent/presence",
        headers={"X-Node-Token": api_token},
        timeout=(0.6, max(1.0, float(timeout))),
        verify=verify_tls,
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict) or payload.get("status") != "ok":
        raise RuntimeError("invalid node presence response")
    return payload


def probe_node_snapshot(api_url: str, api_token: str, verify_tls: bool = True, timeout: int = 15) -> dict:
    health_url = f"{api_url.rstrip('/')}/api/node-agent/health"
    try:
        response = requests.get(
            health_url,
            headers={"X-Node-Token": api_token},
            timeout=(min(4, max(2, int(timeout))), max(3, int(timeout))),
            verify=bool(verify_tls),
        )
        response.raise_for_status()
        snapshot = response.json()
        if not isinstance(snapshot, dict) or snapshot.get("status") != "ok":
            raise RuntimeError("پاسخ سلامت نود معتبر نیست")
        return snapshot
    except Exception as exc:
        raise RuntimeError(_node_request_error(exc, health_url)) from exc


def probe_node_ping(api_url: str, api_token: str, verify_tls: bool = True, timeout: int = 4) -> dict:
    """Probe only the lightweight authenticated liveness endpoint."""
    ping_url = f"{api_url.rstrip('/')}/api/node-agent/ping"
    try:
        response = requests.get(
            ping_url,
            headers={"X-Node-Token": api_token},
            timeout=(min(3, max(1, int(timeout))), max(2, int(timeout))),
            verify=bool(verify_tls),
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict) or payload.get("status") != "ok":
            raise RuntimeError("پاسخ ping نود معتبر نیست")
        return payload
    except Exception as exc:
        raise RuntimeError(_node_request_error(exc, ping_url)) from exc


def _merge_node_usage_snapshot(db: Session, node: VpnNode, snapshot: dict) -> int:
    """Merge cumulative per-node counters and first-connect lifecycle state.

    Usage and first-connect timestamps are runtime facts produced by the node.
    They must flow back to the controller; otherwise the next controller sync
    can leave ``used_bytes`` growing while ``first_connect_at`` stays NULL.
    """
    usage = snapshot.get("usage_totals") or {}
    if not isinstance(usage, dict):
        usage = {}
    runtime = snapshot.get("user_runtime") or {}
    if not isinstance(runtime, dict):
        runtime = {}

    generated_at = None
    try:
        raw_generated = str(snapshot.get("generated_at") or "").strip()
        if raw_generated:
            generated_at = datetime.fromisoformat(raw_generated.replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        generated_at = None
    generated_at = generated_at or datetime.utcnow()

    key = f"node_usage_cursor_v1_{int(node.id)}"
    try:
        cursors = json.loads(_get(db, key, "{}") or "{}")
    except Exception:
        cursors = {}
    if not isinstance(cursors, dict):
        cursors = {}

    changed = 0
    touched: set[str] = set()
    for username, raw in usage.items():
        username = str(username)
        touched.add(username)
        try:
            current = max(0, int(raw or 0))
        except (TypeError, ValueError):
            continue
        previous = max(0, int(cursors.get(username, 0) or 0))
        delta = current - previous if current >= previous else current
        user = db.query(VpnUser).filter(VpnUser.username == username).first()
        if user is not None:
            if delta > 0:
                user.used_bytes = int(user.used_bytes or 0) + delta
                changed += 1

            runtime_row = runtime.get(username) if isinstance(runtime.get(username), dict) else {}
            remote_first = None
            try:
                raw_first = str(runtime_row.get("first_connect_at") or "").strip()
                if raw_first:
                    remote_first = datetime.fromisoformat(raw_first.replace("Z", "+00:00")).replace(tzinfo=None)
            except Exception:
                remote_first = None

            # New nodes provide the exact timestamp. For an older node, any
            # positive cumulative usage is still conclusive evidence that a
            # successful connection occurred; use snapshot time as a safe
            # fallback rather than leaving the account pending forever.
            if remote_first is not None or current > 0:
                if ensure_first_connect(user, remote_first or generated_at):
                    changed += 1
        cursors[username] = current

    # Merge lifecycle state even for a zero-traffic/idle first connection.
    for username, raw_runtime in runtime.items():
        username = str(username)
        if username in touched or not isinstance(raw_runtime, dict):
            continue
        raw_first = str(raw_runtime.get("first_connect_at") or "").strip()
        if not raw_first:
            continue
        try:
            remote_first = datetime.fromisoformat(raw_first.replace("Z", "+00:00")).replace(tzinfo=None)
        except Exception:
            continue
        user = db.query(VpnUser).filter(VpnUser.username == username).first()
        if user is not None and ensure_first_connect(user, remote_first):
            changed += 1

    _set(db, key, json.dumps(cursors, ensure_ascii=False, separators=(",", ":")))
    return changed



def refresh_node(db: Session, node: VpnNode, timeout: int = 15) -> dict:
    try:
        snapshot = probe_node_snapshot(
            node.api_url, node.api_token, bool(getattr(node, "verify_tls", True)), timeout
        )
        _node_health_failure_count(int(node.id or 0), reset=True)
        desired_panel_mode = bool(getattr(node, "node_panel_enabled", True))
        remote_panel_mode = snapshot.get("node_panel_enabled")
        if remote_panel_mode is not None and bool(remote_panel_mode) != desired_panel_mode:
            try:
                set_remote_node_panel_enabled(node, desired_panel_mode, timeout=timeout)
                snapshot["node_panel_enabled"] = desired_panel_mode
                snapshot["panel_server_role"] = "node" if desired_panel_mode else "main"
            except Exception as mode_exc:
                logger.warning("Could not apply node panel mode to %s: %s", node.name, mode_exc)
        node.status = "online"
        node.last_seen_at = datetime.utcnow()
        node.last_error = None
        _merge_node_usage_snapshot(db, node, snapshot)
        node.last_snapshot = json.dumps(snapshot, ensure_ascii=False, separators=(",", ":"))
        db.commit()
        return snapshot
    except Exception as snapshot_exc:
        snapshot_message = str(snapshot_exc)[:1500]

        # A full health snapshot can be briefly slow because it includes live
        # sessions, usage and protocol runtime.  Verify the cheap Node Agent
        # ping before treating that as an outage.  When ping succeeds, preserve
        # the last good snapshot and never flash a red error on an online card.
        try:
            ping = probe_node_ping(
                node.api_url,
                node.api_token,
                bool(getattr(node, "verify_tls", True)),
                timeout=min(5, max(2, int(timeout) // 3)),
            )
        except Exception as ping_exc:
            failures = _node_health_failure_count(int(node.id or 0))
            recently_online = False
            if node.last_seen_at is not None:
                try:
                    recently_online = (datetime.utcnow() - node.last_seen_at).total_seconds() <= 45
                except Exception:
                    recently_online = False

            combined = f"{snapshot_message} | ping: {str(ping_exc)}"[:1500]
            if node.status == "online" and recently_online and failures < 3:
                node.status = "online"
                # Do not persist a one-off transport hiccup in the UI. The
                # server log still records it for diagnostics.
                node.last_error = None
                db.commit()
                logger.warning(
                    "Suppressed transient node-health failure %s/3 for %s: %s",
                    failures, node.name, combined,
                )
                raise RuntimeError(combined) from snapshot_exc

            node.status = "offline"
            node.last_error = combined
            db.commit()
            raise RuntimeError(combined) from snapshot_exc

        _node_health_failure_count(int(node.id or 0), reset=True)
        node.status = "online"
        node.last_seen_at = datetime.utcnow()
        node.last_error = None
        db.commit()
        logger.info("Node %s ping is healthy; retained cached snapshot after slow full health response", node.name)
        cached = _node_out_snapshot(node) or {}
        if not cached:
            cached = dict(ping)
        cached.setdefault("status", "ok")
        cached["controller_snapshot_cached"] = True
        return cached


def _user_payload(user: VpnUser) -> dict:
    return {
        "username": user.username,
        "password": user.password,
        "sub_token": user.sub_token,
        "enable_l2tp": bool(user.enable_l2tp),
        "enable_pptp": bool(user.enable_pptp),
        "enable_openvpn": bool(user.enable_openvpn),
        "enable_sstp": bool(user.enable_sstp),
        "enable_ikev2": bool(user.enable_ikev2),
        "enable_openconnect": bool(user.enable_openconnect),
        "enable_vmess": bool(user.enable_vmess),
        "enable_vless": bool(user.enable_vless),
        "vmess_internet_blocked": bool(getattr(user, "vmess_internet_blocked", False)),
        "vless_internet_blocked": bool(getattr(user, "vless_internet_blocked", False)),
        "xray_uuid": user.xray_uuid,
        "openvpn_auth_mode": user.openvpn_auth_mode,
        "sstp_auth_mode": user.sstp_auth_mode,
        "quota_bytes": int(user.quota_bytes or 0),
        "used_bytes": int(user.used_bytes or 0),
        "max_devices": int(user.max_devices or 0),
        "download_limit_mbps": int(user.download_limit_mbps or 0),
        "upload_limit_mbps": int(user.upload_limit_mbps or 0),
        "expire_mode": user.expire_mode,
        "expire_after_days": user.expire_after_days,
        "first_connect_at": user.first_connect_at.isoformat() if user.first_connect_at else None,
        "expire_date": user.expire_date.isoformat() if user.expire_date else None,
        "is_active": bool(user.is_active),
        "note": user.note,
    }



def _node_assigned_users(db: Session, node: VpnNode) -> list[VpnUser]:
    if not bool(getattr(node, "user_assignment_enabled", True)):
        return []
    return [
        user
        for user in db.query(VpnUser).filter(VpnUser.node_managed == False).order_by(VpnUser.id).all()  # noqa: E712
        if user_selected_for_node(user, int(node.id))
    ]


def _user_config_hash_from_payloads(users: list[dict]) -> str:
    normalized = [
        {key: value for key, value in raw.items() if key != "used_bytes"}
        for raw in users
    ]
    return hashlib.sha256(
        json.dumps(normalized, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()


def _node_expected_user_config_hash(db: Session, node: VpnNode) -> str:
    return _user_config_hash_from_payloads([_user_payload(user) for user in _node_assigned_users(db, node)])



NODE_GLOBAL_BANS_KEY_PREFIX = "node_global_bans_"
NODE_GLOBAL_CUTS_KEY_PREFIX = "node_global_cuts_"


def _controller_control_key(prefix: str, controller_id: str) -> str:
    return f"{prefix}{str(controller_id or '')[:32]}"


def _load_managed_ip_set(db: Session, key: str) -> set[str]:
    raw = _get(db, key, "[]")
    try:
        values = json.loads(raw)
    except Exception:
        return set()
    if not isinstance(values, list):
        return set()
    return {str(value).strip() for value in values if str(value).strip()}


def _global_controls_payload(db: Session) -> dict:
    """Return the controller-authoritative public-IP controls for Node sync."""
    return {
        "banned_ips": [
            {
                "ip_address": row.ip_address,
                "reason": row.reason,
            }
            for row in db.query(BannedIP).order_by(BannedIP.id.asc()).all()
        ],
        "internet_blocks": [
            {
                "ip_address": row.ip_address,
                "username": row.username,
                "protocol": row.protocol,
                "reason": row.reason,
                "blocked_by_username": row.blocked_by_username,
            }
            for row in db.query(InternetBlockedIP).order_by(InternetBlockedIP.id.asc()).all()
        ],
    }


def _normalize_control_items(items: list[dict] | None) -> dict[str, dict]:
    """Deduplicate controller snapshots while accepting only valid IPv4 keys."""
    import ipaddress

    result: dict[str, dict] = {}
    for raw in items or []:
        if not isinstance(raw, dict):
            continue
        value = str(raw.get("ip_address") or "").strip()
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            continue
        if parsed.version != 4:
            continue
        result[str(parsed)] = raw
    return result


def _normalize_ipv4_values(values: Iterable[str] | None) -> set[str]:
    import ipaddress

    result: set[str] = set()
    for raw in values or []:
        try:
            parsed = ipaddress.ip_address(str(raw or "").strip())
        except ValueError:
            continue
        if parsed.version == 4:
            result.add(str(parsed))
    return result


def apply_global_controls_snapshot(
    db: Session,
    controller_id: str,
    *,
    banned_ips: list[dict] | None,
    internet_blocks: list[dict] | None,
    force_unban_ips: Iterable[str] | None = None,
    force_restore_ips: Iterable[str] | None = None,
) -> dict:
    """Apply controller bans/cuts without deleting node-local control records.

    The node stores only the IPs that were created by this controller in two
    settings. A regular later snapshot removes only controller-managed rows.
    Explicit unban/restore tombstones are the intentional exception: they remove
    the matching IP everywhere, including a legacy or node-local collision.
    """
    from app.services.vpn_manager import (
        disconnect_sessions_by_ip,
        sync_internet_blocks,
        sync_ip_bans,
    )

    result = {
        "bans_created": 0,
        "bans_updated": 0,
        "bans_removed": 0,
        "cuts_created": 0,
        "cuts_updated": 0,
        "cuts_removed": 0,
    }
    disconnect_ips: set[str] = set()
    force_unban = _normalize_ipv4_values(force_unban_ips)
    force_restore = _normalize_ipv4_values(force_restore_ips)

    if banned_ips is not None:
        desired = _normalize_control_items(banned_ips)
        # The newest controller snapshot wins over an older queued tombstone.
        force_unban.difference_update(desired)
        key = _controller_control_key(NODE_GLOBAL_BANS_KEY_PREFIX, controller_id)
        previous = _load_managed_ip_set(db, key)
        managed: set[str] = set()

        for ip_address, raw in desired.items():
            row = db.query(BannedIP).filter(BannedIP.ip_address == ip_address).first()
            if row is None:
                row = BannedIP(
                    ip_address=ip_address,
                    reason=(str(raw.get("reason")).strip() if raw.get("reason") else None),
                    banned_by_admin_id=None,
                )
                db.add(row)
                managed.add(ip_address)
                disconnect_ips.add(ip_address)
                result["bans_created"] += 1
            elif ip_address in previous:
                new_reason = str(raw.get("reason")).strip() if raw.get("reason") else None
                if row.reason != new_reason or row.banned_by_admin_id is not None:
                    row.reason = new_reason
                    row.banned_by_admin_id = None
                    result["bans_updated"] += 1
                managed.add(ip_address)
            # Existing node-local rows already enforce the same IP. Do not
            # claim ownership so a controller-side unban cannot erase them.

        for ip_address in force_unban:
            row = db.query(BannedIP).filter(BannedIP.ip_address == ip_address).first()
            if row is not None:
                db.delete(row)
                result["bans_removed"] += 1
            managed.discard(ip_address)
            previous.discard(ip_address)

        for ip_address in previous - set(desired):
            row = db.query(BannedIP).filter(BannedIP.ip_address == ip_address).first()
            if row is not None:
                db.delete(row)
                result["bans_removed"] += 1
        _set(db, key, json.dumps(sorted(managed), ensure_ascii=False, separators=(",", ":")))

    if internet_blocks is not None:
        desired = _normalize_control_items(internet_blocks)
        force_restore.difference_update(desired)
        key = _controller_control_key(NODE_GLOBAL_CUTS_KEY_PREFIX, controller_id)
        previous = _load_managed_ip_set(db, key)
        managed: set[str] = set()

        for ip_address, raw in desired.items():
            row = db.query(InternetBlockedIP).filter(InternetBlockedIP.ip_address == ip_address).first()
            values = {
                "username": (str(raw.get("username")).strip() if raw.get("username") else None),
                "protocol": (str(raw.get("protocol")).strip() if raw.get("protocol") else None),
                "reason": (str(raw.get("reason")).strip() if raw.get("reason") else None),
                "blocked_by_username": (
                    str(raw.get("blocked_by_username")).strip()
                    if raw.get("blocked_by_username") else "controller"
                ),
            }
            if row is None:
                row = InternetBlockedIP(
                    ip_address=ip_address,
                    user_id=None,
                    blocked_by_admin_id=None,
                    **values,
                )
                db.add(row)
                managed.add(ip_address)
                disconnect_ips.add(ip_address)
                result["cuts_created"] += 1
            elif ip_address in previous:
                changed = False
                for field, value in values.items():
                    if getattr(row, field) != value:
                        setattr(row, field, value)
                        changed = True
                if row.user_id is not None or row.blocked_by_admin_id is not None:
                    row.user_id = None
                    row.blocked_by_admin_id = None
                    changed = True
                if changed:
                    result["cuts_updated"] += 1
                managed.add(ip_address)

        for ip_address in force_restore:
            row = db.query(InternetBlockedIP).filter(InternetBlockedIP.ip_address == ip_address).first()
            if row is not None:
                db.delete(row)
                result["cuts_removed"] += 1
            managed.discard(ip_address)
            previous.discard(ip_address)

        for ip_address in previous - set(desired):
            row = db.query(InternetBlockedIP).filter(InternetBlockedIP.ip_address == ip_address).first()
            if row is not None:
                db.delete(row)
                result["cuts_removed"] += 1
        _set(db, key, json.dumps(sorted(managed), ensure_ascii=False, separators=(",", ":")))

    db.commit()

    if banned_ips is not None:
        sync_ip_bans(db)
    if internet_blocks is not None:
        sync_internet_blocks(db)
    for ip_address in sorted(disconnect_ips):
        try:
            disconnect_sessions_by_ip(db, ip_address)
        except Exception:
            logger.exception("Could not disconnect newly controlled IP %s on node", ip_address)

    return result


def sync_node(db: Session, node: VpnNode, timeout: int = 45) -> dict:
    controller_id = get_or_create_controller_id(db)
    users = _node_assigned_users(db, node)
    user_payloads = [_user_payload(user) for user in users]
    expected_user_config_hash = _user_config_hash_from_payloads(user_payloads)
    from app.services.cert_manager import (
        ensure_controller_openvpn_pki, export_pki_bundle, pki_bundle_fingerprint,
    )
    from app.services.vpn_manager import get_ipsec_psk
    try:
        openvpn_pki = ensure_controller_openvpn_pki(db)
    except Exception as exc:
        logger.warning("Canonical OpenVPN PKI is not ready while syncing %s: %s", node.name, exc)
        openvpn_pki = export_pki_bundle()
    canonical_openvpn_fingerprint = pki_bundle_fingerprint(openvpn_pki)
    payload = {
        "controller_id": controller_id,
        "users": user_payloads,
        "openvpn_pki": openvpn_pki,
        "ipsec_psk": get_ipsec_psk(),
        **_global_controls_payload(db),
    }
    try:
        response = requests.post(
            f"{node.api_url.rstrip('/')}/api/node-agent/sync",
            headers={"X-Node-Token": node.api_token},
            json=payload,
            timeout=timeout,
            verify=bool(getattr(node, "verify_tls", True)),
        )
        response.raise_for_status()
        data = response.json()
        node.status = "online"
        node.last_seen_at = datetime.utcnow()
        node.last_error = None
        node_fingerprint = str(data.get("openvpn_pki_fingerprint") or "") if isinstance(data, dict) else ""
        _set(
            db,
            f"node_openvpn_pki_fingerprint_{int(node.id)}",
            node_fingerprint if canonical_openvpn_fingerprint and node_fingerprint == canonical_openvpn_fingerprint else "",
        )
        node_user_hash = str(data.get("user_config_hash") or "") if isinstance(data, dict) else ""
        auth_ready = bool(data.get("openvpn_auth_ready")) if isinstance(data, dict) else False
        _set(
            db,
            f"node_openvpn_user_config_hash_{int(node.id)}",
            node_user_hash if auth_ready and hmac.compare_digest(node_user_hash, expected_user_config_hash) else "",
        )
        db.commit()
        try:
            refresh_node(db, node, timeout=10)
        except Exception:
            pass
        return data
    except Exception as exc:
        node.status = "offline"
        node.last_error = str(exc)[:1500]
        db.commit()
        raise RuntimeError(node.last_error) from exc


def refresh_node_presence(db: Session, node: VpnNode, timeout: float = 2.0) -> dict:
    presence = probe_node_presence(
        node.api_url, node.api_token, bool(getattr(node, "verify_tls", True)), timeout
    )
    try:
        snapshot = json.loads(node.last_snapshot or "{}")
    except Exception:
        snapshot = {}
    if not isinstance(snapshot, dict):
        snapshot = {}
    snapshot.setdefault("status", "ok")
    snapshot["online_users"] = presence.get("online_users") or []
    snapshot["generated_at"] = str(presence.get("generated_at") or datetime.utcnow().isoformat() + "Z")
    snapshot["presence_only_update"] = True
    node.last_snapshot = json.dumps(snapshot, ensure_ascii=False, separators=(",", ":"))
    node.status = "online"
    node.last_seen_at = datetime.utcnow()
    node.last_error = None
    db.commit()
    return presence


def _refresh_one_node_presence(node_id: int) -> None:
    db = SessionLocal()
    try:
        node = db.query(VpnNode).filter(VpnNode.id == int(node_id), VpnNode.enabled == True).first()  # noqa: E712
        if not node:
            return
        try:
            refresh_node_presence(db, node, timeout=1.4)
        except Exception:
            # Full health owns offline/error state. A single missed fast poll
            # must not make a healthy node flap red.
            db.rollback()
    finally:
        db.close()


def refresh_all_node_presence() -> None:
    db = SessionLocal()
    try:
        node_ids = [int(value) for (value,) in db.query(VpnNode.id).filter(VpnNode.enabled == True).all()]  # noqa: E712
    finally:
        db.close()
    if not node_ids:
        return
    with ThreadPoolExecutor(max_workers=min(8, len(node_ids)), thread_name_prefix="vpn-node-presence") as pool:
        futures = [pool.submit(_refresh_one_node_presence, node_id) for node_id in node_ids]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception:
                logger.exception("Unexpected concurrent node-presence failure")


def _refresh_one_node(node_id: int) -> None:
    db = SessionLocal()
    try:
        node = db.query(VpnNode).filter(VpnNode.id == int(node_id), VpnNode.enabled == True).first()  # noqa: E712
        if not node:
            return
        try:
            refresh_node(db, node, timeout=12)
        except Exception:
            logger.info("Node %s is offline", node.name)
    finally:
        db.close()


def refresh_all_nodes() -> None:
    db = SessionLocal()
    try:
        node_ids = [int(value) for (value,) in db.query(VpnNode.id).filter(VpnNode.enabled == True).all()]  # noqa: E712
    finally:
        db.close()
    if not node_ids:
        return
    # One slow/offline node must not delay the online-session snapshot of every
    # other server. Each worker owns its SQLAlchemy session.
    with ThreadPoolExecutor(max_workers=min(8, len(node_ids)), thread_name_prefix="vpn-node-health") as pool:
        futures = [pool.submit(_refresh_one_node, node_id) for node_id in node_ids]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception:
                logger.exception("Unexpected concurrent node-health failure")


def _sync_one_node(node_id: int) -> None:
    db = SessionLocal()
    try:
        node = db.query(VpnNode).filter(VpnNode.id == int(node_id), VpnNode.enabled == True).first()  # noqa: E712
        if not node:
            return
        try:
            sync_node(db, node)
        except Exception:
            logger.exception("Failed to sync node %s", node.name)
    finally:
        db.close()


def sync_all_nodes() -> None:
    db = SessionLocal()
    try:
        node_ids = [int(value) for (value,) in db.query(VpnNode.id).filter(VpnNode.enabled == True).all()]  # noqa: E712
    finally:
        db.close()
    if not node_ids:
        return
    # PKI/user synchronization is independent per node. Running it concurrently
    # prevents one offline server from delaying every healthy server and keeps
    # controller upgrades bounded even with a large node fleet.
    with ThreadPoolExecutor(max_workers=min(8, len(node_ids)), thread_name_prefix="vpn-node-sync") as pool:
        futures = [pool.submit(_sync_one_node, node_id) for node_id in node_ids]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception:
                logger.exception("Unexpected concurrent node-sync failure")


def sync_all_nodes_async() -> None:
    thread = threading.Thread(target=sync_all_nodes, daemon=True, name="vpn-node-sync")
    thread.start()


_GLOBAL_CONTROLS_SYNC_LOCK = threading.Lock()
_GLOBAL_CONTROLS_SYNC_PENDING = threading.Event()
_GLOBAL_CONTROLS_PENDING_STATE_LOCK = threading.Lock()
_GLOBAL_CONTROLS_FORCE_UNBAN: set[str] = set()
_GLOBAL_CONTROLS_FORCE_RESTORE: set[str] = set()


def sync_global_controls_to_active_nodes(
    *,
    force_unban_ips: Iterable[str] | None = None,
    force_restore_ips: Iterable[str] | None = None,
) -> dict:
    """Push the current ban/cut snapshot concurrently to every enabled node.

    This lightweight path avoids sending users, PKI and protocol configuration
    for an urgent operator action. Offline nodes remain safe because the normal
    full sync also carries the same snapshot every 120 seconds and after they
    become reachable again.
    """
    db = SessionLocal()
    try:
        controller_id = get_or_create_controller_id(db)
        payload = {
            "controller_id": controller_id,
            **_global_controls_payload(db),
            "force_unban_ips": sorted(_normalize_ipv4_values(force_unban_ips)),
            "force_restore_ips": sorted(_normalize_ipv4_values(force_restore_ips)),
        }
        nodes = [
            {
                "id": int(row.id),
                "name": row.name,
                "api_url": row.api_url,
                "api_token": row.api_token,
                "verify_tls": bool(getattr(row, "verify_tls", True)),
            }
            for row in db.query(VpnNode).filter(VpnNode.enabled == True).order_by(VpnNode.id).all()  # noqa: E712
        ]
    finally:
        db.close()

    if not nodes:
        return {"ok": True, "total": 0, "succeeded": 0, "failed": 0, "results": []}

    def push(node: dict) -> dict:
        try:
            response = requests.post(
                f"{str(node['api_url']).rstrip('/')}/api/node-agent/global-controls/sync",
                headers={"X-Node-Token": node["api_token"]},
                json=payload,
                timeout=12,
                verify=bool(node["verify_tls"]),
            )
            if response.status_code >= 400:
                detail = response.text[-800:] or f"HTTP {response.status_code}"
                return {
                    "node_id": node["id"],
                    "name": node["name"],
                    "ok": False,
                    "status_code": response.status_code,
                    "detail": detail,
                }
            return {
                "node_id": node["id"],
                "name": node["name"],
                "ok": True,
                "status_code": response.status_code,
                "detail": "",
            }
        except Exception as exc:
            return {
                "node_id": node["id"],
                "name": node["name"],
                "ok": False,
                "status_code": 502,
                "detail": str(exc)[:800],
            }

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=min(8, len(nodes)), thread_name_prefix="vpn-global-control") as pool:
        futures = [pool.submit(push, node) for node in nodes]
        for future in as_completed(futures):
            results.append(future.result())
    order = {node["id"]: index for index, node in enumerate(nodes)}
    results.sort(key=lambda item: order.get(int(item.get("node_id") or 0), 999999))
    succeeded = sum(1 for item in results if item.get("ok"))
    for item in results:
        if not item.get("ok"):
            logger.warning(
                "Global IP controls could not reach node %s: %s",
                item.get("name"),
                item.get("detail"),
            )
    return {
        "ok": succeeded == len(results),
        "total": len(results),
        "succeeded": succeeded,
        "failed": len(results) - succeeded,
        "results": results,
    }


def sync_global_controls_to_active_nodes_async(
    *,
    force_unban_ips: Iterable[str] | None = None,
    force_restore_ips: Iterable[str] | None = None,
) -> None:
    """Coalesce rapid operator actions without losing the newest snapshot.

    Explicit removal tombstones are retained until the active worker has sent
    them. This also clears a legacy same-IP row that existed on a Node before
    controller ownership tracking was introduced.
    """
    with _GLOBAL_CONTROLS_PENDING_STATE_LOCK:
        _GLOBAL_CONTROLS_FORCE_UNBAN.update(_normalize_ipv4_values(force_unban_ips))
        _GLOBAL_CONTROLS_FORCE_RESTORE.update(_normalize_ipv4_values(force_restore_ips))
        _GLOBAL_CONTROLS_SYNC_PENDING.set()

    def worker() -> None:
        if not _GLOBAL_CONTROLS_SYNC_LOCK.acquire(blocking=False):
            return
        try:
            while True:
                with _GLOBAL_CONTROLS_PENDING_STATE_LOCK:
                    queued_unbans = set(_GLOBAL_CONTROLS_FORCE_UNBAN)
                    queued_restores = set(_GLOBAL_CONTROLS_FORCE_RESTORE)
                    _GLOBAL_CONTROLS_FORCE_UNBAN.clear()
                    _GLOBAL_CONTROLS_FORCE_RESTORE.clear()
                    _GLOBAL_CONTROLS_SYNC_PENDING.clear()
                sync_global_controls_to_active_nodes(
                    force_unban_ips=queued_unbans,
                    force_restore_ips=queued_restores,
                )
                if not _GLOBAL_CONTROLS_SYNC_PENDING.is_set():
                    break
        finally:
            _GLOBAL_CONTROLS_SYNC_LOCK.release()
            # Close the tiny race where a new action was queued after the loop
            # checked the event but before this worker released the lock.
            if _GLOBAL_CONTROLS_SYNC_PENDING.is_set():
                sync_global_controls_to_active_nodes_async()

    threading.Thread(
        target=worker,
        daemon=True,
        name="vpn-global-controls-sync",
    ).start()


def _openvpn_runtime_ack_fingerprint(
    db: Session, controller_id: str, openvpn_pki: dict[str, str] | None,
) -> str:
    """Return the public fleet fingerprint only after runtime reload success."""
    if not openvpn_pki:
        return ""
    from app.services.cert_manager import export_pki_bundle, pki_bundle_fingerprint

    applied_bundle = export_pki_bundle()
    if not applied_bundle:
        return ""
    expected_full_hash = hashlib.sha256(
        json.dumps(openvpn_pki, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    runtime_hash_key = f"node_pki_runtime_{str(controller_id or '')[:32]}"
    if _get(db, runtime_hash_key) != expected_full_hash:
        return ""
    return pki_bundle_fingerprint(applied_bundle)


def _sync_openvpn_pki_runtime(
    db: Session, controller_id: str, openvpn_pki: dict[str, str] | None,
) -> list[str]:
    """Apply controller PKI and make the running OpenVPN daemons load it.

    Older node syncs copied CA/server/tls-auth files but did not restart the
    OpenVPN units.  The generated profile then contained the new ``ta.key``
    while the daemon still held the previous key in memory, producing
    ``packet HMAC authentication failed`` whenever a combined multi-node
    profile reached that node.

    Two hashes are tracked deliberately:
      * ``node_pki_*`` means the files were written.
      * ``node_pki_runtime_*`` means the OpenVPN processes successfully
        restarted after those exact files were written.

    Keeping them separate also repairs nodes upgraded from older releases:
    their file hash may already exist, but the runtime hash does not, so the
    first controller sync after upgrading performs the required one-time
    restart.
    """
    if not openvpn_pki:
        return []

    from app.services.cert_manager import import_pki_bundle

    warnings: list[str] = []
    pki_hash = hashlib.sha256(
        json.dumps(openvpn_pki, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    suffix = str(controller_id or "")[:32]
    file_hash_key = f"node_pki_{suffix}"
    runtime_hash_key = f"node_pki_runtime_{suffix}"

    if _get(db, file_hash_key) != pki_hash:
        try:
            warnings.extend(import_pki_bundle(openvpn_pki))
            _set(db, file_hash_key, pki_hash)
            db.commit()
        except Exception as exc:
            db.rollback()
            warnings.append(f"OpenVPN PKI: {exc}")
            return warnings

    # Do not unexpectedly enable a protocol that the administrator disabled.
    # Leaving the runtime hash unset makes the next sync restart it once the
    # protocol is enabled again.
    if not _bool(db, "openvpn_enabled", True):
        return warnings

    if _get(db, runtime_hash_key) != pki_hash:
        try:
            from app.services.protocol_admin import control_protocol

            ok, detail = control_protocol("openvpn", "restart", db)
            if not ok:
                warnings.append(f"OpenVPN PKI runtime reload failed: {detail[-1200:]}")
            else:
                _set(db, runtime_hash_key, pki_hash)
                db.commit()
        except Exception as exc:
            db.rollback()
            warnings.append(f"OpenVPN PKI runtime reload: {exc}")

    return warnings


def apply_agent_sync(
    db: Session, controller_id: str, users: list[dict], *,
    openvpn_pki: dict[str, str] | None = None, ipsec_psk: str | None = None,
    banned_ips: list[dict] | None = None, internet_blocks: list[dict] | None = None,
) -> dict:
    """Apply a complete controller snapshot without touching local users."""
    from datetime import date as date_cls
    from app.services.vpn_manager import (
        sync_chap_secrets, sync_ikev2_secrets, sync_openconnect_secrets,
        runtime_auth_drift_reasons, repair_runtime_auth_drift,
    )
    from app.services.xray_manager import sync_xray_users
    from app.services.rate_limiter import reconcile_shared_rate_limits
    from app.services.vpn_manager import get_ipsec_psk, set_ipsec_psk

    infra_warnings: list[str] = []
    # A managed node must always let its local protocol daemons consume the
    # controller-pushed rows. Repair stale databases restored from a main
    # server where the local assignment switch had been disabled.
    set_local_assignment_enabled(db, True)
    infra_warnings.extend(_sync_openvpn_pki_runtime(db, controller_id, openvpn_pki))
    psk_is_node_override = _get(db, "ipsec_psk_local_override").strip() == "1"
    if ipsec_psk and not psk_is_node_override and get_ipsec_psk() != ipsec_psk:
        try:
            set_ipsec_psk(ipsec_psk)
        except Exception as exc:
            infra_warnings.append(f"IPsec PSK: {exc}")

    config_hash = _user_config_hash_from_payloads(users)
    sync_hash_key = f"node_sync_{controller_id[:32]}"
    config_changed = _get(db, sync_hash_key) != config_hash

    wanted: set[str] = set()
    created = 0
    updated = 0
    conflicts: list[str] = []

    for raw in users:
        username = str(raw.get("username") or "").strip()
        if not username:
            continue
        wanted.add(username)
        row = db.query(VpnUser).filter(VpnUser.username == username).first()
        if row and not bool(getattr(row, "node_managed", False)):
            conflicts.append(username)
            continue
        if row and row.node_source != controller_id:
            conflicts.append(username)
            continue
        if not row:
            row = VpnUser(username=username, password=str(raw.get("password") or ""))
            row.node_managed = True
            row.node_source = controller_id
            db.add(row)
            created += 1
        else:
            if config_changed:
                updated += 1

        for key in (
            "password", "sub_token", "openvpn_auth_mode", "sstp_auth_mode", "expire_mode", "note", "xray_uuid"
        ):
            if key in raw:
                setattr(row, key, raw.get(key))
        for key in (
            "enable_l2tp", "enable_pptp", "enable_openvpn", "enable_sstp", "enable_ikev2",
            "enable_openconnect", "enable_vmess", "enable_vless", "is_active",
            "vmess_internet_blocked", "vless_internet_blocked",
        ):
            if key in raw:
                setattr(row, key, bool(raw.get(key)))
        for key in ("quota_bytes", "max_devices", "download_limit_mbps", "upload_limit_mbps"):
            if key in raw:
                setattr(row, key, max(0, int(raw.get(key) or 0)))
        row.expire_after_days = raw.get("expire_after_days")
        # first_connect_at is runtime evidence created on this node. Never erase
        # a local non-NULL value merely because the controller has not received
        # it yet; merge the earliest timestamp in either direction instead.
        try:
            incoming_first = datetime.fromisoformat(
                str(raw.get("first_connect_at")).replace("Z", "+00:00")
            ).replace(tzinfo=None) if raw.get("first_connect_at") else None
        except Exception:
            incoming_first = None
        if incoming_first is not None:
            ensure_first_connect(row, incoming_first)

        if row.expire_mode == "after_first_connect":
            refresh_after_first_expiry(row)
        else:
            try:
                row.expire_date = date_cls.fromisoformat(str(raw.get("expire_date"))[:10]) if raw.get("expire_date") else None
            except Exception:
                row.expire_date = None
        row.node_managed = True
        row.node_source = controller_id

    stale = db.query(VpnUser).filter(VpnUser.node_managed == True, VpnUser.node_source == controller_id).all()  # noqa: E712
    deleted = 0
    for row in stale:
        if row.username in wanted:
            continue
        db.query(XrayUsageCounter).filter(XrayUsageCounter.user_id == row.id).delete()
        db.query(ConnectionLog).filter(ConnectionLog.user_id == row.id).delete()
        db.delete(row)
        deleted += 1

    db.commit()
    runtime_drift_before = runtime_auth_drift_reasons(db)
    runtime_repaired: list[str] = []
    if config_changed:
        # The authoritative user snapshot changed, so rebuild every runtime
        # credential store exactly once. sync_chap_secrets also refreshes IKEv2
        # and OpenConnect; the explicit calls are retained for compatibility
        # with older monkeypatched deployments/tests.
        sync_chap_secrets(db)
        sync_ikev2_secrets(db)
        sync_openconnect_secrets(db)
        runtime_repaired.extend(("chap-secrets", "ikev2-secrets", "openconnect-passwd"))
        try:
            sync_xray_users(db, protocols=("vmess", "vless"), restart=True)
            runtime_repaired.extend(("xray-vmess", "xray-vless"))
        except Exception:
            logger.exception("Xray sync failed on node agent")
        # OpenVPN auth is database-backed but its dropped-privilege hook needs
        # a minimal env file. Repair it when a stale node reports drift even
        # though the user snapshot itself changed in the same request.
        if any(reason.startswith("openvpn-hook-env:") for reason in runtime_drift_before):
            runtime_repaired.extend(repair_runtime_auth_drift(db, [
                reason for reason in runtime_drift_before
                if reason.startswith("openvpn-hook-env:")
            ]))
    elif runtime_drift_before:
        # Critical fix: an unchanged controller hash must not suppress repair
        # of deleted/corrupt auth files on one node. This was the common cause
        # of a node staying online while every protocol rejected users.
        runtime_repaired.extend(repair_runtime_auth_drift(db, runtime_drift_before))
        # Client certificates are issued only by the controller.  A managed
        # node needs the shared CA/server/CRL material to authenticate clients,
        # but must never mutate the shared EasyRSA serial/index independently.
        # Independent issuance on several nodes can reuse the same serial for
        # different certificates and make per-node/all-server files revoke one
        # another unpredictably.
        try:
            reconcile_shared_rate_limits(db, force=True)
        except Exception:
            logger.exception("Rate limit reconciliation failed on node agent")

    # Persist after any successful snapshot application. Older builds did this
    # only in the unchanged-hash drift branch, so every real sync looked changed
    # forever and rebuilt auth stores on every controller poll.
    _set(db, sync_hash_key, config_hash)
    db.commit()

    local_rows = db.query(VpnUser).filter(
        VpnUser.node_managed == True, VpnUser.node_source == controller_id  # noqa: E712
    ).all()
    usage = {row.username: int(row.used_bytes or 0) for row in local_rows}
    global_controls = None
    if banned_ips is not None or internet_blocks is not None:
        global_controls = apply_global_controls_snapshot(
            db,
            controller_id,
            banned_ips=banned_ips,
            internet_blocks=internet_blocks,
        )
    # Do not advertise a node in an all-server profile merely because the
    # new files reached disk. The running UDP/TCP daemons must have loaded
    # those exact files successfully, otherwise they may still reject the
    # shared profile with an HMAC error.
    runtime_fingerprint = _openvpn_runtime_ack_fingerprint(db, controller_id, openvpn_pki)
    managed_by_name = {row.username: row for row in local_rows}
    runtime_drift_after = runtime_auth_drift_reasons(db)
    openvpn_hook_healthy = not any(
        reason.startswith("openvpn-hook-env:") for reason in runtime_drift_after
    )
    auth_ready = not conflicts and openvpn_hook_healthy and all(
        username in managed_by_name
        and bool(managed_by_name[username].is_active) == bool(raw.get("is_active"))
        and bool(managed_by_name[username].enable_openvpn) == bool(raw.get("enable_openvpn"))
        and hmac.compare_digest(str(managed_by_name[username].password or ""), str(raw.get("password") or ""))
        for raw in users
        for username in [str(raw.get("username") or "").strip()]
        if username
    )
    return {
        "ok": True, "created": created, "updated": updated, "deleted": deleted,
        "conflicts": conflicts, "warnings": infra_warnings, "usage": usage,
        "config_changed": config_changed, "global_controls": global_controls,
        "openvpn_pki_fingerprint": runtime_fingerprint,
        "user_config_hash": config_hash,
        "openvpn_auth_ready": bool(auth_ready),
        "runtime_auth_drift_before": runtime_drift_before,
        "runtime_auth_repaired": list(dict.fromkeys(runtime_repaired)),
        "runtime_auth_drift_after": runtime_drift_after,
    }


def selected_endpoints(db: Session, user: VpnUser | None = None) -> list[dict]:
    """Return local/remote snapshots according to the controller mode."""
    mode = get_node_mode(db)
    result: list[dict] = []
    from app.services.server_targets import local_assignment_enabled
    if mode in {"local_only", "all"} and local_assignment_enabled(db):
        local = build_local_snapshot(db)
        local["id"] = "local"
        local["name"] = "سرور اصلی"
        local["local"] = True
        if user is None or endpoint_selected_for_user(user, local):
            result.append(local)
    if mode in {"nodes_only", "all"}:
        nodes = db.query(VpnNode).filter(VpnNode.enabled == True, VpnNode.user_assignment_enabled == True, VpnNode.status == "online").order_by(VpnNode.weight.desc(), VpnNode.id).all()  # noqa: E712
        for node in nodes:
            snapshot = _node_out_snapshot(node)
            if not snapshot:
                continue
            snapshot = _apply_protocol_domain_overrides(dict(snapshot), node)
            snapshot["id"] = node.id
            snapshot["name"] = node.name
            snapshot["local"] = False
            snapshot["weight"] = node.weight
            if user is None or endpoint_selected_for_user(user, snapshot):
                result.append(snapshot)
    return result


def _snapshot_xray_uri(user: VpnUser, protocol: str, endpoint: dict) -> str | None:
    if protocol not in {"vmess", "vless"}:
        return None
    if not getattr(user, f"enable_{protocol}", False):
        return None
    settings = ((endpoint.get("protocols") or {}).get(protocol) or {})
    if not settings.get("enabled"):
        return None
    host = settings.get("server_address") or endpoint.get("public_address")
    if not host:
        return None
    try:
        port = int(settings.get("port") or 0)
    except Exception:
        return None
    if not (1 <= port <= 65535):
        return None
    transport = settings.get("transport") or "tcp"
    tls_enabled = bool(settings.get("tls_enabled"))
    tls_domain = settings.get("tls_domain") or ""
    ws_path = settings.get("ws_path") or "/"
    node_name = endpoint.get("name") or "Node"
    remark = settings.get("remark") or protocol.upper()
    label = f"{remark} - {node_name} - {user.username}"
    if protocol == "vmess":
        payload = {
            "v": "2", "ps": label, "add": host, "port": str(port), "id": user.xray_uuid,
            "aid": "0", "scy": "auto", "net": transport, "type": "none",
            "host": tls_domain if transport == "ws" else "",
            "path": ws_path if transport == "ws" else "",
            "tls": "tls" if tls_enabled else "", "sni": tls_domain if tls_enabled else "",
        }
        return "vmess://" + base64.b64encode(json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()).decode("ascii")
    query = {"encryption": "none", "security": "tls" if tls_enabled else "none", "type": transport}
    if transport == "ws":
        query["path"] = ws_path
        if tls_domain:
            query["host"] = tls_domain
    if tls_enabled and tls_domain:
        query["sni"] = tls_domain
    if settings.get("flow"):
        query["flow"] = settings["flow"]
    query_text = "&".join(f"{quote(k)}={quote(str(v), safe='/')}" for k, v in query.items())
    return f"vless://{user.xray_uuid}@{host}:{port}?{query_text}#{quote(label, safe='')}"


def build_multi_xray_profiles(db: Session, user: VpnUser) -> list[dict]:
    endpoints = selected_endpoints(db, user)
    profiles: list[dict] = []
    for endpoint in endpoints:
        for protocol in ("vmess", "vless"):
            uri = _snapshot_xray_uri(user, protocol, endpoint)
            if uri:
                profiles.append({
                    "protocol": protocol,
                    "label": f"{protocol.upper()} · {endpoint.get('name')}",
                    "node_name": endpoint.get("name"),
                    "node_id": endpoint.get("id"),
                    "uri": uri,
                })
    return profiles


def public_node_list(db: Session, user: VpnUser | None = None) -> list[dict]:
    from app.services.vpn_manager import get_ipsec_psk

    result = []
    user_fields = {
        "l2tp": "enable_l2tp",
        "pptp": "enable_pptp",
        "sstp": "enable_sstp",
        "openvpn": "enable_openvpn",
        "ikev2": "enable_ikev2",
        "openconnect": "enable_openconnect",
        "vmess": "enable_vmess",
        "vless": "enable_vless",
    }
    for endpoint in selected_endpoints(db, user):
        protocols = {}
        for key, raw in (endpoint.get("protocols") or {}).items():
            item = dict(raw or {})
            # Old node snapshots did not attach a public address to every
            # classic protocol.  Fill it here so the public page can switch
            # servers without falling back to the first server's details.
            item["server_address"] = (
                str(item.get("server_address") or "").strip()
                or str(endpoint.get("public_address") or "").strip()
            )
            if str(key).lower() == "l2tp":
                # Never substitute the controller PSK for a remote node. Prefer
                # the protocol snapshot, then that node's top-level legacy field.
                item["ipsec_psk"] = (
                    str(item.get("ipsec_psk") or "").strip()
                    or str(endpoint.get("ipsec_psk") or "").strip()
                    or (str(get_ipsec_psk() or "").strip() if bool(endpoint.get("local")) else "")
                )
            field = user_fields.get(str(key).lower())
            if user is not None and field:
                item["enabled"] = bool(item.get("enabled") and getattr(user, field, False))
            protocols[key] = item
        # The node snapshot's public_address is usually the raw server IP.  A
        # controller can override each protocol with a customer-facing domain;
        # the public subscription card must show that configured endpoint, not
        # leak the snapshot IP.  Use the first protocol that is actually enabled
        # for this user and fall back to the node public address only when no
        # protocol-specific address exists.
        display_address = next(
            (
                str(item.get("server_address") or "").strip()
                for item in protocols.values()
                if bool(item.get("enabled")) and str(item.get("server_address") or "").strip()
            ),
            str(endpoint.get("public_address") or "").strip(),
        )
        result.append({
            "id": endpoint.get("id"),
            "name": endpoint.get("name"),
            "address": endpoint.get("public_address"),
            "display_address": display_address,
            "local": bool(endpoint.get("local")),
            "ipsec_psk": str((protocols.get("l2tp") or {}).get("ipsec_psk") or endpoint.get("ipsec_psk") or "").strip(),
            "protocols": protocols,
        })
    return result


def _openvpn_profile_endpoints(
    db: Session, user: VpnUser | None = None, *, include_offline: bool = False,
) -> list[dict]:
    """Return provisioned OpenVPN endpoints for a downloadable profile.

    A temporarily offline node should remain in an already-generated all-server
    profile once it has previously acknowledged the canonical PKI. OpenVPN will
    skip that remote quickly and can use it again when the node returns. Normal
    dashboard/subscription views still use :func:`selected_endpoints` and show
    only currently-online nodes.
    """
    result = selected_endpoints(db, user)
    if not include_offline or get_node_mode(db) not in {"nodes_only", "all"}:
        return result

    present_ids: set[int] = set()
    for endpoint in result:
        if bool(endpoint.get("local")):
            continue
        try:
            present_ids.add(int(endpoint.get("id")))
        except (TypeError, ValueError):
            continue

    nodes = db.query(VpnNode).filter(
        VpnNode.enabled == True,  # noqa: E712
        VpnNode.user_assignment_enabled == True,  # noqa: E712
        VpnNode.status != "online",
    ).order_by(VpnNode.weight.desc(), VpnNode.id).all()
    for node in nodes:
        if int(node.id) in present_ids:
            continue
        snapshot = _node_out_snapshot(node)
        if not snapshot:
            continue
        snapshot = _apply_protocol_domain_overrides(dict(snapshot), node)
        snapshot["id"] = node.id
        snapshot["name"] = node.name
        snapshot["local"] = False
        snapshot["weight"] = node.weight
        snapshot["online"] = False
        if user is None or endpoint_selected_for_user(user, snapshot):
            result.append(snapshot)
    return result


def _node_openvpn_auth_snapshot_ready(db: Session, node_id: int) -> bool:
    node = db.query(VpnNode).filter(VpnNode.id == int(node_id)).first()
    if node is None:
        return False
    expected = _node_expected_user_config_hash(db, node)
    acknowledged = _get(db, f"node_openvpn_user_config_hash_{int(node_id)}")
    return bool(expected and acknowledged and hmac.compare_digest(expected, acknowledged))


def openvpn_profile_nodes(
    db: Session, user: VpnUser | None = None, *, require_shared_pki: bool = False,
) -> list[dict]:
    """Return stable OpenVPN download targets, including compatible offline nodes.

    Subscription cards normally hide offline nodes.  Downloadable OpenVPN files
    should not change merely because a node is rebooting, so this list retains an
    enabled assigned node after it has acknowledged the canonical CA/tls-auth
    fingerprint.  When ``require_shared_pki`` is false the list is also useful
    for distinguishing a missing target from one that only needs synchronization.
    """
    canonical_fingerprint = ""
    if require_shared_pki:
        from app.services.cert_manager import export_pki_bundle, pki_bundle_fingerprint
        canonical_fingerprint = pki_bundle_fingerprint(export_pki_bundle())
        if not canonical_fingerprint:
            return []

    result: list[dict] = []
    for endpoint in _openvpn_profile_endpoints(db, user, include_offline=True):
        item = dict(((endpoint.get("protocols") or {}).get("openvpn") or {}))
        if not bool(item.get("enabled")):
            continue
        address = (
            str(item.get("server_address") or "").strip()
            or str(endpoint.get("public_address") or "").strip()
        )
        if not address:
            continue
        if require_shared_pki and not bool(endpoint.get("local")):
            try:
                node_id = int(endpoint.get("id"))
            except (TypeError, ValueError):
                continue
            if _get(db, f"node_openvpn_pki_fingerprint_{node_id}") != canonical_fingerprint:
                continue
            # Shared PKI alone is insufficient: a node whose unprivileged auth
            # hook cannot read its runtime token will complete TLS and then return
            # AUTH_FAILED. Advertise the node only after it acknowledges the exact
            # user snapshot and a healthy OpenVPN auth path.
            if not _node_openvpn_auth_snapshot_ready(db, node_id):
                continue
        item["server_address"] = address
        result.append({
            "id": endpoint.get("id"),
            "name": endpoint.get("name") or ("سرور اصلی" if endpoint.get("local") else "Node"),
            "address": endpoint.get("public_address"),
            "display_address": address,
            "public_address": endpoint.get("public_address"),
            "local": bool(endpoint.get("local")),
            "online": bool(endpoint.get("online", True)),
            "protocols": {"openvpn": item},
        })
    return result


def openvpn_remotes(
    db: Session, user: VpnUser | None = None, *, require_shared_pki: bool = False,
) -> list[tuple[str, int, str]]:
    """Return ordered OpenVPN remotes for the active node mode.

    Combined profiles set ``require_shared_pki`` so a newly-added or stale node
    is not advertised until it has acknowledged the controller's canonical
    CA/tls-auth fingerprint.  This makes one downloaded file reliable across
    any number of nodes instead of occasionally reaching a node with a
    different HMAC key.
    """
    canonical_fingerprint = ""
    if require_shared_pki:
        from app.services.cert_manager import export_pki_bundle, pki_bundle_fingerprint
        canonical_fingerprint = pki_bundle_fingerprint(export_pki_bundle())
        if not canonical_fingerprint:
            return []
    # Build two explicit phases. Every server's primary UDP/TCP listeners are
    # attempted before any fallback/extra listener. This guarantees that a
    # combined profile starts from the canonical ports and reaches custom ports
    # only when the primary path is unavailable.
    primary_candidates: list[tuple[str, int, str]] = []
    fallback_candidates: list[tuple[str, int, str]] = []
    endpoints = _openvpn_profile_endpoints(
        db, user, include_offline=require_shared_pki,
    )
    for endpoint in endpoints:
        if require_shared_pki and not bool(endpoint.get("local")):
            try:
                node_id = int(endpoint.get("id"))
            except (TypeError, ValueError):
                continue
            if _get(db, f"node_openvpn_pki_fingerprint_{node_id}") != canonical_fingerprint:
                continue
            if not _node_openvpn_auth_snapshot_ready(db, node_id):
                continue
        item = ((endpoint.get("protocols") or {}).get("openvpn") or {})
        address = str(item.get("server_address") or endpoint.get("public_address") or "").strip()
        if not address or not item.get("enabled"):
            continue
        try:
            primary_candidates.extend([
                (address, int(item.get("udp_port") or 1194), "udp"),
                (address, int(item.get("tcp_port") or 1194), "tcp"),
            ])
        except (TypeError, ValueError):
            continue
        extras: list[tuple[str, int, str]] = []
        for extra in item.get("extra_ports") or []:
            if not extra.get("active", True):
                continue
            try:
                proto = "tcp" if str(extra.get("protocol") or "udp").lower().startswith("tcp") else "udp"
                extras.append((address, int(extra.get("port")), proto))
            except (TypeError, ValueError):
                continue
        extras.sort(key=lambda row: (int(row[1]), 0 if row[2] == "udp" else 1))
        fallback_candidates.extend(extras)

    remotes: list[tuple[str, int, str]] = []
    seen: set[tuple[str, int, str]] = set()
    for candidate in primary_candidates + fallback_candidates:
        if not 1 <= int(candidate[1]) <= 65535 or candidate in seen:
            continue
        seen.add(candidate)
        remotes.append(candidate)
    return remotes
