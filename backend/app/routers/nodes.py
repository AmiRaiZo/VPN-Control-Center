from __future__ import annotations

import html
import json
import re
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import quote, urlparse

import requests
from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response, UploadFile
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.config import get_settings
from app.models import Admin, AdminRole, Setting, VpnNode, VpnUser
from app.schemas import (
    NodeActionRequest,
    NodeAdminHandoffRequest,
    NodeAgentSyncRequest,
    NodeAgentGlobalControlsSyncRequest,
    NodeCreate,
    NodeModeRequest,
    LocalServerAssignmentRequest,
    NodePanelModeRequest,
    NodeProtocolProxyRequest,
    NodeLocalShellRequest,
    NodeRemoteInstallRequest,
    NodeRoleRequest,
    NodeSelfRegisterRequest,
    NodeSelfUnregisterRequest,
    NodeSshExecuteRequest,
    NodeUpdate,
    NodeUpdateReportRequest,
    ClusterAdmissionReserveRequest,
    ClusterAdmissionReleaseRequest,
    ClusterAdmissionXrayBatchRequest,
)
from app.security import create_access_token, ensure_permission, ensure_protocol_permission, require_permission, require_superadmin, verify_password, admin_can_access_protocol, can_view_all_users
from app.services.node_manager import (
    effective_server_role,
    panel_ui_server_role,
    set_local_node_panel_enabled,
    apply_agent_sync,
    build_local_snapshot,
    build_cached_local_snapshot,
    build_cached_local_presence,
    build_local_ping,
    get_node_mode,
    get_or_create_agent_token,
    node_to_dict,
    probe_node_snapshot,
    refresh_node,
    set_node_mode,
    set_remote_node_role,
    set_remote_node_panel_enabled,
    sync_node,
    sync_all_nodes_async,
    sync_global_controls_to_active_nodes_async,
    verify_agent_token,
)
from app.services.node_remote import (
    action_command,
    decrypt_password,
    encrypt_password,
    get_job,
    start_local_shell_job,
    start_remote_install_job,
    start_ssh_job,
)
from app.services.telegram_notifier import log_event
from app.services.node_admin_handoff import issue_handoff
from app.services.server_targets import (
    admin_can_access_target, local_assignment_enabled, set_local_assignment_enabled,
    targets_for_admin, serialize_admin_targets, serialize_targets, targets_for_user,
    globally_assignable_tokens,
)
from app.services import update_manager

router = APIRouter(prefix="/api/nodes", tags=["nodes"])
agent_router = APIRouter(prefix="/api/node-agent", tags=["node-agent"])


def _agent_auth(db: Session, token: str | None) -> None:
    if not verify_agent_token(db, token):
        raise HTTPException(status_code=401, detail="node_token_invalid")


def _setting(db: Session, key: str, value: str) -> None:
    row = db.query(Setting).filter(Setting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(Setting(key=key, value=value))


def _notify_node_update_result(
    db: Session,
    row: VpnNode,
    admin: Admin,
    *,
    ok: bool,
    message: str,
    source: str,
    signature: str,
) -> bool:
    """Emit one terminal Telegram notice per distinct node update result."""
    key = f"node_update_notice_{int(row.id)}"
    seen = db.query(Setting).filter(Setting.key == key).first()
    if seen and seen.value == signature:
        return False
    _setting(db, key, signature)
    db.commit()
    title = "✅ آپدیت Node موفق بود" if ok else "❌ آپدیت Node ناموفق بود"
    safe_detail = html.escape(str(message or ("آپدیت با موفقیت کامل شد." if ok else "فرایند آپدیت با خطا متوقف شد."))[:1800])
    source_label = {"agent": "API نود", "ssh": "SSH", "manual": "گزارش پنل"}.get(source, source)
    log_event(
        title,
        f"🖥 نود: <code>{html.escape(row.name)}</code>\n"
        f"📌 نتیجه: <b>{'موفق' if ok else 'ناموفق'}</b>\n"
        f"🔁 مسیر اجرا: <b>{source_label}</b>\n"
        f"📝 توضیح: {safe_detail}",
        actor=admin.username,
    )
    return True


def _node_or_404(db: Session, node_id: int, admin: Admin | None = None) -> VpnNode:
    row = db.query(VpnNode).filter(VpnNode.id == node_id).first()
    if not row:
        raise HTTPException(404, "نود پیدا نشد")
    if admin is not None and not admin_can_access_target(admin, f"node:{int(row.id)}"):
        raise HTTPException(403, "این ادمین به نود انتخاب‌شده دسترسی ندارد")
    return row


def _ssh_details(row: VpnNode, *, host=None, port=None, username=None, password=None):
    parsed = urlparse(row.api_url or "")
    final_host = (host or row.ssh_host or parsed.hostname or "").strip()
    final_port = int(port or row.ssh_port or 22)
    final_username = (username or row.ssh_username or "root").strip()
    final_password = password or decrypt_password(row.ssh_password_enc)
    if not final_host or not final_username or not final_password:
        raise HTTPException(400, "برای SSH آدرس، نام کاربری و رمز عبور را وارد کنید")
    return final_host, final_port, final_username, final_password


_PROTOCOL_PROXY_PATHS = (
    re.compile(r"^/api/settings/vpn-protocols$"),
    re.compile(r"^/api/settings/protocol-center(?:/.*)?$"),
    re.compile(r"^/api/settings/xray/(?:vmess|vless)$"),
    re.compile(r"^/api/settings/ipsec-psk$"),
    re.compile(r"^/api/settings/openvpn-ports(?:/\d+(?:/toggle)?)?$"),
    re.compile(r"^/api/settings/openconnect/use-443$"),
)


def _validate_protocol_proxy_path(path: str) -> str:
    normalized = "/" + str(path or "").lstrip("/")
    if "?" in normalized or "#" in normalized or ".." in normalized:
        raise HTTPException(400, "مسیر مدیریت پروتکل نود معتبر نیست")
    if not any(pattern.fullmatch(normalized) for pattern in _PROTOCOL_PROXY_PATHS):
        raise HTTPException(403, "این مسیر برای مدیریت پروتکل نود مجاز نیست")
    return normalized


def _authorize_protocol_proxy(admin: Admin, payload: NodeProtocolProxyRequest) -> None:
    path = _validate_protocol_proxy_path(payload.path)
    method = payload.method.upper()
    key_match = re.search(r"/protocol-center/([^/]+)", path) or re.search(r"/xray/([^/]+)", path)
    key = key_match.group(1) if key_match else ("openvpn" if "/openvpn-ports" in path else None)
    if key in {"install-jobs"}:
        key = None
    if path.endswith("/logs") and method in {"GET", "DELETE"}:
        capability = "logs"
    elif method == "GET":
        capability = "view"
    elif "/service/" in path:
        capability = "start_stop"
    elif path.endswith("/install"):
        capability = "install"
    else:
        capability = "edit"
    ensure_permission(admin, f"protocols:{capability}", "settings")
    if key and key not in {"all", "infrastructure"}:
        ensure_protocol_permission(admin, key, capability if capability in {"view", "edit"} else "view")


def _proxy_response(response: requests.Response) -> Response:
    media_type = response.headers.get("content-type", "application/json").split(";", 1)[0]
    return Response(content=response.content, status_code=response.status_code, media_type=media_type)


def _remember_node_ipsec_psk(db: Session, row: VpnNode, payload: NodeProtocolProxyRequest, response: requests.Response) -> None:
    """Mirror a successful node PSK edit into its cached public snapshot."""
    if response.status_code >= 400 or payload.method.upper() != "POST":
        return
    if _validate_protocol_proxy_path(payload.path) != "/api/settings/ipsec-psk":
        return
    body = payload.body if isinstance(payload.body, dict) else {}
    psk = str(body.get("psk") or "").strip()
    if not psk:
        return
    try:
        snapshot = json.loads(row.last_snapshot or "{}")
        if not isinstance(snapshot, dict):
            snapshot = {}
    except Exception:
        snapshot = {}
    protocols = snapshot.get("protocols") if isinstance(snapshot.get("protocols"), dict) else {}
    l2tp = protocols.get("l2tp") if isinstance(protocols.get("l2tp"), dict) else {}
    l2tp["ipsec_psk"] = psk
    protocols["l2tp"] = l2tp
    snapshot["protocols"] = protocols
    snapshot["ipsec_psk"] = psk
    row.last_snapshot = json.dumps(snapshot, ensure_ascii=False)
    row.last_seen_at = datetime.utcnow()
    row.status = "online"
    db.add(row)
    db.commit()


def _response_json_dict(response: Response) -> dict:
    try:
        raw = getattr(response, "body", b"")
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        data = json.loads(raw or "{}")
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


_NODE_ADMIN_SESSION_CACHE: dict[int, dict] = {}


def _node_admin_credentials(row: VpnNode) -> tuple[str, str]:
    username = (getattr(row, "panel_admin_username", None) or "").strip()
    password = decrypt_password(getattr(row, "panel_admin_password_enc", None))
    if not username or not password:
        raise HTTPException(409, (
            f"Node Agent نود «{row.name}» قدیمی است و مشخصات ادمین پنل نود برای مسیر سازگار ذخیره نشده است. "
            "در ویرایش نود، مدیریت کامل پنل نود و ذخیره امن نام کاربری/رمز را فعال کنید یا نود را آپدیت کنید."
        ))
    return username, password


def _node_admin_session(row: VpnNode, *, force_refresh: bool = False) -> tuple[str, bool, str]:
    """Return a short-lived cached admin token for a legacy node.

    Central protocol and update polling can hit the controller every couple of
    seconds.  Re-authenticating on every poll generated a flood of successful
    login audit events on old nodes, so cache the JWT briefly and refresh it
    once when the remote API rejects it.
    """
    username, password = _node_admin_credentials(row)
    base_url = (row.api_url or "").rstrip("/")
    verify_tls = bool(getattr(row, "verify_tls", True))
    cache_key = int(getattr(row, "id", 0) or 0)
    fingerprint = f"{base_url}|{username}|{getattr(row, 'panel_admin_password_enc', '')}"
    cached = _NODE_ADMIN_SESSION_CACHE.get(cache_key)
    if (
        not force_refresh
        and cached
        and cached.get("fingerprint") == fingerprint
        and float(cached.get("expires_at") or 0) > time.monotonic()
        and cached.get("token")
    ):
        return base_url, verify_tls, str(cached["token"])
    try:
        login = requests.post(
            f"{base_url}/api/auth/login",
            json={"username": username, "password": password},
            headers={"Accept": "application/json"},
            timeout=20,
            verify=verify_tls,
        )
    except requests.RequestException as exc:
        raise HTTPException(502, f"ورود مستقیم به پنل نود «{row.name}» برقرار نشد: {exc}") from exc
    if login.status_code >= 400:
        detail = login.text[-1000:] or f"HTTP {login.status_code}"
        try:
            detail = str(login.json().get("detail") or detail)
        except Exception:
            pass
        raise HTTPException(login.status_code, f"ورود ادمین به نود «{row.name}» ناموفق بود: {detail}")
    try:
        token = str(login.json().get("access_token") or "").strip()
    except Exception as exc:
        raise HTTPException(502, f"پاسخ ورود پنل نود «{row.name}» معتبر نبود") from exc
    if not token:
        raise HTTPException(502, f"پنل نود «{row.name}» توکن ورود برنگرداند")
    _NODE_ADMIN_SESSION_CACHE[cache_key] = {
        "fingerprint": fingerprint,
        "token": token,
        "expires_at": time.monotonic() + 300.0,
    }
    return base_url, verify_tls, token


def _direct_node_admin_api_response(
    row: VpnNode,
    method: str,
    path: str,
    *,
    timeout: int = 180,
    params: dict | None = None,
    body: dict | None = None,
) -> requests.Response:
    normalized = "/" + str(path or "").lstrip("/")
    if "?" in normalized or "#" in normalized or ".." in normalized:
        raise HTTPException(400, "مسیر مستقیم پنل نود معتبر نیست")

    def perform(force_refresh: bool = False) -> requests.Response:
        base_url, verify_tls, token = _node_admin_session(row, force_refresh=force_refresh)
        try:
            return requests.request(
                method.upper(),
                f"{base_url}{normalized}",
                headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
                params=params or None,
                json=body if method.upper() in {"POST", "PUT", "PATCH", "DELETE"} else None,
                timeout=timeout,
                verify=verify_tls,
            )
        except requests.RequestException as exc:
            raise HTTPException(502, f"ارتباط مستقیم با پنل نود «{row.name}» ناموفق بود: {exc}") from exc

    response = perform(False)
    if response.status_code in {401, 403}:
        _NODE_ADMIN_SESSION_CACHE.pop(int(getattr(row, "id", 0) or 0), None)
        response = perform(True)
    return response


def _response_detail(response: requests.Response) -> str:
    detail = response.text[-1000:] or f"HTTP {response.status_code}"
    try:
        body = response.json()
        detail = str(body.get("message") or body.get("detail") or detail)
    except Exception:
        pass
    return detail


def _response_code(response: requests.Response) -> str:
    try:
        body = response.json()
        return str(body.get("detail") or "")
    except Exception:
        return ""


def _direct_node_admin_response(row: VpnNode, payload: NodeProtocolProxyRequest) -> requests.Response:
    """Proxy protocol operations through the node's normal admin API.

    Nodes installed before the Node Agent protocol-proxy endpoint existed return
    a plain 404 for ``/api/node-agent/protocol-proxy``.  The controller already
    stores optional encrypted superadmin credentials for direct node management,
    so use those credentials as a backwards-compatible transport instead of
    showing a misleading ``Not Found`` console.
    """
    method = payload.method.upper()
    response = _direct_node_admin_api_response(
        row,
        method,
        _validate_protocol_proxy_path(payload.path),
        timeout=180,
        params=payload.params or None,
        body=payload.body if method in {"POST", "PUT", "DELETE"} else None,
    )

    # Versions before 2.3.96 ignored ``fresh=1`` and returned a cheap placeholder
    # on first load.  Let their background snapshot finish and return the first
    # authoritative result so the controller does not paint every prerequisite
    # red even though the services are installed.
    is_fresh_center = (
        method == "GET"
        and payload.path.rstrip("/") == "/api/settings/protocol-center"
        and str((payload.params or {}).get("fresh", "")).lower() in {"1", "true", "yes"}
        and response.status_code < 400
    )
    if is_fresh_center:
        deadline = time.monotonic() + 14.0
        while time.monotonic() < deadline:
            try:
                body = response.json()
            except Exception:
                break
            if not bool(body.get("refreshing")):
                break
            time.sleep(0.55)
            try:
                response = _direct_node_admin_api_response(
                    row,
                    "GET",
                    payload.path,
                    timeout=25,
                )
            except HTTPException:
                break
    return response


def _node_agent_request(row: VpnNode, method: str, path: str, *, timeout: int = 30) -> Response:
    """Call a privileged Node Agent endpoint with a useful controller error."""
    if not row.enabled:
        raise HTTPException(409, "این نود غیرفعال است")
    try:
        response = requests.request(
            method.upper(),
            f"{row.api_url.rstrip('/')}/api/node-agent/{path.lstrip('/')}",
            headers={"X-Node-Token": row.api_token},
            timeout=timeout,
            verify=bool(getattr(row, "verify_tls", True)),
        )
    except requests.RequestException as exc:
        raise HTTPException(502, f"ارتباط با نود «{row.name}» برقرار نشد: {exc}") from exc
    if response.status_code >= 400:
        detail = response.text[-1000:] or f"HTTP {response.status_code}"
        try:
            detail = str(response.json().get("detail") or detail)
        except Exception:
            pass
        raise HTTPException(response.status_code, f"نود «{row.name}»: {detail}")
    return _proxy_response(response)


_LEGACY_UPDATE_RESTORE_TIMERS: dict[int, threading.Timer] = {}
_LEGACY_UPDATE_RESTORE_LOCK = threading.Lock()


def _controller_url_from_db(db: Session) -> str:
    values = {
        row.key: row.value
        for row in db.query(Setting).filter(
            Setting.key.in_(["domain", "domain_ssl_status", "panel_port"])
        ).all()
    }
    domain = str(values.get("domain") or "").strip()
    ssl_active = str(values.get("domain_ssl_status") or "").lower() == "active"
    try:
        port = int(values.get("panel_port") or (443 if ssl_active else 80))
    except (TypeError, ValueError):
        port = 443 if ssl_active else 80
    scheme = "https" if ssl_active else "http"
    host = domain or str(get_settings().PUBLIC_SERVER_IP or "").strip()
    if not host:
        return ""
    default_port = 443 if scheme == "https" else 80
    suffix = "" if port == default_port else f":{port}"
    return f"{scheme}://{host}{suffix}"


def _post_node_role(
    row: VpnNode,
    role: str,
    *,
    controller_url: str = "",
    temporary: bool = False,
    timeout: int = 15,
) -> None:
    payload = {"role": role, "temporary": bool(temporary)}
    if controller_url:
        payload["controller_url"] = controller_url
    try:
        response = requests.post(
            f"{row.api_url.rstrip('/')}/api/node-agent/role",
            headers={"X-Node-Token": row.api_token},
            json=payload,
            timeout=timeout,
            verify=bool(getattr(row, "verify_tls", True)),
        )
        response.raise_for_status()
    except requests.RequestException as exc:
        raise HTTPException(502, f"تغییر موقت حالت نود «{row.name}» ناموفق بود: {exc}") from exc


def _schedule_legacy_role_restore(row: VpnNode, controller_url: str, delay: int = 1800) -> None:
    node_id = int(getattr(row, "id", 0) or 0)
    api_url = str(row.api_url or "").rstrip("/")
    api_token = str(row.api_token or "")
    verify_tls = bool(getattr(row, "verify_tls", True))

    def restore() -> None:
        try:
            requests.post(
                f"{api_url}/api/node-agent/role",
                headers={"X-Node-Token": api_token},
                json={"role": "node", "controller_url": controller_url},
                timeout=15,
                verify=verify_tls,
            )
        finally:
            with _LEGACY_UPDATE_RESTORE_LOCK:
                _LEGACY_UPDATE_RESTORE_TIMERS.pop(node_id, None)

    timer = threading.Timer(delay, restore)
    timer.daemon = True
    with _LEGACY_UPDATE_RESTORE_LOCK:
        previous = _LEGACY_UPDATE_RESTORE_TIMERS.pop(node_id, None)
        if previous:
            previous.cancel()
        _LEGACY_UPDATE_RESTORE_TIMERS[node_id] = timer
    timer.start()


def _restore_legacy_node_role(row: VpnNode, controller_url: str) -> None:
    node_id = int(getattr(row, "id", 0) or 0)
    try:
        _post_node_role(row, "node", controller_url=controller_url, timeout=15)
    except HTTPException:
        # Keep the already scheduled safety timer alive so a brief restart or
        # network interruption cannot leave the upgraded server in main mode.
        return
    with _LEGACY_UPDATE_RESTORE_LOCK:
        timer = _LEGACY_UPDATE_RESTORE_TIMERS.pop(node_id, None)
    if timer:
        timer.cancel()


def _node_snapshot_version(row: VpnNode) -> str | None:
    try:
        snapshot = node_to_dict(row).get("snapshot") or {}
        value = str(snapshot.get("version") or "").strip()
        return value or None
    except Exception:
        return None


def _legacy_update_api_response(
    row: VpnNode,
    method: str,
    action: str,
    *,
    timeout: int,
    controller_url: str,
) -> tuple[requests.Response, bool]:
    path = f"/api/backup/update/{action}"
    role_switched = False
    response = _direct_node_admin_api_response(row, method, path, timeout=timeout)
    if response.status_code == 423 and _response_code(response) == "node_managed_by_controller":
        # Old node builds intentionally block all normal admin APIs while in
        # node mode. Temporarily release that guard only for the update API,
        # then restore node mode after completion (plus a safety timer).
        _post_node_role(row, "main", controller_url=controller_url, temporary=True)
        role_switched = True
        _schedule_legacy_role_restore(row, controller_url)
        _NODE_ADMIN_SESSION_CACHE.pop(int(getattr(row, "id", 0) or 0), None)
        deadline = time.monotonic() + 6.0
        while True:
            time.sleep(0.65)
            response = _direct_node_admin_api_response(row, method, path, timeout=timeout)
            if not (response.status_code == 423 and _response_code(response) == "node_managed_by_controller"):
                break
            if time.monotonic() >= deadline:
                break
    return response, role_switched



def _normalized_update_sha(value: object) -> str | None:
    digest = str(value or "").strip().lower()
    return digest if re.fullmatch(r"[0-9a-f]{64}", digest) else None


def _remember_node_release_label(db: Session, row: VpnNode, version: str) -> None:
    """Keep the controller's cached node card aligned with the published label."""
    try:
        snapshot = json.loads(row.last_snapshot or "{}")
        if not isinstance(snapshot, dict):
            snapshot = {}
    except Exception:
        snapshot = {}
    snapshot["version"] = version
    row.last_snapshot = json.dumps(snapshot, ensure_ascii=False, separators=(",", ":"))
    row.last_seen_at = datetime.utcnow()
    db.add(row)
    db.commit()


def _sync_node_release_label(row: VpnNode, version: str, sha256: str | None) -> None:
    """Best-effort metadata sync; older nodes simply ignore the new endpoint."""
    try:
        requests.post(
            f"{row.api_url.rstrip('/')}/api/node-agent/update/version-sync",
            headers={"X-Node-Token": row.api_token},
            json={"version": version, "sha256": sha256},
            timeout=12,
            verify=bool(getattr(row, "verify_tls", True)),
        )
    except requests.RequestException:
        pass


def _controller_release_for_node(
    row: VpnNode,
    node_payload: dict,
    db: Session,
) -> dict:
    """Use the license console as the sole source of the node's latest label.

    A node may expose the immutable archive build from its local files. That is
    useful for package identity, but the visible release label is owned by the
    license console and must be identical on the main panel and every node.
    """
    latest = update_manager.check_latest(db)
    result = dict(node_payload or {})

    current = str(result.get("current_version") or _node_snapshot_version(row) or "").strip() or None
    latest_version = str(latest.get("latest_version") or "").strip() or current
    latest_sha = _normalized_update_sha(latest.get("latest_sha256"))
    installed_sha = _normalized_update_sha(result.get("installed_sha256"))
    package_version = str(latest.get("package_version") or "").strip() or None
    installed_code_version = str(result.get("installed_code_version") or "").strip() or None

    if latest_sha and installed_sha:
        update_available = latest_sha != installed_sha
        basis = "controller-package-sha256"
    elif package_version and installed_code_version:
        update_available = package_version != installed_code_version
        basis = "controller-package-version"
    elif latest_version and current:
        update_available = update_manager.is_published_version_newer(latest_version, current)
        basis = "controller-license-version-fallback"
    elif latest_version and installed_code_version:
        update_available = update_manager.is_published_version_newer(latest_version, installed_code_version)
        basis = "controller-license-version-vs-code-fallback"
    elif latest_version:
        update_available = True
        basis = "controller-license-version-unbound"
    else:
        update_available = False
        basis = "controller-no-release"

    result.update({
        "current_version": current,
        "latest_version": latest_version,
        "reported_version": latest.get("reported_version") or latest_version,
        "package_version": package_version,
        "latest_sha256": latest_sha,
        "update_available": bool(update_available),
        "comparison_basis": basis,
        "notes": latest.get("notes"),
        "published_at": latest.get("published_at"),
        "transport": "controller-release-metadata",
    })
    return result


def _node_update_request(
    row: VpnNode,
    method: str,
    action: str,
    *,
    timeout: int,
    db: Session | None = None,
    controller_url: str = "",
) -> Response:
    """Use Node Agent first and keep update metadata controller-authoritative."""
    try:
        agent_response = _node_agent_request(row, method, f"update/{action}", timeout=timeout)
        if action == "check" and db is not None:
            try:
                return JSONResponse(content=_controller_release_for_node(
                    row, _response_json_dict(agent_response), db
                ))
            except HTTPException:
                # The node's own check remains useful during a brief license
                # console outage; do not turn a metadata merge failure into a
                # failed node-health request.
                return agent_response
        return agent_response
    except HTTPException as exc:
        if exc.status_code not in {404, 405, 501}:
            raise

    if action == "check" and db is not None:
        try:
            return JSONResponse(content=_controller_release_for_node(row, {}, db))
        except HTTPException:
            pass

    response, role_switched = _legacy_update_api_response(
        row, method, action, timeout=timeout, controller_url=controller_url
    )
    if response.status_code >= 400:
        if role_switched:
            _restore_legacy_node_role(row, controller_url)
        raise HTTPException(response.status_code, f"نود «{row.name}»: {_response_detail(response)}")

    if action == "check":
        if role_switched:
            _restore_legacy_node_role(row, controller_url)
        if db is not None:
            try:
                payload = response.json()
                payload = payload if isinstance(payload, dict) else {}
            except Exception:
                payload = {}
            try:
                return JSONResponse(content=_controller_release_for_node(row, payload, db))
            except HTTPException:
                return _proxy_response(response)
    elif action == "start":
        if role_switched:
            _schedule_legacy_role_restore(row, controller_url)
    elif action == "status":
        try:
            state = str(response.json().get("state") or "").lower()
        except Exception:
            state = ""
        if state in {"success", "succeeded", "completed", "done", "failed", "error"}:
            _restore_legacy_node_role(row, controller_url)
    return _proxy_response(response)

def _sanitize_node_payload_for_admin(payload: dict, admin: Admin) -> dict:
    if admin.role == AdminRole.superadmin:
        return payload
    result = dict(payload)
    result["protocol_domains"] = {
        key: value for key, value in (result.get("protocol_domains") or {}).items()
        if admin_can_access_protocol(admin, key)
    }
    snapshot = result.get("snapshot")
    if isinstance(snapshot, dict):
        snapshot = dict(snapshot)
        # Never reveal the node-local L2TP/IPsec secret to a delegated admin
        # unless that account explicitly has access to L2TP/IPsec settings.
        if not (admin_can_access_protocol(admin, "l2tp") or admin_can_access_protocol(admin, "ipsec")):
            snapshot.pop("ipsec_psk", None)
        for field in ("protocols", "protocol_domains"):
            value = snapshot.get(field)
            if isinstance(value, dict):
                filtered = {
                    key: item for key, item in value.items()
                    if admin_can_access_protocol(admin, key)
                }
                l2tp = filtered.get("l2tp")
                if isinstance(l2tp, dict) and not (
                    admin_can_access_protocol(admin, "l2tp") or admin_can_access_protocol(admin, "ipsec")
                ):
                    l2tp = dict(l2tp)
                    l2tp.pop("ipsec_psk", None)
                    filtered["l2tp"] = l2tp
                snapshot[field] = filtered
        statuses = snapshot.get("protocol_statuses")
        if isinstance(statuses, list):
            snapshot["protocol_statuses"] = [
                dict(item) for item in statuses
                if isinstance(item, dict) and admin_can_access_protocol(admin, str(item.get("key") or ""))
            ]
        result["snapshot"] = snapshot
    return result


@router.get("")
def list_nodes(db: Session = Depends(get_db), admin: Admin = Depends(require_permission("nodes:view", "nodes"))):
    controller_row = db.query(Setting).filter(Setting.key == "node_controller_url").first()
    rows = db.query(VpnNode).order_by(VpnNode.id).all()
    rows = [row for row in rows if admin_can_access_target(admin, f"node:{int(row.id)}")]
    return {
        "mode": get_node_mode(db),
        "local_role": panel_ui_server_role(db),
        "controller_url": (controller_row.value if controller_row else ""),
        "local_shell_allowed": admin.role == AdminRole.superadmin,
        "local_user_assignment_enabled": bool(local_assignment_enabled(db)),
        "nodes": [_sanitize_node_payload_for_admin(node_to_dict(row), admin) for row in rows],
    }


@router.get("/protocol-targets")
def protocol_targets(
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("protocols:view", "settings")),
):
    local_name = "سرور اصلی" if effective_server_role(db) != "node" else "این نود"
    targets = []
    if admin_can_access_target(admin, "local"):
        targets.append({
            "id": "local", "name": local_name, "local": True, "status": "online",
            "api_url": "", "version": build_local_snapshot(db).get("version"),
        })
    for row in db.query(VpnNode).filter(VpnNode.enabled == True).order_by(VpnNode.id).all():  # noqa: E712
        if not admin_can_access_target(admin, f"node:{int(row.id)}"):
            continue
        snapshot = node_to_dict(row).get("snapshot") or {}
        targets.append({
            "id": f"node:{row.id}", "node_id": row.id, "name": row.name, "local": False,
            "status": row.status or "unknown",
            "version": snapshot.get("version"), "last_error": row.last_error,
        })
    return {"targets": targets}


@router.post("/protocols/{protocol}/restart-all")
def restart_protocol_on_all_nodes(
    protocol: str,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("protocols:start_stop", "settings")),
):
    """Restart one protocol concurrently on every enabled, accessible node.

    This controller-side orchestration intentionally does not restart the local
    main server.  It is the bulk counterpart of each node's normal protocol
    restart action and returns a per-node result so the UI can surface partial
    failures instead of hiding them.
    """
    key = str(protocol or "").strip().lower()
    allowed = {"l2tp", "ipsec", "pptp", "openvpn", "openconnect", "sstp", "ikev2", "vmess", "vless"}
    if key not in allowed:
        raise HTTPException(404, "پروتکل انتخاب‌شده معتبر نیست")
    ensure_protocol_permission(admin, key, "view")

    rows = [
        row for row in db.query(VpnNode).filter(VpnNode.enabled == True).order_by(VpnNode.id).all()  # noqa: E712
        if admin_can_access_target(admin, f"node:{int(row.id)}")
    ]
    if not rows:
        raise HTTPException(404, "هیچ نود فعالی برای ری‌استارت پیدا نشد")

    payload = NodeProtocolProxyRequest(
        method="POST",
        path=f"/api/settings/protocol-center/{key}/service/restart",
        params={},
        body=None,
    )

    def run(row: VpnNode) -> dict:
        try:
            response = requests.post(
                f"{row.api_url.rstrip('/')}/api/node-agent/protocol-proxy",
                headers={"X-Node-Token": row.api_token},
                json=payload.model_dump(),
                timeout=180,
                verify=bool(getattr(row, "verify_tls", True)),
            )
            if response.status_code in {404, 405, 501}:
                response = _direct_node_admin_response(row, payload)
            detail = response.text[-1200:] if response.content else ""
            try:
                body = response.json()
                detail = str(body.get("message") or body.get("detail") or detail) if isinstance(body, dict) else detail
            except Exception:
                pass
            return {
                "node_id": int(row.id), "name": row.name,
                "ok": response.status_code < 400, "status_code": response.status_code,
                "detail": detail,
            }
        except Exception as exc:
            return {
                "node_id": int(row.id), "name": row.name,
                "ok": False, "status_code": 502, "detail": str(exc),
            }

    results = []
    with ThreadPoolExecutor(max_workers=min(8, len(rows))) as pool:
        futures = {pool.submit(run, row): row for row in rows}
        for future in as_completed(futures):
            results.append(future.result())
    order = {int(row.id): index for index, row in enumerate(rows)}
    results.sort(key=lambda item: order.get(int(item.get("node_id") or 0), 999999))
    succeeded = sum(1 for item in results if item.get("ok"))
    return {
        "ok": succeeded == len(results),
        "protocol": key,
        "succeeded": succeeded,
        "failed": len(results) - succeeded,
        "total": len(results),
        "results": results,
    }


@router.post("/{node_id}/protocol-proxy")
def protocol_proxy(
    node_id: int,
    payload: NodeProtocolProxyRequest,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("protocols:view", "settings")),
):
    _authorize_protocol_proxy(admin, payload)
    row = _node_or_404(db, node_id, admin)
    if not row.enabled:
        raise HTTPException(409, "این نود غیرفعال است")
    try:
        response = requests.post(
            f"{row.api_url.rstrip('/')}/api/node-agent/protocol-proxy",
            headers={"X-Node-Token": row.api_token},
            json=payload.model_dump(),
            timeout=180,
            verify=bool(getattr(row, "verify_tls", True)),
        )
    except requests.RequestException as exc:
        raise HTTPException(502, f"ارتباط مدیریت پروتکل با نود «{row.name}» ناموفق بود: {exc}") from exc

    # A plain 404/405 here means the selected node predates the privileged
    # protocol-proxy endpoint.  Fall back to its normal admin API using the
    # encrypted credentials that the operator explicitly opted to save.
    if response.status_code in {404, 405, 501}:
        response = _direct_node_admin_response(row, payload)
    _remember_node_ipsec_psk(db, row, payload, response)
    return _proxy_response(response)


@router.post("/{node_id}/sessions/{session_id}/disconnect")
def node_session_disconnect(
    node_id: int,
    session_id: int,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("online:disconnect", "online")),
):
    row = _node_or_404(db, node_id, admin)
    return _node_agent_request(row, "POST", f"sessions/{int(session_id)}/disconnect", timeout=45)


@router.post("/{node_id}/sessions/{session_id}/internet-block")
def node_session_internet_block(
    node_id: int,
    session_id: int,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("online:disconnect", "online")),
):
    row = _node_or_404(db, node_id, admin)
    response = _node_agent_request(row, "POST", f"sessions/{int(session_id)}/internet-block", timeout=45)
    body = _response_json_dict(response)
    ip_address = str(body.get("ip_address") or "").strip()
    if ip_address:
        from app.services.vpn_manager import block_internet_ip

        node_username = str(body.get("username") or "").strip()
        owned_user = db.query(VpnUser).filter(VpnUser.username == node_username).first() if node_username else None
        if owned_user is not None and not can_view_all_users(admin) and owned_user.owner_admin_id != admin.id:
            raise HTTPException(403, "به این کاربر دسترسی ندارید")
        block_internet_ip(
            db,
            ip_address,
            user=owned_user,
            username=(node_username or None),
            reason=f"قطع اینترنت از پنل اصلی؛ سشن نود {row.name}",
            admin_id=admin.id,
            admin_username=admin.username,
            owner_admin_id=(owned_user.owner_admin_id if owned_user and owned_user.owner_admin_id is not None else admin.id),
        )
        sync_global_controls_to_active_nodes_async()
        body["global_nodes_sync_started"] = True
        return JSONResponse(content=body, status_code=response.status_code)
    return response


@router.post("/{node_id}/sessions/{session_id}/ban-ip")
def node_session_ban_ip(
    node_id: int,
    session_id: int,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("bans:manage", "online")),
):
    row = _node_or_404(db, node_id, admin)
    response = _node_agent_request(row, "POST", f"sessions/{int(session_id)}/ban-ip", timeout=45)
    body = _response_json_dict(response)
    ip_address = str(body.get("ip_address") or "").strip()
    if ip_address:
        from app.services.vpn_manager import ban_ip

        node_username = str(body.get("username") or "").strip()
        owned_user = db.query(VpnUser).filter(VpnUser.username == node_username).first() if node_username else None
        if owned_user is not None and not can_view_all_users(admin) and owned_user.owner_admin_id != admin.id:
            raise HTTPException(403, "به این کاربر دسترسی ندارید")
        ban_ip(
            db,
            ip_address,
            f"بن از پنل اصلی؛ سشن نود {row.name}",
            admin.id,
            owner_admin_id=(owned_user.owner_admin_id if owned_user and owned_user.owner_admin_id is not None else admin.id),
        )
        sync_global_controls_to_active_nodes_async()
        body["global_nodes_sync_started"] = True
        return JSONResponse(content=body, status_code=response.status_code)
    return response


@router.put("/assignment/local")
def update_local_assignment(
    payload: LocalServerAssignmentRequest,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("nodes:manage", "nodes")),
):
    if admin.role != AdminRole.superadmin:
        raise HTTPException(403, "تغییر نمایش سرور اصلی فقط برای ادمین اصلی مجاز است")
    set_local_assignment_enabled(db, bool(payload.enabled))
    db.commit()
    # Rebuild local credentials immediately so a globally hidden local server
    # stops provisioning existing users as well.
    try:
        from app.services.vpn_manager import sync_chap_secrets
        from app.services.xray_manager import sync_xray_users
        sync_chap_secrets(db)
        sync_xray_users(db, protocols=("vmess", "vless"), restart=False)
    except Exception:
        pass
    return {"ok": True, "enabled": bool(payload.enabled)}


@router.post("")
def create_node(payload: NodeCreate, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("nodes:manage", "nodes"))):
    if db.query(VpnNode).filter((VpnNode.name == payload.name) | (VpnNode.api_url == payload.api_url)).first():
        raise HTTPException(409, "نام یا آدرس API این نود قبلاً ثبت شده است")
    password_enc = encrypt_password(payload.ssh_password) if payload.save_ssh_password else None
    panel_admin_username = (payload.panel_admin_username or "").strip() or None
    panel_admin_password_enc = (
        encrypt_password(payload.panel_admin_password)
        if payload.save_panel_admin_credentials and payload.panel_admin_password else None
    )
    if payload.remote_admin_enabled and (not panel_admin_username or not panel_admin_password_enc):
        raise HTTPException(400, "برای فعال‌کردن مدیریت پنل نود، نام کاربری و رمز ادمین نود را وارد و ذخیره کنید")
    row = VpnNode(
        name=payload.name.strip(),
        api_url=payload.api_url.strip().rstrip("/"),
        api_token=payload.api_token.strip(),
        enabled=payload.enabled,
        verify_tls=payload.verify_tls,
        weight=payload.weight,
        ssh_host=(payload.ssh_host or "").strip() or None,
        ssh_port=payload.ssh_port,
        ssh_username=(payload.ssh_username or "").strip() or None,
        ssh_password_enc=password_enc,
        panel_admin_username=panel_admin_username,
        panel_admin_password_enc=panel_admin_password_enc,
        remote_admin_enabled=bool(payload.remote_admin_enabled),
        user_assignment_enabled=bool(payload.user_assignment_enabled),
        node_panel_enabled=bool(payload.node_panel_enabled),
        protocol_domains=json.dumps(payload.protocol_domains or {}, ensure_ascii=False, separators=(",", ":")),
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    try:
        set_remote_node_role(row, "node" if row.enabled else "main")
        if row.enabled:
            set_remote_node_panel_enabled(row, bool(getattr(row, "node_panel_enabled", True)))
        refresh_node(db, row)
    except Exception:
        pass
    log_event("🖥 افزودن Node", f"نام: {row.name} | API: {row.api_url}", actor=admin.username)
    return node_to_dict(row)


@router.post("/local-shell")
def local_shell(
    payload: NodeLocalShellRequest,
    admin: Admin = Depends(require_permission("nodes:ssh", "nodes")),
):
    if admin.role != AdminRole.superadmin:
        raise HTTPException(403, "ترمینال سرور فعلی فقط برای ادمین اصلی مجاز است")
    job_id = start_local_shell_job(
        command=payload.command,
        title="ترمینال سرور فعلی",
        timeout_seconds=payload.timeout_seconds,
    )
    log_event("⌨️ ترمینال سرور فعلی", "اجرای دستور محلی از بخش نودها", actor=admin.username)
    return {"ok": True, "job_id": job_id}


@router.put("/{node_id}")
def update_node(node_id: int, payload: NodeUpdate, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("nodes:manage", "nodes"))):
    row = _node_or_404(db, node_id, admin)
    old_enabled = bool(row.enabled)
    old_assignment_enabled = bool(getattr(row, "user_assignment_enabled", True))
    old_node_panel_enabled = bool(getattr(row, "node_panel_enabled", True))
    data = payload.model_dump(exclude_unset=True)
    ssh_password = data.pop("ssh_password", None)
    save_password = data.pop("save_ssh_password", None)
    clear_password = bool(data.pop("clear_ssh_password", False))
    panel_admin_password = data.pop("panel_admin_password", None)
    save_panel_admin = data.pop("save_panel_admin_credentials", None)
    clear_panel_admin = bool(data.pop("clear_panel_admin_credentials", False))
    protocol_domains = data.pop("protocol_domains", None)
    if "api_url" in data and data["api_url"]:
        data["api_url"] = data["api_url"].rstrip("/")
    for key in ("ssh_host", "ssh_username", "panel_admin_username"):
        if key in data and isinstance(data[key], str):
            data[key] = data[key].strip() or None
    for key, value in data.items():
        setattr(row, key, value)
    if protocol_domains is not None:
        row.protocol_domains = json.dumps(protocol_domains or {}, ensure_ascii=False, separators=(",", ":"))
    if clear_password:
        row.ssh_password_enc = None
    elif ssh_password and save_password:
        row.ssh_password_enc = encrypt_password(ssh_password)
    elif save_password is False and ssh_password:
        # Password was supplied for this test only; never persist it.
        pass
    if clear_panel_admin:
        row.panel_admin_username = None
        row.panel_admin_password_enc = None
        row.remote_admin_enabled = False
    elif panel_admin_password and save_panel_admin:
        row.panel_admin_password_enc = encrypt_password(panel_admin_password)
    if bool(getattr(row, "remote_admin_enabled", False)) and (
        not getattr(row, "panel_admin_username", None) or not getattr(row, "panel_admin_password_enc", None)
    ):
        db.rollback()
        raise HTTPException(400, "برای فعال‌کردن مدیریت پنل نود، نام کاربری و رمز ادمین نود را وارد و ذخیره کنید")
    db.commit()
    db.refresh(row)
    if old_assignment_enabled != bool(getattr(row, "user_assignment_enabled", True)):
        sync_all_nodes_async()
    if old_enabled != bool(row.enabled):
        try:
            set_remote_node_role(row, "node" if row.enabled else "main")
        except Exception as exc:
            row.last_error = f"تغییر نقش نود به سرور مقصد نرسید: {exc}"[:1500]
            db.commit()
    if row.enabled and old_node_panel_enabled != bool(getattr(row, "node_panel_enabled", True)):
        try:
            set_remote_node_panel_enabled(row, bool(getattr(row, "node_panel_enabled", True)))
        except Exception as exc:
            row.last_error = f"حالت پنل نود ذخیره شد اما هنوز به سرور مقصد نرسیده است: {exc}"[:1500]
            db.commit()
    # Credential and metadata edits are durable after the commit above. Do not
    # make the browser wait for a remote health probe here; the periodic node
    # health job refreshes the snapshot shortly after the response.
    log_event("✏️ ویرایش Node", f"نام: {row.name}", actor=admin.username)
    return node_to_dict(row)


@router.post("/{node_id}/open-admin")
def open_node_admin(
    node_id: int,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("nodes:manage", "nodes")),
):
    if admin.role != AdminRole.superadmin:
        raise HTTPException(403, "مدیریت مستقیم پنل نود فقط برای ادمین اصلی مجاز است")
    row = _node_or_404(db, node_id, admin)
    if not bool(getattr(row, "remote_admin_enabled", False)):
        raise HTTPException(400, "مدیریت مستقیم این نود فعال نشده است")
    username = (getattr(row, "panel_admin_username", None) or "").strip()
    password = decrypt_password(getattr(row, "panel_admin_password_enc", None))
    if not username or not password:
        raise HTTPException(400, "مشخصات ادمین پنل نود ذخیره نشده است")
    endpoint = f"{row.api_url.rstrip('/')}/api/node-agent/admin-handoff"
    try:
        response = requests.post(
            endpoint,
            headers={"X-Node-Token": row.api_token},
            json={"username": username, "password": password, "redirect_path": "/dashboard"},
            timeout=(5, 10),
            verify=bool(getattr(row, "verify_tls", True)),
        )
        if response.status_code in {401, 403}:
            detail = "نام کاربری یا رمز ادمین ذخیره‌شده برای پنل نود اشتباه است"
            try:
                detail = str(response.json().get("detail") or detail)
            except Exception:
                pass
            raise HTTPException(response.status_code, detail)
        response.raise_for_status()
        data = response.json()
        path = str(data.get("path") or "")
        if not path.startswith("/api/auth/node-handoff/consume?ticket="):
            raise RuntimeError("پاسخ ورود خودکار نود معتبر نیست")
        return {"ok": True, "url": f"{row.api_url.rstrip('/')}{path}"}
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f"ساخت ورود مستقیم به پنل نود ناموفق بود: {exc}") from exc


def _remove_node_record(db: Session, row: VpnNode) -> str:
    """Remove one controller-side node row without changing the remote host role.

    A node uses this path after it has already registered with a replacement
    controller.  Calling ``set_remote_node_role(..., "main")`` here would
    incorrectly convert that still-active node into a controller, so cleanup is
    intentionally limited to this controller's database and assignments.
    """
    name = str(row.name or "Node")
    token = f"node:{int(row.id)}"

    # Remove the deleted token from explicitly scoped delegated admins. Admins
    # using ["all"] remain future-aware and need no rewrite.
    for delegated in db.query(Admin).filter(Admin.role == AdminRole.admin).all():
        scope = targets_for_admin(delegated)
        if "all" not in scope and token in scope:
            delegated.server_targets = serialize_admin_targets(scope - {token})

    # Keep explicit user placements valid. If their last server disappears,
    # move them to the first currently assignable server; if none exists,
    # deactivate rather than silently granting all servers.
    fallback = [item for item in globally_assignable_tokens(db) if item != token]
    for user in db.query(VpnUser).all():
        scope = targets_for_user(user)
        if "all" in scope or token not in scope:
            continue
        remaining = scope - {token}
        if remaining:
            user.server_targets = serialize_targets(remaining)
        elif fallback:
            user.server_targets = serialize_targets([fallback[0]])
        else:
            user.is_active = False

    db.delete(row)
    return name


@router.delete("/{node_id}")
def delete_node(node_id: int, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("nodes:manage", "nodes"))):
    row = _node_or_404(db, node_id, admin)
    try:
        set_remote_node_role(row, "main")
    except Exception:
        pass
    name = _remove_node_record(db, row)
    db.commit()
    log_event("🗑 حذف Node", f"نام: {name}", actor=admin.username)
    return {"ok": True}


@router.get("/{node_id}/update/check")
def node_update_check(
    node_id: int,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("nodes:view", "nodes")),
):
    return _node_update_request(
        _node_or_404(db, node_id, admin), "GET", "check", timeout=45, db=db,
        controller_url=_controller_url_from_db(db),
    )


@router.post("/{node_id}/update/start")
def node_update_start(
    node_id: int,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("nodes:install", "nodes")),
):
    row = _node_or_404(db, node_id, admin)
    response = _node_update_request(
        row, "POST", "start", timeout=45, db=db,
        controller_url=_controller_url_from_db(db),
    )
    log_event("⬆️ شروع آپدیت Node", f"نام: {row.name}", actor=admin.username)
    return response


@router.get("/{node_id}/update/status")
def node_update_status(
    node_id: int,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("nodes:view", "nodes")),
):
    row = _node_or_404(db, node_id, admin)
    response = _node_update_request(
        row, "GET", "status", timeout=25, db=db,
        controller_url=_controller_url_from_db(db),
    )
    payload = _response_json_dict(response) if isinstance(response, Response) else (response if isinstance(response, dict) else {})
    state = str(payload.get("state") or "").lower()
    if state in {"success", "succeeded", "completed", "done", "failed", "error"}:
        ok = state in {"success", "succeeded", "completed", "done"}
        detail = str(payload.get("message") or ("آپدیت با موفقیت کامل شد." if ok else "فرایند آپدیت با خطا متوقف شد."))
        signature = f"agent|{state}|{detail}|{payload.get('version') or payload.get('current_version') or ''}"
        _notify_node_update_result(db, row, admin, ok=ok, message=detail, source="agent", signature=signature)
    return response


@router.post("/{node_id}/update/report")
def node_update_report(
    node_id: int,
    payload: NodeUpdateReportRequest,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("nodes:install", "nodes")),
):
    """Receive terminal SSH/fallback update results for Telegram audit."""
    row = _node_or_404(db, node_id, admin)
    detail = payload.message or ("آپدیت با موفقیت کامل شد." if payload.ok else "فرایند آپدیت با خطا متوقف شد.")
    signature = f"{payload.source}|{'success' if payload.ok else 'failed'}|{detail}"
    sent = _notify_node_update_result(
        db, row, admin, ok=payload.ok, message=detail, source=payload.source, signature=signature
    )
    return {"ok": True, "notice_sent": sent}


@router.get("/{node_id}/update/log")
def node_update_log(
    node_id: int,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("nodes:view", "nodes")),
):
    return _node_update_request(
        _node_or_404(db, node_id, admin), "GET", "log", timeout=25, db=db,
        controller_url=_controller_url_from_db(db),
    )


@router.post("/{node_id}/test")
def test_node(node_id: int, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("nodes:view", "nodes"))):
    row = _node_or_404(db, node_id, admin)
    try:
        snapshot = refresh_node(db, row, timeout=15)
    except RuntimeError as exc:
        raise HTTPException(502, str(exc))
    return {"ok": True, "snapshot": snapshot}


@router.post("/{node_id}/sync")
def sync_one_node(node_id: int, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("nodes:manage", "nodes"))):
    row = _node_or_404(db, node_id, admin)
    try:
        result = sync_node(db, row)
    except RuntimeError as exc:
        raise HTTPException(502, str(exc))
    log_event("🔄 همگام‌سازی Node", f"نام: {row.name}", actor=admin.username)
    return result


@router.post("/{node_id}/ssh")
def node_ssh(node_id: int, payload: NodeSshExecuteRequest, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("nodes:ssh", "nodes"))):
    row = _node_or_404(db, node_id, admin)
    host, port, username, password = _ssh_details(
        row, host=payload.host, port=payload.port, username=payload.username, password=payload.password
    )
    if payload.save_password:
        row.ssh_host, row.ssh_port, row.ssh_username = host, port, username
        row.ssh_password_enc = encrypt_password(password)
        db.commit()
    job_id = start_ssh_job(
        host=host, port=port, username=username, password=password,
        command=payload.command, title=f"SSH — {row.name}", timeout_seconds=payload.timeout_seconds,
    )
    log_event("⌨️ SSH Node", f"نود: {row.name}", actor=admin.username)
    return {"ok": True, "job_id": job_id}


@router.post("/{node_id}/action")
def node_action(node_id: int, payload: NodeActionRequest, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("nodes:manage", "nodes"))):
    row = _node_or_404(db, node_id, admin)
    host, port, username, password = _ssh_details(row)
    try:
        command, timeout_seconds = action_command(payload.action)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    job_id = start_ssh_job(
        host=host, port=port, username=username, password=password,
        command=command, title=f"{payload.action} — {row.name}", timeout_seconds=timeout_seconds,
    )
    return {"ok": True, "job_id": job_id}


@router.post("/remote-install")
def remote_install(payload: NodeRemoteInstallRequest, request: Request, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("nodes:install", "nodes"))):
    controller_url = (payload.controller_url or str(request.base_url)).strip().rstrip("/")
    token = get_or_create_agent_token(db)
    job_id = start_remote_install_job(payload.model_dump(), controller_url, token)
    log_event("🚀 نصب خودکار Node", f"مقصد: {payload.host} | نام: {payload.node_name}", actor=admin.username)
    return {"ok": True, "job_id": job_id}


@router.get("/jobs/{job_id}")
def node_job(job_id: str, admin: Admin = Depends(require_permission("nodes:view", "nodes"))):
    job = get_job(job_id)
    if not job:
        raise HTTPException(404, "عملیات نود پیدا نشد یا سرویس پنل ری‌استارت شده است")
    return job


@router.post("/mode")
def update_mode(payload: NodeModeRequest, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("nodes:manage", "nodes"))):
    mode = set_node_mode(db, payload.mode)
    log_event("🧭 تغییر حالت Node", f"حالت: {mode}", actor=admin.username)
    return {"ok": True, "mode": mode}


@router.get("/agent-token")
def agent_token(db: Session = Depends(get_db), admin: Admin = Depends(require_superadmin)):
    """Reveal the cluster-wide Node Agent token only to the superadmin."""
    return {"token": get_or_create_agent_token(db)}


@router.post("/agent-token/regenerate")
def regenerate_agent_token(db: Session = Depends(get_db), admin: Admin = Depends(require_superadmin)):
    """Token rotation is a cluster-secret operation and cannot be delegated."""
    token = get_or_create_agent_token(db, regenerate=True)
    log_event("🔐 بازسازی توکن Node Agent", "توکن اتصال نود تغییر کرد", actor=admin.username)
    return {"token": token}


@agent_router.post("/register")
def node_agent_register(
    payload: NodeSelfRegisterRequest,
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    _agent_auth(db, x_node_token)
    normalized_url = payload.api_url.strip().rstrip("/")
    # Do not create a ghost/offline row merely because the node could reach the
    # controller. The controller must first be able to reach the advertised
    # public Node Agent endpoint itself. This catches Cloudflare 521, wrong
    # scheme/port and incomplete SSL setup before the row is committed.
    try:
        snapshot = probe_node_snapshot(
            normalized_url, payload.api_token.strip(), bool(payload.verify_tls), timeout=15
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    row = db.query(VpnNode).filter(
        (VpnNode.api_url == normalized_url) | (VpnNode.name == payload.name.strip())
    ).first()
    if row is None:
        row = VpnNode(name=payload.name.strip(), api_url=normalized_url, api_token=payload.api_token.strip())
        db.add(row)
    else:
        row.name = payload.name.strip()
        row.api_url = normalized_url
        row.api_token = payload.api_token.strip()
    row.enabled = bool(payload.enabled)
    row.verify_tls = bool(payload.verify_tls)
    row.weight = int(payload.weight)
    if payload.ssh_host:
        row.ssh_host = payload.ssh_host.strip()
    if payload.ssh_port:
        row.ssh_port = int(payload.ssh_port)
    if payload.ssh_username:
        row.ssh_username = payload.ssh_username.strip()
    if payload.clear_ssh_password:
        row.ssh_password_enc = None
    elif payload.save_ssh_password and payload.ssh_password:
        row.ssh_password_enc = encrypt_password(payload.ssh_password)
    if payload.protocol_domains:
        row.protocol_domains = json.dumps(payload.protocol_domains, ensure_ascii=False, separators=(",", ":"))
    row.status = "online"
    row.last_seen_at = datetime.utcnow()
    row.last_error = None
    row.last_snapshot = json.dumps(snapshot, ensure_ascii=False, separators=(",", ":"))
    db.commit()
    db.refresh(row)
    # A freshly registered node must receive the controller's canonical
    # OpenVPN CA/tls-auth bundle immediately.  Waiting for the periodic sync
    # leaves a short window where a combined multi-server profile can fail on
    # the new node with HMAC authentication errors.
    sync_all_nodes_async()
    return {"ok": True, "node": node_to_dict(row)}


@agent_router.post("/unregister")
def node_agent_unregister(
    payload: NodeSelfUnregisterRequest,
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    """Remove the caller's old node row after a successful controller move.

    Authentication requires the old controller's cluster token, while the
    payload must also contain the node's own Agent token.  This two-secret
    check prevents an unrelated registered node from deleting another row.
    The endpoint is idempotent so migrations from older controllers can retry.
    """
    _agent_auth(db, x_node_token)
    query = db.query(VpnNode).filter(VpnNode.api_token == payload.api_token.strip())
    row = query.first()
    if row is None and payload.api_url:
        row = db.query(VpnNode).filter(VpnNode.api_url == payload.api_url.strip().rstrip("/")).first()
    if row is None:
        return {"ok": True, "removed": False}

    name = _remove_node_record(db, row)
    db.commit()
    log_event("🔁 انتقال Node", f"نود {name} به کنترلر دیگری منتقل شد", actor="node-self-migration")
    return {"ok": True, "removed": True, "name": name}


@agent_router.post("/admission/reserve")
def node_agent_cluster_admission_reserve(
    payload: ClusterAdmissionReserveRequest,
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    from app.models import VpnUser
    from app.services.cluster_admission import registered_node_from_token, reserve_on_controller
    from app.services.server_targets import user_selected_for_node

    node = registered_node_from_token(db, x_node_token)
    if node is None:
        raise HTTPException(status_code=401, detail="registered_node_token_invalid")
    user = db.query(VpnUser).filter(VpnUser.username == payload.username).first()
    if user is None or not user_selected_for_node(user, int(node.id)):
        raise HTTPException(status_code=403, detail="server_not_selected")
    decision = reserve_on_controller(
        db,
        username=user.username,
        server_key=f"node:{int(node.id)}",
        session_key=payload.session_key,
        protocol=payload.protocol,
        public_ip=payload.ip_address,
        connect_time=payload.connect_time,
        source_port=payload.source_port,
        tunnel_ip=payload.tunnel_ip,
    )
    if not decision.allowed:
        db.rollback()
        raise HTTPException(status_code=403, detail=decision.reason or "max_devices_reached_all_protocols")
    db.commit()
    return {
        "ok": True,
        "allowed": True,
        "session_key": decision.session_key,
        "replaces_session_key": decision.replaces_session_key,
        "active_count": decision.active_count,
        "max_devices": decision.max_devices,
    }


@agent_router.post("/admission/release")
def node_agent_cluster_admission_release(
    payload: ClusterAdmissionReleaseRequest,
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    from app.services.cluster_admission import registered_node_from_token, release_on_controller

    node = registered_node_from_token(db, x_node_token)
    if node is None:
        raise HTTPException(status_code=401, detail="registered_node_token_invalid")
    deleted = release_on_controller(
        db, server_key=f"node:{int(node.id)}", session_key=payload.session_key
    )
    db.commit()
    return {"ok": True, "released": deleted}


@agent_router.post("/admission/xray-batch")
def node_agent_cluster_xray_batch(
    payload: ClusterAdmissionXrayBatchRequest,
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    from app.models import VpnUser
    from app.services.cluster_admission import (
        registered_node_from_token,
        release_missing_xray_on_controller,
        reserve_on_controller,
    )
    from app.services.server_targets import user_selected_for_node

    node = registered_node_from_token(db, x_node_token)
    if node is None:
        raise HTTPException(status_code=401, detail="registered_node_token_invalid")
    server_key = f"node:{int(node.id)}"
    release_missing_xray_on_controller(
        db, server_key=server_key, active_session_keys=payload.active_session_keys
    )
    denied: list[str] = []
    for item in payload.candidates:
        user = db.query(VpnUser).filter(VpnUser.username == item.username).first()
        if user is None or not user_selected_for_node(user, int(node.id)):
            denied.append(item.session_key)
            continue
        decision = reserve_on_controller(
            db,
            username=user.username,
            server_key=server_key,
            session_key=item.session_key,
            protocol=item.protocol,
            public_ip=item.ip_address,
            connect_time=item.connect_time,
        )
        if not decision.allowed:
            denied.append(item.session_key)
    db.commit()
    return {"ok": True, "denied_session_keys": denied}


@agent_router.post("/update/version-sync")
def node_agent_update_version_sync(
    payload: dict,
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    _agent_auth(db, x_node_token)
    try:
        return update_manager.sync_published_release_label(
            payload.get("version"), payload.get("sha256")
        )
    except ValueError as exc:
        raise HTTPException(400, "published_version_invalid") from exc


@agent_router.get("/update/check")
def node_agent_update_check(
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    _agent_auth(db, x_node_token)
    return update_manager.check_latest(db)


@agent_router.post("/update/start")
def node_agent_update_start(
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    _agent_auth(db, x_node_token)
    return update_manager.start_update(db)


@agent_router.get("/update/status")
def node_agent_update_status(
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    _agent_auth(db, x_node_token)
    return update_manager.get_status()


@agent_router.get("/update/log")
def node_agent_update_log(
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    _agent_auth(db, x_node_token)
    return update_manager.get_log()


@agent_router.post("/admin-handoff")
def node_agent_admin_handoff(
    payload: NodeAdminHandoffRequest,
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    _agent_auth(db, x_node_token)
    target = db.query(Admin).filter(Admin.username == payload.username).first()
    if not target or not target.is_active or not verify_password(payload.password, target.password_hash):
        raise HTTPException(401, "نام کاربری یا رمز ادمین پنل نود اشتباه است")
    if target.role != AdminRole.superadmin:
        raise HTTPException(403, "برای مدیریت کامل نود باید مشخصات ادمین اصلی نود ذخیره شود")
    node_name_row = db.query(Setting).filter(Setting.key == "node_name").first()
    ticket = issue_handoff(db, {
        "username": target.username,
        "redirect_path": payload.redirect_path,
        "node_name": str(node_name_row.value or "Node") if node_name_row else "Node",
    })
    return {
        "ok": True,
        "path": f"/api/auth/node-handoff/consume?ticket={quote(ticket, safe='')}",
        "expires_in": 75,
    }


@agent_router.post("/protocol-proxy")
def node_agent_protocol_proxy(
    payload: NodeProtocolProxyRequest,
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    _agent_auth(db, x_node_token)
    path = _validate_protocol_proxy_path(payload.path)
    admin = (
        db.query(Admin)
        .filter(Admin.role == AdminRole.superadmin, Admin.is_active == True)  # noqa: E712
        .order_by(Admin.id)
        .first()
    )
    if not admin:
        raise HTTPException(503, "ادمین اصلی فعال روی نود پیدا نشد")
    token = create_access_token({"sub": admin.username}, expires_minutes=3)
    settings = get_settings()
    try:
        response = requests.request(
            payload.method.upper(),
            f"http://127.0.0.1:{int(settings.BACKEND_PORT)}{path}",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Node-Internal-Proxy": "1",
                "Accept": "application/json",
            },
            params=payload.params or None,
            json=payload.body if payload.method.upper() in {"POST", "PUT", "DELETE"} else None,
            timeout=170,
        )
        return _proxy_response(response)
    except Exception as exc:
        raise HTTPException(502, f"اجرای مدیریت پروتکل در خود نود ناموفق بود: {exc}") from exc


def _node_agent_local_admin_post(db: Session, path: str) -> Response:
    admin = (
        db.query(Admin)
        .filter(Admin.role == AdminRole.superadmin, Admin.is_active == True)  # noqa: E712
        .order_by(Admin.id)
        .first()
    )
    if not admin:
        raise HTTPException(503, "ادمین اصلی فعال روی نود پیدا نشد")
    token = create_access_token({"sub": admin.username}, expires_minutes=3)
    settings = get_settings()
    try:
        response = requests.post(
            f"http://127.0.0.1:{int(settings.BACKEND_PORT)}{path}",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Node-Internal-Proxy": "1",
                "Accept": "application/json",
            },
            timeout=40,
        )
        return _proxy_response(response)
    except requests.RequestException as exc:
        raise HTTPException(502, f"اجرای عملیات اتصال در خود نود ناموفق بود: {exc}") from exc


@agent_router.post("/sessions/{session_id}/disconnect")
def node_agent_session_disconnect(
    session_id: int,
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    _agent_auth(db, x_node_token)
    return _node_agent_local_admin_post(db, f"/api/users/sessions/{int(session_id)}/disconnect")


@agent_router.post("/sessions/{session_id}/internet-block")
def node_agent_session_internet_block(
    session_id: int,
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    _agent_auth(db, x_node_token)
    return _node_agent_local_admin_post(db, f"/api/users/sessions/{int(session_id)}/internet-block")


@agent_router.post("/sessions/{session_id}/ban-ip")
def node_agent_session_ban_ip(
    session_id: int,
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    _agent_auth(db, x_node_token)
    return _node_agent_local_admin_post(db, f"/api/users/sessions/{int(session_id)}/ban-ip")


@agent_router.get("/subscription-asset/{token}/{asset_name}")
def node_agent_subscription_asset(
    token: str,
    asset_name: str,
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    """Return generated OpenVPN/SSTP assets to the authenticated controller.

    Public subscription routes are intentionally blocked when this server is a
    managed node.  The controller therefore uses this Node Agent endpoint,
    authenticated with the per-node token, and the node generates/reads the
    asset locally where its PKI and SSTP certificate actually exist.
    """
    _agent_auth(db, x_node_token)
    asset = str(asset_name or "").strip().lower()
    from app.routers import sub as sub_router

    if asset == "openvpn-config":
        if effective_server_role(db) == "node":
            # Managed nodes never issue client certificates. The controller is
            # the only EasyRSA writer and generates both combined and per-node
            # profiles from one stable credential pair. This prevents duplicate
            # serials and profiles that invalidate each other across nodes.
            raise HTTPException(409, "openvpn_profile_must_be_generated_by_controller")
        return sub_router.download_sub_openvpn_config(token, db)
    if asset == "sstp-cert":
        return sub_router.download_sub_sstp_cert(token, db)
    raise HTTPException(404, "subscription_asset_not_supported")


@agent_router.get("/openvpn-pki/export")
def node_agent_openvpn_pki_export(
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    """Export this node's complete OpenVPN PKI to its authenticated controller.

    This private endpoint is used only once when upgrading a management-only
    controller that historically had no local EasyRSA directory.  Adopting an
    existing node bundle preserves old client profiles, after which the same
    canonical bundle is mirrored to every current and future node.
    """
    _agent_auth(db, x_node_token)
    from app.services.cert_manager import export_pki_bundle, pki_bundle_fingerprint

    bundle = export_pki_bundle()
    if not bundle:
        raise HTTPException(404, "openvpn_pki_not_available")
    return {
        "ok": True,
        "openvpn_pki": bundle,
        "fingerprint": pki_bundle_fingerprint(bundle),
    }


@agent_router.get("/backup/export")
def node_agent_backup_export(
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    """Return this node's exact local full backup to its authenticated controller."""
    _agent_auth(db, x_node_token)
    from app.routers.backup import build_full_backup_payload

    return build_full_backup_payload(db, include_cluster_nodes=False)


@agent_router.post("/backup/import")
async def node_agent_backup_import(
    request: Request,
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    """Replace the node's local DB/config identity from a controller backup."""
    _agent_auth(db, x_node_token)
    from app.routers.backup import import_backup

    from app.services.backup_codec import BackupFormatError, decode_backup_bytes, encode_json_backup

    settings = get_settings()
    max_upload = max(1, int(settings.BACKUP_MAX_COMPRESSED_BYTES))
    chunks: list[bytes] = []
    received = 0
    try:
        async for chunk in request.stream():
            received += len(chunk)
            if received > max_upload:
                raise BackupFormatError("node backup upload exceeds the configured safety limit")
            chunks.append(chunk)
        raw = decode_backup_bytes(b"".join(chunks))
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("node backup root must be an object")
    except (BackupFormatError, json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise HTTPException(400, "فایل بکاپ نود معتبر یا قابل‌اعتماد نیست") from exc
    from io import BytesIO
    upload = UploadFile(
        filename="node-backup.json.gz",
        file=BytesIO(encode_json_backup(payload)),
    )
    actor = Admin(username="node-controller-restore", password_hash="-", role=AdminRole.superadmin)
    return import_backup(
        file=upload, restore_mode="replace", restore_nodes=False, allow_degraded=False, db=db, admin=actor
    )


@agent_router.get("/ping")
def node_agent_ping(
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    """Cheap authenticated reachability check used when a full snapshot is slow."""
    _agent_auth(db, x_node_token)
    return build_local_ping(db)


@agent_router.get("/presence")
def node_agent_presence(
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    _agent_auth(db, x_node_token)
    db.expire_all()
    return build_cached_local_presence(db, max_age_seconds=1.0)


@agent_router.get("/health")
def node_agent_health(
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    _agent_auth(db, x_node_token)
    # Do not block the controller request behind a stale Xray refresh.  The
    # local scheduler normally maintains presence; in the rare stale case,
    # trigger a best-effort refresh in the background and serve the short-lived
    # cached snapshot immediately.  This removes intermittent 12-second read
    # timeouts on small nodes while preserving live Online Users data.
    from app.services.scheduler import refresh_xray_presence_if_stale, xray_presence_age_seconds
    if xray_presence_age_seconds() > 12.0:
        threading.Thread(
            target=lambda: refresh_xray_presence_if_stale(max_age_seconds=12.0),
            daemon=True,
            name="node-agent-xray-refresh",
        ).start()
    db.expire_all()
    return build_cached_local_snapshot(db, max_age_seconds=8.0)


@agent_router.post("/role")
def node_agent_role(
    payload: NodeRoleRequest,
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    _agent_auth(db, x_node_token)
    _setting(db, "server_role", payload.role)
    if payload.role == "node":
        _setting(db, "deployment_role", "node")
        if payload.controller_url:
            _setting(db, "node_controller_url", payload.controller_url.strip().rstrip("/"))
        _setting(db, "node_temporary_main_mode", "0")
        _setting(db, "node_temporary_main_started_at", "")
    elif payload.temporary:
        # Durable marker consumed by startup self-healing.  The update may
        # restart the API before the controller can send the restore request.
        _setting(db, "node_temporary_main_mode", "1")
        _setting(db, "node_temporary_main_started_at", datetime.utcnow().isoformat() + "Z")
        if payload.controller_url:
            _setting(db, "node_controller_url", payload.controller_url.strip().rstrip("/"))
    else:
        # A deliberate conversion to a main panel must not be auto-reverted.
        # Clear every node-only marker in the same transaction so the next API
        # restart and the local UI both observe one consistent identity.
        _setting(db, "deployment_role", "main")
        _setting(db, "server_role", "main")
        _setting(db, "node_panel_enabled", "0")
        _setting(db, "node_controller_url", "")
        _setting(db, "node_controller_token", "")
        _setting(db, "node_name", "")
        _setting(db, "node_public_url", "")
        _setting(db, "node_temporary_main_mode", "0")
        _setting(db, "node_temporary_main_started_at", "")
    db.commit()
    return {
        "ok": True,
        "role": payload.role,
        "temporary": bool(payload.temporary),
        "controller_url": payload.controller_url or "",
    }


@agent_router.post("/panel-mode")
def node_agent_panel_mode(
    payload: NodePanelModeRequest,
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    _agent_auth(db, x_node_token)
    enabled = set_local_node_panel_enabled(db, bool(payload.enabled))
    return {
        "ok": True,
        "enabled": enabled,
        "server_role": panel_ui_server_role(db),
        "message": "پنل اختصاصی نود فعال شد" if enabled else "رابط کامل محلی روی نود فعال شد",
    }


@agent_router.post("/sync")
def node_agent_sync(
    payload: NodeAgentSyncRequest,
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    _agent_auth(db, x_node_token)
    try:
        return apply_agent_sync(
            db,
            payload.controller_id,
            payload.users,
            openvpn_pki=payload.openvpn_pki,
            ipsec_psk=payload.ipsec_psk,
            banned_ips=payload.banned_ips,
            internet_blocks=payload.internet_blocks,
        )
    except Exception as exc:
        db.rollback()
        raise HTTPException(500, f"همگام‌سازی Node ناموفق بود: {exc}")


@agent_router.post("/global-controls/sync")
def node_agent_global_controls_sync(
    payload: NodeAgentGlobalControlsSyncRequest,
    x_node_token: str | None = Header(None, alias="X-Node-Token"),
    db: Session = Depends(get_db),
):
    _agent_auth(db, x_node_token)
    try:
        from app.services.node_manager import apply_global_controls_snapshot

        return {
            "ok": True,
            "global_controls": apply_global_controls_snapshot(
                db,
                payload.controller_id,
                banned_ips=payload.banned_ips,
                internet_blocks=payload.internet_blocks,
                force_unban_ips=payload.force_unban_ips,
                force_restore_ips=payload.force_restore_ips,
            ),
        }
    except Exception as exc:
        db.rollback()
        raise HTTPException(500, f"همگام‌سازی مسدودی‌های سراسری Node ناموفق بود: {exc}")
