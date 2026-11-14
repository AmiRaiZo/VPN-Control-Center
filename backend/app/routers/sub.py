"""
روتر عمومیِ «لینک اشتراک» - عمداً هیچ‌کدام از اندپوینت‌های این فایل نیاز به
توکن ادمین (JWT) ندارند؛ همان‌طور که در پنل‌های مشابه رایج است، خودِ توکن
تصادفی و طولانی داخل URL (sub_token) نقش اعتبارسنجی را بازی می‌کند. کاربر
نهایی این لینک را (نه پنل مدیریت را) باز می‌کند تا وضعیت اشتراک خودش و
اطلاعات اتصال L2TP/PPTP/OpenVPN را ببیند.
"""
from datetime import date, datetime, time as datetime_time
import base64
import io
import re
from urllib.parse import quote

import requests
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
import qrcode
from qrcode.image.svg import SvgPathImage
from sqlalchemy.orm import Session

from app.database import get_db
from app.config import get_settings
from app.models import VpnUser, VpnUserSubAlias, ConnectionLog, VpnNode
from app.services.vpn_manager import get_ipsec_psk, build_client_ovpn, reconcile_openconnect_sessions
from app.services.cert_manager import (
    get_client_profile_credentials, read_sstp_cert,
    ensure_controller_openvpn_pki, CertError,
)
from app.services.sub_link import (
    get_setting as _setting,
    build_sub_link,
    build_xray_sub_origin,
)
from app.services.node_manager import (
    build_multi_xray_profiles, public_node_list, openvpn_profile_nodes, openvpn_remotes, sync_all_nodes_async,
)
from app.routers.meta import get_platform_apps

router = APIRouter(prefix="/api/sub", tags=["subscription"])


def _get_user_by_token(db: Session, token: str) -> VpnUser:
    # Subscription URLs are intentionally permanent.  First resolve the
    # current token, then legacy aliases retained across restores/rotations.
    u = db.query(VpnUser).filter(VpnUser.sub_token == token).first()
    if not u:
        alias = db.query(VpnUserSubAlias).filter(VpnUserSubAlias.token == token).first()
        if alias:
            u = db.query(VpnUser).filter(VpnUser.id == alias.user_id).first()
    if not u:
        raise HTTPException(404, "لینک اشتراک نامعتبر است یا حذف شده")
    return u


def _status(u: VpnUser) -> tuple[str, str]:
    """کلید و برچسبِ فارسیِ وضعیت نهایی این کاربر."""
    is_expired = u.expire_date is not None and u.expire_date < date.today()
    quota_exceeded = u.quota_bytes > 0 and u.used_bytes >= u.quota_bytes

    if not u.is_active:
        return "disabled_admin", "غیرفعال (توسط ادمین)"
    if quota_exceeded and is_expired:
        return "quota_and_time", "غیرفعال (اتمام حجم و زمان)"
    if quota_exceeded:
        return "quota", "غیرفعال (اتمام حجم)"
    if is_expired:
        return "time", "غیرفعال (اتمام زمان)"
    return "active", "فعال"


def _assert_subscription_active(u: VpnUser) -> None:
    status_key, _ = _status(u)
    if status_key != "active":
        raise HTTPException(403, "اشتراک این کاربر فعال نیست")


def _qr_svg_bytes(value: str) -> bytes:
    """Build an SVG QR without Pillow or a second public HTTP request."""
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=9,
        border=3,
    )
    qr.add_data(value)
    qr.make(fit=True)
    image = qr.make_image(image_factory=SvgPathImage)
    buffer = io.BytesIO()
    image.save(buffer)
    return buffer.getvalue()


def _qr_data_url(value: str) -> str:
    return "data:image/svg+xml;base64," + base64.b64encode(_qr_svg_bytes(value)).decode("ascii")


def _request_origin(request: Request) -> str | None:
    """Return the public origin that successfully served this request.

    A subscription page that already loaded is the most reliable source for the
    raw subscription host. Database domain flags can become stale after DNS, SSL,
    or port changes; using the current origin prevents those stale settings from
    producing a dead link.
    """
    proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "http").split(",", 1)[0].strip().lower()
    host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc).split(",", 1)[0].strip()
    if proto not in {"http", "https"} or not host or not re.fullmatch(r"[A-Za-z0-9.\-:\[\]]+", host):
        return None
    return f"{proto}://{host}"

def _human_bytes(value: int) -> str:
    value = max(0, int(value or 0))
    units = ("B", "KB", "MB", "GB", "TB")
    size = float(value)
    unit = units[0]
    for unit in units:
        if size < 1024 or unit == units[-1]:
            break
        size /= 1024
    digits = 0 if unit in {"B", "KB", "MB"} else 2
    return f"{size:.{digits}f}{unit}"


def _subscription_usage_summary(user: VpnUser) -> str:
    quota_unlimited = int(user.quota_bytes or 0) <= 0
    time_unlimited = user.expire_date is None and not (
        user.expire_mode == "after_first_connect" and user.expire_after_days and user.first_connect_at is None
    )
    if quota_unlimited and time_unlimited:
        return "تمام نامحدود"

    if user.expire_date is not None:
        days = max(0, (user.expire_date - date.today()).days)
        time_text = f"{days} روز مانده"
    elif user.expire_mode == "after_first_connect" and user.expire_after_days and user.first_connect_at is None:
        time_text = "زمان بعد از اولین اتصال"
    else:
        time_text = "زمان نامحدود"

    if quota_unlimited:
        quota_text = "حجم نامحدود"
    else:
        quota_text = f"{_human_bytes(user.used_bytes)} از {_human_bytes(user.quota_bytes)} مصرف شده"
    return f"{time_text} | {quota_text}"


def _subscription_userinfo_header(user: VpnUser) -> str:
    fields = [
        "upload=0",
        f"download={int(user.used_bytes or 0)}",
        f"total={int(user.quota_bytes or 0)}",
    ]
    if user.expire_date is not None:
        expires = datetime.combine(user.expire_date, datetime_time.max)
        fields.append(f"expire={int(expires.timestamp())}")
    return "; ".join(fields)


def _enabled_protocol_target(nodes: list[dict], protocol: str):
    """Return the first selected endpoint that really exposes ``protocol``.

    ``public_node_list`` has already combined the endpoint capability with the
    user's per-protocol permission, so this is the single source of truth for
    both local and remote-node subscription cards.
    """
    for node in nodes:
        settings = ((node.get("protocols") or {}).get(protocol) or {})
        if bool(settings.get("enabled")):
            return node, settings
    return None


def _target_address(target, fallback: str) -> str:
    if not target:
        return fallback
    node, settings = target
    return (
        str(settings.get("server_address") or "").strip()
        or str(node.get("display_address") or "").strip()
        or str(node.get("address") or "").strip()
        or fallback
    )


def _target_port(target, key: str, fallback: int) -> int:
    if not target:
        return fallback
    _node, settings = target
    try:
        value = int(settings.get(key) or fallback)
        return value if 1 <= value <= 65535 else fallback
    except (TypeError, ValueError):
        return fallback


def _target_text(target, key: str, fallback: str | None = None) -> str | None:
    """Read one endpoint-local subscription value without cross-node fallback.

    Secrets such as the L2TP/IPsec PSK can intentionally differ per node.  A
    missing value on a remote node must therefore remain missing instead of
    silently showing the controller's value, which would produce a plausible
    but non-working configuration.
    """
    if not target:
        return fallback
    _node, settings = target
    value = str(settings.get(key) or "").strip()
    return value or fallback


def _remote_asset_response(
    db: Session,
    user: VpnUser,
    target,
    asset_path: str,
    *,
    timeout: int = 120,
) -> requests.Response | None:
    """Fetch a generated subscription asset from the selected remote node.

    In Nodes Only mode the controller may deliberately have no local OpenVPN
    PKI or SSTP certificate.  Reading/generating those files on the controller
    therefore fails even though the protocol is healthy on the node.  The user
    is already mirrored to the node with the same long subscription token, so
    proxy the node's own public subscription asset instead of touching local
    protocol files.
    """
    if not target:
        return None
    endpoint, _settings = target
    if bool(endpoint.get("local")):
        return None
    try:
        node_id = int(endpoint.get("id"))
    except (TypeError, ValueError):
        raise HTTPException(502, "شناسه نود انتخاب‌شده برای دانلود معتبر نیست")
    node = db.query(VpnNode).filter(VpnNode.id == node_id, VpnNode.enabled == True).first()  # noqa: E712
    if not node:
        raise HTTPException(503, "نود انتخاب‌شده برای دانلود در دسترس نیست")
    token = quote(str(user.sub_token or ""), safe="")
    asset_name = str(asset_path or "").strip().strip("/")
    if asset_name not in {"openvpn-config", "sstp-cert"}:
        raise HTTPException(400, "نوع فایل درخواستی از نود معتبر نیست")

    # Controller-managed nodes intentionally block their public /api/sub routes.
    # Fetch the asset through the authenticated Node Agent route instead; this
    # route is explicitly allowed in node mode and never exposes the node token
    # to the browser.  Keep a legacy fallback for older nodes that do not yet
    # expose the agent asset endpoint.
    agent_url = f"{node.api_url.rstrip('/')}/api/node-agent/subscription-asset/{token}/{asset_name}"
    legacy_url = f"{node.api_url.rstrip('/')}/api/sub/{token}/{asset_name}"
    common = {
        "timeout": timeout,
        "verify": bool(getattr(node, "verify_tls", True)),
        "headers": {
            "X-Node-Token": str(node.api_token or ""),
            "Accept": "application/octet-stream, application/json",
        },
    }
    try:
        response = requests.get(agent_url, **common)
        if response.status_code in {404, 405, 501}:
            legacy_headers = {"Accept": "application/octet-stream, application/json"}
            response = requests.get(legacy_url, timeout=timeout, verify=common["verify"], headers=legacy_headers)
    except requests.RequestException as exc:
        raise HTTPException(502, f"دریافت فایل از نود «{node.name}» ناموفق بود: {exc}") from exc
    if response.status_code >= 400:
        detail = response.text[-1200:] or f"HTTP {response.status_code}"
        try:
            body = response.json()
            detail = str(body.get("detail") or body.get("message") or detail)
        except Exception:
            pass
        if response.status_code == 423 and "node_managed_by_controller" in detail:
            detail = "نود هنوز از مسیر قدیمی دانلود استفاده می‌کند؛ همین نسخه را روی نود هم نصب کنید"
        raise HTTPException(response.status_code, f"نود «{node.name}»: {detail}")
    return response


def _openvpn_target_remotes(target) -> list[tuple[str, int, str]]:
    """Return every active OpenVPN listener for exactly one public endpoint."""
    if not target:
        return []
    node, settings = target
    if not bool(settings.get("enabled")):
        return []
    address = (
        str(settings.get("server_address") or "").strip()
        or str(node.get("display_address") or "").strip()
        or str(node.get("address") or "").strip()
    )
    if not address:
        return []
    candidates = [
        (address, settings.get("udp_port") or 1194, "udp"),
        (address, settings.get("tcp_port") or 1194, "tcp"),
    ]
    extras = []
    for extra in settings.get("extra_ports") or []:
        if not extra.get("active", True):
            continue
        extras.append((address, extra.get("port"), extra.get("protocol") or "udp"))
    extras.sort(key=lambda row: (int(row[1] or 0), 0 if str(row[2]).lower().startswith("udp") else 1))
    candidates.extend(extras)
    result: list[tuple[str, int, str]] = []
    seen: set[tuple[str, int, str]] = set()
    for host, raw_port, raw_proto in candidates:
        try:
            port = int(raw_port)
        except (TypeError, ValueError):
            continue
        proto = "tcp" if str(raw_proto or "").lower().startswith("tcp") else "udp"
        item = (host, port, proto)
        if 1 <= port <= 65535 and item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _openvpn_target_key(node: dict) -> str:
    if bool(node.get("local")):
        return "local"
    try:
        return f"node-{int(node.get('id'))}"
    except (TypeError, ValueError):
        return ""


def _find_openvpn_target(nodes: list[dict], target_key: str):
    key = str(target_key or "").strip().lower()
    for node in nodes:
        if _openvpn_target_key(node) != key:
            continue
        settings = ((node.get("protocols") or {}).get("openvpn") or {})
        if bool(settings.get("enabled")):
            return node, settings
    return None


def _find_protocol_target(nodes: list[dict], target_key: str, protocol: str):
    key = str(target_key or "").strip().lower()
    protocol = str(protocol or "").strip().lower()
    for node in nodes:
        if _openvpn_target_key(node) != key:
            continue
        settings = ((node.get("protocols") or {}).get(protocol) or {})
        if bool(settings.get("enabled")):
            return node, settings
    return None


def _safe_download_name(value: str, fallback: str = "server") -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", str(value or "").strip()).strip("-._")
    return cleaned[:80] or fallback


def _profile_credentials(user: VpnUser) -> tuple[str, str]:
    """Get one stable credential pair shared by combined and per-node files.

    EasyRSA state changes only for a first issue or an explicit repair/reissue.
    In those cases immediately queue a fleet sync so every node receives the
    same index and CRL; an ordinary repeat download does not restart nodes.
    """
    cert_pem, key_pem, status = get_client_profile_credentials(user.username)
    if status in {"generated", "reissued"}:
        sync_all_nodes_async()
    return cert_pem, key_pem


def _rewrite_ovpn_remotes(profile: str, remotes: list[tuple[str, int, str]]) -> str:
    """Replace only ``remote`` directives while preserving node PKI blocks."""
    remote_lines: list[str] = []
    seen: set[tuple[str, int, str]] = set()
    for host, port, proto in remotes:
        host = str(host or "").strip()
        normalized = "tcp" if str(proto or "").lower().startswith("tcp") else "udp"
        try:
            port = int(port)
        except (TypeError, ValueError):
            continue
        if not host or not (1 <= port <= 65535) or any(ch in host for ch in "\r\n \t"):
            continue
        key = (host, port, normalized)
        if key in seen:
            continue
        seen.add(key)
        remote_lines.append(f"remote {host} {port} {'tcp-client' if normalized == 'tcp' else 'udp'}")
    if not remote_lines:
        return profile

    lines = profile.splitlines()
    stripped = [
        line
        for line in lines
        if not re.match(r"^\s*remote\s+", line, re.IGNORECASE)
        and not re.match(r"^\s*remote-random\s*$", line, re.IGNORECASE)
        and not re.match(r"^\s*persist-remote-ip\s*$", line, re.IGNORECASE)
        and not re.match(r"^\s*connect-retry-max\s+\S+\s*$", line, re.IGNORECASE)
    ]
    insert_at = next(
        (index + 1 for index, line in enumerate(stripped) if re.match(r"^\s*dev\s+", line, re.IGNORECASE)),
        min(3, len(stripped)),
    )
    stripped[insert_at:insert_at] = remote_lines + ["connect-retry-max 1"]
    return "\n".join(stripped).rstrip() + "\n"


@router.get("/{token}")
def get_sub_info(token: str, request: Request, db: Session = Depends(get_db)):
    u = _get_user_by_token(db, token)
    status_key, status_label = _status(u)
    reconcile_openconnect_sessions(db, username=u.username)

    online_count = (
        db.query(ConnectionLog)
        .filter(ConnectionLog.user_id == u.id, ConnectionLog.is_online == True, ConnectionLog.device_limit_blocked == False)  # noqa: E712
        .count()
    )

    vpn_domain = _setting(db, "vpn_domain")
    vpn_domain_active = _setting(db, "vpn_domain_status") == "active"
    server_address = vpn_domain if (vpn_domain and vpn_domain_active) else get_settings().PUBLIC_SERVER_IP

    l2tp_port = int(_setting(db, "l2tp_port") or 1701)
    sstp_port = int(_setting(db, "sstp_port") or 4433)

    # اگر برای IKEv2 دامنه‌ی اختصاصی با گواهی معتبر Let's Encrypt تنظیم شده
    # باشد (Settings > SSL برای IKEv2)، همان دامنه به کلاینت نمایش داده
    # می‌شود؛ در غیر این صورت آی‌پی خام سرور (نه server_address بالا).
    #
    # چرا اینجا نباید از server_address (که ممکن است vpn_domain باشد) استفاده
    # کرد: vpn_domain («دامنه‌ی اختصاصیِ پروتکل‌ها») فقط توسط
    # setup_vpn_domain_ssl.sh تنظیم می‌شود و آن اسکریپت فقط گواهی SSTP را در
    # /etc/accel-ppp/sstp-certs می‌نویسد - هیچ ارتباطی به /etc/ipsec.d یا
    # leftid واقعیِ conn IKEv2-MSCHAPv2 ندارد (نگاه کنید به install/setup_ikev2.sh:
    # leftid فقط وقتی به یک دامنه ست می‌شود که مارکر .ikev2-ssl-domain وجود
    # داشته باشد - یعنی فقط از مسیر «Settings > SSL برای IKEv2»، نه از
    # «دامنه‌ی اختصاصیِ پروتکل‌ها»). وقتی آن مارکر نیست، گواهی IKEv2 (self-signed)
    # فقط IP عمومی و hostname سرور را در SAN دارد. قبلاً اینجا اگر ادمین فقط
    # vpn_domain را تنظیم کرده بود (بدون تنظیم جداگانه‌ی SSL اختصاصیِ IKEv2)،
    # به کاربر گفته می‌شد با همان vpn_domain به IKEv2 وصل شود - درحالی‌که
    # گواهیِ واقعیِ سرور اصلاً شامل آن دامنه نبود؛ کلاینت‌های موبایل (iOS/اندروید)
    # در تطبیق هویت سرور IKEv2 سخت‌گیرند و این یعنی خطای "Unsuccessful"/
    # AUTH_FAILED حتی با یوزرنیم/پسورد کاملاً درست.
    ikev2_ssl_domain = _setting(db, "ikev2_ssl_domain")
    ikev2_ssl_active = _setting(db, "ikev2_ssl_status") == "active"
    ikev2_address = ikev2_ssl_domain if (ikev2_ssl_domain and ikev2_ssl_active) else get_settings().PUBLIC_SERVER_IP
    raw_profiles = build_multi_xray_profiles(db, u) if status_key == "active" else []
    vmess_uri = next((item["uri"] for item in raw_profiles if item["protocol"] == "vmess"), None)
    vless_uri = next((item["uri"] for item in raw_profiles if item["protocol"] == "vless"), None)
    current_origin = _request_origin(request)
    # دامنه‌ی مستقل ساب باید منبع اصلی لینک باشد. origin فعلی فقط fallback است؛
    # قبلاً برعکس بود و با بازکردن صفحه از دامنه پنل، لینک خام هم اشتباهاً
    # روی همان دامنه پنل ساخته می‌شد.
    subscription_page_url = build_sub_link(db, token, request_origin=current_origin) or (f"{current_origin}/sub/{token}" if current_origin else None)
    configured_xray_origin = build_xray_sub_origin(db, request_origin=current_origin)
    xray_origin = configured_xray_origin or current_origin
    xray_subscription_path = f"/api/sub/{token}/xray-sub" if raw_profiles else None
    xray_subscription_url = f"{xray_origin}{xray_subscription_path}" if xray_origin and xray_subscription_path else None
    configured_xray_subscription_url = None
    xray_subscription_qr_data_url = _qr_data_url(xray_subscription_url) if xray_subscription_url else None
    usage_summary = _subscription_usage_summary(u)
    xray_profiles = [
        {**item, "qr_data_url": _qr_data_url(item["uri"])}
        for item in raw_profiles
    ]

    nodes = public_node_list(db, u)
    # OpenVPN download targets are allowed to include a temporarily offline node
    # that already acknowledged the canonical fleet PKI.  That keeps both the
    # individual file and the all-server file stable while a node reboots.
    openvpn_available_nodes = (
        openvpn_profile_nodes(db, u, require_shared_pki=False)
        if bool(u.enable_openvpn) else []
    )
    openvpn_download_nodes = (
        openvpn_profile_nodes(db, u, require_shared_pki=True)
        if bool(u.enable_openvpn) else []
    )
    openvpn_syncing = bool(openvpn_available_nodes) and len(openvpn_download_nodes) < len(openvpn_available_nodes)
    if openvpn_syncing:
        # Do not silently render an empty OpenVPN card. Start repairing PKI in
        # the background and expose the readiness state to the public page.
        sync_all_nodes_async()

    # Resolve every protocol from the endpoints actually selected for this
    # user.  The previous code did this only for L2TP; all other classic VPN
    # flags still depended on ``local_selected`` and therefore disappeared on
    # node-only subscriptions even though the node and user both had them
    # enabled.
    protocol_targets = {
        protocol: _enabled_protocol_target(nodes, protocol)
        for protocol in ("l2tp", "pptp", "openvpn", "sstp", "ikev2", "openconnect")
    }
    l2tp_target = protocol_targets["l2tp"]
    pptp_target = protocol_targets["pptp"]
    openvpn_target = protocol_targets["openvpn"]
    sstp_target = protocol_targets["sstp"]
    ikev2_target = protocol_targets["ikev2"]
    openconnect_target = protocol_targets["openconnect"]
    openvpn_profiles = []
    for node in openvpn_download_nodes:
        settings = ((node.get("protocols") or {}).get("openvpn") or {})
        target = (node, settings)
        target_key = _openvpn_target_key(node)
        remotes = _openvpn_target_remotes(target)
        if not target_key or not remotes:
            continue
        openvpn_profiles.append({
            "target_key": target_key,
            "node_id": node.get("id"),
            "node_name": node.get("name") or ("سرور اصلی" if node.get("local") else "Node"),
            "server_address": remotes[0][0],
            "listeners": [
                {"host": host, "port": port, "protocol": proto}
                for host, port, proto in remotes
            ],
            "download_path": f"/api/sub/{u.sub_token}/openvpn-config/{target_key}",
        })

    l2tp_server_address = _target_address(l2tp_target, server_address)
    l2tp_port = _target_port(l2tp_target, "port", l2tp_port)
    l2tp_ipsec_psk = _target_text(
        l2tp_target,
        "ipsec_psk",
        get_ipsec_psk() if l2tp_target and bool(l2tp_target[0].get("local")) else None,
    )
    pptp_server_address = _target_address(pptp_target, server_address)
    sstp_server_address = _target_address(sstp_target, server_address)
    sstp_port = _target_port(sstp_target, "port", sstp_port)
    openconnect_server_address = _target_address(openconnect_target, server_address)
    openconnect_port = _target_port(
        openconnect_target, "port", int(_setting(db, "openconnect_port") or 8443)
    )

    # Preserve the local IKEv2 certificate-aware address calculation.  Remote
    # nodes use the per-protocol domain saved on that node (or its public
    # address as a fallback).
    if ikev2_target and not bool(ikev2_target[0].get("local")):
        ikev2_address = _target_address(ikev2_target, ikev2_address)

    return {
        "username": u.username,
        "password": u.password,
        "status_key": status_key,
        "status_label": status_label,
        "quota_bytes": u.quota_bytes,
        "used_bytes": u.used_bytes,
        "max_devices": u.max_devices,
        "online_count": online_count,
        "expire_date": u.expire_date,
        "expire_mode": u.expire_mode,
        "server_address": server_address,
        "l2tp_server_address": l2tp_server_address,
        "l2tp_port": l2tp_port,
        "ipsec_psk": l2tp_ipsec_psk,
        "enable_l2tp": bool(l2tp_target),
        "enable_pptp": bool(pptp_target),
        "pptp_server_address": pptp_server_address,
        "enable_openvpn": bool(openvpn_target),
        "openvpn_profiles": openvpn_profiles,
        "openvpn_combined_download_path": f"/api/sub/{u.sub_token}/openvpn-config" if openvpn_profiles else None,
        "openvpn_syncing": openvpn_syncing,
        "openvpn_available_targets": len(openvpn_available_nodes),
        "openvpn_ready_targets": len(openvpn_download_nodes),
        "sstp_port": sstp_port,
        "enable_sstp": bool(sstp_target),
        "sstp_server_address": sstp_server_address,
        "sstp_auth_mode": u.sstp_auth_mode,
        "enable_ikev2": bool(ikev2_target),
        "ikev2_address": ikev2_address,
        # OpenConnect (ocserv) هیچ setting فعال/غیرفعال یا پورت قابل‌تغییری در
        # پنل ندارد (برخلاف بقیه‌ی پروتکل‌ها) - پورت همیشه همان مقداری است که
        # install/setup_openconnect.sh هنگام نصب زیرساخت روی سرور نوشته
        # (پیش‌فرض 8443، هم TCP هم UDP).
        "enable_openconnect": bool(openconnect_target) and status_key == "active",
        "openconnect_server_address": openconnect_server_address,
        "openconnect_port": openconnect_port,
        "enable_vmess": bool(vmess_uri),
        "enable_vless": bool(vless_uri),
        "vmess_uri": vmess_uri,
        "vless_uri": vless_uri,
        "subscription_page_url": subscription_page_url,
        "xray_subscription_url": xray_subscription_url,
        "xray_subscription_path": xray_subscription_path,
        "xray_subscription_alt_url": configured_xray_subscription_url,
        "xray_subscription_qr_data_url": xray_subscription_qr_data_url,
        "usage_summary": usage_summary,
        "xray_profiles": xray_profiles,
        "nodes": nodes,
        # دکمه‌ی دانلود سفارشی (Settings > تنظیمات ساب): اگر ادمین تنظیم نکرده
        # باشد هر دو مقدار None/خالی می‌مانند و SubPage.jsx دکمه را اصلاً نشان نمی‌دهد.
        "custom_download_label": _setting(db, "sub_download_label"),
        "custom_download_url": _setting(db, "sub_download_url"),
        # برنامه‌های پیشنهادی برای اتصال (Settings > تنظیمات ساب)؛ همیشه یک
        # دیکشنری کامل با کلیدهای android/windows/ios/mac برمی‌گردد (پیش‌فرض
        # یا سفارشی‌شده‌ی ادمین) - نگاه کنید به app.routers.meta.get_platform_apps.
        "platform_apps": get_platform_apps(db),
    }


@router.get("/{token}/openvpn-config")
def download_sub_openvpn_config(token: str, db: Session = Depends(get_db)):
    """Download one canonical profile that fails over across every assigned node.

    The profile is always generated by the controller from its canonical CA and
    tls-auth key.  Remote nodes are advertised only after they acknowledge the
    exact same fingerprint, so adding a third, tenth, or hundredth server does
    not require a separate client file and cannot produce intermittent HMAC
    failures.
    """
    u = _get_user_by_token(db, token)
    _assert_subscription_active(u)
    if not u.enable_openvpn:
        raise HTTPException(400, "OpenVPN برای این کاربر غیرفعال است")

    canonical_ready = True
    try:
        # Fresh installs and upgrades prepare/generate the canonical bundle
        # outside the request path. Never run apt/EasyRSA while a browser is
        # waiting for a download; this call may only adopt an existing node PKI.
        ensure_controller_openvpn_pki(db, allow_generate=False)
    except CertError:
        canonical_ready = False

    available_remotes = openvpn_remotes(db, u)
    try:
        all_remotes = openvpn_remotes(db, u, require_shared_pki=True) if canonical_ready else []
    except TypeError:
        # Backward-compatible test/plugin shim for wrappers that still expose
        # the pre-2.3.138 two-argument helper signature.
        all_remotes = available_remotes if canonical_ready else []

    if not all_remotes and available_remotes and not canonical_ready:
        # Never issue a client certificate independently on a managed node.
        # Multiple EasyRSA writers sharing one CA can reuse serial numbers and
        # make the combined/per-node profiles invalidate each other.  Ask the
        # controller to adopt/synchronize the canonical PKI, then retry.
        sync_all_nodes_async()
        raise HTTPException(503, "PKI مشترک OpenVPN در حال آماده‌سازی است؛ چند ثانیه بعد دوباره دانلود کنید")

    if not all_remotes:
        if available_remotes:
            sync_all_nodes_async()
            raise HTTPException(503, "کلید مشترک OpenVPN در حال همگام‌سازی با نودهاست؛ چند ثانیه بعد دوباره دانلود کنید")
        raise HTTPException(503, "هیچ سرور OpenVPN فعالی در حالت Node انتخاب‌شده وجود ندارد")

    server_address, first_port, first_proto = all_remotes[0]
    udp_port = first_port if first_proto == "udp" else next((p for h, p, proto in all_remotes if h == server_address and proto == "udp"), first_port)
    tcp_port = first_port if first_proto == "tcp" else next((p for h, p, proto in all_remotes if h == server_address and proto == "tcp"), first_port)

    try:
        cert_pem, key_pem = _profile_credentials(u)
    except CertError as exc:
        raise HTTPException(500, f"ساخت سرتیفیکیت اختصاصی این کاربر ناموفق بود: {exc}") from exc

    try:
        content = build_client_ovpn(
            u.username, server_address, udp_port, tcp_port, cert_pem, key_pem,
            # all_remotes already contains every base and extra listener for
            # every compatible endpoint. Reusing the controller-local extra
            # port table here could incorrectly attach a main-server port to a
            # remote node.
            extra_ports=[],
            auth_mode=u.openvpn_auth_mode, password=u.password,
            additional_remotes=all_remotes,
            profile_name=f"ALL-{_safe_download_name(u.username, 'user')}",
        )
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(500, str(exc)) from exc

    return Response(
        content=content,
        media_type="application/x-openvpn-profile",
        headers={"Content-Disposition": f'attachment; filename="ALL-{_safe_download_name(u.username, "user")}.ovpn"'},
    )


@router.get("/{token}/openvpn-config/{target_key}")
def download_sub_openvpn_config_for_target(target_key: str, token: str, db: Session = Depends(get_db)):
    """Download one server-pinned profile from the canonical shared PKI.

    The previous implementation proxied a freshly generated profile from each
    remote node.  That made the single-server downloads depend on that node's
    local certificate/tls-auth files, while the working combined profile used
    the controller's canonical fleet PKI.  A stale node could therefore produce
    a file that looked valid but failed TLS/HMAC negotiation.  Single profiles
    now use exactly the same CA, tls-auth key, client certificate and auth mode
    as the combined profile, with only the selected server's remote lines.
    """
    u = _get_user_by_token(db, token)
    _assert_subscription_active(u)
    if not u.enable_openvpn:
        raise HTTPException(400, "OpenVPN برای این کاربر غیرفعال است")

    available_nodes = openvpn_profile_nodes(db, u, require_shared_pki=False)
    compatible_nodes = openvpn_profile_nodes(db, u, require_shared_pki=True)
    target = _find_openvpn_target(compatible_nodes, target_key)
    if not target:
        if _find_openvpn_target(available_nodes, target_key):
            sync_all_nodes_async()
            raise HTTPException(503, "کلید مشترک OpenVPN این سرور هنوز همگام نشده است؛ چند ثانیه بعد دوباره دانلود کنید")
        raise HTTPException(404, "سرور OpenVPN انتخاب‌شده برای این کاربر فعال نیست")
    remotes = _openvpn_target_remotes(target)
    if not remotes:
        raise HTTPException(503, "هیچ لیسنر OpenVPN فعالی روی سرور انتخاب‌شده پیدا نشد")

    try:
        ensure_controller_openvpn_pki(db, allow_generate=False)
    except CertError as exc:
        raise HTTPException(503, f"کلید مشترک OpenVPN روی سرور اصلی آماده نیست: {exc}") from exc

    endpoint, _settings = target
    filename_node = _safe_download_name(endpoint.get("name"), _openvpn_target_key(endpoint))
    server_address, first_port, first_proto = remotes[0]
    udp_port = first_port if first_proto == "udp" else next(
        (port for host, port, proto in remotes if host == server_address and proto == "udp"),
        first_port,
    )
    tcp_port = first_port if first_proto == "tcp" else next(
        (port for host, port, proto in remotes if host == server_address and proto == "tcp"),
        first_port,
    )

    try:
        cert_pem, key_pem = _profile_credentials(u)
    except CertError as exc:
        raise HTTPException(500, f"ساخت سرتیفیکیت اختصاصی این کاربر ناموفق بود: {exc}") from exc

    try:
        content = build_client_ovpn(
            u.username,
            server_address,
            udp_port,
            tcp_port,
            cert_pem,
            key_pem,
            extra_ports=[],
            auth_mode=u.openvpn_auth_mode,
            password=u.password,
            additional_remotes=remotes,
            profile_name=f"{_safe_download_name(u.username)}-{filename_node}",
        )
    except (FileNotFoundError, ValueError) as exc:
        raise HTTPException(500, str(exc)) from exc

    return Response(
        content=content,
        media_type="application/x-openvpn-profile",
        headers={"Content-Disposition": f'attachment; filename="{_safe_download_name(u.username)}-{filename_node}.ovpn"'},
    )


@router.get("/{token}/qr/{protocol}")
def xray_profile_qr(token: str, protocol: str, db: Session = Depends(get_db)):
    """Return a self-contained SVG QR for one enabled Xray profile."""
    protocol = (protocol or "").strip().lower()
    if protocol not in {"vmess", "vless"}:
        raise HTTPException(404, "پروتکل QR نامعتبر است")
    u = _get_user_by_token(db, token)
    _assert_subscription_active(u)
    uri = next((item["uri"] for item in build_multi_xray_profiles(db, u) if item["protocol"] == protocol), None)
    if not uri:
        raise HTTPException(404, f"{protocol.upper()} برای این کاربر فعال نیست")
    return Response(
        content=_qr_svg_bytes(uri),
        media_type="image/svg+xml; charset=utf-8",
        headers={
            "Cache-Control": "private, max-age=60",
            "Content-Disposition": "inline",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.get("/{token}/xray-sub")
def xray_subscription(token: str, request: Request, db: Session = Depends(get_db)):
    """Return a strict, client-compatible Base64 VMess/VLESS subscription."""
    u = _get_user_by_token(db, token)
    _assert_subscription_active(u)
    profiles = [item["uri"] for item in build_multi_xray_profiles(db, u)]
    if not profiles:
        raise HTTPException(404, "هیچ کانفیگ VMess/VLESS فعالی برای این کاربر وجود ندارد")

    # Only real profiles belong in the payload. The previous synthetic VLESS
    # status item used an all-zero UUID and loopback port 1; strict clients could
    # reject the entire subscription because of that intentionally invalid item.
    # v2rayNG and several strict subscription parsers expect canonical
    # standard Base64 with no extra blank item. Keep the inner profile list
    # newline-separated, but do not append a trailing newline before encoding.
    payload = "\n".join(profiles).encode("utf-8")
    encoded = base64.b64encode(payload).decode("ascii")
    web_page = build_sub_link(db, token)
    return Response(
        content=encoded,
        media_type="text/plain; charset=utf-8",
        headers={
            "Profile-Title": "VPN Panel",
            "Profile-Web-Page-Url": web_page,
            "Subscription-Userinfo": _subscription_userinfo_header(u),
            "Profile-Update-Interval": "4",
            "Cache-Control": "no-store, max-age=0, must-revalidate",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": "inline; filename=subscription.txt",
        },
    )


@router.get("/{token}/xray-config")
def download_sub_xray_config(token: str, db: Session = Depends(get_db)):
    u = _get_user_by_token(db, token)
    _assert_subscription_active(u)
    links = [item["uri"] for item in build_multi_xray_profiles(db, u)]
    if not links:
        raise HTTPException(404, "هیچ کانفیگ VMess/VLESS فعالی برای این کاربر وجود ندارد")
    content = "\n".join(links) + "\n"
    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{u.username}-xray.txt"'},
    )


@router.get("/{token}/sstp-cert")
def download_sub_sstp_cert(
    token: str,
    db: Session = Depends(get_db),
    target_key: str | None = Query(None),
):
    """سرتیفیکیت TLS سرور SSTP را برای دانلود/نصب توسط کلاینت برمی‌گرداند.
    این سرتیفیکیت مشترک همه‌ی کاربران است (متعلق به خودِ سرور، نه هر کاربر
    جدا)، برخلاف OpenVPN که سرتیفیکیت اختصاصی هر کاربر را می‌سازد."""
    u = _get_user_by_token(db, token)
    _assert_subscription_active(u)
    if not u.enable_sstp:
        raise HTTPException(400, "SSTP برای این کاربر غیرفعال است")

    # Direct Python callers (including maintenance/tests from older releases)
    # receive FastAPI's Query object when they omit the optional parameter.
    # Treat that exactly like no target so the original route remains backward
    # compatible while HTTP requests still receive the parsed string.
    if not isinstance(target_key, str):
        target_key = None

    nodes = public_node_list(db, u)
    sstp_target = (
        _find_protocol_target(nodes, target_key, "sstp")
        if target_key else _enabled_protocol_target(nodes, "sstp")
    )
    if target_key and not sstp_target:
        raise HTTPException(404, "SSTP روی سرور انتخاب‌شده فعال یا در دسترس نیست")
    remote_response = _remote_asset_response(db, u, sstp_target, "sstp-cert")
    if remote_response is not None:
        return Response(
            content=remote_response.content,
            media_type="application/x-x509-ca-cert",
            headers={"Content-Disposition": 'attachment; filename="sstp-cert.cer"'},
        )

    cert_pem = read_sstp_cert()
    if not cert_pem:
        raise HTTPException(
            404,
            "سرتیفیکیت SSTP روی سرور پیدا نشد (زیرساخت SSTP نصب نشده یا مسیر گواهی تنظیم نشده)",
        )

    return Response(
        content=cert_pem,
        media_type="application/x-x509-ca-cert",
        headers={"Content-Disposition": 'attachment; filename="sstp-cert.cer"'},
    )
