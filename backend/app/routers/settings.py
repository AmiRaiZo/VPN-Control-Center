import json
import os
import grp
import re
import subprocess
import threading
import time
import shlex
import requests
from pathlib import Path
from urllib.parse import urlparse, urlunparse
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field, field_validator

from app.database import get_db, SessionLocal
from app.config import get_settings
from app.models import Setting, Admin, OpenvpnExtraPort
from app.security import require_permission, get_current_admin, require_superadmin, ensure_protocol_permission, ensure_permission
from app.services.ssl_manager import (
    apply_domain_ssl, apply_sub_domain_ssl, apply_sub_domain_port,
    apply_xray_sub_domain_ssl, apply_xray_sub_domain_port, disable_xray_sub_domain,
    apply_vpn_domain_ssl, apply_ikev2_ssl,
)
from app.services.vpn_manager import (
    apply_vpn_protocol_settings, apply_openconnect_settings, get_ipsec_psk, set_ipsec_psk,
    sync_openvpn_extra_ports, get_protocol_statuses, control_protocol_service,
    ALLOWED_PROTOCOL_KEYS, ALLOWED_ACTIONS, reconcile_openvpn_extra_ports, sync_internet_blocks,
)
from app.routers.meta import (
    DEFAULT_PANEL_TITLE, DEFAULT_SUB_TITLE,
    DEFAULT_PLATFORM_APPS, get_platform_apps,
)
from app.schemas import (
    PanelPortRequest, VpnProtocolSettings, IpsecPskRequest,
    OpenvpnExtraPortCreate, OpenvpnExtraPortOut, XrayProtocolSettings, NodeLocalSshSettingsRequest,
)
from app.proc_utils import BASH
from app.services.telegram_notifier import log_event
from app.services.node_manager import effective_server_role, get_or_create_agent_token
from app.services.node_remote import encrypt_password, decrypt_password
from app.services.protocol_admin import (
    get_protocol_center, control_protocol, protocol_logs, clear_protocol_logs, get_protocol_config,
    save_protocol_config, start_install_job, get_install_job, infrastructure_status,
)
from app.services.xray_manager import (
    get_protocol_settings as get_xray_settings,
    save_protocol_settings as save_xray_settings,
    sync_xray_users,
)
from app.services.branding import get_branding, save_asset, delete_asset, set_setting as set_branding_setting
from app.services.protocol_options import apply_protocol_options
from app.services.protocol_dns import apply_protocol_dns_settings
from app.services import system_time


router = APIRouter(prefix="/api/settings", tags=["settings"])

DOMAIN_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$")


# Keep every supported backend visible.  IPsec shares strongSwan with L2TP and
# IKEv2, but it remains a useful standalone provisioning/health card and avoids
# leaving an unexplained empty slot in the protocol grid.
_HIDDEN_PROTOCOL_CARDS: set[str] = set()
_PROTOCOL_CENTER_CACHE_LOCK = threading.Lock()
_PROTOCOL_CENTER_CACHE: dict | None = None
_PROTOCOL_CENTER_REFRESHING = False
_PROTOCOL_CENTER_TTL_SECONDS = 30.0

def _filter_protocol_rows_for_admin(rows: list[dict], admin: Admin) -> list[dict]:
    visible: list[dict] = []
    for row in rows:
        if row.get("key") in _HIDDEN_PROTOCOL_CARDS:
            continue
        try:
            ensure_protocol_permission(admin, row["key"], "view")
            visible.append(row)
        except HTTPException:
            continue
    return visible

def _protocol_placeholder(db: Session) -> dict:
    # Returned only before the first real health snapshot is ready. It is cheap
    # enough to build synchronously and lets the frontend render every card now.
    labels = {
        "l2tp": ("L2TP", "xl2tpd + pppd", "UDP " + (_get_setting(db, "l2tp_port") or "1701")),
        "ipsec": ("IPsec", "strongSwan (charon)", "UDP 500 / 4500"),
        "pptp": ("PPTP", "pptpd + pppd", "TCP 1723 + GRE"),
        "openvpn": ("OpenVPN", "OpenVPN", f"UDP {_get_setting(db, 'openvpn_udp_port') or '1194'} / TCP {_get_setting(db, 'openvpn_tcp_port') or '1194'}"),
        "openconnect": ("OpenConnect (Cisco)", "ocserv", "TCP+UDP " + (_get_setting(db, "openconnect_port") or "8443")),
        "sstp": ("SSTP", "accel-ppp", "TCP " + (_get_setting(db, "sstp_port") or "4433")),
        "ikev2": ("IKEv2", "strongSwan (charon)", "UDP 500 / 4500"),
        "vmess": ("VMess", "Xray-core", "TCP " + (_get_setting(db, "vmess_port") or "10000")),
        "vless": ("VLESS", "Xray-core", "TCP " + (_get_setting(db, "vless_port") or "10001")),
    }
    rows = []
    for key, (label, backend, listen) in labels.items():
        rows.append({
            "key": key, "label": label, "backend": backend, "units": [], "unit": "",
            "state": "checking", "unit_states": {}, "installed": False, "version": "…",
            "inbounds": 0, "listen": listen, "refreshing": True, "last_error": "",
            "restart_count": 0, "port_notice": None, "config_files": [],
            "health": {"state": "checking", "process": False, "ports": {}, "ports_ok": False,
                       "config": False, "permissions": True, "restart_count": 0,
                       "exit_status": 0, "managed": False, "last_error": ""},
        })
    return {
        "protocols": rows,
        "infrastructure": {"ip_forwarding": False, "firewall": "checking", "nftables": False, "iproute2": False, "modules": {}},
        "panel": {"port": int(_get_setting(db, "panel_port") or 80), "domain": _get_setting(db, "domain"), "domain_active": _get_setting(db, "domain_ssl_status") == "active"},
        "refreshing": True, "generated_at": 0.0,
    }

def _protocol_center_payload(db: Session) -> dict:
    """Build a real protocol-center snapshot from the current host.

    The fast endpoint normally serves a short-lived cache.  Remote node views
    need one authoritative snapshot on first selection; otherwise the cache
    placeholder (all services missing) can be mistaken for the real node state.
    """
    return {
        "protocols": get_protocol_center(db),
        "infrastructure": infrastructure_status(),
        "panel": {
            "port": int(_get_setting(db, "panel_port") or 80),
            "domain": _get_setting(db, "domain"),
            "domain_active": _get_setting(db, "domain_ssl_status") == "active",
        },
        "refreshing": False,
        "generated_at": time.time(),
    }


def _store_protocol_center_cache(payload: dict) -> None:
    global _PROTOCOL_CENTER_CACHE
    with _PROTOCOL_CENTER_CACHE_LOCK:
        _PROTOCOL_CENTER_CACHE = payload


def _build_protocol_center_snapshot() -> None:
    global _PROTOCOL_CENTER_REFRESHING
    db = SessionLocal()
    try:
        _store_protocol_center_cache(_protocol_center_payload(db))
    finally:
        db.close()
        with _PROTOCOL_CENTER_CACHE_LOCK:
            _PROTOCOL_CENTER_REFRESHING = False

def _refresh_protocol_center_async() -> None:
    global _PROTOCOL_CENTER_REFRESHING
    with _PROTOCOL_CENTER_CACHE_LOCK:
        if _PROTOCOL_CENTER_REFRESHING:
            return
        _PROTOCOL_CENTER_REFRESHING = True
    threading.Thread(target=_build_protocol_center_snapshot, daemon=True, name="protocol-center-refresh").start()

def _fast_protocol_center(db: Session) -> dict:
    # Stale-while-revalidate: once a real snapshot exists, always return it
    # immediately.  Older releases changed ``refreshing`` to true whenever
    # the two-second cache expired; the frontend interpreted that flag as a
    # reason to replace every protocol card with skeletons, so the whole page
    # appeared to disappear and reload every few seconds.
    with _PROTOCOL_CENTER_CACHE_LOCK:
        cached = dict(_PROTOCOL_CENTER_CACHE) if _PROTOCOL_CENTER_CACHE else None
        refresh_running = bool(_PROTOCOL_CENTER_REFRESHING)
    if cached:
        age = time.time() - float(cached.get("generated_at") or 0)
        stale = age > _PROTOCOL_CENTER_TTL_SECONDS
        if stale and not refresh_running:
            _refresh_protocol_center_async()
            refresh_running = True
        cached["refreshing"] = False
        cached["background_refreshing"] = bool(stale or refresh_running)
        cached["cache_age_seconds"] = max(0.0, age)
        return cached
    _refresh_protocol_center_async()
    placeholder = _protocol_placeholder(db)
    placeholder["background_refreshing"] = True
    return placeholder


def warm_protocol_center_cache() -> None:
    """Start cache generation during API startup without blocking startup."""
    _refresh_protocol_center_async()



class BrandingSettingsRequest(BaseModel):
    hero_enabled: bool = True
    brand_name: str = Field("", max_length=80)
    hero_badge: str = Field("", max_length=100)
    hero_title: str = Field("", max_length=180)
    hero_subtitle: str = Field("", max_length=500)
    hero_footer: str = Field("", max_length=180)
    login_footer_note: str = Field("", max_length=180)

    @field_validator("brand_name", "hero_badge", "hero_title", "hero_subtitle", "hero_footer", "login_footer_note")
    @classmethod
    def clean_text(cls, value: str) -> str:
        return (value or "").strip()


class LoginFooterNoteRequest(BaseModel):
    text: str = Field("", max_length=180)

    @field_validator("text")
    @classmethod
    def clean_login_footer(cls, value: str) -> str:
        return (value or "").strip()


class PortFallbackSettingsRequest(BaseModel):
    enabled: bool = True
    minimum: int = Field(20000, ge=1024, le=65535)
    maximum: int = Field(55000, ge=1024, le=65535)

    @field_validator("maximum")
    @classmethod
    def valid_maximum(cls, value: int, info):
        minimum = info.data.get("minimum", 20000)
        if value < minimum:
            raise ValueError("حداکثر بازه باید از حداقل بزرگ‌تر یا مساوی باشد")
        return value


class ProtocolConfigSaveRequest(BaseModel):
    file_id: str = Field(..., min_length=1, max_length=64)
    content: str = Field(..., max_length=1024 * 1024)
    restart: bool = True


class ProtocolInstallRequest(BaseModel):
    force: bool = True
    # A deliberate Install/Repair click should leave the selected protocol usable,
    # not merely install its binary and silently preserve a stale disabled flag.
    enable_after_install: bool = True


class OpenConnect443Request(BaseModel):
    panel_port: int = Field(8444, ge=1, le=65535)
    dns1: str = Field("8.8.8.8", max_length=64)
    dns2: str = Field("1.1.1.1", max_length=64)

    @field_validator("dns1", "dns2")
    @classmethod
    def validate_dns(cls, value: str) -> str:
        value = value.strip()
        if value and not re.match(r"^[0-9a-fA-F:.]+$", value):
            raise ValueError("آدرس DNS معتبر نیست")
        return value

class DomainRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip().lower()
        if not DOMAIN_RE.match(v):
            raise ValueError("دامنه معتبر نیست، مثال صحیح: panel.example.com")
        return v


class VpnDomainRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip().lower()
        if not DOMAIN_RE.match(v):
            raise ValueError("دامنه معتبر نیست، مثال صحیح: vpn.yourdomain.com")
        return v


class SubDomainRequest(BaseModel):
    domain: str
    port: int = Field(443, ge=1, le=65535)

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip().lower()
        if not DOMAIN_RE.match(v):
            raise ValueError("دامنه معتبر نیست، مثال صحیح: sub.yourdomain.com")
        return v


class XrayConnectionHostsRequest(BaseModel):
    vmess_host: str = Field("", max_length=253)
    vless_host: str = Field("", max_length=253)

    @field_validator("vmess_host", "vless_host")
    @classmethod
    def validate_host(cls, value: str) -> str:
        value = (value or "").strip().lower()
        if not value:
            return ""
        if "://" in value or "/" in value or "?" in value or "#" in value:
            raise ValueError("فقط دامنه یا IP را بدون http/https، مسیر و پورت وارد کنید")
        try:
            import ipaddress
            ipaddress.ip_address(value)
            return value
        except ValueError:
            pass
        if not DOMAIN_RE.match(value):
            raise ValueError("دامنه یا IP معتبر نیست")
        return value


class SubDomainPortRequest(BaseModel):
    port: int = Field(..., ge=1, le=65535)


class Ikev2DomainRequest(BaseModel):
    domain: str

    @field_validator("domain")
    @classmethod
    def validate_domain(cls, v: str) -> str:
        v = v.strip().lower()
        if not DOMAIN_RE.match(v):
            raise ValueError("دامنه معتبر نیست، مثال صحیح: ikev2.yourdomain.com")
        return v


def _get_setting(db: Session, key: str):
    row = db.query(Setting).filter(Setting.key == key).first()
    return row.value if row else None


def _setting_or_default(
    db: Session, key: str, default: str, *, preserve_blank: bool = False
) -> str:
    value = _get_setting(db, key)
    if value is None:
        return default
    if not preserve_blank and value == "":
        return default
    return value


def _set_setting(db: Session, key: str, value: str):
    row = db.query(Setting).filter(Setting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(Setting(key=key, value=value))


class SystemTimeSettingsRequest(BaseModel):
    mode: str = Field(..., pattern=r"^(auto|manual)$")
    country_code: str = Field("", max_length=2)
    timezone: str = Field(..., min_length=1, max_length=128)
    manual_datetime: str | None = Field(default=None, max_length=64)

    @field_validator("country_code")
    @classmethod
    def clean_country_code(cls, value: str) -> str:
        cleaned = str(value or "").strip().upper()
        if cleaned and (len(cleaned) != 2 or not cleaned.isalpha()):
            raise ValueError("کد کشور معتبر نیست")
        return cleaned


def _system_time_payload(db: Session) -> dict:
    countries = system_time.country_timezones()
    current = system_time.status()
    mode = (_get_setting(db, "system_time_mode") or "auto").strip().lower()
    if mode not in {"auto", "manual"}:
        mode = "auto"
    country_code = (_get_setting(db, "system_time_country_code") or "").strip().upper()
    configured_timezone = (_get_setting(db, "system_timezone") or current["timezone"]).strip()
    return {
        **current,
        "mode": mode,
        "country_code": country_code,
        "configured_timezone": configured_timezone,
        "countries": [{"code": code, "timezones": zones} for code, zones in countries.items()],
        "timezones": system_time.timezone_names(),
    }


@router.get("/system-time")
def get_system_time_settings(
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("settings")),
):
    return _system_time_payload(db)


@router.post("/system-time")
def set_system_time_settings(
    payload: SystemTimeSettingsRequest,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_superadmin),
):
    countries = system_time.country_timezones()
    selected_timezone = str(payload.timezone or "").strip()
    if payload.mode == "auto":
        if not payload.country_code or payload.country_code not in countries:
            raise HTTPException(400, "برای حالت خودکار یک کشور معتبر انتخاب کنید")
        allowed = countries[payload.country_code]
        if selected_timezone not in allowed:
            raise HTTPException(400, "منطقه زمانی انتخاب‌شده با کشور هم‌خوان نیست")
    try:
        result = system_time.apply(
            mode=payload.mode,
            timezone_name=selected_timezone,
            manual_datetime=payload.manual_datetime,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except Exception as exc:
        raise HTTPException(500, f"اعمال ساعت سرور ناموفق بود: {exc}") from exc

    _set_setting(db, "system_time_mode", payload.mode)
    _set_setting(db, "system_time_country_code", payload.country_code if payload.mode == "auto" else "")
    _set_setting(db, "system_timezone", selected_timezone)
    db.commit()
    log_event(
        "ساعت و منطقه زمانی سرور تغییر کرد",
        f"حالت: {payload.mode} | منطقه زمانی: {selected_timezone}",
        actor=admin.username,
    )
    return {**_system_time_payload(db), **result}


# ---------------------------------------------------------------------------
# سه سرویس مختلف روی این سرور می‌توانند مستقیماً روی TCP بایند بشوند و پورت
# هرکدام هم از پنل قابل تغییر است: خودِ پنل (nginx)، دامنه‌ی ساب/لینک
# اشتراک (nginx - ووهاست جدا)، و OpenConnect (ocserv). قبل از اعمال هرکدام،
# پورت انتخابی را با آن دو تای دیگر مقایسه می‌کنیم تا به‌جای شکست خوردن
# سرویس بعد از اجرای اسکریپت (که تشخیصش برای ادمین سخت‌تر است)، همین‌جا با
# یک پیام روشن رد شود.
# ---------------------------------------------------------------------------
def _bool_setting(db: Session, key: str, default: bool) -> bool:
    value = _get_setting(db, key)
    return value == "1" if value is not None else default


def _int_setting(db: Session, key: str, default: int) -> int:
    value = _get_setting(db, key)
    try:
        return int(value) if value is not None else default
    except (TypeError, ValueError):
        return default


def _configured_listeners(db: Session) -> list[tuple[str, str, str, int]]:
    """Configured listeners that can actually collide at bind time.

    Tuple fields are (key, label, transport, port).  TCP and UDP are tracked
    separately, so OpenVPN TCP/1194 and UDP/1194 are correctly allowed.
    """
    rows: list[tuple[str, str, str, int]] = []
    rows.append(("panel", "پنل مدیریتی", "tcp", _int_setting(db, "panel_port", 80)))
    if _get_setting(db, "sub_domain"):
        rows.append(("sub_domain", "دامنه‌ی صفحه اشتراک", "tcp", _int_setting(db, "sub_domain_port", 443)))
    if _get_setting(db, "xray_sub_domain"):
        rows.append(("xray_sub_domain", "دامنه‌ی سابسکریپشن VMess/VLESS", "tcp", _int_setting(db, "xray_sub_domain_port", 443)))

    # OpenConnect has no separate enabled flag; its service card controls
    # start/stop, while the configured TCP+UDP listener remains reserved.
    oc_port = _int_setting(db, "openconnect_port", 8443)
    rows.extend([
        ("openconnect", "OpenConnect", "tcp", oc_port),
        ("openconnect", "OpenConnect", "udp", oc_port),
    ])
    if _bool_setting(db, "sstp_enabled", True):
        rows.append(("sstp", "SSTP", "tcp", _int_setting(db, "sstp_port", 4433)))
    if _bool_setting(db, "openvpn_enabled", True):
        rows.extend([
            ("openvpn", "OpenVPN TCP", "tcp", _int_setting(db, "openvpn_tcp_port", 1194)),
            ("openvpn", "OpenVPN UDP", "udp", _int_setting(db, "openvpn_udp_port", 1194)),
        ])
    l2tp_enabled = _bool_setting(db, "l2tp_enabled", True)
    ikev2_enabled = _bool_setting(db, "ikev2_enabled", True)
    if l2tp_enabled or ikev2_enabled:
        rows.extend([
            ("strongswan", "IPsec/IKE", "udp", 500),
            ("strongswan", "IPsec NAT-T", "udp", 4500),
        ])
    if l2tp_enabled:
        rows.append(("l2tp", "L2TP", "udp", _int_setting(db, "l2tp_port", 1701)))
    if _bool_setting(db, "pptp_enabled", True):
        rows.append(("pptp", "PPTP", "tcp", 1723))
    if _bool_setting(db, "vmess_enabled", False):
        rows.append(("vmess", "VMess", "tcp", _int_setting(db, "vmess_port", 10000)))
    if _bool_setting(db, "vless_enabled", False):
        rows.append(("vless", "VLESS", "tcp", _int_setting(db, "vless_port", 10001)))

    for item in db.query(OpenvpnExtraPort).filter(OpenvpnExtraPort.is_active == True).all():  # noqa: E712
        if item.protocol in {"tcp", "both"}:
            rows.append(("openvpn_extra", f"پورت اضافه OpenVPN TCP ({item.port})", "tcp", item.port))
        if item.protocol in {"udp", "both"}:
            rows.append(("openvpn_extra", f"پورت اضافه OpenVPN UDP ({item.port})", "udp", item.port))
    return rows


def _check_listener_conflict(
    db: Session,
    port: int,
    transport: str,
    exclude: set[str] | None = None,
) -> None:
    excluded = exclude or set()
    for key, label, proto, used_port in _configured_listeners(db):
        if key in excluded or proto != transport:
            continue
        if int(port) == int(used_port):
            raise HTTPException(
                status_code=400,
                detail=f"پورت {port}/{transport.upper()} همین الان برای {label} تنظیم شده است.",
            )




def _check_protocol_payload_conflicts(db: Session, payload: VpnProtocolSettings) -> None:
    """Validate the complete legacy/all-protocol form as one future state.

    Per-card saves use `_check_listener_conflict`, but this endpoint receives all
    main protocol values at once.  Comparing each value with the *old* database
    state would reject valid port swaps and miss conflicts among two new values,
    so build and validate the resulting listener set atomically.
    """
    changing = {"l2tp", "pptp", "openvpn", "sstp", "strongswan", "openconnect"}
    listeners = [row for row in _configured_listeners(db) if row[0] not in changing]
    candidates: list[tuple[str, str, str, int]] = []

    if payload.l2tp_enabled or payload.ikev2_enabled:
        candidates.extend([
            ("strongswan", "IPsec/IKE", "udp", 500),
            ("strongswan", "IPsec NAT-T", "udp", 4500),
        ])
    if payload.l2tp_enabled:
        candidates.append(("l2tp", "L2TP", "udp", payload.l2tp_port))
    if payload.pptp_enabled:
        candidates.append(("pptp", "PPTP", "tcp", 1723))
    if payload.openvpn_enabled:
        candidates.extend([
            ("openvpn", "OpenVPN UDP", "udp", payload.openvpn_udp_port),
            ("openvpn", "OpenVPN TCP", "tcp", payload.openvpn_tcp_port),
        ])
    if payload.sstp_enabled:
        candidates.append(("sstp", "SSTP", "tcp", payload.sstp_port))
    candidates.extend([
        ("openconnect", "OpenConnect", "tcp", payload.openconnect_port),
        ("openconnect", "OpenConnect", "udp", payload.openconnect_port),
    ])

    occupied: dict[tuple[str, int], str] = {}
    for _key, label, transport, port in [*listeners, *candidates]:
        bind = (transport, int(port))
        previous = occupied.get(bind)
        if previous:
            raise HTTPException(
                400,
                f"پورت {port}/{transport.upper()} هم‌زمان برای {previous} و {label} انتخاب شده است.",
            )
        occupied[bind] = label



@router.get("/domain")
def get_domain(db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    return {
        "domain": _get_setting(db, "domain"),
        "status": _get_setting(db, "domain_ssl_status") or "not_configured",
        "log": _get_setting(db, "domain_ssl_log"),
    }


@router.post("/domain")
def set_domain(payload: DomainRequest, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    # apply_domain_ssl creates an nginx listener on TCP/443.  Reject the
    # operation before certbot/nginx changes anything if 443 is reserved by
    # OpenConnect, SSTP, the subscription vhost, or another TCP listener.
    _check_listener_conflict(db, 443, "tcp", {"panel"})
    _set_setting(db, "domain_ssl_status", "in_progress")
    db.commit()

    ok, log = apply_domain_ssl(payload.domain)

    _set_setting(db, "domain", payload.domain)
    _set_setting(db, "domain_ssl_status", "active" if ok else "failed")
    _set_setting(db, "domain_ssl_log", log)
    if ok:
        _set_setting(db, "panel_port", "443")
    db.commit()

    if not ok:
        raise HTTPException(
            status_code=500,
            detail=f"دریافت SSL ناموفق بود. مطمئن شوید رکورد A دامنه به آی‌پی سرور اشاره می‌کند. جزئیات: {log[-500:]}",
        )

    role = effective_server_role(db)
    node_url = f"https://{payload.domain}"
    if role == "node":
        _set_setting(db, "node_public_url", node_url)
        db.commit()
        try:
            _persist_node_registration_url(node_url)
            _reregister_node_async()
        except Exception as exc:
            log_event("⚠️ ثبت دوباره نود بعد از SSL ناموفق بود", str(exc), actor=admin.username)

    log_event("🌐 تنظیم دامنه‌ی پنل", f"دامنه: {payload.domain}", actor=admin.username)
    return {
        "ok": True,
        "domain": payload.domain,
        "url": node_url,
        "node_reregistering": role == "node",
    }


# ---------- دامنه‌ی اختصاصی «لینک اشتراک» (Subscription) ----------
# دامنه‌ای که فقط صفحه‌ی عمومی /sub/<token> روی آن نمایش داده می‌شود؛ عمداً از
# دامنه‌ی خودِ پنل (بالا) جدا نگه داشته شده تا لینکی که دست کاربر نهایی
# می‌دهید هیچ ارتباطی با آدرس ورود ادمین نداشته باشد. یک ووهاست Nginx کاملاً
# جدا (با گواهی SSL مستقل خودش) برایش ساخته می‌شود، بدون این‌که ووهاست دامنه‌ی
# پنل دست بخورد.
@router.get("/sub-domain")
def get_sub_domain(db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    return {
        "domain": _get_setting(db, "sub_domain"),
        "status": _get_setting(db, "sub_domain_status") or "not_configured",
        "log": _get_setting(db, "sub_domain_log"),
        "port": int(_get_setting(db, "sub_domain_port") or 443),
    }


@router.post("/sub-domain")
def set_sub_domain(payload: SubDomainRequest, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    panel_domain = _get_setting(db, "domain")
    if panel_domain and payload.domain == panel_domain:
        raise HTTPException(400, "دامنه‌ی ساب باید با دامنه‌ی خودِ پنل فرق داشته باشد")

    _check_listener_conflict(db, payload.port, "tcp", {"sub_domain"})

    _set_setting(db, "sub_domain_status", "in_progress")
    db.commit()

    ok, log = apply_sub_domain_ssl(payload.domain, payload.port)

    _set_setting(db, "sub_domain", payload.domain)
    _set_setting(db, "sub_domain_status", "active" if ok else "failed")
    _set_setting(db, "sub_domain_log", log)
    if ok:
        _set_setting(db, "sub_domain_port", str(payload.port))
    db.commit()

    if not ok:
        raise HTTPException(
            status_code=500,
            detail=f"دریافت SSL برای دامنه‌ی ساب ناموفق بود. جزئیات: {log[-500:]}",
        )

    log_event("🌐 تنظیم دامنه‌ی ساب", f"دامنه: {payload.domain}، پورت: {payload.port}", actor=admin.username)
    url = f"https://{payload.domain}:{payload.port}/sub/" if payload.port != 443 else f"https://{payload.domain}/sub/"
    return {"ok": True, "domain": payload.domain, "port": payload.port, "url": url}


@router.delete("/sub-domain")
def clear_sub_domain(db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    _set_setting(db, "sub_domain", None)
    _set_setting(db, "sub_domain_status", "not_configured")
    db.commit()
    log_event("🌐 حذف دامنه‌ی ساب", "", actor=admin.username)
    return {"ok": True}


@router.post("/sub-domain-port")
def set_sub_domain_port(payload: SubDomainPortRequest, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    domain = _get_setting(db, "sub_domain")
    domain_active = _get_setting(db, "sub_domain_status") == "active"
    if not domain or not domain_active:
        raise HTTPException(status_code=400, detail="ابتدا باید دامنه‌ی ساب را از همین صفحه فعال کنید.")

    _check_listener_conflict(db, payload.port, "tcp", {"sub_domain"})

    ok, log = apply_sub_domain_port(domain, payload.port)
    if not ok:
        raise HTTPException(status_code=500, detail=f"تغییر پورت ناموفق بود: {log[-500:]}")

    _set_setting(db, "sub_domain_port", str(payload.port))
    db.commit()

    log_event("🔧 تغییر پورت دامنه‌ی ساب", f"دامنه: {domain}، پورت جدید: {payload.port}", actor=admin.username)
    url = f"https://{domain}:{payload.port}/sub/" if payload.port != 443 else f"https://{domain}/sub/"
    return {"ok": True, "port": payload.port, "url": url}



# ---------- آدرس اتصال داخل کانفیگ‌های VMess/VLESS ----------
@router.get("/xray-connection-hosts")
def get_xray_connection_hosts(
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("settings")),
):
    return {
        "vmess_host": _get_setting(db, "vmess_server_address") or "",
        "vless_host": _get_setting(db, "vless_server_address") or "",
        "fallback": _get_setting(db, "vpn_domain") or get_settings().PUBLIC_SERVER_IP,
    }


@router.post("/xray-connection-hosts")
def set_xray_connection_hosts(
    payload: XrayConnectionHostsRequest,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("settings")),
):
    _set_setting(db, "vmess_server_address", payload.vmess_host)
    _set_setting(db, "vless_server_address", payload.vless_host)
    db.commit()
    log_event(
        "🌐 تغییر آدرس اتصال Xray",
        f"VMess: {payload.vmess_host or 'auto'} | VLESS: {payload.vless_host or 'auto'}",
        actor=admin.username,
    )
    return {
        "ok": True,
        "vmess_host": payload.vmess_host,
        "vless_host": payload.vless_host,
    }


# ---------- دامنه‌ی اختصاصی سابسکریپشن VMess/VLESS ----------
@router.get("/xray-sub-domain")
def get_xray_sub_domain(db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    return {
        "domain": _get_setting(db, "xray_sub_domain"),
        "status": _get_setting(db, "xray_sub_domain_status") or "not_configured",
        "log": _get_setting(db, "xray_sub_domain_log"),
        "port": int(_get_setting(db, "xray_sub_domain_port") or 443),
    }


@router.post("/xray-sub-domain")
def set_xray_sub_domain(payload: SubDomainRequest, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    panel_domain = _get_setting(db, "domain")
    page_sub_domain = _get_setting(db, "sub_domain")
    if panel_domain and payload.domain == panel_domain:
        raise HTTPException(400, "دامنه‌ی سابسکریپشن Xray باید با دامنه‌ی پنل فرق داشته باشد")
    if page_sub_domain and payload.domain == page_sub_domain:
        raise HTTPException(400, "دامنه‌ی سابسکریپشن Xray باید با دامنه‌ی صفحه اشتراک فرق داشته باشد")

    _check_listener_conflict(db, payload.port, "tcp", {"xray_sub_domain"})
    _set_setting(db, "xray_sub_domain_status", "in_progress")
    db.commit()

    ok, log = apply_xray_sub_domain_ssl(payload.domain, payload.port)
    _set_setting(db, "xray_sub_domain", payload.domain)
    _set_setting(db, "xray_sub_domain_status", "active" if ok else "failed")
    _set_setting(db, "xray_sub_domain_log", log)
    if ok:
        _set_setting(db, "xray_sub_domain_port", str(payload.port))
    db.commit()

    if not ok:
        raise HTTPException(
            status_code=500,
            detail=f"دریافت SSL برای دامنه‌ی سابسکریپشن Xray ناموفق بود. جزئیات: {log[-500:]}",
        )

    log_event("🌐 تنظیم دامنه‌ی سابسکریپشن Xray", f"دامنه: {payload.domain}، پورت: {payload.port}", actor=admin.username)
    port_part = "" if payload.port == 443 else f":{payload.port}"
    return {
        "ok": True,
        "domain": payload.domain,
        "port": payload.port,
        "url": f"https://{payload.domain}{port_part}/api/sub/USER_TOKEN/xray-sub",
    }


@router.delete("/xray-sub-domain")
def clear_xray_sub_domain(db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    ok, log = disable_xray_sub_domain()
    if not ok:
        raise HTTPException(status_code=500, detail=f"غیرفعال‌سازی دامنه ناموفق بود: {log[-500:]}")
    _set_setting(db, "xray_sub_domain", None)
    _set_setting(db, "xray_sub_domain_status", "not_configured")
    _set_setting(db, "xray_sub_domain_log", log)
    db.commit()
    log_event("🌐 حذف دامنه‌ی سابسکریپشن Xray", "", actor=admin.username)
    return {"ok": True}


@router.post("/xray-sub-domain-port")
def set_xray_sub_domain_port(payload: SubDomainPortRequest, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    domain = _get_setting(db, "xray_sub_domain")
    active = _get_setting(db, "xray_sub_domain_status") == "active"
    if not domain or not active:
        raise HTTPException(status_code=400, detail="ابتدا دامنه‌ی سابسکریپشن Xray را فعال کنید")

    _check_listener_conflict(db, payload.port, "tcp", {"xray_sub_domain"})
    ok, log = apply_xray_sub_domain_port(domain, payload.port)
    if not ok:
        raise HTTPException(status_code=500, detail=f"تغییر پورت ناموفق بود: {log[-500:]}")

    _set_setting(db, "xray_sub_domain_port", str(payload.port))
    _set_setting(db, "xray_sub_domain_log", log)
    db.commit()
    log_event("🔧 تغییر پورت دامنه‌ی سابسکریپشن Xray", f"دامنه: {domain}، پورت جدید: {payload.port}", actor=admin.username)
    port_part = "" if payload.port == 443 else f":{payload.port}"
    return {"ok": True, "port": payload.port, "url": f"https://{domain}{port_part}/api/sub/USER_TOKEN/xray-sub"}


@router.get("/branding")
def get_branding_settings(db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    return get_branding(db)


@router.post("/branding")
def set_branding_settings(
    payload: BrandingSettingsRequest,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("settings")),
):
    set_branding_setting(db, "branding_hero_enabled", "1" if payload.hero_enabled else "0")
    set_branding_setting(db, "branding_brand_name", payload.brand_name)
    set_branding_setting(db, "branding_hero_badge", payload.hero_badge)
    set_branding_setting(db, "branding_hero_title", payload.hero_title)
    set_branding_setting(db, "branding_hero_subtitle", payload.hero_subtitle)
    set_branding_setting(db, "branding_hero_footer", payload.hero_footer)
    set_branding_setting(db, "branding_login_footer_note", payload.login_footer_note)
    db.commit()
    log_event("🎨 تغییر ظاهر و برندینگ پنل", "متن و نمایش صفحه ورود بروزرسانی شد", actor=admin.username)
    return get_branding(db)


@router.get("/login-footer-note")
def get_login_footer_note(db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    return {"text": get_branding(db).get("login_footer_note") or ""}


@router.post("/login-footer-note")
def set_login_footer_note(
    payload: LoginFooterNoteRequest,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("settings")),
):
    set_branding_setting(db, "branding_login_footer_note", payload.text)
    db.commit()
    log_event("🎨 تغییر متن زیر فرم ورود", payload.text or "فقط آیکن سپر", actor=admin.username)
    return {"ok": True, "text": payload.text}


@router.post("/branding/upload/{kind}")
async def upload_branding_asset(
    kind: str,
    image: UploadFile = File(...),
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("settings")),
):
    if kind not in {"logo", "hero"}:
        raise HTTPException(404, "نوع تصویر نامعتبر است")
    content = await image.read(10 * 1024 * 1024 + 1)
    try:
        save_asset(kind, content, image.content_type)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    log_event("🖼️ آپلود تصویر برندینگ", f"نوع تصویر: {kind}", actor=admin.username)
    return get_branding(db)


@router.delete("/branding/asset/{kind}")
def remove_branding_asset(
    kind: str,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("settings")),
):
    if kind not in {"logo", "hero"}:
        raise HTTPException(404, "نوع تصویر نامعتبر است")
    delete_asset(kind)
    log_event("🗑️ حذف تصویر برندینگ", f"نوع تصویر: {kind}", actor=admin.username)
    return get_branding(db)


@router.get("/port-fallback")
def get_port_fallback(db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    return {
        "enabled": _bool_setting(db, "auto_port_fallback_enabled", True),
        "minimum": _int_setting(db, "auto_port_fallback_min", 20000),
        "maximum": _int_setting(db, "auto_port_fallback_max", 55000),
        "fixed_protocols": ["PPTP TCP/1723 + GRE", "IPsec/IKEv2 UDP/500 + UDP/4500"],
    }


@router.post("/port-fallback")
def set_port_fallback(
    payload: PortFallbackSettingsRequest,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("settings")),
):
    _set_setting(db, "auto_port_fallback_enabled", "1" if payload.enabled else "0")
    _set_setting(db, "auto_port_fallback_min", str(payload.minimum))
    _set_setting(db, "auto_port_fallback_max", str(payload.maximum))
    db.commit()
    log_event("🔀 تغییر تنظیمات پورت جایگزین", f"فعال: {payload.enabled} | بازه: {payload.minimum}-{payload.maximum}", actor=admin.username)
    return {"ok": True, **payload.model_dump()}


class SiteTitlesRequest(BaseModel):
    panel_title: str
    sub_title: str

    @field_validator("panel_title", "sub_title")
    @classmethod
    def _not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("عنوان نمی‌تواند خالی باشد")
        if len(v) > 100:
            raise ValueError("عنوان بیش از حد طولانی است (حداکثر ۱۰۰ کاراکتر)")
        return v


# ---------- عنوان تب مرورگر پنل و صفحه‌ی عمومی «ساب» ----------
# این دو مستقل از هم هستند: panel_title روی صفحه‌ی ورود و کل پنل مدیریت
# نشان داده می‌شود، sub_title فقط روی صفحه‌ی عمومی /sub/<token> (که کاربر
# نهایی می‌بیند، نه ادمین). مقدار فعلی (یا پیش‌فرض هاردکدشده‌ی قبلی، اگر هنوز
# چیزی ذخیره نشده) همیشه در GET برگردانده می‌شود تا فرم تنظیمات از قبل پر باشد.
@router.get("/site-titles")
def get_site_titles(db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    return {
        "panel_title": _get_setting(db, "panel_site_title") or DEFAULT_PANEL_TITLE,
        "sub_title": _get_setting(db, "sub_site_title") or DEFAULT_SUB_TITLE,
    }


@router.post("/site-titles")
def set_site_titles(
    payload: SiteTitlesRequest, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))
):
    _set_setting(db, "panel_site_title", payload.panel_title)
    _set_setting(db, "sub_site_title", payload.sub_title)
    db.commit()
    log_event("✏️ تغییر عنوان‌های سایت", f"عنوان پنل: {payload.panel_title} | عنوان ساب: {payload.sub_title}", actor=admin.username)
    return {"ok": True, "panel_title": payload.panel_title, "sub_title": payload.sub_title}


# ---------- لینک دانلود سفارشی روی صفحه‌ی عمومی ساب ----------
# دکمه‌ای اضافه، جدا از دانلود مستقیم کانفیگ OpenVPN/سرتیفیکیت SSTP: ادمین هم
# متن نمایش‌داده‌شده و هم آدرس مقصد را خودش تعیین می‌کند (مثلاً لینک اپلیکیشن
# اختصاصی خودش، یا صفحه‌ی آموزش اتصال). اگر هرکدام از دو فیلد خالی باشد،
# دکمه اصلاً روی صفحه‌ی ساب نمایش داده نمی‌شود (سمت روتر sub.py و SubPage.jsx).
SUB_DOWNLOAD_URL_RE = re.compile(r"^https?://.+", re.IGNORECASE)


class SubDownloadLinkRequest(BaseModel):
    label: str = ""
    url: str = ""

    @field_validator("label")
    @classmethod
    def _label_len(cls, v: str) -> str:
        v = (v or "").strip()
        if len(v) > 60:
            raise ValueError("متن دکمه بیش از حد طولانی است (حداکثر ۶۰ کاراکتر)")
        return v

    @field_validator("url")
    @classmethod
    def _url_valid(cls, v: str) -> str:
        v = (v or "").strip()
        if v and not SUB_DOWNLOAD_URL_RE.match(v):
            raise ValueError("لینک معتبر نیست؛ باید با http:// یا https:// شروع شود")
        return v


@router.get("/sub-download")
def get_sub_download_link(db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    return {
        "label": _get_setting(db, "sub_download_label") or "",
        "url": _get_setting(db, "sub_download_url") or "",
    }


@router.post("/sub-download")
def set_sub_download_link(
    payload: SubDownloadLinkRequest, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))
):
    _set_setting(db, "sub_download_label", payload.label or None)
    _set_setting(db, "sub_download_url", payload.url or None)
    db.commit()
    log_event("✏️ تغییر لینک دانلود صفحه‌ی ساب", f"متن: {payload.label or '—'} | لینک: {payload.url or '—'}", actor=admin.username)
    return {"ok": True, "label": payload.label, "url": payload.url}


# ---------- «برنامه‌های پیشنهادی برای اتصال» روی صفحه‌ی عمومی ساب ----------
# چهار گروه پلتفرم (اندروید/ویندوز/iOS/مک) با متن دکمه و لیست برنامه‌های هرکدام
# قابل ویرایش توسط ادمین است. کلیدهای گروه (android/windows/ios/mac) ثابت‌اند
# چون آیکون هرکدام در SubPage.jsx بر همان اساس تعیین می‌شود؛ فقط متن‌ها
# (عنوان پلتفرم و نام/توضیح هر برنامه) قابل تغییرند. اگر ادمین چیزی ذخیره
# نکرده باشد، مقدار پیش‌فرض (DEFAULT_PLATFORM_APPS) برگردانده می‌شود.
class PlatformAppItem(BaseModel):
    name: str
    desc: str = ""
    url: str = ""

    @field_validator("name")
    @classmethod
    def _name_valid(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("نام برنامه نمی‌تواند خالی باشد")
        if len(v) > 60:
            raise ValueError("نام برنامه بیش از حد طولانی است (حداکثر ۶۰ کاراکتر)")
        return v

    @field_validator("desc")
    @classmethod
    def _desc_valid(cls, v: str) -> str:
        v = (v or "").strip()
        if len(v) > 200:
            raise ValueError("توضیح برنامه بیش از حد طولانی است (حداکثر ۲۰۰ کاراکتر)")
        return v

    # لینک دانلود/باز کردن این برنامه‌ی خاص روی صفحه‌ی عمومی ساب - اختیاری؛
    # اگر خالی بماند، روی SubPage.jsx فقط یک ردیف متنی (بدون کلیک) نمایش داده
    # می‌شود، دقیقاً مثل حالت قبل. با همان الگوی SUB_DOWNLOAD_URL_RE بالا.
    @field_validator("url")
    @classmethod
    def _url_valid(cls, v: str) -> str:
        v = (v or "").strip()
        if v and not SUB_DOWNLOAD_URL_RE.match(v):
            raise ValueError("لینک معتبر نیست؛ باید با http:// یا https:// شروع شود")
        return v


class PlatformGroup(BaseModel):
    label: str
    apps: list[PlatformAppItem]

    @field_validator("label")
    @classmethod
    def _label_valid(cls, v: str) -> str:
        v = (v or "").strip()
        if not v:
            raise ValueError("عنوان پلتفرم نمی‌تواند خالی باشد")
        if len(v) > 40:
            raise ValueError("عنوان پلتفرم بیش از حد طولانی است (حداکثر ۴۰ کاراکتر)")
        return v

    @field_validator("apps")
    @classmethod
    def _apps_valid(cls, v: list):
        if not v:
            raise ValueError("هر پلتفرم باید حداقل یک برنامه داشته باشد")
        if len(v) > 8:
            raise ValueError("حداکثر ۸ برنامه برای هر پلتفرم مجاز است")
        return v


class PlatformAppsRequest(BaseModel):
    android: PlatformGroup
    windows: PlatformGroup
    ios: PlatformGroup
    mac: PlatformGroup


@router.get("/platform-apps")
def get_platform_apps_route(db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    return get_platform_apps(db)


@router.post("/platform-apps")
def set_platform_apps(
    payload: PlatformAppsRequest, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))
):
    data = payload.model_dump()
    _set_setting(db, "platform_apps_json", json.dumps(data, ensure_ascii=False))
    db.commit()
    log_event("✏️ تغییر برنامه‌های پیشنهادی صفحه‌ی ساب", "", actor=admin.username)
    return data


@router.delete("/platform-apps")
def reset_platform_apps(db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    _set_setting(db, "platform_apps_json", None)
    db.commit()
    log_event("♻️ بازگردانی برنامه‌های پیشنهادی صفحه‌ی ساب به پیش‌فرض", "", actor=admin.username)
    return DEFAULT_PLATFORM_APPS


# ---------- L2TP/IPsec shared PSK ----------
# این مقدار (Pre-Shared Key) طبق استاندارد پروتکل IPsec بین همه‌ی کاربران L2TP
# مشترک است و امکان تعیین جداگانه به‌ازای هر کاربر وجود ندارد - برای همین
# اینجا (سطح پنل) تنظیم می‌شود، نه در فرم ساخت/ویرایش کاربر.
@router.get("/ipsec-psk")
def get_ipsec_psk_route(admin: Admin = Depends(get_current_admin)):
    _ensure_any_protocol(admin, ("l2tp", "ipsec"), "edit")
    return {"psk": get_ipsec_psk()}


@router.post("/ipsec-psk")
def set_ipsec_psk_route(
    payload: IpsecPskRequest,
    db: Session = Depends(get_db),
    admin: Admin = Depends(get_current_admin),
):
    _ensure_any_protocol(admin, ("l2tp", "ipsec"), "edit")
    set_ipsec_psk(payload.psk)
    # A node can be edited from the controller through protocol-proxy. Mark
    # that deliberate node-local PSK as authoritative; otherwise the periodic
    # full node sync would push the controller's old PSK back a few seconds
    # later and make the field appear not to save.
    if effective_server_role(db) == "node":
        _set_setting(db, "ipsec_psk_local_override", "1")
        db.commit()
    log_event("🔑 تغییر PSK مشترک L2TP/IPsec", "", actor=admin.username)
    return {"ok": True, "psk": payload.psk}


class NodeControllerMigrationRequest(BaseModel):
    controller_url: str = Field(..., min_length=8, max_length=512)
    controller_token: str = Field(..., min_length=16, max_length=512)
    verify_controller_tls: bool = True
    verify_node_tls: bool = True

    @field_validator("controller_url")
    @classmethod
    def validate_controller_url(cls, value: str) -> str:
        value = str(value or "").strip().rstrip("/")
        if value.endswith("/api"):
            value = value[:-4].rstrip("/")
        parsed = urlparse(value)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ValueError("آدرس سرور اصلی باید با http:// یا https:// شروع شود")
        if parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("آدرس سرور اصلی نباید شامل نام کاربری، رمز، query یا fragment باشد")
        if parsed.path not in {"", "/"}:
            raise ValueError("آدرس را بدون مسیر /api وارد کنید")
        return value

    @field_validator("controller_token")
    @classmethod
    def validate_controller_token(cls, value: str) -> str:
        value = str(value or "").strip()
        if len(value) < 16:
            raise ValueError("توکن اتصال سرور اصلی معتبر نیست")
        return value


def _decode_env_value(raw: str) -> str:
    try:
        parts = shlex.split(str(raw or ""), posix=True)
        return parts[0] if parts else ""
    except Exception:
        return str(raw or "").strip().strip("\"'")


def _read_env_map(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    try:
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in line:
                continue
            key, raw = line.split("=", 1)
            values[key.strip()] = _decode_env_value(raw)
    except Exception:
        pass
    return values


def _atomic_update_env(path: Path, updates: dict[str, str], *, mode: int, group: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = path.read_text(encoding="utf-8", errors="ignore").splitlines() if path.exists() else []
    remaining = {str(key): str(value) for key, value in updates.items()}
    output: list[str] = []
    for line in lines:
        if "=" not in line or line.lstrip().startswith("#"):
            output.append(line)
            continue
        key = line.split("=", 1)[0].strip()
        if key in remaining:
            output.append(f"{key}={shlex.quote(remaining.pop(key))}")
        else:
            output.append(line)
    for key, value in remaining.items():
        output.append(f"{key}={shlex.quote(value)}")

    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}-{time.time_ns()}")
    temporary.write_text("\n".join(output).rstrip("\n") + "\n", encoding="utf-8")
    temporary.chmod(mode)
    if group:
        try:
            os.chown(temporary, 0, grp.getgrnam(group).gr_gid)
        except Exception:
            pass
    os.replace(temporary, path)
    path.chmod(mode)


def _node_controller_state(db: Session) -> dict[str, object]:
    """Return the durable controller registration state for a node.

    Older installers did not always persist the controller fields in the same
    place.  Read every supported durable source with an explicit precedence:
    database first, then the canonical node-registration file, followed by the
    panel/backend/install-result environment files used by older releases.
    This keeps the migration UI useful after repair/update conversions instead
    of showing blank values merely because one source is missing.
    """
    env_sources = [
        _read_env_map(Path("/var/lib/vpn-panel/node-registration.env")),
        _read_env_map(Path("/opt/vpn-panel/panel.env")),
        _read_env_map(Path("/opt/vpn-panel/backend/.env")),
        _read_env_map(Path("/var/lib/vpn-panel/install-result.env")),
    ]

    def first_env(*keys: str) -> str:
        for source in env_sources:
            for key in keys:
                value = str(source.get(key) or "").strip()
                if value:
                    return value
        return ""

    controller_url = (
        _get_setting(db, "node_controller_url")
        or first_env("NODE_CONTROLLER_URL", "CONTROLLER_URL")
    ).strip().rstrip("/")
    node_name = (
        _get_setting(db, "node_name")
        or first_env("NODE_NAME")
        or os.uname().nodename.split(".", 1)[0]
    ).strip()
    node_public_url = (
        _get_setting(db, "node_public_url")
        or first_env("NODE_PUBLIC_URL", "PUBLIC_URL")
    ).strip().rstrip("/")
    if not node_public_url:
        try:
            domain_active = _get_setting(db, "domain_ssl_status") == "active"
            domain = (_get_setting(db, "domain") or "").strip()
            port = int(_get_setting(db, "panel_port") or (443 if domain_active else 80))
            node_public_url = _node_public_url_for_port(
                db, port, domain_active=domain_active, domain=domain
            ).strip().rstrip("/")
        except Exception:
            node_public_url = ""

    controller_token = (
        _get_setting(db, "node_controller_token")
        or first_env("NODE_CONTROLLER_TOKEN", "CONTROLLER_TOKEN")
    ).strip()
    verify_controller_raw = (
        _get_setting(db, "node_controller_verify_tls")
        or first_env("NODE_CONTROLLER_VERIFY_TLS", "CONTROLLER_VERIFY_TLS")
        or "1"
    ).strip().lower()
    verify_node_raw = (
        _get_setting(db, "node_verify_tls")
        or first_env("NODE_VERIFY_TLS")
        or "1"
    ).strip().lower()
    return {
        "controller_url": controller_url,
        "node_name": node_name,
        "node_public_url": node_public_url,
        "controller_token": controller_token,
        "token_configured": bool(controller_token),
        "verify_controller_tls": verify_controller_raw not in {"0", "false", "no", "off"},
        "verify_node_tls": verify_node_raw not in {"0", "false", "no", "off"},
        "last_changed_at": _get_setting(db, "node_controller_changed_at") or "",
        "last_error": _get_setting(db, "node_controller_change_error") or "",
    }


def _node_registration_payload(db: Session, state: dict[str, object], *, verify_node_tls: bool) -> dict[str, object]:
    node_name = str(state.get("node_name") or "").strip() or os.uname().nodename.split(".", 1)[0]
    node_public_url = str(state.get("node_public_url") or "").strip().rstrip("/")
    if not node_public_url:
        domain_active = _get_setting(db, "domain_ssl_status") == "active"
        domain = (_get_setting(db, "domain") or "").strip()
        port = int(_get_setting(db, "panel_port") or (443 if domain_active else 80))
        node_public_url = _node_public_url_for_port(db, port, domain_active=domain_active, domain=domain)
    parsed = urlparse(node_public_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(400, "آدرس عمومی این نود معتبر نیست؛ ابتدا دامنه یا پورت پنل نود را اصلاح کنید")

    ssh_password = decrypt_password(_get_setting(db, "node_ssh_password_enc") or "") or ""
    ssh_configured = str(_get_setting(db, "node_ssh_configured") or "0").lower() in {"1", "true", "yes", "on"}
    return {
        "name": node_name,
        "api_url": node_public_url,
        "api_token": get_or_create_agent_token(db),
        "enabled": True,
        "verify_tls": bool(verify_node_tls),
        "weight": 100,
        "ssh_host": (_get_setting(db, "node_ssh_host") or "").strip() or None,
        "ssh_port": int(_get_setting(db, "node_ssh_port") or 22),
        "ssh_username": (_get_setting(db, "node_ssh_username") or "root").strip() or "root",
        "ssh_password": ssh_password or None,
        "save_ssh_password": bool(ssh_password),
        "clear_ssh_password": bool(ssh_configured and not ssh_password),
    }


def _controller_error(response: requests.Response) -> str:
    detail = response.text[-1200:] if response.text else f"HTTP {response.status_code}"
    try:
        payload = response.json()
        if isinstance(payload, dict) and payload.get("detail"):
            detail = str(payload["detail"])
    except Exception:
        pass
    return detail


def _register_with_controller(controller_url: str, controller_token: str, verify_tls: bool, payload: dict[str, object]) -> dict:
    try:
        response = requests.post(
            f"{controller_url.rstrip('/')}/api/node-agent/register",
            headers={"X-Node-Token": controller_token, "Content-Type": "application/json"},
            json=payload,
            timeout=(10, 55),
            verify=bool(verify_tls),
        )
    except requests.RequestException as exc:
        raise HTTPException(502, f"اتصال به سرور اصلی جدید برقرار نشد: {exc}") from exc
    if response.status_code not in {200, 201}:
        raise HTTPException(response.status_code if response.status_code < 500 else 502, f"ثبت نود در سرور اصلی جدید ناموفق بود: {_controller_error(response)}")
    try:
        data = response.json()
        return data if isinstance(data, dict) else {"ok": True}
    except Exception:
        return {"ok": True}


def _best_effort_unregister_old_controller(old_state: dict[str, object], payload: dict[str, object], new_url: str) -> tuple[bool, str]:
    old_url = str(old_state.get("controller_url") or "").strip().rstrip("/")
    old_token = str(old_state.get("controller_token") or "").strip()
    if not old_url or not old_token or old_url == new_url.rstrip("/"):
        return True, ""
    try:
        response = requests.post(
            f"{old_url}/api/node-agent/unregister",
            headers={"X-Node-Token": old_token, "Content-Type": "application/json"},
            json={"api_token": payload["api_token"], "api_url": payload["api_url"], "name": payload["name"]},
            timeout=(5, 18),
            verify=bool(old_state.get("verify_controller_tls", True)),
        )
        if response.status_code in {200, 201}:
            return True, ""
        if response.status_code == 404:
            return False, "کنترلر قبلی از حذف خودکار رکورد نود پشتیبانی نمی‌کند؛ رکورد قدیمی را دستی حذف کنید"
        return False, _controller_error(response)
    except requests.RequestException as exc:
        return False, str(exc)


def _persist_controller_migration(
    db: Session,
    *,
    controller_url: str,
    controller_token: str,
    verify_controller_tls: bool,
    verify_node_tls: bool,
    payload: dict[str, object],
) -> None:
    values = {
        "server_role": "node",
        "deployment_role": "node",
        "node_panel_enabled": "1",
        "node_controller_url": controller_url,
        "node_controller_token": controller_token,
        "node_controller_verify_tls": "1" if verify_controller_tls else "0",
        "node_name": str(payload["name"]),
        "node_public_url": str(payload["api_url"]),
        "node_verify_tls": "1" if verify_node_tls else "0",
        "node_controller_changed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "node_controller_change_error": "",
    }

    file_updates = {
        "SERVER_ROLE": "node",
        "DEPLOYMENT_ROLE": "node",
        "NODE_PANEL_ENABLED": "1",
        "NODE_CONTROLLER_URL": controller_url,
        "CONTROLLER_URL": controller_url,
        "CONTROLLER_TOKEN": controller_token,
        "CONTROLLER_VERIFY_TLS": "1" if verify_controller_tls else "0",
        "NODE_NAME": str(payload["name"]),
        "NODE_PUBLIC_URL": str(payload["api_url"]),
        "NODE_VERIFY_TLS": "1" if verify_node_tls else "0",
    }
    snapshots: dict[Path, bytes | None] = {}
    marker = Path("/var/lib/vpn-panel/node-registration.ok")
    targets = [
        (Path("/var/lib/vpn-panel/node-registration.env"), file_updates, 0o600, None),
        (Path("/opt/vpn-panel/panel.env"), file_updates, 0o640, "nogroup"),
        (Path("/opt/vpn-panel/backend/.env"), file_updates, 0o640, "nogroup"),
        (Path("/var/lib/vpn-panel/install-result.env"), {
            "SERVER_ROLE": "node", "DEPLOYMENT_ROLE": "node", "NODE_CONTROLLER_URL": controller_url,
            "NODE_PUBLIC_URL": str(payload["api_url"]),
        }, 0o600, None),
    ]
    for path, _, _, _ in targets:
        snapshots[path] = path.read_bytes() if path.exists() else None
    snapshots[marker] = marker.read_bytes() if marker.exists() else None

    try:
        for path, updates, mode, group in targets:
            _atomic_update_env(path, updates, mode=mode, group=group)
        for key, value in values.items():
            _set_setting(db, key, value)

        # Write the success marker before committing the database.  This keeps
        # the operation transactional: after db.commit() there are no remaining
        # filesystem writes that could fail and leave DB/files on different
        # controllers.
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker_tmp = marker.with_name(f".{marker.name}.tmp-{os.getpid()}-{time.time_ns()}")
        marker_tmp.write_text(values["node_controller_changed_at"] + "\n", encoding="utf-8")
        marker_tmp.chmod(0o600)
        os.replace(marker_tmp, marker)
        db.commit()
    except Exception as exc:
        db.rollback()
        for path, content in snapshots.items():
            try:
                if content is None:
                    path.unlink(missing_ok=True)
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(content)
            except Exception:
                pass
        raise HTTPException(500, f"ثبت تنظیمات سرور اصلی جدید روی نود ناموفق بود: {exc}") from exc


@router.get("/node-controller")
def get_node_controller_settings(db: Session = Depends(get_db), admin: Admin = Depends(require_superadmin)):
    if effective_server_role(db) != "node":
        raise HTTPException(404, "این تنظیم فقط در پنل نود در دسترس است")
    state = _node_controller_state(db)
    state.pop("controller_token", None)
    return state


@router.post("/node-controller")
def change_node_controller(
    payload: NodeControllerMigrationRequest,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_superadmin),
):
    if effective_server_role(db) != "node":
        raise HTTPException(404, "این تنظیم فقط در پنل نود در دسترس است")

    old_state = _node_controller_state(db)
    registration_payload = _node_registration_payload(db, old_state, verify_node_tls=payload.verify_node_tls)
    _register_with_controller(payload.controller_url, payload.controller_token, payload.verify_controller_tls, registration_payload)

    try:
        _persist_controller_migration(
            db,
            controller_url=payload.controller_url,
            controller_token=payload.controller_token,
            verify_controller_tls=payload.verify_controller_tls,
            verify_node_tls=payload.verify_node_tls,
            payload=registration_payload,
        )
    except HTTPException:
        # The new controller may already contain a row. Remove it again when
        # local persistence fails so retrying remains clean and deterministic.
        try:
            requests.post(
                f"{payload.controller_url.rstrip('/')}/api/node-agent/unregister",
                headers={"X-Node-Token": payload.controller_token},
                json={"api_token": registration_payload["api_token"], "api_url": registration_payload["api_url"], "name": registration_payload["name"]},
                timeout=(5, 15),
                verify=bool(payload.verify_controller_tls),
            )
        except Exception:
            pass
        raise

    cleanup_ok, cleanup_error = _best_effort_unregister_old_controller(old_state, registration_payload, payload.controller_url)
    try:
        subprocess.run(["systemctl", "disable", "--now", "vpn-panel-node-register.timer"], capture_output=True, timeout=10)
    except Exception:
        pass
    log_event(
        "🔁 تغییر سرور اصلی Node",
        f"از {old_state.get('controller_url') or 'نامشخص'} به {payload.controller_url}",
        actor=admin.username,
    )
    return {
        "ok": True,
        "controller_url": payload.controller_url,
        "node_name": registration_payload["name"],
        "node_public_url": registration_payload["api_url"],
        "old_controller_cleanup": cleanup_ok,
        "cleanup_warning": cleanup_error if not cleanup_ok else "",
        "message": "نود با موفقیت به سرور اصلی جدید منتقل شد",
    }


def _node_public_url_for_port(db: Session, port: int, *, domain_active: bool, domain: str) -> str:
    old_url = (_get_setting(db, "node_public_url") or "").strip()
    parsed = urlparse(old_url if "://" in old_url else "")
    scheme = "https" if domain_active else (parsed.scheme or "http")
    host = domain if domain_active and domain else (parsed.hostname or get_settings().PUBLIC_SERVER_IP)
    default_port = 443 if scheme == "https" else 80
    netloc = host if int(port) == default_port else f"{host}:{int(port)}"
    return urlunparse((scheme, netloc, "", "", "", ""))


def _persist_node_registration_url(new_url: str) -> None:
    env_path = Path("/var/lib/vpn-panel/node-registration.env")
    if env_path.exists():
        lines = env_path.read_text(encoding="utf-8").splitlines()
        replaced = False
        output = []
        for line in lines:
            if line.startswith("NODE_PUBLIC_URL="):
                output.append(f"NODE_PUBLIC_URL={shlex.quote(new_url)}")
                replaced = True
            else:
                output.append(line)
        if not replaced:
            output.append(f"NODE_PUBLIC_URL={shlex.quote(new_url)}")
        env_path.write_text("\n".join(output) + "\n", encoding="utf-8")
        env_path.chmod(0o600)

    result_path = Path("/var/lib/vpn-panel/install-result.env")
    if result_path.exists():
        lines = result_path.read_text(encoding="utf-8").splitlines()
        output = []
        seen_url = seen_port = False
        parsed = urlparse(new_url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        for line in lines:
            if line.startswith("NODE_PUBLIC_URL="):
                output.append(f"NODE_PUBLIC_URL={new_url}"); seen_url = True
            elif line.startswith("PANEL_URL="):
                output.append(f"PANEL_URL={new_url}")
            elif line.startswith("PANEL_PORT="):
                output.append(f"PANEL_PORT={port}"); seen_port = True
            else:
                output.append(line)
        if not seen_url: output.append(f"NODE_PUBLIC_URL={new_url}")
        if not seen_port: output.append(f"PANEL_PORT={port}")
        result_path.write_text("\n".join(output) + "\n", encoding="utf-8")
        result_path.chmod(0o600)


def _reregister_node_async() -> None:
    script = "/opt/vpn-panel/scripts/node_registration_retry.sh"
    if Path(script).exists():
        subprocess.Popen(
            [BASH, script], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )


@router.get("/node-ssh")
def get_node_ssh_settings(db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    if effective_server_role(db) != "node":
        raise HTTPException(404, "این تنظیم فقط در پنل نود در دسترس است")
    return {
        "host": _get_setting(db, "node_ssh_host") or get_settings().PUBLIC_SERVER_IP,
        "port": int(_get_setting(db, "node_ssh_port") or 22),
        "username": _get_setting(db, "node_ssh_username") or "root",
        "save_password": bool(_get_setting(db, "node_ssh_password_enc")),
        "password_saved": bool(_get_setting(db, "node_ssh_password_enc")),
    }


@router.post("/node-ssh")
def set_node_ssh_settings(payload: NodeLocalSshSettingsRequest, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    if effective_server_role(db) != "node":
        raise HTTPException(404, "این تنظیم فقط در پنل نود در دسترس است")
    existing_password = _get_setting(db, "node_ssh_password_enc")
    _set_setting(db, "node_ssh_host", payload.host.strip())
    _set_setting(db, "node_ssh_port", str(payload.port))
    _set_setting(db, "node_ssh_username", payload.username.strip())
    _set_setting(db, "node_ssh_configured", "1")
    if payload.clear_password or not payload.save_password:
        _set_setting(db, "node_ssh_password_enc", None)
        password_saved = False
    elif payload.password:
        _set_setting(db, "node_ssh_password_enc", encrypt_password(payload.password))
        password_saved = True
    elif existing_password:
        password_saved = True
    else:
        raise HTTPException(400, "برای اولین ذخیره امن، رمز SSH را وارد کنید")
    db.commit()
    _reregister_node_async()
    return {
        "ok": True,
        "host": payload.host.strip(),
        "port": int(payload.port),
        "username": payload.username.strip(),
        "save_password": password_saved,
        "password_saved": password_saved,
    }


@router.get("/panel-port")
def get_panel_port(db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    domain_active = _get_setting(db, "domain_ssl_status") == "active"
    return {
        "port": int(_get_setting(db, "panel_port") or 80),
        "domain_active": domain_active,
        "domain": _get_setting(db, "domain") if domain_active else None,
    }


@router.post("/panel-port")
def set_panel_port(payload: PanelPortRequest, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    domain_ssl_active = _get_setting(db, "domain_ssl_status") == "active"
    domain = _get_setting(db, "domain") or ""
    if domain_ssl_active and not domain:
        raise HTTPException(status_code=500, detail="وضعیت SSL دامنه فعال است ولی دامنه‌ای ثبت نشده - ابتدا Settings > دامنه را دوباره بررسی کنید.")

    _check_listener_conflict(db, payload.port, "tcp", {"panel"})

    script_args = [BASH, "/opt/vpn-panel/scripts/change_panel_port.sh", str(payload.port)]
    if domain_ssl_active:
        # دامنه فعلی SSL دارد؛ به‌جای مسدود کردن تغییر پورت، گواهی همان دامنه
        # (که قبلاً از Let's Encrypt گرفته شده - وابسته به هیچ پورتی نیست)
        # دوباره روی پورت جدید سوار می‌شود، بدون تماس مجدد با certbot. اگر
        # پورت جدید 443 نباشد، nginx دیگر اصلاً روی 443 گوش نمی‌دهد - یعنی آن
        # پورت برای سرویس دیگری (مثلاً OpenConnect) کاملاً آزاد می‌شود.
        script_args.append(domain)

    try:
        subprocess.run(
            script_args,
            capture_output=True, text=True, timeout=30, check=True,
        )
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"تغییر پورت ناموفق بود: {(e.stderr or e.stdout)[-500:]}")
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=500, detail="اجرای اسکریپت تغییر پورت بیش از حد طول کشید")

    _set_setting(db, "panel_port", str(payload.port))
    role = effective_server_role(db)
    if role == "node":
        url = _node_public_url_for_port(
            db, payload.port, domain_active=domain_ssl_active, domain=domain
        )
        _set_setting(db, "node_public_url", url)
    else:
        url = (
            f"https://{domain}" if domain_ssl_active and payload.port == 443
            else f"https://{domain}:{payload.port}" if domain_ssl_active
            else f"http://{get_settings().PUBLIC_SERVER_IP}:{payload.port}"
        )
    db.commit()
    if role == "node":
        try:
            _persist_node_registration_url(url)
            _reregister_node_async()
        except Exception:
            # The port change itself is already complete. The systemd retry
            # timer can re-register later, so never roll the web panel back.
            pass
    log_event("🔧 تغییر پورت پنل", f"پورت جدید: {payload.port}", actor=admin.username)
    return {"ok": True, "port": payload.port, "url": url, "node_reregistering": role == "node"}


# ---------- VPN protocols domain (separate from the panel's own domain) ----------
# دامنه‌ای که فقط برای اتصال L2TP/PPTP/OpenVPN استفاده می‌شود، کاملاً جدا از
# دامنه‌ی پنل (Settings > Domain & SSL بالا). این دو عمداً از هم جدا نگه داشته
# شده‌اند: اگر دامنه‌ی پنل پشت یک CDN/پروکسی مثل Cloudflare (ابر نارنجی) باشد،
# آن دامنه فقط ترافیک HTTP(S) را جلو می‌برد و پروتکل‌های VPN روی آن اصلاً وصل
# نمی‌شوند — چون این آدرس دیگر IP واقعی سرور نیست. برای پروتکل‌ها باید یک
# ساب‌دامنه‌ی دیگر با رکورد A مستقیم (DNS-only) به IP سرور اشاره کند.
@router.get("/vpn-domain")
def get_vpn_domain(db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    return {
        "domain": _get_setting(db, "vpn_domain"),
        "status": _get_setting(db, "vpn_domain_status") or "not_configured",
        "log": _get_setting(db, "vpn_domain_log"),
    }


@router.post("/vpn-domain")
def set_vpn_domain(payload: VpnDomainRequest, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    _set_setting(db, "vpn_domain_status", "in_progress")
    db.commit()

    # علاوه بر چک DNS، یک گواهی SSL واقعی هم برای همین دامنه می‌گیرد و به
    # سرور SSTP (accel-ppp) وصل می‌کند - وگرنه SSTP همچنان گواهی دامنه‌ی پنل
    # را نشان می‌دهد و کلاینت‌های ویندوزی با خطای 0x800B010F (CN mismatch)
    # مواجه می‌شوند، چون CN گواهی با هاست‌نیمی که کلاینت بهش وصل شده فرق دارد.
    ok, log = apply_vpn_domain_ssl(payload.domain)
    _set_setting(db, "vpn_domain_status", "active" if ok else "failed")
    _set_setting(db, "vpn_domain_log", log)
    if not ok:
        db.commit()
        raise HTTPException(
            status_code=400,
            detail=f"تایید دامنه/دریافت SSL ناموفق بود. جزئیات: {log[-500:]}",
        )

    _set_setting(db, "vpn_domain", payload.domain)
    db.commit()

    _reapply_protocols_with_current_domain(db)

    log_event("🌐 تنظیم دامنه‌ی اختصاصی پروتکل‌ها", f"دامنه: {payload.domain}", actor=admin.username)
    return {"ok": True, "domain": payload.domain}


@router.delete("/vpn-domain")
def clear_vpn_domain(db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    _set_setting(db, "vpn_domain", None)
    _set_setting(db, "vpn_domain_status", "not_configured")
    db.commit()
    _reapply_protocols_with_current_domain(db)
    log_event("🌐 حذف دامنه‌ی اختصاصی پروتکل‌ها", "", actor=admin.username)
    return {"ok": True}


# ---------- SSL برای IKEv2 (جایگزین گواهی self-signed خودکار با یک گواهی
# واقعیِ Let's Encrypt، تا کلاینت‌ها بدون نیاز به trust دستی CA پنل وصل
# شوند) ----------
# جدا از دامنه‌ی اختصاصیِ پروتکل‌ها (بالا، برای SSTP) نگه داشته شده چون یک
# دامنه‌ی دیگر می‌تواند برای هرکدام استفاده شود.
@router.get("/ikev2-ssl")
def get_ikev2_ssl(db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    return {
        "domain": _get_setting(db, "ikev2_ssl_domain"),
        "status": _get_setting(db, "ikev2_ssl_status") or "not_configured",
        "log": _get_setting(db, "ikev2_ssl_log"),
    }


def _run_ikev2_ssl_job(domain: str, actor: str) -> None:
    """در یک ترد جدا اجرا می‌شود (نه داخل request handler) چون
    setup_ikev2_ssl.sh برای گرفتن پورت ۸۰ برای certbot standalone، نصب
    nginx را متوقف/راه‌اندازی مجدد می‌کند - همان nginx که همین درخواست HTTP
    (پشت Cloudflare) را هم به بک‌اند پراکسی می‌کند. اگر این کار داخل خودِ
    request handler (به‌صورت synchronous) انجام شود، همان لحظه‌ای که nginx
    متوقف می‌شود، کانکشنِ خودِ این درخواست هم قطع می‌شود و Cloudflare خطای
    «could not parse response» نشان می‌دهد - حتی اگر عملیات چند ثانیه بعد
    با موفقیت کامل شود (به همین دلیل با رفرش صفحه وضعیت «فعال» دیده می‌شد)."""
    db = SessionLocal()
    try:
        ok, log = apply_ikev2_ssl(domain)
        _set_setting(db, "ikev2_ssl_status", "active" if ok else "failed")
        _set_setting(db, "ikev2_ssl_log", log)
        if ok:
            _set_setting(db, "ikev2_ssl_domain", domain)
        db.commit()
        if ok:
            log_event("🌐 تنظیم SSL برای IKEv2", f"دامنه: {domain}", actor=actor)
    finally:
        db.close()


@router.post("/ikev2-ssl")
def set_ikev2_ssl(payload: Ikev2DomainRequest, db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    _set_setting(db, "ikev2_ssl_status", "in_progress")
    _set_setting(db, "ikev2_ssl_log", None)
    db.commit()

    threading.Thread(
        target=_run_ikev2_ssl_job,
        args=(payload.domain, admin.username),
        daemon=True,
    ).start()

    # پاسخ فوراً برمی‌گردد (قبل از اینکه اسکریپت nginx را متوقف کند)؛ فرانت‌اند
    # با poll کردن GET /ikev2-ssl وضعیت "active"/"failed" را دنبال می‌کند.
    return {"ok": True, "status": "in_progress", "domain": payload.domain}


@router.delete("/ikev2-ssl")
def clear_ikev2_ssl(db: Session = Depends(get_db), admin: Admin = Depends(require_permission("settings"))):
    # توجه: این فقط رکورد پنل را پاک می‌کند - گواهی Let's Encrypt که قبلاً
    # روی strongSwan نصب شده همچنان به‌کار می‌رود تا وقتی دستی/با تنظیم یک
    # دامنه‌ی دیگر جایگزین شود (یا با install/setup_ikev2.sh --force ریست شود).
    _set_setting(db, "ikev2_ssl_domain", None)
    _set_setting(db, "ikev2_ssl_status", "not_configured")
    db.commit()
    log_event("🌐 حذف SSL اختصاصیِ IKEv2", "", actor=admin.username)
    return {"ok": True}


def _reapply_protocols_with_current_domain(db: Session):
    """بعد از تغییر دامنه‌ی پروتکل‌ها، تنظیمات فعلی پورت/فعال‌بودن را دوباره
    اعمال می‌کند تا فایل نمونه‌ی client.ovpn با آدرس جدید بازسازی شود."""
    def _bool(key, default):
        v = _get_setting(db, key)
        return (v == "1") if v is not None else default

    def _int(key, default):
        v = _get_setting(db, key)
        return int(v) if v is not None else default

    apply_vpn_protocol_settings(
        _bool("l2tp_enabled", True), _int("l2tp_port", 1701),
        _bool("pptp_enabled", True),
        _bool("openvpn_enabled", True),
        _int("openvpn_udp_port", 1194), _int("openvpn_tcp_port", 1194),
        _get_setting(db, "vpn_domain") or "",
        _int("l2tp_mtu", 1400), _int("l2tp_mru", 1400),
        # قبلاً این دو پاس داده نمی‌شدند، یعنی apply_vpn_protocol_settings
        # همیشه از مقادیر پیش‌فرض خودش (sstp_enabled=True, sstp_port=4433)
        # استفاده می‌کرد - نه از چیزی که ادمین واقعاً در تنظیمات ذخیره کرده
        # بود. نتیجه: هر بار که دامنه‌ی اختصاصیِ پروتکل‌ها ست/پاک می‌شد (مثلاً
        # set_vpn_domain/clear_vpn_domain بالا)، SSTP بی‌سروصدا به حالت
        # فعال/پورت پیش‌فرض ری‌استارت می‌شد، حتی اگر ادمین آن را خاموش کرده یا
        # پورت دیگری برایش گذاشته بود - دقیقاً همان چیزی که به‌نظر می‌رسید
        # «SSTP خودش خاموش/ریست می‌شود» و فقط با «ذخیره»‌ی دوباره از پنل
        # درست می‌شد.
        #
        # نکته‌ی مهم دیگر: پیش‌فرض 4433 است، نه 443 - چون setup_sstp.sh خود
        # accel-ppp را روی 4433 نصب می‌کند (443 برای nginx/HTTPS پنل رزرو
        # است). قبلاً این‌جا 443 پاس داده می‌شد که با هر «ذخیره»‌ی تنظیمات
        # پروتکل‌ها (حتی بدون این‌که ادمین SSTP را لمس کند) باعث تلاش برای
        # bind شدن accel-ppp-sstp روی پورت 443 (که nginx از قبل گرفته) و در
        # نتیجه crash کامل سرویس SSTP می‌شد.
        _bool("sstp_enabled", True), _int("sstp_port", 4433),
        _bool("ikev2_enabled", True),
        _int("openconnect_port", 8443),
        _setting_or_default(db, "openconnect_dns1", "8.8.8.8"),
        _setting_or_default(db, "openconnect_dns2", "1.1.1.1", preserve_blank=True),
        _setting_or_default(db, "openvpn_dns1", "1.1.1.1"),
        _setting_or_default(db, "openvpn_dns2", "8.8.8.8", preserve_blank=True),
    )


def _save_extended_protocol_settings(db: Session, payload: VpnProtocolSettings, target: str = "all") -> None:
    grouped = {
        "l2tp": ("l2tp_dns1", "l2tp_dns2", "l2tp_local_ip", "l2tp_ip_range", "l2tp_client_to_client"),
        "pptp": ("pptp_dns1", "pptp_dns2", "pptp_local_ip", "pptp_ip_range", "pptp_mtu", "pptp_mru", "pptp_client_to_client"),
        "openvpn": ("openvpn_mtu", "openvpn_cipher", "openvpn_client_to_client", "openvpn_redirect_gateway"),
        "sstp": ("sstp_dns1", "sstp_dns2", "sstp_mtu", "sstp_mru"),
        "ikev2": ("ikev2_dns1", "ikev2_dns2", "ikev2_ip_pool"),
        "openconnect": ("openconnect_mtu", "openconnect_ipv4_network", "openconnect_tunnel_all_dns"),
    }
    keys = [name for group, names in grouped.items() if target in {"all", group} for name in names]
    for name in keys:
        value = getattr(payload, name)
        if isinstance(value, bool):
            value = "1" if value else "0"
        _set_setting(db, name, str(value))


# ---------- VPN protocols (L2TP / PPTP / OpenVPN) ports & enable-disable ----------
@router.get("/vpn-protocols", response_model=VpnProtocolSettings)
def get_vpn_protocols(db: Session = Depends(get_db), admin: Admin = Depends(require_permission("protocols:view", "settings"))):
    def _bool(key, default):
        v = _get_setting(db, key)
        return (v == "1") if v is not None else default

    def _int(key, default):
        v = _get_setting(db, key)
        return int(v) if v is not None else default

    # عمداً از دامنه‌ی پنل (بالا) استفاده نمی‌شود — آن دامنه ممکن است پشت یک
    # CDN/پروکسی HTTP باشد که پروتکل‌های VPN را عبور نمی‌دهد. آدرسی که به
    # کاربران نشان داده می‌شود همیشه از دامنه‌ی اختصاصیِ پروتکل‌ها (در صورت
    # تنظیم و تایید DNS) یا در غیر این صورت IP خام سرور می‌آید.
    vpn_domain = _get_setting(db, "vpn_domain")
    vpn_domain_active = _get_setting(db, "vpn_domain_status") == "active"
    server_address = vpn_domain if (vpn_domain and vpn_domain_active) else get_settings().PUBLIC_SERVER_IP

    return VpnProtocolSettings(
        l2tp_enabled=_bool("l2tp_enabled", True),
        l2tp_port=_int("l2tp_port", 1701),
        l2tp_mtu=_int("l2tp_mtu", 1400),
        l2tp_mru=_int("l2tp_mru", 1400),
        pptp_enabled=_bool("pptp_enabled", True),
        openvpn_enabled=_bool("openvpn_enabled", True),
        openvpn_udp_port=_int("openvpn_udp_port", 1194),
        openvpn_tcp_port=_int("openvpn_tcp_port", 1194),
        openvpn_dns1=_setting_or_default(db, "openvpn_dns1", "1.1.1.1"),
        openvpn_dns2=_setting_or_default(db, "openvpn_dns2", "8.8.8.8", preserve_blank=True),
        sstp_enabled=_bool("sstp_enabled", True),
        sstp_port=_int("sstp_port", 4433),
        ikev2_enabled=_bool("ikev2_enabled", True),
        openconnect_port=_int("openconnect_port", 8443),
        openconnect_dns1=_setting_or_default(db, "openconnect_dns1", "8.8.8.8"),
        openconnect_dns2=_setting_or_default(db, "openconnect_dns2", "1.1.1.1", preserve_blank=True),
        l2tp_dns1=_setting_or_default(db, "l2tp_dns1", "8.8.8.8"),
        l2tp_dns2=_setting_or_default(db, "l2tp_dns2", "8.8.4.4", preserve_blank=True),
        l2tp_local_ip=_get_setting(db, "l2tp_local_ip") or "10.10.10.1",
        l2tp_ip_range=_get_setting(db, "l2tp_ip_range") or "10.10.10.10-10.10.10.250",
        l2tp_client_to_client=_bool("l2tp_client_to_client", False),
        pptp_dns1=_setting_or_default(db, "pptp_dns1", "8.8.8.8"),
        pptp_dns2=_setting_or_default(db, "pptp_dns2", "8.8.4.4", preserve_blank=True),
        pptp_local_ip=_get_setting(db, "pptp_local_ip") or "10.20.20.1",
        pptp_ip_range=_get_setting(db, "pptp_ip_range") or "10.20.20.10-10.20.20.250",
        pptp_mtu=_int("pptp_mtu", 1400), pptp_mru=_int("pptp_mru", 1400),
        pptp_client_to_client=_bool("pptp_client_to_client", False),
        openvpn_mtu=_int("openvpn_mtu", 1500),
        openvpn_cipher=_get_setting(db, "openvpn_cipher") or "AES-256-GCM",
        openvpn_client_to_client=_bool("openvpn_client_to_client", False),
        openvpn_redirect_gateway=_bool("openvpn_redirect_gateway", True),
        sstp_dns1=_setting_or_default(db, "sstp_dns1", "8.8.8.8"),
        sstp_dns2=_setting_or_default(db, "sstp_dns2", "8.8.4.4", preserve_blank=True),
        sstp_mtu=_int("sstp_mtu", 1420), sstp_mru=_int("sstp_mru", 1420),
        ikev2_dns1=_setting_or_default(db, "ikev2_dns1", "8.8.8.8"),
        ikev2_dns2=_setting_or_default(db, "ikev2_dns2", "8.8.4.4", preserve_blank=True),
        ikev2_ip_pool=_get_setting(db, "ikev2_ip_pool") or "10.10.11.10-10.10.11.250",
        openconnect_mtu=_int("openconnect_mtu", 1350),
        openconnect_ipv4_network=_get_setting(db, "openconnect_ipv4_network") or "10.30.0.0/24",
        openconnect_tunnel_all_dns=_bool("openconnect_tunnel_all_dns", True),
        server_address=server_address,
    )


@router.post("/vpn-protocols", response_model=VpnProtocolSettings)
def set_vpn_protocols(
    payload: VpnProtocolSettings,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("settings:manage", "settings")),
):
    vpn_domain = _get_setting(db, "vpn_domain") or ""
    vpn_domain_active = _get_setting(db, "vpn_domain_status") == "active"

    current = get_vpn_protocols(db=db, admin=admin)
    all_fields = set().union(*_PROTOCOL_CARD_FIELDS.values())
    changed_fields = {
        field for field in all_fields
        if getattr(payload, field, None) != getattr(current, field, None)
    }
    if not changed_fields:
        return payload

    all_dns_fields = set().union(*_PROTOCOL_DNS_FIELDS.values())
    if changed_fields.issubset(all_dns_fields):
        changed_protocols = [
            key for key, fields in _PROTOCOL_DNS_FIELDS.items()
            if changed_fields.intersection(fields)
        ]
        applied: list[str] = []
        logs: list[str] = []
        for key in changed_protocols:
            ok, detail = apply_protocol_dns_settings(payload, key)
            if not ok:
                # Restore every protocol already committed at runtime from the
                # pre-request settings. Database values are still untouched.
                for previous in reversed(applied):
                    apply_protocol_dns_settings(current, previous)
                raise HTTPException(
                    status_code=500,
                    detail=f"اعمال امن DNS برای {key} ناموفق بود: {detail[-900:]}",
                )
            applied.append(key)
            logs.append(detail)
        for field in sorted(changed_fields):
            _set_setting(db, field, str(getattr(payload, field)))
        db.commit()
        log_event(
            "🌐 تغییر امن DNS پروتکل‌ها",
            " | ".join(logs)[-1200:],
            actor=admin.username,
        )
        return payload

    # پورت OpenConnect نباید با پورت فعلی خودِ پنل (nginx) تصادم کند - وگرنه
    # ocserv اصلاً روی آن پورت بالا نمی‌آید (پورت قبلاً توسط nginx گرفته شده).
    # این چک قبل از اجرای اسکریپت انجام می‌شود تا ادمین پیام روشن ببیند، نه
    # یک خطای عمومی «سرویس بالا نیامد» بعد از تلاش ناموفق. برای بردن
    # OpenConnect روی 443، ابتدا باید پنل را (از Settings > پورت پنل) به
    # پورت دیگری منتقل کرد.
    _check_protocol_payload_conflicts(db, payload)

    # OpenVPN advanced options are written before the main apply, with their
    # restart deferred. The main script below then performs the only OpenVPN
    # restart. Previously OpenVPN was restarted twice back-to-back and the
    # second restart could leave both instances stopped.
    openvpn_options_ok, openvpn_options_log = apply_protocol_options(
        payload, target="openvpn", restart_services=False
    )
    if not openvpn_options_ok:
        raise HTTPException(
            status_code=500,
            detail=f"اعمال تنظیمات پیشرفته OpenVPN ناموفق بود: {openvpn_options_log[-900:]}",
        )

    ok, log = apply_vpn_protocol_settings(
        payload.l2tp_enabled, payload.l2tp_port,
        payload.pptp_enabled,
        payload.openvpn_enabled, payload.openvpn_udp_port, payload.openvpn_tcp_port,
        vpn_domain if vpn_domain_active else "",
        payload.l2tp_mtu, payload.l2tp_mru,
        payload.sstp_enabled, payload.sstp_port,
        payload.ikev2_enabled,
        payload.openconnect_port,
        payload.openconnect_dns1, payload.openconnect_dns2,
        payload.openvpn_dns1, payload.openvpn_dns2,
    )
    if not ok:
        openvpn_verified = (False, "")
        if payload.openvpn_enabled:
            openvpn_verified = _verify_openvpn_ports(payload.openvpn_udp_port, payload.openvpn_tcp_port)
        # The supplied OpenVPN journal can report a degraded wrapper result even
        # after both real instances are active and the requested sockets are
        # bound. In that exact case, keep the verified runtime state instead of
        # discarding the newly selected ports. Do not mask failures from another
        # explicitly mentioned protocol.
        non_openvpn_failure = any(token in (log or "").lower() for token in ("l2tp", "pptp", "sstp", "ikev2", "openconnect", "ocserv", "strongswan", "xl2tp"))
        if not (openvpn_verified[0] and not non_openvpn_failure):
            raise HTTPException(
                status_code=500,
                detail=f"اعمال تنظیمات پروتکل‌ها ناموفق بود. جزئیات: {log[-500:]} | verify: {openvpn_verified[1]}",
            )
        log += "\n" + openvpn_verified[1]

    # Apply the remaining advanced settings after their basic services have
    # been configured. OpenVPN is intentionally excluded because its advanced
    # config was already included in the single restart above.
    for extended_target in ("l2tp", "pptp", "sstp", "ikev2", "openconnect"):
        extended_ok, extended_log = apply_protocol_options(
            payload, target=extended_target, restart_services=True
        )
        if not extended_ok:
            raise HTTPException(
                status_code=500,
                detail=(
                    f"اعمال تنظیمات پیشرفته {extended_target} ناموفق بود: "
                    f"{extended_log[-900:]}"
                ),
            )
    # Reassert every DNS field changed in this mixed/full save through the same
    # transactional path used by DNS-only edits. This is especially important
    # for existing OpenVPN extra-port instances, which have independent config
    # files and otherwise keep pushing the previous resolver.
    for dns_target, dns_fields in _PROTOCOL_DNS_FIELDS.items():
        if not changed_fields.intersection(dns_fields):
            continue
        dns_ok, dns_log = apply_protocol_dns_settings(payload, dns_target)
        if not dns_ok:
            raise HTTPException(
                status_code=500,
                detail=f"اعمال نهایی DNS برای {dns_target} ناموفق بود: {dns_log[-900:]}",
            )
    _set_setting(db, "l2tp_enabled", "1" if payload.l2tp_enabled else "0")
    _set_setting(db, "l2tp_port", str(payload.l2tp_port))
    _set_setting(db, "l2tp_mtu", str(payload.l2tp_mtu))
    _set_setting(db, "l2tp_mru", str(payload.l2tp_mru))
    _set_setting(db, "pptp_enabled", "1" if payload.pptp_enabled else "0")
    _set_setting(db, "openvpn_enabled", "1" if payload.openvpn_enabled else "0")
    _set_setting(db, "openvpn_udp_port", str(payload.openvpn_udp_port))
    _set_setting(db, "openvpn_tcp_port", str(payload.openvpn_tcp_port))
    _set_setting(db, "openvpn_dns1", payload.openvpn_dns1)
    _set_setting(db, "openvpn_dns2", payload.openvpn_dns2)
    _set_setting(db, "sstp_enabled", "1" if payload.sstp_enabled else "0")
    _set_setting(db, "sstp_port", str(payload.sstp_port))
    _set_setting(db, "ikev2_enabled", "1" if payload.ikev2_enabled else "0")
    _set_setting(db, "openconnect_port", str(payload.openconnect_port))
    _set_setting(db, "openconnect_dns1", payload.openconnect_dns1)
    _set_setting(db, "openconnect_dns2", payload.openconnect_dns2)
    _save_extended_protocol_settings(db, payload, target="all")
    db.commit()

    # پورت‌های اصلی ممکن است عوض شده باشند؛ قوانین DNAT پورت‌های اضافه را هم
    # دوباره با مقادیر تازه هم‌گام می‌کنیم. تنظیمات اصلی (بالا) از قبل commit
    # شده‌اند - اگر همین sync شکست بخورد (مثلاً پورت اصلی تازه با یکی از
    # پورت‌های اضافه‌ی موجود تصادم کند)، دیگر نباید بی‌صدا نادیده گرفته شود؛
    # وگرنه ادمین «موفق» می‌بیند درحالی‌که یک یا چند پورت اضافه واقعاً روی
    # سرور از کار افتاده‌اند.
    extra_ok, extra_log = _sync_extra_ports(db)
    if not extra_ok:
        log_event(
            "⚠️ هم‌گام‌سازی پورت‌های اضافه‌ی OpenVPN بعد از تغییر پروتکل‌ها ناموفق بود",
            extra_log[-500:],
            actor=admin.username,
        )
        raise HTTPException(
            status_code=500,
            detail=(
                "تنظیمات پروتکل‌ها اعمال شد، ولی هم‌گام‌سازی پورت‌های اضافه‌ی OpenVPN بعد از آن "
                f"ناموفق بود (ممکن است پورت اصلی تازه با یکی از پورت‌های اضافه تصادم کرده باشد). جزئیات: {extra_log[-500:]}"
            ),
        )

    sync_internet_blocks(db)

    log_event(
        "🔧 تغییر تنظیمات پروتکل‌های VPN",
        f"L2TP: {'فعال' if payload.l2tp_enabled else 'غیرفعال'}({payload.l2tp_port}) | "
        f"PPTP: {'فعال' if payload.pptp_enabled else 'غیرفعال'} | "
        f"OpenVPN: {'فعال' if payload.openvpn_enabled else 'غیرفعال'}(UDP {payload.openvpn_udp_port}/TCP {payload.openvpn_tcp_port}, DNS {payload.openvpn_dns1}{', ' + payload.openvpn_dns2 if payload.openvpn_dns2 else ''}) | "
        f"SSTP: {'فعال' if payload.sstp_enabled else 'غیرفعال'}({payload.sstp_port}) | "
        f"IKEv2: {'فعال' if payload.ikev2_enabled else 'غیرفعال'} | "
        f"OpenConnect: {payload.openconnect_port} (DNS: {payload.openconnect_dns1}"
        f"{', ' + payload.openconnect_dns2 if payload.openconnect_dns2 else ''})",
        actor=admin.username,
    )

    return payload


def _verify_openvpn_ports(udp_port: int, tcp_port: int, timeout_seconds: float = 6.0) -> tuple[bool, str]:
    """Verify the requested OpenVPN state from configs + real listeners.

    Some systemd/OpenVPN releases briefly return a non-zero restart status even
    though both instance processes become active and bind the new ports. The
    panel must not report "not applied" or discard DB settings in that case.
    """
    configs = {
        "udp": (
            ["/etc/openvpn/server/server-udp.conf", "/etc/openvpn/server-udp.conf"],
            int(udp_port),
        ),
        "tcp": (
            ["/etc/openvpn/server/server-tcp.conf", "/etc/openvpn/server-tcp.conf"],
            int(tcp_port),
        ),
    }
    config_ok = {}
    for proto, (paths, port) in configs.items():
        matched = False
        for raw in paths:
            try:
                text = open(raw, "r", encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            if re.search(rf"(?m)^\s*port\s+{port}\s*$", text):
                matched = True
                break
        config_ok[proto] = matched

    deadline = time.monotonic() + max(0.5, timeout_seconds)
    listener_ok = {"udp": False, "tcp": False}
    unit_ok = False
    last = ""
    while time.monotonic() < deadline:
        try:
            result = subprocess.run(["/usr/bin/ss", "-H", "-lntu"], capture_output=True, text=True, timeout=4, check=False)
            last = (result.stdout or "") + "\n" + (result.stderr or "")
        except Exception as exc:
            last = str(exc)
        # Use the same robust listener verifier as Protocol Center. It falls
        # back to /proc/net when iproute2 output is empty or formatted
        # differently, which is common on newer Ubuntu builds.
        from app.services.protocol_admin import _listener_present
        listener_ok["udp"] = _listener_present(last, "udp", int(udp_port))
        listener_ok["tcp"] = _listener_present(last, "tcp", int(tcp_port))
        active = []
        for unit in ("openvpn-server@server-udp", "openvpn-server@server-tcp", "openvpn@server-udp", "openvpn@server-tcp"):
            try:
                r = subprocess.run(["/usr/bin/systemctl", "is-active", unit], capture_output=True, text=True, timeout=4, check=False)
                if (r.stdout or "").strip() == "active": active.append(unit)
            except Exception:
                pass
        unit_ok = (
            ("openvpn-server@server-udp" in active and "openvpn-server@server-tcp" in active)
            or ("openvpn@server-udp" in active and "openvpn@server-tcp" in active)
        )
        if all(config_ok.values()) and all(listener_ok.values()) and unit_ok:
            return True, f"OpenVPN verified: UDP/{udp_port}, TCP/{tcp_port}"
        time.sleep(0.35)
    # ``systemctl is-active`` for both instances is a reliable final fallback:
    # OpenVPN exits when bind/TUN initialization fails. This prevents a false
    # rollback when the API service cannot observe host sockets through ss.
    if all(config_ok.values()) and unit_ok:
        return True, f"OpenVPN instances active with matching configs: UDP/{udp_port}, TCP/{tcp_port}"
    return False, f"config={config_ok}, listener={listener_ok}, units_active={unit_ok}"


_PROTOCOL_CARD_FIELDS: dict[str, set[str]] = {
    "l2tp": {
        "l2tp_enabled", "l2tp_port", "l2tp_mtu", "l2tp_mru",
        "l2tp_dns1", "l2tp_dns2", "l2tp_local_ip", "l2tp_ip_range",
        "l2tp_client_to_client",
    },
    "pptp": {
        "pptp_enabled", "pptp_dns1", "pptp_dns2", "pptp_local_ip",
        "pptp_ip_range", "pptp_mtu", "pptp_mru", "pptp_client_to_client",
    },
    "openvpn": {
        "openvpn_enabled", "openvpn_udp_port", "openvpn_tcp_port",
        "openvpn_dns1", "openvpn_dns2", "openvpn_mtu", "openvpn_cipher",
        "openvpn_client_to_client", "openvpn_redirect_gateway",
    },
    "sstp": {
        "sstp_enabled", "sstp_port", "sstp_dns1", "sstp_dns2",
        "sstp_mtu", "sstp_mru",
    },
    "ikev2": {
        "ikev2_enabled", "ikev2_dns1", "ikev2_dns2", "ikev2_ip_pool",
    },
    "openconnect": {
        "openconnect_port", "openconnect_dns1", "openconnect_dns2",
        "openconnect_mtu", "openconnect_ipv4_network",
        "openconnect_tunnel_all_dns",
    },
}

_PROTOCOL_DNS_FIELDS: dict[str, set[str]] = {
    key: {field for field in fields if "_dns" in field}
    for key, fields in _PROTOCOL_CARD_FIELDS.items()
}


def _protocol_card_changed_fields(
    key: str, payload: VpnProtocolSettings, current: VpnProtocolSettings
) -> set[str]:
    changed: set[str] = set()
    for field in _PROTOCOL_CARD_FIELDS.get(key, set()):
        if getattr(payload, field, None) != getattr(current, field, None):
            changed.add(field)
    return changed


# ---------- Per-card protocol settings (does not restart unrelated services) ----------
@router.post("/protocol-center/{key}/settings", response_model=VpnProtocolSettings)
def protocol_center_save_settings(
    key: str,
    payload: VpnProtocolSettings,
    db: Session = Depends(get_db),
    admin: Admin = Depends(get_current_admin),
):
    ensure_protocol_permission(admin, key, "edit")
    allowed = {"l2tp", "pptp", "openvpn", "sstp", "ikev2", "openconnect"}
    if key not in allowed:
        raise HTTPException(404, "برای این پروتکل تنظیمات ساختاریافته تعریف نشده است")

    current = get_vpn_protocols(db=db, admin=admin)
    changed_fields = _protocol_card_changed_fields(key, payload, current)

    # Saving an unchanged card must be a no-op. Older builds restarted the
    # selected daemon even when no value changed, which amplified transient
    # node problems and made a harmless modal Save look like a protocol fault.
    if not changed_fields:
        return payload

    # DNS-only edits use an isolated transactional path. It never changes
    # ports/firewall/NAT/routing/PKI and never restarts an unrelated daemon.
    # L2TP/PPTP need no daemon restart at all; OpenVPN/SSTP are restarted only
    # after their files are atomically updated, while IKEv2/OpenConnect use a
    # reload. Any failed runtime check restores the previous files immediately.
    if changed_fields.issubset(_PROTOCOL_DNS_FIELDS.get(key, set())):
        ok, output = apply_protocol_dns_settings(payload, key)
        if not ok:
            raise HTTPException(500, f"اعمال امن DNS برای {key} ناموفق بود: {output[-900:]}")
        for field in sorted(changed_fields):
            _set_setting(db, field, str(getattr(payload, field)))
        db.commit()
        log_event(
            "🌐 تغییر امن DNS پروتکل",
            f"پروتکل: {key} | {output[-500:]}",
            actor=admin.username,
        )
        return payload

    # Validate bind conflicts before touching any config/service.  Different
    # transports may share a number (e.g. TCP/1194 and UDP/1194), but two
    # listeners using the same transport may not.
    if key == "l2tp" and payload.l2tp_enabled:
        _check_listener_conflict(db, payload.l2tp_port, "udp", {"l2tp"})
    elif key == "pptp" and payload.pptp_enabled:
        _check_listener_conflict(db, 1723, "tcp", {"pptp"})
    elif key == "openvpn" and payload.openvpn_enabled:
        _check_listener_conflict(db, payload.openvpn_udp_port, "udp", {"openvpn"})
        _check_listener_conflict(db, payload.openvpn_tcp_port, "tcp", {"openvpn"})
    elif key == "sstp" and payload.sstp_enabled:
        _check_listener_conflict(db, payload.sstp_port, "tcp", {"sstp"})
    elif key == "ikev2" and payload.ikev2_enabled:
        _check_listener_conflict(db, 500, "udp", {"strongswan"})
        _check_listener_conflict(db, 4500, "udp", {"strongswan"})
    elif key == "openconnect":
        _check_listener_conflict(db, payload.openconnect_port, "tcp", {"openconnect"})
        _check_listener_conflict(db, payload.openconnect_port, "udp", {"openconnect"})

    # L2TP and IKEv2 share strongSwan/firewall state.  A modal that was left
    # open must not overwrite the other protocol with a stale checkbox value,
    # so retain the database value for the unrelated card.
    effective_l2tp_enabled = (
        payload.l2tp_enabled
        if key == "l2tp"
        else _bool_setting(db, "l2tp_enabled", True)
    )
    effective_ikev2_enabled = (
        payload.ikev2_enabled
        if key == "ikev2"
        else _bool_setting(db, "ikev2_enabled", True)
    )

    vpn_domain = _get_setting(db, "vpn_domain") or ""
    vpn_domain_active = _get_setting(db, "vpn_domain_status") == "active"

    # Edit the advanced config first and let the main apply step below do the
    # single service restart. This removes the immediate second restart that
    # was leaving OpenVPN stopped after a port change.
    extended_ok, extended_log = apply_protocol_options(
        payload, target=key, restart_services=False
    )
    if not extended_ok:
        raise HTTPException(
            500,
            f"اعمال تنظیمات پیشرفته {key} ناموفق بود: {extended_log[-900:]}",
        )

    if key == "openconnect":
        ok, output = apply_openconnect_settings(
            payload.openconnect_port, payload.openconnect_dns1, payload.openconnect_dns2
        )
    else:
        ok, output = apply_vpn_protocol_settings(
            effective_l2tp_enabled, payload.l2tp_port,
            payload.pptp_enabled,
            payload.openvpn_enabled, payload.openvpn_udp_port, payload.openvpn_tcp_port,
            vpn_domain if vpn_domain_active else "",
            payload.l2tp_mtu, payload.l2tp_mru,
            payload.sstp_enabled, payload.sstp_port,
            effective_ikev2_enabled,
            payload.openconnect_port,
            payload.openconnect_dns1, payload.openconnect_dns2,
            payload.openvpn_dns1, payload.openvpn_dns2,
            target=key,
        )
    if not ok:
        verified = (False, "")
        if key == "openvpn" and payload.openvpn_enabled:
            verified = _verify_openvpn_ports(payload.openvpn_udp_port, payload.openvpn_tcp_port)
        if not verified[0]:
            raise HTTPException(500, f"اعمال تنظیمات {key} ناموفق بود. جزئیات: {output[-900:]} | verify: {verified[1]}")
        output += "\n" + verified[1]
    if changed_fields.intersection(_PROTOCOL_DNS_FIELDS.get(key, set())):
        dns_ok, dns_log = apply_protocol_dns_settings(payload, key)
        if not dns_ok:
            raise HTTPException(500, f"اعمال نهایی DNS برای {key} ناموفق بود: {dns_log[-900:]}")
        output += "\n" + dns_log
    fields = {
        "l2tp": {
            "l2tp_enabled": "1" if payload.l2tp_enabled else "0",
            "l2tp_port": str(payload.l2tp_port),
            "l2tp_mtu": str(payload.l2tp_mtu),
            "l2tp_mru": str(payload.l2tp_mru),
        },
        "pptp": {"pptp_enabled": "1" if payload.pptp_enabled else "0"},
        "openvpn": {
            "openvpn_enabled": "1" if payload.openvpn_enabled else "0",
            "openvpn_udp_port": str(payload.openvpn_udp_port),
            "openvpn_tcp_port": str(payload.openvpn_tcp_port),
            "openvpn_dns1": payload.openvpn_dns1,
            "openvpn_dns2": payload.openvpn_dns2,
        },
        "sstp": {
            "sstp_enabled": "1" if payload.sstp_enabled else "0",
            "sstp_port": str(payload.sstp_port),
        },
        "ikev2": {"ikev2_enabled": "1" if payload.ikev2_enabled else "0"},
        "openconnect": {
            "openconnect_port": str(payload.openconnect_port),
            "openconnect_dns1": payload.openconnect_dns1,
            "openconnect_dns2": payload.openconnect_dns2,
        },
    }[key]
    for setting_key, value in fields.items():
        _set_setting(db, setting_key, value)
    _save_extended_protocol_settings(db, payload, target=key)
    db.commit()

    if key == "openvpn":
        extra_ok, extra_log = _sync_extra_ports(db)
        if not extra_ok:
            raise HTTPException(
                500,
                "تنظیمات اصلی OpenVPN اعمال شد، ولی هم‌گام‌سازی پورت‌های اضافه ناموفق بود: "
                + extra_log[-700:],
            )

    sync_internet_blocks(db)

    log_event(
        "🔧 تغییر تنظیمات یک پروتکل VPN",
        f"پروتکل: {key}",
        actor=admin.username,
    )
    return payload


# ---------- وضعیت لحظه‌ای و کنترل جدا-جدای هر سرویس پروتکل (صفحه‌ی پروتکل‌ها) ----------
@router.get("/vpn-protocols/status")
def vpn_protocols_status(admin: Admin = Depends(require_permission("settings"))):
    return {"protocols": get_protocol_statuses()}


@router.post("/vpn-protocols/{key}/{action}")
def vpn_protocol_control(
    key: str, action: str, admin: Admin = Depends(require_permission("settings"))
):
    if key not in ALLOWED_PROTOCOL_KEYS:
        raise HTTPException(400, "پروتکل نامعتبر است")
    if action not in ALLOWED_ACTIONS:
        raise HTTPException(400, "عملیات نامعتبر است")

    ok, log = control_protocol_service(key, action)
    if not ok:
        raise HTTPException(500, f"اجرای عملیات ناموفق بود. جزئیات: {log[-500:]}")

    log_event("⚙️ کنترل سرویس پروتکل", f"پروتکل: {key} | عملیات: {action}", actor=admin.username)
    return {"ok": True, "protocols": get_protocol_statuses()}


# ---------- VMess / VLESS isolated Xray settings ----------
@router.get("/xray/{protocol}", response_model=XrayProtocolSettings)
def get_xray_protocol_settings(
    protocol: str,
    db: Session = Depends(get_db),
    admin: Admin = Depends(get_current_admin),
):
    ensure_protocol_permission(admin, protocol, "view")
    if protocol not in {"vmess", "vless"}:
        raise HTTPException(404, "پروتکل Xray پیدا نشد")
    return get_xray_settings(db, protocol)


@router.put("/xray/{protocol}", response_model=XrayProtocolSettings)
def set_xray_protocol_settings(
    protocol: str,
    payload: XrayProtocolSettings,
    db: Session = Depends(get_db),
    admin: Admin = Depends(get_current_admin),
):
    ensure_protocol_permission(admin, protocol, "edit")
    if protocol not in {"vmess", "vless"} or payload.protocol != protocol:
        raise HTTPException(400, "پروتکل Xray نامعتبر است")
    if payload.enabled:
        _check_listener_conflict(db, payload.port, "tcp", {protocol})
    try:
        result = save_xray_settings(db, protocol, payload.model_dump())
    except Exception as exc:
        raise HTTPException(500, f"تنظیمات {protocol.upper()} اعمال نشد و rollback شد: {exc}")
    sync_internet_blocks(db)
    log_event("🔧 تغییر تنظیمات Xray", f"پروتکل: {protocol}", actor=admin.username)
    return result


def _visible_protocol_rows(db: Session, admin: Admin) -> list[dict]:
    return _filter_protocol_rows_for_admin(get_protocol_center(db), admin)


def _ensure_any_protocol(admin: Admin, protocols: tuple[str, ...], capability: str) -> None:
    last_error: HTTPException | None = None
    for protocol in protocols:
        try:
            ensure_protocol_permission(admin, protocol, capability)
            return
        except HTTPException as exc:
            last_error = exc
    raise last_error or HTTPException(status_code=403, detail="دسترسی غیرمجاز")


# ---------- Protocol center: status / logs / raw config / installer ----------
@router.get("/protocol-center")
def protocol_center(
    fresh: bool = False,
    db: Session = Depends(get_db),
    admin: Admin = Depends(get_current_admin),
):
    ensure_permission(admin, "protocols:view", "settings")
    # A newly-started node has no protocol cache yet.  Returning the cheap
    # placeholder makes every service and prerequisite look uninstalled until
    # the background worker finishes.  The controller requests ``fresh=1`` on
    # first node selection, so build and cache a real snapshot synchronously.
    if fresh:
        payload = _protocol_center_payload(db)
        _store_protocol_center_cache(payload)
    else:
        payload = _fast_protocol_center(db)
    local_mode = _get_setting(db, "local_services_mode")
    # Existing installations from before 2.3.79 have no mode flag and already
    # run local services, so absence must remain backward-compatible as full.
    if local_mode is None or local_mode == "1":
        resolved_local_mode = "full"
    elif any(bool(item.get("installed")) for item in payload.get("protocols", [])):
        resolved_local_mode = "partial"
    else:
        resolved_local_mode = "management_only"
    return {
        **payload,
        "local_services_mode": resolved_local_mode,
        "protocols": _filter_protocol_rows_for_admin(payload.get("protocols", []), admin),
    }


@router.post("/protocol-center/{key}/service/{action}")
def protocol_center_action(
    key: str,
    action: str,
    db: Session = Depends(get_db),
    admin: Admin = Depends(get_current_admin),
):
    ensure_protocol_permission(admin, key, "start_stop")
    if action not in {"start", "stop", "restart"}:
        raise HTTPException(400, "عملیات نامعتبر است")
    # Start must enable the protocol *before* Xray configuration/preflight is
    # generated.  The previous order started the unit first and wrote the DB flag
    # afterwards; the edit dialog and subscription builder therefore continued
    # to see ``enabled=false`` until the administrator saved the form manually.
    enabled_keys = {"l2tp", "pptp", "openvpn", "sstp", "ikev2", "vmess", "vless"}
    previous_enabled = None
    if key in enabled_keys and action in {"start", "restart"}:
        previous_enabled = _get_setting(db, f"{key}_enabled")
        _set_setting(db, f"{key}_enabled", "1")
        db.commit()
        if key in {"vmess", "vless"}:
            try:
                sync_xray_users(db, protocols=[key], restart=False)
            except Exception as exc:
                if previous_enabled is None:
                    db.query(Setting).filter(Setting.key == f"{key}_enabled").delete(synchronize_session=False)
                else:
                    _set_setting(db, f"{key}_enabled", previous_enabled)
                db.commit()
                raise HTTPException(500, f"ساخت تنظیمات {key.upper()} ناموفق بود: {exc}")

    ok, output = control_protocol(key, action, db)
    if not ok:
        if key in enabled_keys and action in {"start", "restart"}:
            if previous_enabled is None:
                db.query(Setting).filter(Setting.key == f"{key}_enabled").delete(synchronize_session=False)
            else:
                _set_setting(db, f"{key}_enabled", previous_enabled)
            db.commit()
            if key in {"vmess", "vless"}:
                try:
                    sync_xray_users(db, protocols=[key], restart=False)
                except Exception:
                    pass
        raise HTTPException(500, f"اجرای عملیات ناموفق بود: {output[-1200:]}")

    if key in enabled_keys and action == "stop":
        _set_setting(db, f"{key}_enabled", "0")
        db.commit()
    log_event("⚙️ کنترل سرویس پروتکل", f"پروتکل: {key} | عملیات: {action}", actor=admin.username)
    _refresh_protocol_center_async()
    return {"ok": True, "protocols": _visible_protocol_rows(db, admin)}


@router.get("/protocol-center/{key}/logs")
def protocol_center_logs(
    key: str,
    lines: int = 250,
    admin: Admin = Depends(get_current_admin),
):
    ensure_protocol_permission(admin, key, "logs")
    try:
        output = protocol_logs(key, lines)
    except KeyError:
        raise HTTPException(404, "پروتکل پیدا نشد")
    return {"key": key, "lines": max(20, min(lines, 2000)), "output": output}


@router.delete("/protocol-center/{key}/logs")
def protocol_center_logs_clear(
    key: str,
    admin: Admin = Depends(get_current_admin),
):
    ensure_protocol_permission(admin, key, "logs")
    try:
        result = clear_protocol_logs(key)
    except KeyError:
        raise HTTPException(404, "پروتکل پیدا نشد")
    log_event("🧹 پاک‌سازی لاگ پروتکل", f"پروتکل: {key}", actor=admin.username)
    return {"ok": True, **result}


@router.get("/protocol-center/{key}/config")
def protocol_center_config(
    key: str,
    file_id: str | None = None,
    admin: Admin = Depends(get_current_admin),
):
    ensure_protocol_permission(admin, key, "edit")
    try:
        return get_protocol_config(key, file_id)
    except KeyError:
        raise HTTPException(404, "فایل تنظیمات پیدا نشد")


@router.post("/protocol-center/{key}/config")
def protocol_center_config_save(
    key: str,
    payload: ProtocolConfigSaveRequest,
    admin: Admin = Depends(get_current_admin),
):
    ensure_protocol_permission(admin, key, "edit")
    ok, detail = save_protocol_config(key, payload.file_id, payload.content, payload.restart)
    if not ok:
        raise HTTPException(500, detail)
    log_event(
        "📝 ویرایش مستقیم تنظیمات پروتکل",
        f"پروتکل: {key} | فایل: {payload.file_id} | ری‌استارت: {'بله' if payload.restart else 'خیر'}",
        actor=admin.username,
    )
    return {"ok": True, "backup": detail}


@router.post("/protocol-center/{key}/install")
def protocol_center_install(
    key: str,
    payload: ProtocolInstallRequest,
    db: Session = Depends(get_db),
    admin: Admin = Depends(get_current_admin),
):
    if key in {"infrastructure", "all"}:
        ensure_permission(admin, "protocols:install", "settings")
    else:
        ensure_protocol_permission(admin, key, "install")
    if payload.enable_after_install and key in {"l2tp", "pptp", "openvpn", "sstp", "ikev2", "vmess", "vless"}:
        _set_setting(db, f"{key}_enabled", "1")
        db.commit()
    args: list[str] = []
    if key == "openconnect":
        args = [
            f"--port={_get_setting(db, 'openconnect_port') or '8443'}",
            f"--dns1={_setting_or_default(db, 'openconnect_dns1', '8.8.8.8')}",
            f"--dns2={_setting_or_default(db, 'openconnect_dns2', '1.1.1.1', preserve_blank=True)}",
        ]
    elif key in {"vmess", "vless"}:
        args = [f"--protocol={key}"]
    try:
        job_id = start_install_job(key, args)
    except KeyError:
        raise HTTPException(404, "پروتکل پیدا نشد")
    except RuntimeError as exc:
        raise HTTPException(409, str(exc))
    log_event("📦 شروع نصب/ترمیم پروتکل", f"پروتکل: {key}", actor=admin.username)
    return {"ok": True, "job_id": job_id}


@router.get("/protocol-center/install-jobs/{job_id}")
def protocol_center_install_job(
    job_id: str,
    admin: Admin = Depends(get_current_admin),
):
    job = get_install_job(job_id)
    if not job:
        raise HTTPException(404, "عملیات نصب پیدا نشد یا بعد از ری‌استارت بک‌اند پاک شده است")
    if job.get("key") in {"infrastructure", "all"}:
        ensure_permission(admin, "protocols:install", "settings")
    else:
        ensure_protocol_permission(admin, str(job.get("key") or ""), "install")
    return job


@router.post("/openconnect/use-443")
def openconnect_use_443(
    payload: OpenConnect443Request,
    db: Session = Depends(get_db),
    admin: Admin = Depends(get_current_admin),
):
    ensure_protocol_permission(admin, "openconnect", "edit")
    """Atomically move nginx away from 443 and put ocserv on 443.

    Doing this in one backend request is important: after nginx moves, the browser
    can no longer issue a second request to the old port.  On any ocserv failure
    the panel port is rolled back before an error is returned.
    """
    if payload.panel_port == 443:
        raise HTTPException(400, "پورت جدید پنل باید غیر از 443 باشد")
    _check_listener_conflict(db, payload.panel_port, "tcp", {"panel"})
    # 443 must be free on both transports after excluding the current panel
    # listener and the OpenConnect listener that is about to move there.
    _check_listener_conflict(db, 443, "tcp", {"panel", "openconnect"})
    _check_listener_conflict(db, 443, "udp", {"openconnect"})

    old_panel_port = int(_get_setting(db, "panel_port") or 80)
    domain_ssl_active = _get_setting(db, "domain_ssl_status") == "active"
    domain = _get_setting(db, "domain") or ""
    if domain_ssl_active and not domain:
        raise HTTPException(500, "SSL پنل فعال است اما دامنه ثبت نشده است")

    panel_args = [BASH, "/opt/vpn-panel/scripts/change_panel_port.sh", str(payload.panel_port)]
    if domain_ssl_active:
        panel_args.append(domain)
    try:
        subprocess.run(panel_args, capture_output=True, text=True, timeout=45, check=True)
    except subprocess.CalledProcessError as exc:
        raise HTTPException(500, f"انتقال پورت پنل ناموفق بود: {(exc.stderr or exc.stdout)[-700:]}")

    # Apply only ocserv.  Restarting every VPN backend here would disconnect
    # unrelated L2TP/OpenVPN/SSTP/IKEv2 users during a panel-port migration.
    ok, output = apply_openconnect_settings(443, payload.dns1, payload.dns2)
    if not ok:
        rollback = [BASH, "/opt/vpn-panel/scripts/change_panel_port.sh", str(old_panel_port)]
        if domain_ssl_active:
            rollback.append(domain)
        subprocess.run(rollback, capture_output=True, text=True, timeout=45, check=False)
        raise HTTPException(500, f"OpenConnect روی 443 بالا نیامد؛ پورت پنل بازگردانی شد. جزئیات: {output[-900:]}")

    _set_setting(db, "panel_port", str(payload.panel_port))
    _set_setting(db, "openconnect_port", "443")
    _set_setting(db, "openconnect_dns1", payload.dns1)
    _set_setting(db, "openconnect_dns2", payload.dns2)
    db.commit()
    new_url = f"https://{domain}:{payload.panel_port}" if domain_ssl_active else f"http://{get_settings().PUBLIC_SERVER_IP}:{payload.panel_port}"
    log_event(
        "🔀 آزادسازی 443 برای OpenConnect",
        f"پورت پنل: {old_panel_port} -> {payload.panel_port} | OpenConnect: 443",
        actor=admin.username,
    )
    return {"ok": True, "panel_port": payload.panel_port, "openconnect_port": 443, "url": new_url}


# ---------- OpenVPN extra (fallback) ports ----------
# پورت‌های اضافه‌ای که علاوه بر پورت اصلی OpenVPN (بالا) باز می‌شوند. هرکدام
# یک لیسنر OpenVPN مستقل و واقعی است (نه فوروارد فایروال/DNAT) - جزئیات کامل
# در models.OpenvpnExtraPort و manage_openvpn_extra_ports.sh.
# این پورت‌ها یک «استخر» دائمی‌اند: ردیف‌های غیرفعال (is_active=False) هم در
# دیتابیس می‌مانند و هم در کانفیگ OpenVPN همه‌ی کاربران (build_client_ovpn
# همیشه کل جدول را می‌خواند، نه فقط ردیف‌های فعال) - فقط لیسنر واقعی‌شان روی
# سرور خاموش است. یعنی یک‌بار که پورتی به این استخر اضافه شد، از آن به بعد
# روشن/خاموش‌کردنش (توگل) هیچ‌وقت به دانلود دوباره‌ی فایل توسط کاربر نیاز
# ندارد؛ کلاینت همان خط `remote` قدیمی را دارد و به‌محض روشن‌شدن دوباره‌ی
# لیسنر، همان اتصال برقرار می‌شود. فقط حذف کامل (DELETE) این تضمین را از
# بین می‌برد، چون شماره‌پورت را برای همیشه از کانفیگ‌های تازه هم حذف می‌کند.
RESERVED_PORTS = {22, 3306}  # SSH و MySQL - هرگز نباید override شوند

FAILED_PORT_LINE_RE = re.compile(r"FAILED:\s*(\d+)/(tcp|udp)")


def _mark_collateral_extra_port_failures(db: Session, log: str, touched: set[tuple[int, str]]) -> list[str]:
    """اسکریپت manage_openvpn_extra_ports.sh حالا فقط پورت/پروتکل‌هایی را واقعاً
    لمس می‌کند که یا در همین درخواست تغییر کرده‌اند یا از قبل روی سرور بالا
    نبوده‌اند - یعنی یک پورت دیگر که سالم و دست‌نخورده مانده اصولاً نباید هیچ‌وقت
    در این لاگ FAILED باشد. اما اگر به هر دلیل نادری (مثلاً چیزی کاملاً مستقل از
    پنل درست همان لحظه آن پورت را روی سرور اشغال کند) بازهم چنین چیزی رخ داد،
    این تابع همه‌ی خط‌های FAILED لاگ را می‌خواند - نه فقط پورت/پروتکل همین
    درخواست - و اگر به یک ردیفِ دیگر که فعلاً در دیتابیس is_active=True است
    اشاره کند، همان‌جا آن را هم is_active=False می‌کند. بدون این، پنل می‌توانست
    پورتی را «فعال» نشان دهد که واقعاً روی سرور مرده است."""
    collateral: list[str] = []
    for m in FAILED_PORT_LINE_RE.finditer(log):
        port, proto = int(m.group(1)), m.group(2)
        if (port, proto) in touched:
            continue
        row = (
            db.query(OpenvpnExtraPort)
            .filter(
                OpenvpnExtraPort.port == port,
                OpenvpnExtraPort.protocol == proto,
                OpenvpnExtraPort.is_active == True,  # noqa: E712
            )
            .first()
        )
        if row:
            row.is_active = False
            collateral.append(f"{port}/{proto.upper()}")
    if collateral:
        db.commit()
    return collateral


def _sync_extra_ports(db: Session):
    openvpn_udp_port = int(_get_setting(db, "openvpn_udp_port") or 1194)
    openvpn_tcp_port = int(_get_setting(db, "openvpn_tcp_port") or 1194)
    # فقط پورت‌های فعلاً فعال واقعاً به اسکریپت فرستاده می‌شوند تا لیسنر
    # داشته باشند؛ ردیف‌های غیرفعال (استخر) عمداً اینجا نمی‌آیند - اسکریپت هر
    # چیزی که در این لیست نباشد را متوقف/پاک می‌کند (idempotent rebuild).
    ports = [
        (p.port, p.protocol)
        for p in db.query(OpenvpnExtraPort)
        .filter(OpenvpnExtraPort.is_active == True)  # noqa: E712
        .order_by(OpenvpnExtraPort.port)
        .all()
        if not (
            (str(p.protocol) == "udp" and int(p.port) == openvpn_udp_port)
            or (str(p.protocol) == "tcp" and int(p.port) == openvpn_tcp_port)
        )
    ]
    return sync_openvpn_extra_ports(ports, openvpn_udp_port, openvpn_tcp_port)


@router.get("/openvpn-ports", response_model=list[OpenvpnExtraPortOut])
def list_openvpn_ports(db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    ensure_protocol_permission(admin, "openvpn", "edit")
    # قبل از نمایش، وضعیت واقعیِ systemd هر پورتِ «فعال» را چک می‌کند - اگر
    # پورتی مستقل از یک اقدام صریح ادمین (toggle/افزودن) از کار افتاده باشد
    # (کرش، تعارض، یا هر دلیل دیگر)، همین‌جا هم در دیتابیس غیرفعال می‌شود تا
    # پنل هرگز پورت مرده را «تایید/فعال» نشان ندهد - بدون این‌که لازم باشد
    # منتظر تیک بعدیِ زمان‌بند (reconcile_openvpn_extra_ports_job) بمانیم.
    reconcile_openvpn_extra_ports(db)
    return db.query(OpenvpnExtraPort).order_by(OpenvpnExtraPort.is_active.desc(), OpenvpnExtraPort.port).all()


@router.post("/openvpn-ports", response_model=list[OpenvpnExtraPortOut])
def add_openvpn_port(
    payload: OpenvpnExtraPortCreate,
    db: Session = Depends(get_db),
    admin: Admin = Depends(get_current_admin),
):
    ensure_protocol_permission(admin, "openvpn", "edit")
    if payload.port in RESERVED_PORTS:
        raise HTTPException(400, "این پورت برای سرویس‌های دیگر سیستم رزرو شده و قابل استفاده نیست")

    panel_port = int(_get_setting(db, "panel_port") or 80)
    if payload.port == panel_port:
        raise HTTPException(400, "این پورت همین الان برای پنل استفاده می‌شود")

    l2tp_port = int(_get_setting(db, "l2tp_port") or 1701)

    # protocol == "both" یعنی هم یک لیسنر TCP هم یک لیسنر UDP روی همین شماره‌پورت،
    # در همین یک درخواست و فقط یک اجرای sync - به‌جای این‌که ادمین مجبور باشد دوبار
    # جدا-جدا (هرکدام با rebuild/ری‌استارت کامل جداگانه‌ی خودش) اضافه‌شان کند.
    protocols = ["tcp", "udp"] if payload.protocol == "both" else [payload.protocol]

    new_rows: list[OpenvpnExtraPort] = []
    reactivated_rows: list[OpenvpnExtraPort] = []
    already_active: list[str] = []

    openvpn_udp_port = int(_get_setting(db, "openvpn_udp_port") or 1194)
    openvpn_tcp_port = int(_get_setting(db, "openvpn_tcp_port") or 1194)

    for proto in protocols:
        if (proto == "udp" and payload.port == openvpn_udp_port) or (proto == "tcp" and payload.port == openvpn_tcp_port):
            raise HTTPException(400, "این پورت، پورت اصلی OpenVPN برای همین پروتکل است و نباید دوباره به‌عنوان پورت اضافه ثبت شود")
        # Reuse the same transport-aware listener inventory as the main
        # protocol editor.  This prevents an extra OpenVPN listener from
        # stealing the panel, OpenConnect, SSTP, strongSwan, or a primary
        # OpenVPN port.  Existing extra-port rows are handled immediately
        # below, so excluding that category here avoids rejecting a legitimate
        # reactivation of the same pool entry.
        _check_listener_conflict(db, payload.port, proto, {"openvpn_extra"})

        if proto == "udp" and payload.port == l2tp_port:
            raise HTTPException(400, "این پورت همین الان برای L2TP/IPsec استفاده می‌شود")
        if proto == "tcp" and payload.port == 1723:
            raise HTTPException(400, "پورت 1723/TCP برای PPTP رزرو است")

        existing = (
            db.query(OpenvpnExtraPort)
            .filter(OpenvpnExtraPort.port == payload.port, OpenvpnExtraPort.protocol == proto)
            .first()
        )
        if existing and existing.is_active:
            already_active.append(proto)
            continue

        if existing:
            # این پورت/پروتکل قبلاً در استخر بوده و غیرفعال شده - به‌جای ساخت یک
            # ردیف تکراری، همان ردیف را دوباره فعال می‌کنیم (کانفیگ کاربران از قبل
            # همین شماره‌پورت را دارد، پس چیزی برایشان تغییر نمی‌کند).
            existing.is_active = True
            reactivated_rows.append(existing)
        else:
            row = OpenvpnExtraPort(port=payload.port, protocol=proto, is_active=True)
            db.add(row)
            new_rows.append(row)

    if not new_rows and not reactivated_rows:
        # یعنی همه‌ی پروتکل‌های درخواستی (یک یا هردوی TCP/UDP) از قبل فعال بودند.
        msg = "این پورت با همین پروتکل قبلاً اضافه شده"
        if payload.protocol == "both":
            msg = "این پورت با هر دو پروتکل TCP و UDP قبلاً اضافه شده"
        raise HTTPException(400, msg)
    db.commit()

    ok, log = _sync_extra_ports(db)
    if not ok:
        # اسکریپت مدیریت پورت‌ها به‌ازای هر پورت/پروتکل شکست‌خورده یک خط
        # "FAILED: <port>/<proto> - ..." چاپ می‌کند. از روی همین خط‌ها دقیقاً
        # مشخص می‌کنیم کدام‌یک از پروتکل‌های همین درخواست واقعاً شکست خورده - تا
        # اگر مثلاً در حالت «هر دو»، فقط UDP شکست خورد ولی TCP بالا آمد، TCP را
        # (که واقعاً روی سرور فعال است) بی‌جهت از دیتابیس/پنل حذف نکنیم.
        failed_protocols = {
            proto for proto in protocols if f"FAILED: {payload.port}/{proto}" in log
        }
        # اگر به هر دلیلی (مثلاً timeout کل اسکریپت) نتوانستیم دقیق تشخیص بدهیم
        # کدام پروتکل شکست خورده، برای احتیاط همه‌ی پروتکل‌های همین درخواست را
        # rollback می‌کنیم - نه پورت/پروتکل‌های دیگری که این درخواست اصلاً لمسشان نکرده.
        if not failed_protocols:
            failed_protocols = set(protocols)
        succeeded_protocols = [p for p in protocols if p not in failed_protocols]

        for row in new_rows:
            if row.protocol in failed_protocols:
                db.delete(row)
        for row in reactivated_rows:
            if row.protocol in failed_protocols:
                row.is_active = False
        db.commit()
        # توجه: اینجا دیگر sync دوباره صدا زده نمی‌شود - همان اجرای بالا قبلاً
        # پروتکل(های) موفق را هم واقعاً بالا آورده و پورت/پروتکل‌های دیگرِ استخر را
        # هم از نو ساخته؛ صدازدن دوباره فقط یک ری‌استارت غیرضروری و پرریسک روی
        # چیزهایی است که همین الان درست کار می‌کنند.
        #
        # اسکریپت جدید دیگر پورت‌های سالم/دست‌نخورده را اصلاً لمس نمی‌کند، پس
        # طبیعتاً نباید هیچ پورت دیگری اینجا FAILED شده باشد - این فقط یک
        # لایه‌ی احتیاطیِ اضافه است: اگر باز هم (به هر دلیل نادری) پورت دیگری در
        # همین لاگ FAILED دیده شود، به‌جایِ نادیده گرفتنش، در دیتابیس هم
        # is_active=False می‌شود تا پنل هیچ‌وقت چیزی را «فعال» نشان ندهد که واقعاً
        # روی سرور مرده است.
        collateral = _mark_collateral_extra_port_failures(
            db, log, {(payload.port, p) for p in protocols}
        )
        detail = f"راه‌اندازی لیسنر OpenVPN برای پورت {payload.port} ({'/'.join(p.upper() for p in sorted(failed_protocols))}) ناموفق بود"
        if succeeded_protocols:
            detail += f" ({'/'.join(p.upper() for p in succeeded_protocols)} با موفقیت اضافه و فعال شد)"
        if collateral:
            detail += f" | هشدار: پورت(های) دیگر زیر هم روی سرور از کار افتاده بودند و در پنل غیرفعال شدند: {', '.join(collateral)}"
            log_event(
                "⚠️ خرابی جانبی پورت‌های اضافه‌ی OpenVPN حین افزودن پورت جدید",
                f"پورت(های) از کار افتاده: {', '.join(collateral)}",
                actor=admin.username,
            )
        detail += f". جزئیات: {log[-800:]}"
        raise HTTPException(500, detail)

    added_desc = "+".join(protocols)
    if already_active:
        added_desc += f" (پروتکل {'/'.join(p.upper() for p in already_active)} از قبل فعال بود)"
    log_event("➕ افزودن پورت اضافه‌ی OpenVPN", f"پورت: {payload.port}/{added_desc}", actor=admin.username)
    return db.query(OpenvpnExtraPort).order_by(OpenvpnExtraPort.is_active.desc(), OpenvpnExtraPort.port).all()


@router.post("/openvpn-ports/{port_id}/toggle", response_model=list[OpenvpnExtraPortOut])
def toggle_openvpn_port(
    port_id: int, db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin),
):
    ensure_protocol_permission(admin, "openvpn", "edit")
    """روشن/خاموش‌کردن یک پورت از استخر، بدون حذفش از دیتابیس یا از کانفیگ
    کاربران - همان تفاوتی که این قابلیت را با DELETE متمایز می‌کند (پایین)."""
    row = db.query(OpenvpnExtraPort).get(port_id)
    if not row:
        raise HTTPException(404, "پورت پیدا نشد")

    was_active = row.is_active
    if not was_active:
        _check_listener_conflict(db, row.port, row.protocol, {"openvpn_extra"})
    row.is_active = not was_active
    db.commit()

    ok, log = _sync_extra_ports(db)
    if not ok:
        row.is_active = was_active
        db.commit()
        collateral = _mark_collateral_extra_port_failures(
            db, log, {(row.port, row.protocol)}
        )
        action = "روشن" if not was_active else "خاموش"
        detail = f"{action}‌کردن لیسنر OpenVPN برای پورت {row.port}/{row.protocol.upper()} ناموفق بود (پورت‌های دیگر دست‌نخورده باقی ماندند)"
        if collateral:
            detail += f" | هشدار: پورت(های) دیگر زیر هم روی سرور از کار افتاده بودند و در پنل غیرفعال شدند: {', '.join(collateral)}"
            log_event(
                "⚠️ خرابی جانبی پورت‌های اضافه‌ی OpenVPN حین روشن/خاموش‌کردن پورت",
                f"پورت(های) از کار افتاده: {', '.join(collateral)}",
                actor=admin.username,
            )
        raise HTTPException(500, f"{detail}: {log[-800:]}")

    log_event(
        "🔌 روشن/خاموش‌کردن پورت اضافه‌ی OpenVPN",
        f"پورت: {row.port}/{row.protocol} | وضعیت تازه: {'فعال' if row.is_active else 'غیرفعال'}",
        actor=admin.username,
    )
    return db.query(OpenvpnExtraPort).order_by(OpenvpnExtraPort.is_active.desc(), OpenvpnExtraPort.port).all()


@router.delete("/openvpn-ports/{port_id}", response_model=list[OpenvpnExtraPortOut])
def delete_openvpn_port(
    port_id: int, db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)
):
    ensure_protocol_permission(admin, "openvpn", "edit")
    """حذف کامل از استخر - برخلاف toggle، این یعنی از این پس در کانفیگ‌های
    تازه هم دیگر نخواهد بود (برای پاک‌سازی پورت‌هایی که واقعاً دیگر لازم
    نیستند؛ برای خاموش‌کردن موقت از توگل بالا استفاده کن)."""
    row = db.query(OpenvpnExtraPort).get(port_id)
    if not row:
        raise HTTPException(404, "پورت پیدا نشد")
    port, proto = row.port, row.protocol
    db.delete(row)
    db.commit()

    ok, log = _sync_extra_ports(db)
    if not ok:
        raise HTTPException(500, f"پورت حذف شد ولی توقف لیسنر OpenVPN ناموفق بود: {log[-500:]}")

    log_event("🗑 حذف کامل پورت اضافه‌ی OpenVPN از استخر", f"پورت: {port}/{proto}", actor=admin.username)
    return db.query(OpenvpnExtraPort).order_by(OpenvpnExtraPort.is_active.desc(), OpenvpnExtraPort.port).all()
