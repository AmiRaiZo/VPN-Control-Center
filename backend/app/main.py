import logging
import traceback
import time
import threading
import hmac
import uuid

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import jwt
from jwt.exceptions import PyJWTError as JWTError

from app.database import Base, engine, SessionLocal
from app.models import Admin, AdminRole, BannedIP
from app.migrations import run_migrations
from app.routers import auth, users, dashboard, vpn, settings, admins, meta, sub, ip_bans, internet_blocks, backup, nodes, license as license_router
from app.services import license_manager
from app.services.scheduler import start_scheduler
from app.services.vpn_manager import sync_ip_bans, sync_internet_blocks
from app.config import get_settings
from app.services.security_hardening import parse_csv, validate_runtime_security
from app.services.node_manager import panel_ui_server_role
from app.client_ip import request_client_ip

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vpn-panel")

# Validate deployment secrets and fail-closed license configuration before any
# migration, scheduler or network-facing application state is initialized.
_runtime_settings = get_settings()
validate_runtime_security(_runtime_settings)

Base.metadata.create_all(bind=engine)
run_migrations(engine)

# A node restored from an old backup may carry the controller's local-server
# assignment switch as disabled. Managed rows were explicitly pushed to this
# host, so local daemons must accept them regardless of that stale controller
# preference. Repair it at every node API start before any VPN hook arrives.
try:
    from app.services.node_manager import is_node_installation
    from app.services.server_targets import set_local_assignment_enabled

    _node_boot_db = SessionLocal()
    try:
        if is_node_installation(_node_boot_db):
            set_local_assignment_enabled(_node_boot_db, True)
            _node_boot_db.commit()
    finally:
        _node_boot_db.close()
except Exception:
    logger.exception("Could not repair node-local user assignment state at startup")

app = FastAPI(title="VPN Panel API", version="2.4.0")

_cors_origins = parse_csv(_runtime_settings.CORS_ALLOWED_ORIGINS)
if _cors_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=_cors_origins,
        allow_credentials=bool(_runtime_settings.CORS_ALLOW_CREDENTIALS),
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Node-Token", "X-Internal-Token"],
        max_age=600,
    )


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "same-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if str(request.url.path or "").startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response

# Reject banned browser/API addresses before authentication, licensing, or any
# route handler runs. Node-agent and localhost lifecycle hooks are deliberately
# exempt so banning an end-user address cannot disconnect controller traffic.
_IP_BAN_EXEMPT_PREFIXES = ("/api/node-agent/", "/api/internal/", "/api/health")


@app.middleware("http")
async def ip_ban_middleware(request: Request, call_next):
    path = str(request.url.path or "")
    if not path.startswith("/api/") or path.startswith(_IP_BAN_EXEMPT_PREFIXES):
        return await call_next(request)

    client_ip = request_client_ip(request)
    db = SessionLocal()
    try:
        banned = (
            client_ip != "نامشخص"
            and db.query(BannedIP.id).filter(BannedIP.ip_address == client_ip).first() is not None
        )
    except Exception:
        logger.exception("خطا هنگام بررسی بن آی‌پی در middleware")
        banned = False
    finally:
        db.close()

    request.state.panel_ip_ban_checked = True
    if banned:
        return JSONResponse(
            status_code=403,
            content={"detail": "ip_banned", "message": "این آی‌پی اجازه دسترسی به پنل را ندارد."},
            headers={"X-VPN-Panel-Ban": "ip", "Cache-Control": "no-store"},
        )
    return await call_next(request)

# مسیرهایی که حتی وقتی لایسنس قفل است هم باید کار کنند: لاگین (تا بتوانند
# اصلاً وارد شوند)، وضعیت/فعال‌سازی لایسنس (خود فرم رفع قفل)، و health چک.
_LICENSE_EXEMPT_PATHS = ("/api/auth/login", "/api/license/", "/api/meta/", "/api/health")


@app.middleware("http")
async def license_lock_middleware(request: Request, call_next):
    path = request.url.path
    if not path.startswith("/api/") or path.startswith(_LICENSE_EXEMPT_PATHS):
        return await call_next(request)

    db = SessionLocal()
    try:
        locked = license_manager.is_locked(db)
    except Exception:
        logger.exception("خطا هنگام چک وضعیت قفل لایسنس در middleware")
        locked = bool(get_settings().LICENSE_FAIL_CLOSED)
    finally:
        db.close()

    if locked:
        return JSONResponse(
            status_code=402,
            content={"detail": "license_locked", "message": "لایسنس این پنل منقضی شده یا نامعتبر است."},
        )
    return await call_next(request)

# A node installation is remotely managed by its controller.  Keep only login,
# licensing and admin-account endpoints available locally; Node Agent remains
# open to the authenticated controller. The short cache prevents one DB query
# for every polling/static API request on mobile.
_NODE_ALLOWED_PREFIXES = ("/api/auth", "/api/license", "/api/meta", "/api/node-agent", "/api/settings/panel-port", "/api/settings/node-ssh", "/api/settings/node-controller", "/api/health")
_NODE_ROLE_CACHE = {"value": "main", "at": 0.0}
_NODE_ROLE_LOCK = threading.Lock()


def _cached_server_role() -> str:
    now = time.monotonic()
    if now - float(_NODE_ROLE_CACHE.get("at") or 0) < 2.0:
        return str(_NODE_ROLE_CACHE.get("value") or "main")
    with _NODE_ROLE_LOCK:
        if now - float(_NODE_ROLE_CACHE.get("at") or 0) < 2.0:
            return str(_NODE_ROLE_CACHE.get("value") or "main")
        db = SessionLocal()
        try:
            value = panel_ui_server_role(db)
        except Exception:
            value = "main"
        finally:
            db.close()
        _NODE_ROLE_CACHE.update(value=value, at=now)
        return value


def _node_request_superadmin_payload(request: Request) -> dict | None:
    """Validate an active superadmin browser/internal token on a node."""
    authorization = str(request.headers.get("authorization") or "")
    if not authorization.lower().startswith("bearer "):
        return None
    token = authorization.split(None, 1)[1].strip()
    if not token:
        return None
    try:
        settings = get_settings()
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        username = str(payload.get("sub") or "").strip()
        if not username:
            return None
    except JWTError:
        return None
    db = SessionLocal()
    try:
        admin = db.query(Admin).filter(Admin.username == username).first()
        if not admin or not admin.is_active or admin.role != AdminRole.superadmin:
            return None
        return dict(payload)
    except Exception:
        return None
    finally:
        db.close()


def _node_request_has_superadmin(request: Request) -> bool:
    return _node_request_superadmin_payload(request) is not None


def _node_remote_control_allowed(request: Request) -> bool:
    """Allow the one-time controller handoff session to use the full node API.

    Direct node logins remain deliberately minimal. Only the short-lived JWT
    created by ``/api/auth/node-handoff/consume`` carries ``remote_control``.
    """
    payload = _node_request_superadmin_payload(request)
    return bool(payload and payload.get("remote_control") is True)


def _node_internal_vpn_hook_allowed(request: Request) -> bool:
    """Allow authenticated localhost VPN lifecycle hooks while in node mode.

    PPP/OpenVPN/OpenConnect hooks call ``/api/internal/*`` over loopback after
    transport authentication succeeds.  Node-role middleware must not reject
    that local hop as a browser/admin request, otherwise the admission helper
    interprets the 423 response as an explicit denial and immediately kills
    every freshly established tunnel.
    """
    path = str(request.url.path or "")
    if not path.startswith("/api/internal/"):
        return False
    client_host = str(getattr(getattr(request, "client", None), "host", "") or "").strip().lower()
    if client_host not in {"127.0.0.1", "::1", "localhost"}:
        return False
    supplied = str(request.headers.get("x-internal-token") or "")
    expected = str(get_settings().INTERNAL_API_TOKEN or "")
    return bool(supplied and expected and hmac.compare_digest(supplied, expected))


def _node_internal_controller_proxy_allowed(request: Request) -> bool:
    """Allow only the Node Agent's signed localhost hop through node-mode guard.

    The controller calls ``/api/node-agent/protocol-proxy`` with the node token.
    That endpoint then performs the requested normal admin API call against the
    local backend using a short-lived superadmin JWT.  Without this narrowly
    scoped bypass, the second localhost request is rejected by node-role
    middleware as ``node_managed_by_controller`` before it reaches the protocol
    router.  Requiring loopback, an explicit internal marker and a valid active
    superadmin token prevents ordinary browser/API traffic from bypassing node
    restrictions.
    """
    client_host = str(getattr(getattr(request, "client", None), "host", "") or "").strip().lower()
    if client_host not in {"127.0.0.1", "::1", "localhost"}:
        return False
    if str(request.headers.get("x-node-internal-proxy") or "") != "1":
        return False
    return _node_request_has_superadmin(request)


@app.middleware("http")
async def node_role_middleware(request: Request, call_next):
    path = request.url.path
    if path.startswith("/api/") and not path.startswith(_NODE_ALLOWED_PREFIXES):
        if (
            _cached_server_role() == "node"
            and not _node_internal_vpn_hook_allowed(request)
            and not _node_internal_controller_proxy_allowed(request)
            and not _node_remote_control_allowed(request)
        ):
            return JSONResponse(
                status_code=423,
                content={"detail": "node_managed_by_controller", "message": "این سرور در حالت نود است و از پنل اصلی مدیریت می‌شود."},
            )
    return await call_next(request)


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    """
    قبلاً یک خطای پیش‌بینی‌نشده (مثلاً عدم دسترسی نوشتن روی /etc/ppp/chap-secrets)
    باعث می‌شد پاسخ بدون بدنه‌ی JSON برگردد و فرانت‌اند هیچ پیامی نشان ندهد
    (به همین دلیل ساخت کاربر «بی‌صدا» شکست می‌خورد). این هندلر تضمین می‌کند هر
    خطایی همیشه با detail مشخص برگردد و در لاگ سرور هم ثبت شود.
    """
    incident_id = uuid.uuid4().hex[:12]
    logger.error(
        "Unhandled error [%s] on %s %s:\n%s",
        incident_id, request.method, request.url.path, traceback.format_exc(),
    )
    return JSONResponse(
        status_code=500,
        content={
            "detail": "خطای داخلی سرور رخ داد. شناسه خطا را برای پشتیبانی نگه دارید.",
            "incident_id": incident_id,
        },
        headers={"Cache-Control": "no-store"},
    )


app.include_router(auth.router)
app.include_router(users.router)
app.include_router(dashboard.router)
app.include_router(vpn.router)
app.include_router(settings.router)
app.include_router(admins.router)
app.include_router(meta.router)
app.include_router(sub.router)
app.include_router(ip_bans.router)
app.include_router(internet_blocks.router)
app.include_router(backup.router)
app.include_router(nodes.router)
app.include_router(nodes.agent_router)
app.include_router(license_router.router)

_scheduler = None


@app.on_event("startup")
def on_startup():
    global _scheduler
    validate_runtime_security(get_settings())

    # A legacy central update briefly switched a node to main mode.  If the
    # service restarted before the controller could send the cleanup call, the
    # node used to remain a full main panel.  Repair that durable interrupted
    # state before serving requests or starting background jobs.
    db = SessionLocal()
    try:
        from app.services.node_manager import ensure_deployment_identity, repair_orphaned_node_role
        repair_orphaned_node_role(db)
        ensure_deployment_identity(db)
    except Exception:
        db.rollback()
        logger.exception("خطا در بازیابی نقش نود پس از آپدیت موقت")
    finally:
        db.close()

    db = SessionLocal()
    try:
        sync_ip_bans(db)
        sync_internet_blocks(db)
    except Exception:
        logger.exception("خطا در بازسازی قوانین آی‌پی‌های مسدود/اینترنت قطع‌شده هنگام استارت")
    finally:
        db.close()

    # Warm the expensive protocol/system snapshot before an administrator opens
    # the Protocols page.  This runs in a daemon thread and never delays API
    # startup, while making the first page visit use a ready snapshot.
    try:
        settings.warm_protocol_center_cache()
    except Exception:
        logger.exception("خطا در پیش‌گرم‌کردن کش وضعیت پروتکل‌ها")

    # چک اولیه‌ی لایسنس همین حالای استارت (نه صبر تا اولین tick شمارشگر) - تا
    # اگر سرویس ری‌استارت شد و لایسنس در این فاصله منقضی شده بود، بلافاصله
    # قفل شود، نه فقط بعد از LICENSE_CHECK_INTERVAL_SECONDS.
    db = SessionLocal()
    try:
        license_manager.refresh_license_status(db)
    except Exception:
        logger.exception("خطا در چک اولیه‌ی لایسنس هنگام استارت")
    finally:
        db.close()

    db = SessionLocal()
    try:
        from app.services.admin_license_manager import enforce_expirations
        enforce_expirations(db)
    except Exception:
        logger.exception("خطا در بررسی اولیه انقضای لایسنس‌های داخلی ادمین")
    finally:
        db.close()

    db = SessionLocal()
    try:
        from app.services.xray_manager import sync_xray_users
        sync_xray_users(db, protocols=("vmess", "vless"), restart=False)
    except Exception:
        logger.info("Xray نصب نیست یا کانفیگ آن هنوز آماده نشده است")
    finally:
        db.close()

    # Scheduler and node polling are deliberately kept
    # out of the Uvicorn API process on production installs.  Those jobs perform
    # systemctl/SSH/HTTP/management-socket work and previously occupied the only
    # API worker long enough for VPN hooks to receive http=000 and report
    # AUTH_FAILED.  RUN_BACKGROUND_JOBS is fail-safe False by default; development launches may
    # opt in explicitly, while production runs the dedicated
    # vpn-panel-background service instead.
    if get_settings().RUN_BACKGROUND_JOBS:
        _scheduler = start_scheduler()
    else:
        logger.info("Background scheduler disabled in API process; dedicated service is responsible")


@app.get("/api/health")
def health():
    return {"status": "ok"}
