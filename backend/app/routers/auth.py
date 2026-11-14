import json
from datetime import datetime
from html import escape

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.client_ip import ClientAddresses, request_client_addresses, request_client_ip
from app.models import Admin, AdminRole, AdminAccessLicense, BannedIP
from app.schemas import LoginRequest, TokenResponse, MeOut, ChangeCredentialsRequest, AdminRegisterRequest, AdminLicenseInfoRequest, AdminLicenseInfoOut
from app.security import verify_password, hash_password, create_access_token, get_current_admin, get_current_admin_allow_locked
from app.services.telegram_notifier import log_event
from app.services.admin_license_manager import apply_license, is_expired, lock_admin
from app.services.node_admin_handoff import consume_handoff
from app.services.node_remote import encrypt_password
from app.services.node_manager import panel_ui_server_role
from app.services.request_rate_limit import clear_rate_limit, enforce_rate_limit

router = APIRouter(prefix="/api/auth", tags=["auth"])


def _server_role(db: Session) -> str:
    return panel_ui_server_role(db)


def _permissions_list(admin: Admin) -> list[str]:
    if admin.role == AdminRole.superadmin:
        from app.models import ADMIN_SECTIONS, ADMIN_PERMISSION_TOKENS
        return list(dict.fromkeys([*ADMIN_SECTIONS, *ADMIN_PERMISSION_TOKENS]))
    return [p for p in (admin.permissions or "").split(",") if p]


def _request_ip(request: Request) -> str:
    return request_client_ip(request)


def _request_addresses(request: Request) -> ClientAddresses:
    return request_client_addresses(request)


def _login_log_text(username: str, addresses: ClientAddresses | str, extra: str | None = None) -> str:
    if isinstance(addresses, ClientAddresses):
        ipv4 = addresses.ipv4
        ipv6 = addresses.ipv6
    else:
        try:
            parsed = __import__("ipaddress").ip_address(str(addresses or ""))
            ipv4 = str(parsed) if parsed.version == 4 else None
            ipv6 = str(parsed) if parsed.version == 6 else None
        except ValueError:
            ipv4 = None
            ipv6 = None
    lines = [
        f"👤 یوزرنیم: <code>{escape(str(username or '-'))}</code>",
        f"🌐 IPv4: <code>{escape(ipv4 or 'در دسترس نیست')}</code>",
    ]
    if ipv6:
        lines.append(f"🌐 IPv6: <code>{escape(ipv6)}</code>")
    if extra:
        lines.append(extra)
    return "\n".join(lines)


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    enforce_rate_limit(request, bucket="auth-login-ip", limit=12, window_seconds=300)
    enforce_rate_limit(request, bucket="auth-login-user", limit=6, window_seconds=300, identity=payload.username)
    # مقایسه‌ی یوزرنیم نسبت به حروف بزرگ/کوچک حساس است (ستون با کالیشن
    # utf8mb4_bin)، یعنی "Admin" با "admin" دو حساب متفاوت‌اند.
    addresses = _request_addresses(request)
    blocked_address = next((value for value in addresses.all if db.query(BannedIP.id).filter(BannedIP.ip_address == value).first()), None)
    if blocked_address:
        log_event("⛔ ورود مسدودشده با آی‌پی بن‌شده", _login_log_text(payload.username, addresses))
        raise HTTPException(status_code=403, detail="ip_banned")
    admin = db.query(Admin).filter(Admin.username == payload.username).first()
    if not admin or not verify_password(payload.password, admin.password_hash):
        log_event("❌ ورود ناموفق", _login_log_text(payload.username, addresses))
        raise HTTPException(status_code=401, detail="نام کاربری یا رمز ورود اشتباه است")
    if not admin.is_active:
        log_event("❌ ورود ناموفق (حساب غیرفعال)", _login_log_text(admin.username, addresses))
        raise HTTPException(status_code=403, detail="حساب غیرفعال است")

    internal_required = bool(is_expired(admin))
    if internal_required and not bool(getattr(admin, "license_locked", False)):
        try:
            lock_admin(db, admin, disconnect=True)
        except Exception:
            db.rollback()
    admin.last_login_at = datetime.utcnow()
    if admin.role == AdminRole.admin:
        admin.password_vault_enc = encrypt_password(payload.password)
    db.add(admin)
    db.commit()
    log_event(
        "✅ ورود موفق",
        _login_log_text(admin.username, addresses, f"🛡 نقش: <code>{escape(admin.role.value)}</code>"),
    )
    clear_rate_limit(request, bucket="auth-login-user", identity=payload.username)
    token = create_access_token({"sub": admin.username, "role": admin.role.value})
    return TokenResponse(
        access_token=token,
        username=admin.username,
        role=admin.role.value,
        permissions=_permissions_list(admin),
        internal_license_required=internal_required,
        server_role=_server_role(db),
    )


@router.post("/register/license-info", response_model=AdminLicenseInfoOut)
def register_license_info(payload: AdminLicenseInfoRequest, request: Request, db: Session = Depends(get_db)):
    enforce_rate_limit(request, bucket="auth-license-info-ip", limit=15, window_seconds=600)
    enforce_rate_limit(request, bucket="auth-license-code", limit=6, window_seconds=600, identity=payload.license_code)
    row = db.query(AdminAccessLicense).filter(AdminAccessLicense.code == payload.license_code).first()
    if not row or not row.is_active or row.used_by_admin_id is not None:
        raise HTTPException(400, "این لایسنس معتبر یا قابل استفاده نیست")
    bot_username = None
    bot_link = None
    if bool(getattr(row, "telegram_bot_enabled", False)):
        try:
            from app.services.telegram_notifier import call_telegram_api, get_telegram_config
            cfg = get_telegram_config(db)
            ok, result = call_telegram_api(cfg.get("bot_token") or "", "getMe", data={})
            if ok and isinstance(result, dict):
                bot_username = str(result.get("username") or "").strip() or None
                if bot_username:
                    bot_link = f"https://t.me/{bot_username}"
        except Exception:
            pass
    role = getattr(row, "role", AdminRole.admin) or AdminRole.admin
    role_value = role.value if isinstance(role, AdminRole) else str(role)
    return AdminLicenseInfoOut(
        role=role_value,
        telegram_bot_enabled=bool(getattr(row, "telegram_bot_enabled", False)),
        telegram_user_id_required=False,
        preset_telegram_user_id=None,
        bot_username=bot_username,
        bot_link=bot_link,
    )


@router.post("/register", response_model=TokenResponse)
def register(payload: AdminRegisterRequest, request: Request, db: Session = Depends(get_db)):
    addresses = _request_addresses(request)
    enforce_rate_limit(request, bucket="auth-register-ip", limit=8, window_seconds=900)
    enforce_rate_limit(request, bucket="auth-register-code", limit=4, window_seconds=900, identity=payload.license_code)
    enforce_rate_limit(request, bucket="auth-register-user", limit=4, window_seconds=900, identity=payload.username)
    if db.query(Admin).filter(Admin.username == payload.username).first():
        raise HTTPException(400, "این نام کاربری قبلاً استفاده شده است")
    license_row = db.query(AdminAccessLicense).filter(AdminAccessLicense.code == payload.license_code).with_for_update().first()
    if not license_row:
        raise HTTPException(400, "کد لایسنس داخلی نامعتبر است؛ حروف بزرگ و کوچک مهم هستند")
    if not license_row.is_active:
        raise HTTPException(400, "این لایسنس غیرفعال است")
    if license_row.used_by_admin_id is not None:
        raise HTTPException(400, "این لایسنس قبلاً استفاده شده است")
    telegram_capable = bool(getattr(license_row, "telegram_bot_enabled", False))
    telegram_enabled = telegram_capable and not bool(payload.telegram_bot_opt_out)
    if telegram_enabled and not payload.telegram_user_id:
        raise HTTPException(400, "برای فعال‌سازی ربات، آیدی عددی تلگرام الزامی است")
    if telegram_enabled and payload.telegram_user_id:
        duplicate = db.query(Admin).filter(Admin.telegram_user_id == payload.telegram_user_id).first()
        if duplicate:
            raise HTTPException(400, "این آیدی تلگرام قبلاً به حساب دیگری متصل شده است")
        duplicate_license = db.query(AdminAccessLicense).filter(
            AdminAccessLicense.telegram_user_id == payload.telegram_user_id,
            AdminAccessLicense.id != license_row.id,
        ).first()
        if duplicate_license:
            raise HTTPException(400, "این آیدی تلگرام قبلاً روی لایسنس دیگری ثبت شده است")
        if license_row.telegram_user_id not in (None, payload.telegram_user_id):
            raise HTTPException(400, "این لایسنس قبلاً به آیدی تلگرام دیگری متصل شده است")
        # The license row is the durable one-ID ownership record. apply_license
        # commits this value together with the new admin account.
        license_row.telegram_user_id = payload.telegram_user_id
    license_role = getattr(license_row, "role", AdminRole.admin) or AdminRole.admin
    if not isinstance(license_role, AdminRole):
        license_role = AdminRole(str(license_role))
    admin = Admin(
        username=payload.username,
        password_hash=hash_password(payload.password),
        password_vault_enc=encrypt_password(payload.password),
        role=license_role,
        permissions=license_row.permissions if license_role == AdminRole.admin else None,
        see_all_users=bool(license_row.see_all_users) if license_role == AdminRole.admin else False,
        is_active=True,
        managed_by_license=True,
        telegram_bot_enabled=telegram_enabled,
        telegram_user_id=payload.telegram_user_id if telegram_enabled else None,
        telegram_bot_opted_out=bool(telegram_capable and payload.telegram_bot_opt_out),
    )
    db.add(admin)
    db.flush()
    try:
        apply_license(db, admin, license_row)
    except ValueError as exc:
        db.rollback()
        raise HTTPException(400, str(exc))
    clear_rate_limit(request, bucket="auth-register-code", identity=payload.license_code)
    clear_rate_limit(request, bucket="auth-register-user", identity=payload.username)
    token = create_access_token({"sub": admin.username, "role": admin.role.value})
    log_event(
        "🪪 ثبت‌نام ادمین با لایسنس داخلی",
        "\n".join([
            f"👤 یوزرنیم: <code>{escape(admin.username)}</code>",
            f"🛡 نقش: <code>{escape(admin.role.value)}</code>",
            "🔑 رمز عبور: <b>توسط ادمین تعیین شد؛ برای امنیت در لاگ ذخیره نمی‌شود</b>",
            f"🤖 ربات خصوصی: <b>{'فعال' if admin.telegram_bot_enabled else 'غیرفعال'}</b>",
            f"🆔 آیدی تلگرام: <code>{escape(str(admin.telegram_user_id or '—'))}</code>",
            f"🌐 IPv4: <code>{escape(addresses.ipv4 or 'در دسترس نیست')}</code>",
            *([f"🌐 IPv6: <code>{escape(addresses.ipv6)}</code>"] if addresses.ipv6 else []),
        ]),
    )
    return TokenResponse(
        access_token=token, username=admin.username, role=admin.role.value,
        permissions=_permissions_list(admin), internal_license_required=False,
        server_role=_server_role(db),
    )


@router.get("/me", response_model=MeOut)
def me(db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin_allow_locked)):
    return MeOut(
        username=admin.username, role=admin.role.value, permissions=_permissions_list(admin),
        internal_license_required=bool(is_expired(admin)),
        managed_by_license=bool(getattr(admin, "managed_by_license", False)),
        server_role=_server_role(db),
    )


@router.put("/me")
def update_me(
    payload: ChangeCredentialsRequest,
    db: Session = Depends(get_db),
    admin: Admin = Depends(get_current_admin),
):
    if not verify_password(payload.current_password, admin.password_hash):
        raise HTTPException(status_code=401, detail="رمز عبور فعلی اشتباه است")

    old_username = admin.username
    username_changed = bool(payload.new_username and payload.new_username != admin.username)
    password_changed = bool(payload.new_password)

    if username_changed:
        exists = (
            db.query(Admin)
            .filter(Admin.username == payload.new_username, Admin.id != admin.id)
            .first()
        )
        if exists:
            raise HTTPException(status_code=400, detail="این نام کاربری قبلاً استفاده شده است")
        admin.username = payload.new_username

    if payload.new_password:
        admin.password_hash = hash_password(payload.new_password)
        if admin.role == AdminRole.admin:
            admin.password_vault_enc = encrypt_password(payload.new_password)

    db.commit()
    lines = [f"👤 ادمین: <code>{escape(old_username)}</code>"]
    if username_changed:
        lines.append(f"• نام کاربری: <b>{escape(old_username)}</b> ← <b>{escape(admin.username)}</b>")
    if password_changed:
        lines.append("• رمز عبور: <b>تغییر کرد؛ مقدار رمز برای امنیت در لاگ ذخیره نمی‌شود</b>")
    if len(lines) == 1:
        lines.append("• تغییری انجام نشد.")
    log_event("🔑 تغییر مشخصات ورود ادمین", "\n".join(lines), actor=admin.username)
    return {"ok": True, "username": admin.username, "note": "برای اعمال کامل تغییرات دوباره وارد شوید"}


@router.get("/admin-handoff/consume", response_class=HTMLResponse, include_in_schema=False)
def consume_admin_handoff(
    ticket: str = Query(..., min_length=16, max_length=256),
    db: Session = Depends(get_db),
):
    payload = consume_handoff(db, ticket)
    if not payload or payload.get("kind") != "subadmin":
        return HTMLResponse(
            "<!doctype html><meta charset='utf-8'><title>Expired</title>"
            "<body style='font-family:sans-serif;background:#0b0d10;color:#fff;padding:40px'>"
            "<h2>لینک ورود ادمین منقضی یا قبلاً استفاده شده است.</h2>"
            "<p>از پنل سوپرادمین دوباره روی «ورود به پنل» بزنید.</p></body>",
            status_code=401,
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    target = db.query(Admin).filter(
        Admin.id == int(payload.get("admin_id") or 0),
        Admin.username == str(payload.get("username") or ""),
    ).first()
    if not target or not target.is_active or target.role != AdminRole.admin:
        return HTMLResponse(
            "<!doctype html><meta charset='utf-8'><body style='font-family:sans-serif;background:#0b0d10;color:#fff;padding:40px'>"
            "<h2>حساب ادمین زیرمجموعه معتبر یا فعال نیست.</h2></body>",
            status_code=401,
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    issued_by = str(payload.get("issued_by") or "superadmin")
    internal_required = bool(is_expired(target))
    session = {
        "token": create_access_token({
            "sub": target.username,
            "role": target.role.value,
            "impersonated_by": issued_by,
        }, expires_minutes=30),
        "role": target.role.value,
        "permissions": _permissions_list(target),
        "internal_license_required": internal_required,
        "server_role": _server_role(db),
        "redirect_path": payload.get("redirect_path") or "/dashboard",
        "username": target.username,
        "issued_by": issued_by,
    }
    log_event(
        "🚪 ورود مستقیم به پنل ادمین زیرمجموعه",
        f"👤 ادمین مقصد: <code>{escape(target.username)}</code>\n"
        f"🛡 سوپرادمین: <code>{escape(issued_by)}</code>\n"
        "• نشست ۳۰ دقیقه‌ای و یک‌بارمصرف ایجاد شد.",
        actor=issued_by,
    )
    serialized = json.dumps(session, ensure_ascii=False).replace("</", "<\\/")
    body = f"""<!doctype html>
<html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ورود به پنل ادمین</title></head>
<body style="font-family:system-ui;background:#0b0d10;color:#fff;display:grid;place-items:center;min-height:100vh;margin:0">
<div style="width:min(92vw,440px);border:1px solid #2a3038;background:#12161b;border-radius:18px;padding:24px;text-align:center;box-shadow:0 24px 70px #0008">
<div style="margin:auto;width:34px;height:34px;border:3px solid #343b44;border-top-color:#ff6b00;border-radius:999px;animation:spin .8s linear infinite"></div>
<h2 style="font-size:16px;margin:16px 0 8px">ورود به پنل {escape(target.username)}</h2>
<div id="handoff-status" style="color:#aeb6c2;font-size:13px">در حال ساخت نشست ادمین زیرمجموعه…</div>
<a id="handoff-link" href="#" style="display:none;margin-top:16px;align-items:center;justify-content:center;border:1px solid #ff6b00;color:#ff7b19;border-radius:10px;padding:9px 14px;text-decoration:none;font-size:12px">ورود به پنل</a>
</div><style>@keyframes spin{{to{{transform:rotate(360deg)}}}}</style>
<script>
const s={serialized};
try {{
  sessionStorage.setItem('vpn_panel_token', s.token);
  sessionStorage.setItem('vpn_panel_role', s.role);
  sessionStorage.setItem('vpn_panel_permissions', JSON.stringify(s.permissions || []));
  sessionStorage.setItem('vpn_panel_internal_license_required', s.internal_license_required ? '1' : '0');
  sessionStorage.setItem('vpn_panel_server_role', s.server_role === 'node' ? 'node' : 'main');
  sessionStorage.removeItem('vpn_panel_remote_control');
  sessionStorage.removeItem('vpn_panel_remote_node_name');
  sessionStorage.setItem('vpn_panel_impersonated_by', s.issued_by || 'superadmin');
  sessionStorage.setItem('vpn_panel_impersonated_username', s.username || 'admin');
  const target = s.redirect_path || '/dashboard';
  document.getElementById('handoff-status').textContent = 'نشست آماده شد؛ در حال ورود…';
  window.setTimeout(() => window.location.replace(target), 40);
  window.setTimeout(() => {{
    const link = document.getElementById('handoff-link');
    if (link) {{ link.href = target; link.style.display = 'inline-flex'; }}
  }}, 1600);
}} catch (error) {{
  document.getElementById('handoff-status').textContent='ورود خودکار ناموفق بود: ' + (error && error.message ? error.message : 'خطای مرورگر');
  const link = document.getElementById('handoff-link');
  if (link) {{ link.href='/dashboard'; link.style.display='inline-flex'; }}
}}
</script></body></html>"""
    return HTMLResponse(body, headers={
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Pragma": "no-cache",
        "Referrer-Policy": "no-referrer",
        "X-Frame-Options": "DENY",
    })


@router.get("/node-handoff/consume", response_class=HTMLResponse, include_in_schema=False)
def consume_node_handoff(
    ticket: str = Query(..., min_length=16, max_length=256),
    db: Session = Depends(get_db),
):
    payload = consume_handoff(db, ticket)
    if not payload:
        return HTMLResponse(
            "<!doctype html><meta charset='utf-8'><title>Expired</title>"
            "<body style='font-family:sans-serif;background:#0b0d10;color:#fff;padding:40px'>"
            "<h2>لینک ورود نود منقضی یا قبلاً استفاده شده است.</h2>"
            "<p>از پنل اصلی دوباره روی «مدیریت پنل نود» بزنید.</p></body>",
            status_code=401,
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    target = db.query(Admin).filter(Admin.username == str(payload.get("username") or "")).first()
    if not target or not target.is_active or target.role != AdminRole.superadmin:
        return HTMLResponse(
            "<!doctype html><meta charset='utf-8'><body style='font-family:sans-serif;background:#0b0d10;color:#fff;padding:40px'>"
            "<h2>حساب ادمین نود معتبر نیست.</h2></body>",
            status_code=401,
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )
    session = {
        "token": create_access_token({
            "sub": target.username,
            "role": target.role.value,
            "remote_control": True,
        }, expires_minutes=30),
        "role": target.role.value,
        "permissions": _permissions_list(target),
        "internal_license_required": False,
        "server_role": _server_role(db),
        "redirect_path": payload.get("redirect_path") or "/dashboard",
        "node_name": str(payload.get("node_name") or "Node"),
    }
    serialized = json.dumps(session, ensure_ascii=False).replace("</", "<\\/")
    body = f"""<!doctype html>
<html lang="fa" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ورود به پنل نود</title></head>
<body style="font-family:system-ui;background:#0b0d10;color:#fff;display:grid;place-items:center;min-height:100vh;margin:0">
<div style="width:min(92vw,440px);border:1px solid #2a3038;background:#12161b;border-radius:18px;padding:24px;text-align:center;box-shadow:0 24px 70px #0008">
<div style="margin:auto;width:34px;height:34px;border:3px solid #343b44;border-top-color:#ff6b00;border-radius:999px;animation:spin .8s linear infinite"></div>
<h2 style="font-size:16px;margin:16px 0 8px">پنل نود</h2>
<div id="handoff-status" style="color:#aeb6c2;font-size:13px">در حال آماده‌سازی نشست مدیریت نود…</div>
<a id="handoff-link" href="#" style="display:none;margin-top:16px;align-items:center;justify-content:center;border:1px solid #ff6b00;color:#ff7b19;border-radius:10px;padding:9px 14px;text-decoration:none;font-size:12px">ورود به پنل نود</a>
</div><style>@keyframes spin{{to{{transform:rotate(360deg)}}}}</style>
<script>
const s={serialized};
try {{
  sessionStorage.setItem('vpn_panel_token', s.token);
  sessionStorage.setItem('vpn_panel_role', s.role);
  sessionStorage.setItem('vpn_panel_permissions', JSON.stringify(s.permissions || []));
  sessionStorage.setItem('vpn_panel_internal_license_required', s.internal_license_required ? '1' : '0');
  sessionStorage.setItem('vpn_panel_server_role', s.server_role === 'node' ? 'node' : 'main');
  sessionStorage.setItem('vpn_panel_remote_control', '1');
  sessionStorage.setItem('vpn_panel_remote_node_name', s.node_name || 'Node');
  const target = s.redirect_path || '/dashboard';
  document.getElementById('handoff-status').textContent = 'نشست آماده شد؛ در حال بازکردن پنل نود…';
  window.setTimeout(() => window.location.replace(target), 40);
  window.setTimeout(() => {{
    const link = document.getElementById('handoff-link');
    if (link) {{ link.href = target; link.style.display = 'inline-flex'; }}
  }}, 1600);
}} catch (error) {{
  document.getElementById('handoff-status').textContent='ورود خودکار ناموفق بود: ' + (error && error.message ? error.message : 'خطای مرورگر');
  const link = document.getElementById('handoff-link');
  if (link) {{ link.href='/dashboard'; link.style.display='inline-flex'; }}
}}
</script></body></html>"""
    return HTMLResponse(body, headers={
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Pragma": "no-cache",
        "Referrer-Policy": "no-referrer",
        "X-Frame-Options": "DENY",
    })
