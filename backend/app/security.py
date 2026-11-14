from datetime import datetime, timedelta
from typing import Optional
import jwt
from jwt.exceptions import PyJWTError as JWTError
from passlib.context import CryptContext
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.config import get_settings
from app.database import get_db
from app.client_ip import request_client_ip
from app.models import Admin, AdminRole, BannedIP

settings = get_settings()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict, expires_minutes: Optional[int] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(
        minutes=expires_minutes or settings.JWT_EXPIRE_MINUTES
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def get_current_admin_allow_locked(
    request: Request, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> Admin:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="اطلاعات ورود نامعتبر است",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM]
        )
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    if not bool(getattr(request.state, "panel_ip_ban_checked", False)):
        client_ip = request_client_ip(request)
        if client_ip != "نامشخص" and db.query(BannedIP.id).filter(BannedIP.ip_address == client_ip).first():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="ip_banned",
                headers={"X-VPN-Panel-Ban": "ip"},
            )

    admin = db.query(Admin).filter(Admin.username == username).first()
    if admin is None or not admin.is_active:
        raise credentials_exception
    return admin


def get_current_admin(
    admin: Admin = Depends(get_current_admin_allow_locked), db: Session = Depends(get_db)
) -> Admin:
    if bool(getattr(admin, "managed_by_license", False)):
        from app.services.admin_license_manager import is_expired, lock_admin
        if is_expired(admin):
            if not bool(getattr(admin, "license_locked", False)):
                try:
                    lock_admin(db, admin, disconnect=False)
                except Exception:
                    db.rollback()
            raise HTTPException(
                status_code=423,
                detail="subadmin_license_required",
                headers={"X-VPN-Panel-Lock": "internal-license"},
            )
    return admin


def require_superadmin(admin: Admin = Depends(get_current_admin)) -> Admin:
    if admin.role != AdminRole.superadmin:
        raise HTTPException(status_code=403, detail="دسترسی غیرمجاز")
    return admin


def can_view_all_users(admin: Admin) -> bool:
    """آیا این ادمین به کل یوزرهای VPN سرور (نه فقط یوزرهای خودش) دسترسی
    دارد؟ superadmin همیشه بله؛ ادمین زیرمجموعه فقط اگر see_all_users
    برایش فعال شده باشد."""
    return admin.role == AdminRole.superadmin or bool(admin.see_all_users)


def permission_set(admin: Admin) -> set[str]:
    return {p.strip() for p in (admin.permissions or "").split(",") if p.strip()}


def has_permission(admin: Admin, token: str, legacy_section: str | None = None) -> bool:
    if admin.role == AdminRole.superadmin:
        return True
    perms = permission_set(admin)
    if token in perms:
        return True
    section = legacy_section or token.split(":", 1)[0]
    # Legacy installations stored only broad section names. Keep those accounts
    # fully functional while newly-created admins can use fine-grained tokens.
    if section in perms:
        return True
    if ":" not in token and any(p.startswith(token + ":") for p in perms):
        return True
    return False


def ensure_permission(admin: Admin, token: str, legacy_section: str | None = None) -> None:
    if not has_permission(admin, token, legacy_section):
        raise HTTPException(status_code=403, detail="دسترسی لازم برای این عملیات فعال نشده است")


def admin_can_access_protocol(admin: Admin | None, protocol: str) -> bool:
    """Return whether a protocol may be revealed or managed by this admin.

    Legacy delegated admins that predate per-protocol scopes keep access to all
    protocols.  Once at least one ``protocol:*`` token exists, the scope becomes
    explicit and every other protocol must stay invisible to that account.
    """
    if admin is None or getattr(admin, "role", None) == AdminRole.superadmin:
        return True
    perms = permission_set(admin)
    if "settings" in perms or not any(p.startswith("protocol:") for p in perms):
        return True
    return f"protocol:{str(protocol or '').strip().lower()}" in perms


def visible_protocols(admin: Admin | None, protocols) -> list[str]:
    return [
        str(protocol).strip().lower()
        for protocol in protocols
        if str(protocol).strip() and admin_can_access_protocol(admin, str(protocol))
    ]


def ensure_protocol_permission(admin: Admin, protocol: str, capability: str = "view") -> None:
    ensure_permission(admin, f"protocols:{capability}", "settings")
    if not admin_can_access_protocol(admin, protocol):
        raise HTTPException(status_code=403, detail="این گزینه در محدوده دسترسی این حساب نیست")


def ensure_user_protocols(admin: Admin, protocols: set[str] | list[str] | tuple[str, ...]) -> None:
    """Prevent delegated admins from assigning protocols outside their scope.

    Legacy admins without protocol-specific tokens retain access to all protocols.
    """
    if admin.role == AdminRole.superadmin:
        return
    perms = permission_set(admin)
    scoped = {p.split(":", 1)[1] for p in perms if p.startswith("protocol:")}
    if "settings" in perms or not scoped:
        return
    denied = {str(p).lower() for p in protocols if str(p).lower() not in scoped}
    if denied:
        # Never echo hidden protocol names. A delegated admin must not be able
        # to infer which transports exist outside their own license scope.
        raise HTTPException(
            status_code=403,
            detail="یک یا چند گزینه انتخاب‌شده در محدوده دسترسی این حساب نیست",
        )


def require_permission(token: str, legacy_section: str | None = None):
    """FastAPI dependency supporting both legacy section permissions and granular tokens."""
    def _dependency(admin: Admin = Depends(get_current_admin)) -> Admin:
        ensure_permission(admin, token, legacy_section)
        return admin
    return _dependency
