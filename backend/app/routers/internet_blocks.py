from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Admin, InternetBlockedIP, VpnUser
from app.schemas import InternetBlockCreate, InternetBlockOut
from app.security import require_permission, can_view_all_users, ensure_permission
from app.services.telegram_notifier import log_event
from app.services.vpn_manager import block_internet_ip, restore_internet_ip
from app.services.node_manager import sync_global_controls_to_active_nodes_async

router = APIRouter(prefix="/api/internet-blocks", tags=["internet-blocks"])


def _out(row: InternetBlockedIP) -> InternetBlockOut:
    return InternetBlockOut(
        id=row.id,
        ip_address=row.ip_address,
        user_id=row.user_id,
        username=row.username,
        protocol=row.protocol,
        reason=row.reason,
        blocked_by=row.blocked_by_username,
        created_at=row.created_at,
    )


@router.get("", response_model=list[InternetBlockOut])
def list_internet_blocks(
    search: str | None = None,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("internet_blocks:view")),
):
    query = db.query(InternetBlockedIP)
    if not can_view_all_users(admin):
        query = query.filter(InternetBlockedIP.owner_admin_id == admin.id)
    if search:
        like = f"%{search.strip()}%"
        query = query.filter(
            (InternetBlockedIP.ip_address.like(like))
            | (InternetBlockedIP.username.like(like))
            | (InternetBlockedIP.protocol.like(like))
        )
    return [_out(row) for row in query.order_by(InternetBlockedIP.created_at.desc()).all()]


@router.post("", response_model=InternetBlockOut)
def create_internet_block(
    payload: InternetBlockCreate,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("online:disconnect", "online")),
):
    if db.query(InternetBlockedIP).filter(InternetBlockedIP.ip_address == payload.ip_address).first():
        raise HTTPException(400, "این آی‌پی از قبل در لیست اینترنت قطع‌شده‌هاست")

    user = None
    if payload.username:
        user = db.query(VpnUser).filter(VpnUser.username == payload.username.strip()).first()
        if not user:
            raise HTTPException(404, "کاربر پیدا نشد")
        if not can_view_all_users(admin) and user.owner_admin_id != admin.id:
            raise HTTPException(403, "به این کاربر دسترسی ندارید")

    row = block_internet_ip(
        db,
        payload.ip_address,
        user=user,
        username=payload.username.strip() if payload.username else None,
        reason=payload.reason,
        admin_id=admin.id,
        admin_username=admin.username,
        owner_admin_id=(user.owner_admin_id if user and user.owner_admin_id is not None else admin.id),
    )
    sync_global_controls_to_active_nodes_async()
    log_event(
        "⛔ قطع اینترنت عمومی آی‌پی",
        f"آی‌پی: {payload.ip_address}" + (f" | کاربر: {row.username}" if row.username else ""),
        actor=admin.username,
    )
    return _out(row)


@router.delete("/{ip_address}")
def restore_internet_block(
    ip_address: str,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("online:disconnect", "online")),
):
    row = db.query(InternetBlockedIP).filter(InternetBlockedIP.ip_address == ip_address).first()
    if not row:
        raise HTTPException(404, "این آی‌پی در لیست اینترنت قطع‌شده‌ها پیدا نشد")
    ensure_permission(admin, "internet_blocks:view")
    if not can_view_all_users(admin) and row.owner_admin_id != admin.id:
        raise HTTPException(403, "به این رکورد دسترسی ندارید")
    restore_internet_ip(db, ip_address)
    sync_global_controls_to_active_nodes_async(force_restore_ips=[ip_address])
    log_event("✅ وصل اینترنت عمومی آی‌پی", f"آی‌پی: {ip_address}", actor=admin.username)
    return {"ok": True}
