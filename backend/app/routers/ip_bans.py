from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Admin, BannedIP
from app.schemas import BannedIPCreate, BannedIPOut
from app.security import require_permission, can_view_all_users
from app.services.vpn_manager import ban_ip, unban_ip
from app.services.node_manager import sync_global_controls_to_active_nodes_async
from app.services.telegram_notifier import log_event

# همان بخش «online» صفحه‌ی کاربران آنلاین: این قابلیت مستقیماً زیر همان
# صفحه قرار می‌گیرد، پس نیازی به یک دسترسیِ قابل‌واگذاریِ جدا و جداگانه نیست.
router = APIRouter(prefix="/api/ip-bans", tags=["ip-bans"])


@router.get("", response_model=list[BannedIPOut])
def list_banned_ips(
    search: str | None = None,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("online")),
):
    query = db.query(BannedIP)
    if not can_view_all_users(admin):
        query = query.filter(BannedIP.owner_admin_id == admin.id)
    if search:
        like = f"%{search.strip()}%"
        query = query.filter(BannedIP.ip_address.like(like))
    rows = query.order_by(BannedIP.created_at.desc()).all()
    return [
        BannedIPOut(
            id=r.id,
            ip_address=r.ip_address,
            reason=r.reason,
            banned_by=r.banned_by_admin.username if r.banned_by_admin else None,
            created_at=r.created_at,
        )
        for r in rows
    ]


@router.post("", response_model=BannedIPOut)
def create_ban(
    payload: BannedIPCreate,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("online")),
):
    existing = db.query(BannedIP).filter(BannedIP.ip_address == payload.ip_address).first()
    if existing:
        raise HTTPException(400, "این آی‌پی از قبل مسدود شده است")
    record = ban_ip(db, payload.ip_address, payload.reason, admin.id, owner_admin_id=admin.id)
    sync_global_controls_to_active_nodes_async()
    log_event("🚫 مسدودسازی آی‌پی", f"آی‌پی: {payload.ip_address}" + (f" | دلیل: {payload.reason}" if payload.reason else ""), actor=admin.username)
    return BannedIPOut(
        id=record.id,
        ip_address=record.ip_address,
        reason=record.reason,
        banned_by=admin.username,
        created_at=record.created_at,
    )


@router.delete("/{ip_address}")
def delete_ban(
    ip_address: str,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_permission("online")),
):
    row = db.query(BannedIP).filter(BannedIP.ip_address == ip_address).first()
    if not row:
        raise HTTPException(404, "این آی‌پی در لیست مسدودها پیدا نشد")
    if not can_view_all_users(admin) and row.owner_admin_id != admin.id:
        raise HTTPException(403, "به این رکورد دسترسی ندارید")
    ok = unban_ip(db, ip_address)
    if not ok:
        raise HTTPException(404, "این آی‌پی در لیست مسدودها پیدا نشد")
    sync_global_controls_to_active_nodes_async(force_unban_ips=[ip_address])
    log_event("✅ رفع مسدودیت آی‌پی", f"آی‌پی: {ip_address}", actor=admin.username)
    return {"ok": True}
