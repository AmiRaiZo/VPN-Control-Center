from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import Admin
from app.schemas import (
    LicenseActivateRequest, LicenseStatusOut, LicenseReserveRequest, ReservedLicenseOut,
)
from app.models import AdminRole
from app.security import get_current_admin, require_superadmin
from app.services import license_manager
from app.services.telegram_notifier import log_event
from app.services.request_rate_limit import enforce_rate_limit

router = APIRouter(prefix="/api/license", tags=["license"])


@router.get("/status", response_model=LicenseStatusOut)
def status(include_queue_details: bool = False, db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    """هر ادمینی (نه فقط سوپرادمین) می‌تواند وضعیت را ببیند - چون وقتی
    پنل قفل است، فرانت‌اند باید بتواند به همه‌ی نقش‌ها نشان دهد که چرا،
    حتی اگر فقط سوپرادمین اجازه‌ی وارد کردن کد جدید را داشته باشد."""
    result = license_manager.get_status(
        db,
        include_queue_details=include_queue_details,
        include_key_full=admin.role == AdminRole.superadmin,
    )
    # پیام یک‌باره‌ی «لایسنس عوض شد» فقط به سوپرادمین نشان داده می‌شود - بقیه
    # ادمین‌ها اصلاً اجازه‌ی وارد کردن/رزرو کد لایسنس را ندارند.
    if admin.role == AdminRole.superadmin:
        result["switch_notice"] = license_manager.get_switch_notice(db)
    return result


@router.post("/switch-notice/ack")
def ack_switch_notice(db: Session = Depends(get_db), admin: Admin = Depends(require_superadmin)):
    """بعد از این‌که فرانت‌اند پیام یک‌باره‌ی «لایسنس عوض شد» را به سوپرادمین
    نشان داد، همین‌جا پاکش می‌کند تا دوباره نشان داده نشود."""
    license_manager.ack_switch_notice(db)
    return {"ok": True}


@router.post("/activate", response_model=LicenseStatusOut)
def activate(
    payload: LicenseActivateRequest,
    request: Request,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_superadmin),
):
    enforce_rate_limit(request, bucket="license-activate", limit=6, window_seconds=600, identity=payload.key)
    try:
        result = license_manager.activate_license(db, payload.key)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    status_str = result.get("status", "unknown")
    action = result.get("activation_action")
    log_event(
        "🗓️ رزرو خودکار لایسنس بعدی" if action == "reserved" else ("🔑 فعال‌سازی کد لایسنس" if status_str in ("active", "expiring_soon") else "❌ کد لایسنس نامعتبر"),
        f"وضعیت: {status_str} | اقدام: {action or 'failed'}",
        actor=admin.username,
    )
    if status_str == "not_found":
        raise HTTPException(status_code=400, detail="این کد لایسنس معتبر نیست.")
    if status_str == "expired":
        raise HTTPException(status_code=400, detail="این کد لایسنس منقضی شده است.")
    if status_str == "unreachable":
        raise HTTPException(status_code=502, detail="ارتباط با سرور لایسنس برقرار نشد. دوباره تلاش کنید.")
    if status_str == "ip_mismatch":
        raise HTTPException(
            status_code=400,
            detail="این کد لایسنس روی سرور دیگری فعال است. برای انتقال به این سرور، اول از پنل لایسنس روی «ریست لایسنس» بزنید.",
        )
    if status_str == "ip_banned":
        raise HTTPException(status_code=403, detail="آی‌پی این سرور مسدود شده است.")
    if status_str == "reserved_for_other_server":
        raise HTTPException(status_code=400, detail="این کد لایسنس از قبل توسط سرور دیگری رزرو شده است.")
    if status_str == "not_activated":
        raise HTTPException(status_code=400, detail="این کد هنوز قابل فعال‌سازی نیست. وضعیت آن را در سرور لایسنس بررسی کنید.")

    return result


@router.get("/reserved", response_model=list[ReservedLicenseOut])
def reserved(db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    """صف لایسنس‌های رزروشده - هر ادمینی می‌تواند ببیند، فقط سوپرادمین
    می‌تواند اضافه کند. عمداً هیچ endpoint حذفی وجود ندارد."""
    return license_manager.list_reserved_licenses(db)


@router.post("/reserve", response_model=list[ReservedLicenseOut])
def reserve(
    payload: LicenseReserveRequest,
    db: Session = Depends(get_db),
    admin: Admin = Depends(require_superadmin),
):
    """کد لایسنس جدید را برای «بعد از تمام شدن لایسنس فعلی» رزرو می‌کند -
    برخلاف /activate، همین الان جایگزین لایسنس فعال فعلی نمی‌شود؛ در صف
    می‌ماند تا خودکار و بدون قطعی، دقیقاً همان لحظه‌ای که لایسنس فعلی منقضی
    شود جایش را بگیرد (نگاه کنید به license_manager.refresh_license_status)."""
    try:
        result = license_manager.add_reserved_license(db, payload.key)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    log_event(
        "🗓️ رزرو لایسنس بعدی",
        f"کد: {license_manager.mask_key(payload.key.strip().lower())}",
        actor=admin.username,
    )
    return result
