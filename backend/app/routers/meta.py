from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.database import get_db
from app.config import get_settings
from app.models import Setting, Admin
from app.security import get_current_admin
from app.services.branding import asset_path, get_branding

router = APIRouter(prefix="/api/meta", tags=["meta"])

# مقادیر پیش‌فرض عنوان‌های سایت (همان چیزی که در index.html هاردکد بود)؛ هم
# اینجا برای اندپوینت عمومی و هم در routers/settings.py (فرم ویرایش ادمین)
# استفاده می‌شود.
DEFAULT_PANEL_TITLE = "پنل مدیریت VPN"
DEFAULT_SUB_TITLE = "وضعیت اشتراک"

# مقدار پیش‌فرض «برنامه‌های پیشنهادی برای اتصال» در صفحه‌ی عمومی ساب - همان
# چیزی که قبلاً هاردکد بود (SubPage.jsx). حالا فقط به‌عنوان مقدار اولیه/fallback
# استفاده می‌شود؛ ادمین می‌تواند از Settings > تنظیمات ساب متن هر دکمه و
# برنامه‌های زیرش را ویرایش کند (کلیدهای android/windows/ios/mac ثابت‌اند،
# چون آیکون هرکدام در فرانت‌اند بر همین اساس تعیین می‌شود).
DEFAULT_PLATFORM_APPS = {
    "android": {
        "label": "اندروید",
        "apps": [
            {"name": "V2rayNG", "desc": "کلاینت رایگان و محبوب برای OpenVPN/V2ray روی اندروید", "url": ""},
            {"name": "OpenVPN Connect", "desc": "کلاینت رسمی OpenVPN", "url": ""},
            {"name": "L2TP/IPsec PSK VPN", "desc": "اتصال L2TP/IPsec درون‌ساختی اندروید (تنظیمات > VPN)", "url": ""},
        ],
    },
    "windows": {
        "label": "ویندوز",
        "apps": [
            {"name": "OpenVPN Connect", "desc": "کلاینت رسمی OpenVPN برای ویندوز", "url": ""},
            {
                "name": "اتصال VPN داخلی ویندوز",
                "desc": "تنظیمات > شبکه و اینترنت > VPN، برای L2TP/IPsec، PPTP و SSTP (نوع VPN را روی SSTP بگذارید)",
                "url": "",
            },
        ],
    },
    "ios": {
        "label": "آیفون / آیپد (iOS)",
        "apps": [
            {"name": "OpenVPN Connect", "desc": "کلاینت رسمی OpenVPN از App Store", "url": ""},
            {"name": "اتصال VPN داخلی iOS", "desc": "تنظیمات > VPN، برای L2TP/IPsec", "url": ""},
        ],
    },
    "mac": {
        "label": "مک (macOS)",
        "apps": [
            {"name": "OpenVPN Connect", "desc": "کلاینت رسمی OpenVPN برای مک", "url": ""},
            {"name": "اتصال VPN داخلی macOS", "desc": "تنظیمات سیستم > VPN، برای L2TP/IPsec", "url": ""},
        ],
    },
}

PLATFORM_KEYS = ("android", "windows", "ios", "mac")


def _setting(db: Session, key: str):
    row = db.query(Setting).filter(Setting.key == key).first()
    return row.value if row else None


def get_platform_apps(db: Session) -> dict:
    """مقدار ذخیره‌شده‌ی ادمین (Settings > تنظیمات ساب > برنامه‌های پیشنهادی) را
    برمی‌گرداند؛ اگر چیزی ذخیره نشده یا JSON خراب/ناقص باشد، با احتیاط به مقدار
    پیش‌فرض برمی‌گردد تا صفحه‌ی عمومی ساب هیچ‌وقت با خطا مواجه نشود."""
    import json

    raw = _setting(db, "platform_apps_json")
    if not raw:
        return DEFAULT_PLATFORM_APPS
    try:
        data = json.loads(raw)
        result = {}
        for key in PLATFORM_KEYS:
            group = data.get(key) if isinstance(data, dict) else None
            if not isinstance(group, dict) or not group.get("label"):
                result[key] = DEFAULT_PLATFORM_APPS[key]
                continue
            apps = group.get("apps")
            if not isinstance(apps, list) or not apps:
                apps = DEFAULT_PLATFORM_APPS[key]["apps"]
            result[key] = {"label": group["label"], "apps": apps}
        return result
    except (ValueError, TypeError, AttributeError):
        return DEFAULT_PLATFORM_APPS


@router.get("/site-titles")
def site_titles(db: Session = Depends(get_db)):
    """اطلاعات عمومی و بدون نیاز به لاگین - فقط برای عنوان تب مرورگر صفحه‌ی
    ورود پنل و صفحه‌ی عمومی «ساب». هیچ اطلاعات حساسی برنمی‌گرداند، برای همین
    عمداً هیچ Depends احراز هویتی ندارد."""
    return {
        "panel_title": _setting(db, "panel_site_title") or DEFAULT_PANEL_TITLE,
        "sub_title": _setting(db, "sub_site_title") or DEFAULT_SUB_TITLE,
    }




@router.get("/branding")
def public_branding(db: Session = Depends(get_db)):
    """Public, non-sensitive visual identity used by Login and Layout."""
    return get_branding(db)


@router.get("/branding/{kind}")
def public_branding_asset(kind: str):
    path = asset_path(kind)
    if path is None:
        raise HTTPException(status_code=404, detail="branding asset not configured")
    media = {".png": "image/png", ".jpg": "image/jpeg", ".webp": "image/webp"}.get(path.suffix.lower(), "application/octet-stream")
    return FileResponse(path, media_type=media, headers={"Cache-Control": "public, max-age=86400"})

@router.get("/server-address")
def server_address(db: Session = Depends(get_db), admin: Admin = Depends(get_current_admin)):
    """آدرسی که کاربران باید برای اتصال L2TP/PPTP/OpenVPN استفاده کنند (دامنه‌ی
    اختصاصی پروتکل‌ها در صورت تنظیم و تایید، وگرنه IP خام سرور). عمداً برای هر
    ادمین لاگین‌شده در دسترس است (نه فقط کسی که دسترسی «تنظیمات» دارد)، چون در
    فرم ساخت کاربر VPN لازم است."""
    vpn_domain = _setting(db, "vpn_domain")
    vpn_domain_active = _setting(db, "vpn_domain_status") == "active"
    address = vpn_domain if (vpn_domain and vpn_domain_active) else get_settings().PUBLIC_SERVER_IP
    return {"server_address": address}
