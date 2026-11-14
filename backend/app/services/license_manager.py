"""
مدیریت لایسنس پنل.

منطق کلی:
- کلید لایسنسی که ادمین اصلی وارد می‌کند در جدول Setting ذخیره می‌شود
  (کلید "license_key")، نه در .env - چون باید بدون SSH و از داخل خودِ پنل
  قابل تغییر باشد.
- هر LICENSE_CHECK_INTERVAL_SECONDS یک‌بار (نگاه کنید به scheduler.py)
  refresh_license_status() این کلید را به license-server مرکزی (خارج از
  این سرور، پیش خودِ فروشنده‌ی پنل) می‌فرستد و پاسخ را کش می‌کند.
- اگر لایسنس نامعتبر/منقضی باشد: سرویس‌های واقعی VPN (xl2tp/pptp/openvpn/
  sstp) خاموش می‌شوند - یعنی کاربران نهایی هم دیگر وصل نمی‌شوند، نه فقط
  پنل قفل می‌شود - و middleware (در main.py) هر API ای بجز لاگین/فعال‌سازی
  لایسنس را با 402 رد می‌کند.
- اگر بعداً یک کلید معتبر وارد شود، همان سرویس‌ها به وضعیت قبلی‌شان (طبق
  تنظیمات ذخیره‌شده در Settings > پروتکل‌ها) برمی‌گردند.
- قطعی موقتِ خودِ سرور لایسنس (نه انقضای واقعی) بلافاصله پنل را قفل
  نمی‌کند؛ تا LICENSE_GRACE_PERIOD_HOURS از آخرین باری که پاسخ "معتبر"
  گرفته شده، با همان وضعیت قبلی کار می‌کند.
"""

import json
import logging
import subprocess
from datetime import datetime, timedelta

import requests
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import Setting, ReservedLicense

logger = logging.getLogger("vpn-panel.license")
settings = get_settings()

KEY_LICENSE_KEY = "license_key"
KEY_LAST_RESULT = "license_last_result"          # JSON کامل آخرین پاسخ سرور (یا خطا)
KEY_LAST_CHECK_AT = "license_last_check_at"       # آخرین باری که اصلاً تلاش شد (موفق یا نه)
KEY_LAST_VALID_AT = "license_last_valid_at"       # آخرین باری که پاسخ "valid": true بود
KEY_LOCKED = "license_locked"                     # "1" یا "0" - کش سریع برای middleware
KEY_SWITCH_NOTICE = "license_switch_notice"       # پیام یک‌باره‌ی «لایسنس عوض شد» برای سوپرادمین
KEY_UNREACHABLE_SINCE = "license_unreachable_since" # شروع اختلال پیوسته سرور لایسنس


def _get(db: Session, key: str) -> str | None:
    row = db.query(Setting).filter(Setting.key == key).first()
    return row.value if row else None


def _hours_remaining_from_expiry(expires_at_gregorian: str | None) -> int | None:
    """ساعتِ باقی‌ماندهٔ درون همان روز (۰ تا ۲۳) را از timestamp واقعی حساب
    می‌کند - چون days_remaining که از license-server می‌آید یک عدد رند/گرد
    شده به روز است و وقتی کمتر از یک روز مانده، همیشه صفر نشان می‌دهد
    (مثلاً وقتی واقعاً ۵ ساعت مانده، همچنان "0 روز باقی‌مانده" دیده می‌شود که
    گیج‌کننده است). این باقیمانده را جدا حساب می‌کنیم تا فرانت‌اند بتواند
    "X روز Y ساعت" واقعی نشان دهد - Y همیشه باقیماندهٔ داخل روز است، نه کل
    ساعت‌های تا انقضا (که با عدد روز جمع/همخوانی نداشت).

    توجه: این تابع فقط fallback برای لایسنس‌های قدیمی/نوع «fixed» است که
    license-server فقط تاریخِ روزِ انقضا (بدون ساعت دقیق) را می‌دهد. برای
    لایسنس‌های «after_connect» که license-server مقدار دقیق expires_at_ms را
    برمی‌گرداند، به‌جایش از _remaining_from_epoch_ms استفاده کن که هیچ گرد
    کردنی ندارد."""
    if not expires_at_gregorian:
        return None
    try:
        expiry_day = datetime.fromisoformat(expires_at_gregorian)
    except ValueError:
        return None
    # expires_at_gregorian که از license-server می‌آید فقط «تاریخ روز انقضا»ست
    # (چون license-server خودش فقط شماره‌روز/JDN نگه می‌دارد، نه ساعت دقیق) و
    # وقتی parse می‌شود یعنی نیمه‌شبِ ابتدای همان روز. اما لایسنس تا آخر همان
    # روز معتبر است (days_remaining=0 یعنی «امروز آخرین روز است»، نه «همین الان
    # تمام شده»). پس لحظه‌ی واقعی انقضا نیمه‌شبِ پایانِ همان روز (= ابتدای روز
    # بعد) است؛ بدون این +۱ روز، از همان اول صبحِ روز انقضا مقدار همیشه صفر
    # می‌شد چون نیمه‌شبِ ابتدای روز از قبل گذشته بود.
    expiry = expiry_day + timedelta(days=1)
    delta_seconds = (expiry - datetime.utcnow()).total_seconds()
    if delta_seconds <= 0:
        return 0
    return int(delta_seconds % 86400 // 3600)


def _minutes_remaining_from_expiry(expires_at_gregorian: str | None) -> int | None:
    """دقیقهٔ باقی‌ماندهٔ درون همان ساعت (۰ تا ۵۹)، هم‌راستا با
    _hours_remaining_from_expiry، تا فرانت‌اند بتواند "X روز Y ساعت Z دقیقه"
    را کامل نشان دهد. همان محدودیت بالا: فقط fallback برای نوع «fixed» است."""
    if not expires_at_gregorian:
        return None
    try:
        expiry_day = datetime.fromisoformat(expires_at_gregorian)
    except ValueError:
        return None
    # همان دلیلِ +۱ روز که در _hours_remaining_from_expiry توضیح داده شد.
    expiry = expiry_day + timedelta(days=1)
    delta_seconds = (expiry - datetime.utcnow()).total_seconds()
    if delta_seconds <= 0:
        return 0
    return int(delta_seconds % 3600 // 60)


def _remaining_from_epoch_ms(expires_at_ms) -> tuple[int, int, int] | None:
    """محاسبه‌ی دقیق (بدون هیچ گرد کردنی) روز/ساعت/دقیقه‌ی باقی‌مانده از یک
    epoch میلی‌ثانیه‌ای دقیق (expires_at_ms که license-server برای لایسنس‌های
    «after_connect» بعد از اولین فعال‌سازی واقعی برمی‌گرداند).

    چرا این تابع لازم است (نه _hours/_minutes_remaining_from_expiry بالا):
    آن دو تابع از expires_at_gregorian می‌آیند که در license-server فقط بر
    اساس JDN (شماره‌ی روز، بدون ساعت دقیق) محاسبه می‌شود - یعنی لحظه‌ی
    فعال‌سازی همیشه به نیمه‌شبِ همان روز گرد می‌شود. برای لایسنسی که مثلاً
    ساعت ۱۴:۰۰ فعال شده، این گرد کردن به‌طور میانگین ۱۲ ساعت (و در بدترین حالت
    تا ۲۴ ساعت) به زمان واقعی باقی‌مانده اضافه می‌کند - دقیقاً همان چیزی که
    باعث می‌شد یک لایسنس ۳۰ روزه بلافاصله بعد از اولین اتصال چیزی نزدیک به
    "30 روز و چند ساعت" نشان دهد، نه "29 روز و 23 ساعت و 59 دقیقه" که واقعی
    است. با محاسبه‌ی مستقیم از epoch دقیقِ لحظه‌ی فعال‌سازی + مدت کامل لایسنس
    (به میلی‌ثانیه)، این گرد کردن کاملاً حذف می‌شود."""
    if expires_at_ms is None:
        return None
    try:
        expires_at_ms = float(expires_at_ms)
    except (TypeError, ValueError):
        return None
    delta_seconds = (expires_at_ms / 1000.0) - datetime.utcnow().timestamp()
    if delta_seconds <= 0:
        return 0, 0, 0
    total_minutes = int(delta_seconds // 60)
    days, rem_minutes = divmod(total_minutes, 24 * 60)
    hours, minutes = divmod(rem_minutes, 60)
    return days, hours, minutes


def _set(db: Session, key: str, value: str | None):
    row = db.query(Setting).filter(Setting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(Setting(key=key, value=value))


def get_license_key(db: Session) -> str | None:
    return _get(db, KEY_LICENSE_KEY)


def mask_key(key: str) -> str:
    if not key:
        return ""
    parts = key.split("-")
    if len(parts) == 3:
        return f"{parts[0]}-******-{parts[2]}"
    return key[:4] + "..." if len(key) > 4 else "****"


def is_locked(db: Session) -> bool:
    """چک سریع و بدون تماس شبکه‌ای - همان مقداری که آخرین اجرای
    refresh_license_status ذخیره کرده. این تابع در middleware صدا زده
    می‌شود، پس باید سبک باشد."""
    if not settings.LICENSE_SERVER_URL or not settings.LICENSE_API_KEY:
        # Production is fail-closed. A license-free development instance must
        # opt in explicitly through LICENSE_ALLOW_UNLICENSED_DEVELOPMENT=1.
        return not bool(settings.LICENSE_ALLOW_UNLICENSED_DEVELOPMENT)
    return _get(db, KEY_LOCKED) == "1"


def get_switch_notice(db: Session) -> str | None:
    """پیام یک‌باره‌ی «لایسنس عوض شد» را برمی‌گرداند (بدون پاک‌کردنش) - برای
    نمایش در get_status. با ack_switch_notice پاک می‌شود، بعد از این‌که
    فرانت‌اند واقعاً نشانش داد."""
    return _get(db, KEY_SWITCH_NOTICE)


def ack_switch_notice(db: Session) -> None:
    """پیام یک‌باره‌ی «لایسنس عوض شد» را پاک می‌کند - بعد از این‌که سوپرادمین
    آن را دید (تا دفعه‌ی بعد دوباره نشان داده نشود)."""
    _set(db, KEY_SWITCH_NOTICE, None)
    db.commit()


def _activated_server_ip(cached: dict, status: str | None) -> str | None:
    """Return the IP the central license server reports as bound to the key.

    Older/newer license-server builds have used slightly different field names,
    so accept all known variants.  For a valid license, fall back to this
    panel's configured public IP when the server omits the bound-IP field.
    """
    for name in ("bound_ip", "boundIp", "activated_ip", "activatedIp", "server_ip", "serverIp", "ip"):
        value = cached.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    if status in {"active", "expiring_soon"}:
        value = str(get_settings().PUBLIC_SERVER_IP or "").strip()
        if value and value not in {"127.0.0.1", "localhost"}:
            return value
    return None


def get_status(db: Session, include_queue_details: bool = False, include_key_full: bool = False) -> dict:
    key = get_license_key(db)
    raw = _get(db, KEY_LAST_RESULT)
    last_check = _get(db, KEY_LAST_CHECK_AT)
    cached = json.loads(raw) if raw else {}

    reserved_count = db.query(ReservedLicense).count()

    if not settings.LICENSE_SERVER_URL or not settings.LICENSE_API_KEY:
        return {
            "configured": bool(key),
            "locked": not bool(settings.LICENSE_ALLOW_UNLICENSED_DEVELOPMENT),
            "status": "unconfigured",
            "key_masked": mask_key(key) if key else None,
            "key_full": key if (key and include_key_full) else None,
            "activated_server_ip": None,
            "days_remaining": None,
            "hours_remaining": None,
            "minutes_remaining": None,
            "expires_at_jalali_display": None,
            "last_checked_at": last_check,
            "message": "سرور لایسنس روی این پنل تنظیم نشده است.",
            "reserved_count": reserved_count,
            "total_days_remaining_with_queue": None,
        }

    if not key:
        return {
            "configured": False,
            "locked": is_locked(db),
            "status": "unconfigured",
            "key_masked": None,
            "key_full": None,
            "activated_server_ip": None,
            "days_remaining": None,
            "hours_remaining": None,
            "minutes_remaining": None,
            "expires_at_jalali_display": None,
            "last_checked_at": last_check,
            "message": "هنوز کد لایسنسی وارد نشده است.",
            "reserved_count": reserved_count,
            "total_days_remaining_with_queue": (_reserved_queue_days_total(db) or None) if include_queue_details else None,
        }

    locked = is_locked(db)
    status = cached.get("status", "unknown")
    message = {
        "active": "لایسنس معتبر است.",
        "expiring_soon": "لایسنس به‌زودی منقضی می‌شود.",
        "expired": "لایسنس منقضی شده است.",
        "not_found": "این کد لایسنس در سرور مرکزی پیدا نشد.",
        "unreachable": "ارتباط با سرور لایسنس برقرار نشد.",
        "ip_mismatch": "این لایسنس روی سرور دیگری فعال است. برای انتقال به این سرور، از پنل لایسنس روی «ریست لایسنس» بزنید و سپس دوباره کد را اینجا وارد کنید.",
        "not_activated": "این کد لایسنس هنوز روی هیچ سروری فعال نشده. از صفحه‌ی لایسنس همین پنل، کد را دوباره وارد و تایید کنید.",
        "ip_banned": "آی‌پی این سرور مسدود شده است.",
        "reserved_for_other_server": "این کد لایسنس از قبل برای سرور دیگری رزرو شده است.",
    }.get(status, "وضعیت لایسنس نامشخص است.")

    total_days_purchased = None
    created_gr = cached.get("created_at_gregorian")
    expires_gr = cached.get("expires_at_gregorian")
    if created_gr and expires_gr:
        try:
            d1 = datetime.fromisoformat(created_gr)
            d2 = datetime.fromisoformat(expires_gr)
            total_days_purchased = (d2 - d1).days
        except ValueError:
            total_days_purchased = None

    precise = _remaining_from_epoch_ms(cached.get("expires_at_ms"))
    if precise:
        current_days, current_hours, current_minutes = precise
    else:
        current_days = cached.get("days_remaining")
        current_hours = _hours_remaining_from_expiry(cached.get("expires_at_gregorian"))
        current_minutes = _minutes_remaining_from_expiry(cached.get("expires_at_gregorian"))
    queue_days = _reserved_queue_days_total(db) if include_queue_details else 0
    total_with_queue = (current_days or 0) + queue_days

    return {
        "configured": True,
        "locked": locked,
        "status": status,
        "key_masked": mask_key(key),
        "key_full": key if include_key_full else None,
        "activated_server_ip": _activated_server_ip(cached, status),
        "days_remaining": current_days,
        "hours_remaining": current_hours,
        "minutes_remaining": current_minutes,
        "expires_at_jalali_display": cached.get("expires_at_jalali_display"),
        "created_at_jalali_display": cached.get("created_at_jalali_display"),
        "first_online_jalali_display": cached.get("first_online_jalali_display"),
        "total_days_purchased": total_days_purchased,
        "last_checked_at": last_check,
        "message": message,
        "reserved_count": reserved_count,
        "total_days_remaining_with_queue": total_with_queue if include_queue_details and (current_days is not None or reserved_count > 0) else None,
    }


def _call_verify(key: str, explicit_activate: bool = False, reserve: bool = False) -> dict:
    """تماس با license-server. خروجی همیشه یک dict با کلید status است:
    active / expiring_soon / expired / not_found / unreachable / ip_mismatch /
    not_activated / ip_banned / reserved_for_other_server.

    explicit_activate=True فقط باید وقتی فرستاده شود که یک ادمین همین الان با
    دست کد را وارد/تایید کرده (نصب یا صفحه‌ی لایسنس داخل پنل) - نه در چک
    خودکار پس‌زمینه‌ای (scheduler). دلیلش: license-server فقط IP لایسنس‌های
    هنوز-بایندنشده را وقتی این پرچم true باشد قفل می‌کند، تا بعد از "ریست
    لایسنس"، یک پنل قدیمی که هنوز روشن است و خودکار هر چند دقیقه چک می‌کند
    نتواند دوباره خودش را صاحب لایسنس کند.

    reserve=True فقط از add_reserved_license می‌آید - یعنی این پنل دارد این
    کد را برای "بعد" کنار می‌گذارد. license-server با دیدن این پرچم، IP این
    پنل را روی لایسنس (به‌عنوان reservedIp) ثبت می‌کند تا تا وقتی خودِ این
    لایسنس واقعاً جایی فعال نشده، هیچ سرور دیگری نتواند همین کد رزرونشده را
    زودتر رزرو یا فعال کند و آن را از این پنل بقاپد."""
    url = settings.LICENSE_SERVER_URL.rstrip("/") + "/api/verify"
    try:
        r = requests.post(
            url,
            json={"key": key, "activate": bool(explicit_activate), "reserve": bool(reserve)},
            headers={"x-api-key": settings.LICENSE_API_KEY, "Content-Type": "application/json"},
            timeout=10,
        )
    except requests.RequestException:
        logger.warning("عدم دسترسی به license-server برای verify")
        return {"status": "unreachable", "valid": False}

    if r.status_code == 401 or r.status_code == 403:
        logger.error("کلید API لایسنس این پنل نامعتبر/باطل شده است (پاسخ %s از license-server)", r.status_code)
        return {"status": "unreachable", "valid": False}

    try:
        data = r.json()
    except ValueError:
        return {"status": "unreachable", "valid": False}

    if not isinstance(data, dict) or "valid" not in data:
        return {"status": "unreachable", "valid": False}

    return data


def _apply_lock_state(db: Session, should_lock: bool):
    """اعمال واقعیِ قفل/بازکردن روی سرویس‌های VPN. Import محلی برای جلوگیری
    از وابستگی چرخه‌ای بین این ماژول و vpn_manager."""
    from app.services.vpn_manager import (
        stop_all_protocol_services, apply_current_protocol_settings,
    )

    currently_locked = _get(db, KEY_LOCKED) == "1"
    if should_lock and not currently_locked:
        logger.warning("لایسنس نامعتبر/منقضی - خاموش کردن سرویس‌های VPN")
        try:
            stop_all_protocol_services()
            for unit in ("vpn-panel-xray-vmess", "vpn-panel-xray-vless"):
                subprocess.run(["/usr/bin/systemctl", "stop", unit], capture_output=True, timeout=20, check=False)
        except Exception:
            logger.exception("خطا هنگام خاموش کردن سرویس‌های VPN بابت قفل لایسنس")
    elif not should_lock and currently_locked:
        logger.info("لایسنس دوباره معتبر شد - بازگرداندن سرویس‌های VPN به حالت عادی")
        try:
            apply_current_protocol_settings(db)
            from app.services.xray_manager import sync_xray_users
            sync_xray_users(db, protocols=("vmess", "vless"), restart=True)
        except Exception:
            logger.exception("خطا هنگام روشن کردن دوباره‌ی سرویس‌های VPN بعد از رفع قفل لایسنس")

    _set(db, KEY_LOCKED, "1" if should_lock else "0")


# وضعیت‌هایی که یعنی لایسنس اصلی دیگر برای این سرور قابل استفاده نیست. قبل
# از قفل‌کردن سرویس‌ها، در همین حالت‌ها صف رزرو امتحان می‌شود:
#   expired      -> تاریخ لایسنس فعلی گذشته
#   not_found    -> لایسنس فعلی از پنل لایسنس پاک شده
#   not_activated-> لایسنس فعلی در سرور مرکزی ریست شده (bound_ip پاک شده)
#   ip_mismatch  -> لایسنس اصلی از این سرور خارج/به سرور دیگری منتقل شده
# قطعی موقت ارتباط (unreachable) عمداً محرک تعویض نیست و از grace period
# استفاده می‌کند تا یک اختلال شبکه باعث مصرف ناخواسته‌ی لایسنس رزرو نشود.
_QUEUE_TRIGGER_STATUSES = {"expired", "not_found", "not_activated", "ip_mismatch"}

# متن قابل‌نمایش برای هرکدام از دلایل بالا - در پیام یک‌باره‌ی «لایسنس عوض
# شد» به سوپرادمین استفاده می‌شود.
_QUEUE_TRIGGER_REASON_TEXT = {
    "expired": "لایسنس قبلی تمام شده بود",
    "not_found": "لایسنس قبلی از پنل لایسنس پاک شده بود",
    "not_activated": "لایسنس قبلی ریست شده بود",
    "ip_mismatch": "لایسنس قبلی دیگر به این سرور تعلق نداشت",
}


def _next_queue_order(db: Session) -> int:
    return (db.query(func.max(ReservedLicense.order)).scalar() or 0) + 1


def _reservation_lost(row: ReservedLicense, info: dict) -> bool:
    """True یعنی این کد رزروشده دیگر برای این پنل معتبر نیست و باید از صف
    حذف شود - یا کلاً از پنل لایسنس پاک شده، یا رزرو/فعال‌سازی‌اش به سرور
    دیگری داده شده. تشخیص «داده شدن به سرور دیگر» با مقایسه‌ی reservedIp
    فعلیِ لایسنس (که همیشه در پاسخ verify برمی‌گردد، حتی در چک‌های ساکت)
    با همان IP ای است که در لحظه‌ی رزرو روی این ردیف ذخیره کرده بودیم."""
    status = info.get("status")
    if status == "not_found":
        # لایسنس کلاً از پنل لایسنس پاک شده.
        return True
    if status == "ip_mismatch":
        # این کد از قبل روی یک سرور دیگر واقعاً فعال (bound) شده.
        return True
    reserved_ip_now = info.get("reserved_ip")
    if row.reserved_ip and reserved_ip_now and reserved_ip_now != row.reserved_ip:
        # رزرو قبلاً برای IP همین پنل بود، الان برای IP دیگری‌ست - یعنی
        # از پنل لایسنس (clear-reservation/ریست) آزاد و به سرور دیگری
        # داده شده.
        return True
    return False


def list_reserved_licenses(db: Session) -> list[dict]:
    rows = db.query(ReservedLicense).order_by(ReservedLicense.order.asc()).all()
    out = []
    changed = False
    for r in rows:
        # چک ساده و بدون فعال‌سازی/رزرو - فقط برای نمایش وضعیت و روزهای
        # باقی‌مانده‌ی این کد در صف؛ هیچ اثری روی reservedIp/boundIp نمی‌گذارد.
        info = _call_verify(r.key, explicit_activate=False, reserve=False)

        if _reservation_lost(r, info):
            # این کد دیگر متعلق به این پنل نیست (پاک شده یا به سرور دیگری
            # داده شده) - از صف محلی حذفش کن تا دیگر نشانش ندهیم.
            db.delete(r)
            changed = True
            continue

        out.append({
            "id": r.id,
            "key_masked": mask_key(r.key),
            "added_at": r.added_at.isoformat() if r.added_at else None,
            "status": info.get("status"),
            "days_remaining": info.get("days_remaining"),
            "duration_days": info.get("duration_days"),
            "expiry_pending": bool(info.get("expiry_pending")),
        })

    if changed:
        db.commit()

    for i, item in enumerate(out):
        item["queue_position"] = i + 1
    return out


def _reserved_queue_days_total(db: Session) -> int:
    """مجموع روزهایی که صف رزرو (بدون در نظر گرفتن لایسنس فعلی) رویهم
    می‌تواند بدهد: برای کدهایی که شمارش‌شان شروع شده days_remaining واقعی،
    برای بقیه (after_connect که هنوز فعال نشده) کل duration_days‌شان."""
    total = 0
    for r in list_reserved_licenses(db):
        if r.get("expiry_pending"):
            total += r.get("duration_days") or 0
        else:
            total += r.get("days_remaining") or 0
    return total


def add_reserved_license(db: Session, key: str) -> list[dict]:
    """یک کد لایسنس را به‌عنوان «رزرو برای بعد» به صف اضافه می‌کند. این کد
    فعال (activate=True) نمی‌شود - فقط ذخیره می‌شود - چون بایند شدنش به این
    سرور باید دقیقاً همان لحظه‌ای اتفاق بیفتد که واقعاً لازم می‌شود (لایسنس
    فعلی منقضی شد)، نه زودتر. با این حال با فرستادن reserve=True به
    license-server، IP همین سرور همین الان روی لایسنس (به‌عنوان
    "رزروشده برای این سرور") ثبت می‌شود - تا وقتی این کد بعداً واقعاً روی
    یک سرور فعال شود، هیچ سرور دیگری نتواند در همین فاصله زودتر همین کد
    رزرونشده را از این پنل بقاپد."""
    key = (key or "").strip().lower()
    if not key:
        raise ValueError("کد لایسنس نمی‌تواند خالی باشد.")

    current_key = get_license_key(db)
    if current_key and key == current_key:
        raise ValueError("این کد همان کد لایسنس فعال فعلی است.")

    if db.query(ReservedLicense).filter(ReservedLicense.key == key).first():
        raise ValueError("این کد لایسنس قبلاً در صف رزرو ثبت شده است.")

    if not settings.LICENSE_SERVER_URL or not settings.LICENSE_API_KEY:
        raise ValueError("سرور لایسنس روی این پنل تنظیم نشده است.")

    result = _call_verify(key, explicit_activate=False, reserve=True)
    status = result.get("status")
    if status == "not_found":
        raise ValueError("این کد لایسنس معتبر نیست.")
    if status == "expired":
        raise ValueError("این کد لایسنس منقضی شده است.")
    if status == "ip_banned":
        raise ValueError("آی‌پی این سرور مسدود شده است.")
    if status == "unreachable":
        raise ValueError("ارتباط با سرور لایسنس برقرار نشد. دوباره تلاش کنید.")
    if status == "ip_mismatch":
        raise ValueError(
            "این لایسنس روی سرور دیگری فعال است. برای رزرو روی این پنل، اول از پنل لایسنس روی «ریست لایسنس» بزنید."
        )
    if status == "reserved_for_other_server":
        raise ValueError("این کد لایسنس از قبل توسط سرور دیگری رزرو شده است.")
    # not_activated / active / expiring_soon همگی برای رزرو قابل قبول‌اند.

    db.add(ReservedLicense(
        key=key,
        order=_next_queue_order(db),
        added_at=datetime.utcnow(),
        reserved_ip=result.get("reserved_ip"),
    ))
    db.commit()
    return list_reserved_licenses(db)


def _try_promote_from_queue(db: Session, previous_status: str | None = None) -> dict | None:
    """اولین لایسنس صف رزرو را امتحان می‌کند. اگر معتبر بود، همان لحظه جای
    لایسنس فعلی (که تازه نامعتبر تشخیص داده شده) می‌نشیند و از صف حذف
    می‌شود - پس هیچ‌وقت بین «منقضی‌شدن لایسنس قبلی» و «فعال‌شدن لایسنس بعدی»
    یک لحظه‌ی قفل‌شده وجود ندارد. اگر خودِ آن هم دیگر قابل استفاده نبود
    (مثلاً در همین فاصله خودش هم منقضی شده)، از صف حذف و بعدی امتحان
    می‌شود. اگر صف خالی شد یا هیچ‌کدام معتبر نبودند، None برمی‌گرداند.

    previous_status: دلیلی که لایسنس قبلی از رده خارج شد (یکی از کلیدهای
    _QUEUE_TRIGGER_REASON_TEXT) - فقط برای ساختن پیام یک‌باره‌ی «لایسنس عوض
    شد» که بعد از ورود بعدیِ سوپرادمین نشانش می‌دهیم."""
    while True:
        row = db.query(ReservedLicense).order_by(ReservedLicense.order.asc()).first()
        if not row:
            return None
        next_key = row.key
        result = _call_verify(next_key, explicit_activate=True)
        if result.get("valid"):
            _set(db, KEY_LICENSE_KEY, next_key)
            db.delete(row)
            reason_text = _QUEUE_TRIGGER_REASON_TEXT.get(
                previous_status, "لایسنس قبلی دیگر معتبر نبود"
            )
            _set(db, KEY_SWITCH_NOTICE, f"{reason_text} و لایسنس جدید شما فعال شد.")
            db.commit()
            logger.warning(
                "لایسنس قبلی منقضی/نامعتبر شد - لایسنس رزروشده‌ی بعدی خودکار جایگزین شد (بدون قفل‌شدن پنل)"
            )
            return result
        logger.warning("لایسنس رزروشده‌ی بعدی هم دیگر قابل استفاده نبود (status=%s) - از صف حذف شد", result.get("status"))
        db.delete(row)
        db.commit()


def refresh_license_status(db: Session, force: bool = False, explicit_activate: bool = False) -> dict:
    """این تابع در scheduler به‌صورت خاموش و در جریان فعال‌سازی برای تازه‌کردن
    وضعیت لایسنس اصلی صدا زده می‌شود. ``explicit_activate`` فقط برای فعال‌سازی
    دوباره‌ی همان کد فعلی بعد از ریست مرکزی استفاده شود؛ چک پس‌زمینه نباید یک
    لایسنس آزادشده را دوباره به این سرور بایند کند."""
    if not settings.LICENSE_SERVER_URL or not settings.LICENSE_API_KEY:
        _set(db, KEY_LOCKED, "0" if settings.LICENSE_ALLOW_UNLICENSED_DEVELOPMENT else "1")
        db.commit()
        return {"status": "unconfigured", "valid": bool(settings.LICENSE_ALLOW_UNLICENSED_DEVELOPMENT)}

    key = get_license_key(db)
    now = datetime.utcnow().isoformat()

    if not key:
        _set(db, KEY_LAST_CHECK_AT, now)
        _set(db, KEY_LAST_RESULT, json.dumps({"status": "unconfigured"}))
        _apply_lock_state(db, should_lock=True)
        db.commit()
        return {"status": "unconfigured"}

    result = _call_verify(key, explicit_activate=explicit_activate)
    _set(db, KEY_LAST_CHECK_AT, now)

    if result.get("status") == "unreachable":
        # A transport timeout is not a license rejection. Preserve an already
        # unlocked panel for a bounded grace period even when an older installer
        # did not seed license_last_valid_at. This prevents the UI from bouncing
        # between the dashboard and /license-locked during short controller,
        # DNS, TLS, or proxy interruptions.
        current_locked_raw = _get(db, KEY_LOCKED)
        last_valid_raw = _get(db, KEY_LAST_VALID_AT)
        unreachable_since_raw = _get(db, KEY_UNREACHABLE_SINCE)
        now_dt = datetime.utcnow()
        if not unreachable_since_raw:
            unreachable_since_raw = now
            _set(db, KEY_UNREACHABLE_SINCE, unreachable_since_raw)

        grace_anchor = last_valid_raw or (unreachable_since_raw if current_locked_raw == "0" else None)
        within_grace = False
        if grace_anchor:
            try:
                anchor = datetime.fromisoformat(grace_anchor)
                within_grace = now_dt - anchor < timedelta(hours=settings.LICENSE_GRACE_PERIOD_HOURS)
            except (TypeError, ValueError):
                within_grace = False

        cached_raw = _get(db, KEY_LAST_RESULT)
        try:
            cached = json.loads(cached_raw) if cached_raw else {}
        except (TypeError, json.JSONDecodeError):
            cached = {}
        previously_valid_or_unlocked = bool(cached.get("valid")) or current_locked_raw == "0"
        if within_grace and previously_valid_or_unlocked:
            _apply_lock_state(db, should_lock=False)
            db.commit()
            return cached if cached.get("valid") else {**result, "valid": True, "grace_mode": True}

        _set(db, KEY_LAST_RESULT, json.dumps(result))
        _apply_lock_state(db, should_lock=True)
        db.commit()
        return result

    # Any reachable response ends the continuous-outage window. A genuinely
    # invalid/expired response is still enforced immediately below.
    _set(db, KEY_UNREACHABLE_SINCE, None)

    if not result.get("valid") and result.get("status") in _QUEUE_TRIGGER_STATUSES:
        # قبل از قفل‌کردن پنل، اول صف رزرو را امتحان کن - اگر یک لایسنس
        # معتبر آنجا پیدا شد، همین‌جا جایگزین می‌شود و اصلاً به مرحله‌ی
        # قفل‌کردن نمی‌رسیم.
        promoted = _try_promote_from_queue(db, previous_status=result.get("status"))
        if promoted is not None:
            result = promoted

    _set(db, KEY_LAST_RESULT, json.dumps(result))
    if result.get("valid"):
        _set(db, KEY_LAST_VALID_AT, now)
    _apply_lock_state(db, should_lock=not bool(result.get("valid")))
    db.commit()
    return result


def _status_has_more_than_one_minute(db: Session, status: dict) -> bool:
    """Whether the current valid license should stay primary.

    Use the exact cached expiry timestamp whenever the license server supplied
    one.  This avoids a floor-to-minutes edge case where 1m59s could otherwise
    look like exactly one minute and be replaced too early.  Legacy fixed-date
    licenses are measured against the real end of their expiry day.  Unknown
    remaining time is treated as active, so a pasted key is reserved rather
    than unexpectedly replacing a working license.
    """
    if not status or status.get("locked") or status.get("status") not in {"active", "expiring_soon"}:
        return False

    cached_raw = _get(db, KEY_LAST_RESULT)
    try:
        cached = json.loads(cached_raw) if cached_raw else {}
    except (TypeError, ValueError):
        cached = {}

    expires_at_ms = cached.get("expires_at_ms")
    if expires_at_ms is not None:
        try:
            remaining = float(expires_at_ms) / 1000.0 - datetime.utcnow().timestamp()
            return remaining > 60
        except (TypeError, ValueError):
            pass

    expires_at_gregorian = cached.get("expires_at_gregorian")
    if expires_at_gregorian:
        try:
            expiry = datetime.fromisoformat(expires_at_gregorian) + timedelta(days=1)
            return (expiry - datetime.utcnow()).total_seconds() > 60
        except ValueError:
            pass

    raw = _get_status_remaining_seconds(status)
    return True if raw is None else raw > 60


def _get_status_remaining_seconds(status: dict) -> int | None:
    try:
        days = status.get("days_remaining")
        hours = status.get("hours_remaining")
        minutes = status.get("minutes_remaining")
        if days is None and hours is None and minutes is None:
            return None
        return max(0, int(days or 0) * 86400 + int(hours or 0) * 3600 + int(minutes or 0) * 60)
    except (TypeError, ValueError):
        return None


def _persist_verified_license(db: Session, key: str, result: dict) -> None:
    """Persist a successful explicit verify without making a second network call."""
    now = datetime.utcnow().isoformat()
    _set(db, KEY_LICENSE_KEY, key)
    _set(db, KEY_LAST_CHECK_AT, now)
    _set(db, KEY_LAST_RESULT, json.dumps(result))
    if result.get("valid"):
        _set(db, KEY_LAST_VALID_AT, now)
    _apply_lock_state(db, should_lock=not bool(result.get("valid")))
    db.commit()


def activate_license(db: Session, key: str) -> dict:
    """Smart activate/reserve action used by the single activation button.

    * No usable primary license, or less than one minute remaining: activate
      the entered key immediately.
    * A valid primary license with more than one minute remaining: reserve the
      entered key for automatic promotion and leave the current key untouched.
    * Entering the same key that is already active is rejected. Re-using the
      current key adds no value and previously caused duplicate activation
      attempts and confusing success messages.

    Invalid entered keys never overwrite a working current license.
    """
    key = (key or "").strip().lower()
    if not key:
        raise ValueError("کد لایسنس نمی‌تواند خالی باشد.")

    current_key = get_license_key(db)
    if current_key and key == current_key:
        raise ValueError("این کد همین حالا روی پنل فعال است و دوباره قابل فعال‌سازی نیست.")

    # Refresh the primary key first.  This also promotes an already-reserved
    # key immediately when the previous primary was expired, removed, reset,
    # or transferred away from this server.
    if current_key:
        refresh_license_status(db, force=True, explicit_activate=False)
    current_status = get_status(db, include_queue_details=False)

    if get_license_key(db) and _status_has_more_than_one_minute(db, current_status):
        add_reserved_license(db, key)
        status = get_status(db, include_queue_details=True)
        status["activation_action"] = "reserved"
        status["message"] = "لایسنس فعلی هنوز فعال است؛ کد جدید با موفقیت در صف رزرو قرار گرفت."
        return status

    # Activate now, but verify before changing the stored primary key.  This
    # avoids a bad pasted key replacing/locking the final seconds of a valid
    # current license.
    result = _call_verify(key, explicit_activate=True)
    if not result.get("valid"):
        return result
    _persist_verified_license(db, key, result)
    status = get_status(db, include_queue_details=True)
    status["activation_action"] = "activated"
    status["message"] = "لایسنس با موفقیت فعال شد."
    return status
