"""
ثبت اولیه‌ی کد لایسنس هنگام نصب (اختیاری). توسط اسکریپت نصب فراخوانی می‌شود:
python3 -m app.init_license <key>

اگر کلید خالی/نامعتبر بود یا سرور لایسنس در دسترس نبود، نصب همچنان با
موفقیت ادامه پیدا می‌کند - پنل فقط قفل بالا می‌آید و ادمین اصلی می‌تواند
بعداً از همان صفحه‌ی قفل، کد را وارد کند. یعنی این اسکریپت هیچ‌وقت exit
code غیرصفر برنمی‌گرداند (نباید باعث fail شدن install.sh با set -e شود).
"""
import sys

from app.database import SessionLocal, Base, engine
from app.services import license_manager


def _keep_archive_version() -> None:
    """The installed version is copied from the package VERSION file.

    The license server may expose a human-entered display label.  That label is
    never allowed to overwrite /opt/vpn-panel/VERSION, otherwise values such as
    "5" can make every installation look permanently outdated.
    """
    print("نسخه‌ی نصب‌شده از فایل VERSION داخل خود بسته نگه داشته شد.")


def main():
    if len(sys.argv) != 2 or not sys.argv[1].strip():
        print("لایسنس در حین نصب وارد نشد - می‌توانید بعداً از داخل پنل وارد کنید.")
        return

    key = sys.argv[1].strip().lower()
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        result = license_manager.activate_license(db, key)
        status = result.get("status")
        if status in ("active", "expiring_soon"):
            print(f"لایسنس با موفقیت فعال شد (وضعیت: {status}).")
            _keep_archive_version()
        else:
            print(f"توجه: لایسنس وارد‌شده تایید نشد (وضعیت: {status}). پنل قفل باقی می‌ماند تا کد معتبر وارد شود.")
    except Exception as e:
        print(f"توجه: چک لایسنس هنگام نصب با خطا مواجه شد ({e}). پنل قفل باقی می‌ماند تا کد معتبر وارد شود.")
    finally:
        db.close()


if __name__ == "__main__":
    main()
