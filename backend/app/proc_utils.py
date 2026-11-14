"""
این ماژول مسیر مطلق برنامه‌های سیستمی (bash، systemctl، kill و ...) را پیدا
می‌کند تا صدا زدن آن‌ها در subprocess.run(...) به PATH محیط اجرایی سرویس
وابسته نباشد.

چرا این فایل لازم است؟
سرویس systemd پنل (vpn-panel-api) با یک PATH محدود اجرا می‌شود که فقط شامل
پوشه‌ی venv پروژه است (برای جلوگیری از تداخل با پکیج‌های سیستمی پایتون).
همین باعث می‌شد subprocess.run(["bash", ...]) یا subprocess.run(["systemctl", ...])
نتواند این برنامه‌ها را پیدا کند و خطای زیر رخ بدهد:

    [Errno 2] No such file or directory: 'bash'

با پیدا کردن مسیر مطلق یک‌بار در زمان بالا آمدن برنامه (با fallback به مسیرهای
استاندارد اوبونتو در صورتی که shutil.which چیزی پیدا نکند)، این مشکل مستقل از
PATH سرویس systemd حل می‌شود.
"""
import shutil


def _resolve(name: str, fallback: str) -> str:
    return shutil.which(name) or fallback


BASH = _resolve("bash", "/bin/bash")
SYSTEMCTL = _resolve("systemctl", "/usr/bin/systemctl")
KILL = _resolve("kill", "/bin/kill")
PS = _resolve("ps", "/usr/bin/ps")
IPTABLES = _resolve("iptables", "/usr/sbin/iptables")
NETFILTER_PERSISTENT = _resolve("netfilter-persistent", "/usr/sbin/netfilter-persistent")
IPSEC = _resolve("ipsec", "/usr/sbin/ipsec")
# ابزار کنترل خط‌فرمان ocserv (OpenConnect) - برای قطع دستی سشن‌های کاربر،
# نگاه کنید به vpn_manager.kill_openconnect_session
OCCTL = _resolve("occtl", "/usr/bin/occtl")
