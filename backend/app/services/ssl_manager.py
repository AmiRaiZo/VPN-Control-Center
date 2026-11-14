import subprocess

from app.proc_utils import BASH


def apply_domain_ssl(domain: str) -> tuple[bool, str]:
    """اجرای اسکریپت setup_domain_ssl.sh برای گرفتن SSL و تنظیم Nginx روی دامنه.
    از ادمین ایمیل خواسته نمی‌شود؛ اسکریپت داخلاً از
    certbot --register-unsafely-without-email استفاده می‌کند (تمدید گواهی
    خودکار است و به ایمیل نیازی ندارد)."""
    try:
        result = subprocess.run(
            [BASH, "/opt/vpn-panel/scripts/setup_domain_ssl.sh", domain],
            capture_output=True,
            text=True,
            timeout=180,
            check=True,
        )
        return True, result.stdout[-3000:]
    except subprocess.CalledProcessError as e:
        log = (e.stdout or "") + "\n" + (e.stderr or "")
        return False, log[-3000:]
    except subprocess.TimeoutExpired:
        return False, "Timed out waiting for certbot (check that the domain's DNS A record points to this server)."


def apply_sub_domain_ssl(domain: str, port: int = 443) -> tuple[bool, str]:
    """اجرای اسکریپت setup_sub_domain_ssl.sh برای گرفتن SSL و تنظیم یک ووهاست
    Nginx جدا و مستقل (کنار دامنه‌ی پنل) مخصوص صفحه‌ی «لینک اشتراک». مثل
    apply_domain_ssl، بدون نیاز به ایمیل. پورت HTTPS این ووهاست هم قابل تنظیم
    است (پیش‌فرض 443)."""
    try:
        result = subprocess.run(
            [BASH, "/opt/vpn-panel/scripts/setup_sub_domain_ssl.sh", domain, str(port)],
            capture_output=True,
            text=True,
            timeout=180,
            check=True,
        )
        return True, result.stdout[-3000:]
    except subprocess.CalledProcessError as e:
        log = (e.stdout or "") + "\n" + (e.stderr or "")
        return False, log[-3000:]
    except subprocess.TimeoutExpired:
        return False, "Timed out waiting for certbot (check that the sub-domain's DNS A record points to this server)."


def apply_sub_domain_port(domain: str, port: int) -> tuple[bool, str]:
    """اجرای اسکریپت change_sub_domain_port.sh: پورت ووهاست دامنه‌ی ساب را
    عوض می‌کند بدون تماس مجدد با certbot (گواهی موجود همان‌طور که هست دوباره
    سوار می‌شود روی پورت جدید) - دقیقاً همان الگوی change_panel_port.sh."""
    try:
        result = subprocess.run(
            [BASH, "/opt/vpn-panel/scripts/change_sub_domain_port.sh", str(port), domain],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        return True, result.stdout[-3000:]
    except subprocess.CalledProcessError as e:
        log = (e.stdout or "") + "\n" + (e.stderr or "")
        return False, log[-3000:]
    except subprocess.TimeoutExpired:
        return False, "اجرای اسکریپت تغییر پورت بیش از حد طول کشید"



def apply_xray_sub_domain_ssl(domain: str, port: int = 443) -> tuple[bool, str]:
    """Issue SSL and configure a dedicated Nginx vhost that exposes only
    public VMess/VLESS subscription endpoints under /api/sub/."""
    try:
        result = subprocess.run(
            [BASH, "/opt/vpn-panel/scripts/setup_xray_sub_domain_ssl.sh", domain, str(port)],
            capture_output=True,
            text=True,
            timeout=180,
            check=True,
        )
        return True, result.stdout[-3000:]
    except subprocess.CalledProcessError as e:
        log = (e.stdout or "") + "\n" + (e.stderr or "")
        return False, log[-3000:]
    except subprocess.TimeoutExpired:
        return False, "Timed out waiting for certbot (check that the Xray subscription domain points to this server)."


def apply_xray_sub_domain_port(domain: str, port: int) -> tuple[bool, str]:
    """Move the dedicated Xray subscription vhost to a new HTTPS port."""
    try:
        result = subprocess.run(
            [BASH, "/opt/vpn-panel/scripts/change_xray_sub_domain_port.sh", str(port), domain],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        return True, result.stdout[-3000:]
    except subprocess.CalledProcessError as e:
        log = (e.stdout or "") + "\n" + (e.stderr or "")
        return False, log[-3000:]
    except subprocess.TimeoutExpired:
        return False, "اجرای اسکریپت تغییر پورت دامنه سابسکریپشن Xray بیش از حد طول کشید"


def disable_xray_sub_domain() -> tuple[bool, str]:
    """Disable the isolated Xray subscription Nginx vhost."""
    try:
        result = subprocess.run(
            [BASH, "/opt/vpn-panel/scripts/disable_xray_sub_domain.sh"],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        return True, result.stdout[-3000:]
    except subprocess.CalledProcessError as e:
        log = (e.stdout or "") + "\n" + (e.stderr or "")
        return False, log[-3000:]
    except subprocess.TimeoutExpired:
        return False, "غیرفعال‌سازی دامنه‌ی سابسکریپشن Xray بیش از حد طول کشید"

def apply_vpn_domain_ssl(domain: str) -> tuple[bool, str]:
    """اجرای اسکریپت setup_vpn_domain_ssl.sh: هم DNS دامنه‌ی اختصاصی پروتکل‌ها
    را چک می‌کند و هم (برخلاف نسخه‌ی قبلی که فقط DNS را چک می‌کرد) یک گواهی
    SSL واقعی برایش می‌گیرد و به سرور SSTP (accel-ppp) وصل می‌کند - در غیر
    این صورت SSTP همچنان گواهی دامنه‌ی پنل را نشان می‌دهد و کلاینت‌های
    ویندوزی با خطای CN mismatch (0x800B010F) مواجه می‌شوند. مثل
    apply_domain_ssl/apply_sub_domain_ssl، بدون نیاز به ایمیل؛ تمدید گواهی
    هم خودکار و بدون دخالت دستی انجام می‌شود (نگاه کنید به دیپلوی‌هوک داخل
    خودِ اسکریپت)."""
    try:
        result = subprocess.run(
            [BASH, "/opt/vpn-panel/scripts/setup_vpn_domain_ssl.sh", domain],
            capture_output=True,
            text=True,
            timeout=180,
            check=True,
        )
        return True, result.stdout[-3000:]
    except subprocess.CalledProcessError as e:
        log = (e.stdout or "") + "\n" + (e.stderr or "")
        return False, log[-3000:]
    except subprocess.TimeoutExpired:
        return False, "Timed out waiting for certbot (check that the domain's DNS A record points to this server and tcp/80 is reachable)."


def apply_ikev2_ssl(domain: str) -> tuple[bool, str]:
    """اجرای اسکریپت setup_ikev2_ssl.sh: یک گواهی SSL واقعی برای دامنه می‌گیرد
    و آن را به‌جای گواهی self-signed پیش‌فرض (که install/setup_ikev2.sh در
    اولین راه‌اندازی می‌سازد) به strongSwan/IKEv2 وصل می‌کند - تا کلاینت‌ها
    بدون نیاز به trust دستی CA پنل وصل شوند. مثل بقیه‌ی اسکریپت‌های SSL، بدون
    نیاز به ایمیل؛ تمدید خودکار است."""
    try:
        result = subprocess.run(
            [BASH, "/opt/vpn-panel/scripts/setup_ikev2_ssl.sh", domain],
            capture_output=True,
            text=True,
            timeout=180,
            check=True,
        )
        return True, result.stdout[-3000:]
    except subprocess.CalledProcessError as e:
        log = (e.stdout or "") + "\n" + (e.stderr or "")
        return False, log[-3000:]
    except subprocess.TimeoutExpired:
        return False, "Timed out waiting for certbot (check that the domain's DNS A record points to this server and tcp/80 is reachable)."
