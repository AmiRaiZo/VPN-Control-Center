from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    # Installer metadata may grow across releases. Ignore unknown keys in the
    # local .env so adding an installer-only value can never crash Uvicorn on
    # a fresh host. Known deployment fields remain typed below.
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=True)

    DB_HOST: str = "127.0.0.1"
    DB_PORT: int = 3306
    DB_NAME: str = "vpn_panel"
    DB_USER: str = "vpn_panel"
    DB_PASSWORD: str = ""

    JWT_SECRET: str = ""
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRE_MINUTES: int = 1440

    INTERNAL_API_TOKEN: str = ""

    # Separate key used only for encrypting sensitive database fields such as
    # stored SSH credentials. Backup files themselves are intentionally plain
    # gzip-compressed JSON and do not use a recovery/decryption key.
    DATA_ENCRYPTION_KEY: str = ""

    # Same-origin deployments should leave this empty. Cross-origin API clients
    # must list explicit HTTPS origins separated by commas; wildcard + cookies
    # is deliberately rejected at startup.
    CORS_ALLOWED_ORIGINS: str = ""
    CORS_ALLOW_CREDENTIALS: bool = True

    # Import limits defend the restore endpoint and Node Agent against gzip bombs.
    BACKUP_MAX_COMPRESSED_BYTES: int = 128 * 1024 * 1024
    BACKUP_MAX_DECOMPRESSED_BYTES: int = 768 * 1024 * 1024

    # Paramiko uses a persistent trust-on-first-use store and rejects key changes.
    SSH_KNOWN_HOSTS_PATH: str = "/var/lib/vpn-panel/ssh_known_hosts"
    SSH_HOST_KEY_POLICY: str = "tofu"

    # If the local license cache cannot be evaluated, protected APIs fail closed.
    LICENSE_FAIL_CLOSED: bool = True
    # Production is license-only. Development without a license server requires
    # an explicit opt-in and must never be enabled on customer deployments.
    LICENSE_ALLOW_UNLICENSED_DEVELOPMENT: bool = False

    # Private loopback listener used by Uvicorn and the local VPN hook scripts.
    # This value is written by the installer when the public panel port must
    # move away from 8080/8000.  It is intentionally not exposed publicly, but
    # it must be declared here because pydantic-settings rejects unknown env
    # keys by default.
    BACKEND_PORT: int = 8000

    # Deployment role/state written by install.sh. Older releases wrote these
    # values without declaring them in Settings; pydantic-settings then rejected
    # the fresh .env and the API restarted forever at 78% of installation.
    SERVER_ROLE: str = "main"
    INSTALL_LOCAL_SERVICES: int = 1
    NODE_CONTROLLER_URL: str = ""

    # Production systemd installs run scheduler/node polling/Telegram in a
    # separate process so the local VPN authentication API stays responsive.
    # The default preserves developer/legacy launches that start app.main
    # directly without the companion service.
    RUN_BACKGROUND_JOBS: bool = False

    PUBLIC_SERVER_IP: str = "127.0.0.1"
    IPSEC_PSK: str = ""

    CHAP_SECRETS_PATH: str = "/etc/ppp/chap-secrets"
    IPSEC_SECRETS_PATH: str = "/etc/ipsec.secrets"
    OPENVPN_STATUS_LOG: str = "/etc/openvpn/server/openvpn-status.log"
    OPENVPN_CCD_DIR: str = "/etc/openvpn/server/ccd"
    OPENVPN_CA_PATH: str = "/etc/openvpn/server/ca.crt"
    OPENVPN_TA_PATH: str = "/etc/openvpn/server/ta.key"
    OPENVPN_CRL_PATH: str = "/etc/openvpn/server/crl.pem"
    EASYRSA_DIR: str = "/etc/openvpn/easy-rsa"

    # سرتیفیکیت TLS سرور SSTP (accel-ppp)، همان‌طور که install/setup_sstp.sh
    # می‌سازد/کپی می‌کند. وقتی self-signed باشد، کلاینت‌های SSTP (به‌خصوص
    # ویندوز) باید همین فایل را دانلود و در فهرست گواهی‌های مورد اعتماد نصب
    # کنند، وگرنه اتصال با خطای گواهی نامعتبر رد می‌شود.
    SSTP_CERT_PATH: str = "/etc/accel-ppp/sstp-certs/fullchain.pem"

    # فایل پسورد OpenConnect (ocserv) به فرمت ocpasswd، همان‌طور که
    # install/setup_openconnect.sh می‌سازد. جدا از chap-secrets/ipsec.secrets
    # است چون ocserv با ماژول "plain" خودش (نه PAM) این فایل را می‌خواند و
    # فرمتش (username:group:hash) با آن دو فرق دارد - نگاه کنید به
    # vpn_manager.sync_openconnect_secrets.
    OCSERV_PASSWD_PATH: str = "/etc/ocserv/ocpasswd"
    # سرتیفیکیت TLS سرور OpenConnect (ocserv)، همان‌طور که
    # install/setup_openconnect.sh می‌سازد/کپی می‌کند.
    OCSERV_CERT_PATH: str = "/etc/ocserv/ocserv-certs/fullchain.pem"

    # ---------------------------------------------------------------
    # لایسنس: آدرس سرور لایسنس مرکزی (license-server) و کلید API که برای
    # همین پنل از داخل «License Console» ساخته شده. این دو مقدار توسط
    # install.sh/update.sh پرسیده و در .env نوشته می‌شوند - کلید لایسنس
    # مشتری (که خودِ کاربر نهایی وارد می‌کند) اینجا نیست و در جدول Setting
    # دیتابیس ذخیره می‌شود (نگاه کنید به license_manager.py) چون ممکن است
    # عوض شود بدون نیاز به دسترسی SSH.
    LICENSE_SERVER_URL: str = ""
    LICENSE_API_KEY: str = ""
    # هر چند ثانیه یک‌بار وضعیت لایسنس از سرور مرکزی دوباره چک شود.
    LICENSE_CHECK_INTERVAL_SECONDS: int = 15
    # اگر سرور لایسنس در دسترس نبود (قطعی اینترنت/سرور)، تا چند ساعت با
    # آخرین وضعیتِ «معتبر» شناخته‌شده کار ادامه پیدا کند قبل از قفل‌شدن.
    LICENSE_GRACE_PERIOD_HOURS: int = 72

    MONITOR_INTERVAL_SECONDS: int = 4

    # فاصله‌ی چک خودکار سلامت سرویس‌های پروتکل (بیشتر برای accel-ppp-sstp که
    # سابقه‌ی کرش غیرمنتظره دارد) - نگاه کنید به
    # vpn_manager.reconcile_protocol_services و scheduler.py. عمداً از
    # MONITOR_INTERVAL_SECONDS جدا نگه داشته شده: آن یکی روی ردیف‌های
    # دیتابیس کار می‌کند (خیلی سبک، هر چند ثانیه بی‌ضرر است)، این یکی
    # systemctl صدا می‌زند (سبک‌تر است اگر کمتر تکرار شود).
    PROTOCOL_WATCHDOG_INTERVAL_SECONDS: int = 60

    @property
    def SQLALCHEMY_DATABASE_URL(self) -> str:
        return (
            f"mysql+pymysql://{self.DB_USER}:{self.DB_PASSWORD}"
            f"@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}?charset=utf8mb4"
        )


@lru_cache
def get_settings() -> Settings:
    return Settings()
