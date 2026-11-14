import enum
import uuid
from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Boolean, DateTime, BigInteger,
    ForeignKey, Enum, Date, Text, UniqueConstraint
)
from sqlalchemy.orm import relationship
from app.database import Base


class AdminRole(str, enum.Enum):
    superadmin = "superadmin"
    admin = "admin"


# بخش‌های قابل واگذاری پنل به ادمین زیرمجموعه. این لیست دقیقاً با آیتم‌های
# منوی فرانت‌اند (Layout.jsx) مطابقت دارد.
ADMIN_SECTIONS = ["dashboard", "users", "online", "bans", "license", "protocols", "settings", "nodes"]
ADMIN_PERMISSION_TOKENS = [
    "dashboard:view",
    "users:view", "users:create", "users:edit", "users:delete", "users:disconnect", "users:subscription",
    "online:view", "online:disconnect", "internet_blocks:view",
    "bans:view", "bans:manage",
    "license:view",
    "protocols:view", "protocols:start_stop", "protocols:install", "protocols:logs", "protocols:edit",
    "settings:view", "settings:manage",
    "nodes:view", "nodes:manage", "nodes:ssh", "nodes:install",
    "protocol:l2tp", "protocol:ipsec", "protocol:pptp", "protocol:openvpn", "protocol:openconnect", "protocol:sstp", "protocol:ikev2", "protocol:vmess", "protocol:vless",
]


class Admin(Base):
    __tablename__ = "admins"

    id = Column(Integer, primary_key=True, index=True)
    # collation=utf8mb4_bin: مقایسه‌ی یوزرنیم ادمین در سطح دیتابیس نسبت به
    # حروف بزرگ/کوچک حساس باشد (کالیشن پیش‌فرض utf8mb4 در MySQL حساس نیست و
    # "Admin" و "admin" را یکی می‌دید).
    username = Column(String(64, collation="utf8mb4_bin"), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    # نسخه رمزگذاری‌شده‌ی رمز فعلی برای خزانه مدیریت ادمین‌های زیرمجموعه.
    # احراز هویت همچنان فقط با password_hash انجام می‌شود؛ این مقدار فقط با
    # DATA_ENCRYPTION_KEY رمزگذاری و فقط برای superadmin قابل بازیابی است.
    password_vault_enc = Column(Text, nullable=True)
    role = Column(Enum(AdminRole), default=AdminRole.admin, nullable=False)
    # فقط برای role=admin معنا دارد: لیست بخش‌های مجاز از ADMIN_SECTIONS،
    # جدا شده با کاما (مثلاً "users,online"). superadmin به همه چیز دسترسی
    # کامل دارد و این فیلد برایش نادیده گرفته می‌شود.
    permissions = Column(String(2048), nullable=True)
    # فقط برای role=admin معنا دارد: اگر True باشد، این ادمین زیرمجموعه علاوه
    # بر یوزرهای خودش، کل یوزرهای VPN سرور (متعلق به هر ادمینی) را هم می‌بیند
    # و می‌تواند کنترل کند. superadmin همیشه (صرف‌نظر از این فیلد) به همه‌ی
    # یوزرها دسترسی کامل دارد.
    see_all_users = Column(Boolean, default=False, nullable=False)
    # Server scope for delegated admins. JSON tokens: ["all"], ["local"],
    # or ["node:<id>", ...]. NULL keeps backward-compatible access to all
    # current and future servers.
    server_targets = Column(Text, nullable=True)

    # سقف‌های اختصاص‌یافته به این ادمین زیرمجموعه توسط ادمین اصلی (فقط برای
    # role=admin معنا دارد؛ superadmin هیچ سقفی ندارد). NULL یعنی نامحدود.
    # max_users: حداکثر تعداد کل یوزر VPN که این ادمین اجازه دارد بسازد
    # (owner_admin_id این ادمین باشد).
    max_users = Column(Integer, nullable=True)
    # max_total_quota_bytes: حداکثر مجموع حجمی (quota_bytes) که این ادمین
    # اجازه دارد در کل بین یوزرهای خودش تقسیم کند (یک استخر حجم مشترک).
    max_total_quota_bytes = Column(BigInteger, nullable=True)
    # subscription_expire_date: تاریخ انقضای اشتراک/دسترسی خود این ادمین
    # زیرمجموعه (توسط ادمین اصلی تعیین می‌شود). NULL = بدون انقضا. بعد از این
    # تاریخ، این ادمین دیگر نمی‌تواند یوزر جدید بسازد یا سقف/حجم یوزرهای
    # موجودش را افزایش دهد.
    subscription_expire_date = Column(Date, nullable=True)
    # انقضای دقیق برای ادمین‌هایی که با لایسنس داخلی ثبت‌نام کرده‌اند.
    # این فیلد ساعت و دقیقه را نیز نگه می‌دارد؛ فیلد Date بالا برای سازگاری
    # ادمین‌های قدیمی و ساخت دستی حفظ شده است.
    subscription_expire_at = Column(DateTime, nullable=True)
    managed_by_license = Column(Boolean, default=False, nullable=False)
    access_license_code = Column(String(64, collation="utf8mb4_bin"), nullable=True, index=True)
    license_activated_at = Column(DateTime, nullable=True)
    license_locked = Column(Boolean, default=False, nullable=False)
    # اتصال اختیاری این ادمین به کنترل خصوصی ربات تلگرام.
    telegram_bot_enabled = Column(Boolean, default=False, nullable=False)
    telegram_user_id = Column(BigInteger, nullable=True, unique=True, index=True)
    # True only when the account was created from a bot-capable license while
    # the registrant explicitly selected «فعلاً ربات نمی‌خواهم». It allows the
    # same used license to bind exactly one Telegram numeric ID later.
    telegram_bot_opted_out = Column(Boolean, default=False, nullable=False)

    is_active = Column(Boolean, default=True)
    # آخرین ورود واقعی این ادمین به پنل. برای نمایش در پنل و ربات استفاده می‌شود.
    last_login_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class TelegramAdminGroup(Base):
    """A Telegram group scoped to exactly one panel administrator.

    Every Telegram member of the linked group may use the bot, but every action
    is executed through the current permissions, server targets, quotas and
    ownership scope of this panel administrator. The group never stores a copy
    of permissions, so later permission or account changes take effect instantly.
    """
    __tablename__ = "telegram_admin_groups"
    __table_args__ = (
        UniqueConstraint("chat_id", name="uq_telegram_admin_groups_chat_id"),
    )

    id = Column(Integer, primary_key=True, index=True)
    admin_id = Column(Integer, ForeignKey("admins.id"), nullable=False, index=True)
    chat_id = Column(BigInteger, nullable=False, index=True)
    title = Column(String(255), nullable=True)
    chat_type = Column(String(32), nullable=False, default="supergroup")
    chat_username = Column(String(255), nullable=True)
    control_enabled = Column(Boolean, nullable=False, default=True)
    # all_members: every member is allowed unless explicitly denied.
    # allowlist_only: only explicitly allowed numeric Telegram IDs may control the bot.
    access_mode = Column(String(32), nullable=False, default="all_members")
    is_active = Column(Boolean, nullable=False, default=True)
    linked_by_telegram_user_id = Column(BigInteger, nullable=False)
    last_verified_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    admin = relationship("Admin", foreign_keys=[admin_id])
    member_rules = relationship(
        "TelegramGroupMemberRule",
        back_populates="group",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )


class TelegramGroupMemberRule(Base):
    """Explicit allow/deny rule for one numeric Telegram user inside one linked group."""
    __tablename__ = "telegram_group_member_rules"
    __table_args__ = (
        UniqueConstraint("group_id", "telegram_user_id", name="uq_telegram_group_member_rule"),
    )

    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("telegram_admin_groups.id", ondelete="CASCADE"), nullable=False, index=True)
    telegram_user_id = Column(BigInteger, nullable=False, index=True)
    is_allowed = Column(Boolean, nullable=False, default=False)
    display_name = Column(String(255), nullable=True)
    telegram_username = Column(String(255), nullable=True)
    note = Column(String(500), nullable=True)
    created_by_admin_id = Column(Integer, ForeignKey("admins.id"), nullable=True, index=True)
    last_seen_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    group = relationship("TelegramAdminGroup", back_populates="member_rules")
    created_by_admin = relationship("Admin", foreign_keys=[created_by_admin_id])


class TelegramGroupLinkCode(Base):
    """Short-lived, one-time code used to bind a group to an admin."""
    __tablename__ = "telegram_group_link_codes"

    id = Column(Integer, primary_key=True, index=True)
    admin_id = Column(Integer, ForeignKey("admins.id"), nullable=False, index=True)
    code_hash = Column(String(64, collation="utf8mb4_bin"), nullable=False, unique=True, index=True)
    expires_at = Column(DateTime, nullable=False, index=True)
    used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    admin = relationship("Admin", foreign_keys=[admin_id])


class AdminAccessLicense(Base):
    """لایسنس داخلی و یک‌بارمصرف برای ساخت/تمدید ادمین زیرمجموعه."""
    __tablename__ = "admin_access_licenses"

    id = Column(Integer, primary_key=True, index=True)
    # کدها همیشه با حروف بزرگ ساخته می‌شوند و collation باینری حساسیت به
    # کوچک/بزرگ بودن حروف را در خود دیتابیس تضمین می‌کند.
    code = Column(String(64, collation="utf8mb4_bin"), unique=True, index=True, nullable=False)
    # نقشی که دارنده‌ی این کد هنگام ثبت‌نام دریافت می‌کند. مقدار پیش‌فرض
    # admin سازگاری کامل با تمام لایسنس‌های ساخته‌شده در نسخه‌های قبلی دارد.
    role = Column(Enum(AdminRole), default=AdminRole.admin, nullable=False)
    permissions = Column(String(2048), nullable=False)
    see_all_users = Column(Boolean, default=False, nullable=False)
    # محدوده سرورهایی که ادمین پس از فعال‌سازی این لایسنس می‌تواند مدیریت کند.
    # NULL فقط برای لایسنس‌های قدیمی و به معنی دسترسی قبلی به همه سرورهاست؛
    # JSON [] یعنی عمداً هیچ سروری انتخاب نشده است.
    server_targets = Column(Text, nullable=True)
    max_users = Column(Integer, nullable=True)
    max_total_quota_bytes = Column(BigInteger, nullable=True)
    expire_mode = Column(String(32), default="after_activation", nullable=False)
    duration_minutes = Column(Integer, nullable=True)
    fixed_expire_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    used_by_admin_id = Column(Integer, ForeignKey("admins.id"), nullable=True, index=True)
    activated_at = Column(DateTime, nullable=True)
    note = Column(Text, nullable=True)
    # در صورت فعال بودن، ثبت‌نام‌کننده باید آیدی عددی تلگرام بدهد و همان
    # حساب با دسترسی‌های این لایسنس در ربات خصوصی مجاز می‌شود.
    telegram_bot_enabled = Column(Boolean, default=False, nullable=False)
    telegram_user_id = Column(BigInteger, nullable=True, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class VpnUser(Base):
    __tablename__ = "vpn_users"

    id = Column(Integer, primary_key=True, index=True)
    # collation=utf8mb4_bin: هم یوزرنیم و هم پسورد نسبت به حروف بزرگ/کوچک
    # حساس باشند ("User1" با "user1" یکی نیست)، چه در چک یکتا بودن یوزرنیم
    # و چه در تطبیق پسورد.
    username = Column(String(64, collation="utf8mb4_bin"), unique=True, index=True, nullable=False)
    password = Column(String(255, collation="utf8mb4_bin"), nullable=False)  # plain for PPP secrets file / hashed check for OpenVPN

    # توکن تصادفی و یکتای این کاربر برای «لینک اشتراک» (Subscription Link):
    # آدرس عمومی /sub/<sub_token> بدون نیاز به لاگین ادمین، وضعیت/حجم/مشخصات
    # اتصال این کاربر را نشان می‌دهد. جدا از پسورد پنل است و قابل ریست/تعویض.
    sub_token = Column(String(64, collation="utf8mb4_bin"), unique=True, index=True, nullable=True)

    # ادمینی که این کاربر VPN را ساخته/مالک آن است. هر ادمین زیرمجموعه فقط
    # یوزرهایی را می‌بیند/کنترل می‌کند که owner_admin_id آن‌ها خودش باشد؛
    # مگر اینکه see_all_users برایش فعال باشد یا superadmin باشد. NULL یعنی
    # یوزری قدیمی از قبل از این قابلیت (بدون مالک مشخص) - فقط برای
    # superadmin / ادمین‌های see_all_users قابل مشاهده است.
    owner_admin_id = Column(Integer, ForeignKey("admins.id"), nullable=True, index=True)

    enable_l2tp = Column(Boolean, default=True)
    enable_pptp = Column(Boolean, default=True)
    enable_openvpn = Column(Boolean, default=True)
    # فقط روی سرورهایی اثر دارد که زیرساخت SSTP با install/setup_sstp.sh
    # نصب شده باشد؛ در غیر این صورت این فلگ صرفاً در دیتابیس ذخیره می‌شود.
    enable_sstp = Column(Boolean, default=True)
    # فقط روی سرورهایی اثر دارد که زیرساخت IKEv2/IPsec با install/setup_ikev2.sh
    # نصب شده باشد؛ در غیر این صورت این فلگ صرفاً در دیتابیس ذخیره می‌شود.
    # احراز هویت این پروتکل EAP-MSCHAPv2 است (یوزرنیم/پسورد همین کاربر، بدون
    # سرتیفیکیت کلاینت - فقط سرور یک سرتیفیکیت برای احراز هویت خودش دارد).
    enable_ikev2 = Column(Boolean, default=True)

    # فقط روی سرورهایی اثر دارد که زیرساخت OpenConnect (ocserv - سازگار با
    # کلاینت Cisco AnyConnect) با install/setup_openconnect.sh نصب شده باشد؛
    # در غیر این صورت این فلگ صرفاً در دیتابیس ذخیره می‌شود. احراز هویت این
    # پروتکل با یوزرنیم/پسورد همین کاربر است (فایل ocpasswd، جدا از
    # chap-secrets/ipsec.secrets - نگاه کنید به vpn_manager.sync_openconnect_secrets).
    enable_openconnect = Column(Boolean, default=True)

    # هویت پایدار Xray برای VMess/VLESS. هر دو پروتکل عمداً به‌صورت پیش‌فرض
    # خاموش‌اند تا مهاجرت روی نصب‌های موجود هیچ دسترسی تازه‌ای را فعال نکند.
    # UUID مستقل از یوزرنیم/پسورد است و در ویرایش‌های عادی تغییر نمی‌کند.
    enable_vmess = Column(Boolean, default=False, nullable=False)
    enable_vless = Column(Boolean, default=False, nullable=False)
    # قطع اینترنت Xray بدون بستن خود اتصال: کلاینت Connected می‌ماند اما
    # ترافیک اینترنتی همان پروتکل با fwmark/nftables DROP می‌شود.
    vmess_internet_blocked = Column(Boolean, default=False, nullable=False)
    vless_internet_blocked = Column(Boolean, default=False, nullable=False)
    xray_uuid = Column(
        String(36, collation="utf8mb4_bin"),
        unique=True, index=True, nullable=True,
        default=lambda: str(uuid.uuid4()),
    )

    # نحوه‌ی احراز هویت OpenVPN این کاربر (سرتیفیکیت همیشه برای همه لازم است؛
    # این فقط تعیین می‌کند لایه‌ی یوزر/پس هم اضافه شود یا نه):
    #   cert_only     -> فقط سرتیفیکیت. یوزرنیم/پسورد همین کاربر به‌صورت
    #                     نامرئی داخل خودِ فایل .ovpn جاسازی می‌شود (بلوک
    #                     <auth-user-pass>) تا سرور بتواند هویت را با
    #                     Common Name سرتیفیکیت تطبیق دهد، بدون این‌که کاربر
    #                     نهایی چیزی وارد کند یا حتی ببیند.
    #   cert_password -> علاوه بر سرتیفیکیت، کلاینت موقع اتصال یک باکس
    #                     یوزرنیم/پسورد هم نشان می‌دهد و کاربر باید دستی پر کند.
    # در هر دو حالت سرور همیشه چک می‌کند که یوزرنیم ارسالی دقیقاً با Common
    # Name همان سرتیفیکیتی که کلاینت با آن TLS handshake کرده یکی باشد - یعنی
    # حتی اگر یوزر/پس یک کاربر دیگر به‌نحوی لو برود، بدون داشتن سرتیفیکیت
    # اختصاصی همان کاربر امکان اتصال با آن هویت وجود ندارد.
    openvpn_auth_mode = Column(String(32), default="cert_only", nullable=False)

    # نحوه‌ی احراز هویت SSTP این کاربر. برخلاف OpenVPN، سرور SSTP (accel-ppp)
    # کلاینت را از طریق سرتیفیکیت شناسایی نمی‌کند - احراز هویت واقعی همیشه با
    # یوزرنیم/پسورد (PPP CHAP/PAP) انجام می‌شود. این فیلد فقط تعیین می‌کند که
    # آیا کاربر برای برقراری اتصال باید سرتیفیکیت TLS سرور SSTP را هم دانلود و
    # نصب/trust کند یا نه (لازم وقتی سرور از گواهی self-signed استفاده می‌کند،
    # نگاه کنید به install/setup_sstp.sh):
    #   password_only -> فقط یوزرنیم/پسورد لازم است (مثلاً گواهی دامنه از
    #                     Let's Encrypt و از قبل مورد اعتماد ویندوز/سیستم‌عامل است)
    #   cert_password -> علاوه بر یوزر/پس، سرتیفیکیت SSTP هم باید از صفحه‌ی
    #                     ساب دانلود و به کلاینت اضافه شود
    sstp_auth_mode = Column(String(32), default="password_only", nullable=False)

    quota_bytes = Column(BigInteger, default=0)   # 0 = نامحدود
    used_bytes = Column(BigInteger, default=0)

    max_devices = Column(Integer, default=1)      # تعداد کل تونل/اتصال هم‌زمان؛ مستقل از IP پابلیک
    # محدودیت سرعت قدیمی/سازگاری؛ مقدار جدید از دو جهت مستقل ساخته می‌شود.
    speed_limit_mbps = Column(Integer, default=0, nullable=False)
    # محدودیت مستقل دانلود/آپلود هر کاربر برحسب Mbps. صفر = بدون محدودیت.
    download_limit_mbps = Column(Integer, default=0, nullable=False)
    upload_limit_mbps = Column(Integer, default=0, nullable=False)

    # نحوه‌ی انقضا:
    #   fixed               -> از روی expire_date (تاریخ ثابت، توسط ادمین تعیین می‌شود)
    #   after_first_connect -> expire_date به‌صورت خودکار = تاریخ اولین اتصال + expire_after_days
    #                          (تا وصل نشده باشد expire_date خالی می‌ماند یعنی بدون انقضا)
    expire_mode = Column(String(32), default="fixed", nullable=False)
    expire_after_days = Column(Integer, nullable=True)
    first_connect_at = Column(DateTime, nullable=True)

    expire_date = Column(Date, nullable=True)      # null = بدون انقضا
    is_active = Column(Boolean, default=True)

    note = Column(Text, nullable=True)

    # Server placement for this account. JSON tokens: ["all"], ["local"],
    # or ["node:<id>", ...]. NULL is treated as "all" for backward
    # compatibility so upgrading never removes existing access.
    server_targets = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # کاربران همگام‌شده از کنترلر مرکزی روی یک Node. این دو فیلد باعث می‌شوند
    # همگام‌سازی فقط رکوردهای متعلق به همان کنترلر را ویرایش/حذف کند و به
    # کاربران محلی احتمالی روی سرور Node دست نزند.
    node_managed = Column(Boolean, default=False, nullable=False)
    node_source = Column(String(64), nullable=True, index=True)

    sessions = relationship("ConnectionLog", back_populates="user")
    owner_admin = relationship("Admin", foreign_keys=[owner_admin_id])


class VpnUserSubAlias(Base):
    """Legacy subscription tokens mapped to a user.

    Subscription URLs are permanent identifiers.  When a database restore,
    node import, or a future explicit token rotation changes ``sub_token``,
    the previous token is kept here so links already delivered to customers
    continue to work.
    """
    __tablename__ = "vpn_user_sub_aliases"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("vpn_users.id", ondelete="CASCADE"), nullable=False, index=True)
    token = Column(String(128, collation="utf8mb4_bin"), unique=True, index=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)



class ConnectionLog(Base):
    __tablename__ = "connection_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("vpn_users.id"), nullable=False)
    protocol = Column(String(16), nullable=False)   # l2tp / pptp / openvpn
    ip_address = Column(String(64), nullable=True)
    # پورت مبدأ TCP برای VMess/VLESS مستقیم؛ دو دستگاه پشت یک NAT را جدا می‌کند.
    source_port = Column(Integer, nullable=True)
    interface = Column(String(32), nullable=True)
    # آی‌پی مجازی داخل تونل؛ برای تشخیص سشن و اعمال محدودیت روی OpenVPN مشترک.
    tunnel_ip = Column(String(64), nullable=True)
    connect_time = Column(DateTime, default=datetime.utcnow)
    disconnect_time = Column(DateTime, nullable=True)
    bytes_in = Column(BigInteger, default=0)
    bytes_out = Column(BigInteger, default=0)
    is_online = Column(Boolean, default=True)
    # وضعیت حضور زنده‌ی سشن. active یعنی در نمونه‌ی اخیر ترافیک واقعی داشته،
    # idle یعنی تونل/سوکت هنوز برقرار است اما در همان بازه بایتی جابه‌جا نشده،
    # probing یعنی یک بار سیگنال اتصال گم شده و تا بررسی دوم (حداکثر ۱۰ ثانیه)
    # فرصت داده می‌شود، و offline فقط برای ردیف‌های بسته‌شده نگه داشته می‌شود.
    presence_state = Column(String(16), default="active", nullable=False)
    presence_failures = Column(Integer, default=0, nullable=False)
    last_seen_at = Column(DateTime, nullable=True)
    last_activity_at = Column(DateTime, nullable=True)
    # اثرانگشت شبکه‌ی Xray. وقتی source port قابل مشاهده باشد، ترکیب
    # protocol/public-IP/source-port اجازه می‌دهد دو اتصال هم‌زمان پشت یک NAT
    # به‌صورت best-effort از هم جدا شوند. این شناسه سخت‌افزاری نیست.
    device_fingerprint = Column(String(160), nullable=True, index=True)
    # فقط وقتی True می‌شود که پروتکل با شاهد اختصاصی همان سرویس تأیید شده باشد.
    # از 2.3.87 به بعد برای مصرف max_devices علاوه بر این فلگ، endpoint دقیق
    # access-log/listener و protocol_evidence_at نیز الزامی است؛ آمار online یا
    # افزایش شمارنده به‌تنهایی اجازه ساختن سشن در پروتکل خواهر را ندارد.
    identity_verified = Column(Boolean, default=False, nullable=False)
    # endpoint واقعیِ transport که در listener همان پروتکل دیده شده است. در
    # اتصال مستقیم با ip_address/source_port یکی است؛ پشت Nginx معمولاً
    # 127.0.0.1:ephemeral است و برای تشخیص قطع واقعی باید جدا نگهداری شود.
    transport_ip_address = Column(String(64), nullable=True)
    transport_source_port = Column(Integer, nullable=True)
    # آخرین زمانی که شاهد قوی و اختصاصی همان پروتکل دیده شد (access-log همان
    # daemon + socket دقیق همان listener). ردیف‌های قدیمی/مبهم تا دوباره با
    # شاهد قوی تأیید نشوند حق مصرف max_devices را ندارند.
    protocol_evidence_at = Column(DateTime, nullable=True)
    # برای VMess/VLESS: اتصال برقرار است اما چون از سقف دستگاه کاربر بیشتر است،
    # routing پویا آن را به outbound مسدود هدایت می‌کند.
    device_limit_blocked = Column(Boolean, default=False, nullable=False)
    # pid پردازش pppd مربوط به این سشن (فقط برای l2tp/pptp؛ توسط ppp_ip_up.sh
    # هنگام اتصال ارسال می‌شود). برای قطع دستی/اجباری سشن استفاده می‌شود چون
    # pppd نام‌کاربری را در آرگومان‌های خط فرمانش نمی‌گذارد.
    pid = Column(Integer, nullable=True)
    # پلتفرم واقعیِ اعلام‌شده توسط خودِ کلاینت:
    # - OpenVPN: از IV_PLAT (همیشه در دسترس) - windows / mac / linux / ios / android / ...
    # - L2TP: از AVPهای Host Name/Vendor Name که خود کلاینت هنگام برقراری
    #   تونل می‌فرستد (best effort - ppp_ip_up.sh) - مثلاً روترهای MikroTik
    #   دقیقاً "MikroTik" می‌فرستند؛ خیلی از کلاینت‌های دیگر این AVPها را
    #   نمی‌فرستند و در آن صورت خالی می‌ماند.
    # - PPTP: هیچ‌وقت پر نمی‌شود (pptpd چنین AVP/فیلدی در پروتکلش ندارد).
    platform = Column(String(32), nullable=True)
    # نام/نسخه‌ی کلاینت (فقط OpenVPN؛ از IV_GUI_VER) مثل "net.openvpn.connect.ios 3.4.2"
    client_info = Column(String(128), nullable=True)
    # Stable fleet-wide admission identity. The same hook retry keeps the same
    # key, while a real new tunnel gets a new one. It is exported in Node
    # snapshots so the controller can count one account across all servers.
    cluster_session_key = Column(String(64), nullable=True, index=True)

    user = relationship("VpnUser", back_populates="sessions")


class ClusterAdmissionReservation(Base):
    __tablename__ = "cluster_admission_reservations"
    __table_args__ = (
        UniqueConstraint("server_key", "session_key", name="uq_cluster_admission_server_session"),
    )

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64, collation="utf8mb4_bin"), nullable=False, index=True)
    server_key = Column(String(128), nullable=False, index=True)
    session_key = Column(String(64), nullable=False, index=True)
    protocol = Column(String(16), nullable=False)
    ip_address = Column(String(64), nullable=True)
    connect_time = Column(DateTime, default=datetime.utcnow, nullable=False)
    replaces_session_key = Column(String(64), nullable=True)
    last_seen_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)


class XrayUsageCounter(Base):
    """آخرین شمارنده‌های تجمعی Xray برای محاسبه‌ی دلتای مصرف هر کاربر.

    Xray شمارنده‌ها را از زمان استارت همان سرویس نگه می‌دارد و با ری‌استارت
    صفر می‌کند. این جدول مانع double-count می‌شود و صفرشدن شمارنده را هم
    تشخیص می‌دهد. داده‌ی این جدول runtime-only است و جزو هویت/بکاپ کاربر نیست.
    """
    __tablename__ = "xray_usage_counters"
    __table_args__ = (UniqueConstraint("user_id", "protocol", name="uq_xray_usage_user_protocol"),)

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("vpn_users.id", ondelete="CASCADE"), nullable=False, index=True)
    protocol = Column(String(16), nullable=False)
    last_uplink = Column(BigInteger, default=0, nullable=False)
    last_downlink = Column(BigInteger, default=0, nullable=False)
    # baseline مستقل nftables تا قطع موقت StatsService باعث از دست رفتن مصرف نشود.
    last_nft_uplink = Column(BigInteger, default=0, nullable=False)
    last_nft_downlink = Column(BigInteger, default=0, nullable=False)
    # منبع شمارنده برای جلوگیری از double-count هنگام fallback بین API Xray
    # و شمارنده‌های nftables.
    usage_source = Column(String(16), default="xray", nullable=False)
    # آخرین لحظه‌ای که افزایش واقعی شمارنده‌ی Xray دیده شد. updated_at در هر
    # نمونه‌برداری تغییر می‌کند و برای تشخیص فعالیت مناسب نیست.
    last_activity_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    user = relationship("VpnUser")


class BannedIP(Base):
    """آی‌پی‌های عمومی مسدود شده: هر آی‌پی که اینجا ثبت شود با یک قانون
    iptables (زنجیره‌ی اختصاصی VPN-PANEL-BANS) در سطح شبکه DROP می‌شود - یعنی
    حتی قبل از رسیدن به مرحله‌ی احراز هویت هر پروتکل (L2TP/PPTP/OpenVPN/SSTP)
    بسته‌هایش دور ریخته می‌شوند و امکان اتصال مجدد از همان آی‌پی وجود ندارد،
    حتی با یوزرنیم/پسورد یا سرتیفیکیت دیگر. مستقل از یوزر VPN است (یک آی‌پی
    ممکن است هیچ‌وقت به یک کاربر خاص مرتبط نبوده باشد، مثلاً یک آی‌پی مزاحم
    که فقط تلاش‌های ناموفق اتصال داشته)."""
    __tablename__ = "banned_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(64), unique=True, index=True, nullable=False)
    reason = Column(String(255), nullable=True)
    banned_by_admin_id = Column(Integer, ForeignKey("admins.id"), nullable=True)
    # مالک دامنه داده برای ادمین‌های زیرمجموعه. برای رکوردهای جدید برابر
    # ادمینی است که IP مربوط به کاربران اوست؛ NULL فقط برای رکوردهای قدیمی/سراسری.
    owner_admin_id = Column(Integer, ForeignKey("admins.id"), nullable=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    banned_by_admin = relationship("Admin", foreign_keys=[banned_by_admin_id])


class InternetBlockedIP(Base):
    """Public client IPs whose VPN access is temporarily cut.

    This is intentionally separate from ``BannedIP``. A ban is a security
    action that drops every packet from the source IP. An internet cut is a
    reversible operator action that blocks only the listeners/transports of
    the panel's nine VPN protocols while leaving the web panel and unrelated
    server services reachable.
    """
    __tablename__ = "internet_blocked_ips"

    id = Column(Integer, primary_key=True, index=True)
    ip_address = Column(String(64), unique=True, index=True, nullable=False)
    # Snapshot ids/names intentionally have no foreign keys: an operator must
    # be able to delete a VPN user or delegated admin without losing or
    # blocking restoration of an active public-IP cut record.
    user_id = Column(Integer, nullable=True, index=True)
    username = Column(String(64), nullable=True, index=True)
    protocol = Column(String(32), nullable=True)
    reason = Column(String(255), nullable=True)
    blocked_by_admin_id = Column(Integer, nullable=True, index=True)
    # مالک کاربر/رکورد برای جداسازی کامل داده‌های هر ادمین زیرمجموعه.
    owner_admin_id = Column(Integer, nullable=True, index=True)
    blocked_by_username = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)


class VpnNode(Base):
    """سرور متصل به پنل مرکزی. هر Node یک نصب دیگر از همین پنل است که
    Node Agent داخلی آن با توکن مشترک، کاربران را دریافت و سرویس‌های VPN
    خودش را همگام می‌کند. last_snapshot شامل آدرس عمومی، پورت‌ها و وضعیت
    واقعی پروتکل‌های همان Node است و برای ساخت لینک‌های چندسروره استفاده می‌شود.
    """
    __tablename__ = "vpn_nodes"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(96), unique=True, nullable=False)
    api_url = Column(String(512), unique=True, nullable=False)
    api_token = Column(Text, nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)
    verify_tls = Column(Boolean, default=True, nullable=False)
    weight = Column(Integer, default=100, nullable=False)
    ssh_host = Column(String(255), nullable=True)
    ssh_port = Column(Integer, default=22, nullable=False)
    ssh_username = Column(String(128), nullable=True)
    ssh_password_enc = Column(Text, nullable=True)
    # Optional node-panel superadmin credentials. The password is encrypted
    # with the controller JWT secret and is never returned by the API. These
    # fields are used only to create a short-lived, one-time remote admin
    # handoff when the main-panel superadmin explicitly opens the node panel.
    panel_admin_username = Column(String(128), nullable=True)
    panel_admin_password_enc = Column(Text, nullable=True)
    remote_admin_enabled = Column(Boolean, default=False, nullable=False)
    # Whether this server is available in user create/edit placement and
    # subscription provisioning. This is separate from enabled: disabling
    # assignment keeps the node online and manageable.
    user_assignment_enabled = Column(Boolean, default=True, nullable=False)
    # UI mode for this registered node. True keeps the dedicated node panel;
    # False exposes the full local panel UI while the server remains a node.
    node_panel_enabled = Column(Boolean, default=True, nullable=False)
    protocol_domains = Column(Text, nullable=True)
    status = Column(String(32), default="unknown", nullable=False)
    last_seen_at = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    last_snapshot = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


class Setting(Base):
    __tablename__ = "settings"

    key = Column(String(64), primary_key=True)
    value = Column(Text, nullable=True)


class ReservedLicense(Base):
    """صف لایسنس‌های رزروشده (خریداری‌شده برای بعد). وقتی لایسنس فعلی
    (license_key در Setting) منقضی/نامعتبر شود، license_manager به‌صورت
    خودکار اولین ردیف این صف (بر اساس order) را امتحان می‌کند و اگر معتبر
    بود، همان لحظه جای لایسنس فعلی می‌نشیند - بدون این‌که پنل هرگز قفل شود.
    عمداً هیچ endpoint حذفی دستی برای این جدول وجود ندارد: یک ادمین نمی‌تواند
    مستقیماً از همین‌جا یک ردیف را پاک کند - اما list_reserved_licenses
    به‌صورت خودکار ردیف‌هایی را که دیگر برای این پنل معتبر نیستند (لایسنس از
    پنل لایسنس پاک شده یا رزروش به سرور دیگری داده شده) از صف حذف می‌کند تا
    دیگر به این ادمین نشان داده نشوند."""
    __tablename__ = "reserved_licenses"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(128, collation="utf8mb4_bin"), unique=True, nullable=False)
    order = Column(Integer, nullable=False)
    added_at = Column(DateTime, default=datetime.utcnow)
    # آی‌پی‌ای که license-server در لحظه‌ی رزرو، به‌عنوان "رزروشده برای این
    # پنل" روی لایسنس ثبت کرد (پاسخ reserved_ip از _call_verify هنگام رزرو).
    # بعداً در list_reserved_licenses با reserved_ip فعلیِ همان لایسنس مقایسه
    # می‌شود - اگر فرق کند یعنی رزرو به سرور دیگری داده شده. برای ردیف‌های
    # قدیمی (قبل از این فیلد) می‌تواند خالی باشد.
    reserved_ip = Column(String(64), nullable=True)


class OpenvpnExtraPort(Base):
    """پورت‌های اضافه‌ی OpenVPN (علاوه بر دو پورت اصلی UDP/TCP در Settings >
    پروتکل‌ها). هرکدام از این‌ها یک پردازش OpenVPN مستقل و واقعی است (کانفیگ،
    ساب‌نت و systemd unit مخصوص خودش)، نه یک فوروارد فایروال - کاملاً از
    داخل پنل مدیریت می‌شود (manage_openvpn_extra_ports.sh) و می‌توان هرچند
    پورت که خواستی هم برای tcp و هم برای udp اضافه کرد. پنل هیچ قانون
    iptables/فایروالی برای این پورت‌ها نمی‌زند؛ باز/بسته بودنشان روی سرور
    مسئولیت دستی ادمین است.

    is_active: این ردیف یک «استخر» (pool) دائمی از پورت‌های رزروشده است -
    این ستون تعیین می‌کند لیسنر واقعی OpenVPN همین حالا روشن است یا نه، اما
    خودِ ردیف (و در نتیجه شماره‌پورتش) هیچ‌وقت به‌خاطر خاموش‌شدن از دیتابیس
    حذف نمی‌شود. build_client_ovpn همیشه همه‌ی ردیف‌ها (فعال و غیرفعال) را
    در فایل کاربر می‌گنجاند؛ یعنی یک‌بار که یک پورت به این استخر اضافه شد،
    از آن به بعد روشن/خاموش‌کردنش هیچ‌وقت نیاز به دانلود دوباره‌ی فایل توسط
    کاربر ندارد - فقط حذف کامل از استخر (delete، نه توگل) این تضمین را از
    بین می‌برد."""
    __tablename__ = "openvpn_extra_ports"

    id = Column(Integer, primary_key=True, index=True)
    port = Column(Integer, nullable=False)
    protocol = Column(String(8), nullable=False)  # "tcp" یا "udp"
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        UniqueConstraint("port", "protocol", name="uq_openvpn_extra_port_proto"),
    )
