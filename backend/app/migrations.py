"""
مهاجرت سبک برای پایگاه‌داده‌های موجود (نصب‌های قبلی): چون این پروژه از Alembic
استفاده نمی‌کند، `Base.metadata.create_all` فقط جدول‌های جدید را می‌سازد و ستون‌های
تازه به مدل‌های موجود اضافه نمی‌شوند. این ماژول هنگام استارت بک‌اند بررسی می‌کند
چه ستون‌هایی کم است و آن‌ها را با ALTER TABLE اضافه می‌کند. برای نصب تازه، جدول از
ابتدا با ستون‌های کامل ساخته می‌شود و این تابع کاری انجام نمی‌دهد.
"""
import logging
import uuid
from datetime import datetime, timedelta
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

logger = logging.getLogger("vpn-panel.migrations")

# (table, column, ddl_type_and_default)
_REQUIRED_COLUMNS = [
    ("vpn_users", "expire_mode", "VARCHAR(32) NOT NULL DEFAULT 'fixed'"),
    ("vpn_users", "expire_after_days", "INT NULL"),
    ("vpn_users", "first_connect_at", "DATETIME NULL"),
    # لیست بخش‌های مجاز پنل برای ادمین زیرمجموعه (جدا شده با کاما)
    ("admins", "permissions", "VARCHAR(2048) NULL"),
    # آیا این ادمین زیرمجموعه به کل یوزرهای سرور (نه فقط یوزرهای خودش) دسترسی دارد
    ("admins", "see_all_users", "BOOLEAN NOT NULL DEFAULT 0"),
    ("admins", "server_targets", "TEXT NULL"),
    # ادمین مالک هر یوزر VPN (برای محدودسازی دید هر ادمین به یوزرهای خودش)
    ("vpn_users", "owner_admin_id", "INT NULL"),
    # سقف تعداد یوزر / حجم کل / تاریخ انقضای اشتراک هر ادمین زیرمجموعه
    ("admins", "max_users", "INT NULL"),
    ("admins", "max_total_quota_bytes", "BIGINT NULL"),
    ("admins", "subscription_expire_date", "DATE NULL"),
    ("admins", "subscription_expire_at", "DATETIME NULL"),
    ("admins", "managed_by_license", "BOOLEAN NOT NULL DEFAULT 0"),
    ("admins", "access_license_code", "VARCHAR(64) NULL"),
    ("admins", "license_activated_at", "DATETIME NULL"),
    ("admins", "license_locked", "BOOLEAN NOT NULL DEFAULT 0"),
    ("admins", "telegram_bot_enabled", "BOOLEAN NOT NULL DEFAULT 0"),
    ("admins", "telegram_user_id", "BIGINT NULL"),
    ("admins", "telegram_bot_opted_out", "BOOLEAN NOT NULL DEFAULT 0"),
    ("admins", "last_login_at", "DATETIME NULL"),
    ("telegram_admin_groups", "access_mode", "VARCHAR(32) NOT NULL DEFAULT 'all_members'"),
    ("admins", "password_vault_enc", "TEXT NULL"),
    # مالک رکوردهای امنیتی/قطع اینترنت برای جداسازی داده ادمین‌های زیرمجموعه.
    ("banned_ips", "owner_admin_id", "INT NULL"),
    ("internet_blocked_ips", "owner_admin_id", "INT NULL"),
    # نقش حسابی که با لایسنس داخلی ساخته می‌شود. لایسنس‌های قدیمی همگی
    # ادمین زیرمجموعه محسوب می‌شوند.
    ("admin_access_licenses", "role", "VARCHAR(32) NOT NULL DEFAULT 'admin'"),
    # محدوده سرورهای قابل دسترسی برای لایسنس داخلی ادمین
    ("admin_access_licenses", "server_targets", "TEXT NULL"),
    ("admin_access_licenses", "telegram_bot_enabled", "BOOLEAN NOT NULL DEFAULT 0"),
    ("admin_access_licenses", "telegram_user_id", "BIGINT NULL"),
    # پی‌آی‌دی پردازش pppd هر سشن L2TP/PPTP، برای قطع دستی مستقیم
    ("connection_logs", "pid", "INT NULL"),
    ("connection_logs", "platform", "VARCHAR(32) NULL"),
    ("connection_logs", "client_info", "VARCHAR(128) NULL"),
    ("connection_logs", "source_port", "INT NULL"),
    # توکن یکتای لینک اشتراک (Subscription Link) هر کاربر VPN
    ("vpn_users", "sub_token", "VARCHAR(64) NULL"),
    # نحوه‌ی احراز هویت OpenVPN این کاربر: cert_only / cert_password
    ("vpn_users", "openvpn_auth_mode", "VARCHAR(32) NOT NULL DEFAULT 'cert_only'"),
    # اجازه‌ی اتصال این کاربر با SSTP (کنار L2TP/PPTP/OpenVPN)
    ("vpn_users", "enable_sstp", "BOOLEAN NOT NULL DEFAULT 1"),
    # نحوه‌ی احراز هویت SSTP این کاربر: password_only / cert_password
    ("vpn_users", "sstp_auth_mode", "VARCHAR(32) NOT NULL DEFAULT 'password_only'"),
    # آیا این پورت اضافه‌ی OpenVPN همین حالا روشن است - ردیف حتی وقتی خاموش
    # می‌شود در دیتابیس (استخر پورت‌های رزروشده) باقی می‌ماند تا کانفیگ‌های
    # قبلاً دانلودشده‌ی کاربران همیشه شامل همین شماره‌پورت بمانند.
    ("openvpn_extra_ports", "is_active", "BOOLEAN NOT NULL DEFAULT 1"),
    # آی‌پی‌ای که license-server در لحظه‌ی رزرو روی این کد به‌عنوان "رزروشده
    # برای این پنل" ثبت کرد - برای تشخیص خودکار اینکه رزرو بعداً به سرور
    # دیگری داده شده یا نه (list_reserved_licenses).
    ("reserved_licenses", "reserved_ip", "VARCHAR(64) NULL"),
    # اجازه‌ی اتصال این کاربر با IKEv2/IPsec (EAP-MSCHAPv2) کنار سایر پروتکل‌ها
    ("vpn_users", "enable_ikev2", "BOOLEAN NOT NULL DEFAULT 1"),
    # اجازه‌ی اتصال این کاربر با OpenConnect (ocserv / Cisco AnyConnect) کنار
    # سایر پروتکل‌ها
    ("vpn_users", "enable_openconnect", "BOOLEAN NOT NULL DEFAULT 1"),
    # افزونه‌های اختیاری Xray؛ مهاجرت عمداً هیچ‌کدام را برای کاربران قبلی فعال نمی‌کند.
    ("vpn_users", "enable_vmess", "BOOLEAN NOT NULL DEFAULT 0"),
    ("vpn_users", "enable_vless", "BOOLEAN NOT NULL DEFAULT 0"),
    ("vpn_users", "vmess_internet_blocked", "BOOLEAN NOT NULL DEFAULT 0"),
    ("vpn_users", "vless_internet_blocked", "BOOLEAN NOT NULL DEFAULT 0"),
    ("connection_logs", "device_limit_blocked", "BOOLEAN NOT NULL DEFAULT 0"),
    ("connection_logs", "presence_state", "VARCHAR(16) NOT NULL DEFAULT 'active'"),
    ("connection_logs", "presence_failures", "INT NOT NULL DEFAULT 0"),
    ("connection_logs", "last_seen_at", "DATETIME NULL"),
    ("connection_logs", "last_activity_at", "DATETIME NULL"),
    ("connection_logs", "device_fingerprint", "VARCHAR(160) NULL"),
    ("connection_logs", "identity_verified", "BOOLEAN NOT NULL DEFAULT 0"),
    ("connection_logs", "transport_ip_address", "VARCHAR(64) NULL"),
    ("connection_logs", "transport_source_port", "INT NULL"),
    ("connection_logs", "protocol_evidence_at", "DATETIME NULL"),
    ("vpn_users", "node_managed", "BOOLEAN NOT NULL DEFAULT 0"),
    ("vpn_users", "node_source", "VARCHAR(64) NULL"),
    ("vpn_users", "server_targets", "TEXT NULL"),
    ("vpn_nodes", "verify_tls", "BOOLEAN NOT NULL DEFAULT 1"),
    ("vpn_nodes", "ssh_host", "VARCHAR(255) NULL"),
    ("vpn_nodes", "ssh_port", "INT NOT NULL DEFAULT 22"),
    ("vpn_nodes", "ssh_username", "VARCHAR(128) NULL"),
    ("vpn_nodes", "ssh_password_enc", "TEXT NULL"),
    ("vpn_nodes", "panel_admin_username", "VARCHAR(128) NULL"),
    ("vpn_nodes", "panel_admin_password_enc", "TEXT NULL"),
    ("vpn_nodes", "remote_admin_enabled", "BOOLEAN NOT NULL DEFAULT 0"),
    ("vpn_nodes", "user_assignment_enabled", "BOOLEAN NOT NULL DEFAULT 1"),
    ("vpn_nodes", "node_panel_enabled", "BOOLEAN NOT NULL DEFAULT 1"),
    ("vpn_nodes", "protocol_domains", "TEXT NULL"),
    ("vpn_users", "xray_uuid", "VARCHAR(36) NULL"),
    # محدودیت سرعت هر کاربر برحسب Mbps. صفر = بدون محدودیت
    ("vpn_users", "speed_limit_mbps", "INT NOT NULL DEFAULT 0"),
    ("vpn_users", "download_limit_mbps", "INT NOT NULL DEFAULT 0"),
    ("vpn_users", "upload_limit_mbps", "INT NOT NULL DEFAULT 0"),
    ("connection_logs", "tunnel_ip", "VARCHAR(64) NULL"),
    ("connection_logs", "cluster_session_key", "VARCHAR(64) NULL"),
    # آخرین فعالیت واقعی VMess/VLESS برای fallback وضعیت آنلاین.
    ("xray_usage_counters", "last_activity_at", "DATETIME NULL"),
    ("xray_usage_counters", "usage_source", "VARCHAR(16) NOT NULL DEFAULT 'xray'"),
    ("xray_usage_counters", "last_nft_uplink", "BIGINT NOT NULL DEFAULT 0"),
    ("xray_usage_counters", "last_nft_downlink", "BIGINT NOT NULL DEFAULT 0"),
]

# ستون‌هایی که باید نسبت به حروف بزرگ/کوچک حساس باشند (کالیشن پیش‌فرض
# utf8mb4 در MySQL حساس به بزرگ/کوچکی حروف نیست؛ اینجا برای نصب‌های قبلی هم
# همان کالیشن حساس مدل‌ها (utf8mb4_bin) روی جدول واقعی اعمال می‌شود).
_REQUIRED_COLLATIONS = [
    ("admins", "username", "VARCHAR(64)", "NOT NULL"),
    ("admins", "access_license_code", "VARCHAR(64)", "NULL"),
    ("admin_access_licenses", "code", "VARCHAR(64)", "NOT NULL"),
    ("vpn_users", "username", "VARCHAR(64)", "NOT NULL"),
    ("vpn_users", "password", "VARCHAR(255)", "NOT NULL"),
]


def run_migrations(engine: Engine) -> None:
    try:
        insp = inspect(engine)
        existing_tables = set(insp.get_table_names())

        with engine.begin() as conn:
            for table, column, ddl in _REQUIRED_COLUMNS:
                if table not in existing_tables:
                    # جدول هنوز وجود ندارد؛ create_all آن را با شمای کامل می‌سازد
                    continue
                cols = {c["name"] for c in insp.get_columns(table)}
                if column not in cols:
                    logger.info("migrating: adding column %s.%s", table, column)
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))

            # Older builds created admins.permissions as VARCHAR(255), which is
            # too short for granular license permissions. Widen it idempotently.
            if "admins" in existing_tables:
                try:
                    conn.execute(text("ALTER TABLE admins MODIFY COLUMN permissions VARCHAR(2048) NULL"))
                except Exception:
                    logger.exception("خطا در افزایش طول ستون admins.permissions")

            # انتقال مقدار محدودیت یکسان نسخه قبل به دو ستون جدید، فقط
            # برای کاربرانی که هنوز مقدار مستقل نگرفته‌اند.
            if "vpn_users" in existing_tables:
                try:
                    fresh_cols = {c["name"] for c in inspect(conn).get_columns("vpn_users")}
                    if {"speed_limit_mbps", "download_limit_mbps", "upload_limit_mbps"}.issubset(fresh_cols):
                        conn.execute(text(
                            "UPDATE vpn_users SET "
                            "download_limit_mbps = CASE WHEN download_limit_mbps = 0 AND upload_limit_mbps = 0 THEN speed_limit_mbps ELSE download_limit_mbps END, "
                            "upload_limit_mbps = CASE WHEN download_limit_mbps = 0 AND upload_limit_mbps = 0 THEN speed_limit_mbps ELSE upload_limit_mbps END, "
                            "speed_limit_mbps = 0 "
                            "WHERE speed_limit_mbps > 0"
                        ))
                except Exception:
                    logger.exception("خطا در انتقال محدودیت سرعت قدیمی به دانلود/آپلود")

            for table, column, coltype, extra in _REQUIRED_COLLATIONS:
                if table not in existing_tables:
                    continue
                cols = {c["name"] for c in insp.get_columns(table)}
                if column not in cols:
                    continue
                # قبل از ALTER چک کن کالیشن همین الان هم utf8mb4_bin هست یا نه.
                # بدون این چک، این MODIFY COLUMN (که در InnoDB معمولاً کل جدول
                # را rebuild می‌کند، نه یک عملیات instant) روی *هر* ری‌استارت
                # بک‌اند اجرا می‌شد - حتی وقتی چیزی برای تغییر نبود - و روی
                # جدول‌هایی مثل vpn_users که ممکن است ردیف‌های زیادی داشته
                # باشند، همین باعث می‌شد استارت سرویس (و در نتیجه بالا آمدن
                # پنل - چون nginx تا وقتی بک‌اند جواب ندهد منتظر می‌ماند) کند
                # شود. این ری‌استارت دقیقاً همان چیزی است که update.sh به‌طور
                # خودکار در پایان هر آپدیت انجام می‌دهد.
                try:
                    current = conn.execute(
                        text(
                            "SELECT COLLATION_NAME FROM information_schema.COLUMNS "
                            "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :t AND COLUMN_NAME = :c"
                        ),
                        {"t": table, "c": column},
                    ).scalar()
                except Exception:
                    current = None

                if current == "utf8mb4_bin":
                    continue

                try:
                    conn.execute(text(
                        f"ALTER TABLE {table} MODIFY COLUMN {column} {coltype} "
                        f"CHARACTER SET utf8mb4 COLLATE utf8mb4_bin {extra}"
                    ))
                except Exception:
                    logger.exception(
                        "خطا در تنظیم حساسیت به حروف بزرگ/کوچک برای %s.%s", table, column
                    )

            # Granular admin permissions need more room than the legacy four-section list.
            if "admins" in existing_tables:
                try:
                    length = conn.execute(text(
                        "SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS "
                        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME='admins' AND COLUMN_NAME='permissions'"
                    )).scalar()
                    if length is not None and int(length) < 2048:
                        conn.execute(text("ALTER TABLE admins MODIFY COLUMN permissions VARCHAR(2048) NULL"))
                except Exception:
                    logger.exception("خطا در افزایش ظرفیت دسترسی‌های ادمین")

            # برای همه‌ی کاربران قدیمی UUID پایدار و تصادفی بساز. این کار
            # بعد از اضافه‌شدن ستون و قبل از ساخت ایندکس یکتا انجام می‌شود و
            # idempotent است: رکوردهایی که UUID دارند دست‌نخورده می‌مانند.
            if "vpn_users" in existing_tables:
                # Re-inspect inside the same migration transaction so a column
                # added just above is visible immediately on the first startup.
                fresh_insp = inspect(conn)
                cols = {c["name"] for c in fresh_insp.get_columns("vpn_users")}
                if "xray_uuid" in cols:
                    missing_ids = conn.execute(
                        text("SELECT id FROM vpn_users WHERE xray_uuid IS NULL OR xray_uuid = ''")
                    ).scalars().all()
                    for user_id in missing_ids:
                        conn.execute(
                            text("UPDATE vpn_users SET xray_uuid = :value WHERE id = :id"),
                            {"value": str(uuid.uuid4()), "id": user_id},
                        )
                    existing_indexes = {ix["name"] for ix in fresh_insp.get_indexes("vpn_users")}
                    if "ix_vpn_users_xray_uuid" not in existing_indexes:
                        try:
                            conn.execute(text(
                                "ALTER TABLE vpn_users ADD UNIQUE INDEX ix_vpn_users_xray_uuid (xray_uuid)"
                            ))
                        except Exception:
                            logger.exception("خطا در ساخت ایندکس یکتای xray_uuid")

            # Each Telegram numeric ID may control at most one panel admin and
            # may be owned by at most one bot-capable admin license. Older
            # releases created normal indexes with these same names, so inspect
            # the uniqueness flag and replace a non-unique index when needed.
            def _dedupe_telegram_ids(table: str) -> None:
                # A UNIQUE index cannot be installed while legacy duplicate IDs
                # exist. Resolve them deterministically instead of silently
                # continuing without the security constraint. For admins, keep
                # the oldest account and return every duplicate account to the
                # explicit deferred-binding state so its own license can be
                # connected again safely. For licenses, prefer the license that
                # belongs to the retained linked admin, then the oldest row.
                duplicates = conn.execute(text(
                    f"SELECT telegram_user_id FROM {table} "
                    "WHERE telegram_user_id IS NOT NULL "
                    "GROUP BY telegram_user_id HAVING COUNT(*) > 1"
                )).scalars().all()
                for raw_value in duplicates:
                    value = int(raw_value)
                    if table == "admins":
                        rows = conn.execute(text(
                            "SELECT id FROM admins WHERE telegram_user_id = :value ORDER BY id ASC"
                        ), {"value": value}).scalars().all()
                        if not rows:
                            continue
                        keep_id = int(rows[0])
                        duplicate_ids = [int(item) for item in rows[1:]]
                        if duplicate_ids:
                            params = {f"id_{i}": item for i, item in enumerate(duplicate_ids)}
                            placeholders = ",".join(f":id_{i}" for i in range(len(duplicate_ids)))
                            conn.execute(text(
                                f"UPDATE admins SET telegram_user_id = NULL, "
                                f"telegram_bot_enabled = 0, telegram_bot_opted_out = 1 "
                                f"WHERE id IN ({placeholders})"
                            ), params)
                            conn.execute(text(
                                f"UPDATE admin_access_licenses SET telegram_user_id = NULL "
                                f"WHERE used_by_admin_id IN ({placeholders})"
                            ), params)
                            logger.warning(
                                "Removed duplicate Telegram ID %s from admin IDs %s; kept admin %s",
                                value, duplicate_ids, keep_id,
                            )
                        continue

                    linked_admin_id = conn.execute(text(
                        "SELECT id FROM admins WHERE telegram_user_id = :value ORDER BY id ASC LIMIT 1"
                    ), {"value": value}).scalar()
                    rows = conn.execute(text(
                        "SELECT id, used_by_admin_id FROM admin_access_licenses "
                        "WHERE telegram_user_id = :value ORDER BY id ASC"
                    ), {"value": value}).mappings().all()
                    if not rows:
                        continue
                    winner = None
                    if linked_admin_id is not None:
                        winner = next((row for row in rows if row.get("used_by_admin_id") == linked_admin_id), None)
                    winner = winner or rows[0]
                    loser_ids = [int(row["id"]) for row in rows if int(row["id"]) != int(winner["id"])]
                    if loser_ids:
                        params = {f"id_{i}": item for i, item in enumerate(loser_ids)}
                        placeholders = ",".join(f":id_{i}" for i in range(len(loser_ids)))
                        conn.execute(text(
                            f"UPDATE admin_access_licenses SET telegram_user_id = NULL "
                            f"WHERE id IN ({placeholders})"
                        ), params)
                        logger.warning(
                            "Removed duplicate Telegram ID %s from license IDs %s; kept license %s",
                            value, loser_ids, int(winner["id"]),
                        )

            def _ensure_unique_telegram_index(table: str, index_name: str) -> None:
                _dedupe_telegram_ids(table)
                fresh = inspect(conn)
                indexes = {ix.get("name"): ix for ix in fresh.get_indexes(table)}
                existing = indexes.get(index_name)
                if existing and bool(existing.get("unique")):
                    return
                if existing:
                    dialect = str(conn.dialect.name or "")
                    if dialect in {"mysql", "mariadb"}:
                        conn.execute(text(f"DROP INDEX {index_name} ON {table}"))
                    else:
                        conn.execute(text(f"DROP INDEX {index_name}"))
                conn.execute(text(f"CREATE UNIQUE INDEX {index_name} ON {table} (telegram_user_id)"))

            if "admins" in existing_tables:
                try:
                    _ensure_unique_telegram_index("admins", "ix_admins_telegram_user_id")
                except Exception:
                    logger.exception("خطا در ساخت ایندکس یکتای آیدی تلگرام ادمین")

            # Backfill the explicit deferred-bot marker for accounts created by
            # versions 2.3.162-2.3.165. These accounts have a used bot-capable
            # license but no Telegram ID because the registrant selected the
            # opt-out switch during registration.
            if "admins" in existing_tables and "admin_access_licenses" in existing_tables:
                try:
                    fresh_insp = inspect(conn)
                    admin_cols = {c["name"] for c in fresh_insp.get_columns("admins")}
                    license_cols = {c["name"] for c in fresh_insp.get_columns("admin_access_licenses")}
                    if "telegram_bot_opted_out" in admin_cols and {"telegram_bot_enabled", "telegram_user_id"}.issubset(license_cols):
                        conn.execute(text(
                            "UPDATE admins SET telegram_bot_opted_out = 1 "
                            "WHERE telegram_user_id IS NULL AND telegram_bot_enabled = 0 "
                            "AND EXISTS (SELECT 1 FROM admin_access_licenses l "
                            "WHERE l.used_by_admin_id = admins.id "
                            "AND l.telegram_bot_enabled = 1 AND l.telegram_user_id IS NULL)"
                        ))
                    _ensure_unique_telegram_index(
                        "admin_access_licenses",
                        "ix_admin_access_licenses_telegram_user_id",
                    )
                except Exception:
                    logger.exception("خطا در مهاجرت اتصال یک‌به‌یک تلگرام و لایسنس")

            # Speed up the online-users endpoint. This composite index matches
            # its hot filter and ordering path and avoids a full scan as the
            # connection history grows.
            if "connection_logs" in existing_tables:
                try:
                    fresh_insp = inspect(conn)
                    existing_indexes = {ix["name"] for ix in fresh_insp.get_indexes("connection_logs")}
                    if "ix_connection_logs_online_fast" not in existing_indexes:
                        conn.execute(text(
                            "CREATE INDEX ix_connection_logs_online_fast "
                            "ON connection_logs (is_online, device_limit_blocked, connect_time, user_id)"
                        ))
                    if "ix_connection_logs_device_fingerprint" not in existing_indexes:
                        conn.execute(text(
                            "CREATE INDEX ix_connection_logs_device_fingerprint "
                            "ON connection_logs (device_fingerprint)"
                        ))
                except Exception:
                    logger.exception("خطا در ساخت ایندکس سریع کاربران آنلاین")

            # Keep every current subscription token as a permanent alias.
            # The alias table is created by Base.metadata.create_all before this
            # migration runs. INSERT IGNORE makes the backfill idempotent.
            if "vpn_users" in existing_tables and "vpn_user_sub_aliases" in existing_tables:
                try:
                    conn.execute(text(
                        "INSERT IGNORE INTO vpn_user_sub_aliases (user_id, token, created_at) "
                        "SELECT id, sub_token, UTC_TIMESTAMP() FROM vpn_users "
                        "WHERE sub_token IS NOT NULL AND sub_token <> ''"
                    ))
                except Exception:
                    logger.exception("خطا در ثبت alias لینک‌های اشتراک موجود")

            # ایندکس یکتای sub_token (برای نصب‌های قبلی که ستون تازه اضافه شده و
            # هنوز ایندکس ندارد؛ NULL چندتایی در MySQL روی یکتا بودن مشکلی ایجاد
            # نمی‌کند، پس برای یوزرهای قدیمیِ بدون sub_token هم مشکلی پیش نمی‌آید).
            if "vpn_users" in existing_tables:
                cols = {c["name"] for c in insp.get_columns("vpn_users")}
                if "sub_token" in cols:
                    existing_indexes = {ix["name"] for ix in insp.get_indexes("vpn_users")}
                    if "ix_vpn_users_sub_token" not in existing_indexes:
                        try:
                            conn.execute(text(
                                "ALTER TABLE vpn_users ADD UNIQUE INDEX ix_vpn_users_sub_token (sub_token)"
                            ))
                        except Exception:
                            logger.exception("خطا در ساخت ایندکس یکتای sub_token")

        # Keep this runtime-state reset in its own final transaction. The main
        # migration block contains legacy best-effort DDL; isolating this write
        # guarantees that a later incompatible ALTER cannot roll back the
        # marker or resurrect stale VMess/VLESS rows on the next restart.
        if "settings" in existing_tables and "connection_logs" in existing_tables:
            try:
                with engine.begin() as conn:
                    marker_key = "xray_activity_confirmation_v1"
                    marker = conn.execute(
                        text("SELECT value FROM settings WHERE `key` = :key"),
                        {"key": marker_key},
                    ).scalar()
                    if marker != "1":
                        conn.execute(text(
                            "UPDATE connection_logs SET "
                            "is_online = 0, presence_state = 'offline', "
                            "presence_failures = 2, device_limit_blocked = 0, "
                            "disconnect_time = COALESCE(disconnect_time, CURRENT_TIMESTAMP) "
                            "WHERE protocol IN ('vmess', 'vless') AND is_online = 1"
                        ))
                        updated = conn.execute(
                            text("UPDATE settings SET value = '1' WHERE `key` = :key"),
                            {"key": marker_key},
                        )
                        if int(updated.rowcount or 0) == 0:
                            conn.execute(
                                text("INSERT INTO settings (`key`, value) VALUES (:key, '1')"),
                                {"key": marker_key},
                            )


                    # 2.3.117: discard protocol-scoped admission residue and
                    # ambiguous sibling rows once.  Older state could retain a
                    # phantom VLESS lease while the real endpoint was VMess, so
                    # max_devices immediately installed a blocking rule against
                    # the live tunnel after an update/restart.
                    collision_marker_key = "xray_sibling_protocol_collision_v1"
                    collision_marker = conn.execute(
                        text("SELECT value FROM settings WHERE `key` = :key"),
                        {"key": collision_marker_key},
                    ).scalar()
                    if collision_marker != "1":
                        conn.execute(text(
                            "UPDATE connection_logs SET "
                            "is_online = 0, presence_state = 'offline', "
                            "presence_failures = 2, device_limit_blocked = 0, "
                            "disconnect_time = COALESCE(disconnect_time, CURRENT_TIMESTAMP) "
                            "WHERE protocol IN ('vmess', 'vless') AND is_online = 1"
                        ))
                        for runtime_key in (
                            "xray_max_device_rules_v1",
                            "xray_max_device_desired_rules_v1",
                            "xray_connection_admission_v5",
                            "xray_connection_admission_v6",
                        ):
                            conn.execute(
                                text("UPDATE settings SET value = '{}' WHERE `key` = :key"),
                                {"key": runtime_key},
                            )
                        updated = conn.execute(
                            text("UPDATE settings SET value = '1' WHERE `key` = :key"),
                            {"key": collision_marker_key},
                        )
                        if int(updated.rowcount or 0) == 0:
                            conn.execute(
                                text("INSERT INTO settings (`key`, value) VALUES (:key, '1')"),
                                {"key": collision_marker_key},
                            )
            except Exception:
                logger.exception("خطا در پاک‌سازی یک‌باره وضعیت آنلاین قدیمی Xray")

        # 2.3.141: older node/controller sync paths could accumulate traffic while
        # first_connect_at remained NULL. Recover the earliest confirmed session
        # from connection history once, then let the runtime merge keep it synced.
        if {"settings", "vpn_users", "connection_logs"}.issubset(existing_tables):
            try:
                with engine.begin() as conn:
                    marker_key = "first_connect_runtime_backfill_v1"
                    marker = conn.execute(
                        text("SELECT value FROM settings WHERE `key` = :key"),
                        {"key": marker_key},
                    ).scalar()
                    if marker != "1":
                        rows = conn.execute(text(
                            "SELECT u.id AS user_id, u.expire_mode, u.expire_after_days, "
                            "MIN(c.connect_time) AS first_seen "
                            "FROM vpn_users u JOIN connection_logs c ON c.user_id = u.id "
                            "WHERE u.first_connect_at IS NULL AND c.connect_time IS NOT NULL "
                            "GROUP BY u.id, u.expire_mode, u.expire_after_days"
                        )).mappings().all()
                        for row in rows:
                            first_seen = row.get("first_seen")
                            if isinstance(first_seen, str):
                                try:
                                    first_seen = datetime.fromisoformat(first_seen.replace("Z", "+00:00")).replace(tzinfo=None)
                                except Exception:
                                    first_seen = None
                            if not isinstance(first_seen, datetime):
                                continue
                            expire_date = None
                            if row.get("expire_mode") == "after_first_connect" and int(row.get("expire_after_days") or 0) > 0:
                                expire_date = first_seen.date() + timedelta(days=int(row.get("expire_after_days") or 0))
                            conn.execute(text(
                                "UPDATE vpn_users SET first_connect_at = :first_seen, "
                                "expire_date = CASE WHEN expire_mode = 'after_first_connect' "
                                "THEN :expire_date ELSE expire_date END WHERE id = :user_id"
                            ), {
                                "first_seen": first_seen,
                                "expire_date": expire_date,
                                "user_id": int(row["user_id"]),
                            })
                        updated = conn.execute(
                            text("UPDATE settings SET value = '1' WHERE `key` = :key"),
                            {"key": marker_key},
                        )
                        if int(updated.rowcount or 0) == 0:
                            conn.execute(
                                text("INSERT INTO settings (`key`, value) VALUES (:key, '1')"),
                                {"key": marker_key},
                            )
            except Exception:
                logger.exception("خطا در ترمیم زمان اولین اتصال از تاریخچه سشن‌ها")
    except Exception:
        logger.exception("خطا در اجرای مهاجرت خودکار پایگاه‌داده")
