"""
این ماژول مسئول همگام‌سازی کاربران دیتابیس با فایل‌های سیستمی است که
xl2tpd/pptpd (از طریق pppd) و OpenVPN برای احراز هویت از آن‌ها استفاده می‌کنند.

- L2TP/IPsec و PPTP هر دو در نهایت از pppd و فایل chap-secrets استفاده می‌کنند.
  PSK به‌صورت مشترک (Pre-Shared Key) برای IPsec در ipsec.secrets تنظیم شده و
  همه‌ی کاربران با یک PSK وارد فاز IPsec می‌شوند، سپس pppd با chap-secrets
  کاربر را احراز هویت می‌کند. این روش استاندارد اکثر پنل‌های L2TP/IPsec است.

- OpenVPN همیشه با سرتیفیکیت اختصاصی هر کاربر (easy-rsa، از طریق cert_manager.py)
  احراز هویت می‌شود. علاوه بر آن، به‌ازای هر کاربر (VpnUser.openvpn_auth_mode)
  می‌توان یک لایه‌ی یوزر/پس هم اضافه کرد: سرور همیشه یک auth-user-pass-verify
  دارد (اسکریپت openvpn_auth.sh -> API داخلی /api/internal/openvpn-auth) که چک
  می‌کند یوزرنیمِ ارسالی دقیقاً با Common Name همان سرتیفیکیت TLS یکی است -
  یعنی حتی اگر یوزر/پس یک کاربر دیگر لو برود، بدون سرتیفیکیت اختصاصی همان
  کاربر امکان اتصال با آن هویت نیست. تفاوت دو حالت فقط در همان فایل .ovpn
  است: cert_only یوزر/پس را نامرئی داخل فایل جا می‌دهد (بدون پرسش از کاربر)،
  cert_password کلاینت را وادار به پرسیدن دستی می‌کند (build_client_ovpn را
  ببینید). چک‌های enable/فعال‌بودن/انقضا/حجم/تعداد دستگاه جدا و در
  client-connect (اسکریپت openvpn_connect.sh -> API داخلی) انجام می‌شود.
"""
try:
    import crypt as _crypt
except ModuleNotFoundError:  # Python 3.13 removed the stdlib crypt module.
    _crypt = None
from passlib.hash import sha256_crypt
import json
import logging
import os
import re
import socket
import threading
import time
import fcntl
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import VpnUser, ConnectionLog, BannedIP, InternetBlockedIP, Setting, OpenvpnExtraPort
from app.services.server_targets import user_enabled_on_this_server
from app.services.user_lifecycle import ensure_first_connect
from app.proc_utils import BASH, SYSTEMCTL, KILL, PS, IPTABLES, NETFILTER_PERSISTENT, IPSEC, OCCTL

settings = get_settings()
logger = logging.getLogger("vpn-panel")

# OpenVPN همیشه با دو پروسه‌ی هم‌زمان اجرا می‌شود (UDP و TCP)، هرکدام با یک
# management interface جدا - نگاه کنید به install/install.sh.
OPENVPN_MGMT_PORTS = (7505, 7506)
MANUAL_PROTOCOL_STOP_DIR = "/var/lib/vpn-panel/manual-protocol-stop"
XL2TPD_PENDING_RESTART = "/var/lib/vpn-panel/pending/xl2tpd-restart"

# رابط کنترل TCP خود accel-ppp برای مدیریت سشن‌های SSTP. این پورت فقط روی
# loopback گوش می‌دهد (در setup_sstp.sh تضمین می‌شود) و از بیرون سرور در
# دسترس نیست. برخلاف L2TP/PPTP، accel-ppp برای هر سشن پردازش pppd جدا ندارد؛
# بنابراین تنها راه درستِ قطع یک کاربر/اینترفیس، فرمان terminate همین CLI است.
SSTP_CLI_HOST = "127.0.0.1"
SSTP_CLI_PORT = 2001

CHAP_MARK_START = "# BEGIN-VPN-PANEL-USERS (auto-generated, do not edit manually)"
CHAP_MARK_END = "# END-VPN-PANEL-USERS"
IFF_UP = 0x1

# بلوک خودکار کاربران IKEv2 (EAP-MSCHAPv2) داخل همان /etc/ipsec.secrets، جدا
# از خط PSK مشترک L2TP (که در بالای همان فایل و خارج از این بلوک می‌ماند).
IKEV2_MARK_START = "# BEGIN-VPN-PANEL-IKEV2-USERS (auto-generated, do not edit manually)"
IKEV2_MARK_END = "# END-VPN-PANEL-IKEV2-USERS"


def _read_file_lines(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    with open(path, "r") as f:
        return f.readlines()


def _restart_strongswan() -> bool:
    """Restart strongSwan across Ubuntu package/service variants.

    Ubuntu releases and strongSwan packages expose different systemd unit
    names.  Do not silently assume ``strongswan-starter`` exists: try the
    known units first and fall back to the ``ipsec`` command.
    """
    for unit in ("strongswan-starter", "strongswan", "ipsec"):
        try:
            probe = subprocess.run(
                [SYSTEMCTL, "show", unit, "--property=LoadState", "--value"],
                capture_output=True, text=True, timeout=8, check=False,
            )
            if probe.stdout.strip() != "loaded":
                continue
            result = subprocess.run(
                [SYSTEMCTL, "restart", unit],
                capture_output=True, text=True, timeout=20, check=False,
            )
            if result.returncode == 0:
                return True
        except (OSError, subprocess.TimeoutExpired):
            continue

    for action in ("reload", "restart"):
        try:
            result = subprocess.run(
                [IPSEC, action], capture_output=True, text=True, timeout=20, check=False
            )
            if result.returncode == 0:
                return True
        except (OSError, subprocess.TimeoutExpired):
            continue
    logger.warning("Unable to restart strongSwan with any known service variant")
    return False


def sync_chap_secrets(db: Session):
    """بازنویسی بخش خودکار فایل /etc/ppp/chap-secrets بر اساس دیتابیس."""
    path = settings.CHAP_SECRETS_PATH
    lines = _read_file_lines(path)

    # حذف بلوک قبلی auto-generated
    new_lines = []
    inside = False
    for line in lines:
        if line.strip() == CHAP_MARK_START:
            inside = True
            continue
        if line.strip() == CHAP_MARK_END:
            inside = False
            continue
        if not inside:
            new_lines.append(line)

    users = [u for u in db.query(VpnUser).filter(VpnUser.is_active == True).all() if user_enabled_on_this_server(db, u)]  # noqa: E712
    block = [CHAP_MARK_START + "\n"]
    for u in users:
        if u.enable_l2tp or u.enable_pptp or u.enable_sstp:
            # فرمت: username  server  password  ip
            block.append(f'{u.username}\t*\t{u.password}\t*\n')
    block.append(CHAP_MARK_END + "\n")

    with open(path, "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.writelines(new_lines + block)
        fcntl.flock(f, fcntl.LOCK_UN)
    os.chmod(path, 0o600)

    # کاربران IKEv2 (EAP-MSCHAPv2) هم همیشه همراه با chap-secrets هم‌گام
    # می‌شوند - این دو همیشه با هم به‌روزرسانی می‌شوند (هر جا کاربری
    # ساخته/ویرایش/حذف می‌شود)، پس نیازی به صدا زدن جداگانه در هر call-site
    # نیست.
    sync_ikev2_secrets(db)

    # همین‌طور کاربران OpenConnect (ocserv) - به همان دلیل بالا، همیشه همراه
    # با chap-secrets هم‌گام می‌شود.
    sync_openconnect_secrets(db)


def sync_ikev2_secrets(db: Session):
    """بازنویسی بخش خودکار کاربران IKEv2 (EAP-MSCHAPv2) داخل /etc/ipsec.secrets.
    این بلوک کاملاً جدا از خط «: PSK ...» (مشترک L2TP، در بالای همان فایل)
    نگه داشته می‌شود تا با هم تداخل نکنند. فقط روی سرورهایی اثر واقعی دارد که
    زیرساخت IKEv2 با install/setup_ikev2.sh نصب شده باشد (conn
    IKEv2-MSCHAPv2 داخل ipsec.conf)؛ در غیر این صورت این بلوک صرفاً در فایل
    نوشته می‌شود ولی هیچ اتصالی از آن استفاده نمی‌کند."""
    path = settings.IPSEC_SECRETS_PATH
    lines = _read_file_lines(path)

    new_lines = []
    inside = False
    for line in lines:
        if line.strip() == IKEV2_MARK_START:
            inside = True
            continue
        if line.strip() == IKEV2_MARK_END:
            inside = False
            continue
        if not inside:
            new_lines.append(line)

    users = [u for u in db.query(VpnUser).filter(VpnUser.is_active == True).all() if user_enabled_on_this_server(db, u)]  # noqa: E712
    block = [IKEV2_MARK_START + "\n"]
    for u in users:
        if u.enable_ikev2:
            # فرمت strongSwan برای EAP: username : EAP "password"
            block.append(f'{u.username} : EAP "{u.password}"\n')
    block.append(IKEV2_MARK_END + "\n")

    with open(path, "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.writelines(new_lines + block)
        fcntl.flock(f, fcntl.LOCK_UN)
    os.chmod(path, 0o600)

    _restart_strongswan()


def sync_openconnect_secrets(db: Session):
    """بازنویسی فایل پسورد OpenConnect (ocserv) بر اساس دیتابیس.

    فقط روی سرورهایی اثر واقعی دارد که زیرساخت OpenConnect با
    install/setup_openconnect.sh نصب شده باشد (یعنی ماژول "plain" با
    passwd=OCSERV_PASSWD_PATH در /etc/ocserv/ocserv.conf تنظیم شده باشد)؛ در
    غیر این صورت این فایل صرفاً نوشته می‌شود ولی هیچ اتصالی از آن استفاده
    نمی‌کند.

    فرمت فایل دقیقاً همان چیزی است که خودِ ابزار ocpasswd تولید می‌کند:
    "username:groupname:hash" (هر کاربر یک خط، بدون گروه خاص یعنی "*").
    هش با crypt.METHOD_SHA256 (همان الگوریتم $5$ که ocpasswd خودش استفاده
    می‌کند) ساخته می‌شود تا ماژول "plain" داخلی ocserv (که هم از crypt() سیستم
    برای تطبیق استفاده می‌کند) بتواند آن را تأیید کند.

    برخلاف chap-secrets/ipsec.secrets، ocserv نیازی به ری‌استارت سرویس ندارد؛
    فایل پسورد را در همان لحظه‌ی هر تلاش اتصال دوباره از دیسک می‌خواند، پس
    سشن‌های همین الان آنلاین با بازنویسی این فایل قطع نمی‌شوند.
    """
    path = settings.OCSERV_PASSWD_PATH
    if not os.path.exists(os.path.dirname(path)):
        # زیرساخت OpenConnect اصلاً نصب نشده (پوشه‌ی /etc/ocserv وجود ندارد) -
        # چیزی برای نوشتن نیست.
        return

    users = [u for u in db.query(VpnUser).filter(VpnUser.is_active == True).all() if user_enabled_on_this_server(db, u)]  # noqa: E712
    lines = []
    for u in users:
        if u.enable_openconnect:
            if _crypt is not None:
                pw_hash = _crypt.crypt(u.password, _crypt.mksalt(_crypt.METHOD_SHA256))
            else:
                # passlib emits the same modular-crypt $5$ format accepted by
                # ocserv plain auth, and keeps fresh installs working on Python
                # 3.13 where the standard-library crypt module no longer exists.
                pw_hash = sha256_crypt.using(rounds=5000).hash(u.password)
            lines.append(f"{u.username}:*:{pw_hash}\n")

    with open(path, "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.writelines(lines)
        fcntl.flock(f, fcntl.LOCK_UN)
    os.chmod(path, 0o600)



def _runtime_file_text(path: str) -> str:
    try:
        return open(path, "r", encoding="utf-8", errors="replace").read()
    except OSError:
        return ""


def _openconnect_hash_matches(password: str, stored_hash: str) -> bool:
    """Verify an ocserv modular-crypt hash without rewriting the file."""
    if not stored_hash:
        return False
    try:
        if _crypt is not None:
            return _crypt.crypt(password, stored_hash) == stored_hash
        return bool(sha256_crypt.verify(password, stored_hash))
    except Exception:
        return False


def runtime_auth_drift_reasons(db: Session) -> list[str]:
    """Return damaged/stale runtime credential stores for this server.

    Controller snapshots are content-addressed. Older builds skipped rebuilding
    chap-secrets, IKEv2, ocserv and Xray whenever the database snapshot hash had
    not changed. That is normally efficient, but it also means a deleted file,
    bad permission, interrupted atomic replacement or restored old runtime file
    can leave one node unable to authenticate *every* protocol forever while
    the node itself still reports online. This check compares the live stores
    to the authoritative database and lets the watchdog repair only real drift.
    """
    reasons: list[str] = []
    users = [
        user for user in db.query(VpnUser).filter(VpnUser.is_active == True).all()  # noqa: E712
        if user_enabled_on_this_server(db, user)
    ]

    chap_text = _runtime_file_text(settings.CHAP_SECRETS_PATH)
    chap_expected = [
        f"{user.username}\t*\t{user.password}\t*"
        for user in users
        if user.enable_l2tp or user.enable_pptp or user.enable_sstp
    ]
    if CHAP_MARK_START not in chap_text or CHAP_MARK_END not in chap_text:
        reasons.append("chap-secrets:managed-block-missing")
    elif any(line not in chap_text for line in chap_expected):
        reasons.append("chap-secrets:user-mismatch")
    try:
        if os.path.exists(settings.CHAP_SECRETS_PATH) and (os.stat(settings.CHAP_SECRETS_PATH).st_mode & 0o777) != 0o600:
            reasons.append("chap-secrets:permissions")
    except OSError:
        reasons.append("chap-secrets:unreadable")

    ipsec_text = _runtime_file_text(settings.IPSEC_SECRETS_PATH)
    ike_expected = [
        f'{user.username} : EAP "{user.password}"'
        for user in users if user.enable_ikev2
    ]
    if IKEV2_MARK_START not in ipsec_text or IKEV2_MARK_END not in ipsec_text:
        reasons.append("ikev2-secrets:managed-block-missing")
    elif any(line not in ipsec_text for line in ike_expected):
        reasons.append("ikev2-secrets:user-mismatch")

    if os.path.isdir(os.path.dirname(settings.OCSERV_PASSWD_PATH)):
        ocserv_text = _runtime_file_text(settings.OCSERV_PASSWD_PATH)
        hashes: dict[str, str] = {}
        for raw in ocserv_text.splitlines():
            parts = raw.split(":", 2)
            if len(parts) == 3 and parts[0]:
                hashes[parts[0]] = parts[2]
        for user in users:
            if not user.enable_openconnect:
                continue
            if user.username not in hashes:
                reasons.append("openconnect-passwd:user-missing")
                break
            if not _openconnect_hash_matches(str(user.password or ""), hashes[user.username]):
                reasons.append("openconnect-passwd:password-mismatch")
                break

    # OpenVPN's TLS certificate is separate, but the username/password hook
    # still needs its minimal root-generated runtime environment. Validate the
    # values and traversal/reader bits rather than exposing panel.env again.
    def _db_bool_setting(key: str, default: bool = False) -> bool:
        row = db.query(Setting).filter(Setting.key == key).first()
        if not row or row.value is None:
            return default
        return str(row.value).strip().lower() in {"1", "true", "yes", "on"}

    openvpn_enabled = _db_bool_setting("openvpn_enabled", True) and any(user.enable_openvpn for user in users)
    if openvpn_enabled:
        runtime_env = "/etc/vpn-panel/openvpn-hook.env"
        env_text = _runtime_file_text(runtime_env)
        if "BACKEND_PORT=" not in env_text or "INTERNAL_API_TOKEN=" not in env_text:
            reasons.append("openvpn-hook-env:missing-or-incomplete")
        try:
            import glob
            import grp
            import pwd

            env_stat = os.stat(runtime_env)
            parent_stat = os.stat(os.path.dirname(runtime_env))
            if not (env_stat.st_mode & 0o040):
                reasons.append("openvpn-hook-env:not-group-readable")

            drop_user = ""
            drop_group = ""
            for conf_path in sorted(set(glob.glob("/etc/openvpn/server/*.conf") + glob.glob("/etc/openvpn/*.conf"))):
                try:
                    conf_text = _runtime_file_text(conf_path)
                except Exception:
                    continue
                if not drop_user:
                    match = re.search(r"(?mi)^\s*user\s+(\S+)", conf_text)
                    drop_user = match.group(1) if match else ""
                if not drop_group:
                    match = re.search(r"(?mi)^\s*group\s+(\S+)", conf_text)
                    drop_group = match.group(1) if match else ""
                if drop_user and drop_group:
                    break

            expected_gid = None
            if drop_group:
                try:
                    expected_gid = int(grp.getgrnam(drop_group).gr_gid)
                except KeyError:
                    pass
            if expected_gid is None and drop_user:
                try:
                    expected_gid = int(pwd.getpwnam(drop_user).pw_gid)
                except KeyError:
                    pass
            if expected_gid is None:
                expected_gid = 65534
            if int(env_stat.st_gid) != expected_gid:
                reasons.append("openvpn-hook-env:wrong-reader-group")
            if not (parent_stat.st_mode & 0o001):
                reasons.append("openvpn-hook-env:parent-not-traversable")
        except OSError:
            reasons.append("openvpn-hook-env:unreadable")

    try:
        from app.services.xray_manager import PROTOCOLS, XRAY_BINARY, build_config, config_path

        if not os.path.isfile(str(XRAY_BINARY)):
            raise FileNotFoundError("Xray binary is not installed")
        for protocol in PROTOCOLS:
            if not _db_bool_setting(f"{protocol}_enabled", False):
                continue
            expected_payload = build_config(db, protocol)
            expected_clients = {
                (str(item.get("id") or ""), str(item.get("email") or ""))
                for item in (((expected_payload.get("inbounds") or [{}])[0].get("settings") or {}).get("clients") or [])
            }
            target = config_path(protocol)
            if not target.exists():
                if expected_clients:
                    reasons.append(f"xray-{protocol}:config-missing")
                continue
            try:
                actual_payload = json.loads(target.read_text(encoding="utf-8", errors="replace"))
                actual_clients = {
                    (str(item.get("id") or ""), str(item.get("email") or ""))
                    for item in (((actual_payload.get("inbounds") or [{}])[0].get("settings") or {}).get("clients") or [])
                }
            except Exception:
                reasons.append(f"xray-{protocol}:config-invalid")
                continue
            if actual_clients != expected_clients:
                reasons.append(f"xray-{protocol}:client-mismatch")
    except FileNotFoundError:
        pass
    except Exception as exc:
        logger.warning("runtime Xray credential drift probe failed: %s", exc)

    return list(dict.fromkeys(reasons))


def repair_runtime_auth_drift(db: Session, reasons: list[str] | None = None) -> list[str]:
    """Repair only the runtime stores proven to have drifted.

    Returns a compact list of repaired areas. The operation is idempotent and
    avoids restarting Xray/strongSwan when their files are already healthy.
    """
    reasons = list(reasons if reasons is not None else runtime_auth_drift_reasons(db))
    if not reasons:
        return []

    repaired: list[str] = []
    if any(reason.startswith("openvpn-hook-env:") for reason in reasons):
        helper = "/opt/vpn-panel/scripts/refresh_openvpn_runtime_env.sh"
        try:
            result = subprocess.run([BASH, helper], capture_output=True, text=True, timeout=20, check=False)
            if result.returncode == 0:
                repaired.append("openvpn-hook-env")
            else:
                logger.warning("OpenVPN hook env self-repair failed: %s", (result.stderr or result.stdout or "")[-1000:])
        except Exception:
            logger.exception("OpenVPN hook env self-repair failed")

    if any(reason.startswith(("chap-secrets:", "ikev2-secrets:", "openconnect-passwd:")) for reason in reasons):
        sync_chap_secrets(db)
        repaired.extend(["chap-secrets", "ikev2-secrets", "openconnect-passwd"])

    xray_protocols = tuple(
        protocol for protocol in ("vmess", "vless")
        if any(reason.startswith(f"xray-{protocol}:") for reason in reasons)
    )
    if xray_protocols:
        try:
            from app.services.xray_manager import sync_xray_users
            sync_xray_users(db, protocols=xray_protocols, restart=True)
            repaired.extend(f"xray-{protocol}" for protocol in xray_protocols)
        except Exception:
            logger.exception("Xray runtime credential self-repair failed")

    return list(dict.fromkeys(repaired))

def get_ipsec_psk() -> str | None:
    """خواندن مقدار فعلی PSK مشترک L2TP/IPsec از /etc/ipsec.secrets.
    این PSK ماهیتاً بین همه‌ی کاربران L2TP مشترک است (استاندارد پروتکل)،
    برای همین سطح تنظیم آن پنل (Settings) است، نه هر کاربر جداگانه."""
    path = settings.IPSEC_SECRETS_PATH
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        content = f.read()
    # Accept canonical quoted lines and older unquoted strongSwan files.
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "PSK" not in line:
            continue
        match = re.search(r'\bPSK\b\s+(?:"([^"]*)"|([^#\s]+))', line)
        if match:
            return (match.group(1) if match.group(1) is not None else match.group(2) or "").strip()
    return None


def set_ipsec_psk(new_psk: str):
    """نوشتن PSK جدید در /etc/ipsec.secrets و ری‌استارت strongSwan تا فوراً
    اعمال شود. کاربرانی که همین الان با PSK قدیمی وصل هستند قطع نمی‌شوند،
    ولی اتصال‌های جدید باید PSK جدید را استفاده کنند.

    توجه: قبلاً این تابع کل فایل ipsec.secrets را با همین یک خط بازنویسی
    می‌کرد - یعنی هر بار PSK عوض می‌شد، بلوک خودکار کاربران IKEv2 (که
    sync_ikev2_secrets پایین‌تر در همین فایل می‌نویسد) هم پاک می‌شد. حالا
    فقط خط «: PSK ...» جایگزین/اضافه می‌شود و بقیه‌ی فایل (از جمله آن بلوک)
    دست‌نخورده می‌ماند."""
    path = settings.IPSEC_SECRETS_PATH
    lines = _read_file_lines(path)
    new_lines = [l for l in lines if not re.match(r'^\s*:\s*PSK\b', l)]
    new_lines.insert(0, f': PSK "{new_psk}"\n')
    with open(path, "w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.writelines(new_lines)
        fcntl.flock(f, fcntl.LOCK_UN)
    os.chmod(path, 0o600)
    _restart_strongswan()


def kill_ppp_session(db: Session, username: str):
    """قطع تمام سشن‌های فعال L2TP/PPTP یک کاربر.

    قبلاً این تابع سعی می‌کرد با grep کردن `ps -eo pid,args` به‌دنبال خطی که
    هم شامل «pppd» و هم نام کاربری باشد، پردازش را پیدا کند. اما pppd هرگز
    نام‌کاربری را در آرگومان‌های خط فرمان خودش نمی‌گذارد (احراز هویت کاربر از
    طریق CHAP/PAP و فایل chap-secrets انجام می‌شود، نه آرگومان ورودی) - در
    نتیجه این جستجو تقریباً همیشه چیزی پیدا نمی‌کرد و دکمه‌ی «قطع» برای
    کاربران L2TP/PPTP عملاً بی‌اثر بود.

    روش درست: هنگام اتصال، اسکریپت ppp_ip_up.sh پی‌آی‌دیِ خودِ پردازش pppd
    (یعنی $PPID اسکریپت) را همراه رویداد connect به پنل می‌فرستد و در همان
    رکورد ConnectionLog ذخیره می‌شود؛ این تابع همان PID را مستقیماً kill
    می‌کند.

    نکته‌ی مهم درباره‌ی سیگنال: قبلاً از kill -9 (SIGKILL) استفاده می‌شد که
    pppd هیچ فرصتی برای اجرای اسکریپت ip-down پیدا نمی‌کرد (SIGKILL قابل
    مدیریت/catch نیست) - در نتیجه بعد از هر «قطع» دستی از پنل، رکورد
    ConnectionLog مربوطه برای همیشه به‌عنوان «آنلاین» در دیتابیس باقی می‌ماند
    (یکی از منشاهای اصلی باگ «کاربر آنلاین که در واقع قطع است»). حالا اول
    SIGTERM فرستاده می‌شود (سیگنال قابل مدیریت که pppd با آن به‌طور تمیز
    خاموش شده و ip-down را هم اجرا می‌کند)، و صرف‌نظر از موفقیت آن، خودِ همین
    تابع هم بلافاصله رکورد را در دیتابیس «آفلاین» علامت می‌زند تا پنل هیچ‌وقت
    منتظر اجرای موفق اسکریپت خارجی نماند.
    """
    sessions = (
        db.query(ConnectionLog)
        .join(VpnUser, VpnUser.id == ConnectionLog.user_id)
        .filter(
            VpnUser.username == username,
            ConnectionLog.protocol.in_(["l2tp", "pptp"]),
            ConnectionLog.is_online == True,  # noqa: E712
            ConnectionLog.pid.isnot(None),
        )
        .all()
    )
    for s in sessions:
        try:
            subprocess.run([KILL, "-TERM", str(s.pid)], check=False)
        except Exception:
            pass
        s.is_online = False
        s.disconnect_time = datetime.utcnow()

    # fallback برای سشن‌های قدیمی‌ای که قبل از این تغییر وصل شده‌اند و هنوز
    # pid ذخیره‌شده ندارند - در اکثر نصب‌ها هیچ‌وقت match نمی‌کند، ولی بی‌ضرر است.
    try:
        out = subprocess.run(
            [PS, "-eo", "pid,args"], capture_output=True, text=True, check=False
        ).stdout
        for line in out.splitlines():
            if "pppd" in line and username in line:
                pid = line.strip().split()[0]
                subprocess.run([KILL, "-TERM", pid], check=False)
    except Exception:
        pass

    db.commit()


def kill_single_ppp_session(db: Session, log: ConnectionLog) -> None:
    """قطع دقیقاً همان یک سشن L2TP/PPTP (نه همه‌ی سشن‌های کاربر)، با استفاده
    از pid ذخیره‌شده‌ی همان رکورد ConnectionLog."""
    if log.pid:
        try:
            subprocess.run([KILL, "-TERM", str(log.pid)], check=False)
        except Exception:
            pass
    log.is_online = False
    log.disconnect_time = datetime.utcnow()
    db.commit()


def _sstp_cli_command(command: str, timeout: float = 4.0) -> bool:
    """اجرای یک فرمان روی CLI داخلی accel-ppp از طریق TCP محلی.

    عمداً مستقیم با socket صحبت می‌کنیم و به وجود باینری ``accel-cmd`` در
    PATH سرویس وابسته نیستیم. setup_sstp.sh بخش زیر را در کانفیگ تضمین می‌کند:

        [cli]
        tcp=127.0.0.1:2001

    پاسخ CLI برای فرمان‌های terminate خروجی خاصی ندارد؛ موفقیت یعنی اتصال
    برقرار شده، فرمان کامل ارسال شده و سوکت بدون خطای شبکه‌ای بسته شده است.
    "exit" بعد از فرمان باعث می‌شود خود CLI اتصال مدیریتی را تمیز ببندد.
    """
    try:
        with socket.create_connection((SSTP_CLI_HOST, SSTP_CLI_PORT), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall((command + "\nexit\n").encode("utf-8"))
            # خروجی را تا بسته‌شدن اتصال یا timeout کوتاه می‌خوانیم. برای
            # terminate معمولاً پاسخی چاپ نمی‌شود؛ timeout بعد از ارسال موفق
            # را شکست حساب نمی‌کنیم، چون فرمان همان لحظه در daemon صف شده است.
            while True:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
        return True
    except OSError as exc:
        logger.warning("SSTP CLI command failed (%s): %s", command, exc)
        return False


def _close_sstp_logs(db: Session, logs: list[ConnectionLog]) -> None:
    """رکوردهای مشخص SSTP را بلافاصله آفلاین می‌کند.

    رویداد واقعی ip-down کمی بعد از accel-ppp می‌رسد و routers/vpn.py حالا
    می‌تواند همان رکورد آفلاین‌شده را با interface دوباره پیدا کند و فقط
    دلتای نهایی حجم را اضافه کند؛ بنابراین نه وضعیت آنلاین معطل می‌ماند و نه
    حجم دوبار شمرده می‌شود.
    """
    now = datetime.utcnow()
    for log in logs:
        log.is_online = False
        log.disconnect_time = log.disconnect_time or now
    if logs:
        db.commit()


def kill_sstp_session(db: Session, username: str) -> bool:
    """قطع تمام سشن‌های فعال SSTP یک کاربر از داخل خود accel-ppp.

    فرمان ``terminate match username`` به‌جای ``terminate username`` استفاده
    می‌شود، چون نوع دوم در accel-ppp فقط اولین سشن مطابق را قطع می‌کند؛ نوع
    match روی همه‌ی سشن‌های هم‌نام اجرا می‌شود. نام کاربری با ``re.escape`` و
    anchor کامل به regex امن و exact تبدیل می‌شود.

    اگر CLI روی یک نصب خیلی قدیمی هنوز فعال نشده باشد، به‌عنوان fallback
    سرویس SSTP ری‌استارت می‌شود تا کاربر بن‌شده قطعاً آنلاین نماند. این fallback
    ممکن است سایر کاربران SSTP را هم یک‌بار قطع کند، اما فقط در نصب معیوب/قدیمی
    رخ می‌دهد؛ update.sh قبل از روشن‌کردن بک‌اند، setup_sstp.sh را اجرا و CLI
    محلی را ترمیم می‌کند، پس در نصب عادی فرمان دقیقِ کاربر استفاده می‌شود.
    """
    logs = (
        db.query(ConnectionLog)
        .join(VpnUser, VpnUser.id == ConnectionLog.user_id)
        .filter(
            VpnUser.username == username,
            ConnectionLog.protocol == "sstp",
            ConnectionLog.is_online == True,  # noqa: E712
        )
        .all()
    )
    # آخرین شمارنده‌های قابل‌خواندن را قبل از terminate ثبت کن؛ ip-down دلتای
    # باقیمانده را بعداً اضافه خواهد کرد. حتی اگر هیچ ConnectionLog ای پیدا
    # نشد باز هم فرمان CLI اجرا می‌شود؛ ممکن است یک نصب قدیمی رویداد ip-up را
    # ثبت نکرده باشد ولی سشن واقعی هنوز داخل accel-ppp زنده باشد.
    if logs:
        try:
            sample_ppp_traffic(db)
        except Exception:
            pass

    exact_username_regex = f"^{re.escape(username)}$"
    ok = _sstp_cli_command(f"terminate match username {exact_username_regex} hard")
    if not ok:
        try:
            result = subprocess.run(
                [SYSTEMCTL, "restart", "accel-ppp-sstp"],
                capture_output=True, text=True, timeout=15, check=False,
            )
            ok = result.returncode == 0
        except Exception:
            ok = False

    if ok:
        _close_sstp_logs(db, logs)
    return ok


def kill_single_sstp_session(db: Session, log: ConnectionLog) -> bool:
    """قطع دقیقاً یک سشن SSTP با نام interface ثبت‌شده‌ی همان اتصال."""
    if log.protocol != "sstp":
        return False

    try:
        sample_ppp_traffic(db)
    except Exception:
        pass

    ok = False
    if log.interface:
        # ifname توسط خود accel-ppp ساخته شده و از دیتابیس داخلی آمده است؛ با
        # این حال فقط یک توکن بدون whitespace را می‌پذیریم تا فرمان CLI مبهم
        # یا چندبخشی نشود.
        if re.fullmatch(r"[A-Za-z0-9_.:-]+", log.interface):
            ok = _sstp_cli_command(f"terminate if {log.interface} hard")
    if not ok and log.user:
        # رکوردهای خیلی قدیمی ممکن است interface نداشته باشند؛ در این حالت
        # ناچار همه‌ی SSTPهای همان کاربر قطع می‌شوند.
        return kill_sstp_session(db, log.user.username)

    if ok:
        _close_sstp_logs(db, [log])
    return ok


def _ppp_interface_is_live(interface: str | None) -> bool:
    """Return False once pppd has administratively lowered the PPP netdev.

    A dead L2TP peer is first reported by pppd as ``Serial link appears to be
    disconnected``.  During the following teardown, both the pppd PID and the
    ``/sys/class/net/ppp*`` directory can remain present while final counters
    and ip-down hooks run.  Existence-only checks consequently displayed that
    already-dead session as online.

    Linux clears IFF_UP as part of PPP network-protocol shutdown.  Reading the
    sysfs ``flags`` value distinguishes this teardown window from a live idle
    tunnel.  Missing/unreadable flags stay fail-open for compatibility with
    unusual kernels and test/container environments; a missing interface is
    still unambiguously offline.
    """
    name = str(interface or "").strip()
    if not name or "/" in name or name in {".", ".."}:
        return False
    base = f"/sys/class/net/{name}"
    if not os.path.isdir(base):
        return False
    try:
        with open(f"{base}/flags", "r", encoding="utf-8") as handle:
            flags = int(handle.read().strip(), 0)
    except (OSError, ValueError):
        return True
    return bool(flags & IFF_UP)


def _invalidate_node_presence_snapshot() -> None:
    """Best-effort cache invalidation without introducing an import cycle."""
    try:
        from app.services.node_manager import invalidate_local_snapshot_cache

        invalidate_local_snapshot_cache()
    except Exception:
        # Presence reconciliation must remain available even during partial
        # upgrades where node_manager has not loaded the new helper yet.
        pass


def _release_retired_cluster_sessions(db: Session, session_keys: set[str]) -> None:
    """Release fleet admission slots after evidence-based stale cleanup."""
    keys = {str(value or "").strip() for value in session_keys}
    keys.discard("")
    if not keys:
        return
    try:
        from app.services.cluster_admission import release_cluster_session

        for cluster_key in sorted(keys):
            release_cluster_session(db, session_key=cluster_key)
        db.commit()
    except Exception:
        db.rollback()


def reconcile_ppp_sessions(db: Session) -> int:
    """خودترمیمی سشن‌های L2TP/PPTP که در دیتابیس «آنلاین» مانده‌اند ولی
    پردازش pppd مربوطه‌شان دیگر روی سرور اجرا نیست (مثلاً به‌دلیل قطع ناگهانی
    شبکه‌ی کاربر یا کرش pppd که اسکریپت ip-down هرگز برایش اجرا نشده). این
    دقیقاً همان سشن‌های «یتیم»ی هستند که در صفحه‌ی کاربران آنلاین به‌صورت
    نادرست همیشه آنلاین نشان داده می‌شوند (و در طول زمان تعداد رکوردهای باز
    مانده در دیتابیس هم زیاد و زیاد می‌شود). با چک‌کردن زنده‌بودن pid (بدون
    ارسال سیگنال واقعی، فقط os.kill(pid, 0)) این رکوردها خودکار آفلاین
    می‌شوند. تعداد رکوردهای اصلاح‌شده را برمی‌گرداند.

    قبل از آفلاین‌کردن، یک‌بار sample_ppp_traffic را صدا می‌زنیم: pppd همین
    الان مرده، ولی خودِ اینترفیس ppp معمولاً چند لحظه بعد از مرگ pppd پاک
    می‌شود (نه هم‌زمان) - پس این آخرین فرصت است که اگر شمارنده‌ی اینترفیس هنوز
    خواندنی باشد، حجم واقعی این سشنِ کرش‌کرده به‌جای صفر ماندن برای همیشه، در
    used_bytes کاربر ثبت شود."""
    sample_ppp_traffic(db)
    sessions = (
        db.query(ConnectionLog)
        .filter(
            ConnectionLog.protocol.in_(["l2tp", "pptp"]),
            ConnectionLog.is_online == True,  # noqa: E712
        )
        .all()
    )
    fixed = 0
    retired_cluster_keys: set[str] = set()
    for s in sessions:
        stale = False
        valid_pid = int(s.pid or 0) > 1
        if valid_pid:
            try:
                os.kill(int(s.pid), 0)
                # PID reuse must not keep an old VPN row online. Verify that
                # the process is still pppd and not a zombie/recycled PID.
                with open(f"/proc/{int(s.pid)}/comm", "r", encoding="utf-8") as handle:
                    stale = handle.read().strip() != "pppd"
                if not stale:
                    with open(f"/proc/{int(s.pid)}/stat", "r", encoding="utf-8") as handle:
                        fields = handle.read().split()
                    stale = len(fields) > 2 and fields[2] == "Z"
            except PermissionError:
                # The process exists; the interface check below remains the
                # second authoritative signal.
                stale = False
            except (ProcessLookupError, OSError):
                stale = True
            except Exception:
                stale = False
        # The PPP interface is an equally authoritative liveness signal.  It
        # may still exist after LCP has declared the serial link dead, so also
        # require IFF_UP instead of treating directory presence as sufficient.
        if not stale:
            if s.interface:
                stale = not _ppp_interface_is_live(s.interface)
            elif not valid_pid:
                # Legacy rows without either identity can never be matched to
                # a live tunnel. Keep a short admission grace, then close them
                # instead of displaying a permanent ghost connection.
                connected_at = s.connect_time or datetime.utcnow()
                stale = (datetime.utcnow() - connected_at).total_seconds() > 15
        if stale:
            try:
                from app.services.rate_limiter import remove_session_limits

                if s.user is not None:
                    remove_session_limits(s.user, s)
            except Exception:
                # Presence and admission recovery are more important than a
                # best-effort tc cleanup for an interface already going down.
                pass
            s.is_online = False
            s.presence_state = "offline"
            s.disconnect_time = s.disconnect_time or datetime.utcnow()
            cluster_key = str(getattr(s, "cluster_session_key", "") or "").strip()
            if cluster_key:
                retired_cluster_keys.add(cluster_key)
            fixed += 1
    if fixed:
        db.commit()
        _invalidate_node_presence_snapshot()
        # A missed/late ip-down hook must not leave the fleet-wide admission
        # reservation occupied for another 30 seconds. That stale reservation
        # is what makes the user's immediate reconnect fail even after the
        # local row has already been retired.
        _release_retired_cluster_sessions(db, retired_cluster_keys)
    return fixed


def sample_ppp_traffic(db: Session) -> int:
    """حجم مصرفی L2TP/PPTP هرگز به‌صورت لحظه‌ای ثبت نمی‌شد - تنها نقطه‌ای که
    used_bytes به‌روزرسانی می‌شد، اسکریپت ppp_ip_down.sh بود که فقط یک‌بار،
    درست لحظه‌ی قطع اتصال، rx/tx نهایی را از /sys/class/net/<iface>/statistics
    می‌خواند و به /api/internal/disconnect می‌فرستاد. یعنی تا وقتی سشن باز
    بود (که می‌تواند ساعت‌ها/روزها طول بکشد) هم صفحه‌ی مصرف کاربر و هم چک
    quota_bytes در enforce_limits_job، حجمِ همان سشنِ درحال‌اجرا را کاملاً
    نادیده می‌گرفتند - این همان چیزی است که به‌عنوان «تشخیص داده نشدنِ حجم
    L2TP» دیده می‌شود. بدتر: اگر pppd به‌جای قطع تمیز کرش می‌کرد (یا شبکه‌ی
    کاربر ناگهان قطع می‌شد)، ip-down اصلاً اجرا نمی‌شد و reconcile_ppp_sessions
    آن سشن را صرفاً «آفلاین» می‌کرد بدون این‌که حجمش هرگز به دیتابیس اضافه
    شود - یعنی کل حجم آن سشن برای همیشه گم می‌شد.

    این تابع (هر MONITOR_INTERVAL_SECONDS - پیش‌فرض ۴ ثانیه - از همان جاب
    reconcile_sessions_job) شمارنده‌های اینترفیس هر سشن آنلاینِ l2tp/pptp/sstp
    را می‌خواند و فقط تفاضل (delta) نسبت به آخرین مقداری که قبلاً روی همین
    ConnectionLog ثبت شده را به used_bytes کاربر اضافه می‌کند - نه کل مقدار
    شمارنده را. همین «فقط دلتا» تضمین می‌کند که وقتی در پایان سشن
    ppp_ip_down.sh/sstp_ip_down.sh مقدار نهایی را می‌فرستد (disconnect_event
    در vpn.py هم به همین روش دلتا اصلاح شده)، هیچ بایتی دوبار حساب نشود.

    SSTP (accel-ppp، pppd-compat) هم اینجا اضافه شده: اینترفیس‌هایش دقیقاً
    مثل l2tp/pptp یک ppp* استاندارد هستند (نگاه کنید به کامنت sstp_ip_down.sh)
    پس همین شمارنده‌های /sys برایشان هم معتبرند - قبلاً این تابع فقط
    l2tp/pptp را شامل می‌شد و SSTP outside آن مانده بود، یعنی دقیقاً همان
    باگ «حجم فقط لحظه‌ی قطع آپدیت می‌شود» که در بالای این تابع برای
    l2tp/pptp توضیح داده شده، برای SSTP هنوز برقرار بود.

    bytes_in/bytes_out روی ConnectionLog از این به بعد یعنی «آخرین شمارنده‌ی
    خوانده‌شده برای این سشن» (چه هنوز آنلاین چه بعد از قطع)، نه فقط «مقدار
    نهایی لحظه‌ی قطع»."""
    sessions = (
        db.query(ConnectionLog)
        .filter(
            ConnectionLog.protocol.in_(["l2tp", "pptp", "sstp"]),
            ConnectionLog.is_online == True,  # noqa: E712
            ConnectionLog.interface.isnot(None),
        )
        .all()
    )
    sampled = 0
    for s in sessions:
        rx_path = f"/sys/class/net/{s.interface}/statistics/rx_bytes"
        tx_path = f"/sys/class/net/{s.interface}/statistics/tx_bytes"
        try:
            with open(rx_path) as f:
                rx_bytes = int(f.read().strip())
            with open(tx_path) as f:
                tx_bytes = int(f.read().strip())
        except (OSError, ValueError):
            # اینترفیس دیگر وجود ندارد (مثلاً همین لحظه pppd پایین رفته) -
            # reconcile_ppp_sessions در همین دور آن را آفلاین می‌کند، همین‌جا
            # کاری از دست ما ساخته نیست.
            continue

        s.last_seen_at = datetime.utcnow()
        s.presence_state = "active"
        s.presence_failures = 0
        if s.user:
            ensure_first_connect(s.user, s.connect_time)
        prev_rx = s.bytes_in or 0
        prev_tx = s.bytes_out or 0
        # اگر مقدار جدید از قبلی کمتر باشد (اینترفیس با همین نام دوباره از صفر
        # ساخته شده - عملاً برای ppp بعید است چون هر اتصال نام iface جدید
        # می‌گیرد، ولی محافظتی) کل شمارنده‌ی فعلی را delta در نظر می‌گیریم،
        # نه یک عدد منفی.
        delta_rx = rx_bytes - prev_rx if rx_bytes >= prev_rx else rx_bytes
        delta_tx = tx_bytes - prev_tx if tx_bytes >= prev_tx else tx_bytes

        if delta_rx or delta_tx:
            u = db.query(VpnUser).filter(VpnUser.id == s.user_id).first()
            if u:
                ensure_first_connect(u, s.connect_time)
                u.used_bytes = (u.used_bytes or 0) + delta_rx + delta_tx
            s.bytes_in = rx_bytes
            s.bytes_out = tx_bytes
            sampled += 1

    # Presence metadata must also be persisted when counters did not change in
    # this exact sample. This keeps the five-second live state fresh for idle
    # PPP sessions and prevents a connected session from looking stale.
    if sessions:
        db.commit()
    return sampled


def _live_openvpn_clients(port: int, timeout: float = 2.0) -> dict[str, dict] | None:
    """اتصال به management interface یک اینستنس OpenVPN (UDP یا TCP، پورت
    7505/7506) و برگرداندن دیکشنری {username: {"bytes_in", "bytes_out"}}
    برای کلاینت‌هایی که همین الان واقعاً وصل‌اند (از خروجی «status 2» -
    فرمت CLIENT_LIST,CommonName,RealAddress,VirtualAddress,VirtualIPv6,
    BytesReceived,BytesSent,...).

    اگر اصلاً نتوانیم به management وصل شویم/جواب بگیریم، None برمی‌گرداند -
    نه دیکشنری خالی. قبلاً هر دو حالت («واقعاً هیچ کلاینتی وصل نیست» و
    «اصلاً نتوانستیم mgmt را کوئری کنیم») همگی dict خالی برمی‌گرداندند؛ چون
    قبلی طبق کامنت باید fail-open باشد (یعنی «در آن حالت نه سشنی را به
    اشتباه آفلاین می‌کنیم») ولی در عمل دقیقاً برعکس بود: reconcile_openvpn_sessions
    یک dict خالی را همان «هیچ‌کس آنلاین نیست» تفسیر می‌کرد و همه‌ی سشن‌های
    واقعاً آنلاین را آفلاین می‌زد - اگر management موقتاً پاسخ نمی‌داد (مثلاً
    یک اتصال دیگر هم‌زمان به همان سوکت باز بود - OpenVPN mgmt پیش‌فرض فقط
    یک کلاینت هم‌زمان قبول می‌کند - یا صرفاً یک تایم‌اوت گذرا)، این دقیقاً
    همان چیزی بود که کاربر واقعاً وصل و درحال‌کار را هر چند ثانیه آفلاین
    نشان می‌داد. حالا None به این معنی است «این پورت را این دور نتوانستیم
    بخوانیم، چیزی درباره‌اش نتیجه نگیر».

    نکته‌ی مهم درباره‌ی «quit»: قبلاً «status 2\nquit\n» با هم و پشت سر هم
    فرستاده می‌شد. روی برخی بیلدهای OpenVPN mgmt (تأیید شده روی سرور واقعی)
    این باعث می‌شود «quit» زودتر از تکمیل/فلاش‌شدنِ خروجی «status 2» پردازش
    شود و کانکشن بسته شود - یعنی فقط بنر اولیه (>INFO:...) دریافت می‌شود و
    هیچ خط CLIENT_LIST/END ای هرگز نمی‌رسد. دقیقاً همین رفتار بود که باعث
    می‌شد sample_openvpn_traffic همیشه any_ok=False ببیند و هیچ‌وقت حجم
    OpenVPN را زنده آپدیت نکند (فقط در پایان واقعی اتصال، از طریق
    client-disconnect، یک‌جا اضافه می‌شد). راه‌حل: فقط «status 2» فرستاده
    می‌شود؛ نیازی به گفتن «quit» به OpenVPN نیست - همین که خودمان بعد از
    خواندن END (یا رسیدن به timeout) سوکت را ببندیم برای OpenVPN دقیقاً هم‌ارز
    با قطع شدن کلاینت مدیریتی است."""
    # Keep every live tunnel separately.  Keying only by username overwrote
    # sibling/reconnected sessions and made stale OpenVPN rows look online as
    # long as any tunnel with that username was still present.
    clients: dict[str, dict] = {}
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(b"status 2\n")
            data = b""
            while True:
                try:
                    chunk = s.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
                if b"\r\nEND" in data or b"\nEND" in data:
                    break
    except OSError:
        return None
    if b"END" not in data:
        # اتصال برقرار شد ولی خروجی کامل «status 2» تا پایانِ END دریافت
        # نشد (مثلاً پروسه‌ی OpenVPN مشغول بوده و وسط جواب قطع شده) - این هم
        # یک شکست واقعی است، نه «صفر کلاینت»، پس همان None برمی‌گردد.
        return None
    for line in data.decode(errors="ignore").splitlines():
        if not line.startswith("CLIENT_LIST,"):
            continue
        parts = line.split(",")
        # ایندکس ۵/۶ (Bytes Received/Sent) طبق فرمت رسمی «status 2» - اگر
        # نسخه‌ی OpenVPN فیلد کمتری چاپ کند (بعید، ولی محافظتی) کلاینت را
        # با بایت صفر ثبت می‌کنیم، نه اینکه کامل نادیده گرفته شود (چون
        # reconcile_openvpn_sessions هنوز به همین دیکشنری برای «آنلاینه یا
        # نه» نیاز دارد).
        if len(parts) <= 1 or not parts[1]:
            continue
        username = parts[1]
        real_address = parts[2].strip() if len(parts) > 2 else ""
        tunnel_ip = parts[3].strip() if len(parts) > 3 else ""
        try:
            bytes_in = int(parts[5]) if len(parts) > 5 else 0
            bytes_out = int(parts[6]) if len(parts) > 6 else 0
        except ValueError:
            bytes_in = bytes_out = 0
        source_port = None
        if real_address:
            try:
                source_port = int(real_address.rsplit(":", 1)[1])
            except (ValueError, IndexError):
                source_port = None
        connected_at = None
        if len(parts) > 8:
            try:
                connected_at = datetime.utcfromtimestamp(int(parts[8]))
            except (TypeError, ValueError, OSError, OverflowError):
                connected_at = None
        identity = f"{username}|{tunnel_ip}|{real_address}|{port}"
        clients[identity] = {
            "username": username,
            "tunnel_ip": tunnel_ip or None,
            "real_address": real_address or None,
            "source_port": source_port,
            "connected_at": connected_at,
            "management_port": int(port),
            "bytes_in": bytes_in,
            "bytes_out": bytes_out,
        }
    return clients


_EXTRA_PORT_MGMT_RE = re.compile(r'^management\s+127\.0\.0\.1\s+(\d+)\s*$', re.MULTILINE)


def _extra_openvpn_mgmt_ports(db: Session) -> list[int]:
    """پورت‌های اضافه‌ی OpenVPN (Settings > پورت‌های OpenVPN، جدول
    OpenvpnExtraPort) هرکدام یک پروسه‌ی OpenVPN کاملاً جدا با management
    interface خودشان هستند - نه یکی از دو پورت اصلی (7505/7506). شماره‌ی
    این mgmt port را خودِ manage_openvpn_extra_ports.sh موقع ساخت هر
    instance به‌صورت پویا از بازه‌ی 7601-7699 انتخاب می‌کند و هیچ‌جا در
    دیتابیس ذخیره نمی‌شود - تنها جای واقعی‌اش همان خط «management 127.0.0.1
    <port>» داخل کانفیگ خودِ آن instance است.

    قبلاً OPENVPN_MGMT_PORTS فقط شامل همان دو پورت اصلی بود، یعنی هر کاربری
    که از یک «پورت اضافه» وصل می‌شد (سناریوی بسیار رایج برای دورزدن
    فیلترینگ) نه در sample_openvpn_traffic دیده می‌شد (حجمش هیچ‌وقت زنده
    آپدیت نمی‌شد) و نه در reconcile_openvpn_sessions (چون در status همان دو
    پورت اصلی حاضر نبود، هر دور به‌اشتباه «آفلاین» اعلام می‌شد - همان چیزی
    که به‌عنوان «دیگه کاربر آنلاین هم نشون نمی‌ده» گزارش شد)."""
    from app.models import OpenvpnExtraPort  # local import عمدی، مثل بقیه‌ی reconcile ها

    ports: list[int] = []
    rows = db.query(OpenvpnExtraPort).filter(OpenvpnExtraPort.is_active == True).all()  # noqa: E712
    for row in rows:
        conf_path = f"/etc/openvpn/server/server-extra-{row.protocol}-{row.port}.conf"
        try:
            with open(conf_path) as f:
                content = f.read()
        except OSError:
            continue
        m = _EXTRA_PORT_MGMT_RE.search(content)
        if m:
            ports.append(int(m.group(1)))
    return ports


_OPENVPN_LIVE_CACHE_LOCK = threading.Lock()
_OPENVPN_LIVE_REFRESH_LOCK = threading.Lock()
_OPENVPN_LIVE_CACHE: dict[tuple[int, ...], tuple[float, dict[str, dict], bool]] = {}
# One snapshot is shared by presence, traffic and admission callers.  A 1.25s
# cache still allowed two scheduler jobs plus concurrent HTTP hooks to fan out
# across every management port at once.  The single-flight lock below ensures
# only one scan is in progress, while a short stale window remains fail-open.
_OPENVPN_LIVE_CACHE_TTL_SECONDS = 3.5
_OPENVPN_LIVE_CACHE_STALE_SECONDS = 12.0


def _live_openvpn_clients_all_ports(
    db: Session | None = None, *, timeout: float = 0.65, use_cache: bool = True,
) -> tuple[dict[str, dict], bool]:
    """Read all OpenVPN management sockets with a single shared scan.

    Presence, traffic accounting and connect admission can overlap.  Older
    builds let every caller open one socket per listener, producing status-2
    storms and broken pipes.  Only one refresh is now allowed; concurrent
    callers use a recent snapshot or fail-open when no trustworthy snapshot
    exists.
    """
    ports = list(dict.fromkeys(list(OPENVPN_MGMT_PORTS) + (
        _extra_openvpn_mgmt_ports(db) if db is not None else []
    )))
    if not ports:
        return {}, False

    cache_key = tuple(sorted(ports))

    def cached_snapshot(max_age: float):
        now = time.monotonic()
        with _OPENVPN_LIVE_CACHE_LOCK:
            cached = _OPENVPN_LIVE_CACHE.get(cache_key)
            if cached and now - cached[0] <= max_age:
                return dict(cached[1]), bool(cached[2])
        return None

    if use_cache:
        cached = cached_snapshot(_OPENVPN_LIVE_CACHE_TTL_SECONDS)
        if cached is not None:
            return cached

    # Do not queue scheduler/API threads behind a slow management socket.  The
    # current refresher will publish a snapshot shortly; meanwhile a recent
    # stale snapshot is safer than multiplying probes or declaring users dead.
    if not _OPENVPN_LIVE_REFRESH_LOCK.acquire(blocking=False):
        cached = cached_snapshot(_OPENVPN_LIVE_CACHE_STALE_SECONDS)
        return cached if cached is not None else ({}, False)

    try:
        # Another caller may have completed between our initial cache check and
        # lock acquisition.  Forced admission probes skip this only when no
        # current refresh was available.
        if use_cache:
            cached = cached_snapshot(_OPENVPN_LIVE_CACHE_TTL_SECONDS)
            if cached is not None:
                return cached

        merged: dict[str, dict] = {}
        any_ok = False
        with ThreadPoolExecutor(max_workers=min(6, len(ports)), thread_name_prefix="ovpn-mgmt") as pool:
            futures = {pool.submit(_live_openvpn_clients, port, timeout): port for port in ports}
            for future in as_completed(futures):
                try:
                    result = future.result()
                except Exception:
                    result = None
                if result is not None:
                    any_ok = True
                    merged.update(result)

        with _OPENVPN_LIVE_CACHE_LOCK:
            _OPENVPN_LIVE_CACHE[cache_key] = (time.monotonic(), dict(merged), any_ok)
            if len(_OPENVPN_LIVE_CACHE) > 16:
                oldest = min(_OPENVPN_LIVE_CACHE, key=lambda key: _OPENVPN_LIVE_CACHE[key][0])
                _OPENVPN_LIVE_CACHE.pop(oldest, None)
        return merged, any_ok
    finally:
        _OPENVPN_LIVE_REFRESH_LOCK.release()


def _match_live_openvpn_session(live: dict[str, dict], session: ConnectionLog) -> dict | None:
    """Match one DB row to one exact OpenVPN management session.

    Pool addresses can be reused immediately after a reconnect.  Therefore a
    tunnel IP alone is not sufficient: current hooks also persist trusted_port,
    and status 2 provides both the peer port and connection timestamp.  This
    lets a new tunnel retire a ghost row even when it receives the same 10.8.x
    address, without collapsing two genuine devices behind one NAT.
    """
    username = session.user.username if session.user else None
    if not username:
        return None
    candidates = [row for row in live.values() if row.get("username") == username]
    if session.tunnel_ip:
        candidates = [row for row in candidates if row.get("tunnel_ip") == session.tunnel_ip]
    if int(getattr(session, "source_port", 0) or 0) > 0:
        candidates = [
            row for row in candidates
            if int(row.get("source_port") or 0) == int(session.source_port)
        ]
    if session.connect_time:
        timed = []
        for row in candidates:
            connected_at = row.get("connected_at")
            if connected_at is None or abs((connected_at - session.connect_time).total_seconds()) <= 20:
                timed.append(row)
        candidates = timed
    if len(candidates) == 1:
        return candidates[0]
    if len(candidates) > 1:
        return max(candidates, key=lambda row: int(row.get("bytes_in") or 0) + int(row.get("bytes_out") or 0))
    return None


def sample_openvpn_traffic(db: Session) -> int:
    """مثل sample_ppp_traffic ولی برای OpenVPN: قبلاً used_bytes کاربران
    OpenVPN فقط یک‌بار، درست لحظه‌ی قطع اتصال (disconnect_event) به‌روزرسانی
    می‌شد - یعنی تا وقتی کاربر وصل بود (حتی ساعت‌ها)، هم صفحه‌ی مصرف هم چک
    quota_bytes در enforce_limits_job، حجمِ همان سشنِ درحال‌اجرا را کاملاً
    نادیده می‌گرفتند؛ کاربری که همان لحظه‌ی وصل‌شدن حجمش کافی بود می‌توانست
    چند برابر quota_bytes مصرف کند تا بالاخره قطع/دوباره‌وصل شود.

    این تابع (هر MONITOR_INTERVAL_SECONDS از reconcile_sessions_job، دقیقاً
    هم‌زمان با enforce_limits_job که با همان فاصله اجرا می‌شود) شمارنده‌ی
    بایت هر کلاینت زنده را از management interface می‌خواند و فقط دلتای آن
    نسبت به آخرین مقدار ثبت‌شده روی همان ConnectionLog را به used_bytes
    کاربر اضافه می‌کند - همان الگوی دقیق sample_ppp_traffic، تا در پایان
    واقعی اتصال (disconnect_event) بایتی دوباره حساب نشود.

    اگر این دور اصلاً نتوانیم mgmt هیچ‌کدام از دو پروسه را بخوانیم، هیچ‌کاری
    نمی‌کند (نه صفر می‌نویسد، نه دلتای غلط حساب می‌کند) - دور بعدی جبران
    می‌شود."""
    live, any_ok = _live_openvpn_clients_all_ports(db)
    if not any_ok:
        return 0

    sessions = (
        db.query(ConnectionLog)
        .join(VpnUser, VpnUser.id == ConnectionLog.user_id)
        .filter(
            ConnectionLog.protocol == "openvpn",
            ConnectionLog.is_online == True,  # noqa: E712
        )
        .all()
    )
    sampled = 0
    for s in sessions:
        data = _match_live_openvpn_session(live, s)
        if not data:
            continue
        s.last_seen_at = datetime.utcnow()
        s.presence_state = "active"
        s.presence_failures = 0
        if s.user:
            ensure_first_connect(s.user, s.connect_time)
        prev_rx = s.bytes_in or 0
        prev_tx = s.bytes_out or 0
        new_rx = data["bytes_in"]
        new_tx = data["bytes_out"]
        # اگر مقدار جدید از قبلی کمتر باشد (مثلاً همان یوزرنیم با یک سشن
        # کاملاً تازه‌ی دیگر - شمارنده‌ی OpenVPN با هر اتصال از صفر شروع
        # می‌شود)، کل مقدار فعلی را delta در نظر می‌گیریم، نه یک عدد منفی.
        delta_rx = new_rx - prev_rx if new_rx >= prev_rx else new_rx
        delta_tx = new_tx - prev_tx if new_tx >= prev_tx else new_tx
        if delta_rx or delta_tx:
            if s.user:
                s.user.used_bytes = (s.user.used_bytes or 0) + delta_rx + delta_tx
            s.bytes_in = new_rx
            s.bytes_out = new_tx
            sampled += 1
    if sessions:
        db.commit()
    return sampled


def reconcile_openvpn_sessions(
    db: Session, username: str | None = None, *, probe_timeout: float = 0.65,
    grace_seconds: float = 3.0, use_cache: bool = True,
) -> int:
    """مثل reconcile_ppp_sessions ولی برای OpenVPN: چون OpenVPN (برخلاف
    pppd) یک پردازش جدای مستقیم به‌ازای هر کاربر ندارد (همه از دو پروسه‌ی
    مشترک UDP/TCP رد می‌شوند)، به‌جای چک pid، مستقیماً از management
    interface هر دو پروسه لیست واقعی کلاینت‌های متصل را می‌گیرد و هر رکورد
    ConnectionLog که «آنلاین» مانده ولی دیگر در آن لیست نیست را آفلاین می‌کند.

    چرا لازم است (جدا از کاهش تازه‌ی keepalive روی خودِ سرور): اگر اسکریپت
    client-disconnect به هر دلیل (مثلاً بک‌اند لحظه‌ای پایین/کند بوده باشد)
    نتواند رویداد قطع را به پنل برساند، رکورد برای همیشه «آنلاین» می‌ماند تا
    یک ادمین دستی آن را قطع کند - همین حالت باعث می‌شد با max_devices=1،
    اتصال مجدد واقعی همان کاربر رد شود («قبلاً وصل است») حتی وقتی خودِ
    OpenVPN دیگر آن کلاینت را نمی‌شناسد.

    این تابع هم به‌صورت دوره‌ای (scheduler) و هم مستقیماً همان لحظه‌ی اتصال
    مجدد (routers/vpn.py، قبل از رد کردن به‌خاطر max_devices) صدا زده
    می‌شود - تا آن حالت فوراً/لحظه‌ای رفع شود، نه با تاخیر تا اجرای بعدی job.

    اگر این دور اصلاً نتوانیم mgmt هیچ‌کدام از دو پروسه را بخوانیم، هیچ
    سشنی آفلاین نمی‌شود (fail-open واقعی - قبلاً این حالت با «هیچ‌کس آنلاین
    نیست» یکی حساب می‌شد که باعث آفلاین‌شدنِ نادرستِ کاربرانِ واقعاً وصل
    می‌شد).

    username (اختیاری): اگر داده شود فقط سشن‌های همان کاربر بررسی می‌شود
    (برای چک لحظه‌ای موقع اتصال مجدد، سریع‌تر از خواندن کل جدول)."""
    live, any_ok = _live_openvpn_clients_all_ports(
        db, timeout=probe_timeout, use_cache=use_cache,
    )
    if not any_ok:
        return 0
    live_usernames = {str(row.get("username") or "") for row in live.values()}

    q = (
        db.query(ConnectionLog)
        .join(VpnUser, VpnUser.id == ConnectionLog.user_id)
        .filter(
            ConnectionLog.protocol == "openvpn",
            ConnectionLog.is_online == True,  # noqa: E712
        )
    )
    if username:
        q = q.filter(VpnUser.username == username)
    sessions = q.all()

    # مهلت محافظتی: بین لحظه‌ای که openvpn_connect.sh رکورد را با is_online=True
    # می‌سازد (client-connect - قبل از این‌که OpenVPN واقعاً PUSH_REPLY را
    # بفرستد) تا لحظه‌ای که همان کلاینت در خروجی «status 2» ظاهر شود، یک
    # فاصله‌ی چند ثانیه‌ای واقعی وجود دارد (کمی بیشتر اگر بک‌اند کند جواب
    # داده باشد - همان --max-time 5 خودِ اسکریپت). اگر این تابع دقیقاً وسط
    # همان فاصله اجرا شود (هر MONITOR_INTERVAL_SECONDS از scheduler)، کلاینت
    # هنوز در live_usernames نیست ولی واقعاً دارد وصل می‌شود - نتیجه همان باگ
    # «کاربر یک لحظه آنلاین بعد فوراً آفلاین می‌شود، با اینکه واقعاً وصل است»
    # بود (و چون خودِ OpenVPN هیچ‌وقت client-disconnect برای این اتصال صدا
    # نمی‌زد، حجمش هم فقط در پایانِ واقعی اتصال به‌صورت یک‌جا اضافه می‌شد، نه
    # لحظه‌ای - که دقیقاً چیزی است که کاربر دیده). با نادیده‌گرفتن سشن‌هایی که
    # کمتر از GRACE_SECONDS پیش ساخته شده‌اند، به آن پنجره‌ی زمانی فرصت
    # می‌دهیم تا خودش را در status نشان دهد، قبل از این‌که آفلاین اعلام شود.
    GRACE_SECONDS = max(0.0, float(grace_seconds))
    now = datetime.utcnow()

    fixed = 0
    retired_cluster_keys: set[str] = set()
    for s in sessions:
        if (now - s.connect_time).total_seconds() < GRACE_SECONDS:
            continue
        uname = s.user.username if s.user else None
        matched = _match_live_openvpn_session(live, s)
        # Rows created by current hooks have a tunnel_ip and can be retired
        # exactly.  A legacy row without tunnel_ip stays fail-open while any
        # tunnel for that username exists.
        missing = matched is None and (bool(s.tunnel_ip) or not uname or uname not in live_usernames)
        if missing:
            try:
                from app.services.rate_limiter import remove_session_limits

                if s.user is not None:
                    remove_session_limits(s.user, s)
            except Exception:
                pass
            s.is_online = False
            s.presence_state = "offline"
            s.disconnect_time = datetime.utcnow()
            cluster_key = str(getattr(s, "cluster_session_key", "") or "").strip()
            if cluster_key:
                retired_cluster_keys.add(cluster_key)
            fixed += 1
        elif matched is not None:
            s.last_seen_at = datetime.utcnow()
            s.presence_state = "active"
            s.presence_failures = 0
    if sessions:
        db.commit()
    if fixed:
        _invalidate_node_presence_snapshot()
        _release_retired_cluster_sessions(db, retired_cluster_keys)
    return fixed


def kill_openvpn_session(username: str, ip_address: str | None = None):
    """قطع اتصال فعال یک کاربر OpenVPN از طریق management interface.

    اگر ip_address داده شود، اسکریپت فقط همان سشن مشخص (با همان آی‌پی) را
    با client-kill قطع می‌کند؛ در غیر این صورت (مثلاً قطع از صفحه‌ی کاربران)
    مثل قبل همه‌ی سشن‌های آن کاربر با kill بر اساس نام‌کاربری قطع می‌شوند.
    """
    try:
        args = [BASH, "/opt/vpn-panel/scripts/openvpn_kill.sh", username]
        if ip_address:
            args.append(ip_address)
        subprocess.run(args, check=False)
    except Exception:
        pass


def kill_single_openvpn_session(db: Session, log: ConnectionLog) -> bool:
    """قطع همان اتصال OpenVPN و بستن فوری رکورد دیتابیس."""
    if log.protocol != "openvpn" or not log.user:
        return False
    try:
        kill_openvpn_session(log.user.username, log.ip_address or None)
        log.is_online = False
        log.disconnect_time = datetime.utcnow()
        db.commit()
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# IKEv2/IPsec (strongSwan، EAP-MSCHAPv2) - آنلاین‌بودن + حجم مصرفی
#
# برخلاف L2TP/PPTP (که pppd خودش اسکریپت ip-up/ip-down را صدا می‌زند و رویداد
# connect/disconnect را به /api/internal می‌فرستد) و OpenVPN (که client-connect/
# client-disconnect دقیقاً همین کار را می‌کند)، charon/strongSwan هیچ اسکریپت
# هوک استانداردی برای «کاربر با یوزرنیم X وصل/قطع شد» ندارد که به پنل خبر
# بدهد - همین باعث می‌شد کاربران IKEv2 هیچ‌وقت در صفحه‌ی «کاربران آنلاین»
# دیده نشوند و حجم مصرفی‌شان هم هیچ‌وقت در used_bytes ثبت نشود (نه در لحظه‌ی
# قطع، نه در طول اتصال).
#
# راه‌حل: به‌جای هوک، خروجی «ipsec statusall» را دوره‌ای (همان
# reconcile_sessions_job، هر MONITOR_INTERVAL_SECONDS) می‌خوانیم؛ این خروجی
# هم لیست IKE_SAهای زنده را می‌دهد (با EAP identity = یوزرنیم، چون
# eap_identity=%identity در conn IKEv2-MSCHAPv2) هم شمارنده‌ی بایت هر
# CHILD_SA را. یک پاس همزمان هم سشن‌های تازه را کشف/ثبت می‌کند (چون رویداد
# connect وجود ندارد)، هم سشن‌های قطع‌شده را آفلاین می‌کند، هم دلتای حجم را
# مثل sample_ppp_traffic به used_bytes اضافه می‌کند.
#
# کلید یکتای هر سشن: unique IKE_SA id گزارش‌شده توسط strongSwan (پایدار تا
# وقتی همان SA زنده است) در ConnectionLog.interface به‌صورت "ike-<id>" ذخیره
# می‌شود - همان نقشی که ستون interface برای l2tp/pptp دارد.
# ---------------------------------------------------------------------------

# «connname[3]: ESTABLISHED ... 1.2.3.4[server-id]...5.6.7.8[username]»
_IKEV2_ESTABLISHED_RE = re.compile(
    r'^\S+\[(\d+)\]:\s+ESTABLISHED\b.*\.\.\.([0-9a-fA-F:.]+)\[(.+)\]\s*$'
)
# دو فرمت مختلف که نسخه‌های مختلف strongSwan برای شمارنده‌ی بایت CHILD_SA
# چاپ می‌کنند: «12345 bytes_i, 6789 bytes_o» یا «bytes_i (12345), bytes_o (6789)»
_IKEV2_BYTES_RE_A = re.compile(r'(\d+)\s*bytes_i,\s*(\d+)\s*bytes_o')
_IKEV2_BYTES_RE_B = re.compile(r'bytes_i\s*\((\d+)\),\s*bytes_o\s*\((\d+)\)')
# CHILD_SA traffic selector line, e.g.
#   ikev2-eap{3}: 0.0.0.0/0 === 10.10.11.4/32
# The right-hand host address is the virtual IP assigned to this user.
_IKEV2_TUNNEL_IP_RE = re.compile(r'===\s*([0-9a-fA-F:.]+)/(?:32|128)(?:\s|$)')


def _live_ikev2_sessions(timeout: float = 4.0) -> dict[str, dict]:
    """اجرای «ipsec statusall» و پارس خروجی آن به یک دیکشنری
    {ike_sa_id: {"username", "ip", "bytes_in", "bytes_out"}}. اگر strongSwan
    نصب/بالا نباشد یا هر خطای دیگری رخ دهد، دیکشنری خالی برمی‌گرداند
    (fail-open - هیچ سشنی را به اشتباه آفلاین نمی‌کنیم)."""
    try:
        out = subprocess.run(
            [IPSEC, "statusall"], capture_output=True, text=True, timeout=timeout, check=False
        )
        output = out.stdout or ""
    except Exception:
        return {}

    sessions: dict[str, dict] = {}
    current_id = None
    current_ip = None
    current_username = None
    current_tunnel_ip = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        m = _IKEV2_ESTABLISHED_RE.match(line)
        if m:
            current_id, current_ip, current_username = m.group(1), m.group(2), m.group(3)
            current_tunnel_ip = None
            continue
        mt = _IKEV2_TUNNEL_IP_RE.search(line)
        if mt and current_id is not None:
            current_tunnel_ip = mt.group(1)
            if current_id in sessions:
                sessions[current_id]["tunnel_ip"] = current_tunnel_ip
        mb = _IKEV2_BYTES_RE_A.search(line) or _IKEV2_BYTES_RE_B.search(line)
        if mb and current_id is not None:
            sessions[current_id] = {
                "username": current_username,
                "ip": current_ip,
                "tunnel_ip": current_tunnel_ip,
                "bytes_in": int(mb.group(1)),
                "bytes_out": int(mb.group(2)),
            }
    return sessions


def reconcile_ikev2_sessions(db: Session) -> int:
    """یک پاس کامل روی وضعیت واقعی IKEv2 (از ipsec statusall):
      ۱) سشن‌هایی که در دیتابیس «آنلاین» مانده ولی دیگر در strongSwan زنده
         نیستند را آفلاین می‌کند (با آخرین بایت شمرده‌شده به‌جای گم‌شدن حجم).
      ۲) حجم دلتای سشن‌های هنوز آنلاین را به used_bytes اضافه می‌کند (زنده،
         نه فقط لحظه‌ی قطع - دقیقاً مثل sample_ppp_traffic برای l2tp/pptp).
      ۳) سشن‌های تازه‌ی زنده که هنوز رکوردی در دیتابیس ندارند را می‌سازد (چون
         IKEv2 هیچ رویداد connect ای شبیه پروتکل‌های دیگر ندارد).
    تعداد IKE_SAهای زنده را برمی‌گرداند."""
    live = _live_ikev2_sessions()
    live_keys = {f"ike-{ike_id}" for ike_id in live}

    tracked = (
        db.query(ConnectionLog)
        .filter(ConnectionLog.protocol == "ikev2", ConnectionLog.is_online == True)  # noqa: E712
        .all()
    )
    tracked_keys = {s.interface for s in tracked if s.interface}
    changed = False

    for s in tracked:
        if s.interface not in live_keys:
            s.is_online = False
            s.disconnect_time = datetime.utcnow()
            changed = True
            continue
        data = live.get(s.interface.split("-", 1)[1])
        if not data:
            continue
        if s.user:
            ensure_first_connect(s.user, s.connect_time)
        prev_rx = s.bytes_in or 0
        prev_tx = s.bytes_out or 0
        new_rx = data["bytes_in"]
        new_tx = data["bytes_out"]
        delta_rx = new_rx - prev_rx if new_rx >= prev_rx else new_rx
        delta_tx = new_tx - prev_tx if new_tx >= prev_tx else new_tx
        tunnel_ip = data.get("tunnel_ip")
        if tunnel_ip and s.tunnel_ip != tunnel_ip:
            s.tunnel_ip = tunnel_ip
            changed = True
        if delta_rx or delta_tx:
            u = db.query(VpnUser).filter(VpnUser.id == s.user_id).first()
            if u:
                u.used_bytes = (u.used_bytes or 0) + delta_rx + delta_tx
            s.bytes_in = new_rx
            s.bytes_out = new_tx
            changed = True

    for ike_id, data in live.items():
        key = f"ike-{ike_id}"
        if key in tracked_keys:
            continue
        username = data.get("username")
        if not username:
            continue
        u = db.query(VpnUser).filter(VpnUser.username == username).first()
        if not u:
            continue

        # IKEv2 has no synchronous connect hook. Enforce the same global cap
        # here, on the first four-second strongSwan snapshot: keep the already
        # admitted/older tunnel and terminate this newly discovered IKE_SA.
        invalid = (
            not bool(u.is_active)
            or not bool(u.enable_ikev2)
            or bool(u.expire_date and u.expire_date < datetime.utcnow().date())
            or bool(u.quota_bytes > 0 and int(u.used_bytes or 0) >= int(u.quota_bytes))
        )
        active_count = (
            db.query(ConnectionLog)
            .filter(
                ConnectionLog.user_id == u.id,
                ConnectionLog.is_online == True,  # noqa: E712
                ConnectionLog.device_limit_blocked == False,  # noqa: E712
            )
            .count()
        )
        over_limit = int(u.max_devices or 0) > 0 and active_count >= int(u.max_devices)
        if invalid or over_limit:
            try:
                subprocess.run(
                    [IPSEC, "terminate", "--ike-id", str(ike_id)],
                    capture_output=True, text=True, timeout=10, check=False,
                )
            except Exception:
                pass
            continue

        connected_at = datetime.utcnow()
        ensure_first_connect(u, connected_at)
        initial_rx = max(0, int(data.get("bytes_in") or 0))
        initial_tx = max(0, int(data.get("bytes_out") or 0))
        # These bytes were transferred between the IKE handshake and the first
        # poll. Count them once instead of silently using them only as baseline.
        if initial_rx or initial_tx:
            u.used_bytes = int(u.used_bytes or 0) + initial_rx + initial_tx
        db.add(ConnectionLog(
            user_id=u.id,
            protocol="ikev2",
            ip_address=data.get("ip"),
            interface=key,
            tunnel_ip=data.get("tunnel_ip"),
            connect_time=connected_at,
            is_online=True,
            bytes_in=initial_rx,
            bytes_out=initial_tx,
        ))
        changed = True

    if changed:
        db.commit()
    return len(live)


def kill_ikev2_session(db: Session, username: str) -> None:
    """قطع تمام سشن‌های IKEv2 یک کاربر. برخلاف OpenVPN که یک management
    interface با دستور client-kill دارد، strongSwan باید با ike-id واقعی
    (از ipsec statusall) صدا زده شود - هر IKE_SA زنده‌ی همان یوزرنیم را جدا
    terminate می‌کنیم."""
    live = _live_ikev2_sessions()
    for ike_id, data in live.items():
        if data.get("username") == username:
            try:
                subprocess.run(
                    [IPSEC, "terminate", "--ike-id", str(ike_id)],
                    capture_output=True, text=True, timeout=10, check=False,
                )
            except Exception:
                pass

    sessions = (
        db.query(ConnectionLog)
        .join(VpnUser, VpnUser.id == ConnectionLog.user_id)
        .filter(
            VpnUser.username == username,
            ConnectionLog.protocol == "ikev2",
            ConnectionLog.is_online == True,  # noqa: E712
        )
        .all()
    )
    for s in sessions:
        s.is_online = False
        s.disconnect_time = datetime.utcnow()
    if sessions:
        db.commit()


def kill_single_ikev2_session(db: Session, log: ConnectionLog) -> bool:
    """قطع دقیق یک IKE_SA با شناسه ذخیره‌شده در interface (ike-<id>)."""
    if log.protocol != "ikev2":
        return False
    ike_id = None
    if log.interface and str(log.interface).startswith("ike-"):
        ike_id = str(log.interface).split("-", 1)[1]
    ok = False
    if ike_id and ike_id.isdigit():
        try:
            result = subprocess.run(
                [IPSEC, "terminate", "--ike-id", ike_id],
                capture_output=True, text=True, timeout=10, check=False,
            )
            ok = result.returncode == 0
        except Exception:
            ok = False
    elif log.user:
        kill_ikev2_session(db, log.user.username)
        return True
    log.is_online = False
    log.disconnect_time = datetime.utcnow()
    db.commit()
    return ok


# ---------------------------------------------------------------------------
# OpenConnect (ocserv - سازگار با کلاینت Cisco AnyConnect)
#
# برخلاف IKEv2 (که هیچ رویداد connect/disconnect ای ندارد)، آنلاین‌شدن/
# آفلاین‌شدن OpenConnect از طریق دو اسکریپت هوک مستقیم ocserv
# (connect-script/disconnect-script - نگاه کنید به
# scripts/openconnect_connect.sh و scripts/openconnect_disconnect.sh) که
# مستقیماً به /api/internal/connect و /api/internal/disconnect خبر می‌دهند
# ثبت می‌شود؛ پس نیازی به polling/reconcile جداگانه برای کشف سشن‌های
# تازه/قطع‌شده (مثل reconcile_ikev2_sessions) نیست.
#
# اما خودِ حجم مصرفی («used_bytes») قبلاً فقط در همان لحظه‌ی قطع اتصال
# به‌روزرسانی می‌شد: STATS_BYTES_IN/STATS_BYTES_OUT فقط توسط ocserv در پایان
# سشن به openconnect_disconnect.sh داده می‌شود، نه در حین اتصال. یعنی دقیقاً
# همان باگ «حجم L2TP/PPTP فقط لحظه‌ی قطع آپدیت می‌شود» (نگاه کنید به
# sample_ppp_traffic) برای OpenConnect هم برقرار بود: تا وقتی کاربر وصل بود
# (حتی روزها)، هم صفحه‌ی مصرف هم چک quota_bytes در enforce_limits_job حجم
# همان سشنِ درحال‌اجرا را نادیده می‌گرفتند. sample_openconnect_traffic (پایین‌تر)
# این را با نمونه‌برداری زنده از occtl - درست مثل sample_ppp_traffic/
# sample_openvpn_traffic - رفع می‌کند؛ خودِ آنلاین/آفلاین‌شدن دست‌نخورده و
# به عهده‌ی همان دو اسکریپت هوک باقی می‌ماند.
# ---------------------------------------------------------------------------

def _parse_counter_value(value) -> int:
    """Parse occtl counters from either raw integers or human-readable text."""
    if value is None:
        return 0
    if isinstance(value, (int, float)):
        return max(0, int(value))
    text = str(value).strip().replace(",", "")
    if not text:
        return 0
    try:
        return max(0, int(float(text)))
    except ValueError:
        pass
    m = re.match(r"^([0-9]+(?:\.[0-9]+)?)\s*([kmgtpe]?i?b)?$", text, re.I)
    if not m:
        return 0
    number = float(m.group(1))
    unit = (m.group(2) or "b").lower()
    powers = {"b": 0, "kb": 1, "kib": 1, "mb": 2, "mib": 2, "gb": 3, "gib": 3,
              "tb": 4, "tib": 4, "pb": 5, "pib": 5, "eb": 6, "eib": 6}
    base = 1024 if "i" in unit else 1000
    return max(0, int(number * (base ** powers.get(unit, 0))))


def _normalise_occtl_entries(data) -> list[dict]:
    """Accept the different JSON shapes emitted by occtl releases.

    Depending on distro/version, `occtl --json show users` may return a list,
    a mapping containing `users`, or an object keyed by session id.  The old
    code accepted only a top-level list, which made live accounting silently
    stop on those other valid shapes.
    """
    if isinstance(data, list):
        return [row for row in data if isinstance(row, dict)]
    if not isinstance(data, dict):
        return []
    for key in ("users", "Users", "sessions", "Sessions", "connections", "Connections"):
        value = data.get(key)
        if isinstance(value, list):
            return [row for row in value if isinstance(row, dict)]
        if isinstance(value, dict):
            return [row for row in value.values() if isinstance(row, dict)]
    # Some versions return {"session-id": { ... }, ...}
    if all(isinstance(value, dict) for value in data.values()):
        return list(data.values())
    return [data]


def _ci_value(entry: dict, *names: str):
    normalised = {re.sub(r"[^a-z0-9]", "", str(k).lower()): v for k, v in entry.items()}
    for name in names:
        key = re.sub(r"[^a-z0-9]", "", name.lower())
        if key in normalised:
            return normalised[key]
    return None


def _live_openconnect_sessions() -> dict[str, dict]:
    """Return live ocserv sessions keyed by their vpns interface.

    JSON is preferred, but the parser intentionally tolerates the output
    variations seen across Ubuntu's ocserv packages.  Interface counters in
    sysfs are used separately by `sample_openconnect_traffic` and remain the
    primary source of truth for bytes while a tunnel is online.
    """
    try:
        out = subprocess.run(
            [OCCTL, "--json", "show", "users"],
            capture_output=True, text=True, timeout=4, check=False,
        )
        data = json.loads(out.stdout or "[]")
    except Exception:
        return {}

    sessions: dict[str, dict] = {}
    for entry in _normalise_occtl_entries(data):
        device = _ci_value(entry, "Device", "Interface", "Tun", "VPN device")
        username = _ci_value(entry, "Username", "User", "Name")
        if not device or not username:
            continue
        device = str(device).strip()
        username = str(username).strip()
        if not re.match(r"^[A-Za-z0-9_.:-]+$", device):
            continue
        sessions[device] = {
            "username": username,
            "bytes_in": _parse_counter_value(_ci_value(entry, "RX", "Bytes RX", "Received", "RX bytes")),
            "bytes_out": _parse_counter_value(_ci_value(entry, "TX", "Bytes TX", "Transmitted", "TX bytes")),
        }
    return sessions


def reconcile_openconnect_sessions(db: Session, username: str | None = None) -> int:
    """Close stale OpenConnect rows using ocserv's live session table.

    A missed disconnect hook previously left an old IP online forever.  The
    live occtl interface list is authoritative; a short grace period protects
    a brand-new hook from being closed before occtl exposes it.
    """
    live = _live_openconnect_sessions()
    query = db.query(ConnectionLog).filter(
        ConnectionLog.protocol == "openconnect",
        ConnectionLog.is_online == True,  # noqa: E712
    )
    if username:
        query = query.join(VpnUser, VpnUser.id == ConnectionLog.user_id).filter(VpnUser.username == username)
    rows = query.order_by(ConnectionLog.connect_time.desc()).all()
    now = datetime.utcnow()
    changed = 0
    seen_interfaces: set[str] = set()
    for row in rows:
        interface = (row.interface or "").strip()
        live_row = live.get(interface) if interface else None
        live_username = str((live_row or {}).get("username") or "").strip()
        expected_username = row.user.username if row.user else ""
        duplicate = bool(interface and interface in seen_interfaces)
        if interface:
            seen_interfaces.add(interface)
        is_live = bool(live_row and (not expected_username or live_username == expected_username))
        age = (now - row.connect_time).total_seconds() if row.connect_time else 999
        if duplicate or (age >= 4 and not is_live):
            row.is_online = False
            row.disconnect_time = row.disconnect_time or now
            changed += 1
    if changed:
        db.commit()
    return changed


def _interface_counters(interface: str | None) -> tuple[int, int] | None:
    """Read per-session tunnel counters directly from Linux sysfs.

    ocserv creates one `vpns*` interface per connected user.  These counters
    update continuously and do not depend on occtl's JSON schema, which makes
    them considerably more reliable for live quota accounting.
    """
    if not interface or not re.match(r"^[A-Za-z0-9_.:-]+$", interface):
        return None
    root = f"/sys/class/net/{interface}/statistics"
    try:
        rx = int(open(os.path.join(root, "rx_bytes"), "r", encoding="ascii").read().strip())
        tx = int(open(os.path.join(root, "tx_bytes"), "r", encoding="ascii").read().strip())
        return max(0, rx), max(0, tx)
    except (OSError, ValueError):
        return None


def sample_openconnect_traffic(db: Session) -> int:
    """درست مثل sample_ppp_traffic/sample_openvpn_traffic: هر
    MONITOR_INTERVAL_SECONDS یک‌بار (از همان reconcile_sessions_job) بایت‌های
    زنده‌ی هر سشن آنلاینِ OpenConnect را از occtl می‌خواند و فقط تفاضل
    (delta) نسبت به آخرین مقدار ثبت‌شده روی همان ConnectionLog را به
    used_bytes کاربر اضافه می‌کند - نه کل مقدار را. همین «فقط دلتا» تضمین
    می‌کند وقتی در پایان سشن openconnect_disconnect.sh مقدار نهایی
    (STATS_BYTES_IN/OUT) را می‌فرستد، disconnect_event (routers/vpn.py - که
    از قبل به همین روش دلتا نوشته شده بود) دوباره همان بایت‌ها را حساب نکند.

    برخلاف sample_ppp_traffic (که آفلاین‌کردن سشن‌های یتیم را هم خودش انجام
    می‌دهد)، اینجا فقط حجم به‌روزرسانی می‌شود: تشخیص قطع واقعی OpenConnect
    همچنان کاملاً به عهده‌ی openconnect_disconnect.sh است (نگاه کنید به کامنت
    بالای این بخش)."""
    # sysfs is the primary source; occtl is only a fallback when the interface
    # counters are not available (for example during a very short race while
    # the device is being torn down).
    live = _live_openconnect_sessions()

    tracked = (
        db.query(ConnectionLog)
        .filter(
            ConnectionLog.protocol == "openconnect",
            ConnectionLog.is_online == True,  # noqa: E712
            ConnectionLog.interface.isnot(None),
        )
        .all()
    )
    sampled = 0
    for s in tracked:
        counters = _interface_counters(s.interface)
        if counters is not None:
            new_rx, new_tx = counters
        else:
            data = live.get(s.interface)
            if not data:
                continue
            new_rx = data["bytes_in"]
            new_tx = data["bytes_out"]
        if s.user:
            ensure_first_connect(s.user, s.connect_time)
        prev_rx = s.bytes_in or 0
        prev_tx = s.bytes_out or 0
        delta_rx = new_rx - prev_rx if new_rx >= prev_rx else new_rx
        delta_tx = new_tx - prev_tx if new_tx >= prev_tx else new_tx

        if delta_rx or delta_tx:
            u = db.query(VpnUser).filter(VpnUser.id == s.user_id).first()
            if u:
                u.used_bytes = (u.used_bytes or 0) + delta_rx + delta_tx
            s.bytes_in = new_rx
            s.bytes_out = new_tx
            sampled += 1

    if sampled:
        db.commit()
    return sampled


def kill_openconnect_session(username: str) -> None:
    """قطع تمام سشن‌های فعال OpenConnect یک کاربر با ابزار occtl (کنترل
    خط‌فرمان ocserv). مثل kill_openvpn_session، عمداً fail-silent است: اگر
    زیرساخت OpenConnect اصلاً نصب نباشد (occtl موجود نیست) یا سوکت مدیریتی
    در دسترس نباشد، این فقط یعنی کاربری برای قطع‌کردن هم وجود نداشت - نباید
    باعث خطا در ذخیره‌شدن تغییرات کاربر شود. رویداد disconnect واقعی توسط
    خودِ ocserv (openconnect_disconnect.sh) به پنل خبر داده می‌شود و ConnectionLog
    را می‌بندد، پس اینجا نیازی به آفلاین‌کردن دستی رکورد نیست."""
    try:
        subprocess.run(
            [OCCTL, "disconnect", "user", username],
            capture_output=True, text=True, timeout=10, check=False,
        )
    except Exception:
        pass


def kill_single_openconnect_session(db: Session, log: ConnectionLog) -> bool:
    """قطع دقیق یک سشن OpenConnect با ID گزارش‌شده توسط ocserv."""
    if log.protocol != "openconnect":
        return False
    ok = False
    session_id = int(log.pid or 0)
    if session_id > 0:
        try:
            result = subprocess.run(
                [OCCTL, "disconnect", "id", str(session_id)],
                capture_output=True, text=True, timeout=10, check=False,
            )
            ok = result.returncode == 0
        except Exception:
            ok = False
    elif log.user:
        kill_openconnect_session(log.user.username)
        ok = True
    log.is_online = False
    log.disconnect_time = datetime.utcnow()
    db.commit()
    return ok


# ---------------------------------------------------------------------------
# مسدودسازی آی‌پی عمومی (صفحه‌ی «آی‌پی‌های مسدود شده»، زیر کاربران آنلاین)
#
# پیاده‌سازی روی یک زنجیره‌ی اختصاصی iptables (نه دستکاری مستقیم INPUT) تا:
#   - قوانین این پنل کاملاً از بقیه‌ی قوانین فایروال سرور (نصب/NAT و...) جدا
#     و قابل شناسایی باشد
#   - flush/rebuild این زنجیره هیچ‌وقت قانون دیگری را پاک نکند
# این DROP در سطح شبکه (INPUT) است، یعنی قبل از رسیدن به هر پروتکلی (پس با
# یک بن، هر چهار پروتکل L2TP/PPTP/OpenVPN/SSTP هم‌زمان مسدود می‌شوند).
# ---------------------------------------------------------------------------

IP_BAN_CHAIN = "VPN-PANEL-BANS"


def _run_iptables(args: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run([IPTABLES, *args], capture_output=True, text=True, timeout=10, check=False)


def _ensure_ban_chain():
    """ساخت زنجیره‌ی اختصاصی (اگر نبود) و اتصال آن به INPUT (اگر وصل نبود).
    idempotent: اجرای چندباره‌اش مشکلی ایجاد نمی‌کند."""
    # ساخت زنجیره - اگر از قبل وجود داشته باشد iptables با کد خطا برمی‌گردد که نادیده گرفته می‌شود
    _run_iptables(["-N", IP_BAN_CHAIN])
    # اتصال به INPUT فقط اگر قبلاً وصل نشده باشد (اول چک، بعد اضافه - جلوگیری از تکرار)
    check = _run_iptables(["-C", "INPUT", "-j", IP_BAN_CHAIN])
    if check.returncode != 0:
        _run_iptables(["-I", "INPUT", "1", "-j", IP_BAN_CHAIN])


def _persist_iptables():
    """ذخیره‌ی قوانین فعلی تا بعد از ری‌استارت سرور هم باقی بمانند (نصب شده
    توسط install/install.sh: بسته‌ی iptables-persistent)."""
    try:
        subprocess.run([NETFILTER_PERSISTENT, "save"], capture_output=True, text=True, timeout=15, check=False)
    except Exception:
        pass


def ban_ip(
    db: Session, ip_address: str, reason: str | None, admin_id: int | None,
    owner_admin_id: int | None = None,
) -> BannedIP:
    """ثبت آی‌پی در دیتابیس + اعمال فوری قانون DROP روی iptables + قطع هر
    اتصال فعالی که همین الان از همان آی‌پی برقرار است (صرف‌نظر از این‌که
    متعلق به کدام کاربر/پروتکل باشد)."""
    existing = db.query(BannedIP).filter(BannedIP.ip_address == ip_address).first()
    if existing:
        return existing

    record = BannedIP(
        ip_address=ip_address, reason=(reason or None),
        banned_by_admin_id=admin_id, owner_admin_id=owner_admin_id if owner_admin_id is not None else admin_id,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    _ensure_ban_chain()
    check = _run_iptables(["-C", IP_BAN_CHAIN, "-s", ip_address, "-j", "DROP"])
    if check.returncode != 0:
        _run_iptables(["-A", IP_BAN_CHAIN, "-s", ip_address, "-j", "DROP"])
    _persist_iptables()

    disconnect_sessions_by_ip(db, ip_address)
    return record


def unban_ip(db: Session, ip_address: str) -> bool:
    """حذف آی‌پی از دیتابیس + حذف قانون DROP متناظر از iptables."""
    record = db.query(BannedIP).filter(BannedIP.ip_address == ip_address).first()
    if not record:
        return False
    db.delete(record)
    db.commit()

    _run_iptables(["-D", IP_BAN_CHAIN, "-s", ip_address, "-j", "DROP"])
    _persist_iptables()
    return True


def sync_ip_bans(db: Session):
    """بازسازی کامل زنجیره‌ی بن از روی دیتابیس - هنگام استارت بک‌اند صدا زده
    می‌شود تا اگر (به هر دلیلی، مثلاً iptables-persistent نصب/فعال نبوده)
    قوانین بعد از ری‌بوت سرور از دست رفته باشند، دوباره از روی دیتابیس اعمال
    شوند."""
    _ensure_ban_chain()
    _run_iptables(["-F", IP_BAN_CHAIN])
    ips = [r.ip_address for r in db.query(BannedIP).all()]
    for ip in ips:
        _run_iptables(["-A", IP_BAN_CHAIN, "-s", ip, "-j", "DROP"])


# ---------------------------------------------------------------------------
# Temporary global VPN internet cuts by public client IP.
#
# Unlike a security ban, this chain blocks only the transports/listeners used
# by the panel's nine VPN protocols. The web panel and unrelated server ports
# remain reachable from the same public IP. Every blocked IP is stored in
# ``internet_blocked_ips`` and can be restored from its dedicated panel page.
# ---------------------------------------------------------------------------

INTERNET_BLOCK_CHAIN = "VPN-PANEL-CUTS"


def _db_setting(db: Session, key: str, default: int) -> int:
    row = db.query(Setting).filter(Setting.key == key).first()
    try:
        return int(row.value) if row and row.value is not None else int(default)
    except (TypeError, ValueError):
        return int(default)


def _internet_block_transports(db: Session) -> tuple[set[int], set[int], set[str]]:
    """Return TCP ports, UDP ports and raw IP protocols for all VPNs.

    The list covers PPTP, IPsec/L2TP, SSTP, OpenConnect, OpenVPN, VMess,
    VLESS and IKEv2. IPsec and IKEv2 share UDP 500/4500 and ESP. PPTP uses
    TCP 1723 plus GRE. Active extra OpenVPN listeners are included too.
    """
    tcp_ports = {
        _db_setting(db, "pptp_port", 1723),
        _db_setting(db, "sstp_port", 4433),
        _db_setting(db, "openconnect_port", 8443),
        _db_setting(db, "openvpn_tcp_port", 1194),
        _db_setting(db, "vmess_port", 10000),
        _db_setting(db, "vless_port", 10001),
    }
    udp_ports = {
        _db_setting(db, "l2tp_port", 1701),
        500,
        4500,
        _db_setting(db, "openconnect_port", 8443),
        _db_setting(db, "openvpn_udp_port", 1194),
    }
    for extra in db.query(OpenvpnExtraPort).filter(OpenvpnExtraPort.is_active == True).all():  # noqa: E712
        try:
            port = int(extra.port)
        except (TypeError, ValueError):
            continue
        if str(extra.protocol).lower() == "tcp":
            tcp_ports.add(port)
        elif str(extra.protocol).lower() == "udp":
            udp_ports.add(port)
    return ({p for p in tcp_ports if 1 <= p <= 65535}, {p for p in udp_ports if 1 <= p <= 65535}, {"gre", "esp"})


def _ensure_internet_block_chain() -> None:
    _run_iptables(["-N", INTERNET_BLOCK_CHAIN])
    check = _run_iptables(["-C", "INPUT", "-j", INTERNET_BLOCK_CHAIN])
    if check.returncode != 0:
        # Put temporary cuts before general accept rules while preserving the
        # independent permanent-ban chain. Both chains are idempotent.
        _run_iptables(["-I", "INPUT", "1", "-j", INTERNET_BLOCK_CHAIN])


def _append_internet_block_rules(db: Session, ip_address: str) -> None:
    tcp_ports, udp_ports, raw_protocols = _internet_block_transports(db)
    for port in sorted(tcp_ports):
        _run_iptables(["-A", INTERNET_BLOCK_CHAIN, "-s", ip_address, "-p", "tcp", "--dport", str(port), "-j", "DROP"])
    for port in sorted(udp_ports):
        _run_iptables(["-A", INTERNET_BLOCK_CHAIN, "-s", ip_address, "-p", "udp", "--dport", str(port), "-j", "DROP"])
    for protocol in sorted(raw_protocols):
        _run_iptables(["-A", INTERNET_BLOCK_CHAIN, "-s", ip_address, "-p", protocol, "-j", "DROP"])


def block_internet_ip(
    db: Session,
    ip_address: str,
    *,
    user: VpnUser | None = None,
    username: str | None = None,
    protocol: str | None = None,
    reason: str | None = None,
    admin_id: int | None = None,
    admin_username: str | None = None,
    owner_admin_id: int | None = None,
) -> InternetBlockedIP:
    """Temporarily cut one public IP across every supported VPN protocol.

    New protocol handshakes and packets from existing tunnels are dropped,
    then all tracked active sessions from the public IP are terminated. The
    record remains until an administrator explicitly restores it.
    """
    existing = db.query(InternetBlockedIP).filter(InternetBlockedIP.ip_address == ip_address).first()
    if existing:
        sync_internet_blocks(db)
        disconnect_sessions_by_ip(db, ip_address)
        return existing

    resolved_username = username or (user.username if user else None)
    record = InternetBlockedIP(
        ip_address=ip_address,
        user_id=user.id if user else None,
        username=resolved_username,
        protocol=(protocol or None),
        reason=(reason or None),
        blocked_by_admin_id=admin_id,
        owner_admin_id=(owner_admin_id if owner_admin_id is not None else (user.owner_admin_id if user else admin_id)),
        blocked_by_username=(admin_username or None),
    )
    db.add(record)

    # Remove legacy per-Xray-protocol internet flags. From this version the
    # public-IP cut is the single source of truth for all nine protocols.
    if user is not None:
        user.vmess_internet_blocked = False
        user.vless_internet_blocked = False
    db.commit()
    db.refresh(record)

    sync_internet_blocks(db)
    disconnect_sessions_by_ip(db, ip_address)

    if user is not None:
        try:
            from app.services.xray_manager import sync_xray_users
            sync_xray_users(db, protocols=("vmess", "vless"), restart=False)
        except Exception:
            logger.exception("failed to clear legacy Xray internet flags while applying global IP cut")
    return record


def restore_internet_ip(db: Session, ip_address: str) -> bool:
    record = db.query(InternetBlockedIP).filter(InternetBlockedIP.ip_address == ip_address).first()
    if not record:
        return False
    db.delete(record)
    db.commit()
    # Rules for one IP span multiple dynamic protocol ports, so rebuilding the
    # small dedicated chain is safer than trying to delete individual rules.
    sync_internet_blocks(db)
    return True


def sync_internet_blocks(db: Session) -> None:
    """Rebuild all temporary VPN cut rules from the database.

    Called on backend startup and after protocol-port changes so blocked public
    IPs remain blocked even when a listener is moved to a different port.
    """
    _ensure_internet_block_chain()
    _run_iptables(["-F", INTERNET_BLOCK_CHAIN])
    for row in db.query(InternetBlockedIP).order_by(InternetBlockedIP.id.asc()).all():
        _append_internet_block_rules(db, row.ip_address)
    _persist_iptables()


def disconnect_sessions_by_ip(db: Session, ip_address: str) -> int:
    """قطع تمام سشن‌های آنلاینی که همین الان از این آی‌پی مشخص وصل‌اند
    (ممکن است به چند یوزر/پروتکل مختلف تعلق داشته باشند)."""
    sessions = (
        db.query(ConnectionLog)
        .join(VpnUser, VpnUser.id == ConnectionLog.user_id)
        .filter(ConnectionLog.ip_address == ip_address, ConnectionLog.is_online == True)  # noqa: E712
        .all()
    )
    count = 0
    # Some backends can only terminate by username (OpenConnect) rather than by
    # an individual public IP.  De-duplicate those calls when a user has more
    # than one tracked session from the banned address.
    killed_openconnect: set[str] = set()
    killed_ikev2: set[str] = set()
    for s in sessions:
        username = s.user.username if s.user else ""
        if s.protocol in ("l2tp", "pptp"):
            kill_single_ppp_session(db, s)
        elif s.protocol == "sstp":
            kill_single_sstp_session(db, s)
        elif s.protocol == "openvpn":
            kill_openvpn_session(username, s.ip_address)
            s.is_online = False
            s.disconnect_time = s.disconnect_time or datetime.utcnow()
        elif s.protocol == "ikev2" and username:
            if username not in killed_ikev2:
                kill_ikev2_session(db, username)
                killed_ikev2.add(username)
            s.is_online = False
            s.disconnect_time = s.disconnect_time or datetime.utcnow()
        elif s.protocol == "openconnect" and username:
            if username not in killed_openconnect:
                kill_openconnect_session(username)
                killed_openconnect.add(username)
            # The disconnect hook normally closes every record.  Mark this one
            # immediately too so the panel never continues to display a banned
            # connection if the hook cannot reach the API during shutdown.
            s.is_online = False
            s.disconnect_time = s.disconnect_time or datetime.utcnow()
        elif s.protocol in {"vmess", "vless"} and username:
            try:
                from app.services.xray_manager import disconnect_xray_session
                disconnect_xray_session(db, username, protocol=s.protocol, ip_address=ip_address)
            except Exception:
                pass
            s.is_online = False
            s.disconnect_time = s.disconnect_time or datetime.utcnow()
        count += 1
    if count:
        db.commit()
    return count


def reload_ppp_services():
    """Compatibility no-op.

    pppd reads ``chap-secrets`` for every new authentication.  xl2tpd has no
    safe in-place reload on the supported Ubuntu packages: systemd translates
    ``reload-or-restart`` into a full restart, which destroys the daemon's
    tunnel table while clients are still sending packets.  That exact sequence
    produces ``Can not find tunnel ...`` floods and visible connection stalls.
    Credential changes therefore require no service signal at all.
    """
    return None


def _live_l2tp_pppd_pids() -> list[int]:
    """Return pppd processes that were launched by xl2tpd."""
    pids: list[int] = []
    try:
        entries = os.listdir("/proc")
    except OSError:
        return pids
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/comm", "r", encoding="utf-8", errors="ignore") as fh:
                if fh.read().strip() != "pppd":
                    continue
            with open(f"/proc/{entry}/cmdline", "rb") as fh:
                cmdline = fh.read().replace(b"\x00", b" ").decode("utf-8", "ignore")
        except OSError:
            continue
        if "options.xl2tpd" in cmdline or "/etc/ppp/options.xl2tpd" in cmdline:
            pids.append(int(entry))
    return pids


def apply_pending_xl2tpd_restart_if_idle() -> bool:
    """Apply a deferred daemon-level L2TP change only after the last call ends.

    Port/daemon changes are written immediately but never interrupt a live
    tunnel.  The two-second PPP presence job calls this helper after retiring
    dead sessions.  A second process check immediately before restart reduces
    the reconnect race to the smallest practical window.
    """
    if not os.path.exists(XL2TPD_PENDING_RESTART):
        return False
    if os.path.exists(os.path.join(MANUAL_PROTOCOL_STOP_DIR, "l2tp")):
        try:
            os.unlink(XL2TPD_PENDING_RESTART)
        except OSError:
            pass
        return False
    if _live_l2tp_pppd_pids():
        return False
    if _live_l2tp_pppd_pids():
        return False
    try:
        result = subprocess.run(
            [SYSTEMCTL, "restart", "xl2tpd"],
            capture_output=True, text=True, timeout=35, check=False,
        )
    except Exception:
        logger.exception("deferred xl2tpd restart failed")
        return False
    if result.returncode != 0:
        logger.error("deferred xl2tpd restart failed: %s", ((result.stdout or "") + "\n" + (result.stderr or ""))[-1500:])
        return False
    try:
        os.unlink(XL2TPD_PENDING_RESTART)
    except OSError:
        pass
    logger.warning("deferred xl2tpd restart applied after all L2TP sessions became idle")
    return True


def apply_openconnect_settings(
    port: int,
    dns1: str = "8.8.8.8",
    dns2: str = "1.1.1.1",
) -> tuple[bool, str]:
    """Apply only ocserv's port/DNS configuration.

    This deliberately does not touch L2TP, PPTP, OpenVPN, SSTP, or strongSwan.
    It is used by the one-click 443 migration so freeing port 443 does not
    unnecessarily restart every other VPN backend and disconnect unrelated
    users.
    """
    try:
        result = subprocess.run(
            [
                BASH, "/opt/vpn-panel/scripts/setup_openconnect.sh",
                f"--port={port}", f"--dns1={dns1}", f"--dns2={dns2}", "--force", "--configure-only",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
        return True, (result.stdout or "")[-3000:]
    except subprocess.CalledProcessError as exc:
        log = (exc.stdout or "") + "\n" + (exc.stderr or "")
        return False, log[-3000:]
    except subprocess.TimeoutExpired:
        return False, "اجرای اسکریپت OpenConnect بیش از حد طول کشید"


def apply_vpn_protocol_settings(
    l2tp_enabled: bool,
    l2tp_port: int,
    pptp_enabled: bool,
    openvpn_enabled: bool,
    openvpn_udp_port: int,
    openvpn_tcp_port: int,
    vpn_domain: str = "",
    l2tp_mtu: int = 1400,
    l2tp_mru: int = 1400,
    sstp_enabled: bool = True,
    sstp_port: int = 4433,
    ikev2_enabled: bool = True,
    openconnect_port: int = 8443,
    openconnect_dns1: str = "8.8.8.8",
    openconnect_dns2: str = "1.1.1.1",
    openvpn_dns1: str = "1.1.1.1",
    openvpn_dns2: str = "8.8.8.8",
    target: str = "all",
) -> tuple[bool, str]:
    """اجرای configure_vpn_protocols.sh برای اعمال پورت/وضعیت/DNS روی
    سرویس‌های واقعی و همگام‌کردن قوانین INPUT همان پروتکل در فایروال میزبان.
    آرگومان ``target`` اجازه می‌دهد ویرایش یک کارت فقط همان backend را لمس
    کند؛ مسیر قدیمی/نصب کامل با ``all`` همه‌ی پروتکل‌ها را بازاعمال می‌کند.

    OpenVPN همیشه با دو پروسه‌ی هم‌زمان اجرا می‌شود (UDP و TCP)؛ openvpn_enabled
    هر دو را با هم روشن/خاموش می‌کند، هرکدام پورت جدای خودشان را دارند.

    vpn_domain (اختیاری): دامنه‌ی اختصاصیِ خودِ پروتکل‌ها (جدا از دامنه‌ی پنل) —
    اگر ست باشد، در فایل نمونه‌ی client.ovpn به‌جای آی‌پی سرور استفاده می‌شود.

    l2tp_mtu/l2tp_mru: مقادیر MTU/MRU که برای pppd روی تونل L2TP (فقط L2TP،
    نه PPTP/OpenVPN) در /etc/ppp/options.xl2tpd نوشته می‌شود.

    openconnect_port: برخلاف بقیه‌ی پروتکل‌ها (که همه از داخل configure_vpn_
    protocols.sh مدیریت می‌شوند)، OpenConnect زیرساخت کاملاً جدای خودش
    (setup_openconnect.sh/ocserv) را دارد - برای همین جدا و بعد از آن
    اسکریپت صدا زده می‌شود. --force یعنی همیشه (حتی اگر پورت عوض نشده باشد)
    اعمال/بررسی شود، دقیقاً مثل بقیه‌ی پروتکل‌ها که هر «ذخیره» از پنل انجامش
    می‌دهند؛ خودِ اسکریپت هم فقط وقتی واقعاً سرویس را ری‌استارت می‌کند که
    پورت عوض شده، گواهی تازه ساخته شده، یا سرویس از قبل پایین بوده باشد.

    اگر سرویس ocserv واقعاً روی پورت جدید بالا نیاید (مثلاً پورت توسط یک
    سرویس دیگر اشغال شده)، خودِ setup_openconnect.sh این را چک می‌کند
    (systemctl is-active + گوش‌دادن واقعی روی پورت)، به پیکربندی/پورتِ قبلی
    که قبلاً درست کار می‌کرد برمی‌گردد و با کد خروجی غیرصفر خارج می‌شود -
    این‌جا همان CalledProcessError را می‌گیرد و (ok=False, log) برمی‌گرداند؛
    روتر /vpn-protocols (routers/settings.py) با دیدن ok=False اصلاً
    openconnect_port جدید را در دیتابیس ذخیره نمی‌کند، پس هم روی سرور هم در
    پنل، پورت قبلیِ فعال دست‌نخورده می‌ماند و ادمین پیام خطای واضح می‌بیند."""
    # Saving an enabled protocol is an explicit request to run it again. Clear
    # any marker left by the separate manual Stop button before applying the
    # authoritative configuration; failed starts are then eligible for the
    # periodic ingress watchdog instead of remaining skipped forever.
    marker_keys: list[str] = []
    if target in {"all", "l2tp"} and l2tp_enabled:
        marker_keys.append("l2tp")
    if target in {"all", "l2tp", "ipsec", "ikev2"} and (l2tp_enabled or ikev2_enabled):
        marker_keys.append("ipsec")
    if target in {"all", "openvpn"} and openvpn_enabled:
        marker_keys.extend(("openvpn_udp", "openvpn_tcp"))
    for marker_key in marker_keys:
        try:
            os.unlink(os.path.join(MANUAL_PROTOCOL_STOP_DIR, marker_key))
        except FileNotFoundError:
            pass
        except OSError:
            logger.warning("could not clear manual protocol stop marker: %s", marker_key)

    try:
        result = subprocess.run(
            [
                BASH, "/opt/vpn-panel/scripts/configure_vpn_protocols.sh",
                "1" if l2tp_enabled else "0", str(l2tp_port),
                "1" if pptp_enabled else "0",
                "1" if openvpn_enabled else "0",
                str(openvpn_udp_port), str(openvpn_tcp_port),
                vpn_domain or "",
                str(l2tp_mtu), str(l2tp_mru),
                "1" if sstp_enabled else "0", str(sstp_port),
                "1" if ikev2_enabled else "0",
                openvpn_dns1, openvpn_dns2,
                target,
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
        ok, log = True, result.stdout[-3000:]
    except subprocess.CalledProcessError as e:
        log = (e.stdout or "") + "\n" + (e.stderr or "")
        return False, log[-3000:]
    except subprocess.TimeoutExpired:
        return False, "اجرای اسکریپت بیش از حد طول کشید"

    if target == "all":
        oc_ok, oc_log = apply_openconnect_settings(
            openconnect_port, openconnect_dns1, openconnect_dns2
        )
        if not oc_ok:
            return False, (log + "\n" + oc_log)[-5000:]
        log += "\n" + oc_log[-2000:]

    return ok, log


def sync_openvpn_extra_ports(
    extra_ports: list[tuple[int, str]], primary_udp_port: int, primary_tcp_port: int
) -> tuple[bool, str]:
    """اجرای اسکریپت manage_openvpn_extra_ports.sh: هر بار کل لیست فعلی پورت‌های
    اضافه‌ی OpenVPN (از دیتابیس) را می‌فرستد؛ اسکریپت لیسنرهای قبلی خودش را
    پاک و لیست تازه را از نو می‌سازد (idempotent). هر پورت اضافه یک پردازش
    OpenVPN واقعی و مستقل است (نه فوروارد فایروال) - کاملاً از داخل پنل
    کنترل می‌شود و می‌توان برای هر پروتکل (tcp/udp) هرچند پورت که خواستی
    اضافه کرد. این تابع/اسکریپت NAT مسیر ترافیک را می‌زند و همچنین به‌صورت
    خودکار پورت را روی فایروال خودِ سرور (ufw/firewalld/iptables، هرکدام که
    روی سرور فعال باشد) هم باز می‌کند - فقط برای پورت‌هایی که لیسنرشان واقعاً
    بالا آمده. تنها استثنا: اگر سرور پشت فایروال ابری (Security Group در
    AWS/GCP/Hetzner/DigitalOcean و مشابه) باشد، آن یک شیء کنترل‌پلین جدا از
    خودِ ماشین است و اسکریپت روی سرور اصلاً بهش دسترسی ندارد - بازکردنش همچنان
    دستی و روی پنل همان سرویس ابری است.
    primary_udp_port/primary_tcp_port دیگر لازم نیست به اسکریپت پاس داده
    شوند (سابقاً برای DNAT لازم بودند)، اما پارامتر امضای تابع برای سازگاری
    با فراخوانی‌های موجود در روتر نگه داشته شده و استفاده نمی‌شود."""
    ports_arg = ",".join(f"{p}/{proto}" for p, proto in extra_ports)
    try:
        result = subprocess.run(
            [
                BASH, "/opt/vpn-panel/scripts/manage_openvpn_extra_ports.sh",
                ports_arg,
            ],
            capture_output=True, text=True, timeout=45, check=True,
        )
        return True, result.stdout[-2000:]
    except subprocess.CalledProcessError as e:
        log = (e.stdout or "") + "\n" + (e.stderr or "")
        return False, log[-2000:]
    except subprocess.TimeoutExpired:
        return False, "اجرای اسکریپت هم‌گام‌سازی پورت‌های اضافه بیش از حد طول کشید"


# ---------------------------------------------------------------------------
# وضعیت لحظه‌ای و کنترل جدا-جدای هر سرویس زیرساخت پروتکل‌ها (صفحه‌ی «پروتکل‌ها»)
#
# هر پروتکل ممکن است روی یک یا چند واحد systemd سوار باشد:
#   - L2TP        -> xl2tpd
#   - IPsec       -> strongswan-starter (یا strongswan/ipsec، بسته به توزیع)
#   - PPTP        -> pptpd
#   - OpenVPN UDP -> openvpn-server@server-udp (یا openvpn@server-udp)
#   - OpenVPN TCP -> openvpn-server@server-tcp (یا openvpn@server-tcp)
#
# این پنج مورد کاملاً مستقل از هم روشن/خاموش/ری‌استارت می‌شوند - مثلاً می‌توان
# IPsec را نگه داشت ولی فقط xl2tpd را ری‌استارت کرد، یا فقط OpenVPN-TCP را
# بدون لمس OpenVPN-UDP خاموش کرد.
# ---------------------------------------------------------------------------

PROTOCOL_LABELS = {
    "l2tp": "L2TP",
    "ipsec": "IPsec (strongSwan)",
    "pptp": "PPTP",
    "openvpn_udp": "OpenVPN (UDP)",
    "openvpn_tcp": "OpenVPN (TCP)",
    "sstp": "SSTP",
    "openconnect": "OpenConnect (ocserv)",
}

ALLOWED_PROTOCOL_KEYS = set(PROTOCOL_LABELS)
ALLOWED_ACTIONS = {"start", "stop", "restart"}


def _openvpn_unit_prefix() -> str:
    try:
        out = subprocess.run(
            [SYSTEMCTL, "list-unit-files"], capture_output=True, text=True, timeout=10, check=False
        ).stdout or ""
    except Exception:
        out = ""
    if "openvpn@" in out and "openvpn-server@" not in out:
        return "openvpn@"
    return "openvpn-server@"


def _pick_existing_unit(candidates: list[str]) -> str:
    try:
        out = subprocess.run(
            [SYSTEMCTL, "list-unit-files"], capture_output=True, text=True, timeout=10, check=False
        ).stdout or ""
    except Exception:
        out = ""
    for c in candidates:
        if c in out:
            return c
    return candidates[0]


def _protocol_units() -> dict[str, str]:
    prefix = _openvpn_unit_prefix()
    return {
        "l2tp": "xl2tpd",
        "ipsec": _pick_existing_unit(["strongswan-starter", "strongswan", "ipsec"]),
        "pptp": "pptpd",
        "openvpn_udp": f"{prefix}server-udp",
        "openvpn_tcp": f"{prefix}server-tcp",
        # ساخته‌شده توسط install/setup_sstp.sh (سرویس accel-ppp با ماژول SSTP)
        "sstp": "accel-ppp-sstp",
        # ساخته‌شده توسط install/setup_openconnect.sh - برخلاف بقیه، اسم سرویس
        # همیشه ثابت "ocserv" است (بدون prefix/instance).
        "openconnect": "ocserv",
    }


def _service_state(unit: str) -> str:
    """خروجی systemctl is-active: active / inactive / failed / activating / ...
    اگر واحدی روی سیستم اصلاً نصب نباشد هم معمولاً 'inactive' برمی‌گردد."""
    try:
        r = subprocess.run(
            [SYSTEMCTL, "is-active", unit], capture_output=True, text=True, timeout=10, check=False
        )
        return (r.stdout or "").strip() or "unknown"
    except Exception:
        return "unknown"


def _service_state_any_prefix(instance_name: str) -> str:
    """مثل _service_state، ولی به‌جای اعتماد به یک حدسِ سراسریِ prefix
    (_openvpn_unit_prefix - که فقط یک‌بار بر اساس این‌که کدام تمپلیت systemd
    روی کل سرور *نصب* است تصمیم می‌گیرد)، هر دو تمپلیت ممکن (openvpn-server@
    و openvpn@) را برای همین instance مشخص چک می‌کند و هرکدام که واقعاً
    active بود را برمی‌گرداند.

    چرا لازم است: اگر سروری هر دو تمپلیت را نصب داشته باشد، یک پورت اضافه
    که قبلاً (مثلاً توسط نسخه‌ی خیلی قدیمی‌تر همین اسکریپت) زیر یکی از این
    دو تمپلیت ساخته و enable شده، ممکن است زیر تمپلیت دیگری - همانی که
    حدسِ سراسری این‌بار انتخاب می‌کند - اصلاً وجود نداشته باشد. حدس سراسری
    آن را غلط «inactive» گزارش می‌کرد، در حالی‌که واقعاً و سالم در حال
    اجراست؛ دقیقاً همین باعث می‌شد reconcile هر ۳۰ ثانیه (scheduler)
    پورت‌های کاملاً سالم را در دیتابیس is_active=False کند - بدون این‌که
    ادمین هیچ کاری کرده باشد."""
    for prefix in ("openvpn-server@", "openvpn@"):
        if _service_state(f"{prefix}{instance_name}") == "active":
            return "active"
    return "inactive"


def get_protocol_statuses() -> list[dict]:
    """وضعیت لحظه‌ای هر یک از پنج سرویس، برای نمایش جدا-جدا در صفحه‌ی پروتکل‌ها."""
    units = _protocol_units()
    return [
        {"key": key, "label": PROTOCOL_LABELS[key], "unit": unit, "state": _service_state(unit)}
        for key, unit in units.items()
    ]


def control_protocol_service(key: str, action: str) -> tuple[bool, str]:
    """اجرای start/stop/restart روی دقیقاً همان سرویسی که کاربر از پنل انتخاب
    کرده، بدون اثر روی سرویس‌های دیگر."""
    if key not in ALLOWED_PROTOCOL_KEYS:
        return False, "کلید پروتکل نامعتبر است"
    if action not in ALLOWED_ACTIONS:
        return False, "عملیات نامعتبر است"

    unit = _protocol_units()[key]
    marker = os.path.join(MANUAL_PROTOCOL_STOP_DIR, key)
    try:
        os.makedirs(MANUAL_PROTOCOL_STOP_DIR, mode=0o755, exist_ok=True)
        if action == "stop":
            with open(marker, "w", encoding="utf-8") as handle:
                handle.write(datetime.utcnow().isoformat() + "Z\n")
        else:
            try:
                os.unlink(marker)
            except FileNotFoundError:
                pass
        r = subprocess.run(
            [SYSTEMCTL, action, unit], capture_output=True, text=True, timeout=30, check=True
        )
        return True, r.stdout[-1000:]
    except subprocess.CalledProcessError as e:
        log = (e.stdout or "") + "\n" + (e.stderr or "")
        return False, log[-1000:]
    except subprocess.TimeoutExpired:
        return False, "اجرای دستور بیش از حد طول کشید"


def stop_all_protocol_services() -> None:
    """خاموش کردن قطعی هر پنج سرویس پروتکل (l2tp/ipsec/pptp/openvpn udp+tcp/
    sstp)، صرف‌نظر از این‌که در Settings > پروتکل‌ها فعال بودند یا نه. فقط
    برای قفل شدن پنل بابت انقضای لایسنس استفاده می‌شود (license_manager.py) -
    یعنی کاربران نهایی هم دیگر واقعاً نمی‌توانند وصل شوند، نه فقط پنل تحت وب
    غیرقابل استفاده می‌شود. تنظیمات ذخیره‌شده (کدام پروتکل باید فعال باشد)
    دست‌نخورده می‌ماند تا وقتی لایسنس دوباره معتبر شد با
    apply_current_protocol_settings به همان حالت قبلی برگردد."""
    for unit in _protocol_units().values():
        try:
            subprocess.run([SYSTEMCTL, "stop", unit], capture_output=True, text=True, timeout=20, check=False)
        except Exception:
            logger.exception("خطا هنگام stop سرویس %s بابت قفل لایسنس", unit)


def apply_current_protocol_settings(db: Session) -> tuple[bool, str]:
    """همان چیزی که settings.py._reapply_protocols_with_current_domain انجام
    می‌دهد اما به‌صورت عمومی، برای استفاده از جاهای دیگر (مثلاً بعد از
    رفع قفل لایسنس در license_manager.py) بدون وابستگی چرخه‌ای به روتر."""
    from app.models import Setting  # local import عمدی، مثل reconcile_protocol_services

    def get_setting(key: str):
        row = db.query(Setting).filter(Setting.key == key).first()
        return row.value if row else None

    def bool_setting(key: str, default: bool) -> bool:
        v = get_setting(key)
        return (v == "1") if v is not None else default

    def int_setting(key: str, default: int) -> int:
        v = get_setting(key)
        return int(v) if v is not None else default

    def text_setting(key: str, default: str, preserve_blank: bool = False) -> str:
        v = get_setting(key)
        if v is None or (v == "" and not preserve_blank):
            return default
        return v

    return apply_vpn_protocol_settings(
        bool_setting("l2tp_enabled", True), int_setting("l2tp_port", 1701),
        bool_setting("pptp_enabled", True),
        bool_setting("openvpn_enabled", True),
        int_setting("openvpn_udp_port", 1194), int_setting("openvpn_tcp_port", 1194),
        get_setting("vpn_domain") or "",
        int_setting("l2tp_mtu", 1400), int_setting("l2tp_mru", 1400),
        bool_setting("sstp_enabled", True), int_setting("sstp_port", 4433),
        bool_setting("ikev2_enabled", True),
        int_setting("openconnect_port", 8443),
        text_setting("openconnect_dns1", "8.8.8.8"),
        text_setting("openconnect_dns2", "1.1.1.1", True),
        text_setting("openvpn_dns1", "1.1.1.1"),
        text_setting("openvpn_dns2", "8.8.8.8", True),
    )


def repair_vpn_ingress() -> tuple[bool, str]:
    """Repair listeners and host INPUT rules for OpenVPN and L2TP/IPsec.

    Authentication self-healing is not enough when packets never reach the
    daemons.  The helper respects explicit manual-stop markers created by
    ``control_protocol_service`` and therefore does not undo admin intent.
    """
    script = "/opt/vpn-panel/scripts/repair_vpn_ingress.sh"
    if not os.path.isfile(script):
        return False, "repair_vpn_ingress.sh is missing"
    try:
        result = subprocess.run(
            [BASH, script], capture_output=True, text=True, timeout=55, check=False
        )
        output = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()[-5000:]
        return result.returncode == 0, output
    except subprocess.TimeoutExpired as exc:
        output = ((exc.stdout or "") + "\n" + (exc.stderr or "")).strip()[-5000:]
        return False, (output + "\ningress repair timed out").strip()
    except Exception as exc:
        return False, str(exc)


def reconcile_protocol_services(db: Session) -> list[str]:
    """اجرای دوره‌ای (از scheduler.py): وضعیت واقعیِ هر سرویس پروتکل را با آن
    چیزی که ادمین در Settings > پروتکل‌ها ذخیره کرده مقایسه می‌کند و اگر
    سرویسی که باید روشن باشد، روشن نیست (inactive/failed)، خودش را دوباره
    روشن می‌کند - بدون این‌که ادمین لازم باشد به پنل برگردد و «ذخیره» بزند.

    چرا اصلاً لازم است: هر Restart=on-failure در systemd هم یک محدودیت
    پیش‌فرض دارد (۵ بار شکست در ۱۰ ثانیه => دیگر هیچ‌وقت خودکار تلاش نمی‌کند
    و برای همیشه «failed» می‌ماند)؛ install/setup_sstp.sh این محدودیت را
    برای accel-ppp-sstp غیرفعال کرده (نگاه کنید به StartLimitIntervalSec=0)
    اما این خودش تضمین نمی‌کند سرویس هرگز کرش نکند - فقط یعنی تلاش دوباره
    متوقف نمی‌شود. این تابع همان «تلاش دوباره» را از سمت پنل هم تضمین
    می‌کند، مستقل از رفتار خودِ systemd. عمداً فقط روی SSTP اعمال می‌شود -
    دلیلش پایین‌تر توضیح داده شده.

    علاوه بر روشن‌کردن سرویس، اگر accel-ppp-sstp پایین باشد، هر رکورد SSTP
    که در دیتابیس هنوز «آنلاین» مانده را هم آفلاین می‌کند: برخلاف pppd (که
    برای L2TP/PPTP یک پردازش زنده و قابل‌چک‌کردن به‌ازای هر سشن است)،
    accel-ppp یک پردازش واحد است - اگر خودِ آن پردازش پایین بیاید، دیگر هیچ
    رویداد ip-down ای (sstp_ip_down.sh) برای سشن‌های بازِ آن هرگز نمی‌رسد و
    بدون این پاک‌سازی، آن رکوردها برای همیشه به‌عنوان «آنلاین» در پنل
    می‌ماندند.

    خروجی: لیست کلیدهای پروتکلی که همین بار روشن/ترمیم شدند (برای لاگ)."""

    # مستقیماً از جدول Setting می‌خوانیم (بدون وابستگی به routers/settings.py
    # تا این ماژول با آن import چرخه‌ای نسازد).
    from app.models import Setting  # local import عمدی

    def get_setting(key: str):
        row = db.query(Setting).filter(Setting.key == key).first()
        return row.value if row else None

    def bool_setting(key: str, default: bool) -> bool:
        v = get_setting(key)
        return (v == "1") if v is not None else default

    # عمداً فقط SSTP اینجا خودکار ترمیم می‌شود، نه هر پنج سرویس: صفحه‌ی
    # Protocols (کارت‌های جدا-جدا) یک دکمه‌ی «خاموش کردن» دستی هم دارد که
    # مستقیماً systemctl stop می‌زند بدون این‌که l2tp_enabled/pptp_enabled/
    # openvpn_enabled در جدول Setting را تغییر دهد (نگاه کنید به
    # control_protocol_service بالا). اگر این تابع همه‌ی پروتکل‌ها را چک
    # می‌کرد، همان خاموش‌کردن دستی و عمدی‌ی ادمین را ۳۰ ثانیه بعد دوباره
    # روشن می‌کرد - رفتاری کاملاً غیرمنتظره. SSTP/accel-ppp تنها سرویسی است
    # که واقعاً سابقه‌ی کرش غیرمنتظره (بدون دخالت ادمین) داشته، پس محدودکردن
    # ترمیم خودکار به همین یکی، هم مشکل گزارش‌شده را حل می‌کند و هم چیزی را
    # خراب نمی‌کند.
    units = _protocol_units()
    healed: list[str] = []

    sstp_unit = units.get("sstp")
    if sstp_unit and bool_setting("sstp_enabled", True):
        state = _service_state(sstp_unit)
        if state not in ("active", "activating", "reloading"):
            # سرویس باید روشن باشد ولی نیست (inactive/failed/unknown) -> تلاش
            # برای روشن‌کردن. ابتدا reset-failed تا اگر systemd سرویس را
            # «failed» نگه داشته پاک شود؛ سپس start (نه restart - همین الان
            # روشن نیست، پس start کافی و کم‌اثرتر است).
            subprocess.run([SYSTEMCTL, "reset-failed", sstp_unit], capture_output=True, text=True, timeout=10, check=False)
            r = subprocess.run([SYSTEMCTL, "start", sstp_unit], capture_output=True, text=True, timeout=30, check=False)
            if r.returncode == 0:
                healed.append("sstp")

    # اگر سرویس SSTP همین الان (بعد از تلاش بالا هم) پایین است، سشن‌های
    # «یتیم» SSTP را آفلاین کن - دلیل کامل در docstring بالا. این بخش
    # مستقل از sstp_enabled است: حتی اگر ادمین دستی SSTP را خاموش کرده،
    # رکوردهای آنلاینِ باقی‌مانده باید بسته شوند.
    if sstp_unit and _service_state(sstp_unit) not in ("active", "activating", "reloading"):
        orphaned = (
            db.query(ConnectionLog)
            .filter(ConnectionLog.protocol == "sstp", ConnectionLog.is_online == True)  # noqa: E712
            .all()
        )
        if orphaned:
            sample_ppp_traffic(db)
            for s in orphaned:
                s.is_online = False
                s.disconnect_time = datetime.utcnow()
            db.commit()

    return healed


def reconcile_openvpn_extra_ports(db: Session) -> list[str]:
    """Self-heal active OpenVPN extra ports without changing admin intent.

    A short API/update restart can make the systemd instances appear inactive
    for a few seconds. Older releases immediately wrote ``is_active=False`` to
    the database in that transient window, so a normal panel update looked as
    if it had switched ports off. The database flag is a user setting and must
    only change after an explicit add/toggle/delete request.

    This reconciler now rebuilds every listener that is still marked active,
    checks the runtime a second time, and returns only the ports that remain
    unhealthy for logging. It never mutates ``OpenvpnExtraPort.is_active``.
    """
    from app.models import OpenvpnExtraPort

    # A controller-only installation has no local OpenVPN daemon to repair.
    # Running the listener watchdog there only creates false failures and a
    # permanent Telegram alert loop. Likewise, skip while OpenVPN is disabled
    # or its base server configs are not installed yet.
    if _db_setting(db, "local_services_mode", 1) == 0:
        return []
    if _db_setting(db, "openvpn_enabled", 1) == 0:
        return []
    if not (
        os.path.exists("/etc/openvpn/server/server-udp.conf")
        or os.path.exists("/etc/openvpn/server/server-tcp.conf")
    ):
        return []

    rows = (
        db.query(OpenvpnExtraPort)
        .filter(OpenvpnExtraPort.is_active == True)  # noqa: E712
        .order_by(OpenvpnExtraPort.port, OpenvpnExtraPort.protocol)
        .all()
    )
    if not rows:
        return []

    # Old builds allowed the primary OpenVPN port to remain in the extra-port
    # table. Such a row can never own a second listener on the same transport;
    # every watchdog pass therefore tried to bind an already-used port and
    # reported it as broken forever. Normalize those legacy rows once. The
    # primary listener already provides the exact same remote, so disabling the
    # redundant pool row does not remove connectivity from client profiles.
    primary_udp = _db_setting(db, "openvpn_udp_port", 1194)
    primary_tcp = _db_setting(db, "openvpn_tcp_port", 1194)
    valid_rows = []
    normalized = False
    for row in rows:
        is_primary_duplicate = (
            (str(row.protocol) == "udp" and int(row.port) == primary_udp)
            or (str(row.protocol) == "tcp" and int(row.port) == primary_tcp)
        )
        if is_primary_duplicate:
            row.is_active = False
            normalized = True
        else:
            valid_rows.append(row)
    if normalized:
        db.commit()
    rows = valid_rows
    if not rows:
        return []

    def unhealthy() -> list[OpenvpnExtraPort]:
        return [
            row for row in rows
            if _service_state_any_prefix(f"server-extra-{row.protocol}-{row.port}") != "active"
        ]

    missing = unhealthy()
    if not missing:
        return []

    # Rebuild from the authoritative active rows. The helper is idempotent and
    # waits for each listener, so the second runtime check is meaningful.
    sync_openvpn_extra_ports(
        [(int(row.port), str(row.protocol)) for row in rows],
        primary_udp,
        primary_tcp,
    )

    return [f"{row.port}/{row.protocol.upper()}" for row in unhealthy()]


def check_vpn_domain(domain: str) -> tuple[bool, str]:
    """بررسی این‌که رکورد A دامنه‌ی اختصاصی پروتکل‌ها واقعاً به آی‌پی همین سرور
    اشاره می‌کند (بدون درخواست SSL — پروتکل‌های VPN نیازی به گواهی ندارند)."""
    try:
        result = subprocess.run(
            [BASH, "/opt/vpn-panel/scripts/check_vpn_domain.sh", domain],
            capture_output=True,
            text=True,
            timeout=30,
            check=True,
        )
        return True, result.stdout[-2000:]
    except subprocess.CalledProcessError as e:
        log = (e.stdout or "") + "\n" + (e.stderr or "")
        return False, log[-2000:]
    except subprocess.TimeoutExpired:
        return False, "بررسی DNS بیش از حد طول کشید"


def build_client_ovpn(
    username: str, server_address: str, udp_port: int, tcp_port: int,
    cert_pem: str | None = None, key_pem: str | None = None,
    extra_ports: list[tuple[int, str]] | None = None,
    auth_mode: str = "cert_only", password: str | None = None,
    additional_remotes: list[tuple[str, int, str]] | None = None,
    profile_name: str | None = None,
) -> str:
    """ساخت متن فایل client.ovpn برای یک کاربر مشخص، با آدرس/پورت‌های فعلی و
    (در صورت داده شدن) سرتیفیکیت اختصاصی همان کاربر. مثل بخش نظیر در
    configure_vpn_protocols.sh، اما این نسخه از داخل بک‌اند (بدون نیاز به
    اجرای اسکریپت) و برای دانلود تکی هر کاربر استفاده می‌شود.

    چون سرور همیشه هم‌زمان روی UDP و TCP گوش می‌دهد، کانفیگ کاربر remoteها را
    دقیقاً به ترتیب اولویت تولید می‌کند: ابتدا پورت‌های اصلی همه‌ی سرورها، سپس
    پورت‌های اضافه. گزینه‌ی remote-random عمداً وجود ندارد؛ بنابراین کلاینت از
    اولین remote شروع می‌کند و فقط در صورت شکست به خط بعدی می‌رود.

    extra_ports: لیست پورت‌های اضافه (Settings > پورت‌های OpenVPN)، هرکدام به
    شکل (port, "tcp"/"udp") - این پورت‌ها هم با iptables (DNAT) به پورت اصلی
    همان پروتکل هدایت می‌شوند و همیشه فعال‌اند (چون هر دو پروتکل هم‌زمان زنده‌اند).

    auth_mode/password: نحوه‌ی احراز هویت OpenVPN این کاربر (به‌همراه سرتیفیکیت):
      - "cert_only": یوزرنیم/پسورد همین کاربر به‌صورت نامرئی داخل فایل جاسازی
        می‌شود (بلوک <auth-user-pass>) تا کلاینت هیچ پرسشی از کاربر نکند، اما
        سرور (openvpn_auth.sh -> auth-user-pass-verify) همچنان چک می‌کند که
        این یوزرنیم دقیقاً با Common Name همین سرتیفیکیت یکی باشد.
      - "cert_password": فقط دستور خامِ `auth-user-pass` (بدون فایل/بلوک) اضافه
        می‌شود؛ کلاینت هنگام اتصال از کاربر یوزرنیم/پسورد می‌پرسد."""
    ca_path = settings.OPENVPN_CA_PATH
    ta_path = settings.OPENVPN_TA_PATH
    if not os.path.exists(ca_path) or not os.path.exists(ta_path):
        raise FileNotFoundError("گواهی‌های OpenVPN روی سرور پیدا نشد (هنوز نصب نشده؟)")

    with open(ca_path) as f:
        ca_content = f.read()
    with open(ta_path) as f:
        ta_content = f.read()

    def _client_proto(value: str) -> str:
        return "tcp-client" if str(value or "").lower().startswith("tcp") else "udp"

    def _normalized_remote(host, port, proto):
        host = str(host or "").strip()
        if not host or any(char in host for char in "\r\n\t \x00"):
            return None
        try:
            port = int(port)
        except (TypeError, ValueError):
            return None
        if not 1 <= port <= 65535:
            return None
        normalized_proto = "tcp" if str(proto or "").lower().startswith("tcp") else "udp"
        return host, port, normalized_proto

    # Build the remote list once and deduplicate the exact host/port/transport
    # triplet. Both the all-server profile and each per-node profile pass their
    # authoritative listener list in ``additional_remotes``; the two base
    # entries remain for backward compatibility with direct callers.
    if additional_remotes:
        # The controller/node snapshot is authoritative. Do not manufacture a
        # TCP or UDP listener by reusing the other protocol's port when a server
        # intentionally exposes only one transport.
        candidates = list(additional_remotes)
    else:
        candidates = [
            (server_address, udp_port, "udp"),
            (server_address, tcp_port, "tcp"),
        ]
        candidates.extend((server_address, port, proto) for port, proto in (extra_ports or []))

    remote_lines: list[str] = []
    seen_remotes: set[tuple[str, int, str]] = set()
    for raw in candidates:
        if not isinstance(raw, (tuple, list)) or len(raw) != 3:
            continue
        item = _normalized_remote(raw[0], raw[1], raw[2])
        if item is None or item in seen_remotes:
            continue
        seen_remotes.add(item)
        host, port, proto = item
        remote_lines.append(f"remote {host} {port} {_client_proto(proto)}")
    if not remote_lines:
        raise ValueError("هیچ آدرس و پورت معتبر OpenVPN برای ساخت فایل پیدا نشد")
    remotes_block = "\n".join(remote_lines)

    # هر کاربر همیشه سرتیفیکیت اختصاصی خودش را لازم دارد؛ اگر هنوز ساخته نشده
    # باشد (حالت غیرمنتظره - همیشه قبل از این تابع ساخته می‌شود) خطای واضح می‌دهیم.
    if not cert_pem or not key_pem:
        raise FileNotFoundError(f"سرتیفیکیت اختصاصی کاربر {username} پیدا نشد")

    cert_block = f"""<cert>
{cert_pem}
</cert>

<key>
{key_pem}
</key>

"""

    # Inline auth is a two-line virtual file. Newline/NUL characters would turn
    # a database value into extra OpenVPN directives or a malformed credential
    # file, so reject them explicitly instead of producing a plausible but
    # unusable profile.
    username = str(username or "")
    password = "" if password is None else str(password)
    if not username or any(char in username for char in "\r\n\x00"):
        raise ValueError("نام کاربری OpenVPN برای قرارگرفتن داخل فایل معتبر نیست")
    if any(char in password for char in "\r\n\x00"):
        raise ValueError("رمز کاربر OpenVPN نباید شامل خط جدید یا کاراکتر NUL باشد")

    # سرور همیشه (صرف‌نظر از حالت این کاربر) یک auth-user-pass-verify دارد که
    # چک می‌کند یوزرنیمِ ارسالی دقیقاً با Common Name همین سرتیفیکیت یکی باشد؛
    # پس در هر دو حالت زیر باید یک یوزر/پس معتبر برای همین کاربر فرستاده شود.
    if auth_mode == "cert_password":
        # فقط دستور خام - کلاینت خودش موقع اتصال باکس یوزرنیم/پسورد نشان می‌دهد.
        auth_block = "auth-user-pass\n"
    else:
        # cert_only: یوزر/پس همین کاربر به‌صورت نامرئی داخل خودِ فایل جاسازی
        # می‌شود؛ کلاینت هیچ پرسشی نمی‌کند و اتصال فقط با داشتن همین فایل برقرار می‌شود.
        auth_block = f"""<auth-user-pass>
{username}
{password or ""}
</auth-user-pass>
"""

    requested_profile_name = str(profile_name or username).strip()
    if not requested_profile_name or any(char in requested_profile_name for char in "\r\n\x00"):
        raise ValueError("نام پروفایل OpenVPN معتبر نیست")
    # Keep the OpenVPN profile free of explanatory comments. This single
    # Access Server-compatible metadata line is intentionally retained so
    # clients that understand it use the requested friendly name rather than
    # deriving the title from the first remote hostname.
    friendly_profile_name = re.sub(r"[<>:\"/\\|?*]+", "-", requested_profile_name).strip(" .-")[:100]
    if not friendly_profile_name:
        raise ValueError("نام پروفایل OpenVPN پس از پاک‌سازی خالی شد")

    return f"""# OVPN_ACCESS_SERVER_FRIENDLY_NAME={friendly_profile_name}
client
dev tun
{remotes_block}
connect-retry 1 3
connect-retry-max 1
server-poll-timeout 3
connect-timeout 3
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
ncp-ciphers AES-256-GCM:AES-128-GCM
{cert_block}{auth_block}
cipher AES-256-GCM
auth SHA256
verb 3

<ca>
{ca_content}
</ca>

<tls-auth>
{ta_content}
</tls-auth>
key-direction 1
"""
