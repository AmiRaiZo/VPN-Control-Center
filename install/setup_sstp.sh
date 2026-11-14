#!/bin/bash
###############################################################################
# SSTP infrastructure setup (standalone, isolated from the rest of the panel)
#
# این اسکریپت فقط «زیرساخت» SSTP را روی سرور بالا می‌آورد؛ به بک‌اند/فرانت‌اند
# پنل و به مدیریت کاربران دست نمی‌زند. به‌صورت خودکار از داخل install.sh و
# update.sh هم صدا زده می‌شود (idempotent است، پس اجرای مجدد از هر جا مشکلی
# ندارد)؛ برای نصب/تلاش مجدد دستی هم می‌توانید مستقیماً همین فایل را اجرا
# کنید. بعد از اجرا، کاربران را همچنان باید دستی (یا با اسکریپت‌های همین
# فایل) به /etc/ppp/chap-secrets اضافه کنید تا بتوانند با SSTP وصل شوند -
# پنل خودش این فایل را برای هر کاربر مدیریت می‌کند.
#
# چرا accel-ppp؟ روی نسخه‌های جدید اوبونتو (20.04+) پکیج آماده‌ی sstpd دیگر در
# ریپازیتوری رسمی نیست، بنابراین از accel-ppp (که SSTP را پشتیبانی می‌کند) از
# سورس کامپایل می‌شود.
#
# این اسکریپت idempotent است: install.sh و update.sh هر دو آن را در هر اجرا
# صدا می‌زنند. اگر زیرساخت از قبل ساخته شده باشد (باینری + سرویس systemd)،
# کامپایل دوباره (که چند دقیقه طول می‌کشد) انجام نمی‌شود - فقط مطمئن می‌شویم
# سرویس روشن است. برای اجبار به نصب/کامپایل مجدد از صفر: sudo bash setup_sstp.sh --force
#
# Usage:
#   sudo bash setup_sstp.sh [--force]
###############################################################################
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -r "$SCRIPT_DIR/apt_preflight.sh" ]; then
  # shellcheck source=apt_preflight.sh
  source "$SCRIPT_DIR/apt_preflight.sh"
fi

if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root (sudo bash setup_sstp.sh)"
  exit 1
fi

FORCE=0
SSTP_SUBNET="192.168.45"
SSTP_PORT="4433"   # پیش‌فرض روی 4433؛ چون پورت 443 برای HTTPS پنل/nginx لازمه و SSTP نباید باهاش تداخل کنه
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=1 ;;
    --port=*) SSTP_PORT="${arg#--port=}" ;;
  esac
done
if ! [[ "$SSTP_PORT" =~ ^[0-9]+$ ]] || [ "$SSTP_PORT" -lt 1 ] || [ "$SSTP_PORT" -gt 65535 ]; then
  echo "Invalid --port value: $SSTP_PORT" >&2
  exit 1
fi

# setup_sstp used to start accel-ppp before install.sh copied the SSTP hooks to
# /opt/vpn-panel/scripts.  That produced a live daemon with missing ip-up/down
# programs.  Install only the SSTP-related hooks here before any restart.
install_sstp_hooks() {
  local source_dir="" candidate hook
  for candidate in \
    "$SCRIPT_DIR/../backend/app/scripts" \
    "/opt/vpn-panel/backend/app/scripts" \
    "/opt/vpn-panel/scripts"; do
    if [ -f "$candidate/sstp_ip_up.sh" ] && [ -f "$candidate/sstp_ip_down.sh" ]; then
      source_dir="$candidate"
      break
    fi
  done
  [ -n "$source_dir" ] || return 0
  install -d -m 0755 /opt/vpn-panel/scripts
  for hook in sstp_ip_up.sh sstp_ip_down.sh admission_guard.sh ensure_session_networking.sh; do
    [ -f "$source_dir/$hook" ] || continue
    if [ "$source_dir/$hook" != "/opt/vpn-panel/scripts/$hook" ]; then
      install -m 0755 "$source_dir/$hook" "/opt/vpn-panel/scripts/$hook"
    fi
  done
}

CERT_DIR="/etc/accel-ppp/sstp-certs"

# ---------------------------------------------------------------------------
# آی‌پی عمومی سرور را برای گواهی تشخیص می‌دهیم (کلاینت‌های ویندوزی SSTP با
# همین IP به سرور وصل می‌شوند، پس باید داخل SAN گواهی باشد - نه فقط CN).
# ---------------------------------------------------------------------------
detect_public_ip() {
  local ip=""
  local url
  for url in "https://ifconfig.me" "https://icanhazip.com" "https://api.ipify.org"; do
    ip=$(curl -s -f -4 --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]')
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
      echo "$ip"
      return
    fi
  done
  hostname -I 2>/dev/null | awk '{print $1}'
}

# ---------------------------------------------------------------------------
# گواهی TLS سرور SSTP را می‌سازد (یا اگر Let's Encrypt موجود باشد، همان را
# کپی می‌کند). این تابع همیشه اجرا می‌شود - حتی در مسیر «از قبل نصب است» -
# چون نسخه‌های قدیمی این اسکریپت گواهی self-signed را بدون SAN می‌ساختند که
# باعث خطای ویندوزی SSTP «0x80090308: The token supplied to the function is
# invalid» می‌شود. اگر گواهی فعلی SAN نداشته باشد، دوباره ساخته می‌شود.
# ---------------------------------------------------------------------------
ensure_sstp_cert() {
  local public_ip regen_needed=0
  public_ip=$(detect_public_ip)

  LE_LIVE_DIR=$(find /etc/letsencrypt/live -mindepth 1 -maxdepth 1 -type d 2>/dev/null | head -n1)
  if [ -n "$LE_LIVE_DIR" ] && [ -f "$LE_LIVE_DIR/fullchain.pem" ]; then
    echo "[*] Using existing Let's Encrypt certificate: $LE_LIVE_DIR"
    cp "$LE_LIVE_DIR/fullchain.pem" "$CERT_DIR/fullchain.pem"
    cp "$LE_LIVE_DIR/privkey.pem" "$CERT_DIR/privkey.pem"
    chmod 600 "$CERT_DIR/privkey.pem"
    return 0
  fi

  mkdir -p "$CERT_DIR"
  if [ -f "$CERT_DIR/fullchain.pem" ]; then
    # اگر گواهی موجود SAN نداشته باشد یا IP فعلی سرور را پوشش ندهد، دوباره بساز
    if ! openssl x509 -in "$CERT_DIR/fullchain.pem" -noout -ext subjectAltName 2>/dev/null | grep -q "IP Address\|DNS"; then
      echo "[*] گواهی موجود فاقد SAN است (علت خطای 0x80090308 در کلاینت‌های ویندوزی) - در حال ساخت دوباره..."
      regen_needed=1
    elif [ -n "$public_ip" ] && ! openssl x509 -in "$CERT_DIR/fullchain.pem" -noout -ext subjectAltName 2>/dev/null | grep -q "$public_ip"; then
      echo "[*] گواهی موجود IP فعلی سرور ($public_ip) را در SAN ندارد - در حال ساخت دوباره..."
      regen_needed=1
    fi
  else
    regen_needed=1
  fi

  if [ "$regen_needed" = "1" ]; then
    echo "[*] Generating self-signed certificate with SAN (IP: ${public_ip:-N/A}, DNS: $(hostname))..."
    local san="DNS:$(hostname)"
    [ -n "$public_ip" ] && san="IP:${public_ip},${san}"
    openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
      -keyout "$CERT_DIR/privkey.pem" -out "$CERT_DIR/fullchain.pem" \
      -subj "/CN=${public_ip:-$(hostname)}" \
      -addext "subjectAltName=${san}"
    chmod 600 "$CERT_DIR/privkey.pem"
    return 2   # یعنی گواهی عوض شد -> سرویس باید ری‌استارت شود
  fi
  echo "[*] گواهی SSTP معتبر است و نیازی به ساخت دوباره نیست."
  return 0
}

# ---------------------------------------------------------------------------
# اگر زیرساخت از قبل کامل نصب شده (باینری accel-pppd + سرویس systemd هر دو
# موجودند)، از کامپایل دوباره صرف‌نظر می‌کنیم و فقط سرویس را روشن نگه می‌داریم.
# با این حال، گواهی را همیشه بررسی/ترمیم می‌کنیم (به دلیل بالا).
# ---------------------------------------------------------------------------
if [ "$FORCE" != "1" ] \
  && [ -x /usr/sbin/accel-pppd ] \
  && [ -f /etc/systemd/system/accel-ppp-sstp.service ] \
  && find /usr/lib /usr/lib64 /usr/local/lib -type f -name "libauth_mschap_v1.so" -print -quit 2>/dev/null | grep -q . \
  && find /usr/lib /usr/lib64 /usr/local/lib -type f -name "libauth_mschap_v2.so" -print -quit 2>/dev/null | grep -q . \
  && find /usr/lib /usr/lib64 /usr/local/lib -type f -name "libsigchld.so" -print -quit 2>/dev/null | grep -q .; then
  echo "[*] زیرساخت SSTP از قبل نصب است - از کامپایل دوباره صرف‌نظر شد."
  install_sstp_hooks

  # ---------------------------------------------------------------------------
  # ترمیم نصب‌های قدیمی که با نسخه‌ی باگ‌دار این اسکریپت ساخته شده‌اند: مقدار
  # نامعتبر accept=1 (باید accept=ssl باشد) و نام غلط دایرکتیو ssl-pemfile-key
  # (اسم درست در accel-ppp خودِ ssl-keyfile است). بدون این دو، ماژول sstp اصلاً
  # TLS را ترمیناته نمی‌کند: کلاینت هندشیک را شروع می‌کند ولی سرور آن را به‌عنوان
  # SSL نمی‌شناسد (خطای «wrong version number» سمت کلاینت) و چون هیچ‌وقت به سطح
  # SSL نمی‌رسد، هیچ لاگ اتصالی هم ثبت نمی‌شود. این بخش idempotent است.
  # ---------------------------------------------------------------------------
  sstp_conf_healed=0
  if [ -f /etc/accel-ppp/sstp.conf ]; then
    if grep -q '^accept=1$' /etc/accel-ppp/sstp.conf || grep -q '^ssl-pemfile-key=' /etc/accel-ppp/sstp.conf; then
      echo "[*] کانفیگ SSTP قدیمی/باگ‌دار شناسایی شد (accept=1 یا ssl-pemfile-key) - در حال ترمیم..."
      sed -i 's/^accept=1$/accept=ssl/' /etc/accel-ppp/sstp.conf
      sed -i 's/^ssl-pemfile-key=/ssl-keyfile=/' /etc/accel-ppp/sstp.conf
      sstp_conf_healed=1
    fi

    # ---------------------------------------------------------------------
    # ترمیم نصب‌های قدیمی‌تر (قبل از اضافه‌شدن pppd_compat): بدون این ماژول،
    # accel-ppp کاربران SSTP را با chap-secrets درست وصل می‌کند ولی هیچ
    # رویداد connect/disconnect به پنل نمی‌رسد - همان چیزی که باعث می‌شود
    # کاربران آنلاین و حجم مصرفی SSTP در پنل همیشه خالی/صفر دیده شود.
    # ---------------------------------------------------------------------
    # DNS is optional in accel-ppp builds. Some distro/source builds do not
    # ship libdns.so; advertising a missing module prevents accel-ppp from
    # loading the configuration at all. Add [dns] only when the plugin exists,
    # otherwise remove stale module/section entries left by older panel builds.
    dns_available=0
    if find /usr/lib /usr/lib64 /usr/local/lib -type f -name "libdns.so" -print -quit 2>/dev/null | grep -q .; then
      dns_available=1
    fi
    dns_tmp="$(mktemp)"
    python3 - /etc/accel-ppp/sstp.conf "$dns_available" > "$dns_tmp" <<'PYDNS'
from pathlib import Path
import sys

path = Path(sys.argv[1])
available = sys.argv[2] == "1"
lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
out = []
section = ""
for raw in lines:
    stripped = raw.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        section = stripped[1:-1].strip().lower()
        if section == "dns" and not available:
            continue
    if section == "dns" and not available:
        continue
    if section == "modules" and stripped == "dns" and not available:
        continue
    out.append(raw)

if available:
    section = ""
    has_module = False
    has_section = False
    for raw in out:
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
            if section == "dns":
                has_section = True
        elif section == "modules" and stripped == "dns":
            has_module = True
    if not has_module:
        for index, raw in enumerate(out):
            if raw.strip().lower() == "[modules]":
                out.insert(index + 1, "dns")
                break
    if not has_section:
        if out and out[-1].strip():
            out.append("")
        out.extend(["[dns]", "dns1=1.1.1.1", "dns2=8.8.8.8"])

print("\n".join(out).rstrip() + "\n", end="")
PYDNS
    if ! cmp -s "$dns_tmp" /etc/accel-ppp/sstp.conf; then
      install -m 0600 "$dns_tmp" /etc/accel-ppp/sstp.conf
      sstp_conf_healed=1
    fi
    rm -f "$dns_tmp"

    if ! grep -q '^pppd_compat$' /etc/accel-ppp/sstp.conf; then
      echo "[*] ماژول pppd_compat (گزارش آنلاین/حجم SSTP به پنل) وجود ندارد - در حال اضافه‌کردن..."
      sed -i '/^\[modules\]/a pppd_compat' /etc/accel-ppp/sstp.conf
      if ! grep -q '^\[pppd-compat\]' /etc/accel-ppp/sstp.conf; then
        cat >> /etc/accel-ppp/sstp.conf << 'PPPDCOMPATEOF'

[pppd-compat]
verbose=1
ip-up=/opt/vpn-panel/scripts/sstp_ip_up.sh
ip-down=/opt/vpn-panel/scripts/sstp_ip_down.sh
PPPDCOMPATEOF
      fi
      sstp_conf_healed=1
    fi

    # ---------------------------------------------------------------------
    # ترمیم نصب‌های قدیمی‌تر با lcp-echo-interval=30 (تشخیص قطع تا ۹۰ ثانیه
    # طول می‌کشید) - به ۲/۳ (حداکثر ۶ ثانیه) به‌روزرسانی می‌شود، هم‌راستا با
    # L2TP/PPTP/OpenVPN.
    # ---------------------------------------------------------------------
    if ! grep -q '^lcp-echo-timeout=12$' /etc/accel-ppp/sstp.conf; then
      echo "[*] تنظیم adaptive LCP echo برای جلوگیری از قطع کاذب SSTP اعمال می‌شود..."
      sed -i 's/^lcp-echo-interval=.*/lcp-echo-interval=2/;/^lcp-echo-failure=/d;/^lcp-echo-timeout=/d' /etc/accel-ppp/sstp.conf
      sed -i '/^lcp-echo-interval=2$/a lcp-echo-timeout=12' /etc/accel-ppp/sstp.conf
      sstp_conf_healed=1
    fi

    # ---------------------------------------------------------------------
    # ترمیم نصب‌های قدیمی‌تر که اصلاً بخش [client-ip-range] نداشتند: بدون
    # این بخش، ماژول iprange داخلی accel-ppp هر کلاینتی که از IP واقعی خودش
    # (نه IP مجازی pool) وصل می‌شود رد می‌کند و در لاگ "IP is out of
    # client-ip-range, droping connection..." می‌نویسد - دقیقاً بعد از اینکه
    # chap authentication موفق شده، یعنی کاربر می‌بیند رمز درست پذیرفته شد
    # ولی هیچ‌وقت واقعاً وصل نمی‌شود. این باگ از همان اولین نسخه‌ای که این
    # اسکریپت sstp.conf را می‌ساخت وجود داشته - این بخش هیچ‌وقت نوشته نمی‌شد.
    # ---------------------------------------------------------------------
    if ! grep -q '^\[client-ip-range\]$' /etc/accel-ppp/sstp.conf; then
      echo "[*] بخش [client-ip-range] در کانفیگ SSTP وجود ندارد - در حال اضافه‌کردن..."
      cat >> /etc/accel-ppp/sstp.conf << 'CLIENTIPRANGEEOF'

[client-ip-range]
0.0.0.0/0
CLIENTIPRANGEEOF
      sstp_conf_healed=1
    fi

    # The two-/1 workaround used by older releases also included the SSTP
    # tunnel pool itself (192.168.45.0/24). accel-ppp then authenticated the
    # user but rejected every assigned tunnel IP with "requested IP cannot be
    # assigned". Replace the entire section with the documented 0.0.0.0/0
    # sentinel, which disables this overlap guard for our dynamic pool.
    if python3 - /etc/accel-ppp/sstp.conf <<'PYRANGE'
from pathlib import Path
import sys
path = Path(sys.argv[1])
lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
out = []
in_target = False
found = False
changed = False
for raw in lines:
    stripped = raw.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        in_target = stripped[1:-1].strip().lower() == "client-ip-range"
        out.append(raw)
        if in_target:
            found = True
            out.append("0.0.0.0/0")
        continue
    if in_target:
        if stripped != "0.0.0.0/0":
            changed = True
        continue
    out.append(raw)
if not found:
    if out and out[-1].strip():
        out.append("")
    out.extend(["[client-ip-range]", "0.0.0.0/0"])
    changed = True
normalized = "\n".join(out).rstrip() + "\n"
original = "\n".join(lines).rstrip() + "\n"
if normalized != original:
    path.write_text(normalized, encoding="utf-8")
    changed = True
raise SystemExit(0 if changed else 1)
PYRANGE
    then
      sstp_conf_healed=1
    fi

    # [client-ip-range] is parsed by accel-ppp core; it is not a loadable
    # module. Older panel releases inserted it into [modules], which produces
    # loader: 'client-ip-range' not found on every service start.
    if awk '
      BEGIN{section=""; found=0}
      /^\[/{section=$0}
      section=="[modules]" && $0=="client-ip-range"{found=1}
      END{exit !found}
    ' /etc/accel-ppp/sstp.conf; then
      echo "[*] حذف ورودی نامعتبر client-ip-range از [modules]..."
      awk '
        BEGIN{section=""}
        /^\[/{section=$0}
        !(section=="[modules]" && $0=="client-ip-range"){print}
      ' /etc/accel-ppp/sstp.conf > /etc/accel-ppp/sstp.conf.tmp
      install -m 0600 /etc/accel-ppp/sstp.conf.tmp /etc/accel-ppp/sstp.conf
      rm -f /etc/accel-ppp/sstp.conf.tmp
      sstp_conf_healed=1
    fi

    # MikroTik and Windows SSTP clients normally negotiate MSCHAP. Ensure the
    # corresponding accel-ppp auth modules exist in upgraded configurations.
    for auth_module in auth_pap auth_chap_md5 auth_mschap_v1 auth_mschap_v2 sigchld; do
      if ! awk -v module="$auth_module" '
        BEGIN{section=""; found=0}
        /^\[/{section=$0}
        section=="[modules]" && $0==module{found=1}
        END{exit !found}
      ' /etc/accel-ppp/sstp.conf; then
        sed -i "/^\[modules\]$/a ${auth_module}" /etc/accel-ppp/sstp.conf
        sstp_conf_healed=1
      fi
    done

    if ! grep -q '^ifname=sstp%d$' /etc/accel-ppp/sstp.conf; then
      sed -i '/^\[sstp\]$/a ifname=sstp%d' /etc/accel-ppp/sstp.conf
      sstp_conf_healed=1
    fi
    for ppp_option in ipv4=require ipv6=deny; do
      if ! grep -q "^${ppp_option}$" /etc/accel-ppp/sstp.conf; then
        sed -i "/^\[ppp\]$/a ${ppp_option}" /etc/accel-ppp/sstp.conf
        sstp_conf_healed=1
      fi
    done

    # ---------------------------------------------------------------------
    # رابط کنترل محلی accel-ppp برای قطع دقیق سشن SSTP از پنل. accel-ppp یک
    # پردازش مشترک برای همه‌ی کاربران دارد و با kill کردن PID نمی‌توان یک
    # کاربر خاص را قطع کرد؛ backend از فرمان‌های رسمی CLI مثل
    # "terminate match username ... hard" و "terminate if pppX hard"
    # استفاده می‌کند. پورت فقط روی 127.0.0.1 باز است و از شبکه قابل دسترسی
    # نیست. نصب‌های قدیمی این بخش را نداشتند و دکمه‌ی قطع/بن SSTP بی‌اثر بود.
    # ---------------------------------------------------------------------
    if ! grep -q '^\[cli\]$' /etc/accel-ppp/sstp.conf; then
      echo "[*] رابط کنترل محلی SSTP وجود ندارد - در حال اضافه‌کردن برای قطع/بن فوری کاربران..."
      cat >> /etc/accel-ppp/sstp.conf << 'SSTPCLIEOF'

[cli]
verbose=1
tcp=127.0.0.1:2001
SSTPCLIEOF
      sstp_conf_healed=1
    elif ! grep -q '^tcp=127\.0\.0\.1:2001$' /etc/accel-ppp/sstp.conf; then
      echo "[*] رابط کنترل SSTP روی loopback:2001 تنظیم نبود - در حال اصلاح..."
      sed -i '/^\[cli\]$/,/^\[/ { /^tcp=/d; /^\[cli\]$/a tcp=127.0.0.1:2001
      }' /etc/accel-ppp/sstp.conf
      sstp_conf_healed=1
    fi
  fi

  # -----------------------------------------------------------------------
  # ترمیم نصب‌های قدیمی‌تر (قبل از اضافه‌شدن StartLimitIntervalSec=0): بدون
  # این، اگر accel-pppd چند بار پشت سر هم در فاصله‌ی کوتاهی کرش کند، systemd
  # برای همیشه از تلاش دوباره برای روشن‌کردنش دست می‌کشد (وضعیت «failed»
  # دائمی) تا یک ادمین دستی «systemctl restart» بزند - که دقیقاً همان رفتاری
  # است که با زدن دکمه‌ی «ذخیره» در پنل (که همین دستور را صدا می‌زند) موقتاً
  # درست به‌نظر می‌رسد، ولی خودِ کرش دوباره تکرار می‌شود.
  # -----------------------------------------------------------------------
  unit_healed=0
  if [ -f /etc/systemd/system/accel-ppp-sstp.service ] && ! grep -q '^StartLimitIntervalSec=0$' /etc/systemd/system/accel-ppp-sstp.service; then
    echo "[*] تنظیم StartLimitIntervalSec روی سرویس accel-ppp-sstp وجود ندارد - در حال اضافه‌کردن..."
    sed -i '/^After=network.target$/a StartLimitIntervalSec=0' /etc/systemd/system/accel-ppp-sstp.service
    unit_healed=1
  fi

  # همان باگ setup_ikev2.sh: ensure_sstp_cert عمداً 2 برمی‌گرداند وقتی گواهی
  # جدید ساخته می‌شود. زیر set -e، فراخوانی مستقیم تابع که non-zero برگرداند
  # باعث خروج فوری کل اسکریپت می‌شود - یعنی هیچ‌وقت به daemon-reload/restart
  # سرویس نمی‌رسید و SSTP علی‌رغم گواهی جدید هیچ‌وقت واقعاً ری‌استارت نمی‌شد.
  set +e
  ensure_sstp_cert
  cert_changed=$?
  set -e
  systemctl daemon-reload
  systemctl enable accel-ppp-sstp >/dev/null 2>&1 || true
  if ! systemctl is-active --quiet accel-ppp-sstp || [ "$cert_changed" = "2" ] || [ "$sstp_conf_healed" = "1" ] || [ "$unit_healed" = "1" ]; then
    echo "[*] سرویس accel-ppp-sstp را (به‌خاطر گواهی جدید، ترمیم کانفیگ یا خاموش بودن) روشن/ری‌استارت می‌کنیم..."
    systemctl restart accel-ppp-sstp || echo "    هشدار: روشن‌کردن سرویس ناموفق بود؛ برای جزئیات: systemctl status accel-ppp-sstp"
  fi
  if [ "$sstp_conf_healed" = "1" ]; then
    echo "[*] کانفیگ SSTP ترمیم و سرویس ری‌استارت شد (accept=ssl / ssl-keyfile اصلاح شدند)."
  fi
  if [ "$cert_changed" = "2" ]; then
    echo ""
    echo "[!] گواهی جدید ساخته شد. حتماً گواهی جدید را از پنل (صفحه‌ی سابسکریپشن کاربر ->"
    echo "    دانلود گواهی SSTP) دوباره دانلود و روی کلاینت ویندوزی در"
    echo "    Trusted Root Certification Authorities نصب کنید، وگرنه خطای"
    echo "    0x80090308 همچنان تکرار می‌شود."
  fi
  echo "[*] SSTP آماده است (پورت: $(grep -E '^port=' /etc/accel-ppp/sstp.conf 2>/dev/null | cut -d= -f2 || echo "$SSTP_PORT"))."
  exit 0
fi

echo "[*] Installing build dependencies..."
if [ "${SKIP_APT_UPDATE:-0}" != "1" ]; then vpn_panel_apt_get update; fi
vpn_panel_install_packages git build-essential cmake liblua5.1-0-dev \
  libpcre2-dev libssl-dev linux-headers-$(uname -r) \
  libpcap-dev libnl-genl-3-dev iptables-persistent openssl

echo "[*] Fetching accel-ppp source..."
SRC_DIR="/usr/local/src/accel-ppp"
rm -rf "$SRC_DIR"
git clone --depth=1 https://github.com/accel-ppp/accel-ppp.git "$SRC_DIR"

echo "[*] Building accel-ppp with SSTP support..."
mkdir -p "$SRC_DIR/build"
cd "$SRC_DIR/build"
cmake -DBUILD_DRIVER=FALSE -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_BUILD_TYPE=Release ..
make -j"$(nproc)"
make install

echo "[*] Preparing TLS certificate for SSTP..."
mkdir -p "$CERT_DIR"
# اگر پنل قبلاً از certbot گواهی گرفته، همان استفاده می‌شود؛ وگرنه یک گواهی
# self-signed با SAN صحیح ساخته می‌شود (نگاه کنید به تابع ensure_sstp_cert
# در بالای فایل - بدون SAN، کلاینت‌های ویندوزی خطای 0x80090308 می‌گیرند).
# همان باگ set -e: در نصب تازه معمولاً هیچ گواهی Let's Encrypt نیست، پس این
# تابع تقریباً همیشه self-signed می‌سازد و 2 برمی‌گرداند - بدون set +e/-e،
# اسکریپت همین‌جا (قبل از نوشتن sstp.conf و ساخت/روشن‌کردن سرویس systemd)
# با شکست خاتمه پیدا می‌کرد.
set +e
ensure_sstp_cert
set -e

echo "[*] Writing accel-ppp SSTP config..."
install_sstp_hooks
mkdir -p /etc/accel-ppp
touch /etc/ppp/chap-secrets
chmod 600 /etc/ppp/chap-secrets

SSTP_DNS_MODULE_LINE=""
SSTP_DNS_SECTION=""
if find /usr/lib /usr/lib64 /usr/local/lib -type f -name "libdns.so" -print -quit 2>/dev/null | grep -q .; then
  SSTP_DNS_MODULE_LINE="dns"
  SSTP_DNS_SECTION=$'\n[dns]\ndns1=1.1.1.1\ndns2=8.8.8.8'
else
  echo "[*] libdns.so در این build وجود ندارد؛ SSTP بدون ماژول اختیاری DNS نوشته می‌شود."
fi

cat > /etc/accel-ppp/sstp.conf << EOF
[modules]
log_syslog
sstp
chap-secrets
auth_pap
auth_chap_md5
auth_mschap_v1
auth_mschap_v2
ippool
sigchld
pppd_compat
${SSTP_DNS_MODULE_LINE}
[core]
log-error=/var/log/accel-ppp/sstp-core.log
thread-count=2

# رابط کنترل فقط-محلی برای اجرای فرمان‌های رسمی terminate از پنل. این پورت
# روی IP عمومی listen نمی‌کند و فقط backend همان سرور به آن وصل می‌شود.
[cli]
verbose=1
tcp=127.0.0.1:2001

[sstp]
verbose=1
ifname=sstp%d
port=${SSTP_PORT}
accept=ssl
ssl-pemfile=${CERT_DIR}/fullchain.pem
ssl-keyfile=${CERT_DIR}/privkey.pem
mppe=prefer

# ماژول pppd_compat (بالا) accel-ppp را وادار می‌کند دقیقاً مثل pppd، به
# ازای هر سشن که واقعاً وصل/قطع می‌شود، این دو اسکریپت را با همان قرارداد
# آرگومان‌های pppd (و متغیر محیطی PEERNAME = یوزرنیم) صدا بزند. بدون این
# بخش، accel-ppp کاربران را با chap-secrets درست احراز هویت می‌کند ولی هیچ
# رویدادی به پنل نمی‌رسد - پنل هیچ‌وقت نمی‌فهمد کدام کاربر SSTP همین الان
# آنلاین است یا چقدر حجم مصرف کرده (برخلاف L2TP/PPTP که از طریق
# /etc/ppp/ip-up.d و OpenVPN که از طریق client-connect همین اطلاعات را
# می‌فرستند). جزئیات کامل در خودِ دو اسکریپت.
[pppd-compat]
verbose=1
ip-up=/opt/vpn-panel/scripts/sstp_ip_up.sh
ip-down=/opt/vpn-panel/scripts/sstp_ip_down.sh

[chap-secrets]
chap-secrets=/etc/ppp/chap-secrets
gw-ip-address=${SSTP_SUBNET}.1

[ppp]
verbose=1
ipv4=require
ipv6=deny
min-mtu=1280
mtu=1400
mru=1400
ccp=1
mppe=prefer
# با interval=2/failure=3 این تشخیص («کاربر واقعاً آفلاین شده») حداکثر ۶
# ثانیه طول می‌کشد - هم‌راستا با L2TP/PPTP/OpenVPN، زیر سقف ۷ ثانیه‌ای که
# می‌خواهیم.
lcp-echo-interval=2
lcp-echo-timeout=12

${SSTP_DNS_SECTION}

[ip-pool]
gw-ip-address=${SSTP_SUBNET}.1
${SSTP_SUBNET}.10-${SSTP_SUBNET}.250

# بدون این بخش، ماژول iprange داخلی accel-ppp به‌صورت پیش‌فرض IP مبدأ واقعی
# کلاینت (نه IP مجازی تخصیص‌یافته از ip-pool، بلکه همان IP عمومی که کلاینت
# از آن به سرور وصل می‌شود) را با هیچ رنج مجازی مطابقت نمی‌دهد و لاگ
# "IP is out of client-ip-range, droping connection..." می‌دهد - دقیقاً
# همان چیزی که باعث می‌شد کاربر بعد از احراز هویت موفق (chap) هنوز نتواند
# وصل شود. مقدار ویژه‌ی 0.0.0.0/0 بررسی هم‌پوشانی IP مبدأ/تونل را غیرفعال
# می‌کند؛ دو رنج /1 نباید استفاده شوند چون استخر 192.168.45.0/24 را هم
# می‌پوشانند و accel-ppp آدرس تخصیص‌یافته را رد می‌کند.
[client-ip-range]
0.0.0.0/0

[log]
log-file=/var/log/accel-ppp/sstp.log
log-emerg=/var/log/accel-ppp/sstp-emerg.log
copy=1
level=3
EOF

mkdir -p /var/log/accel-ppp

echo "[*] Creating systemd service..."
cat > /etc/systemd/system/accel-ppp-sstp.service << 'EOF'
[Unit]
Description=accel-ppp SSTP server
After=network.target
# systemd به‌صورت پیش‌فرض اگر یک سرویس بیش از ۵ بار در ۱۰ ثانیه شکست بخورد،
# دیگر هیچ‌وقت (حتی با Restart=on-failure) خودش را دوباره روشن نمی‌کند و
# برای همیشه در وضعیت «failed» می‌ماند - این دقیقاً همان چیزی است که باعث
# می‌شد بعد از چند بار کرش پشت سر هم (مثلاً به‌خاطر یک بسته‌ی بدشکل یا باگ
# خودِ accel-pppd)، سرویس SSTP خاموش بماند تا ادمین دستی از پنل «ذخیره»
# بزند (که systemctl restart را دوباره صدا می‌زند و شمارنده‌ی شکست را ریست
# می‌کند). با غیرفعال‌کردن این محدودیت، Restart=on-failure/RestartSec=3
# پایین همیشه و بدون وقفه اعمال می‌شود.
StartLimitIntervalSec=0

[Service]
Type=simple
# نکته‌ی مهم: پرچم -d باعث می‌شود accel-pppd خودش را داخل پس‌زمینه fork/detach
# کند (double-fork). این با Type=simple سازگار نیست: systemd همان پردازه‌ای را
# که ExecStart مستقیماً اجرا کرده رصد می‌کند و به‌محض این‌که آن پردازه (به‌خاطر
# -d) خارج شود، سرویس را بلافاصله «inactive/failed» گزارش می‌کند - حتی اگر
# systemctl start خودش با کد موفقیت (0) برگردد و پیام «با موفقیت روشن شد» در
# پنل نمایش داده شود. برای همین -d باید حذف شود تا accel-pppd در foreground
# باقی بماند و systemd بتواند به‌درستی وضعیت واقعی سرویس را دنبال کند.
ExecStart=/usr/sbin/accel-pppd -c /etc/accel-ppp/sstp.conf -p /run/accel-ppp-sstp.pid
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable accel-ppp-sstp
systemctl restart accel-ppp-sstp

echo "[*] Configuring NAT/forwarding for SSTP subnet..."
NET_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
sysctl -w net.ipv4.ip_forward=1 >/dev/null
grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

iptables -t nat -C POSTROUTING -s ${SSTP_SUBNET}.0/24 -o "${NET_IFACE}" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s ${SSTP_SUBNET}.0/24 -o "${NET_IFACE}" -j MASQUERADE
iptables -C FORWARD -s ${SSTP_SUBNET}.0/24 -m comment --comment "vpnpanel-sstp-forward-out" -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -s ${SSTP_SUBNET}.0/24 -m comment --comment "vpnpanel-sstp-forward-out" -j ACCEPT
iptables -C FORWARD -d ${SSTP_SUBNET}.0/24 -m conntrack --ctstate ESTABLISHED,RELATED \
  -m comment --comment "vpnpanel-sstp-forward-in" -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -d ${SSTP_SUBNET}.0/24 -m conntrack --ctstate ESTABLISHED,RELATED \
    -m comment --comment "vpnpanel-sstp-forward-in" -j ACCEPT
iptables -t mangle -C FORWARD -s ${SSTP_SUBNET}.0/24 -p tcp --tcp-flags SYN,RST SYN \
  -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
  iptables -t mangle -A FORWARD -s ${SSTP_SUBNET}.0/24 -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --clamp-mss-to-pmtu
netfilter-persistent save >/dev/null 2>&1 || true

echo ""
echo "=============================================================="
echo " SSTP infrastructure is up."
echo "   - Port:      tcp/${SSTP_PORT}  (make sure it's open in your"
echo "                firewall/security group. Default is 4433, not 443,"
echo "                because 443 is reserved for the panel's own HTTPS"
echo "                (nginx). If you really want SSTP on 443 instead,"
echo "                edit 'port=' in /etc/accel-ppp/sstp.conf, make sure"
echo "                nginx is NOT also bound to 443, then:"
echo "                systemctl restart accel-ppp-sstp)"
echo "   - Subnet:    ${SSTP_SUBNET}.0/24"
echo "   - Users:     shared with L2TP/PPTP via /etc/ppp/chap-secrets"
echo "                (format: username sstp password *)"
echo "   - Cert:      ${CERT_DIR}/fullchain.pem"
echo "   - Logs:      /var/log/accel-ppp/sstp.log"
echo "   - Service:   systemctl status accel-ppp-sstp"
echo "=============================================================="
