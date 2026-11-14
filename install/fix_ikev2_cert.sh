#!/bin/bash
###############################################################################
# تعمیر دستی گواهی IKEv2 وقتی یک گواهی Let's Encrypt برای دامنه از قبل صادر
# شده (مثلاً از قبل با install/setup_ikev2_ssl.sh <domain> یا از پنل، Settings
# > SSL برای IKEv2) ولی وضعیت روی خودِ strongSwan/ipsec.d خراب/قدیمی مانده -
# بدون نیاز به درخواست دوباره از certbot (که ممکن است rate-limit بخورد).
#
# این اسکریپت همان کاری را می‌کند که install/setup_ikev2_ssl.sh بعد از گرفتن
# گواهی انجام می‌دهد، ولی این‌بار روی یک گواهی که از قبل در
# /etc/letsencrypt/live/<domain> موجود است - عمداً چند نکته را که در
# دستورهای دستیِ رایج (کپی/پیست ساده‌ی cert.pem/privkey.pem + pkill -9) از
# قلم می‌افتد رعایت می‌کند:
#
#   ۱) فقط leaf cert (cert.pem) در leftcert می‌رود، نه fullchain.pem و حتی نه
#      chain.pem داخل cacerts - دقیقاً همان دلیلی که در
#      ikev2_ssl_renew_hook.sh توضیح داده شده: strongSwan هر گواهی داخل
#      cacerts را خودکار به زنجیره‌ای که می‌فرستد اضافه می‌کند، و زنجیره‌ی
#      بزرگ‌تر باعث fragmentation در IKE_AUTH می‌شود که خیلی از کلاینت‌های
#      موبایل reassemble نمی‌کنند و اتصال بی‌دلیل قطع/تایم‌اوت می‌شود.
#   ۲) مارکر ${CERT_DIR}/.ikev2-ssl-domain نوشته/به‌روز می‌شود - بدون این،
#      install/setup_ikev2.sh (که هر بار در install.sh/update.sh دوباره اجرا
#      می‌شود) فکر می‌کند دامنه‌ی اختصاصی برای IKEv2 هیچ‌وقت تنظیم نشده و
#      همین گواهی درست را با یک گواهی self-signed جایگزین می‌کند.
#   ۳) leftid داخل /etc/ipsec.conf با @<domain> هم‌سو می‌شود - اگر leftid با
#      CN/SAN گواهی نصب‌شده یکی نباشد، احراز هویت سرور (leftauth=pubkey) با
#      AUTH_FAILED رد می‌شود، حتی اگر خودِ گواهی کاملاً معتبر باشد.
#   ۴) ری‌استارت با «systemctl restart strongswan-starter» - نه kill -9 دستیِ
#      charon/starter و بعد start جدا؛ kill -9 دستی pid های قدیمی را از
#      دستِ systemd خارج می‌کند و می‌تواند واحد را در حالت ناسازگار (چند
#      پردازش charon هم‌زمان، یا failed state) رها کند.
#
# Usage: sudo bash fix_ikev2_cert.sh <domain>
###############################################################################
set -e

if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root (sudo bash fix_ikev2_cert.sh <domain>)" >&2
  exit 1
fi

DOMAIN="$1"
if [ -z "$DOMAIN" ]; then
  echo "Usage: fix_ikev2_cert.sh <domain>" >&2
  exit 1
fi

CERT_DIR="/etc/ipsec.d"
LIVE_DIR="/etc/letsencrypt/live/${DOMAIN}"

if [ ! -f "${LIVE_DIR}/cert.pem" ]; then
  echo "ERROR: ${LIVE_DIR}/cert.pem پیدا نشد - این اسکریپت گواهی جدید صادر" >&2
  echo "نمی‌کند، فقط گواهی موجود را دوباره در ipsec.d سینک می‌کند. برای صدور" >&2
  echo "اولیه از install/setup_ikev2_ssl.sh ${DOMAIN} یا Settings > SSL برای" >&2
  echo "IKEv2 در پنل استفاده کنید." >&2
  exit 1
fi

mkdir -p "${CERT_DIR}/certs" "${CERT_DIR}/private" "${CERT_DIR}/cacerts"

# پاکسازی کامل گواهی/کلید/CA قدیمی (self-signed یا دامنه‌ی قبلی) - دقیقاً
# مثل ensure_ikev2_cert در setup_ikev2.sh قبل از نصب گواهی جدید.
rm -f "${CERT_DIR}"/certs/*.pem "${CERT_DIR}"/private/*.pem "${CERT_DIR}"/cacerts/*.pem

cp "${LIVE_DIR}/cert.pem"    "${CERT_DIR}/certs/ikev2-server-cert.pem"
cp "${LIVE_DIR}/privkey.pem" "${CERT_DIR}/private/ikev2-server-key.pem"
chmod 600 "${CERT_DIR}/private/ikev2-server-key.pem"

# تایید این‌که cert.pem و privkey.pem واقعاً یک جفت هستند - قبلاً این اسکریپت
# کورکورانه فرض می‌کرد چون هر دو از یک LIVE_DIR کپی شدند حتماً جفتِ هم‌اند.
# اگر LIVE_DIR به هر دلیلی (renewal ناقص، symlink شکسته‌ی certbot، یا اجرای
# این اسکریپت وسط یک renewal که privkey.pem تازه‌تر از cert.pem نوشته شده)
# ناهماهنگ باشد، charon بدون هیچ خطای واضحی فقط AUTH_FAILED می‌فرستد - همان
# چیزی که در لاگ دیده می‌شود. اینجا مودولوس هر دو را قبل از هرگونه ری‌استارت
# مقایسه می‌کنیم تا اگر جفت نبودند، همین‌جا با خطای صریح متوقف شویم، نه اینکه
# یک جفتِ خراب را نصب کنیم و کاربر دوباره با AUTH_FAILED گیج شود.
CERT_MODULUS=$(openssl x509 -noout -modulus -in "${CERT_DIR}/certs/ikev2-server-cert.pem" 2>/dev/null | openssl md5)
KEY_MODULUS=$(openssl rsa -noout -modulus -in "${CERT_DIR}/private/ikev2-server-key.pem" 2>/dev/null | openssl md5)
if [ "$CERT_MODULUS" != "$KEY_MODULUS" ]; then
  echo "ERROR: cert.pem و privkey.pem داخل ${LIVE_DIR} جفتِ هم نیستند" >&2
  echo "       (مودولوس یکی نیست) - نصب متوقف شد تا یک گواهی/کلیدِ ناسازگار" >&2
  echo "       جایگزین نشود. LIVE_DIR را چک کنید یا با" >&2
  echo "       'certbot certificates -d ${DOMAIN}' وضعیتش را ببینید." >&2
  exit 1
fi

echo "$DOMAIN" > "${CERT_DIR}/.ikev2-ssl-domain"

if [ -f /etc/ipsec.conf ] && grep -q "^conn IKEv2-MSCHAPv2" /etc/ipsec.conf; then
  sed -i '/^conn IKEv2-MSCHAPv2/,/^conn /{s/^\(\s*leftcert=\).*/\1ikev2-server-cert.pem/}' /etc/ipsec.conf
  sed -i '/^conn IKEv2-MSCHAPv2/,/^conn /{s/^\(\s*leftid=\).*/\1@'"${DOMAIN}"'/}' /etc/ipsec.conf
else
  echo "[!] هشدار: بلوک «conn IKEv2-MSCHAPv2» در /etc/ipsec.conf پیدا نشد - " >&2
  echo "    یعنی install/setup_ikev2.sh هنوز اصلاً اجرا نشده. ابتدا آن را " >&2
  echo "    اجرا کنید تا زیرساخت IKEv2 ساخته شود، بعد این اسکریپت را دوباره." >&2
fi

touch /etc/ipsec.secrets
if ! grep -q "ikev2-server-key.pem" /etc/ipsec.secrets; then
  sed -i "1i : RSA ikev2-server-key.pem" /etc/ipsec.secrets
fi
chmod 600 /etc/ipsec.secrets

echo "[*] چک نهایی گواهی نصب‌شده:"
openssl x509 -noout -subject -issuer -dates -in "${CERT_DIR}/certs/ikev2-server-cert.pem"

# ---------------------------------------------------------------------------
# ری‌استارت مطمئن: صرفاً «systemctl restart strongswan-starter» گاهی charon
# را واقعاً نمی‌کشد (بسته به نسخه/توزیع، charon زیرپردازه‌ی starter است و اگر
# starter خودش هنگ/نیمه‌جان باشد، restart آن ممکن است موفق گزارش شود بدون
# اینکه charon واقعاً عوض شود) - این دقیقاً همان چیزی است که در لاگت دیده
# می‌شد: بعد از "restart"، charon هنوز CERTREQ برای CA خودامضای قدیمی
# می‌فرستاد، یعنی همان پردازش قدیمی با گواهی/CA کش‌شده‌ی قبلی سرِ کار مانده
# بود. این‌جا: ۱) pid فعلیِ charon را قبل از هر کاری می‌گیریم، ۲) stop می‌زنیم
# و صبر می‌کنیم charon واقعاً از /proc محو شود (نه فقط اینکه دستور برگردد)،
# اگر بعد از چند ثانیه هنوز زنده بود صراحتاً SIGTERM/SIGKILL می‌فرستیم، ۳)
# بعد start می‌زنیم و pid جدید را تایید می‌کنیم که با pid قبلی فرق دارد.
OLD_CHARON_PID=$(pgrep -x charon | head -n1)

systemctl stop strongswan-starter 2>/dev/null || systemctl stop strongswan 2>/dev/null || ipsec stop 2>/dev/null || true

for _ in 1 2 3 4 5 6 7 8; do
  pgrep -x charon >/dev/null 2>&1 || break
  sleep 1
done
if pgrep -x charon >/dev/null 2>&1; then
  echo "[*] charon بعد از stop عادی هنوز بالاست - SIGTERM/SIGKILL دستی..."
  pkill -TERM -x charon 2>/dev/null || true
  sleep 2
  pkill -KILL -x charon 2>/dev/null || true
  sleep 1
fi

systemctl start strongswan-starter 2>/dev/null || systemctl start strongswan 2>/dev/null || ipsec start 2>/dev/null || true
sleep 2

NEW_CHARON_PID=$(pgrep -x charon | head -n1)
if [ -z "$NEW_CHARON_PID" ]; then
  echo "[!] charon بعد از start بالا نیامد - لاگ را چک کنید: journalctl -u strongswan-starter -n 50" >&2
  exit 1
fi
if [ -n "$OLD_CHARON_PID" ] && [ "$NEW_CHARON_PID" = "$OLD_CHARON_PID" ]; then
  echo "[!] هشدار: pid پردازش charon (${NEW_CHARON_PID}) عوض نشده - یعنی همان" >&2
  echo "    پردازشِ قبلی با گواهی/CA کش‌شده‌ی قبلی هنوز سرِ کار است. دستی چک کنید:" >&2
  echo "    systemctl status strongswan-starter --no-pager" >&2
  exit 1
fi
echo "[*] charon با pid جدید (${NEW_CHARON_PID}) بالا آمد - گواهی جدید لود شده."

if command -v ipsec >/dev/null 2>&1 && ipsec statusall >/dev/null 2>&1; then
  echo "[*] conn IKEv2-MSCHAPv2 لود شد."
fi

echo "IKEV2_CERT_FIX_OK ${DOMAIN}"
