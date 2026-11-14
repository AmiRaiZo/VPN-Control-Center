#!/bin/bash
###############################################################################
# تعمیر اضطراری و مستقل از پروسه‌ی آپدیت پنل: وقتی گواهی Let's Encrypt یک
# دامنه برای IKEv2 از قبل صادر شده (در /etc/letsencrypt/live/<domain>) ولی
# strongSwan هنوز CA خودامضای قدیمی («CN=VPN Panel IKEv2 CA») را پیشنهاد
# می‌دهد - مثلاً چون setup_ikev2.sh به‌روزشده هنوز روی این سرور دیپلوی نشده،
# یا فقط می‌خواهید همین الان بدون منتظر ماندن برای آپدیت کامل پنل رفع شود.
#
# برخلاف install/fix_ikev2_cert.sh (که چک مودولوس/تایید pid و... هم دارد)،
# این اسکریپت عمداً کوتاه و مستقیم است - همان دستورهایی که برای دیباگ دستی
# استفاده شد، فقط پارامتری‌شده روی دامنه.
#
# Usage: sudo bash emergency_ikev2_fix.sh <domain>
###############################################################################
set -e

if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root (sudo bash emergency_ikev2_fix.sh <domain>)" >&2
  exit 1
fi

DOMAIN="$1"
if [ -z "$DOMAIN" ]; then
  echo "Usage: emergency_ikev2_fix.sh <domain>" >&2
  exit 1
fi

LIVE="/etc/letsencrypt/live/${DOMAIN}"

echo "[*] چک اولیه..."
if [ -f "${LIVE}/cert.pem" ]; then
  echo "    LE cert exists (${LIVE})"
else
  echo "    LE cert MISSING for ${DOMAIN} - این اسکریپت گواهی جدید صادر نمی‌کند." >&2
  exit 1
fi

echo "[*] پاکسازی CA خودامضای قدیمی و نصب گواهی دامنه..."
rm -f /etc/ipsec.d/cacerts/*.pem
cp "${LIVE}/cert.pem"    /etc/ipsec.d/certs/ikev2-server-cert.pem
cp "${LIVE}/privkey.pem" /etc/ipsec.d/private/ikev2-server-key.pem
chmod 600 /etc/ipsec.d/private/ikev2-server-key.pem
echo "$DOMAIN" > /etc/ipsec.d/.ikev2-ssl-domain
sed -i '/^conn IKEv2-MSCHAPv2/,/^conn /{s/^\(\s*leftid=\).*/\1@'"${DOMAIN}"'/}' /etc/ipsec.conf

echo "[*] ری‌استارت strongSwan..."
systemctl stop strongswan-starter
sleep 2
systemctl start strongswan-starter
sleep 2

echo "[*] pid فعلی charon:"
pgrep -x charon

echo "[*] گواهی نصب‌شده (باید دامنه‌ی شما باشد، نه \"VPN Panel IKEv2 CA\"):"
openssl x509 -noout -issuer -subject -in /etc/ipsec.d/certs/ikev2-server-cert.pem

echo ""
echo "[*] دیاگنوستیک تکمیلی:"
echo "--- آیا setup_ikev2.sh نسخه‌ی جدید (با ترمیم خودکار دامنه) روی این سرور دیپلوی شده؟"
grep -c "دوباره سینک/ترمیم شد" /opt/vpn-panel/scripts/setup_ikev2.sh 2>/dev/null || echo "0 (فایل پیدا نشد)"
echo "--- مارکر دامنه:"
cat /etc/ipsec.d/.ikev2-ssl-domain 2>/dev/null || echo "NO MARKER FILE"
echo "--- دامنه‌های Let's Encrypt موجود روی این سرور:"
ls -la /etc/letsencrypt/live/ 2>/dev/null
echo "--- محتوای cacerts (باید خالی باشد):"
ls -la /etc/ipsec.d/cacerts/
echo "--- محتوای certs:"
ls -la /etc/ipsec.d/certs/
