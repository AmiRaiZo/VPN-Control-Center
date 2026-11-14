#!/bin/bash
# مسیر این اسکریپت مستقیماً در /etc/ocserv/ocserv.conf (کلید connect-script=)
# نوشته می‌شود؛ خودِ ocserv (نه از طریق pppd/run-parts) این را به‌ازای هر
# سشن جدید و موفق (بعد از احراز هویت با فایل ocpasswd) اجرا می‌کند.
#
# طبق مستندات ocserv، این متغیرهای محیطی در دسترس‌اند:
#   USERNAME    نام‌کاربری‌ای که با آن احراز هویت شده
#   DEVICE      نام اینترفیس tun اختصاص‌یافته به این سشن (مثلاً vpns0)
#   IP_REAL     آی‌پی واقعی/پابلیک کلاینت (گاهی به‌صورت IP:port)
#   IP_REMOTE   آی‌پی مجازی تونل که به کلاینت اختصاص داده شده
#   ID          شناسه‌ی عددی سشن (یکتا در همان اجرای ocserv)
#
# اگر پنل صریحاً اتصال را رد کند (غیرفعال/منقضی/اتمام حجم/سقف کاربر/قطع
# اینترنت IP)، خروج غیرصفر فقط همین اتصال تازه را می‌بندد. خطا یا کندی خودِ
# API دیگر باعث قطعی سراسری VPN نمی‌شود و با لاگ FAIL-OPEN ثبت می‌شود.

source /opt/vpn-panel/panel.env
BACKEND_PORT="${BACKEND_PORT:-8000}"
source /opt/vpn-panel/scripts/admission_guard.sh

if [ -z "${USERNAME}" ]; then
  exit 0
fi

# IP_REAL گاهی به‌صورت "1.2.3.4:5678" (با پورت مبدأ کلاینت) فرستاده می‌شود؛
# فقط بخش آی‌پی برای ثبت در دیتابیس لازم است. این جداسازی فقط برای الگوی
# ساده‌ی IPv4:port است - اگر IP_REAL شامل بیش از یک ":" باشد (IPv6)، دست‌نخورده
# نگه داشته می‌شود.
CLIENT_IP="${IP_REAL}"
if [[ "${CLIENT_IP}" == *:*:* ]]; then
  : # IPv6 - همان‌طور که هست باقی می‌ماند
elif [[ "${CLIENT_IP}" == *:* ]]; then
  CLIENT_IP="${CLIENT_IP%%:*}"
fi

SESSION_ID="${ID:-0}"
[[ "$SESSION_ID" =~ ^[0-9]+$ ]] || SESSION_ID=0
PAYLOAD="{\"username\":\"${USERNAME}\",\"protocol\":\"openconnect\",\"ip_address\":\"${CLIENT_IP}\",\"interface\":\"${DEVICE}\",\"tunnel_ip\":\"${IP_REMOTE}\",\"pid\":${SESSION_ID}}"
if ! vpn_panel_admission_request "$PAYLOAD" "$USERNAME" "openconnect" "$CLIENT_IP"; then
  exit 1
fi

if [ -x /opt/vpn-panel/scripts/ensure_session_networking.sh ]; then
  /opt/vpn-panel/scripts/ensure_session_networking.sh --up openconnect "$DEVICE" "$IP_REMOTE" >/dev/null 2>&1 || true
fi

exit 0
