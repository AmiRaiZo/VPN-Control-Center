#!/bin/bash
# جفتِ openconnect_connect.sh - مسیرش در /etc/ocserv/ocserv.conf (کلید
# disconnect-script=) نوشته می‌شود و مستقیماً توسط ocserv در پایان هر سشن
# اجرا می‌شود (برخلاف ppp_ip_down.sh که از طریق /etc/ppp/ip-down.d و
# run-parts صدا زده می‌شود، پس نیازی به تشخیص pid از روی /proc نیست).
#
# علاوه بر USERNAME/DEVICE (نگاه کنید به openconnect_connect.sh)، ocserv در
# لحظه‌ی قطع این دو متغیر آماری را هم فراهم می‌کند:
#   STATS_BYTES_IN   بایت‌های دریافتی این سشن (از دید سرور: از کلاینت)
#   STATS_BYTES_OUT  بایت‌های ارسالی این سشن (از دید سرور: به کلاینت)

source /opt/vpn-panel/panel.env
BACKEND_PORT="${BACKEND_PORT:-8000}"

if [ -z "${USERNAME}" ]; then
  exit 0
fi

RX_BYTES="${STATS_BYTES_IN:-0}"
TX_BYTES="${STATS_BYTES_OUT:-0}"

curl -s -o /dev/null -X POST "http://127.0.0.1:${BACKEND_PORT}/api/internal/disconnect" \
  -H "Content-Type: application/json" \
  -H "X-Internal-Token: ${INTERNAL_API_TOKEN}" \
  -d "{\"username\":\"${USERNAME}\",\"protocol\":\"openconnect\",\"interface\":\"${DEVICE}\",\"tunnel_ip\":\"${IP_REMOTE}\",\"pid\":null,\"bytes_in\":${RX_BYTES},\"bytes_out\":${TX_BYTES}}"

if [ -x /opt/vpn-panel/scripts/ensure_session_networking.sh ]; then
  /opt/vpn-panel/scripts/ensure_session_networking.sh --down openconnect "$DEVICE" "$IP_REMOTE" >/dev/null 2>&1 || true
fi

exit 0
