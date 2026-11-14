#!/bin/bash
# جفتِ sstp_ip_up.sh - مسیرش در /etc/accel-ppp/sstp.conf (بخش [pppd-compat]،
# کلید ip-down=) نوشته می‌شود و مستقیماً توسط accel-ppp اجرا می‌شود، نه از
# طریق /etc/ppp/ip-down.d. توضیحات کامل درباره‌ی تفاوت با ppp_ip_down.sh
# (بدون نیاز به تشخیص پردازش pppd، بدون ارسال pid) در sstp_ip_up.sh آمده.

source /opt/vpn-panel/panel.env
BACKEND_PORT="${BACKEND_PORT:-8000}"

IFACE="$1"
TUNNEL_IP="$5"
USERNAME="${PEERNAME}"

if [ -z "$USERNAME" ]; then
  exit 0
fi

# خواندن حجم مصرفی از شمارنده‌های اینترفیس (بایت) - دقیقاً همان روشی که
# ppp_ip_down.sh برای L2TP/PPTP استفاده می‌کند؛ اینترفیس‌های SSTP هم مثل
# آن‌ها یک ppp* استاندارد هستند، پس همین شمارنده‌های /sys برایشان هم معتبرند.
RX_BYTES=0
TX_BYTES=0
if [ -f "/sys/class/net/${IFACE}/statistics/rx_bytes" ]; then
  RX_BYTES=$(cat "/sys/class/net/${IFACE}/statistics/rx_bytes")
  TX_BYTES=$(cat "/sys/class/net/${IFACE}/statistics/tx_bytes")
fi

curl -s -o /dev/null -X POST "http://127.0.0.1:${BACKEND_PORT}/api/internal/disconnect" \
  -H "Content-Type: application/json" \
  -H "X-Internal-Token: ${INTERNAL_API_TOKEN}" \
  -d "{\"username\":\"${USERNAME}\",\"protocol\":\"sstp\",\"interface\":\"${IFACE}\",\"tunnel_ip\":\"${TUNNEL_IP}\",\"pid\":null,\"bytes_in\":${RX_BYTES},\"bytes_out\":${TX_BYTES}}"

if [ -x /opt/vpn-panel/scripts/ensure_session_networking.sh ]; then
  /opt/vpn-panel/scripts/ensure_session_networking.sh --down sstp "$IFACE" "$TUNNEL_IP" >/dev/null 2>&1 || true
fi

exit 0
