#!/bin/bash
# این اسکریپت باید در /etc/ppp/ip-down.d/ قرار بگیرد
source /opt/vpn-panel/panel.env
BACKEND_PORT="${BACKEND_PORT:-8000}"

IFACE="$1"
TUNNEL_IP="$5"
USERNAME="${PEERNAME}"

if [ -z "$USERNAME" ]; then
  exit 0
fi

# پیدا کردن pid واقعیِ pppd (نه $PPID خام) - دلیل دقیقاً همان چیزی است که در
# ppp_ip_up.sh توضیح داده شده: روی Ubuntu، اسکریپت‌های ip-down.d/ هم از طریق
# run-parts اجرا می‌شوند، پس $PPID اینجا pid خودِ run-parts است نه pppd. اگر
# این‌جا هم همان pid اشتباه فرستاده شود، با pidِ درستی که ip-up.sh (بعد از
# اصلاح) ذخیره کرده مطابقت پیدا نمی‌کند و رکورد درست در دیتابیس بسته نمی‌شود.
get_ppid() { awk '/^PPid:/{print $2}' "/proc/$1/status" 2>/dev/null; }
get_comm() { cat "/proc/$1/comm" 2>/dev/null; }

PPPD_PID=""
WALK_PID="$PPID"
for _ in 1 2 3 4 5 6; do
  if [ -z "$WALK_PID" ] || [ "$WALK_PID" = "1" ]; then
    break
  fi
  if [ "$(get_comm "$WALK_PID")" = "pppd" ]; then
    PPPD_PID="$WALK_PID"
    break
  fi
  WALK_PID=$(get_ppid "$WALK_PID")
done
[ -z "$PPPD_PID" ] && PPPD_PID="$PPID"

# Release the per-process idempotency marker created by ppp_ip_up.sh.  The
# wildcard is safe because the directory is private to the panel and the PID is
# numeric; it also handles a process whose /proc entry disappeared unusually
# early before ip-down finished.
rm -f /run/vpn-panel/ppp-hooks/${PPPD_PID}-*.up 2>/dev/null || true

PROTOCOL="l2tp"
DAEMON_PID=$(get_ppid "$PPPD_PID")
if [ -n "$DAEMON_PID" ]; then
  DAEMON_CMD=$(get_comm "$DAEMON_PID")
  if echo "$DAEMON_CMD" | grep -qi "pptp"; then
    PROTOCOL="pptp"
  fi
fi

# خواندن حجم مصرفی از شمارنده‌های اینترفیس (بایت)
RX_BYTES=0
TX_BYTES=0
if [ -f "/sys/class/net/${IFACE}/statistics/rx_bytes" ]; then
  RX_BYTES=$(cat "/sys/class/net/${IFACE}/statistics/rx_bytes")
  TX_BYTES=$(cat "/sys/class/net/${IFACE}/statistics/tx_bytes")
fi

# PPPD_PID اینجا همان پردازش pppd است که این سشن مشخص را مدیریت می‌کرد (همان
# مقداری که ppp_ip_up.sh هنگام اتصال همین سشن فرستاده بود) - دقیق‌ترین
# شناسه برای پیدا کردن رکورد درست در دیتابیس، چون یک کاربر می‌تواند هم‌زمان
# چند سشن باز داشته باشد.
curl -s -o /dev/null -X POST "http://127.0.0.1:${BACKEND_PORT}/api/internal/disconnect" \
  -H "Content-Type: application/json" \
  -H "X-Internal-Token: ${INTERNAL_API_TOKEN}" \
  -d "{\"username\":\"${USERNAME}\",\"protocol\":\"${PROTOCOL}\",\"interface\":\"${IFACE}\",\"tunnel_ip\":\"${TUNNEL_IP}\",\"pid\":${PPPD_PID},\"bytes_in\":${RX_BYTES},\"bytes_out\":${TX_BYTES}}"

if [ -x /opt/vpn-panel/scripts/ensure_session_networking.sh ]; then
  /opt/vpn-panel/scripts/ensure_session_networking.sh --down "$PROTOCOL" "$IFACE" "$TUNNEL_IP" >/dev/null 2>&1 || true
fi

exit 0
