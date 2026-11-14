#!/bin/bash
# این اسکریپت مسیرش مستقیماً در /etc/accel-ppp/sstp.conf (بخش [pppd-compat],
# کلید ip-up=) نوشته می‌شود - برخلاف ppp_ip_up.sh که در /etc/ppp/ip-up.d/
# قرار می‌گیرد و توسط دیسپچر pppd (از طریق run-parts) صدا زده می‌شود.
# accel-ppp (ماژول pppd_compat) این مسیر را مستقیماً و خودش اجرا می‌کند.
#
# طبق مستندات/سورس accel-ppp (accel-pppd/extra/pppd_compat.c)، این ماژول
# دقیقاً همان قرارداد آرگومان‌های pppd را رعایت می‌کند:
#   $1=interface  $2=tty(همیشه "none")  $3=speed(همیشه "0")
#   $4=local-ip   $5=peer-ip(آی‌پی داخلی تونل)  $6=calling-station-id
# و متغیر محیطی PEERNAME هم مثل pppd همان یوزرنیمی است که کاربر با آن
# احراز هویت شده (از همان chap-secrets مشترکی که sync_chap_secrets می‌نویسد).
#
# برخلاف ppp_ip_up.sh نیازی به پیدا کردن پردازش pppd/xl2tpd/pptpd از روی
# /proc نیست: این اسکریپت فقط برای SSTP نوشته شده، پس PROTOCOL همیشه ثابت و
# مشخص است - آن پیچیدگی مخصوص pppd (که ip-up.d را با run-parts صدا می‌زند و
# پروتکل واقعی را باید از پدرِ پردازش pppd حدس زد) اینجا اصلاً موضوعیت ندارد.
#
# نکته‌ی مهم درباره‌ی PID: برخلاف pppd (که یک پردازش جدا و زنده به‌ازای هر
# سشن است و PID آن تا پایان اتصال باقی می‌ماند)، accel-ppp یک پردازش واحد
# است که این اسکریپت را فقط به‌صورت لحظه‌ای/کوتاه fork می‌کند - PID همین
# اسکریپت بلافاصله بعد از اجرا از بین می‌رود و هیچ ربطی به طول عمر خودِ سشن
# ندارد. برای همین (برخلاف ppp_ip_up.sh) پیدی به بک‌اند فرستاده نمی‌شود؛
# قطع سشن‌های SSTP فقط با رویداد ip-down (که accel-ppp همیشه و به‌صورت
# داخلی/قابل‌اعتماد صدا می‌زند، نه از طریق دیسپچر جدای run-parts) یا با
# پایین‌آمدن کامل سرویس accel-ppp-sstp (چک‌شده توسط reconcile_protocol_services
# در scheduler.py) بسته می‌شود.

source /opt/vpn-panel/panel.env
BACKEND_PORT="${BACKEND_PORT:-8000}"
source /opt/vpn-panel/scripts/admission_guard.sh

IFACE="$1"
TUNNEL_IP="$5"
REMOTE_IP="${6:-$5}"
USERNAME="${PEERNAME}"

if [ -z "$USERNAME" ]; then
  exit 0
fi

PAYLOAD="{\"username\":\"${USERNAME}\",\"protocol\":\"sstp\",\"ip_address\":\"${REMOTE_IP}\",\"interface\":\"${IFACE}\",\"tunnel_ip\":\"${TUNNEL_IP}\",\"pid\":null}"
if ! vpn_panel_admission_request "$PAYLOAD" "$USERNAME" "sstp" "$REMOTE_IP"; then
  python3 - "$IFACE" <<'PYCLI' >/dev/null 2>&1 || true
import socket, sys
iface = sys.argv[1]
with socket.create_connection(("127.0.0.1", 2001), timeout=3) as sock:
    sock.sendall((f"terminate if {iface} hard\nexit\n").encode())
PYCLI
  exit 1
fi

if [ -x /opt/vpn-panel/scripts/ensure_session_networking.sh ]; then
  /opt/vpn-panel/scripts/ensure_session_networking.sh --up sstp "$IFACE" "$TUNNEL_IP" >/dev/null 2>&1 || true
fi

exit 0
