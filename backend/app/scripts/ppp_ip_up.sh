#!/bin/bash
# این اسکریپت باید در /etc/ppp/ip-up.d/ قرار بگیرد (اسکریپت نصب این کار را انجام می‌دهد)
# پارامترهای pppd: $1=interface $2=tty $3=speed $4=local-ip $5=remote-ip $6=ipparam
# متغیر PEERNAME توسط pppd هنگام استفاده از chap-secrets ست می‌شود (نام کاربری)

source /opt/vpn-panel/panel.env
BACKEND_PORT="${BACKEND_PORT:-8000}"
source /opt/vpn-panel/scripts/admission_guard.sh

IFACE="$1"
TUNNEL_IP="$5"
# $5 (remote-ip) آدرس داخلیِ تونل است که به پیر تخصیص داده شده (مثلاً
# 10.8.x.x)، نه آی‌پی پابلیک واقعی کلاینت - قبلاً این مقدار اشتباهی به‌عنوان
# "آی‌پی کاربر" ذخیره می‌شد. هم xl2tpd و هم pptpd به‌صورت پیش‌فرض آی‌پی
# پابلیک واقعی کلاینت را در $6 (ipparam) به اسکریپت‌های ip-up می‌فرستند
# (در pptpd این رفتار با noipparam قابل غیرفعال‌سازی است، ولی پیش‌فرض روشن
# است)؛ همان مقدار درست است. اگر به هر دلیلی خالی بود (مثلاً noipparam ست
# شده)، برای اینکه چیزی از دست نرود به آی‌پی تونلی برمی‌گردیم.
REMOTE_IP="${6:-$5}"
if [ -z "$6" ]; then
  # اگر اینجا رسیدیم یعنی xl2tpd/pptpd به هر دلیلی ipparam را پر نفرستاده و
  # آی‌پی داخلی تونل ($5، مثلاً ${L2TP_SUBNET:-10.x.x}.x) به‌جای آی‌پی پابلیک
  # واقعی کلاینت ذخیره می‌شود - دقیقاً همان باگ قدیمی. این خط فقط لاگ می‌کند
  # (رفتار را تغییر نمی‌دهد) تا با «journalctl -t vpn-panel» فوراً قابل تشخیص
  # باشد که چرا یک سشن با آی‌پی داخلی (نه پابلیک) ثبت شده - مثلاً روی نصب‌های
  # روی نصب‌های خیلی قدیمی که با pptpd سرکار دارند: اگر noipparam صراحتاً
  # روی pptpd ست شده باشد. (برای xl2tpd این با گزینه‌ی "pass peer = yes" در
  # [lns default] تضمین می‌شود - نصب/آپدیت پنل این را ست می‌کند.)
  logger -t vpn-panel "ppp_ip_up: ipparam (\$6) خالی بود، به آی‌پی داخلی تونل ($5) برای کاربر ${PEERNAME} برگشت داده شد - آی‌پی پابلیک واقعی ثبت نشد"
fi
USERNAME="${PEERNAME}"

if [ -z "$USERNAME" ]; then
  exit 0
fi

# --- پیدا کردن pid واقعیِ pppd و پروتکل واقعی -------------------------------
# قبلاً فرض شده بود که $PPID همین‌جا مستقیماً pid خودِ pppd است (پدرِ بی‌واسطه‌ی
# این اسکریپت). این فرض روی Ubuntu درست نیست: دیسپچرِ /etc/ppp/ip-up اسکریپت‌های
# داخل ip-up.d/ (از جمله همین اسکریپت) را با «run-parts» اجرا می‌کند، پس پدرِ
# بی‌واسطه‌ی این اسکریپت خودِ run-parts است، نه pppd - و چون run-parts بلافاصله
# بعد از اجرای همه‌ی اسکریپت‌ها می‌میرد، pidِ اشتباهی که ذخیره می‌شد خیلی زود
# «مرده» به‌نظر می‌رسید و جاب پس‌زمینه‌ی پنل (reconcile_ppp_sessions) بلافاصله
# همان سشن را دوباره «آفلاین» علامت می‌زد - دقیقاً همان باگِ «کاربر آنلاین
# L2TP نشان داده نمی‌شود» (روی OpenVPN اثر نمی‌گذاشت چون آن یک اسکریپت کاملاً
# جدا دارد). راه‌حل: به‌جای اعتماد به $PPID، از روی /proc درخت پردازش‌ها را
# بالا می‌رویم تا خودِ pppd را پیدا کنیم، و بعد پدرِ pppd (xl2tpd یا pptpd) را
# برای تشخیص درست پروتکل چک می‌کنیم.
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
# اگر به هر دلیلی (مثلاً یک توزیع دیگر که همین اسکریپت را مستقیماً از pppd
# اجرا می‌کند) پیدا نشد، به رفتار قبلی ($PPID) برمی‌گردیم - بی‌ضرر.
[ -z "$PPPD_PID" ] && PPPD_PID="$PPID"

PROTOCOL="l2tp"
DAEMON_PID=$(get_ppid "$PPPD_PID")
if [ -n "$DAEMON_PID" ]; then
  DAEMON_CMD=$(get_comm "$DAEMON_PID")
  if echo "$DAEMON_CMD" | grep -qi "pptp"; then
    PROTOCOL="pptp"
  fi
fi

# --- تشخیص پلتفرم کلاینت L2TP از روی AVPهای Host Name/Vendor Name -----------
# هر کلاینت L2TP هنگام برقراری تونل (پیام SCCRQ) می‌تواند این دو AVP اختیاری
# را بفرستد تا پیاده‌سازی خودش را معرفی کند. روترهای MikroTik هر دو را دقیقاً
# "MikroTik" می‌فرستند - همین‌جا آن را می‌گیریم. با «debug avp = yes» در
# xl2tpd.conf ([global] - نصب/آپدیت پنل این را تنظیم می‌کند)، xl2tpd مقدار
# این AVPها را در syslog/journal چاپ می‌کند؛ اینجا آخرین چنین خطی که همین
# چند ثانیه‌ی اخیر (یعنی هم‌زمان با همین تونل) لاگ شده را می‌خوانیم.
# محدودیت‌ها: ۱) خیلی از کلاینت‌های دیگر (ویندوز/iOS/اندروید) اصلاً این
# AVPها را نمی‌فرستند یا مقدار بی‌فایده‌ای می‌گذارند - در آن صورت پلتفرم خالی
# می‌ماند (حدس زده نمی‌شود). ۲) این مقدار را خودِ کلاینت اعلام می‌کند (دقیقاً
# مثل IV_PLAT در OpenVPN)، پس قابل جعل است - برای نمایش اطلاعاتی است، نه
# تصمیم امنیتی. ۳) فقط برای L2TP معناست، چون فقط xl2tpd این AVPها را لاگ
# می‌کند (pptpd چنین لاگی ندارد).
PLATFORM=""
if [ "$PROTOCOL" = "l2tp" ]; then
  AVP_LOG=""
  if command -v journalctl >/dev/null 2>&1; then
    AVP_LOG=$(journalctl -t xl2tpd --no-pager -q --since "-8sec" 2>/dev/null \
      | grep -E "vendor_avp: peer reports vendor|hostname_avp: peer reports hostname" | tail -n 4)
  fi
  if [ -z "$AVP_LOG" ] && [ -f /var/log/syslog ]; then
    AVP_LOG=$(tail -n 400 /var/log/syslog 2>/dev/null \
      | grep -E "xl2tpd.*(vendor_avp: peer reports vendor|hostname_avp: peer reports hostname)" | tail -n 4)
  fi
  if [ -n "$AVP_LOG" ]; then
    # DUX28/xl2tpd معمولاً Vendor عمومیِ xelerance.com و Hostname عمومیِ
    # OpenWrt می‌فرستد؛ این دو نام، مدل دستگاه نیستند. مدل این فریمور در
    # بعضی بیلدها داخل hostname می‌آید و در بعضی بیلدها فقط همان امضاهای
    # عمومی دیده می‌شوند. برای این خانواده برچسب واقعی و یکسان DUX28 را
    # ثبت می‌کنیم تا پنل OpenWrt/xelerance.com را به‌عنوان «پلتفرم» نشان ندهد.
    VENDOR_PLATFORM=$(echo "$AVP_LOG" | grep "vendor_avp" | tail -n1 | sed -E "s/.*vendor '([^']*)'.*/\1/")
    HOST_PLATFORM=$(echo "$AVP_LOG" | grep "hostname_avp" | tail -n1 | sed -E "s/.*hostname '([^']*)'.*/\1/")
    PLATFORM="${VENDOR_PLATFORM:-$HOST_PLATFORM}"
    PLATFORM_SIGNATURE=$(printf '%s %s' "$VENDOR_PLATFORM" "$HOST_PLATFORM" | tr '[:upper:]' '[:lower:]')
    if echo "$PLATFORM_SIGNATURE" | grep -Eq 'dux[ _.-]*28|(^|[[:space:]])openwrt([[:space:]]|$)|xelerance\.com'; then
      PLATFORM="DUX28"
    fi
    # پاکسازی برای امنیت JSON: فقط حروف/عدد/فاصله/چندتا نویسه‌ی بی‌خطر مجازند
    PLATFORM=$(echo "$PLATFORM" | tr -dc 'A-Za-z0-9 ._-')
  fi
fi

# A physical PPP hook can be invoked more than once on upgraded systems when a
# legacy ip-up.d copy is still present.  Guard the *pppd process instance* (PID
# plus /proc start time), not only the interface name which can be reused.
mkdir -p /run/vpn-panel/ppp-hooks 2>/dev/null || true
PPPD_START=$(awk '{print $22}' "/proc/${PPPD_PID}/stat" 2>/dev/null || echo unknown)
HOOK_MARKER="/run/vpn-panel/ppp-hooks/${PPPD_PID}-${PPPD_START}.up"
if ! ( set -o noclobber; : > "$HOOK_MARKER" ) 2>/dev/null; then
  # The canonical/legacy sibling already admitted this exact pppd.  Reassert
  # routing only; never create another DB row and never let a second hook kill
  # the live session as a duplicate reconnect.
  if [ -x /opt/vpn-panel/scripts/ensure_session_networking.sh ]; then
    /opt/vpn-panel/scripts/ensure_session_networking.sh --up "$PROTOCOL" "$IFACE" "$TUNNEL_IP" >/dev/null 2>&1 || true
  fi
  exit 0
fi

PAYLOAD="{\"username\":\"${USERNAME}\",\"protocol\":\"${PROTOCOL}\",\"ip_address\":\"${REMOTE_IP}\",\"interface\":\"${IFACE}\",\"tunnel_ip\":\"${TUNNEL_IP}\",\"pid\":${PPPD_PID},\"platform\":\"${PLATFORM}\"}"
if ! vpn_panel_admission_request "$PAYLOAD" "$USERNAME" "$PROTOCOL" "$REMOTE_IP"; then
  rm -f "$HOOK_MARKER" 2>/dev/null || true
  kill -TERM "$PPPD_PID" 2>/dev/null || true
  exit 1
fi

# Do not rely only on the API's detached best-effort repair. This hook is run by
# root-owned pppd and can make the new PPP interface usable before ip-up returns.
# The helper is idempotent and also installs the provider policy-route mark when
# the VPS default route is not in the main table.
if [ -x /opt/vpn-panel/scripts/ensure_session_networking.sh ]; then
  TRANSITION="fresh"
  [ "${VPN_PANEL_ADMISSION_HANDOVER:-0}" = "1" ] && TRANSITION="handover"
  /opt/vpn-panel/scripts/ensure_session_networking.sh --up "$PROTOCOL" "$IFACE" "$TUNNEL_IP" "$TRANSITION" >/dev/null 2>&1 || true
fi

exit 0
