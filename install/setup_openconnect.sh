#!/bin/bash
###############################################################################
# OpenConnect (ocserv) infrastructure setup (standalone, isolated from the
# rest of the panel) - سرور OpenConnect سازگار با کلاینت رسمی Cisco AnyConnect
# و کلاینت متن‌باز OpenConnect.
#
# این اسکریپت فقط «زیرساخت» OpenConnect را روی سرور بالا می‌آورد؛ به
# بک‌اند/فرانت‌اند پنل و به مدیریت کاربران دست نمی‌زند. به‌صورت خودکار از
# داخل install.sh و update.sh هم صدا زده می‌شود (idempotent است، پس اجرای
# مجدد از هر جا مشکلی ندارد)؛ برای نصب/تلاش مجدد دستی هم می‌توانید مستقیماً
# همین فایل را اجرا کنید.
#
# برخلاف SSTP (accel-ppp، که باید از سورس کامپایل شود)، ocserv در ریپازیتوری
# رسمی اوبونتو (universe) موجود است - نصب مستقیم با apt.
#
# احراز هویت: فایل پسورد به فرمت ocpasswd (ماژول "plain" خودِ ocserv)، که
# توسط بک‌اند پنل (vpn_manager.sync_openconnect_secrets) از روی دیتابیس
# ساخته/به‌روز می‌شود - جدا از chap-secrets/ipsec.secrets، مشابه همان الگویی
# که SSTP/IKEv2 دارند.
#
# Usage:
#   sudo bash setup_openconnect.sh [--force] [--configure-only] \
#       [--port=8443] [--dns1=8.8.8.8] [--dns2=1.1.1.1]
#
# --configure-only is used by the panel for runtime edits: it never runs apt
# and fails cleanly when ocserv has not been installed yet.
###############################################################################
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -r "$SCRIPT_DIR/apt_preflight.sh" ]; then
  # shellcheck source=apt_preflight.sh
  source "$SCRIPT_DIR/apt_preflight.sh"
fi

if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root (sudo bash setup_openconnect.sh)"
  exit 1
fi

FORCE=0
CONFIGURE_ONLY=0
# پیش‌فرض 8443 - نه 443 (رزرو nginx/پنل) و نه 4433 (رزرو SSTP در
# setup_sstp.sh). قابل تغییر با --port=NNNN (از پنل: Settings > پروتکل‌ها)؛
# OpenConnect هم روی TCP و هم روی UDP (DTLS، برای سرعت بهتر) روی همین
# شماره‌پورت گوش می‌دهد.
OCSERV_PORT="8443"
# DNSی که به کلاینت‌های OpenConnect داده می‌شود - قابل تغییر با --dns1=/--dns2=
# (از پنل: Settings > پروتکل‌ها). DNS2 اختیاری است؛ خالی گذاشتنش یعنی فقط یک
# DNS به کلاینت داده شود.
OCSERV_DNS1="8.8.8.8"
OCSERV_DNS2="1.1.1.1"
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=1 ;;
    --configure-only) CONFIGURE_ONLY=1 ;;
    --port=*) OCSERV_PORT="${arg#--port=}" ;;
    --dns1=*) OCSERV_DNS1="${arg#--dns1=}" ;;
    --dns2=*) OCSERV_DNS2="${arg#--dns2=}" ;;
  esac
done
if ! [[ "$OCSERV_PORT" =~ ^[0-9]+$ ]] || [ "$OCSERV_PORT" -lt 1 ] || [ "$OCSERV_PORT" -gt 65535 ]; then
  echo "Invalid --port value: $OCSERV_PORT" >&2
  exit 1
fi
DNS_ADDR_RE='^[0-9a-fA-F:.]+$'
if [ -n "$OCSERV_DNS1" ] && ! [[ "$OCSERV_DNS1" =~ $DNS_ADDR_RE ]]; then
  echo "Invalid --dns1 value: $OCSERV_DNS1" >&2
  exit 1
fi
if [ -n "$OCSERV_DNS2" ] && ! [[ "$OCSERV_DNS2" =~ $DNS_ADDR_RE ]]; then
  echo "Invalid --dns2 value: $OCSERV_DNS2" >&2
  exit 1
fi
OCSERV_SUBNET="192.168.46"
CONF_DIR="/etc/ocserv"
CERT_DIR="${CONF_DIR}/ocserv-certs"
PASSWD_FILE="${CONF_DIR}/ocpasswd"
SCRIPTS_DIR="/opt/vpn-panel/scripts"

# ---------------------------------------------------------------------------
# آی‌پی عمومی سرور را برای گواهی تشخیص می‌دهیم (کلاینت‌های AnyConnect/
# OpenConnect با همین IP یا دامنه به سرور وصل می‌شوند، پس باید داخل SAN
# گواهی باشد).
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
# گواهی TLS سرور ocserv را می‌سازد (یا اگر Let's Encrypt موجود باشد، همان را
# کپی می‌کند). دقیقاً همان الگوی ensure_sstp_cert در setup_sstp.sh - بدون SAN
# صحیح، کلاینت‌های AnyConnect/OpenConnect گواهی را رد می‌کنند.
# ---------------------------------------------------------------------------
ensure_ocserv_cert() {
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
    if ! openssl x509 -in "$CERT_DIR/fullchain.pem" -noout -ext subjectAltName 2>/dev/null | grep -q "IP Address\|DNS"; then
      echo "[*] گواهی موجود فاقد SAN است - در حال ساخت دوباره..."
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
    return 2
  fi
  echo "[*] گواهی OpenConnect معتبر است و نیازی به ساخت دوباره نیست."
  return 0
}

if [ "$CONFIGURE_ONLY" = "1" ]; then
  # Runtime settings changes (port/DNS and the one-click 443 migration) must be
  # fast and must not enter apt/dpkg.  Installation is a separate explicit
  # action in Protocol Center.
  if ! command -v ocserv >/dev/null 2>&1 || ! systemctl cat ocserv >/dev/null 2>&1; then
    echo "ERROR: ocserv is not installed; install it from Protocol Center first" >&2
    exit 1
  fi
  echo "[*] ocserv is installed; applying configuration only..."
else
  echo "[*] Installing/verifying ocserv packages..."
  export DEBIAN_FRONTEND=noninteractive
  wait_for_apt() {
    if declare -F vpn_panel_wait_for_apt_lock >/dev/null 2>&1; then
      vpn_panel_wait_for_apt_lock 600
      vpn_panel_repair_dpkg
    else
      while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do sleep 2; done
      dpkg --force-confdef --force-confold --configure -a
    fi
  }
  wait_for_apt
  if [ "${SKIP_APT_UPDATE:-0}" != "1" ]; then vpn_panel_apt_get update; fi
  vpn_panel_install_packages ocserv gnutls-bin iptables-persistent
fi

# On a fresh/full install stop the package's stock service before replacing
# its configuration.  Runtime edits deliberately keep the existing service
# alive until the new file is ready, minimizing downtime and avoiding a
# stopped service if validation fails before restart.
if [ "$CONFIGURE_ONLY" != "1" ]; then
  systemctl stop ocserv >/dev/null 2>&1 || true
fi

mkdir -p "$CONF_DIR" "$CERT_DIR"
touch "$PASSWD_FILE"
chmod 600 "$PASSWD_FILE"
chown root:root "$PASSWD_FILE"

# پوشه‌ی chroot سرویس (chroot-dir در کانفیگ پایین‌تر) - معمولاً توسط
# post-install پکیج ocserv ساخته می‌شود، اما روی بعضی سرورها (مثلاً اگر
# قبلاً پاک شده یا پکیج ناقص نصب شده) وجود ندارد و بدون آن ocserv با خطای
# "cannot chdir to /var/lib/ocserv" بلافاصله بعد از استارت fail می‌کند.
mkdir -p /var/lib/ocserv/run
chown -R nobody:daemon /var/lib/ocserv

PORT_CHANGED=0
OLD_PORT=""
CONF_BACKUP=""
if [ -f "${CONF_DIR}/ocserv.conf" ]; then
  OLD_PORT=$(grep -oP '^tcp-port = \K[0-9]+' "${CONF_DIR}/ocserv.conf" 2>/dev/null || true)
  if ! grep -q "^tcp-port = ${OCSERV_PORT}$" "${CONF_DIR}/ocserv.conf" 2>/dev/null; then
    PORT_CHANGED=1
  fi
  # از کانفیگ فعلی (که تا همین لحظه واقعاً روی سرور کار می‌کرد) یک نسخه‌ی
  # پشتیبان می‌گیریم تا اگر پورت/تنظیمات جدید سرویس را بالا نیاورد، دقیقاً
  # همین را (با همان پورت قبلی که فعال بود) برگردانیم - نه این‌که کانفیگ
  # جدیدِ خراب روی سرور بماند و فقط یک اخطار چاپ شود.
  CONF_BACKUP=$(mktemp /tmp/ocserv.conf.XXXXXX)
  cp "${CONF_DIR}/ocserv.conf" "$CONF_BACKUP"
fi

echo "[*] Preparing TLS certificate for OpenConnect..."
set +e
ensure_ocserv_cert
cert_changed=$?
set -e

echo "[*] Writing ocserv config..."
# Existing panel-managed configurations may contain low-level custom settings
# edited from the Protocol Center.  Do not replace the whole file when only
# port/DNS is changed; update the required managed directives and preserve all
# unrelated lines.  A stock package config (without our hooks) is replaced by
# the known-good panel template on first setup.
if [ -s "${CONF_DIR}/ocserv.conf" ] && grep -qE '^connect-script = .*/openconnect_connect\.sh$|^# VPN PANEL MANAGED OCSERV$' "${CONF_DIR}/ocserv.conf"; then
  python3 - "${CONF_DIR}/ocserv.conf" "$OCSERV_PORT" "$OCSERV_DNS1" "$OCSERV_DNS2" "$PASSWD_FILE" "$CERT_DIR" "$SCRIPTS_DIR" <<'PYOCSERV'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
port, dns1, dns2, passwd, cert_dir, scripts_dir = sys.argv[2:]
managed = [
    f'auth = "plain[passwd={passwd}]"',
    f'tcp-port = {port}',
    f'udp-port = {port}',
    'run-as-user = nobody',
    'run-as-group = daemon',
    'socket-file = /run/ocserv-socket',
    'chroot-dir = /var/lib/ocserv',
    f'server-cert = {cert_dir}/fullchain.pem',
    f'server-key = {cert_dir}/privkey.pem',
    'use-occtl = true',
    'device = vpns',
    'mtu = 1350',
    'route = default',
    'tunnel-all-dns = true',
    'switch-to-tcp-timeout = 8',
    f'connect-script = {scripts_dir}/openconnect_connect.sh',
    f'disconnect-script = {scripts_dir}/openconnect_disconnect.sh',
]
keys = {
    'auth', 'tcp-port', 'udp-port', 'run-as-user', 'run-as-group',
    'socket-file', 'chroot-dir', 'server-cert', 'server-key', 'use-occtl',
    'device', 'mtu', 'route', 'tunnel-all-dns', 'switch-to-tcp-timeout',
    'connect-script', 'disconnect-script',
}
out = []
in_dns_block = False
for raw in path.read_text(encoding='utf-8', errors='replace').splitlines():
    line = raw.strip()
    if line == '# BEGIN VPN PANEL DNS':
        in_dns_block = True
        continue
    if line == '# END VPN PANEL DNS':
        in_dns_block = False
        continue
    if in_dns_block:
        continue
    match = re.match(r'^([A-Za-z0-9_-]+)\s*=.*$', line)
    if match and match.group(1) in keys:
        continue
    # Migrate old panel versions that wrote unmarked DNS directives.
    if re.match(r'^dns\s*=.*$', line):
        continue
    if line == '# VPN PANEL MANAGED OCSERV':
        continue
    out.append(raw)

while out and not out[-1].strip():
    out.pop()
out.extend(['', '# VPN PANEL MANAGED OCSERV', *managed, '', '# BEGIN VPN PANEL DNS'])
if dns1:
    out.append(f'dns = {dns1}')
if dns2:
    out.append(f'dns = {dns2}')
out.extend(['# END VPN PANEL DNS', ''])
path.write_text('\n'.join(out), encoding='utf-8')
PYOCSERV
else
  cat > "${CONF_DIR}/ocserv.conf" << EOF
# VPN PANEL MANAGED OCSERV
auth = "plain[passwd=${PASSWD_FILE}]"

tcp-port = ${OCSERV_PORT}
udp-port = ${OCSERV_PORT}
run-as-user = nobody
run-as-group = daemon
socket-file = /run/ocserv-socket
chroot-dir = /var/lib/ocserv

# روی بعضی کرنل/glibc های جدیدتر (مثلاً Ubuntu 22.04 با کرنل 5.15)،
# sandbox سکامپِ isolate-workers باعث می‌شود worker درست بعد از accept
# کردن اتصال، وسط هندشیک TLS کرش کند (در لاگ: "The futex facility
# returned an unexpected error code")؛ برای کلاینت این دقیقاً شبیه تایم‌اوت/
# قطع ناگهانی SSL دیده می‌شود. غیرفعال کردنش این مشکل را حل می‌کند.
isolate-workers = false
max-clients = 0
max-same-clients = 0
server-cert = ${CERT_DIR}/fullchain.pem
server-key = ${CERT_DIR}/privkey.pem

# با interval=2/timeout=6 قطع واقعی مشتری حداکثر چند ثانیه طول می‌کشد -
# هم‌راستا با سایر پروتکل‌های پنل (L2TP/PPTP/OpenVPN/SSTP).
keepalive = 32400
dpd = 90
mobile-dpd = 1800
try-mtu-discovery = true
switch-to-tcp-timeout = 8

cert-user-oid = 0.9.2342.19200300.100.1.1
tls-priorities = "NORMAL:%SERVER_PRECEDENCE:%COMPAT"
auth-timeout = 40
min-reauth-time = 5
max-ban-score = 80
ban-reset-time = 1200
cookie-timeout = 300
deny-roaming = false
rekey-time = 172800
rekey-method = ssl
use-occtl = true
pid-file = /run/ocserv.pid
device = vpns
predictable-ips = true
default-domain = openconnect.local
ipv4-network = ${OCSERV_SUBNET}.0
ipv4-netmask = 255.255.255.0
$( [ -n "$OCSERV_DNS1" ] && echo "dns = ${OCSERV_DNS1}" )
$( [ -n "$OCSERV_DNS2" ] && echo "dns = ${OCSERV_DNS2}" )
ping-leases = false
mtu = 1350
route = default
tunnel-all-dns = true

# این دو اسکریپت مستقیماً توسط ocserv (نه از طریق pppd/run-parts) به‌ازای هر
# اتصال/قطع واقعی صدا زده می‌شوند و رویداد را به API داخلی پنل گزارش
# می‌کنند - دقیقاً همان الگوی [pppd-compat] در accel-ppp/sstp.conf.
connect-script = ${SCRIPTS_DIR}/openconnect_connect.sh
disconnect-script = ${SCRIPTS_DIR}/openconnect_disconnect.sh

compression = false
EOF
fi

# چک می‌کند که سرویس واقعاً بالا مانده (نه فقط لحظه‌ی استارت) و واقعاً روی
# پورت درخواستی گوش می‌دهد. چند بار با فاصله چک می‌شود چون گاهی سرویس
# بلافاصله استارت می‌خورد ولی چند ثانیه بعد (مثلاً به‌خاطر تصادم پورت با
# پردازش دیگر، یا خطای کانفیگ) کرش می‌کند و systemd آن را failed می‌کند.
verify_ocserv_up() {
  local expected_port="${1:-$OCSERV_PORT}"
  local i
  for i in 1 2 3; do
    if ! systemctl is-active --quiet ocserv; then
      return 1
    fi
    sleep 1
  done
  if command -v ss >/dev/null 2>&1; then
    if ! ss -ltn 2>/dev/null | grep -q ":${expected_port} "; then
      return 1
    fi
  fi
  return 0
}

echo "[*] Enabling and (re)starting ocserv..."
systemctl daemon-reload
systemctl enable ocserv >/dev/null 2>&1 || true
RESTARTED=0
if ! systemctl is-active --quiet ocserv || [ "$cert_changed" = "2" ] || [ "$FORCE" = "1" ] || [ "$PORT_CHANGED" = "1" ]; then
  systemctl restart ocserv || true
  RESTARTED=1
fi

if [ "$RESTARTED" = "1" ] && ! verify_ocserv_up "$OCSERV_PORT"; then
  echo "" >&2
  echo "[!] خطا: سرویس OpenConnect (ocserv) روی پورت ${OCSERV_PORT} بالا نیامد" >&2
  echo "    (احتمالاً پورت توسط سرویس دیگری اشغال شده یا کانفیگ ناسازگار است)." >&2
  echo "    جزئیات: systemctl status ocserv / journalctl -u ocserv --no-pager -n 50" >&2
  if [ -n "$CONF_BACKUP" ] && [ -n "$OLD_PORT" ]; then
    echo "[*] در حال بازگردانی به پیکربندی/پورت قبلی که فعال بود (${OLD_PORT})..." >&2
    cp "$CONF_BACKUP" "${CONF_DIR}/ocserv.conf"
    systemctl restart ocserv >/dev/null 2>&1 || true
    if verify_ocserv_up "$OLD_PORT"; then
      echo "[*] سرویس OpenConnect با موفقیت روی پورت قبلی (${OLD_PORT}) دوباره بالا آمد." >&2
    else
      echo "[!] بازگردانی به پورت قبلی هم ناموفق بود؛ سرویس OpenConnect در حال حاضر پایین است." >&2
    fi
  else
    echo "[!] پیکربندی قبلی‌ای برای بازگردانی وجود نداشت (اولین نصب) - سرویس OpenConnect پایین ماند." >&2
  fi
  rm -f "$CONF_BACKUP" 2>/dev/null || true
  exit 1
fi
rm -f "$CONF_BACKUP" 2>/dev/null || true

echo "[*] Configuring NAT/forwarding for the live OpenConnect subnet..."
NET_IFACE=$(ip -4 route show default 2>/dev/null | awk '$1=="default" {print $5; exit}')
sysctl -w net.ipv4.ip_forward=1 >/dev/null
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1 || true
grep -q '^net.ipv4.ip_forward=1' /etc/sysctl.conf || echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.conf

# Existing installations may intentionally use a custom pool. Read the CIDR
# from the configuration we just preserved/wrote instead of assuming the new
# installer default (192.168.46.0/24).
ACTIVE_OCSERV_CIDR=$(python3 - "${CONF_DIR}/ocserv.conf" <<'PYOCNET'
from pathlib import Path
import ipaddress, sys
vals = {}
for raw in Path(sys.argv[1]).read_text(encoding='utf-8', errors='replace').splitlines():
    line = raw.strip()
    if not line or line.startswith('#') or '=' not in line:
        continue
    key, value = (part.strip() for part in line.split('=', 1))
    if key in {'ipv4-network', 'ipv4-netmask'}:
        vals[key] = value.strip('"\'')
network = vals.get('ipv4-network', '')
mask = vals.get('ipv4-netmask', '255.255.255.0')
try:
    candidate = network if '/' in network else f"{network}/{mask}"
    print(ipaddress.ip_network(candidate, strict=False))
except Exception:
    pass
PYOCNET
)
[ -n "$ACTIVE_OCSERV_CIDR" ] || ACTIVE_OCSERV_CIDR="${OCSERV_SUBNET}.0/24"

iptables -t nat -C POSTROUTING -s "$ACTIVE_OCSERV_CIDR" -o "${NET_IFACE}" -j MASQUERADE 2>/dev/null || \
  iptables -t nat -I POSTROUTING 1 -s "$ACTIVE_OCSERV_CIDR" -o "${NET_IFACE}" -m comment --comment "vpnpanel-openconnect-nat" -j MASQUERADE
iptables -C FORWARD -s "$ACTIVE_OCSERV_CIDR" -o "${NET_IFACE}" -m comment --comment "vpnpanel-openconnect-forward-out-live" -j ACCEPT 2>/dev/null || \
  iptables -I FORWARD 1 -s "$ACTIVE_OCSERV_CIDR" -o "${NET_IFACE}" -m comment --comment "vpnpanel-openconnect-forward-out-live" -j ACCEPT
iptables -C FORWARD -d "$ACTIVE_OCSERV_CIDR" -i "${NET_IFACE}" -m conntrack --ctstate ESTABLISHED,RELATED \
  -m comment --comment "vpnpanel-openconnect-forward-in-live" -j ACCEPT 2>/dev/null || \
  iptables -I FORWARD 1 -d "$ACTIVE_OCSERV_CIDR" -i "${NET_IFACE}" -m conntrack --ctstate ESTABLISHED,RELATED \
    -m comment --comment "vpnpanel-openconnect-forward-in-live" -j ACCEPT
iptables -t mangle -C FORWARD -s "$ACTIVE_OCSERV_CIDR" -p tcp --tcp-flags SYN,RST SYN \
  -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
  iptables -t mangle -A FORWARD -s "$ACTIVE_OCSERV_CIDR" -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --clamp-mss-to-pmtu
netfilter-persistent save >/dev/null 2>&1 || true

echo "[*] OpenConnect routed subnet: ${ACTIVE_OCSERV_CIDR} via ${NET_IFACE}"

echo "[*] Opening tcp+udp/${OCSERV_PORT} on the host firewall (if one is active)..."
FW_TAG="vpnpanel-openconnect"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "^Status: active"; then
  while true; do
    rule_num=$(ufw status numbered 2>/dev/null | grep "# ${FW_TAG}$" | tail -n1 | grep -oE '^\[[0-9]+\]' | tr -d '[]')
    [ -z "$rule_num" ] && break
    yes | ufw delete "$rule_num" >/dev/null 2>&1 || break
  done
  ufw allow "${OCSERV_PORT}/tcp" comment "${FW_TAG}" >/dev/null 2>&1 || true
  ufw allow "${OCSERV_PORT}/udp" comment "${FW_TAG}" >/dev/null 2>&1 || true
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q "running"; then
  if [ -n "$OLD_PORT" ] && [ "$OLD_PORT" != "$OCSERV_PORT" ]; then
    firewall-cmd --permanent --remove-port="${OLD_PORT}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --permanent --remove-port="${OLD_PORT}/udp" >/dev/null 2>&1 || true
  fi
  firewall-cmd --permanent --add-port="${OCSERV_PORT}/tcp" >/dev/null 2>&1 || true
  firewall-cmd --permanent --add-port="${OCSERV_PORT}/udp" >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
elif command -v iptables >/dev/null 2>&1; then
  if command -v iptables-save >/dev/null 2>&1; then
    while IFS= read -r rule; do
      [ -z "$rule" ] && continue
      del_rule="${rule/-A INPUT/-D INPUT}"
      # shellcheck disable=SC2086
      iptables $del_rule 2>/dev/null || true
    done < <(iptables-save 2>/dev/null | grep -- "--comment \"${FW_TAG}\"")
  fi
  iptables -I INPUT -p tcp --dport "${OCSERV_PORT}" -m comment --comment "${FW_TAG}" -j ACCEPT
  iptables -I INPUT -p udp --dport "${OCSERV_PORT}" -m comment --comment "${FW_TAG}" -j ACCEPT
  netfilter-persistent save >/dev/null 2>&1 || true
else
  echo "    NOTE: no supported firewall tool (ufw/firewalld/iptables) detected - open tcp+udp/${OCSERV_PORT} yourself." >&2
fi

# Every `iptables -I INPUT` inserts above the existing first rule.  Keep the
# panel's IP-ban chain at rule 1 so an OpenConnect ACCEPT rule can never bypass
# a ban after port/DNS changes or a reinstall.
if command -v iptables >/dev/null 2>&1 && iptables -C INPUT -j VPN-PANEL-BANS 2>/dev/null; then
  iptables -D INPUT -j VPN-PANEL-BANS 2>/dev/null || true
  iptables -I INPUT 1 -j VPN-PANEL-BANS
  command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
fi

echo ""
echo "=============================================================="
echo " OpenConnect (ocserv) infrastructure is up."
echo "   - Port:      tcp+udp/${OCSERV_PORT}  (make sure it's open in your"
echo "                firewall/security group. Default is 8443, not 443,"
echo "                because 443 is reserved for the panel's own HTTPS"
echo "                (nginx) and 4433 is reserved for SSTP."
echo "   - Subnet:    ${ACTIVE_OCSERV_CIDR:-${OCSERV_SUBNET}.0/24}"
echo "   - DNS:       ${OCSERV_DNS1}${OCSERV_DNS2:+, ${OCSERV_DNS2}}"
echo "   - Users:     dedicated ocpasswd file (${PASSWD_FILE}), kept in"
echo "                sync with the panel database automatically."
echo "   - Cert:      ${CERT_DIR}/fullchain.pem"
echo "   - Config:    ${CONF_DIR}/ocserv.conf"
echo "   - Service:   systemctl status ocserv"
echo "=============================================================="
