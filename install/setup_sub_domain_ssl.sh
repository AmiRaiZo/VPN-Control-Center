#!/bin/bash
###############################################################################
# Called by the panel backend (as root) when the admin sets a domain under
# Settings > دامنه‌ی اختصاصیِ لینک اشتراک. Issues a Let's Encrypt certificate
# for this sub-domain via certbot and creates a SEPARATE, independent Nginx
# vhost (vpn-panel-sub) that serves ONLY the public /sub/<token> subscription
# page + its API, over HTTPS.
#
# IMPORTANT: this script never touches /etc/nginx/sites-available/vpn-panel
# (the panel's own domain vhost, managed by setup_domain_ssl.sh). The two
# vhosts live side by side, each locked to its own server_name/domain, so a
# subscription link never shares a hostname with the admin login page.
#
# پورت HTTPS این ووهاست پیش‌فرض 443 است ولی قابل تغییر است (آرگومان دوم -
# از پنل: Settings > دامنه‌ی اختصاصیِ لینک اشتراک). اگر پورتی غیر از 443
# انتخاب شود، nginx دیگر اصلاً روی 443 برای این دامنه گوش نمی‌دهد - یعنی 443
# برای سرویس دیگری (مثلاً OpenConnect) کاملاً آزاد می‌شود. تغییر پورت بعدیِ
# همین دامنه (بدون گرفتن گواهی دوباره) با change_sub_domain_port.sh انجام
# می‌شود؛ این اسکریپت فقط برای راه‌اندازی اولیه (که گواهی هم لازم است) است.
#
# Usage: setup_sub_domain_ssl.sh <domain> [port]
###############################################################################
set -e

BACKEND_PORT=8000
if [ -r /opt/vpn-panel/panel.env ]; then
  # shellcheck disable=SC1091
  source /opt/vpn-panel/panel.env
fi
BACKEND_PORT="${BACKEND_PORT:-8000}"

DOMAIN="$1"
PORT="${2:-443}"
WEB_DIR="/var/www/vpn-panel"
ENV_FILE="/opt/vpn-panel/backend/.env"
SITE_FILE="/etc/nginx/sites-available/vpn-panel-sub"


# Prepare the host firewall automatically for ACME and HTTPS. External cloud
# security groups remain provider-side and cannot be changed without provider
# API credentials.
if [ -r /opt/vpn-panel/scripts/bootstrap_host.sh ]; then
  # shellcheck disable=SC1091
  source /opt/vpn-panel/scripts/bootstrap_host.sh
  vpn_panel_firewall_allow tcp 80 vpnpanel-acme
  vpn_panel_firewall_allow tcp 443 vpnpanel-https
  command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
fi

if [ -z "$DOMAIN" ]; then
  echo "Usage: setup_sub_domain_ssl.sh <domain> [port]" >&2
  exit 1
fi
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ]; then
  echo "Invalid port value: $PORT" >&2
  exit 1
fi

if ! command -v certbot >/dev/null 2>&1; then
  if [ "${SKIP_APT_UPDATE:-0}" != "1" ]; then DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get -o DPkg::Lock::Timeout=600 -o Acquire::Retries=4 update -y; fi
  DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get -o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install -y certbot python3-certbot-nginx
fi

# ---------------------------------------------------------------------------
# Preflight: DNS of this sub-domain must either point directly at this
# server's IP, OR be proxied through Cloudflare (orange cloud) - which is a
# legitimate setup for a real HTTP(S) page like the subscription link, since
# Cloudflare forwards the ACME HTTP-01 challenge (and normal HTTPS traffic)
# through to the origin. In that case the A/AAAA record intentionally points
# at a Cloudflare edge IP instead of this server's real IP, so we can't
# require an exact match - we instead check whether the resolved IP belongs
# to Cloudflare's published ranges. Anything else that doesn't match the
# server's own IP is a real misconfiguration and still hard-fails below.
#
# دقت: فقط رکورد A (نه AAAA) با getent/dig خام برمی‌داشتیم که وقتی دامنه هم
# AAAA داشت (مثل کلادفلر) ممکن بود resolver سیستم به‌غلط IPv6 را برگرداند و
# DNS_ERROR بدهد حتی وقتی A درست بود؛ حالا هر دو را جدا می‌خوانیم.
# ---------------------------------------------------------------------------
SERVER_IP=""
if [ -f "$ENV_FILE" ]; then
  SERVER_IP=$(grep -E '^PUBLIC_SERVER_IP=' "$ENV_FILE" | cut -d= -f2-)
fi
if ! [[ "$SERVER_IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  SERVER_IP=""
fi
if [ -z "$SERVER_IP" ]; then
  for _url in "https://ifconfig.me" "https://icanhazip.com" "https://api.ipify.org"; do
    _try=$(curl -s -f -4 --max-time 5 "$_url" 2>/dev/null | tr -d '[:space:]')
    if [[ "$_try" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
      SERVER_IP="$_try"
      break
    fi
  done
fi

RESOLVED_IP=$(dig +short A "$DOMAIN" 2>/dev/null | tail -n1)
RESOLVED_IPV6=$(dig +short AAAA "$DOMAIN" 2>/dev/null | tail -n1)

if [ -z "$RESOLVED_IP" ] && [ -z "$RESOLVED_IPV6" ]; then
  echo "DNS_ERROR: could not resolve any A/AAAA record for ${DOMAIN} yet. Point an A record at ${SERVER_IP} (directly, or proxied through Cloudflare) and wait for DNS to propagate, then try again." >&2
  exit 1
fi

# آی‌پی رنج‌های کلادفلر را برمی‌دارد (آنلاین، با یک فال‌بک استاتیک اگر
# اینترنت/دسترسی به cloudflare.com در همان لحظه نبود) و چک می‌کند آی‌پی داده‌شده
# داخل یکی از آن رنج‌هاست یا نه.
is_cloudflare_ip() {
  local ip="$1"
  local ranges_file="/tmp/.vpnpanel-cf-ranges.$$"
  {
    curl -s --max-time 5 https://www.cloudflare.com/ips-v4 2>/dev/null
    curl -s --max-time 5 https://www.cloudflare.com/ips-v6 2>/dev/null
  } > "$ranges_file"
  # همان دلیل setup_domain_ssl.sh/setup_vpn_domain_ssl.sh: پاسخ curl می‌تواند
  # بدون خطا برگردد ولی محتوایش یک صفحه‌ی خطا/HTML باشد نه لیست واقعی رنج‌های
  # آی‌پی - فقط چک "خالی نبودن" کافی نیست، باید مطمئن شد حداقل چند خط واقعاً
  # شبیه CIDR هستند وگرنه به لیست ثابت داخلی برمی‌گردیم.
  if [ "$(grep -cE '^[0-9a-fA-F:.]+/[0-9]+$' "$ranges_file" 2>/dev/null || echo 0)" -lt 3 ]; then
    : > "$ranges_file"
  fi
  if [ ! -s "$ranges_file" ]; then
    cat > "$ranges_file" << 'EOF'
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22
2400:cb00::/32
2606:4700::/32
2803:f800::/32
2405:b500::/32
2405:8100::/32
2a06:98c0::/29
2c0f:f248::/32
EOF
  fi
  python3 - "$ip" "$ranges_file" << 'PYEOF'
import ipaddress, sys
ip = ipaddress.ip_address(sys.argv[1])
with open(sys.argv[2]) as f:
    ranges = [l.strip() for l in f if l.strip()]
for r in ranges:
    try:
        if ip in ipaddress.ip_network(r, strict=False):
            print("yes")
            sys.exit(0)
    except ValueError:
        continue
print("no")
PYEOF
  rm -f "$ranges_file"
}

CF_CHECK_IP="${RESOLVED_IP:-$RESOLVED_IPV6}"
if [ -n "$RESOLVED_IP" ] && [ -n "$SERVER_IP" ] && [ "$RESOLVED_IP" = "$SERVER_IP" ]; then
  : # مستقیم به آی‌پی همین سرور اشاره می‌کند - مشکلی نیست
elif [ "$(is_cloudflare_ip "$CF_CHECK_IP")" = "yes" ]; then
  echo "[*] ${DOMAIN} از پشت Cloudflare (ابر روشن) عبور می‌کند - این طبیعی است و مشکلی برای دریافت گواهی SSL ندارد."
else
  echo "DNS_ERROR: ${DOMAIN} currently resolves to ${CF_CHECK_IP:-N/A}, but this server's IP is ${SERVER_IP}. Fix the A record (or point it at this server through Cloudflare) and try again." >&2
  exit 1
fi

# NOTE: just like setup_domain_ssl.sh, this script does not open ports in the
# firewall - make sure tcp/80 and tcp/443 are reachable before running this.

# Step 1: temporary HTTP-only vhost for this sub-domain so the ACME
# challenge can reach it.
cat > "$SITE_FILE" << EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    root ${WEB_DIR};
    index index.html;

    location /api/ {
        proxy_pass http://127.0.0.1:${BACKEND_PORT}/api/;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Forwarded-Host \$http_host;
        proxy_set_header X-Forwarded-Port \$server_port;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header CF-Connecting-IP \$http_cf_connecting_ip;
        proxy_set_header True-Client-IP \$http_true_client_ip;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 200s;
        proxy_send_timeout 200s;
        proxy_read_timeout 200s;
    }

    # VPN Panel frontend cache policy v2.3.148
    location = /index.html {
        add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0" always;
        add_header Pragma "no-cache" always;
        add_header Expires "0" always;
        try_files /index.html =404;
    }

    location ^~ /assets/ {
        add_header Cache-Control "public, max-age=31536000, immutable" always;
        try_files \$uri =404;
    }

    location / {
        add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0" always;
        try_files \$uri \$uri/ /index.html;
    }
}
EOF

ln -sf "$SITE_FILE" /etc/nginx/sites-enabled/vpn-panel-sub
nginx -t
systemctl is-active --quiet nginx && systemctl reload nginx || systemctl start nginx

# Step 2: request the certificate (fails loudly if DNS isn't pointed yet)
certbot certonly --nginx -d "${DOMAIN}" --register-unsafely-without-email --agree-tos --non-interactive

# Step 3: final HTTPS vhost for the sub-domain only. Unlike the panel's own
# domain vhost, this one does NOT declare itself default_server / catch-all -
# it only answers for its own server_name, so it can live alongside the
# panel vhost (and the panel vhost's own catch-all rejection block, if the
# panel domain/SSL is configured) without any conflict.
cat > "$SITE_FILE" << EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    return 301 https://\$host:${PORT}\$request_uri;
}

server {
    listen ${PORT} ssl http2;
    listen [::]:${PORT} ssl http2;
    server_name ${DOMAIN};

    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;

    root ${WEB_DIR};
    index index.html;

    # فقط API عمومی لینک اشتراک لازم است، ولی برای سادگی (و چون خودِ API
    # پنل هم پشت JWT محافظت می‌شود) کل /api/ به همان بک‌اند پروکسی می‌شود.
    location /api/ {
        proxy_pass http://127.0.0.1:${BACKEND_PORT}/api/;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Forwarded-Host \$http_host;
        proxy_set_header X-Forwarded-Port \$server_port;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header CF-Connecting-IP \$http_cf_connecting_ip;
        proxy_set_header True-Client-IP \$http_true_client_ip;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 200s;
        proxy_send_timeout 200s;
        proxy_read_timeout 200s;
    }

    # VPN Panel frontend cache policy v2.3.148
    location = /index.html {
        add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0" always;
        add_header Pragma "no-cache" always;
        add_header Expires "0" always;
        try_files /index.html =404;
    }

    location ^~ /assets/ {
        add_header Cache-Control "public, max-age=31536000, immutable" always;
        try_files \$uri =404;
    }

    location / {
        add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0" always;
        try_files \$uri \$uri/ /index.html;
    }
}
EOF

nginx -t
systemctl is-active --quiet nginx && systemctl reload nginx || systemctl start nginx

# certbot installs a systemd timer for renewal automatically; nginx just
# needs a reload after renewal, which certbot's nginx plugin handles.

# ---------------------------------------------------------------------------
# پورت انتخاب‌شده را در فایروال هاست (ufw/firewalld/iptables خام - هرکدام که
# فعال باشد) باز می‌کند، با تگ "vpnpanel-sub" - دقیقاً همان الگوی
# change_panel_port.sh برای پورت پنل. اگر بعداً پورت عوض شود،
# change_sub_domain_port.sh قانون قبلی را (با همین تگ) برمی‌دارد.
# ---------------------------------------------------------------------------
FW_TAG="vpnpanel-sub"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "^Status: active"; then
  while true; do
    rule_num=$(ufw status numbered 2>/dev/null | grep "# ${FW_TAG}$" | tail -n1 | grep -oE '^\[[0-9]+\]' | tr -d '[]')
    [ -z "$rule_num" ] && break
    yes | ufw delete "$rule_num" >/dev/null 2>&1 || break
  done
  ufw allow "${PORT}/tcp" comment "${FW_TAG}" >/dev/null 2>&1 || true
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q "running"; then
  FW_STATE_DIR="/var/lib/vpn-panel/firewall"
  FW_STATE_FILE="${FW_STATE_DIR}/${FW_TAG}-tcp.port"
  mkdir -p "$FW_STATE_DIR"
  OLD_FW_PORT=""
  [ -f "$FW_STATE_FILE" ] && OLD_FW_PORT=$(cat "$FW_STATE_FILE" 2>/dev/null || true)
  [ -n "$OLD_FW_PORT" ] && firewall-cmd --permanent --remove-port="${OLD_FW_PORT}/tcp" >/dev/null 2>&1 || true
  firewall-cmd --permanent --add-port="${PORT}/tcp" >/dev/null 2>&1 || true
  printf '%s' "$PORT" > "$FW_STATE_FILE"
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
  iptables -I INPUT -p tcp --dport "${PORT}" -m comment --comment "${FW_TAG}" -j ACCEPT
  if iptables -C INPUT -j VPN-PANEL-BANS 2>/dev/null; then
    iptables -D INPUT -j VPN-PANEL-BANS 2>/dev/null || true
    iptables -I INPUT 1 -j VPN-PANEL-BANS
  fi
  command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
else
  echo "    NOTE: no supported firewall tool (ufw/firewalld/iptables) detected - open tcp/${PORT} yourself." >&2
fi

# ---------------------------------------------------------------------------
# اختیاری: اگر ادمین قبل از اجرای این اسکریپت دو متغیر محیطی CF_API_TOKEN و
# CF_ZONE_ID را ست کرده باشد، همین‌جا HTTP/3 (QUIC) را روی زون Cloudflare
# خاموش می‌کنیم - همان دلیلِ setup_domain_ssl.sh: وقتی این ساب‌دامنه (لینک
# سابسکریپشن) پشت Cloudflare است، در شبکه‌های فیلترشده (رایج در ایران) که
# UDP/443 (QUIC) مختل می‌شود، کاربر خطای ERR_QUIC_PROTOCOL_ERROR می‌بیند حتی
# اگر HTTPS/گواهی/nginx کاملاً سالم باشند. این یک تنظیم کاملاً سمت Cloudflare
# است، نه چیزی که با کانفیگ این سرور قابل حل باشد.
#
# استفاده (اختیاری، اگر توکن API کلادفلر را داری):
#   CF_API_TOKEN=xxx CF_ZONE_ID=yyy sudo bash install/setup_sub_domain_ssl.sh ${DOMAIN}
# ---------------------------------------------------------------------------
if [ -n "$CF_API_TOKEN" ] && [ -n "$CF_ZONE_ID" ]; then
  echo "[*] در حال خاموش‌کردن HTTP/3 (QUIC) روی زون Cloudflare (رفع ERR_QUIC_PROTOCOL_ERROR)..."
  CF_RESP=$(curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/${CF_ZONE_ID}/settings/http3" \
    -H "Authorization: Bearer ${CF_API_TOKEN}" \
    -H "Content-Type: application/json" \
    --data '{"value":"off"}' 2>/dev/null)
  if echo "$CF_RESP" | grep -q '"success":true'; then
    echo "[*] HTTP/3 روی این زون Cloudflare خاموش شد."
  else
    echo "[!] خاموش‌کردن HTTP/3 روی Cloudflare ناموفق بود - از داشبورد Cloudflare > Network > HTTP/3 (with QUIC) دستی خاموشش کن."
    echo "    پاسخ Cloudflare API: ${CF_RESP}"
  fi
else
  echo "[*] CF_API_TOKEN/CF_ZONE_ID تنظیم نشده بود - HTTP/3 خودکار خاموش نشد."
  echo "    اگر ${DOMAIN} پشت Cloudflare (ابر نارنجی) است و کاربران خطای ERR_QUIC_PROTOCOL_ERROR"
  echo "    می‌بینند: از داشبورد Cloudflare > (این دامنه) > Network > HTTP/3 (with QUIC) را خاموش کن،"
  echo "    یا این اسکریپت را این‌طور دوباره اجرا کن:"
  echo "      CF_API_TOKEN=xxx CF_ZONE_ID=yyy sudo bash install/setup_sub_domain_ssl.sh ${DOMAIN}"
fi

echo "SSL_OK ${DOMAIN}"
