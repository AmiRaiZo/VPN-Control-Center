#!/bin/bash
###############################################################################
# Called by the panel backend (as root) when the admin sets a domain under
# Settings > Domain & SSL. Issues a Let's Encrypt certificate for the domain
# via certbot and rewrites the Nginx site to serve the panel only on that
# domain over HTTPS (HTTP is kept only to redirect to HTTPS).
#
# Usage: setup_domain_ssl.sh <domain>
###############################################################################
set -e

BACKEND_PORT=8000
if [ -r /opt/vpn-panel/panel.env ]; then
  # shellcheck disable=SC1091
  source /opt/vpn-panel/panel.env
fi
BACKEND_PORT="${BACKEND_PORT:-8000}"

DOMAIN="$1"
WEB_DIR="/var/www/vpn-panel"
ENV_FILE="/opt/vpn-panel/backend/.env"


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
  echo "Usage: setup_domain_ssl.sh <domain>" >&2
  exit 1
fi

if ! command -v certbot >/dev/null 2>&1; then
  if [ "${SKIP_APT_UPDATE:-0}" != "1" ]; then DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get -o DPkg::Lock::Timeout=600 -o Acquire::Retries=4 update -y; fi
  DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get -o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install -y certbot python3-certbot-nginx
fi

# ---------------------------------------------------------------------------
# Preflight: make sure the domain actually points at this server before
# bothering certbot - either directly (A record = server IP) or through
# Cloudflare (orange cloud), which is a legitimate setup since Cloudflare
# forwards the ACME HTTP-01 challenge and normal HTTPS traffic through to
# the origin. In the Cloudflare case the resolved IP is intentionally one of
# Cloudflare's edge IPs, not this server's - so instead of requiring an
# exact match we check whether the resolved IP belongs to Cloudflare's
# published ranges. Anything else that doesn't match is a real
# misconfiguration and still hard-fails below with a clear message.
# ---------------------------------------------------------------------------
SERVER_IP=""
if [ -f "$ENV_FILE" ]; then
  SERVER_IP=$(grep -E '^PUBLIC_SERVER_IP=' "$ENV_FILE" | cut -d= -f2-)
fi
# اگر مقدار داخل .env یک آی‌پی معتبر نباشد (مثلاً موقع نصب چیزی غیر از آی‌پی
# وارد شده)، نادیده‌اش بگیر و به‌جایش آی‌پی واقعی سرور را خودکار تشخیص بده.
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

is_cloudflare_ip() {
  local ip="$1"
  local ranges_file="/tmp/.vpnpanel-cf-ranges.$$"
  {
    curl -s --max-time 5 https://www.cloudflare.com/ips-v4 2>/dev/null
    curl -s --max-time 5 https://www.cloudflare.com/ips-v6 2>/dev/null
  } > "$ranges_file"
  # curl می‌تواند بدون خطا برگردد ولی محتوایش یک صفحه‌ی خطا/HTML باشد نه
  # لیست واقعی رنج‌های آی‌پی (مثلاً در شبکه‌هایی که دسترسی به cloudflare.com
  # فیلتر/مختل است و یک صفحه‌ی خطای دیگر برمی‌گردد)؛ فقط چک "خالی نبودن" کافی
  # نیست - باید مطمئن شد حداقل چند خط واقعاً شبیه CIDR هستند، وگرنه به لیست
  # ثابت داخلی برمی‌گردیم. بدون این چک، یک پاسخ خراب (نه خالی) باعث می‌شد
  # هیچ‌کدام از خط‌ها به‌عنوان CIDR معتبر پارس نشوند و دامنه‌ی واقعاً پشت
  # Cloudflareِ پنل/ساب به‌غلط "مشکل DNS" اعلام شود.
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

# Host firewall ports 80/443 were opened above. The DNS record and any
# provider-side security group must still route traffic to this server.

# Step 1: temporary HTTP-only vhost for this domain so the ACME challenge
# can reach it (also keeps the panel reachable during the process).
cat > /etc/nginx/sites-available/vpn-panel << EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};

    root ${WEB_DIR};
    index index.html;

    location /api/ {
        client_max_body_size 256m;
        client_body_timeout 120s;
        proxy_pass http://127.0.0.1:${BACKEND_PORT}/api/;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Forwarded-Host \$http_host;
        proxy_set_header X-Forwarded-Port \$server_port;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header CF-Connecting-IP \$http_cf_connecting_ip;
        proxy_set_header True-Client-IP \$http_true_client_ip;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        # Setting a domain (this same request) can take up to ~3 minutes:
        # certbot has to run before the response comes back. Nginx's default
        # 60s proxy timeout was cutting this off with a bare 504 (no JSON
        # body), which the panel then showed as a generic "SSL failed" error
        # with no details. Give it plenty of headroom.
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

ln -sf /etc/nginx/sites-available/vpn-panel /etc/nginx/sites-enabled/vpn-panel
nginx -t
systemctl is-active --quiet nginx && systemctl reload nginx || systemctl start nginx

# Step 2: request the certificate (fails loudly if DNS isn't pointed yet).
# --register-unsafely-without-email: the admin isn't asked for an email; this
# only means Let's Encrypt can't send expiry-warning emails, which doesn't
# matter here since certbot's systemd timer renews automatically anyway.
certbot certonly --nginx -d "${DOMAIN}" --register-unsafely-without-email --agree-tos --non-interactive

# Step 3: final HTTPS-only vhost, locked to this domain and nothing else.
#
# After SSL is issued, the panel must ONLY be reachable via
# https://${DOMAIN} - not via the server's raw IP, not via the old panel
# port, and not via any other Host header/SNI someone might point at this
# server. Two "catch-all" server blocks below handle everything that is NOT
# an exact match for ${DOMAIN}. Nginx picks the "default_server" block for
# any request that doesn't match a server_name, so without this, the
# panel's own vhost would silently keep answering on the bare IP / any
# Host header.
#
# The 443 catch-all needs *some* certificate to complete the TLS
# handshake before it can return 444, so we generate a throwaway
# self-signed one just for that purpose (kept separate from the panel's
# real Let's Encrypt cert). This works on any nginx version, unlike the
# newer ssl_reject_handshake directive.
REJECT_CERT_DIR="/etc/nginx/vpn-panel-reject"
if [ ! -f "${REJECT_CERT_DIR}/reject.crt" ]; then
  mkdir -p "$REJECT_CERT_DIR"
  openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
    -keyout "${REJECT_CERT_DIR}/reject.key" \
    -out "${REJECT_CERT_DIR}/reject.crt" \
    -subj "/CN=invalid" >/dev/null 2>&1
fi

# ---------------------------------------------------------------------------
# nginx only allows ONE default_server per listen address:port. If another
# site on this box (e.g. license-server's own setup_domain_ssl.sh) already
# claimed default_server on 80/443, claiming it again here produces a fatal
# "duplicate default server" error and/or leaves stale processes fighting
# over the port on reload. So: only take default_server on a port if no
# *other* enabled site already has it.
other_site_has_default_server() {
  local port="$1"
  # NOTE: /etc/nginx/sites-enabled/ entries are symlinks to sites-available/.
  # Plain `grep -r` does NOT follow symlinks discovered during traversal, so
  # it silently found nothing here and this check always returned "no other
  # site has it" - even when one clearly did. Use `-R` (dereference-recursive)
  # so it actually reads through the symlinks.
  grep -Rl "listen ${port}.*default_server\|listen \[::\]:${port}.*default_server" \
    /etc/nginx/sites-enabled/ 2>/dev/null \
    | grep -v "/etc/nginx/sites-enabled/vpn-panel$" \
    | grep -q .
}

DEFAULT_80=""
DEFAULT_443=""
if ! other_site_has_default_server 80; then
  DEFAULT_80="default_server"
fi
if ! other_site_has_default_server 443; then
  DEFAULT_443="default_server"
fi
if [ -z "$DEFAULT_80" ] || [ -z "$DEFAULT_443" ]; then
  echo "[*] Another site already owns default_server on this port; vpn-panel will not compete for it (avoids a duplicate default_server / bind conflict)."
fi

cat > /etc/nginx/sites-available/vpn-panel << EOF
# --- catch-all: anything that isn't ${DOMAIN} gets dropped ---
server {
    listen 80 ${DEFAULT_80};
    listen [::]:80 ${DEFAULT_80};
    server_name _;
    return 444;
}

server {
    listen 443 ssl ${DEFAULT_443};
    listen [::]:443 ssl ${DEFAULT_443};
    ssl_certificate ${REJECT_CERT_DIR}/reject.crt;
    ssl_certificate_key ${REJECT_CERT_DIR}/reject.key;
    server_name _;
    return 444;
}

# --- real vhost: only ${DOMAIN} over HTTPS ---
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DOMAIN};

    ssl_certificate /etc/letsencrypt/live/${DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${DOMAIN}/privkey.pem;

    root ${WEB_DIR};
    index index.html;

    location /api/ {
        client_max_body_size 256m;
        client_body_timeout 120s;
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
# اختیاری: اگر ادمین قبل از اجرای این اسکریپت دو متغیر محیطی CF_API_TOKEN و
# CF_ZONE_ID را ست کرده باشد، همین‌جا HTTP/3 (QUIC) را روی زون Cloudflare
# خاموش می‌کنیم.
#
# چرا لازم است: وقتی این دامنه پشت Cloudflare (ابر نارنجی) است، مرورگر کاربر
# مستقیماً با این سرور صحبت نمی‌کند - با لبه‌ی Cloudflare صحبت می‌کند، آن هم
# اگر HTTP/3 روشن باشد، روی UDP/443 (QUIC). این یک تنظیم کاملاً سمت
# Cloudflare است و هیچ کانفیگ nginx/گواهی روی همین سرور رویش اثر ندارد. در
# شبکه‌هایی که UDP/443 فیلتر یا مختل می‌شود (رایج در ایران)، همین باعث خطای
# ERR_QUIC_PROTOCOL_ERROR در مرورگر کاربر می‌شود - حتی وقتی HTTPS/گواهی/nginx
# روی این سرور کاملاً سالم‌اند. خاموش‌کردن HTTP/3 باعث می‌شود Cloudflare
# همیشه با HTTP/2 روی TCP/443 معمولی جواب بدهد که پشت فیلترینگ پایدارتر است.
#
# استفاده (اختیاری، اگر توکن API کلادفلر را داری):
#   CF_API_TOKEN=xxx CF_ZONE_ID=yyy sudo bash install/setup_domain_ssl.sh ${DOMAIN}
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
  echo "      CF_API_TOKEN=xxx CF_ZONE_ID=yyy sudo bash install/setup_domain_ssl.sh ${DOMAIN}"
fi

echo "SSL_OK ${DOMAIN}"
