#!/bin/bash
###############################################################################
# Called by the panel backend (as root) when the admin sets a "VPN protocols
# domain" under Settings > دامنه‌ی اختصاصیِ پروتکل‌ها. Unlike
# check_vpn_domain.sh (DNS-only, no cert - kept around for backward
# compatibility / manual use), this script actually issues a real Let's
# Encrypt certificate for the domain and wires it into the SSTP server
# (accel-ppp), fixing the classic Windows SSTP error 0x800B010F ("the
# certificate's CN name does not match the passed value") that happens when
# accel-ppp is still serving the panel's own domain certificate instead of
# one that matches the hostname clients actually connect to.
#
# L2TP/PPTP/OpenVPN don't use TLS server certificates at all, so this only
# matters for SSTP - but it's harmless (and idempotent) to run regardless of
# whether SSTP infrastructure is installed; the accel-ppp-specific steps are
# simply skipped if it isn't.
#
# No email is requested from the admin: certbot is used with
# --register-unsafely-without-email. This only means Let's Encrypt can't
# send expiry-warning emails - irrelevant here since renewal is automatic
# (certbot's systemd timer + the deploy-hook installed below, which re-syncs
# the renewed cert into accel-ppp and reloads it, exactly like
# setup_domain_ssl.sh/setup_sub_domain_ssl.sh do for the panel/sub vhosts
# via the nginx certbot plugin).
#
# Usage: setup_vpn_domain_ssl.sh <domain>
###############################################################################
set -e

DOMAIN="$1"
ENV_FILE="/opt/vpn-panel/backend/.env"
CERT_DIR="/etc/accel-ppp/sstp-certs"
HOOK_SCRIPT="/opt/vpn-panel/scripts/vpn_domain_renew_hook.sh"


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
  echo "Usage: setup_vpn_domain_ssl.sh <domain>" >&2
  exit 1
fi

if ! command -v certbot >/dev/null 2>&1; then
  if [ "${SKIP_APT_UPDATE:-0}" != "1" ]; then DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get -o DPkg::Lock::Timeout=600 -o Acquire::Retries=4 update -y; fi
  DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get -o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install -y certbot
fi

# ---------------------------------------------------------------------------
# Preflight: DNS A record must point at this server's real IP (same check as
# check_vpn_domain.sh) - catches proxied/CDN records (e.g. Cloudflare orange
# cloud) that would make the ACME HTTP-01 challenge (and real VPN traffic)
# fail silently.
#
# Unlike the panel/sub-domain SSL scripts, a Cloudflare-proxied record is
# NEVER acceptable here and is explicitly detected/rejected with its own
# message: SSTP is a raw TLS/PPP tunnel, not HTTP(S) traffic, so Cloudflare's
# proxy cannot pass it through correctly (it either terminates TLS at its own
# edge, breaking the SSTP handshake, or tries to parse the connection as HTTP
# and fails - this is exactly the "Cloudflare could not parse the origin
# response" error). This domain must always stay DNS-only (grey cloud).
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

# فقط رکورد A (نه AAAA) را می‌خواهیم - قبلاً با getent hosts، اگر دامنه رکورد
# AAAA هم داشت (مثلاً همان آی‌پی edge کلادفلر)، resolver سیستم ممکن بود آن را
# به‌جای A برگرداند و پیام DNS_ERROR را با یک آی‌پی IPv6 گمراه‌کننده نشان دهد.
RESOLVED_IP=$(dig +short A "$DOMAIN" 2>/dev/null | tail -n1)
RESOLVED_IPV6=$(dig +short AAAA "$DOMAIN" 2>/dev/null | tail -n1)

if [ -z "$RESOLVED_IP" ] && [ -z "$RESOLVED_IPV6" ]; then
  echo "DNS_ERROR: could not resolve any A record for ${DOMAIN} yet. Point an A record (DNS-only, not proxied) at ${SERVER_IP} and wait for DNS to propagate, then try again." >&2
  exit 1
fi

if [ -z "$RESOLVED_IP" ] || [ "$RESOLVED_IP" != "$SERVER_IP" ]; then
  is_cloudflare_ip() {
    local ip="$1"
    local ranges_file="/tmp/.vpnpanel-cf-ranges.$$"
    {
      curl -s --max-time 5 https://www.cloudflare.com/ips-v4 2>/dev/null
      curl -s --max-time 5 https://www.cloudflare.com/ips-v6 2>/dev/null
    } > "$ranges_file"
    # curl می‌تواند بدون خطا برگردد ولی محتوایش یک صفحه‌ی خطا/HTML باشد نه
    # لیست واقعی رنج‌های آی‌پی؛ فقط چک "خالی نبودن" کافی نیست - باید مطمئن شد
    # حداقل چند خط واقعاً شبیه CIDR هستند، وگرنه به لیست ثابت داخلی برمی‌گردیم.
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
  if [ "$(is_cloudflare_ip "$CF_CHECK_IP")" = "yes" ]; then
    echo "CLOUDFLARE_ERROR: ${DOMAIN} is proxied through Cloudflare (orange cloud) - resolves to a Cloudflare edge IP (${CF_CHECK_IP}) instead of this server (${SERVER_IP}). SSTP is a raw TLS tunnel, not HTTP(S) traffic, so it cannot work through Cloudflare's proxy (this is also why you saw 'Cloudflare could not parse the origin response' when testing the domain in a browser). In Cloudflare's DNS settings, click the orange cloud icon next to this specific record to switch it to grey cloud (DNS only), then try again." >&2
  else
    echo "DNS_ERROR: ${DOMAIN} currently resolves to ${CF_CHECK_IP:-N/A}, but this server's IP is ${SERVER_IP}. Fix the A record and try again." >&2
  fi
  exit 1
fi

# ---------------------------------------------------------------------------
# Renewal deploy-hook: re-installed every run (idempotent) so it stays in
# sync with this script. Certbot stores the hook path in this cert's own
# renewal config, so it only fires for THIS lineage - never for the panel's
# or sub-domain's certs, even though the hook file is generic-looking.
# ---------------------------------------------------------------------------
mkdir -p /opt/vpn-panel/scripts
cat > "$HOOK_SCRIPT" << 'EOF'
#!/bin/bash
# Auto-installed by setup_vpn_domain_ssl.sh - runs after certbot renews the
# VPN protocols domain certificate. Re-syncs it into accel-ppp's SSTP config
# (if installed) and reloads the service so it always serves the current,
# non-expired certificate.
set -e
CERT_DIR="/etc/accel-ppp/sstp-certs"
if [ -n "$RENEWED_LINEAGE" ] && [ -f "$RENEWED_LINEAGE/fullchain.pem" ] && [ -d "$CERT_DIR" ]; then
  cp "$RENEWED_LINEAGE/fullchain.pem" "$CERT_DIR/fullchain.pem"
  cp "$RENEWED_LINEAGE/privkey.pem" "$CERT_DIR/privkey.pem"
  chmod 600 "$CERT_DIR/privkey.pem"
  systemctl restart accel-ppp-sstp 2>/dev/null || true
fi
EOF
chmod +x "$HOOK_SCRIPT"

# ---------------------------------------------------------------------------
# Request/renew the certificate. This domain has no web content of its own
# (it's only ever used as a TLS SNI/CN target for VPN protocols, never
# browsed to), so there's no nginx vhost to plug the ACME HTTP-01 challenge
# into like setup_domain_ssl.sh/setup_sub_domain_ssl.sh do. Instead certbot's
# own standalone webserver is used, which needs tcp/80 free for a few
# seconds - nginx (if running, e.g. for the panel/sub domains) is stopped
# just for that window and restarted right after, success or failure.
# ---------------------------------------------------------------------------
NGINX_WAS_ACTIVE=0
if systemctl is-active --quiet nginx 2>/dev/null; then
  NGINX_WAS_ACTIVE=1
  systemctl stop nginx
fi

CERTBOT_OK=1
# همان دلیل setup_ikev2_ssl.sh: بدون این فلگ ممکن است زنجیره‌ای انتخاب شود
# که به یک ریشه‌ی جدیدتر (مثل "ISRG Root YE") ختم شود که هنوز در trust
# store همه‌ی دستگاه‌ها نیست و باعث رد بی‌صدای اتصال می‌شود.
CERTBOT_OUTPUT=$(certbot certonly --standalone -d "${DOMAIN}" \
  --preferred-chain "ISRG Root X1" \
  --register-unsafely-without-email --agree-tos --non-interactive \
  --deploy-hook "$HOOK_SCRIPT" 2>&1) || CERTBOT_OK=0

if [ "$NGINX_WAS_ACTIVE" = "1" ]; then
  systemctl start nginx
fi

if [ "$CERTBOT_OK" != "1" ]; then
  # اگر درخواست HTTP-01 توسط پروکسی کلادفلر (به‌جای رسیدن مستقیم به این سرور)
  # قطع شده باشد، خروجی خام certbot معمولاً شامل صفحه‌ی خطای HTML کلادفلر
  # می‌شود (همان چیزی که در مرورگر هم دیده می‌شود). آن HTML خام را مستقیم در
  # پنل نشان نمی‌دهیم - پیام روشن‌تری می‌دهیم؛ در غیر این صورت فقط خط
  # Detail را (بدون تگ‌های HTML) نشان می‌دهیم.
  if echo "$CERTBOT_OUTPUT" | grep -qi "cloudflare"; then
    echo "CERTBOT_ERROR: Let's Encrypt could not reach ${DOMAIN} directly - the request appears to have been intercepted by Cloudflare's proxy instead of reaching this server (the exact same 'Cloudflare could not parse the origin response' error you'd see visiting the domain in a browser). Even though the DNS check above passed, double-check in Cloudflare's dashboard that the A record for ${DOMAIN} has a GREY cloud icon (DNS only), not orange (proxied) - and give it a few minutes after changing it before retrying, since this can take a moment to take effect." >&2
  else
    DETAIL_LINE=$(echo "$CERTBOT_OUTPUT" | grep -m1 "Detail:" | sed -e 's/<[^>]*>//g' -e 's/^[[:space:]]*//' | cut -c1-300)
    echo "CERTBOT_ERROR: failed to obtain a certificate for ${DOMAIN}. Make sure tcp/80 is reachable from the internet (required for the ACME challenge, separate from the SSTP port itself).${DETAIL_LINE:+ Detail: $DETAIL_LINE}" >&2
  fi
  exit 1
fi

# ---------------------------------------------------------------------------
# Wire the fresh cert into accel-ppp's SSTP config right now too (not just on
# the next renewal) - only if the SSTP infrastructure is actually installed.
# ---------------------------------------------------------------------------
LIVE_DIR="/etc/letsencrypt/live/${DOMAIN}"
if [ -d "$CERT_DIR" ] && [ -f "${LIVE_DIR}/fullchain.pem" ]; then
  cp "${LIVE_DIR}/fullchain.pem" "$CERT_DIR/fullchain.pem"
  cp "${LIVE_DIR}/privkey.pem" "$CERT_DIR/privkey.pem"
  chmod 600 "$CERT_DIR/privkey.pem"
  if systemctl list-unit-files 2>/dev/null | grep -q '^accel-ppp-sstp\.service'; then
    systemctl restart accel-ppp-sstp || true
  fi
fi

echo "VPN_DOMAIN_SSL_OK ${DOMAIN}"
