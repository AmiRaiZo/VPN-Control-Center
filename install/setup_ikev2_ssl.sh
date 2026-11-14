#!/bin/bash
###############################################################################
# Called by the panel backend (as root) from Settings > SSL برای IKEv2. Issues
# a real Let's Encrypt certificate for the given domain and wires it into
# strongSwan's IKEv2 conn (leftcert), so clients trust the connection without
# needing to manually install the panel's self-signed CA (install/setup_ikev2.sh
# generates one automatically the first time IKEv2 is set up, this replaces it
# with a properly-trusted one once you have a domain).
#
# Like setup_domain_ssl.sh/setup_vpn_domain_ssl.sh, no email is requested
# (--register-unsafely-without-email); renewal is automatic via the
# deploy-hook installed below.
#
# Usage: setup_ikev2_ssl.sh <domain>
###############################################################################
set -e

DOMAIN="$1"
ENV_FILE="/opt/vpn-panel/backend/.env"
CERT_DIR="/etc/ipsec.d"
HOOK_SCRIPT="/opt/vpn-panel/scripts/ikev2_ssl_renew_hook.sh"


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
  echo "Usage: setup_ikev2_ssl.sh <domain>" >&2
  exit 1
fi

if ! command -v certbot >/dev/null 2>&1; then
  if [ "${SKIP_APT_UPDATE:-0}" != "1" ]; then DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get -o DPkg::Lock::Timeout=600 -o Acquire::Retries=4 update -y; fi
  DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get -o DPkg::Lock::Timeout=600 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install -y certbot
fi

# ---------------------------------------------------------------------------
# Preflight DNS check (same idea as setup_vpn_domain_ssl.sh - a Cloudflare-
# proxied record can't work here either, since IKEv2 is a raw UDP protocol,
# not HTTP(S)).
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
if [ -z "$RESOLVED_IP" ]; then
  echo "DNS_ERROR: could not resolve any A record for ${DOMAIN} yet. Point an A record (DNS-only, not proxied) at ${SERVER_IP} and wait for DNS to propagate, then try again." >&2
  exit 1
fi
if [ "$RESOLVED_IP" != "$SERVER_IP" ]; then
  echo "DNS_ERROR: ${DOMAIN} currently resolves to ${RESOLVED_IP}, but this server's IP is ${SERVER_IP}. Fix the A record and try again." >&2
  exit 1
fi

mkdir -p /opt/vpn-panel/scripts
cat > "$HOOK_SCRIPT" << 'EOF'
#!/bin/bash
# Auto-installed by setup_ikev2_ssl.sh - re-syncs the renewed certificate
# into strongSwan's IKEv2 config and reloads it.
set -e
CERT_DIR="/etc/ipsec.d"
if [ -n "$RENEWED_LINEAGE" ] && [ -f "$RENEWED_LINEAGE/cert.pem" ] && [ -d "$CERT_DIR" ]; then
  # Only the leaf cert goes in leftcert - sending fullchain.pem (leaf + intermediate)
  # makes the IKE_AUTH payload large enough to require fragmentation, which many
  # mobile clients silently fail to reassemble. Clients already trust Let's
  # Encrypt's intermediates from their OS trust store, and this client profile
  # doesn't validate the IKE server cert against a local CA at all - so we must
  # NOT put the intermediate in cacerts either, since strongSwan auto-attaches
  # any cert it finds there to the chain it sends, causing the same fragmentation.
  cp "$RENEWED_LINEAGE/cert.pem" "${CERT_DIR}/certs/ikev2-server-cert.pem"
  cp "$RENEWED_LINEAGE/privkey.pem" "${CERT_DIR}/private/ikev2-server-key.pem"
  rm -f "${CERT_DIR}/cacerts/ikev2-ca-cert.pem"
  chmod 600 "${CERT_DIR}/private/ikev2-server-key.pem"
  systemctl restart strongswan-starter 2>/dev/null || systemctl restart strongswan 2>/dev/null || ipsec restart 2>/dev/null || true
fi
EOF
chmod +x "$HOOK_SCRIPT"

NGINX_WAS_ACTIVE=0
if systemctl is-active --quiet nginx 2>/dev/null; then
  NGINX_WAS_ACTIVE=1
  systemctl stop nginx
fi

CERTBOT_OK=1
# --preferred-chain "ISRG Root X1": بدون این فلگ، certbot ممکن است زنجیره‌ای
# را انتخاب کند که به یک ریشه‌ی جدیدتر Let's Encrypt (مثل "ISRG Root YE" که
# برای گواهی‌های کوتاه‌مدت/ECDSA استفاده می‌شود) ختم می‌شود - این ریشه‌ها هنوز
# در trust store همه‌ی دستگاه‌ها (خصوصاً موبایل) از قبل نصب نیستند. نتیجه:
# کلاینت زنجیره را تا CA میانی درست می‌سازد ولی به ریشه‌ی نهایی اعتماد
# نمی‌کند و با خطای بی‌صدای AUTH_FAILED رد می‌شود - دقیقاً همین اتفاق با یک
# کلاینت IKEv2 موبایل افتاد. "ISRG Root X1" قدیمی‌ترین و گسترده‌ترین‌
# ریشه‌ی Let's Encrypt است که عملاً روی هر دستگاهی از سال‌ها پیش pre-trusted
# است. certbot این ترجیح را در فایل renewal ذخیره می‌کند، پس تمدیدهای
# خودکار بعدی هم همین زنجیره را می‌گیرند.
CERTBOT_OUTPUT=$(certbot certonly --standalone -d "${DOMAIN}" \
  --preferred-chain "ISRG Root X1" \
  --register-unsafely-without-email --agree-tos --non-interactive \
  --deploy-hook "$HOOK_SCRIPT" 2>&1) || CERTBOT_OK=0

if [ "$NGINX_WAS_ACTIVE" = "1" ]; then
  systemctl start nginx
fi

if [ "$CERTBOT_OK" != "1" ]; then
  if echo "$CERTBOT_OUTPUT" | grep -qi "cloudflare"; then
    echo "CERTBOT_ERROR: Let's Encrypt could not reach ${DOMAIN} directly - the request appears to have been intercepted by Cloudflare's proxy instead of reaching this server. Double-check in Cloudflare's dashboard that the A record for ${DOMAIN} has a GREY cloud icon (DNS only), not orange (proxied), and wait a few minutes after changing it before retrying." >&2
  else
    DETAIL_LINE=$(echo "$CERTBOT_OUTPUT" | grep -m1 "Detail:" | sed -e 's/<[^>]*>//g' -e 's/^[[:space:]]*//' | cut -c1-300)
    echo "CERTBOT_ERROR: failed to obtain a certificate for ${DOMAIN}. Make sure tcp/80 is reachable from the internet (required for the ACME challenge, separate from the IKEv2 UDP ports).${DETAIL_LINE:+ Detail: $DETAIL_LINE}" >&2
  fi
  exit 1
fi

LIVE_DIR="/etc/letsencrypt/live/${DOMAIN}"
if [ -f "${LIVE_DIR}/cert.pem" ]; then
  # Use the leaf cert only (not fullchain.pem, and NOT even chain.pem in
  # cacerts) - see comment in the deploy hook above about IKE fragmentation
  # with mobile clients. strongSwan auto-attaches any cert found in cacerts
  # to the certs it sends, regardless of leftcert, so cacerts must stay empty
  # of this domain's intermediate.
  mkdir -p "${CERT_DIR}/certs" "${CERT_DIR}/private" "${CERT_DIR}/cacerts"
  cp "${LIVE_DIR}/cert.pem" "${CERT_DIR}/certs/ikev2-server-cert.pem"
  cp "${LIVE_DIR}/privkey.pem" "${CERT_DIR}/private/ikev2-server-key.pem"
  rm -f "${CERT_DIR}/cacerts/ikev2-ca-cert.pem"
  chmod 600 "${CERT_DIR}/private/ikev2-server-key.pem"

  # ثبت این‌که این دامنه‌ی مشخص برای IKEv2 اختصاص داده شده - تا install/setup_ikev2.sh
  # (که هر بار در install.sh/update.sh دوباره اجرا می‌شود) بداند این گواهی از
  # قبل درست تنظیم شده و نباید آن را با اولین دامنه‌ی Let's Encrypt که پیدا
  # می‌کند (که ممکن است دامنه‌ی پنل یا هر دامنه‌ی دیگری باشد) جایگزین کند.
  echo "$DOMAIN" > "${CERT_DIR}/.ikev2-ssl-domain"

  # اگر زیرساخت پایه‌ی IKEv2 (conn IKEv2-MSCHAPv2 داخل ipsec.conf) هنوز روی این
  # سرور ساخته نشده باشد - یعنی ادمین مستقیم از همین صفحه (Settings > SSL برای
  # IKEv2) شروع کرده، بدون اینکه install/setup_ikev2.sh قبلاً اجرا شده باشد -
  # قبلاً اینجا هیچ کاری انجام نمی‌شد: گواهی/کلید بالا کپی می‌شدند، مارکر دامنه
  # نوشته می‌شد، ولی چون بلوک زیر (sed روی leftcert/leftid) با grep چک می‌کرد که
  # اول conn موجود باشد، در نبودنش کل بخش بی‌صدا رد می‌شد - یعنی هیچ conn ای
  # برای IKE ساخته/لود نمی‌شد و کلاینت‌ها همان لحظه‌ی اول با "Unsuccessful"
  # مواجه می‌شدند، بدون هیچ خطایی در همین اسکریپت. حالا قبل از آن sed، اگر conn
  # پیدا نشود، همین‌جا setup_ikev2.sh پایه (idempotent) اجرا می‌شود تا conn را
  # بسازد؛ همان اسکریپت چون مارکر دامنه از قبل نوشته شده (خط بالا)، خودش گواهی
  # Let's Encrypt همین دامنه را (نه self-signed) adopt می‌کند.
  if [ -f /etc/ipsec.conf ] && ! grep -q "^conn IKEv2-MSCHAPv2" /etc/ipsec.conf; then
    echo "[*] زیرساخت پایه‌ی IKEv2 هنوز روی این سرور ساخته نشده - در حال اجرای setup_ikev2.sh..."
    BASE_SETUP_SCRIPT="$(dirname "$0")/setup_ikev2.sh"
    [ -f "$BASE_SETUP_SCRIPT" ] || BASE_SETUP_SCRIPT="/opt/vpn-panel/scripts/setup_ikev2.sh"
    if [ -f "$BASE_SETUP_SCRIPT" ]; then
      bash "$BASE_SETUP_SCRIPT" || echo "[!] اجرای setup_ikev2.sh ناموفق بود؛ ادامه می‌دهیم ولی ممکن است conn هنوز ساخته نشده باشد." >&2
    else
      echo "[!] setup_ikev2.sh پیدا نشد (نه کنار همین اسکریپت، نه در /opt/vpn-panel/scripts) - conn پایه‌ی IKEv2 ساخته نخواهد شد." >&2
    fi
  fi

  # مطمئن شو conn IKEv2-MSCHAPv2 روی همین نام فایل (که همیشه ثابت است) اشاره
  # می‌کند - install/setup_ikev2.sh همین نام را می‌نویسد، پس معمولاً از قبل
  # درست است؛ فقط برای اطمینان دوباره ست می‌شود.
  if [ -f /etc/ipsec.conf ] && grep -q "^conn IKEv2-MSCHAPv2" /etc/ipsec.conf; then
    sed -i '/^conn IKEv2-MSCHAPv2/,/^conn /{s/^\(\s*leftcert=\).*/\1ikev2-server-cert.pem/}' /etc/ipsec.conf
    sed -i '/^conn IKEv2-MSCHAPv2/,/^conn /{s/^\(\s*leftid=\).*/\1@'"${DOMAIN}"'/}' /etc/ipsec.conf
    systemctl restart strongswan-starter 2>/dev/null || systemctl restart strongswan 2>/dev/null || ipsec restart 2>/dev/null || true
  else
    echo "[!] هشدار: conn IKEv2-MSCHAPv2 هنوز داخل ipsec.conf پیدا نشد - گواهی نصب شد ولی اتصال IKEv2 کار نخواهد کرد تا این مشکل برطرف شود." >&2
  fi
fi

echo "IKEV2_SSL_OK ${DOMAIN}"
