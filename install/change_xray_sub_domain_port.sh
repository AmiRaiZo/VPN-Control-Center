#!/bin/bash
###############################################################################
# Changes the port Nginx serves the "subscription link" sub-domain vhost
# (vpn-panel-xray-sub) on, WITHOUT calling certbot again - reuses whatever
# Let's Encrypt certificate setup_xray_sub_domain_ssl.sh already issued for
# <domain>. Mirrors change_panel_port.sh's domain-mode branch.
#
# If <port> is anything other than 443, Nginx no longer binds 443 for this
# vhost at all, freeing that port up for another service (e.g. OpenConnect).
#
# Can be called by the backend, or directly via SSH:
#   sudo bash /opt/vpn-panel/scripts/change_xray_sub_domain_port.sh 8444 sub.example.com
#
# Usage: change_xray_sub_domain_port.sh <port> <domain>
###############################################################################
set -e

BACKEND_PORT=8000
if [ -r /opt/vpn-panel/panel.env ]; then
  # shellcheck disable=SC1091
  source /opt/vpn-panel/panel.env
fi
BACKEND_PORT="${BACKEND_PORT:-8000}"

NEW_PORT="$1"
DOMAIN="$2"
WEB_DIR="/var/www/vpn-panel"
SITE_FILE="/etc/nginx/sites-available/vpn-panel-xray-sub"

if [ -z "$NEW_PORT" ] || [ -z "$DOMAIN" ]; then
  echo "Usage: change_xray_sub_domain_port.sh <port> <domain>" >&2
  exit 1
fi
if ! [[ "$NEW_PORT" =~ ^[0-9]+$ ]] || [ "$NEW_PORT" -lt 1 ] || [ "$NEW_PORT" -gt 65535 ]; then
  echo "Invalid port value: $NEW_PORT" >&2
  exit 1
fi
if [ "$NEW_PORT" = "$BACKEND_PORT" ]; then
  echo "ERROR: tcp/${NEW_PORT} is reserved for the private VPN Panel API." >&2
  exit 1
fi

CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
if [ ! -f "${CERT_DIR}/fullchain.pem" ] || [ ! -f "${CERT_DIR}/privkey.pem" ]; then
  echo "ERROR: no Let's Encrypt certificate found for ${DOMAIN} at ${CERT_DIR} - run the sub-domain/SSL setup again instead." >&2
  exit 1
fi
if [ ! -f "$SITE_FILE" ]; then
  echo "ERROR: ${SITE_FILE} does not exist yet - run the sub-domain/SSL setup first." >&2
  exit 1
fi

cat > "$SITE_FILE" << EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${DOMAIN};
    return 301 https://\$host:${NEW_PORT}\$request_uri;
}

server {
    listen ${NEW_PORT} ssl http2;
    listen [::]:${NEW_PORT} ssl http2;
    server_name ${DOMAIN};

    ssl_certificate ${CERT_DIR}/fullchain.pem;
    ssl_certificate_key ${CERT_DIR}/privkey.pem;

    location ^~ /api/sub/ {
        proxy_pass http://127.0.0.1:${BACKEND_PORT}/api/sub/;
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

    location / {
        return 404;
    }
}
EOF

nginx -t
systemctl is-active --quiet nginx && systemctl reload nginx || systemctl start nginx

# ---------------------------------------------------------------------------
# Keep the host firewall in sync: remove our own previous rule (tagged
# "vpnpanel-xray-sub", so nothing added by hand is ever touched) and open the
# new one - same pattern as change_panel_port.sh.
# ---------------------------------------------------------------------------
FW_TAG="vpnpanel-xray-sub"
FW_BACKEND="none"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "^Status: active"; then
  FW_BACKEND="ufw"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q "running"; then
  FW_BACKEND="firewalld"
elif command -v iptables >/dev/null 2>&1; then
  FW_BACKEND="iptables"
fi
case "$FW_BACKEND" in
  ufw)
    while true; do
      rule_num=$(ufw status numbered 2>/dev/null | grep "# ${FW_TAG}$" | tail -n1 | grep -oE '^\[[0-9]+\]' | tr -d '[]')
      [ -z "$rule_num" ] && break
      yes | ufw delete "$rule_num" >/dev/null 2>&1 || break
    done
    ufw allow "${NEW_PORT}/tcp" comment "${FW_TAG}" >/dev/null 2>&1 || true
    ;;
  firewalld)
    FW_STATE_DIR="/var/lib/vpn-panel/firewall"
    FW_STATE_FILE="${FW_STATE_DIR}/${FW_TAG}-tcp.port"
    mkdir -p "$FW_STATE_DIR"
    OLD_FW_PORT=""
    [ -f "$FW_STATE_FILE" ] && OLD_FW_PORT=$(cat "$FW_STATE_FILE" 2>/dev/null || true)
    [ -n "$OLD_FW_PORT" ] && firewall-cmd --permanent --remove-port="${OLD_FW_PORT}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port="${NEW_PORT}/tcp" >/dev/null 2>&1 || true
    printf '%s' "$NEW_PORT" > "$FW_STATE_FILE"
    firewall-cmd --reload >/dev/null 2>&1 || true
    ;;
  iptables)
    if command -v iptables-save >/dev/null 2>&1; then
      while IFS= read -r rule; do
        [ -z "$rule" ] && continue
        del_rule="${rule/-A INPUT/-D INPUT}"
        # shellcheck disable=SC2086
        iptables $del_rule 2>/dev/null || true
      done < <(iptables-save 2>/dev/null | grep -- "--comment \"${FW_TAG}\"")
    fi
    iptables -I INPUT -p tcp --dport "${NEW_PORT}" -m comment --comment "${FW_TAG}" -j ACCEPT
    if iptables -C INPUT -j VPN-PANEL-BANS 2>/dev/null; then
      iptables -D INPUT -j VPN-PANEL-BANS 2>/dev/null || true
      iptables -I INPUT 1 -j VPN-PANEL-BANS
    fi
    command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
    ;;
  *)
    echo "NOTE: no supported firewall tool detected - make sure tcp/${NEW_PORT} is open yourself." >&2
    ;;
esac

echo "PORT_OK ${NEW_PORT}"
