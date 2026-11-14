#!/bin/bash
###############################################################################
# Changes the port Nginx serves the panel on. Two modes:
#   change_panel_port.sh <port>            IP-based panel (no domain/SSL)
#   change_panel_port.sh <port> <domain>   Domain+SSL panel - reuses the
#                                           already-issued Let's Encrypt cert
#                                           for <domain> and rewrites the
#                                           HTTPS vhost to listen on <port>
#                                           instead of 443, WITHOUT calling
#                                           certbot again.
#
# In domain mode, if <port> is 443 the usual "reject anything that isn't
# this domain" catch-all is (re)installed on 443. If <port> is anything
# else, nginx does NOT bind 443 at all anymore, freeing it up for another
# service (e.g. moving OpenConnect to 443).
#
# Can be called by the backend, or directly via SSH:
#   sudo bash /opt/vpn-panel/scripts/change_panel_port.sh 8080
#   sudo bash /opt/vpn-panel/scripts/change_panel_port.sh 8443 panel.example.com
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

if [ -z "$NEW_PORT" ]; then
  echo "Usage: change_panel_port.sh <port> [domain]" >&2
  exit 1
fi
if [ "$NEW_PORT" = "$BACKEND_PORT" ]; then
  echo "ERROR: tcp/${NEW_PORT} is reserved for the private VPN Panel API. Choose a different public panel port." >&2
  exit 1
fi

if [ -n "$DOMAIN" ]; then
  CERT_DIR="/etc/letsencrypt/live/${DOMAIN}"
  if [ ! -f "${CERT_DIR}/fullchain.pem" ] || [ ! -f "${CERT_DIR}/privkey.pem" ]; then
    echo "ERROR: no Let's Encrypt certificate found for ${DOMAIN} at ${CERT_DIR} - run the domain/SSL setup again instead." >&2
    exit 1
  fi

  REJECT_CERT_DIR="/etc/nginx/vpn-panel-reject"
  REJECT_BLOCK=""
  if [ "$NEW_PORT" = "443" ]; then
    if [ ! -f "${REJECT_CERT_DIR}/reject.crt" ]; then
      mkdir -p "$REJECT_CERT_DIR"
      openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
        -keyout "${REJECT_CERT_DIR}/reject.key" \
        -out "${REJECT_CERT_DIR}/reject.crt" \
        -subj "/CN=invalid" >/dev/null 2>&1
    fi
    REJECT_BLOCK="server {
    listen 443 ssl;
    listen [::]:443 ssl;
    ssl_certificate ${REJECT_CERT_DIR}/reject.crt;
    ssl_certificate_key ${REJECT_CERT_DIR}/reject.key;
    server_name _;
    return 444;
}"
  fi

  cat > /etc/nginx/sites-available/vpn-panel << EOF
# --- catch-all on 80: anything that isn't ${DOMAIN} gets dropped ---
server {
    listen 80;
    listen [::]:80;
    server_name _;
    return 444;
}

${REJECT_BLOCK}

# --- real vhost: only ${DOMAIN}, over HTTPS on port ${NEW_PORT} ---
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
        add_header Cache-Control "no-cache" always;
        try_files \$uri \$uri/ /index.html;
    }
}
EOF
else
  cat > /etc/nginx/sites-available/vpn-panel << EOF
server {
    listen ${NEW_PORT};
    listen [::]:${NEW_PORT};
    server_name _;

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
        add_header Cache-Control "no-cache" always;
        try_files \$uri \$uri/ /index.html;
    }
}
EOF
fi

nginx -t
systemctl is-active --quiet nginx && systemctl reload nginx || systemctl start nginx

# Keep every link generator in sync with the actual public listener. Older
# versions changed Nginx but left PANEL_PORT stale, which produced subscription
# links without the new port until another install/repair run.
PANEL_ENV="/opt/vpn-panel/panel.env"
touch "$PANEL_ENV"
if grep -qE '^PANEL_PORT=' "$PANEL_ENV"; then
  sed -i -E "s/^PANEL_PORT=.*/PANEL_PORT=${NEW_PORT}/" "$PANEL_ENV"
else
  printf '\nPANEL_PORT=%s\n' "$NEW_PORT" >> "$PANEL_ENV"
fi
chmod 600 "$PANEL_ENV" 2>/dev/null || true

# ---------------------------------------------------------------------------
# Keep the host firewall (ufw/firewalld/plain iptables - whichever is active)
# in sync with the panel's actual port: remove our own previous rule (tagged
# "vpnpanel-panel", so nothing added by hand is ever touched) and open the
# new one. Without this, changing the panel port here would make Nginx
# listen on it but leave it unreachable until someone opens it by hand -
# and if that happens before this script runs, the panel is temporarily
# unreachable to fix it back.
# ---------------------------------------------------------------------------
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
      rule_num=$(ufw status numbered 2>/dev/null | grep "# vpnpanel-panel$" | tail -n1 | grep -oE '^\[[0-9]+\]' | tr -d '[]')
      [ -z "$rule_num" ] && break
      yes | ufw delete "$rule_num" >/dev/null 2>&1 || break
    done
    ufw allow "${NEW_PORT}/tcp" comment "vpnpanel-panel" >/dev/null 2>&1 || true
    ;;
  firewalld)
    FW_STATE_DIR="/var/lib/vpn-panel/firewall"
    FW_STATE_FILE="${FW_STATE_DIR}/vpnpanel-panel-tcp.port"
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
      done < <(iptables-save 2>/dev/null | grep -- '--comment "vpnpanel-panel"')
    fi
    iptables -I INPUT -p tcp --dport "${NEW_PORT}" -m comment --comment "vpnpanel-panel" -j ACCEPT
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
