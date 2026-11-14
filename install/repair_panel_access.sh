#!/bin/bash
set -Eeuo pipefail

INSTALL_DIR="/opt/vpn-panel"
WEB_DIR="/var/www/vpn-panel"
SITE_AVAILABLE="/etc/nginx/sites-available/vpn-panel"
SITE_ENABLED="/etc/nginx/sites-enabled/vpn-panel"
RESULT_FILE="/var/lib/vpn-panel/install-result.env"

PUBLIC_IP_INPUT="${1:-}"
PANEL_PORT_INPUT="${2:-}"
BACKEND_PORT_INPUT="${3:-}"

log() { printf '[panel-access] %s\n' "$*"; }
warn() { printf '[panel-access] WARNING: %s\n' "$*" >&2; }
fail() { printf '[panel-access] ERROR: %s\n' "$*" >&2; exit 1; }

read_env_value() {
  local file="$1" key="$2"
  [ -r "$file" ] || return 0
  awk -v key="$key" -F= '
    $1 ~ "^[[:space:]]*" key "[[:space:]]*$" {
      v=$0; sub(/^[^=]*=/,"",v); gsub(/^[[:space:]\"\047]+|[[:space:]\"\047]+$/,"",v); print v
    }
  ' "$file" | tail -n1
}

upsert_env_value() {
  local file="$1" key="$2" value="$3"
  mkdir -p "$(dirname "$file")"
  touch "$file"
  chmod 600 "$file" 2>/dev/null || true
  if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$file"; then
    sed -i -E "s#^[[:space:]]*${key}[[:space:]]*=.*#${key}=${value}#" "$file"
  else
    printf '%s=%s\n' "$key" "$value" >> "$file"
  fi
}

detect_public_ip() {
  local value=""
  for url in https://ifconfig.me https://icanhazip.com https://api.ipify.org; do
    value=$(curl -fsS -4 --connect-timeout 3 --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]' || true)
    if [[ "$value" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
      printf '%s' "$value"
      return 0
    fi
  done
  hostname -I 2>/dev/null | awk '{print $1}'
}

detect_backend_port() {
  local port="" exec_line="" unit_file=""
  exec_line=$(systemctl show -p ExecStart --value vpn-panel-api 2>/dev/null || true)
  port=$(printf '%s\n' "$exec_line" | grep -oE -- '--port([=[:space:]])+[0-9]+' | grep -oE '[0-9]+' | tail -n1 || true)
  if [ -z "$port" ]; then
    unit_file=$(systemctl show -p FragmentPath --value vpn-panel-api 2>/dev/null || true)
    [ -f "$unit_file" ] && port=$(grep -oE -- '--port([=[:space:]])+[0-9]+' "$unit_file" 2>/dev/null | grep -oE '[0-9]+' | tail -n1 || true)
  fi
  [ -z "$port" ] && port=$(read_env_value "$INSTALL_DIR/panel.env" BACKEND_PORT || true)
  [ -z "$port" ] && port=$(read_env_value "$INSTALL_DIR/backend/.env" BACKEND_PORT || true)
  [ -z "$port" ] && port=18000
  printf '%s' "$port"
}

detect_panel_port() {
  local port=""
  if [ -f "$SITE_AVAILABLE" ]; then
    port=$(grep -E '^[[:space:]]*listen[[:space:]]+' "$SITE_AVAILABLE" 2>/dev/null \
      | sed -nE 's/.*\[::\]:([0-9]+).*/\1/p; s/^[[:space:]]*listen[[:space:]]+([0-9]+)([[:space:];].*)?$/\1/p' \
      | head -n1 || true)
  fi
  [ -z "$port" ] && port=$(read_env_value "$INSTALL_DIR/panel.env" PANEL_PORT || true)
  [ -z "$port" ] && port=$(read_env_value "$INSTALL_DIR/backend/.env" PANEL_PORT || true)
  [ -z "$port" ] && port=8080
  printf '%s' "$port"
}

port_listener_owner() {
  local port="$1"
  ss -ltnpH 2>/dev/null | awk -v p=":${port}" '$4 ~ p"$" {print; exit}'
}

choose_panel_port() {
  local requested="$1" owner candidate
  owner=$(port_listener_owner "$requested" || true)
  if [ -z "$owner" ] || grep -qi nginx <<<"$owner"; then
    printf '%s' "$requested"
    return 0
  fi
  warn "tcp/${requested} is owned by another process: ${owner}"
  for candidate in 8000 $(seq 8001 8099) $(seq 18080 18120); do
    [ "$candidate" = "$BACKEND_PORT" ] && continue
    owner=$(port_listener_owner "$candidate" || true)
    if [ -z "$owner" ]; then
      warn "Panel port changed automatically: ${requested} -> ${candidate}"
      printf '%s' "$candidate"
      return 0
    fi
  done
  fail "No free public TCP port was found for the panel."
}

open_firewall_port() {
  local port="$1"
  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then
    ufw allow "${port}/tcp" comment "vpnpanel-panel" >/dev/null 2>&1 || true
  elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q running; then
    firewall-cmd --permanent --add-port="${port}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
  elif command -v iptables >/dev/null 2>&1; then
    iptables -C INPUT -p tcp --dport "$port" -j ACCEPT 2>/dev/null || \
      iptables -I INPUT 1 -p tcp --dport "$port" -m comment --comment vpnpanel-panel -j ACCEPT 2>/dev/null || true
    command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
  fi
}

PUBLIC_IP="${PUBLIC_IP_INPUT:-$(detect_public_ip)}"
BACKEND_PORT="${BACKEND_PORT_INPUT:-$(detect_backend_port)}"
REQUESTED_PANEL_PORT="${PANEL_PORT_INPUT:-$(detect_panel_port)}"
[[ "$BACKEND_PORT" =~ ^[0-9]+$ ]] || fail "Invalid backend port: ${BACKEND_PORT}"
[[ "$REQUESTED_PANEL_PORT" =~ ^[0-9]+$ ]] || fail "Invalid panel port: ${REQUESTED_PANEL_PORT}"

[ -f "$WEB_DIR/index.html" ] || fail "Frontend is missing: $WEB_DIR/index.html"
command -v nginx >/dev/null 2>&1 || fail "Nginx is not installed."
mkdir -p /etc/nginx/sites-available /etc/nginx/sites-enabled

site_scheme() {
  local site="$1"
  if grep -Eq '^[[:space:]]*listen[[:space:]].*ssl|^[[:space:]]*ssl_certificate[[:space:]]+' "$site" 2>/dev/null; then
    printf 'https'
  else
    printf 'http'
  fi
}

site_host() {
  local site="$1" host=""
  host=$(awk '
    /^[[:space:]]*server_name[[:space:]]+/ {
      line=$0; sub(/#.*/,"",line); sub(/^[[:space:]]*server_name[[:space:]]+/,"",line); sub(/;.*/,"",line)
      n=split(line,a,/[^A-Za-z0-9._*-]+/)
      for (i=1;i<=n;i++) if (a[i] != "" && a[i] != "_" && a[i] !~ /^\*/) {print a[i]; exit}
    }
  ' "$site" 2>/dev/null || true)
  printf '%s' "${host:-${PUBLIC_IP:-127.0.0.1}}"
}

probe_panel() {
  local scheme="$1" host="$2" port="$3" path="$4"
  curl -kfsS --connect-timeout 2 --max-time 4 \
    --resolve "${host}:${port}:127.0.0.1" \
    "${scheme}://${host}:${port}${path}" >/dev/null 2>&1
}

PANEL_PORT="$REQUESTED_PANEL_PORT"
PANEL_SCHEME="http"
PANEL_HOST="${PUBLIC_IP:-127.0.0.1}"
EXISTING_HEALTHY=0
NGINX_CONFIG_OK=0

if [ -f "$SITE_AVAILABLE" ]; then
  PANEL_SCHEME=$(site_scheme "$SITE_AVAILABLE")
  PANEL_HOST=$(site_host "$SITE_AVAILABLE")
  # The Nginx file is authoritative once a domain/SSL repair moved the panel.
  # Do not keep probing the stale requested/default port (usually 8080), or a
  # healthy HTTPS:443 node is incorrectly replaced by an HTTP recovery vhost.
  DETECTED_SITE_PORT=$(detect_panel_port)
  [[ "$DETECTED_SITE_PORT" =~ ^[0-9]+$ ]] && PANEL_PORT="$DETECTED_SITE_PORT"
  if nginx -t >/dev/null 2>&1; then
    NGINX_CONFIG_OK=1
    systemctl enable nginx >/dev/null 2>&1 || true
    systemctl restart nginx >/dev/null 2>&1 || true
    open_firewall_port "$PANEL_PORT"
    ROOT_OK=0
    API_OK=0
    for _ in $(seq 1 12); do
      probe_panel "$PANEL_SCHEME" "$PANEL_HOST" "$PANEL_PORT" "/" && ROOT_OK=1 || true
      probe_panel "$PANEL_SCHEME" "$PANEL_HOST" "$PANEL_PORT" "/api/health" && API_OK=1 || true
      [ "$ROOT_OK" -eq 1 ] && [ "$API_OK" -eq 1 ] && break
      sleep 1
    done
    if [ "$ROOT_OK" -eq 1 ] && [ "$API_OK" -eq 1 ]; then
      EXISTING_HEALTHY=1
      log "Existing Nginx panel vhost is healthy; preserving its HTTP/HTTPS and domain settings."
    fi
  fi
fi

if [ "$EXISTING_HEALTHY" -ne 1 ]; then
  # Preserve a custom or SSL vhost instead of destroying it. If it is broken,
  # disable only its enabled symlink and create a separate IP-based recovery
  # vhost. The original file remains available for manual/domain repair.
  RECOVERY_MODE=0
  TARGET_SITE_AVAILABLE="$SITE_AVAILABLE"
  TARGET_SITE_ENABLED="$SITE_ENABLED"
  if [ -f "$SITE_AVAILABLE" ]; then
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    cp -a "$SITE_AVAILABLE" "${SITE_AVAILABLE}.pre-repair.${stamp}"
    if [ "$PANEL_SCHEME" = "https" ]; then
      RECOVERY_MODE=1
      TARGET_SITE_AVAILABLE="/etc/nginx/sites-available/vpn-panel-recovery"
      TARGET_SITE_ENABLED="/etc/nginx/sites-enabled/vpn-panel-recovery"
      if [ "$NGINX_CONFIG_OK" -ne 1 ]; then
        rm -f "$SITE_ENABLED"
        warn "The existing HTTPS vhost failed nginx -t and was disabled; a backup was kept at ${SITE_AVAILABLE}.pre-repair.${stamp}."
      else
        warn "The existing HTTPS vhost did not serve the frontend/API correctly; an additional IP-based recovery URL will be created."
      fi
    else
      warn "The existing HTTP vhost did not serve the frontend/API correctly and will be rebuilt; a backup was kept at ${SITE_AVAILABLE}.pre-repair.${stamp}."
    fi
  fi

  RECOVERY_REQUEST="$REQUESTED_PANEL_PORT"
  if [ "$RECOVERY_MODE" -eq 1 ] || [ "$RECOVERY_REQUEST" = "443" ]; then
    RECOVERY_REQUEST=8080
  fi
  PANEL_PORT=$(choose_panel_port "$RECOVERY_REQUEST")
  PANEL_SCHEME="http"
  PANEL_HOST="${PUBLIC_IP:-127.0.0.1}"

  cat > "$TARGET_SITE_AVAILABLE" <<NGINX
server {
    listen ${PANEL_PORT};
    listen [::]:${PANEL_PORT};
    server_name ${PUBLIC_IP:-_} _;

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
        proxy_connect_timeout 30s;
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
NGINX
  ln -sfn "$TARGET_SITE_AVAILABLE" "$TARGET_SITE_ENABLED"
  rm -f /etc/nginx/sites-enabled/default
  nginx -t || fail "Nginx configuration validation failed after panel vhost repair."
  systemctl enable nginx >/dev/null 2>&1 || true
  systemctl restart nginx || {
    systemctl status nginx --no-pager -l >&2 || true
    journalctl -u nginx -n 80 --no-pager >&2 || true
    fail "Nginx failed to start after panel vhost repair."
  }
  open_firewall_port "$PANEL_PORT"
fi

# Require both the static frontend and the API proxy to work through Nginx.
ROOT_OK=0
API_OK=0
for _ in $(seq 1 30); do
  probe_panel "$PANEL_SCHEME" "$PANEL_HOST" "$PANEL_PORT" "/" && ROOT_OK=1 || true
  probe_panel "$PANEL_SCHEME" "$PANEL_HOST" "$PANEL_PORT" "/api/health" && API_OK=1 || true
  [ "$ROOT_OK" -eq 1 ] && [ "$API_OK" -eq 1 ] && break
  sleep 1
done
[ "$ROOT_OK" -eq 1 ] || fail "The panel frontend is not reachable locally through Nginx on ${PANEL_SCHEME} tcp/${PANEL_PORT}."
[ "$API_OK" -eq 1 ] || fail "The panel API proxy is not healthy through Nginx on ${PANEL_SCHEME} tcp/${PANEL_PORT}."
ss -ltnpH 2>/dev/null | grep -Eq "(^|[[:space:]])(0\.0\.0\.0|\*|\[::\]):${PANEL_PORT}([[:space:]]|$)" || \
  fail "Nginx is not listening publicly on tcp/${PANEL_PORT}."

# Keep the runtime values consistent for future updates and the license wrapper.
upsert_env_value "$INSTALL_DIR/panel.env" PANEL_PORT "$PANEL_PORT"
upsert_env_value "$INSTALL_DIR/panel.env" BACKEND_PORT "$BACKEND_PORT"
[ -f "$INSTALL_DIR/backend/.env" ] && upsert_env_value "$INSTALL_DIR/backend/.env" BACKEND_PORT "$BACKEND_PORT"

# Update the panel settings table when the backend environment is usable.
if [ -x "$INSTALL_DIR/backend/venv/bin/python" ] && [ -d "$INSTALL_DIR/backend/app" ]; then
  (cd "$INSTALL_DIR/backend" && "$INSTALL_DIR/backend/venv/bin/python" - "$PANEL_PORT" "$BACKEND_PORT" <<'PYDB'
import sys
from app.database import SessionLocal
from app.models import Setting
values = {"panel_port": sys.argv[1], "backend_port": sys.argv[2]}
db = SessionLocal()
try:
    for key, value in values.items():
        row = db.query(Setting).filter(Setting.key == key).first()
        if row:
            row.value = value
        else:
            db.add(Setting(key=key, value=value))
    db.commit()
finally:
    db.close()
PYDB
  ) || warn "Could not update panel_port/backend_port in the database; web access is still healthy."
fi

ADMIN_USER=$(read_env_value "$RESULT_FILE" ADMIN_USER || true)
[ -z "$ADMIN_USER" ] && ADMIN_USER=admin
SERVER_ROLE=$(read_env_value "$INSTALL_DIR/panel.env" SERVER_ROLE || true)
[ -z "$SERVER_ROLE" ] && SERVER_ROLE=main
INSTALL_LOCAL_SERVICES=$(read_env_value "$INSTALL_DIR/panel.env" INSTALL_LOCAL_SERVICES || true)
[ -z "$INSTALL_LOCAL_SERVICES" ] && INSTALL_LOCAL_SERVICES=1
NODE_CONTROLLER_URL=$(read_env_value "$INSTALL_DIR/panel.env" NODE_CONTROLLER_URL || true)
NODE_PUBLIC_URL=$(read_env_value "$INSTALL_DIR/panel.env" NODE_PUBLIC_URL || true)
PANEL_URL="${PANEL_SCHEME}://${PANEL_HOST}:${PANEL_PORT}"

install -d -m 0750 /var/lib/vpn-panel
cat > "$RESULT_FILE" <<RESULT
SERVER_IP=${PUBLIC_IP}
PANEL_PORT=${PANEL_PORT}
BACKEND_PORT=${BACKEND_PORT}
PANEL_URL=${PANEL_URL}
ADMIN_USER=${ADMIN_USER}
SERVER_ROLE=${SERVER_ROLE}
INSTALL_LOCAL_SERVICES=${INSTALL_LOCAL_SERVICES}
NODE_CONTROLLER_URL=${NODE_CONTROLLER_URL}
NODE_PUBLIC_URL=${NODE_PUBLIC_URL}
PANEL_LOCAL_HEALTH=ok
RESULT
chmod 600 "$RESULT_FILE"

# A self-connect to the public endpoint may fail on providers without NAT
# loopback, so it is advisory. Local Nginx + API health above is mandatory.
PUBLIC_SELF_TEST="unknown"
if [ -n "$PANEL_HOST" ]; then
  if curl -kfsS --connect-timeout 3 --max-time 6 "$PANEL_URL/" >/dev/null 2>&1; then
    PUBLIC_SELF_TEST="ok"
  else
    PUBLIC_SELF_TEST="failed"
    warn "Local panel health is OK, but the server could not reach ${PANEL_URL}. Check the provider/cloud firewall for TCP/${PANEL_PORT}."
  fi
fi
printf 'PANEL_PUBLIC_SELF_TEST=%s\n' "$PUBLIC_SELF_TEST" >> "$RESULT_FILE"

log "Panel verified: ${PANEL_URL} (API 127.0.0.1:${BACKEND_PORT}, public-self-test=${PUBLIC_SELF_TEST})"
printf '%s\n' "$PANEL_PORT"
