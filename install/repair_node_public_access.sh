#!/bin/bash
set -Eeuo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/vpn-panel}"
REG_ENV="${VPN_PANEL_NODE_REGISTRATION_ENV:-/var/lib/vpn-panel/node-registration.env}"
PY="$INSTALL_DIR/backend/venv/bin/python"
STATE_DIR="/var/lib/vpn-panel/node-public-access"
LAST_FAIL="$STATE_DIR/last-ssl-failure"

log() { printf '[node-public-access] %s\n' "$*"; }
warn() { printf '[node-public-access] WARNING: %s\n' "$*" >&2; }
fail() { printf '[node-public-access] ERROR: %s\n' "$*" >&2; exit 1; }

[ -x "$PY" ] || fail "Python runtime is missing: $PY"
install -d -m 0750 "$STATE_DIR"

NODE_PUBLIC_URL=""
NODE_VERIFY_TLS="1"
if [ -r "$REG_ENV" ]; then
  # shellcheck disable=SC1090
  source "$REG_ENV"
  NODE_PUBLIC_URL="${NODE_PUBLIC_URL:-}"
  NODE_VERIFY_TLS="${NODE_VERIFY_TLS:-1}"
fi

read_db_values() {
  (cd "$INSTALL_DIR/backend" && "$PY" - <<'PYEOF'
from app.database import SessionLocal
from app.models import Setting
keys = ("server_role", "node_public_url")
with SessionLocal() as db:
    values = {key: "" for key in keys}
    for row in db.query(Setting).filter(Setting.key.in_(keys)).all():
        values[row.key] = row.value or ""
    print(values["server_role"])
    print(values["node_public_url"])
PYEOF
  )
}
mapfile -t DB_VALUES < <(read_db_values)
SERVER_ROLE="${DB_VALUES[0]:-main}"
DB_NODE_URL="${DB_VALUES[1]:-}"
[ "$SERVER_ROLE" = "node" ] || { log "Server role is not node; nothing to repair."; exit 0; }
[ -n "$NODE_PUBLIC_URL" ] || NODE_PUBLIC_URL="$DB_NODE_URL"
[ -n "$NODE_PUBLIC_URL" ] || fail "Node public URL is empty."

mapfile -t URL_PARTS < <("$PY" - "$NODE_PUBLIC_URL" <<'PYEOF'
import ipaddress, sys
from urllib.parse import urlparse, urlunparse
raw = sys.argv[1].strip().rstrip('/')
if '://' not in raw:
    raw = 'https://' + raw
p = urlparse(raw)
if p.scheme not in {'http', 'https'} or not p.hostname:
    raise SystemExit('invalid node URL')
port = p.port or (443 if p.scheme == 'https' else 80)
try:
    ipaddress.ip_address(p.hostname)
    is_ip = '1'
except ValueError:
    is_ip = '0'
netloc = p.hostname if port == (443 if p.scheme == 'https' else 80) else f'{p.hostname}:{port}'
print(p.scheme)
print(p.hostname)
print(port)
print(is_ip)
print(urlunparse((p.scheme, netloc, '', '', '', '')))
PYEOF
)
SCHEME="${URL_PARTS[0]}"
HOST="${URL_PARTS[1]}"
PORT="${URL_PARTS[2]}"
HOST_IS_IP="${URL_PARTS[3]}"
NODE_PUBLIC_URL="${URL_PARTS[4]}"

LOCAL_TOKEN=$(cd "$INSTALL_DIR/backend" && "$PY" - <<'PYEOF'
from app.database import SessionLocal
from app.services.node_manager import get_or_create_agent_token
with SessionLocal() as db:
    print(get_or_create_agent_token(db))
PYEOF
)

probe_local() {
  local tls_args=()
  [ "$NODE_VERIFY_TLS" = "0" ] && tls_args=(-k)
  curl "${tls_args[@]}" -fsS --connect-timeout 3 --max-time 8 \
    --resolve "${HOST}:${PORT}:127.0.0.1" \
    -H "X-Node-Token: ${LOCAL_TOKEN}" \
    "${SCHEME}://${HOST}:${PORT}/api/node-agent/health" >/dev/null
}

upsert_env() {
  local file="$1" key="$2" value="$3"
  [ -e "$file" ] || return 0
  if grep -qE "^${key}=" "$file"; then
    sed -i -E "s#^${key}=.*#${key}=$(printf '%q' "$value")#" "$file"
  else
    printf '%s=%q\n' "$key" "$value" >> "$file"
  fi
  chmod 600 "$file" 2>/dev/null || true
}

persist_runtime() {
  local domain_status="$1" domain="$2"
  (cd "$INSTALL_DIR/backend" && "$PY" - "$PORT" "$NODE_PUBLIC_URL" "$domain_status" "$domain" <<'PYEOF'
import sys
from app.database import SessionLocal
from app.models import Setting
values = {
    "panel_port": sys.argv[1],
    "node_public_url": sys.argv[2],
    "domain_ssl_status": sys.argv[3],
    "domain": sys.argv[4],
}
with SessionLocal() as db:
    for key, value in values.items():
        row = db.query(Setting).filter(Setting.key == key).first()
        if row:
            row.value = value
        else:
            db.add(Setting(key=key, value=value))
    db.commit()
PYEOF
  )
  if [ -f "$INSTALL_DIR/panel.env" ]; then
    if grep -qE '^PANEL_PORT=' "$INSTALL_DIR/panel.env"; then
      sed -i -E "s/^PANEL_PORT=.*/PANEL_PORT=${PORT}/" "$INSTALL_DIR/panel.env"
    else
      printf '\nPANEL_PORT=%s\n' "$PORT" >> "$INSTALL_DIR/panel.env"
    fi
  fi
  upsert_env "$REG_ENV" NODE_PUBLIC_URL "$NODE_PUBLIC_URL"
}

if probe_local; then
  persist_runtime "$([ "$SCHEME" = https ] && echo active || echo not_configured)" "$([ "$SCHEME" = https ] && echo "$HOST" || echo '')"
  log "Node endpoint is already healthy: $NODE_PUBLIC_URL"
  exit 0
fi

log "Repairing node endpoint for $NODE_PUBLIC_URL"
if [ "$SCHEME" = "https" ]; then
  [ "$HOST_IS_IP" = "0" ] || fail "A verified HTTPS node URL needs a domain name, not a raw IP."
  CERT_DIR="/etc/letsencrypt/live/${HOST}"
  if [ -f "$CERT_DIR/fullchain.pem" ] && [ -f "$CERT_DIR/privkey.pem" ]; then
    log "Reusing the existing Let's Encrypt certificate for $HOST."
    bash "$INSTALL_DIR/scripts/change_panel_port.sh" "$PORT" "$HOST"
  else
    if [ -e "$LAST_FAIL" ] && [ $(( $(date +%s) - $(stat -c %Y "$LAST_FAIL" 2>/dev/null || echo 0) )) -lt 300 ]; then
      fail "The previous SSL attempt failed less than five minutes ago; waiting before the next automatic retry."
    fi
    if ! bash "$INSTALL_DIR/scripts/setup_domain_ssl.sh" "$HOST"; then
      touch "$LAST_FAIL"
      fail "SSL setup for $HOST failed. Ensure TCP 80/443 reaches this server and DNS/Cloudflare points to the node."
    fi
    rm -f "$LAST_FAIL"
    if [ "$PORT" != "443" ]; then
      bash "$INSTALL_DIR/scripts/change_panel_port.sh" "$PORT" "$HOST"
    fi
  fi
  persist_runtime active "$HOST"
else
  bash "$INSTALL_DIR/scripts/change_panel_port.sh" "$PORT"
  persist_runtime not_configured ""
fi

for _ in $(seq 1 20); do
  probe_local && { log "Node endpoint repaired successfully: $NODE_PUBLIC_URL"; exit 0; }
  sleep 1
done
fail "Nginx/API is still not healthy on $NODE_PUBLIC_URL after repair."
