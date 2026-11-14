#!/bin/bash
set -euo pipefail
INSTALL_DIR="${INSTALL_DIR:-/opt/vpn-panel}"
CONTROLLER_URL="${1:-}"
CONTROLLER_TOKEN="${2:-}"
NODE_NAME="${3:-$(hostname -s)}"
NODE_PUBLIC_URL="${4:-}"
CONTROLLER_VERIFY_TLS="${5:-1}"
NODE_VERIFY_TLS="${6:-1}"

if [ -z "$CONTROLLER_URL" ] || [ -z "$CONTROLLER_TOKEN" ] || [ -z "$NODE_PUBLIC_URL" ]; then
  echo "Usage: $0 <controller-url> <controller-token> <node-name> <node-public-url> [verify-controller:0|1] [verify-node:0|1]" >&2
  exit 2
fi
CONTROLLER_URL="${CONTROLLER_URL%/}"
CONTROLLER_URL="${CONTROLLER_URL%/api}"
NODE_PUBLIC_URL="${NODE_PUBLIC_URL%/}"
BACKEND_DIR="$INSTALL_DIR/backend"
PY="$BACKEND_DIR/venv/bin/python"
[ -x "$PY" ] || { echo "VPN Panel Python runtime not found" >&2; exit 1; }
# The registration helper imports the installed backend as the top-level
# ``app`` package.  systemd starts this script outside the backend directory,
# so make that package importable for every embedded Python block.
export PYTHONPATH="$BACKEND_DIR${PYTHONPATH:+:$PYTHONPATH}"
command -v curl >/dev/null 2>&1 || { echo "curl is required for node registration" >&2; exit 1; }

install -d -m 0750 /var/lib/vpn-panel
ENV_FILE=/var/lib/vpn-panel/node-registration.env
{
  printf 'CONTROLLER_URL=%q\n' "$CONTROLLER_URL"
  printf 'CONTROLLER_TOKEN=%q\n' "$CONTROLLER_TOKEN"
  printf 'NODE_NAME=%q\n' "$NODE_NAME"
  printf 'NODE_PUBLIC_URL=%q\n' "$NODE_PUBLIC_URL"
  printf 'CONTROLLER_VERIFY_TLS=%q\n' "$CONTROLLER_VERIFY_TLS"
  printf 'NODE_VERIFY_TLS=%q\n' "$NODE_VERIFY_TLS"
} > "$ENV_FILE"
chmod 0600 "$ENV_FILE"

# Make the advertised endpoint real before the controller sees it. In older
# builds an HTTPS URL could be registered while Nginx was still serving plain
# HTTP on 8080, which produced Cloudflare 521 and a permanently-offline row.
if [ -x "$INSTALL_DIR/scripts/repair_node_public_access.sh" ]; then
  "$INSTALL_DIR/scripts/repair_node_public_access.sh"
  # The repair helper normalizes the URL/port in the persisted environment.
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  NODE_PUBLIC_URL="${NODE_PUBLIC_URL%/}"
fi

LOCAL_TOKEN=$(cd "$INSTALL_DIR/backend" && "$PY" - <<'PYEOF'
from app.database import SessionLocal
from app.services.node_manager import get_or_create_agent_token
with SessionLocal() as db:
    print(get_or_create_agent_token(db))
PYEOF
)
PAYLOAD=$(cd "$BACKEND_DIR" && NODE_NAME="$NODE_NAME" NODE_PUBLIC_URL="$NODE_PUBLIC_URL" LOCAL_TOKEN="$LOCAL_TOKEN" NODE_VERIFY_TLS="$NODE_VERIFY_TLS" "$PY" - <<'PYEOF'
import json, os
from app.database import SessionLocal
from app.models import Setting
from app.services.node_remote import decrypt_password

def setting(db, key, default=""):
    row = db.query(Setting).filter(Setting.key == key).first()
    return row.value if row and row.value is not None else default

with SessionLocal() as db:
    ssh_host = setting(db, "node_ssh_host", "").strip()
    ssh_port_raw = setting(db, "node_ssh_port", "22")
    ssh_username = setting(db, "node_ssh_username", "root").strip() or "root"
    ssh_password = decrypt_password(setting(db, "node_ssh_password_enc", "")) or ""
    ssh_configured = setting(db, "node_ssh_configured", "0").strip().lower() in {"1", "true", "yes", "on"}
try:
    ssh_port = int(ssh_port_raw)
except Exception:
    ssh_port = 22
payload = {
    "name": os.environ["NODE_NAME"],
    "api_url": os.environ["NODE_PUBLIC_URL"],
    "api_token": os.environ["LOCAL_TOKEN"],
    "enabled": True,
    "verify_tls": os.environ.get("NODE_VERIFY_TLS", "1") in {"1", "true", "yes", "y"},
    "weight": 100,
    "ssh_host": ssh_host or None,
    "ssh_port": ssh_port,
    "ssh_username": ssh_username or None,
    "ssh_password": ssh_password or None,
    "save_ssh_password": bool(ssh_password),
    "clear_ssh_password": bool(ssh_configured and not ssh_password),
}
print(json.dumps(payload, ensure_ascii=False))
PYEOF
)
CURL_TLS=()
[ "$CONTROLLER_VERIFY_TLS" = "0" ] && CURL_TLS=(-k)

# A single invocation retries long enough to cover DNS propagation, service
# startup and local firewall reloads. The systemd timer continues later if the
# provider-side network is still unavailable.
last_error=""
for attempt in $(seq 1 12); do
  tmp=$(mktemp)
  status=$(curl "${CURL_TLS[@]}" -sS --connect-timeout 10 --max-time 35 \
    -o "$tmp" -w '%{http_code}' \
    -H "Content-Type: application/json" \
    -H "X-Node-Token: ${CONTROLLER_TOKEN}" \
    -X POST "${CONTROLLER_URL}/api/node-agent/register" \
    --data "$PAYLOAD" 2>"${tmp}.err" || true)
  if [ "$status" = "200" ] || [ "$status" = "201" ]; then
    cat "$tmp"; echo
    rm -f "$tmp" "${tmp}.err"
    echo "Node registered on controller: ${CONTROLLER_URL}"
    exit 0
  fi
  last_error="HTTP ${status:-000}: $(cat "${tmp}.err" 2>/dev/null) $(cat "$tmp" 2>/dev/null)"
  rm -f "$tmp" "${tmp}.err"
  echo "[node-register] attempt ${attempt}/12 failed: ${last_error}" >&2
  sleep $(( attempt < 6 ? 5 : 15 ))
done

echo "Node registration is still pending: ${last_error}" >&2
exit 1
