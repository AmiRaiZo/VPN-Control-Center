#!/bin/bash
set -Eeuo pipefail

reconfigure_phase() { printf '[reconfigure-phase] %s\n' "$*"; }
reconfigure_phase "Deployment reconfiguration started"

INSTALL_DIR="/opt/vpn-panel"
ROLE="main"
LOCAL_SERVICES="1"
CONTROLLER_URL=""
CONTROLLER_TOKEN=""
CONTROLLER_VERIFY_TLS="1"
NODE_NAME=""
NODE_PUBLIC_URL=""
NODE_VERIFY_TLS="1"
INSTALL_NOW="0"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --role) ROLE="${2:-}"; shift 2 ;;
    --local-services) LOCAL_SERVICES="${2:-}"; shift 2 ;;
    --controller-url) CONTROLLER_URL="${2:-}"; shift 2 ;;
    --controller-token) CONTROLLER_TOKEN="${2:-}"; shift 2 ;;
    --controller-verify-tls) CONTROLLER_VERIFY_TLS="${2:-}"; shift 2 ;;
    --node-name) NODE_NAME="${2:-}"; shift 2 ;;
    --node-public-url) NODE_PUBLIC_URL="${2:-}"; shift 2 ;;
    --node-verify-tls) NODE_VERIFY_TLS="${2:-}"; shift 2 ;;
    --install-now) INSTALL_NOW="${2:-}"; shift 2 ;;
    *) echo "ERROR: unknown argument: $1" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root" >&2; exit 1; }
[ -d "$INSTALL_DIR/backend/app" ] || { echo "ERROR: panel is not installed" >&2; exit 1; }
case "$ROLE" in main|node) ;; *) echo "ERROR: role must be main or node" >&2; exit 2 ;; esac
case "$LOCAL_SERVICES" in 0|1) ;; *) echo "ERROR: local-services must be 0 or 1" >&2; exit 2 ;; esac
case "$INSTALL_NOW" in 0|1) ;; *) echo "ERROR: install-now must be 0 or 1" >&2; exit 2 ;; esac
[ "$ROLE" = "node" ] && LOCAL_SERVICES=1

# A main controller must not retain any controller-registration credentials from
# its former node identity.  Clear them before touching persistent state so a
# registration timer cannot race the role conversion.
if [ "$ROLE" = "main" ]; then
  CONTROLLER_URL=""
  CONTROLLER_TOKEN=""
  CONTROLLER_VERIFY_TLS="1"
  NODE_NAME=""
  NODE_PUBLIC_URL=""
  NODE_VERIFY_TLS="1"
  systemctl disable --now vpn-panel-node-register.timer >/dev/null 2>&1 || true
  systemctl disable --now vpn-panel-node-register.service >/dev/null 2>&1 || true
  rm -f \
    /var/lib/vpn-panel/node-registration.env \
    /var/lib/vpn-panel/node-registration.ok \
    /run/vpn-panel/node-registration.env \
    /run/vpn-panel/node-registration.ok
fi

upsert_env() {
  local file="$1" key="$2" value="$3"
  mkdir -p "$(dirname "$file")"
  touch "$file"
  if grep -qE "^[[:space:]]*${key}[[:space:]]*=" "$file"; then
    sed -i -E "s#^[[:space:]]*${key}[[:space:]]*=.*#${key}=${value}#" "$file"
  else
    printf '%s=%s\n' "$key" "$value" >> "$file"
  fi
}

PANEL_ENV="$INSTALL_DIR/panel.env"
BACKEND_ENV="$INSTALL_DIR/backend/.env"
RESULT_ENV="/var/lib/vpn-panel/install-result.env"
NODE_PANEL_ENABLED="$([ "$ROLE" = "node" ] && echo 1 || echo 0)"

# Keep every durable role source synchronized.  Older releases only updated
# panel.env, leaving backend/.env and the database as node, so the UI switched
# back to the restricted node panel immediately after API startup.
for env_file in "$PANEL_ENV" "$BACKEND_ENV"; do
  upsert_env "$env_file" SERVER_ROLE "$ROLE"
  upsert_env "$env_file" DEPLOYMENT_ROLE "$ROLE"
  upsert_env "$env_file" INSTALL_LOCAL_SERVICES "$LOCAL_SERVICES"
  upsert_env "$env_file" NODE_CONTROLLER_URL "$CONTROLLER_URL"
done

upsert_env "$PANEL_ENV" CONTROLLER_URL "$CONTROLLER_URL"
upsert_env "$PANEL_ENV" CONTROLLER_TOKEN "$CONTROLLER_TOKEN"
upsert_env "$PANEL_ENV" CONTROLLER_VERIFY_TLS "$CONTROLLER_VERIFY_TLS"
upsert_env "$PANEL_ENV" NODE_NAME "$NODE_NAME"
upsert_env "$PANEL_ENV" NODE_PUBLIC_URL "$NODE_PUBLIC_URL"
upsert_env "$PANEL_ENV" NODE_VERIFY_TLS "$NODE_VERIFY_TLS"
upsert_env "$PANEL_ENV" NODE_PANEL_ENABLED "$NODE_PANEL_ENABLED"

# backend/.env is parsed by Pydantic. Unknown installer metadata is ignored, but
# writing the complete deployment state here makes systemd/API restarts
# deterministic on both current and legacy installations.
upsert_env "$BACKEND_ENV" CONTROLLER_URL "$CONTROLLER_URL"
upsert_env "$BACKEND_ENV" CONTROLLER_TOKEN "$CONTROLLER_TOKEN"
upsert_env "$BACKEND_ENV" CONTROLLER_VERIFY_TLS "$CONTROLLER_VERIFY_TLS"
upsert_env "$BACKEND_ENV" NODE_NAME "$NODE_NAME"
upsert_env "$BACKEND_ENV" NODE_PUBLIC_URL "$NODE_PUBLIC_URL"
upsert_env "$BACKEND_ENV" NODE_VERIFY_TLS "$NODE_VERIFY_TLS"
upsert_env "$BACKEND_ENV" NODE_PANEL_ENABLED "$NODE_PANEL_ENABLED"

install -d -m 0700 /var/lib/vpn-panel
upsert_env "$RESULT_ENV" SERVER_ROLE "$ROLE"
upsert_env "$RESULT_ENV" DEPLOYMENT_ROLE "$ROLE"
upsert_env "$RESULT_ENV" INSTALL_LOCAL_SERVICES "$LOCAL_SERVICES"
upsert_env "$RESULT_ENV" NODE_CONTROLLER_URL "$CONTROLLER_URL"
upsert_env "$RESULT_ENV" NODE_PUBLIC_URL "$NODE_PUBLIC_URL"

chown root:nogroup "$PANEL_ENV" "$BACKEND_ENV" 2>/dev/null || true
chmod 0640 "$PANEL_ENV" "$BACKEND_ENV" 2>/dev/null || true
chmod 0600 "$RESULT_ENV" 2>/dev/null || true

resolve_panel_python() {
  local candidate
  for candidate in \
    "$INSTALL_DIR/backend/venv/bin/python" \
    "$INSTALL_DIR/backend/venv/bin/python3"; do
    if [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  return 1
}

PANEL_PY="$(resolve_panel_python || true)"
[ -n "$PANEL_PY" ] || {
  echo "ERROR: panel Python runtime was not found under $INSTALL_DIR/backend/venv/bin" >&2
  echo "       Deployment role was not reported as changed because the database could not be updated." >&2
  exit 1
}

reconfigure_phase "Synchronizing deployment role in the database"
(
  cd "$INSTALL_DIR/backend"
  "$PANEL_PY" - \
    "$ROLE" "$LOCAL_SERVICES" "$CONTROLLER_URL" "$CONTROLLER_TOKEN" \
    "$CONTROLLER_VERIFY_TLS" "$NODE_NAME" "$NODE_PUBLIC_URL" "$NODE_VERIFY_TLS" \
    "$NODE_PANEL_ENABLED" <<'PYDB'
import sys
from app.database import SessionLocal
from app.models import Setting
from app.services.node_manager import effective_server_role, is_node_installation, panel_ui_server_role

(
    role,
    local_services,
    controller_url,
    controller_token,
    controller_verify_tls,
    node_name,
    node_public_url,
    node_verify_tls,
    node_panel_enabled,
) = sys.argv[1:]

values = {
    "server_role": role,
    "deployment_role": role,
    "local_services_mode": local_services,
    "node_controller_url": controller_url,
    "node_controller_token": controller_token,
    "node_controller_verify_tls": controller_verify_tls,
    "node_name": node_name,
    "node_public_url": node_public_url,
    "node_verify_tls": node_verify_tls,
    "node_panel_enabled": node_panel_enabled,
    # A previous node update may have left this recovery marker enabled.  It
    # must never resurrect node mode after an explicit conversion to main.
    "node_temporary_main_mode": "0",
    "node_temporary_main_started_at": "",
}

db = SessionLocal()
try:
    for key, value in values.items():
        row = db.query(Setting).filter(Setting.key == key).first()
        if row:
            row.value = value
        else:
            db.add(Setting(key=key, value=value))
    db.flush()

    effective = effective_server_role(db)
    ui_role = panel_ui_server_role(db)
    node_installation = is_node_installation(db)
    expected_node = role == "node"
    if effective != role or ui_role != role or node_installation != expected_node:
        raise RuntimeError(
            "deployment verification failed before commit: "
            f"requested={role} effective={effective} ui={ui_role} node={node_installation}"
        )
    db.commit()
except Exception:
    db.rollback()
    raise
finally:
    db.close()
PYDB
)

# Local services are independent from the panel role.  A full controller can
# keep every VPN daemon installed and running on the same server.
if [ "$LOCAL_SERVICES" = "0" ]; then
  echo "[*] Switching this controller to management-only mode. Existing VPN configuration files are preserved."
  units=(
    xl2tpd pptpd strongswan strongswan-starter ocserv accel-ppp-sstp
    vpn-panel-xray-vmess vpn-panel-xray-vless
    openvpn-server@server openvpn-server@server-udp openvpn-server@server-tcp
    openvpn@server openvpn@server-udp openvpn@server-tcp
    vpn-panel-network-repair.timer vpn-panel-network-repair.service
  )
  for unit in "${units[@]}"; do
    systemctl disable --now "$unit" >/dev/null 2>&1 || true
    systemctl reset-failed "$unit" >/dev/null 2>&1 || true
  done
  while read -r unit _; do
    case "$unit" in
      openvpn-server@server-extra-*.service|openvpn@server-extra-*.service)
        systemctl disable --now "$unit" >/dev/null 2>&1 || true
        systemctl reset-failed "$unit" >/dev/null 2>&1 || true
        ;;
    esac
  done < <(systemctl list-unit-files --no-legend 2>/dev/null || true)
  echo "[*] Local VPN daemons are disabled. They can be installed/enabled later from Protocol Management."
else
  echo "[*] Local VPN services mode enabled."
  if [ "$INSTALL_NOW" = "1" ]; then
    [ -x "$INSTALL_DIR/scripts/install_protocol.sh" ] || {
      echo "ERROR: protocol installer is missing: $INSTALL_DIR/scripts/install_protocol.sh" >&2
      exit 1
    }
    echo "[*] Installing/repairing all local VPN services now..."
    bash "$INSTALL_DIR/scripts/install_protocol.sh" all
  fi
fi

if [ "$ROLE" = "node" ] && [ -n "$CONTROLLER_URL" ] && [ -n "$CONTROLLER_TOKEN" ]; then
  if [ -x "$INSTALL_DIR/scripts/connect_node_controller.sh" ]; then
    "$INSTALL_DIR/scripts/connect_node_controller.sh" \
      "$CONTROLLER_URL" \
      "$CONTROLLER_TOKEN" \
      "${NODE_NAME:-$(hostname -s)}" \
      "$NODE_PUBLIC_URL" \
      "$CONTROLLER_VERIFY_TLS" \
      "$NODE_VERIFY_TLS" || \
      echo "[!] Node registration did not complete; retry it from the Nodes page." >&2
  fi
fi

systemctl daemon-reload
systemctl restart vpn-panel-api
if systemctl cat vpn-panel-background.service >/dev/null 2>&1; then
  systemctl restart vpn-panel-background
fi

for _ in $(seq 1 45); do
  systemctl is-active --quiet vpn-panel-api && break
  sleep 1
done
systemctl is-active --quiet vpn-panel-api || {
  systemctl status vpn-panel-api --no-pager -l >&2 || true
  journalctl -u vpn-panel-api -n 100 --no-pager >&2 || true
  exit 1
}

# Verify again after a real API restart. This catches stale environment files,
# startup recovery code or registration markers that would otherwise switch the
# host back to node mode immediately after the script prints success.
reconfigure_phase "Verifying effective role after API restart"
(
  cd "$INSTALL_DIR/backend"
  "$PANEL_PY" - "$ROLE" <<'PYVERIFY'
import sys
from app.database import SessionLocal
from app.services.node_manager import effective_server_role, is_node_installation, panel_ui_server_role

expected = sys.argv[1]
db = SessionLocal()
try:
    effective = effective_server_role(db)
    ui_role = panel_ui_server_role(db)
    node_installation = is_node_installation(db)
finally:
    db.close()

expected_node = expected == "node"
if effective != expected or ui_role != expected or node_installation != expected_node:
    raise SystemExit(
        "ERROR: deployment role did not persist after restart: "
        f"requested={expected} effective={effective} ui={ui_role} node={node_installation}"
    )
print(f"verified role={effective} ui={ui_role} node_installation={int(node_installation)}")
PYVERIFY
)

if [ -x "$INSTALL_DIR/scripts/repair_panel_access.sh" ]; then
  "$INSTALL_DIR/scripts/repair_panel_access.sh" >/dev/null
fi

# The frontend stores role only for the current browser session.  The backend is
# now authoritative; users already logged in may need one refresh, while every
# new login immediately receives the verified role.
echo "[*] Deployment mode updated successfully: role=${ROLE}, local_services=${LOCAL_SERVICES}."
reconfigure_phase "Deployment reconfiguration complete"
