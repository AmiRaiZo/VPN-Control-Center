#!/bin/bash
set -euo pipefail
INSTALL_DIR="${INSTALL_DIR:-/opt/vpn-panel}"
ENV_FILE="${VPN_PANEL_NODE_REGISTRATION_ENV:-/var/lib/vpn-panel/node-registration.env}"
MARKER="/var/lib/vpn-panel/node-registration.ok"

[ -r "$ENV_FILE" ] || { echo "Node registration environment not found: $ENV_FILE" >&2; exit 2; }
# shellcheck disable=SC1090
source "$ENV_FILE"

: "${CONTROLLER_URL:?missing CONTROLLER_URL}"
: "${CONTROLLER_TOKEN:?missing CONTROLLER_TOKEN}"
: "${NODE_NAME:?missing NODE_NAME}"
: "${NODE_PUBLIC_URL:?missing NODE_PUBLIC_URL}"

if "$INSTALL_DIR/scripts/connect_node_controller.sh" \
  "$CONTROLLER_URL" "$CONTROLLER_TOKEN" "$NODE_NAME" "$NODE_PUBLIC_URL" \
  "${CONTROLLER_VERIFY_TLS:-1}" "${NODE_VERIFY_TLS:-1}"; then
  install -d -m 0750 /var/lib/vpn-panel
  date -u +%FT%TZ > "$MARKER"
  chmod 0600 "$MARKER"
  systemctl disable --now vpn-panel-node-register.timer >/dev/null 2>&1 || true
  exit 0
fi
exit 1
