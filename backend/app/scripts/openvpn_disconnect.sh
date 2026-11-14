#!/bin/bash
# Used by server.conf: client-disconnect /opt/vpn-panel/scripts/openvpn_disconnect.sh
set -u
RUNTIME_ENV="/etc/vpn-panel/openvpn-hook.env"
LEGACY_ENV="/opt/vpn-panel/panel.env"
if [ -r "$RUNTIME_ENV" ]; then
  # shellcheck disable=SC1090
  source "$RUNTIME_ENV"
elif [ -r "$LEGACY_ENV" ]; then
  # shellcheck disable=SC1091
  source "$LEGACY_ENV"
else
  logger -t vpn-panel-admission "disconnect skipped protocol=openvpn reason=hook_env_unreadable uid=$(id -u) gid=$(id -g)"
  exit 0
fi
BACKEND_PORT="${BACKEND_PORT:-8000}"
INTERNAL_API_TOKEN="${INTERNAL_API_TOKEN:-}"

USERNAME="${common_name:-}"
[ -z "$USERNAME" ] && USERNAME="${username:-}"
RX="${bytes_received:-0}"
TX="${bytes_sent:-0}"
TUNNEL_IP="${ifconfig_pool_remote_ip:-}"

/usr/bin/curl -sS --connect-timeout 1 --max-time 3 -o /dev/null -X POST "http://127.0.0.1:${BACKEND_PORT}/api/internal/disconnect" \
  -H "Content-Type: application/json" \
  -H "X-Internal-Token: ${INTERNAL_API_TOKEN}" \
  -d "{\"username\":\"${USERNAME}\",\"protocol\":\"openvpn\",\"interface\":\"${dev:-}\",\"tunnel_ip\":\"${TUNNEL_IP}\",\"bytes_in\":${RX},\"bytes_out\":${TX}}" >/dev/null 2>&1 || true

if [ -x /opt/vpn-panel/scripts/ensure_session_networking.sh ]; then
  /opt/vpn-panel/scripts/ensure_session_networking.sh --down openvpn "${dev:-}" "$TUNNEL_IP" >/dev/null 2>&1 || true
fi
exit 0
