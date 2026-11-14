#!/bin/bash
# Used by server.conf: client-connect /opt/vpn-panel/scripts/openvpn_connect.sh
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
  logger -t vpn-panel-admission "FAIL-OPEN protocol=openvpn reason=hook_env_unreadable uid=$(id -u) gid=$(id -g)"
  exit 0
fi
BACKEND_PORT="${BACKEND_PORT:-8000}"
INTERNAL_API_TOKEN="${INTERNAL_API_TOKEN:-}"
source /opt/vpn-panel/scripts/admission_guard.sh

USERNAME="${common_name:-}"
[ -z "$USERNAME" ] && USERNAME="${username:-}"
REMOTE_IP="${trusted_ip:-}"
TUNNEL_IP="${ifconfig_pool_remote_ip:-}"
SOURCE_PORT="${trusted_port:-}"
PLATFORM="${IV_PLAT:-}"
CLIENT_INFO="${IV_GUI_VER:-}"

SOURCE_PORT_JSON="null"
if [[ "$SOURCE_PORT" =~ ^[0-9]+$ ]] && [ "$SOURCE_PORT" -ge 1 ] && [ "$SOURCE_PORT" -le 65535 ]; then
  SOURCE_PORT_JSON="$SOURCE_PORT"
fi
PAYLOAD="{\"username\":\"${USERNAME}\",\"protocol\":\"openvpn\",\"ip_address\":\"${REMOTE_IP}\",\"source_port\":${SOURCE_PORT_JSON},\"interface\":\"${dev:-}\",\"tunnel_ip\":\"${TUNNEL_IP}\",\"platform\":\"${PLATFORM}\",\"client_info\":\"${CLIENT_INFO}\"}"
if ! vpn_panel_admission_request "$PAYLOAD" "$USERNAME" "openvpn" "$REMOTE_IP"; then
  exit 1
fi

if [ -x /opt/vpn-panel/scripts/ensure_session_networking.sh ]; then
  /opt/vpn-panel/scripts/ensure_session_networking.sh --up openvpn "${dev:-}" "$TUNNEL_IP" >/dev/null 2>&1 || true
fi
exit 0
