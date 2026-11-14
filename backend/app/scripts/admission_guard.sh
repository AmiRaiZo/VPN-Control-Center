#!/bin/bash
# Shared, resilient admission request for authenticated VPN hooks.
# Return 0 = allow; return 1 = explicit panel denial.
# Transport/backend failures are logged and fail open so an API slowdown cannot
# take every VPN protocol offline. User/password/certificate authentication has
# already succeeded before this helper is called.

vpn_panel_admission_request() {
  local payload="$1"
  local username="${2:-unknown}"
  local protocol="${3:-unknown}"
  local client_ip="${4:-unknown}"
  local backend_port="${BACKEND_PORT:-8000}"
  local tmp code curl_rc detail handover
  VPN_PANEL_ADMISSION_HANDOVER=0
  VPN_PANEL_ADMISSION_REPLACED_PID=""

  tmp="$(mktemp /tmp/vpn-panel-admission.XXXXXX 2>/dev/null || echo /tmp/vpn-panel-admission.$$)"
  code=$(curl -sS --connect-timeout 1 --max-time 3 -o "$tmp" -w "%{http_code}" \
    -X POST "http://127.0.0.1:${backend_port}/api/internal/connect" \
    -H "Content-Type: application/json" \
    -H "X-Internal-Token: ${INTERNAL_API_TOKEN}" \
    -d "$payload" 2>/dev/null)
  curl_rc=$?
  detail="$(tr '\n\r' '  ' < "$tmp" 2>/dev/null | cut -c1-240)"

  if [ "$curl_rc" -eq 0 ] && [[ "$code" == 2* ]]; then
    if command -v python3 >/dev/null 2>&1; then
      read -r handover VPN_PANEL_ADMISSION_REPLACED_PID < <(python3 - "$tmp" <<'PYJSON'
import json, sys
try:
    data = json.load(open(sys.argv[1], encoding='utf-8'))
except Exception:
    data = {}
print('1' if data.get('handover') else '0', int(data.get('replaced_pid') or 0))
PYJSON
      )
      VPN_PANEL_ADMISSION_HANDOVER="${handover:-0}"
      [ "${VPN_PANEL_ADMISSION_REPLACED_PID:-0}" = "0" ] && VPN_PANEL_ADMISSION_REPLACED_PID=""
    fi
    rm -f "$tmp" 2>/dev/null || true
    logger -t vpn-panel-admission "ALLOW protocol=${protocol} user=${username} ip=${client_ip} code=${code} handover=${VPN_PANEL_ADMISSION_HANDOVER}"
    return 0
  fi

  rm -f "$tmp" 2>/dev/null || true

  # Explicit application denials remain fail-closed: disabled/expired user,
  # quota, shared max-user cap, blocked public IP, missing user, invalid input.
  if [ "$curl_rc" -eq 0 ] && [[ "$code" == 4* ]] && [ "$code" != "401" ] && [ "$code" != "408" ] && [ "$code" != "429" ]; then
    logger -t vpn-panel-admission "DENY protocol=${protocol} user=${username} ip=${client_ip} code=${code} detail=${detail:-none}"
    return 1
  fi

  # 000/timeouts, 5xx, token-deployment mismatch and temporary overload must
  # not produce a server-wide VPN outage. The scheduler will reconcile the live
  # tunnel shortly after it appears.
  logger -t vpn-panel-admission "FAIL-OPEN protocol=${protocol} user=${username} ip=${client_ip} code=${code:-000} curl_rc=${curl_rc} detail=${detail:-none}"
  return 0
}
