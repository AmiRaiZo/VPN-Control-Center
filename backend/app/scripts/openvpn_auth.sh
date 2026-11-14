#!/bin/bash
# OpenVPN username/password verifier. Runs after the TLS certificate handshake.
set -u
RUNTIME_ENV="/etc/vpn-panel/openvpn-hook.env"
LEGACY_ENV="/opt/vpn-panel/panel.env"

if [ -r "$RUNTIME_ENV" ]; then
  # shellcheck disable=SC1090
  source "$RUNTIME_ENV"
elif [ -r "$LEGACY_ENV" ]; then
  # Compatibility fallback for the brief window during an older upgrade.
  # shellcheck disable=SC1091
  source "$LEGACY_ENV"
else
  logger -t vpn-panel-openvpn-auth "DENY: OpenVPN hook env is not readable by uid=$(id -u) gid=$(id -g); expected=${RUNTIME_ENV}"
  exit 1
fi

BACKEND_PORT="${BACKEND_PORT:-8000}"
INTERNAL_API_TOKEN="${INTERNAL_API_TOKEN:-}"
if ! [[ "$BACKEND_PORT" =~ ^[0-9]+$ ]] || [ -z "$INTERNAL_API_TOKEN" ]; then
  logger -t vpn-panel-openvpn-auth "DENY: OpenVPN hook env is incomplete by uid=$(id -u) gid=$(id -g)"
  exit 1
fi

PAYLOAD=$(/usr/bin/python3 -c 'import json,os; print(json.dumps({"username":os.environ.get("username", ""),"password":os.environ.get("password", ""),"common_name":os.environ.get("common_name", "")}))' 2>/dev/null) || exit 1
RESPONSE_FILE="/tmp/vpn-panel-openvpn-auth.$$.json"
AUTH_CACHE_DIR="/run/vpn-panel/openvpn-auth-cache"
AUTH_CACHE_TTL_SECONDS=180
trap 'rm -f "$RESPONSE_FILE"' EXIT
HTTP_CODE=""
for attempt in 1 2; do
  : > "$RESPONSE_FILE"
  HTTP_CODE=$(/usr/bin/curl -sS --connect-timeout 1 --max-time 2 -o "$RESPONSE_FILE" -w "%{http_code}" \
    -X POST "http://127.0.0.1:${BACKEND_PORT}/api/internal/openvpn-auth" \
    -H "Content-Type: application/json" \
    -H "X-Internal-Token: ${INTERNAL_API_TOKEN}" \
    --data-binary "$PAYLOAD" 2>/dev/null || true)
  [ "${HTTP_CODE:0:1}" = "2" ] && break
  # A 4xx response is an authoritative credential/certificate denial. Retry
  # only connection errors and temporary 5xx responses from a backend restart.
  [ "${HTTP_CODE:0:1}" = "4" ] && break
  [ "$attempt" -lt 2 ] && sleep 0.15
 done

if [ "${HTTP_CODE:0:1}" != "2" ]; then
  DETAIL=$(/usr/bin/python3 - "$RESPONSE_FILE" <<'PYDETAIL' 2>/dev/null || true
import json, sys
try:
    with open(sys.argv[1], "r", encoding="utf-8", errors="replace") as handle:
        payload = json.load(handle)
    value = payload.get("detail") or payload.get("message") or "unknown"
    print(str(value).replace("\n", " ")[:160])
except Exception:
    print("unreadable_response")
PYDETAIL
)

  # A real 4xx denial is authoritative.  Only transport errors/5xx/408/429 may
  # use a recent success for these exact credentials, signed with the internal
  # token. This bridges a short API restart without turning authentication into
  # a global fail-open.
  TEMPORARY=0
  case "${HTTP_CODE:-000}" in
    000|408|429|5??) TEMPORARY=1 ;;
  esac
  if [ "$TEMPORARY" -eq 1 ] && [ "${username:-}" = "${common_name:-}" ] && [ -d "$AUTH_CACHE_DIR" ]; then
    if VPNPANEL_INTERNAL_API_TOKEN="$INTERNAL_API_TOKEN" /usr/bin/python3 - "$AUTH_CACHE_DIR" "$AUTH_CACHE_TTL_SECONDS" <<'PYCHECK'
import hashlib, hmac, os, sys, time
from pathlib import Path
cache_dir, ttl = sys.argv[1:]
token = os.environ.get("VPNPANEL_INTERNAL_API_TOKEN", "")
username = os.environ.get("username", "")
common_name = os.environ.get("common_name", "")
password = os.environ.get("password", "")
key = hashlib.sha256((username + "\0" + common_name).encode()).hexdigest()
path = Path(cache_dir) / (key + ".cache")
try:
    stamp_text, saved = path.read_text(encoding="ascii").splitlines()[:2]
    stamp = int(stamp_text)
except Exception:
    raise SystemExit(1)
if stamp > int(time.time()) + 5 or int(time.time()) - stamp > int(ttl):
    raise SystemExit(1)
message = (username + "\0" + common_name + "\0" + password).encode()
expected = hmac.new(token.encode(), message, hashlib.sha256).hexdigest()
raise SystemExit(0 if hmac.compare_digest(saved, expected) else 1)
PYCHECK
    then
      logger -t vpn-panel-openvpn-auth "ALLOW-CACHED user=${username:-?} cn=${common_name:-?} http=${HTTP_CODE:-curl_error} backend=temporary_failure"
      exit 0
    fi
  fi

  logger -t vpn-panel-openvpn-auth "DENY user=${username:-?} cn=${common_name:-?} http=${HTTP_CODE:-curl_error} reason=${DETAIL:-unknown}"
  exit 1
fi

# Remember only an API-confirmed success.  The cache is short-lived, bound to
# exact username/CN/password and HMAC-signed with the local internal token.
if [ -d "$AUTH_CACHE_DIR" ]; then
  VPNPANEL_INTERNAL_API_TOKEN="$INTERNAL_API_TOKEN" /usr/bin/python3 - "$AUTH_CACHE_DIR" <<'PYWRITE' 2>/dev/null || true
import hashlib, hmac, os, sys, tempfile, time
from pathlib import Path
cache_dir = sys.argv[1]
token = os.environ.get("VPNPANEL_INTERNAL_API_TOKEN", "")
username = os.environ.get("username", "")
common_name = os.environ.get("common_name", "")
password = os.environ.get("password", "")
key = hashlib.sha256((username + "\0" + common_name).encode()).hexdigest()
message = (username + "\0" + common_name + "\0" + password).encode()
digest = hmac.new(token.encode(), message, hashlib.sha256).hexdigest()
root = Path(cache_dir)
fd, temp_name = tempfile.mkstemp(prefix=".auth-", dir=str(root))
try:
    with os.fdopen(fd, "w", encoding="ascii") as handle:
        handle.write(f"{int(time.time())}\n{digest}\n")
        handle.flush(); os.fsync(handle.fileno())
    os.chmod(temp_name, 0o600)
    os.replace(temp_name, root / (key + ".cache"))
finally:
    try: os.unlink(temp_name)
    except FileNotFoundError: pass
PYWRITE
fi
logger -t vpn-panel-openvpn-auth "ALLOW user=${username:-?} cn=${common_name:-?}"
exit 0
