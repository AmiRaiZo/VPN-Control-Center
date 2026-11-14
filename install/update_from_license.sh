#!/bin/bash
###############################################################################
# License-server update runner with atomic progress, hard timeouts, and logs.
###############################################################################
set -Eeuo pipefail
INSTALL_DIR="/opt/vpn-panel"
PROGRESS_FILE="$INSTALL_DIR/update-progress.json"
PUBLIC_PROGRESS_FILE="$INSTALL_DIR/update-progress-public.json"
LOG_FILE="$INSTALL_DIR/update.log"
WORKDIR="/tmp/vpn-panel-update"
RUN_ID="${UPDATE_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$$}"
SYSTEMD_UNIT="${UPDATE_SYSTEMD_UNIT:-}"
FINISHED=0
FAILURE_REPORTED=0

write_status() {
  local percent="$1" state="$2" message="$3"
  mkdir -p "$INSTALL_DIR"
  local tmp="${PROGRESS_FILE}.tmp.$$"
  python3 - "$percent" "$state" "$message" "$RUN_ID" "$SYSTEMD_UNIT" > "$tmp" <<'STATUSPY'
import json, sys
from datetime import datetime, timezone

# Shell pipelines may truncate a UTF-8 log line in the middle of a Persian
# character. Python decodes that orphan byte using surrogateescape, and a
# direct UTF-8 write would then raise UnicodeEncodeError. Normalize every
# argument before serializing progress so a malformed log byte can never stop
# an otherwise successful update.
def clean(value: str) -> str:
    return value.encode("utf-8", "replace").decode("utf-8")

print(json.dumps({
    "percent": int(clean(sys.argv[1])),
    "state": clean(sys.argv[2]),
    "message": clean(sys.argv[3]),
    "run_id": clean(sys.argv[4]),
    "unit_name": clean(sys.argv[5]) or None,
    "updated_at": datetime.now(timezone.utc).isoformat(),
}, ensure_ascii=False))
STATUSPY
  mv -f "$tmp" "$PROGRESS_FILE"
  # Nginx serves this sanitized twin only while the authenticated API is
  # restarting. Never place the real update.log in this public fallback.
  local public_tmp="${PUBLIC_PROGRESS_FILE}.tmp.$$"
  python3 - "$PROGRESS_FILE" > "$public_tmp" <<'PUBLICSTATUSPY'
import json, sys
data = json.load(open(sys.argv[1], encoding="utf-8"))
percent = max(0, min(100, int(data.get("percent") or 0)))
message = str(data.get("message") or "Applying safe update").split(" — ", 1)[0].strip()
public = {
    key: data.get(key)
    for key in ("percent", "state", "message", "run_id", "unit_name", "updated_at")
}
public["message"] = message
public["log_tail"] = (
    "[live-update] The panel API is restarting safely.\n"
    f"[{percent}%] {message}\n"
    "[live-update] Real progress is still being received; do not close this page."
)
print(json.dumps(public, ensure_ascii=False, separators=(",", ":")))
PUBLICSTATUSPY
  chmod 0644 "$public_tmp"
  mv -f "$public_tmp" "$PUBLIC_PROGRESS_FILE"
}

write_failure() {
  FAILURE_REPORTED=1
  local current_percent=1
  if [ -f "$PROGRESS_FILE" ]; then
    current_percent="$(python3 - "$PROGRESS_FILE" <<'PERCENTPY' 2>/dev/null || echo 1
import json, sys
try:
    print(max(1, min(99, int(json.load(open(sys.argv[1])).get("percent", 1)))))
except Exception:
    print(1)
PERCENTPY
)"
  fi
  write_status "${current_percent:-1}" failed "$1"
}

fail_trap() {
  rc=$?
  if [ "$FINISHED" -ne 1 ] && [ "$FAILURE_REPORTED" -ne 1 ]; then
    local last_line
    last_line="$(tail -n 1 "$LOG_FILE" 2>/dev/null | tr -d '\r' | python3 -c 'import sys; print(sys.stdin.buffer.read().decode("utf-8", "replace")[:220], end="")' || true)"
    write_failure "Update stopped unexpectedly${last_line:+: $last_line}. Check /opt/vpn-panel/update.log"
  fi
  exit "$rc"
}
trap fail_trap EXIT

run_phase() {
  local start="$1" cap="$2" timeout_sec="$3" message="$4" out_file="$5"; shift 5
  write_status "$start" running "$message"
  : > "$out_file"
  set +e
  # Stream phase output into the main update.log in real time while also
  # keeping the phase-specific file for precise error extraction.
  timeout --signal=TERM --kill-after=20 "$timeout_sec" "$@" > >(tee "$out_file") 2>&1 &
  local pid=$!
  set -e
  local pct="$start" elapsed=0 last_line=""
  while kill -0 "$pid" 2>/dev/null; do
    sleep 2
    elapsed=$((elapsed + 2))
    [ "$pct" -lt "$cap" ] && pct=$((pct + 1))
    last_line="$(tail -n 1 "$out_file" 2>/dev/null | tr -d '\r' | python3 -c 'import sys; print(sys.stdin.buffer.read().decode("utf-8", "replace")[:140], end="")' || true)"
    if [ -n "$last_line" ]; then
      write_status "$pct" running "$message — $last_line"
    else
      write_status "$pct" running "$message (${elapsed}s)"
    fi
  done
  set +e
  wait "$pid"
  local rc=$?
  set -e
  if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
    echo "[!] Phase timed out after ${timeout_sec}s: $message" >> "$LOG_FILE"
    write_failure "Update phase timed out: $message. See /opt/vpn-panel/update.log"
    return 124
  fi
  if [ "$rc" -ne 0 ]; then
    local detail
    detail="$(grep -v '^[[:space:]]*$' "$out_file" 2>/dev/null | tail -n 1 | tr -d '\r' | python3 -c 'import sys; print(sys.stdin.buffer.read().decode("utf-8", "replace")[:220], end="")' || true)"
    write_failure "Update failed during: $message${detail:+ — $detail}. See /opt/vpn-panel/update.log"
    return "$rc"
  fi
  write_status "$cap" running "$message"
}

mkdir -p "$INSTALL_DIR"
: > "$LOG_FILE"
exec >> "$LOG_FILE" 2>&1

echo "[*] Panel update started at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
# systemd has already loaded this root-only file into the process environment.
# Remove it immediately so update credentials never linger on disk or appear
# in a process command line.
UPDATE_ENV_FILE="${VPN_PANEL_UPDATE_ENV_FILE:-}"
case "$UPDATE_ENV_FILE" in
  /run/vpn-panel/update-*.env) rm -f -- "$UPDATE_ENV_FILE" ;;
esac
unset VPN_PANEL_UPDATE_ENV_FILE UPDATE_ENV_FILE
[ -n "${LICENSE_SERVER_URL:-}" ] && [ -n "${LICENSE_API_KEY:-}" ] && [ -n "${LICENSE_KEY:-}" ] || {
  write_failure "License update configuration is missing."
  exit 1
}
LICENSE_SERVER_URL="${LICENSE_SERVER_URL%/}"

write_status 3 running "Checking latest release..."
LATEST_JSON="$(curl -fsS -G --connect-timeout 10 --max-time 30 \
  -H "x-api-key: ${LICENSE_API_KEY}" --data-urlencode "key=${LICENSE_KEY}" \
  "${LICENSE_SERVER_URL}/api/updates/latest")"
LATEST_VERSION="$(python3 -c 'import json,sys; print(str(json.load(sys.stdin).get("version", "") or "").strip())' <<<"$LATEST_JSON")"
LATEST_SHA256="$(python3 -c 'import json,sys; print(str(json.load(sys.stdin).get("sha256", "") or "").strip().lower())' <<<"$LATEST_JSON")"
# The license console owns the visible version label. The package hash owns
# update identity. A label such as "5" is valid and is written into the local
# VERSION file after a successful verified update.
if [ -n "$LATEST_VERSION" ] && ! printf '%s' "$LATEST_VERSION" | grep -Eq '^[0-9A-Za-z][0-9A-Za-z._+-]{0,63}$'; then
  write_failure "Update service returned an invalid version label."
  exit 1
fi
echo "[*] Published version label: ${LATEST_VERSION:-not provided}."
if [ -n "$LATEST_SHA256" ] && ! printf '%s' "$LATEST_SHA256" | grep -Eq '^[0-9a-f]{64}$'; then
  write_failure "Update service returned an invalid SHA-256 value."
  exit 1
fi

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR/extracted"
cd "$WORKDIR"
run_phase 5 28 300 "Downloading update package" "$WORKDIR/download.log" \
  curl -fL -G --retry 4 --retry-all-errors --connect-timeout 15 --max-time 280 \
  -o update.zip -H "x-api-key: ${LICENSE_API_KEY}" --data-urlencode "key=${LICENSE_KEY}" \
  "${LICENSE_SERVER_URL}/api/updates/download"
run_phase 29 33 60 "Verifying ZIP package" "$WORKDIR/zip-test.log" unzip -tq update.zip
if [ -n "$LATEST_SHA256" ]; then
  ACTUAL_SHA256="$(sha256sum update.zip | awk '{print tolower($1)}')"
  [ "$ACTUAL_SHA256" = "$LATEST_SHA256" ] || {
    write_failure "Downloaded update checksum does not match the license server metadata."
    exit 1
  }
  echo "[*] Downloaded package SHA-256 verified: $ACTUAL_SHA256"
else
  echo "[!] The license server did not publish a SHA-256 value; continuing with ZIP integrity checks. Version metadata is not enforced."
fi
run_phase 34 42 90 "Extracting update package" "$WORKDIR/extract.log" unzip -q -o update.zip -d extracted

UPDATE_SH="$(find extracted -maxdepth 5 -type f -path '*/install/update.sh' -print -quit)"
[ -n "$UPDATE_SH" ] || {
  write_failure "Downloaded package structure is invalid: install/update.sh is missing."
  exit 1
}
PROJECT_ROOT="${UPDATE_SH%/install/update.sh}"
PACKAGE_VERSION=""
if [ -f "$PROJECT_ROOT/VERSION" ]; then
  PACKAGE_VERSION="$(head -n 1 "$PROJECT_ROOT/VERSION" | tr -d '\r\n')"
fi
if [ -n "$PACKAGE_VERSION" ]; then
  echo "[*] Archive VERSION metadata: $PACKAGE_VERSION (code build identity)."
  if [ -n "$LATEST_VERSION" ] && [ "$PACKAGE_VERSION" != "$LATEST_VERSION" ]; then
    echo "[*] Published label differs from archive build identity; the published label will be recorded after installation."
  fi
elif [ -n "$LATEST_VERSION" ]; then
  echo "[*] Archive VERSION is missing/empty; the published label will be recorded after installation."
else
  echo "[!] No usable version label was provided; keeping the version installed by the package."
fi

cd "$PROJECT_ROOT/install"
run_phase 43 96 360 "Applying safe code update" "$WORKDIR/update-run.log" bash update.sh

write_status 98 running "Confirming API health..."
for _ in $(seq 1 30); do
  systemctl is-active --quiet vpn-panel-api && break
  sleep 1
done
systemctl is-active --quiet vpn-panel-api || {
  write_failure "API service is not healthy after update. See update.log"
  exit 1
}

[ -n "$LATEST_VERSION" ] && printf '%s\n' "$LATEST_VERSION" > "$INSTALL_DIR/VERSION"
if printf '%s' "$LATEST_SHA256" | grep -Eq '^[0-9a-f]{64}$'; then
  printf '%s\n' "$LATEST_SHA256" > "$INSTALL_DIR/.last-applied-package.sha256"
  chmod 0600 "$INSTALL_DIR/.last-applied-package.sha256"
fi
rm -rf "$WORKDIR"
FINISHED=1
write_status 100 success "Update completed successfully. Protocol services and ports were preserved."
echo "[*] Panel update finished successfully at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
