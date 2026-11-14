#!/bin/bash
# Safely recover the panel UI after an updater is stuck or was interrupted.
set -u
INSTALL_DIR=/opt/vpn-panel
PROGRESS_FILE="$INSTALL_DIR/update-progress.json"
echo "[*] Stopping only detached VPN Panel update units..."
PROGRESS_UNIT="$(python3 - "$PROGRESS_FILE" <<'UNITPY' 2>/dev/null || true
import json, sys
try:
    print(str(json.load(open(sys.argv[1], encoding='utf-8')).get('unit_name') or ''))
except Exception:
    pass
UNITPY
)"
mapfile -t UPDATE_UNITS < <(
  {
    [ -n "$PROGRESS_UNIT" ] && printf '%s
' "$PROGRESS_UNIT"
    systemctl list-units --all --plain --no-legend 'vpn-panel-update*.service' 2>/dev/null | awk '{print $1}'
  } | awk 'NF && !seen[$0]++'
)
for unit in "${UPDATE_UNITS[@]}"; do
  systemctl stop "$unit" 2>/dev/null || true
  systemctl reset-failed "$unit" 2>/dev/null || true
done
pkill -TERM -f '/tmp/vpn-panel-update/.*/update.sh' 2>/dev/null || true
sleep 2

echo "[*] Restarting panel API and Nginx..."
systemctl daemon-reload 2>/dev/null || true
systemctl restart vpn-panel-api 2>/dev/null || true
nginx -t >/dev/null 2>&1 && (systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null || true)

python3 - "$PROGRESS_FILE" <<'RECOVERPY'
import json, sys
from datetime import datetime, timezone
with open(sys.argv[1], 'w', encoding='utf-8') as f:
    json.dump({
      'percent': 0,
      'state': 'failed',
      'message': 'The previous update was stopped safely. Review update.log, then retry with the safe updater.',
      'updated_at': datetime.now(timezone.utc).isoformat(),
    }, f)
RECOVERPY

echo
echo "===== vpn-panel-update units ====="
if [ "${#UPDATE_UNITS[@]}" -eq 0 ]; then
  echo "No detached update unit is loaded."
else
  for unit in "${UPDATE_UNITS[@]}"; do
    echo "--- $unit ---"
    systemctl status "$unit" --no-pager -l 2>/dev/null | tail -n 25 || true
  done
fi
echo
echo "===== last update log lines ====="
tail -n 100 "$INSTALL_DIR/update.log" 2>/dev/null || true
echo
echo "===== API status ====="
systemctl status vpn-panel-api --no-pager -l 2>/dev/null | head -n 15 || true
echo "[*] Recovery finished."
