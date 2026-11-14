#!/bin/bash
set -Eeuo pipefail
INSTALL_DIR="${INSTALL_DIR:-/opt/vpn-panel}"
SCRIPT="$INSTALL_DIR/scripts/connect_node_controller.sh"
[ "${EUID:-$(id -u)}" -eq 0 ] || { echo "Run as root." >&2; exit 1; }
[ -f "$SCRIPT" ] || { echo "Missing $SCRIPT" >&2; exit 1; }
BACKUP="${SCRIPT}.bak.$(date -u +%Y%m%dT%H%M%SZ)"
cp -a "$SCRIPT" "$BACKUP"
python3 - "$SCRIPT" <<'PY'
from pathlib import Path
import sys
p=Path(sys.argv[1])
s=p.read_text()
if 'export PYTHONPATH="$BACKEND_DIR${PYTHONPATH:+:$PYTHONPATH}"' not in s:
    old='PY="$INSTALL_DIR/backend/venv/bin/python"\n[ -x "$PY" ] || { echo "VPN Panel Python runtime not found" >&2; exit 1; }\n'
    new='BACKEND_DIR="$INSTALL_DIR/backend"\nPY="$BACKEND_DIR/venv/bin/python"\n[ -x "$PY" ] || { echo "VPN Panel Python runtime not found" >&2; exit 1; }\nexport PYTHONPATH="$BACKEND_DIR${PYTHONPATH:+:$PYTHONPATH}"\n'
    if old not in s:
        raise SystemExit('Expected Python runtime block was not found; no changes made.')
    s=s.replace(old,new,1)
else:
    if 'BACKEND_DIR="$INSTALL_DIR/backend"' not in s:
        raise SystemExit('PYTHONPATH marker exists without BACKEND_DIR; refusing an ambiguous edit.')
old='PAYLOAD=$(NODE_NAME="$NODE_NAME" NODE_PUBLIC_URL="$NODE_PUBLIC_URL" LOCAL_TOKEN="$LOCAL_TOKEN" NODE_VERIFY_TLS="$NODE_VERIFY_TLS" "$PY" - <<\'PYEOF\'\n'
new='PAYLOAD=$(cd "$BACKEND_DIR" && NODE_NAME="$NODE_NAME" NODE_PUBLIC_URL="$NODE_PUBLIC_URL" LOCAL_TOKEN="$LOCAL_TOKEN" NODE_VERIFY_TLS="$NODE_VERIFY_TLS" "$PY" - <<\'PYEOF\'\n'
if old in s:
    s=s.replace(old,new,1)
p.write_text(s)
PY
chmod 0750 "$SCRIPT"
bash -n "$SCRIPT"
systemctl daemon-reload
systemctl restart vpn-panel-node-register.service
journalctl -u vpn-panel-node-register.service -n 80 --no-pager -l
