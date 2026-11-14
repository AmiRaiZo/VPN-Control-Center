#!/bin/bash
# Repair the shared /etc/vpn-panel traversal and Xray child ownership without
# reinstalling Xray or changing protocol settings.
set -Eeuo pipefail

[ "$(id -u)" -eq 0 ] || { echo "repair_xray_runtime_permissions.sh must run as root" >&2; exit 1; }

INSTALL_DIR="${VPN_PANEL_INSTALL_DIR:-/opt/vpn-panel}"
SHARED_DIR="${VPN_PANEL_RUNTIME_DIR:-/etc/vpn-panel}"
XRAY_DIR="${XRAY_CONFIG_ROOT:-${SHARED_DIR}/xray}"
LOG_DIR="${XRAY_LOG_ROOT:-/var/log/vpn-panel/xray}"
RESTART_ENABLED=0
[ "${1:-}" = "--restart-enabled" ] && RESTART_ENABLED=1

if ! id vpn-xray >/dev/null 2>&1; then
  if [ ! -d "$XRAY_DIR" ]; then
    echo "[*] Xray is not installed; nothing to repair."
    exit 0
  fi
  useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin vpn-xray
fi

install -d -o root -g root -m 0711 "$SHARED_DIR"
install -d -o root -g vpn-xray -m 0750 "$XRAY_DIR" "$XRAY_DIR/vmess" "$XRAY_DIR/vless"
find "$XRAY_DIR" -type d -exec chown root:vpn-xray {} + -exec chmod 0750 {} +
find "$XRAY_DIR" -type f -exec chown root:vpn-xray {} + -exec chmod 0640 {} +
install -d -o vpn-xray -g vpn-xray -m 0750 "$LOG_DIR"

failures=0
for proto in vmess vless; do
  cfg="$XRAY_DIR/$proto/config.json"
  [ -f "$cfg" ] || continue
  if ! runuser -u vpn-xray -- test -r "$cfg"; then
    echo "ERROR: vpn-xray still cannot read $cfg" >&2
    failures=$((failures + 1))
    continue
  fi
  if [ -x /usr/local/bin/xray ] && ! runuser -u vpn-xray -- /usr/local/bin/xray run -test -config "$cfg" >/tmp/vpn-panel-xray-${proto}-validate.log 2>&1; then
    cat /tmp/vpn-panel-xray-${proto}-validate.log >&2 || true
    echo "ERROR: $proto configuration is not valid" >&2
    failures=$((failures + 1))
    continue
  fi

  if [ "$RESTART_ENABLED" -eq 1 ] && [ -x "$INSTALL_DIR/backend/venv/bin/python" ]; then
    enabled=$(cd "$INSTALL_DIR/backend" && "$INSTALL_DIR/backend/venv/bin/python" - "$proto" <<'PY'
import sys
from app.database import SessionLocal
from app.models import Setting
proto = sys.argv[1]
db = SessionLocal()
try:
    row = db.query(Setting).filter(Setting.key == f"{proto}_enabled").first()
    print("1" if row and str(row.value).lower() in {"1", "true", "yes", "on"} else "0")
finally:
    db.close()
PY
)
    if [ "$enabled" = "1" ]; then
      systemctl restart "vpn-panel-xray-${proto}.service"
    fi
  fi
  echo "[✓] $proto config is readable by vpn-xray"
done

rm -f /tmp/vpn-panel-xray-vmess-validate.log /tmp/vpn-panel-xray-vless-validate.log
[ "$failures" -eq 0 ] || exit 1
echo "[✓] Shared OpenVPN/Xray runtime permissions repaired"
