#!/usr/bin/env bash
# Diagnose and safely repair a VPN Panel node where every protocol has stopped accepting connections.
# Target: VPN Panel 2.3.220+
set -Eeuo pipefail

INSTALL_DIR="/opt/vpn-panel"
BACKEND_DIR="$INSTALL_DIR/backend"
VENV_PY="$BACKEND_DIR/venv/bin/python"
STAMP="$(date -u +%Y%m%d-%H%M%S)"
LOG="/root/vpn-node-all-protocols-repair-${STAMP}.log"
BACKUP="/root/vpn-node-pre-repair-${STAMP}.tar.gz"

exec > >(tee -a "$LOG") 2>&1

say() { printf '\n[%s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
warn() { printf '\n[WARNING] %s\n' "$*"; }

if [ "$(id -u)" -ne 0 ]; then
  echo "Run this script as root." >&2
  exit 1
fi
if [ ! -x "$VENV_PY" ] || [ ! -f "$BACKEND_DIR/app/main.py" ]; then
  echo "VPN Panel backend was not found under $BACKEND_DIR" >&2
  exit 2
fi

say "Creating a small rollback archive"
tar -czf "$BACKUP" \
  /opt/vpn-panel/panel.env \
  /opt/vpn-panel/backend/.env \
  /etc/ppp/chap-secrets \
  /etc/ipsec.secrets \
  /etc/ocserv/ocpasswd \
  /etc/openvpn \
  /etc/vpn-panel \
  /etc/xl2tpd \
  /etc/ppp/options.xl2tpd \
  /etc/ppp/pptpd-options \
  /etc/accel-ppp/sstp.conf \
  /etc/ocserv/ocserv.conf \
  2>/dev/null || true
chmod 0600 "$BACKUP" 2>/dev/null || true
echo "Rollback archive: $BACKUP"

say "Reading node role, license state, users and saved protocol switches"
cd "$BACKEND_DIR"
STATE_JSON="$($VENV_PY - <<'PY'
import json
from app.database import SessionLocal
from app.models import Setting, VpnUser

db = SessionLocal()
try:
    settings = {row.key: row.value for row in db.query(Setting).all()}
    users = db.query(VpnUser).all()
    selected = [u for u in users if bool(getattr(u, "node_managed", False))]
    active = [u for u in users if bool(u.is_active)]
    data = {
        "server_role": settings.get("server_role") or settings.get("panel_server_role") or "unknown",
        "license_locked": settings.get("license_locked") == "1",
        "license_status": settings.get("license_last_result"),
        "users_total": len(users),
        "users_active": len(active),
        "users_node_managed": len(selected),
        "protocols": {
            key: settings.get(key)
            for key in (
                "l2tp_enabled", "pptp_enabled", "openvpn_enabled", "sstp_enabled",
                "ikev2_enabled", "vmess_enabled", "vless_enabled"
            )
        },
    }
    print(json.dumps(data, ensure_ascii=False))
finally:
    db.close()
PY
)"
printf '%s\n' "$STATE_JSON" | $VENV_PY -m json.tool

LOCKED="$(printf '%s' "$STATE_JSON" | $VENV_PY -c 'import json,sys; print("1" if json.load(sys.stdin).get("license_locked") else "0")')"
if [ "$LOCKED" = "1" ]; then
  warn "This node is license-locked. The panel intentionally stops every VPN service in this state."
  echo "Repair was stopped so the license protection is not bypassed. Open the node license page and fix/reset its license binding, then run this script again."
  echo "Diagnostic log: $LOG"
  exit 42
fi

say "Checking and repairing the local API"
systemctl reset-failed vpn-panel-api >/dev/null 2>&1 || true
if ! systemctl is-active --quiet vpn-panel-api; then
  systemctl restart vpn-panel-api
fi
for _ in $(seq 1 20); do
  systemctl is-active --quiet vpn-panel-api && break
  sleep 1
done
if ! systemctl is-active --quiet vpn-panel-api; then
  warn "vpn-panel-api is still not active"
  systemctl status vpn-panel-api --no-pager -l || true
  journalctl -u vpn-panel-api -n 100 --no-pager || true
  exit 3
fi

say "Repairing shared runtime permissions for OpenVPN and Xray"
if [ -x "$INSTALL_DIR/scripts/refresh_openvpn_runtime_env.sh" ]; then
  "$INSTALL_DIR/scripts/refresh_openvpn_runtime_env.sh"
fi
if [ -x "$INSTALL_DIR/scripts/repair_xray_runtime_permissions.sh" ]; then
  "$INSTALL_DIR/scripts/repair_xray_runtime_permissions.sh" || true
fi
install -d -o root -g root -m 0711 /etc/vpn-panel

say "Rebuilding every protocol authentication store from the node database"
$VENV_PY - <<'PY'
from app.database import SessionLocal
from app.services.vpn_manager import sync_chap_secrets
from app.services.xray_manager import sync_xray_users

db = SessionLocal()
try:
    # Also rebuilds IKEv2 and OpenConnect credentials.
    sync_chap_secrets(db)
    try:
        sync_xray_users(db, protocols=("vmess", "vless"), restart=False)
    except Exception as exc:
        print(f"Xray credential rebuild warning: {exc}")
finally:
    db.close()
PY

say "Repairing classic PPP/OpenVPN helpers and runtime routing"
if [ -x "$INSTALL_DIR/scripts/repair_classic_ppp_protocols.sh" ]; then
  "$INSTALL_DIR/scripts/repair_classic_ppp_protocols.sh" --no-restart || true
fi
if [ -x "$INSTALL_DIR/scripts/repair_runtime_networking.sh" ]; then
  "$INSTALL_DIR/scripts/repair_runtime_networking.sh" --apply-config || true
fi
if [ -x "$INSTALL_DIR/scripts/repair_vpn_ingress.sh" ]; then
  "$INSTALL_DIR/scripts/repair_vpn_ingress.sh" || true
fi

say "Reapplying the saved protocol configuration and restarting enabled backends"
$VENV_PY - <<'PY'
from app.database import SessionLocal
from app.services.vpn_manager import apply_current_protocol_settings, sync_chap_secrets
from app.services.xray_manager import sync_xray_users

db = SessionLocal()
try:
    sync_chap_secrets(db)
    ok, detail = apply_current_protocol_settings(db)
    print(detail[-5000:] if detail else "")
    if not ok:
        raise SystemExit("Saved classic protocol settings could not be applied")
    try:
        result = sync_xray_users(db, protocols=("vmess", "vless"), restart=True)
        print("Xray:", result)
    except Exception as exc:
        print(f"Xray restart warning: {exc}")
finally:
    db.close()
PY

say "Reloading systemd and the node API"
systemctl daemon-reload
systemctl restart vpn-panel-api
sleep 2

say "Verifying authentication files and service/listener state"
$VENV_PY - <<'PY'
from pathlib import Path
from app.database import SessionLocal
from app.models import Setting, VpnUser
from app.services.server_targets import user_enabled_on_this_server

db = SessionLocal()
try:
    users = [u for u in db.query(VpnUser).filter(VpnUser.is_active == True).all() if user_enabled_on_this_server(db, u)]
    chap = Path('/etc/ppp/chap-secrets').read_text(encoding='utf-8', errors='replace') if Path('/etc/ppp/chap-secrets').exists() else ''
    ipsec = Path('/etc/ipsec.secrets').read_text(encoding='utf-8', errors='replace') if Path('/etc/ipsec.secrets').exists() else ''
    oc = Path('/etc/ocserv/ocpasswd').read_text(encoding='utf-8', errors='replace') if Path('/etc/ocserv/ocpasswd').exists() else ''
    expected_chap = [u.username for u in users if u.enable_l2tp or u.enable_pptp or u.enable_sstp]
    expected_ike = [u.username for u in users if u.enable_ikev2]
    expected_oc = [u.username for u in users if u.enable_openconnect]
    print('active users:', len(users))
    print('chap expected/found:', len(expected_chap), sum(1 for name in expected_chap if f'{name}\t*\t' in chap))
    print('ikev2 expected/found:', len(expected_ike), sum(1 for name in expected_ike if f'{name} : EAP ' in ipsec))
    print('openconnect expected/found:', len(expected_oc), sum(1 for name in expected_oc if any(line.startswith(name + ':') for line in oc.splitlines())))
finally:
    db.close()
PY

printf '\n%-34s %s\n' "SERVICE" "STATE"
for unit in \
  vpn-panel-api nginx xl2tpd strongswan-starter strongswan ipsec pptpd \
  openvpn-server@server-udp openvpn-server@server-tcp openvpn@server-udp openvpn@server-tcp \
  accel-ppp-sstp ocserv vpn-panel-xray-vmess vpn-panel-xray-vless; do
  load="$(systemctl show "$unit" -p LoadState --value 2>/dev/null || true)"
  [ "$load" = "loaded" ] || continue
  printf '%-34s %s\n' "$unit" "$(systemctl is-active "$unit" 2>/dev/null || true)"
done

echo
echo "Listening VPN ports:"
ss -H -lntup 2>/dev/null | grep -E ':(500|4500|1701|1723|1194|4433|8443|10000|10001)([[:space:]]|$)' || true

echo
echo "Managed firewall chains:"
iptables -S VPNPANEL_FORWARD 2>/dev/null | head -n 20 || true
iptables -t nat -S VPNPANEL_NAT 2>/dev/null | head -n 20 || true

say "Recent errors from shared authentication and protocol services"
journalctl -t vpn-panel-openvpn-auth -n 20 --no-pager 2>/dev/null || true
journalctl -t vpn-panel-admission -n 20 --no-pager 2>/dev/null || true
for unit in xl2tpd pptpd openvpn-server@server-udp openvpn-server@server-tcp accel-ppp-sstp ocserv vpn-panel-xray-vmess vpn-panel-xray-vless; do
  systemctl is-failed --quiet "$unit" 2>/dev/null || continue
  echo "--- $unit ---"
  journalctl -u "$unit" -n 30 --no-pager 2>/dev/null || true
done

say "Repair finished"
echo "Full log: $LOG"
echo "Rollback archive: $BACKUP"
echo "Now test one user on this node. If it still fails, send the file $LOG."
