#!/bin/bash
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "Run as root" >&2; exit 1; }
INSTALL_DIR=/opt/vpn-panel
[ -x "$INSTALL_DIR/backend/venv/bin/python" ] || { echo "Panel backend not found" >&2; exit 2; }

echo "[*] Reading saved protocol state; ports will not be reallocated."
cd "$INSTALL_DIR/backend"
./venv/bin/python - <<'PY'
from app.database import SessionLocal
from app.models import Setting
keys=("l2tp_enabled","l2tp_port","pptp_enabled","openvpn_enabled","openvpn_udp_port","openvpn_tcp_port","sstp_enabled","sstp_port","ikev2_enabled","openconnect_port","vmess_enabled","vmess_port","vless_enabled","vless_port")
db=SessionLocal()
try:
    values={r.key:r.value for r in db.query(Setting).filter(Setting.key.in_(keys)).all()}
    for k in keys: print(f"  {k}={values.get(k, '<missing>')}")
finally: db.close()
PY

SSTP_PORT=$(./venv/bin/python - <<'PY'
from app.database import SessionLocal
from app.models import Setting
db=SessionLocal()
try:
    r=db.query(Setting).filter(Setting.key=="sstp_port").first()
    print(r.value if r and r.value else "4433")
finally: db.close()
PY
)

echo "[*] Repairing L2TP/PPTP/SSTP compatibility without changing other protocols..."
bash "$INSTALL_DIR/scripts/repair_classic_ppp_protocols.sh" --no-restart

echo "[*] Repairing Xray while preserving VMess/VLESS state..."
bash "$INSTALL_DIR/scripts/setup_xray.sh" --protocol=both

echo "[*] Repairing SSTP on saved port tcp/${SSTP_PORT}..."
bash "$INSTALL_DIR/scripts/setup_sstp.sh" "--port=${SSTP_PORT}"

echo "[*] Reapplying saved protocol settings..."
./venv/bin/python - <<'PY'
from app.database import SessionLocal
from app.services.vpn_manager import apply_current_protocol_settings, sync_chap_secrets
from app.services.xray_manager import sync_xray_users
db=SessionLocal()
try:
    sync_chap_secrets(db)
    ok, log = apply_current_protocol_settings(db)
    if not ok:
        raise SystemExit(log or "Protocol settings could not be applied")
    sync_xray_users(db, protocols=("vmess","vless"), restart=True)
finally:
    db.close()
PY

echo "[*] Current relevant listeners:"
ss -lntup | grep -E ':(4433|8443|1194|1701|1723|10000|10001)([[:space:]]|$)' || true
echo "[✓] Saved protocol state reapplied without automatic port changes."
