#!/bin/bash
set -euo pipefail

KEY="${1:-}"
shift || true
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ ! -r "$SCRIPT_DIR/apt_preflight.sh" ]; then
  echo "ERROR: missing protocol preflight helper: $SCRIPT_DIR/apt_preflight.sh" >&2
  exit 1
fi
# shellcheck source=apt_preflight.sh
source "$SCRIPT_DIR/apt_preflight.sh"
trap 'vpn_panel_restore_apt_automation' EXIT

echo "[0/3] Preparing APT/dpkg recovery."
vpn_panel_protocol_preflight

if [ "$(id -u)" -ne 0 ]; then
  echo "ERROR: protocol installer must run as root"
  exit 1
fi

# One-click full provisioning.  Reuse the same per-protocol repair path that is
# used by every individual card, so package installation, saved settings,
# service restarts, port fallback, and runtime health checks stay identical.
# The progress markers are intentionally stable for the web terminal.
if [ "$KEY" = "all" ]; then
  steps=(infrastructure l2tp ipsec pptp openvpn openconnect sstp ikev2 vmess vless)
  labels=("Network prerequisites" "L2TP" "IPsec" "PPTP" "OpenVPN" "OpenConnect" "SSTP" "IKEv2" "VMess" "VLESS")
  progress=(5 15 25 35 47 59 71 82 91 98)
  echo "[0%] Full VPN provisioning started."
  echo "[info] This installs/repairs prerequisites and every protocol, then verifies runtime readiness."
  for i in "${!steps[@]}"; do
    echo
    echo "[${progress[$i]}%] ===== ${labels[$i]} ====="
    if ! bash "$SCRIPT_DIR/install_protocol.sh" "${steps[$i]}" --force; then
      echo "[repair] ${labels[$i]} did not pass readiness on the first run; applying automatic recovery and retrying..." >&2
      case "${steps[$i]}" in
        pptp)
          SKIP_APT_UPDATE=1 bash "$SCRIPT_DIR/setup_pptp.sh" --force --install-only || true
          SKIP_APT_UPDATE=1 bash "$SCRIPT_DIR/setup_pptp.sh" --start || true
          ;;
        l2tp|ipsec|openvpn)
          bash "$SCRIPT_DIR/repair_protocols_after_update.sh" --target "${steps[$i]}" >/dev/null 2>&1 || true
          ;;
      esac
      bash "$SCRIPT_DIR/install_protocol.sh" "${steps[$i]}" --force
    fi
  done
  echo
  echo "[99%] Running combined protocol-center verification..."
  if [ -x /opt/vpn-panel/backend/venv/bin/python ] && [ -d /opt/vpn-panel/backend/app ]; then
    (cd /opt/vpn-panel/backend && /opt/vpn-panel/backend/venv/bin/python - <<'PYALLHEALTH'
from app.database import SessionLocal
from app.services.protocol_admin import get_protocol_center, infrastructure_status

required = {"l2tp", "ipsec", "pptp", "openvpn", "openconnect", "sstp", "ikev2", "vmess", "vless"}
db = SessionLocal()
try:
    rows = {row["key"]: row for row in get_protocol_center(db)}
    failed = []
    for key in sorted(required):
        row = rows.get(key)
        if not row:
            failed.append(f"{key}: card missing")
            continue
        print(f"VERIFY {key}: installed={row['installed']} state={row['state']} ports={row['health']['ports_ok']} config={row['health']['config']}")
        if not row["installed"] or row["state"] != "active":
            failed.append(f"{key}: {row.get('last_error') or row.get('health')}")
    infra = infrastructure_status()
    missing_modules = [name for name, ok in infra.get("modules", {}).items() if not ok]
    critical_modules = {"ppp_generic", "l2tp_ppp", "ip_gre", "ppp_mppe", "tun", "esp4", "xfrm_user"}
    critical_missing = [name for name in missing_modules if name in critical_modules]
    print(f"VERIFY infrastructure: forwarding={infra.get('ip_forwarding')} firewall={infra.get('firewall')} nft={infra.get('nftables')} iproute2={infra.get('iproute2')} modules_missing={missing_modules}")
    if not infra.get("ip_forwarding") or not infra.get("iproute2") or not infra.get("nftables"):
        failed.append("infrastructure: required networking prerequisites are missing")
    if critical_missing:
        failed.append("critical kernel modules unavailable: " + ", ".join(critical_missing))
    if failed:
        raise SystemExit("FULL_PROVISION_FAILED:\n - " + "\n - ".join(failed))
finally:
    db.close()
PYALLHEALTH
    )
  fi
  echo "[100%] FULL_PROVISION_OK — all protocols are installed, enabled, and runtime-verified."
  exit 0
fi

# Resolve a real host-level port collision before any daemon is configured.
# This updates only configurable protocols and writes a persistent notice that
# the Protocol Center shows to the administrator. Standard-only PPTP/IKE ports
# are intentionally never changed silently.
INSTALL_SSTP_PORT="4433"
INSTALL_OCSERV_PORT="8443"
INSTALL_OCSERV_DNS1="8.8.8.8"
INSTALL_OCSERV_DNS2="1.1.1.1"
if [ -x /opt/vpn-panel/backend/venv/bin/python ] && [ -d /opt/vpn-panel/backend/app ]; then
  echo "[port] Checking requested listener ownership and free-port fallback..."
  if [ "$KEY" = "ipsec" ] || [ "$KEY" = "ikev2" ]; then
    echo "[port] Existing charon listeners on UDP/500 and UDP/4500 are accepted when owned by the active strongSwan service."
  fi
  (cd /opt/vpn-panel/backend && /opt/vpn-panel/backend/venv/bin/python -m app.port_allocator "$KEY")
  mapfile -t INSTALL_RUNTIME_ARGS < <(cd /opt/vpn-panel/backend && /opt/vpn-panel/backend/venv/bin/python - "$KEY" <<'PYINSTALLPORTS'
import sys
from app.database import SessionLocal
from app.models import Setting

key = sys.argv[1]
db = SessionLocal()
def get(name, default):
    row = db.query(Setting).filter(Setting.key == name).first()
    return row.value if row and row.value is not None else default
def setv(name, value):
    row = db.query(Setting).filter(Setting.key == name).first()
    if row:
        row.value = value
    else:
        db.add(Setting(key=name, value=value))
try:
    # Clicking Install/Repair means the administrator expects that protocol to
    # become usable. Keep OpenConnect always service-controlled and avoid
    # toggling the shared generic IPsec card, but enable all concrete backends.
    if key in {"l2tp", "pptp", "openvpn", "sstp", "ikev2", "vmess", "vless"}:
        setv(f"{key}_enabled", "1")
        db.commit()
        print(f"[install] {key} was enabled for this repair run", file=sys.stderr)
    print(get("sstp_port", "4433"))
    print(get("openconnect_port", "8443"))
    print(get("openconnect_dns1", "8.8.8.8"))
    print(get("openconnect_dns2", "1.1.1.1"))
finally:
    db.close()
PYINSTALLPORTS
  )
  INSTALL_SSTP_PORT="${INSTALL_RUNTIME_ARGS[0]:-4433}"
  INSTALL_OCSERV_PORT="${INSTALL_RUNTIME_ARGS[1]:-8443}"
  INSTALL_OCSERV_DNS1="${INSTALL_RUNTIME_ARGS[2]:-8.8.8.8}"
  INSTALL_OCSERV_DNS2="${INSTALL_RUNTIME_ARGS[3]:-1.1.1.1}"
fi

case "$KEY" in
  openconnect)
    echo "[1/3] Installing/verifying ocserv packages and configuration..."
    bash "$SCRIPT_DIR/setup_openconnect.sh" "$@" --force --port="$INSTALL_OCSERV_PORT" --dns1="$INSTALL_OCSERV_DNS1" --dns2="$INSTALL_OCSERV_DNS2"
    ;;
  sstp)
    echo "[1/3] Installing/verifying accel-ppp SSTP..."
    bash "$SCRIPT_DIR/setup_sstp.sh" --force --port="$INSTALL_SSTP_PORT"
    ;;
  ikev2)
    echo "[1/3] Installing/verifying strongSwan IKEv2..."
    bash "$SCRIPT_DIR/setup_core_protocol.sh" ipsec
    bash "$SCRIPT_DIR/setup_ikev2.sh" --force
    ;;
  l2tp|ipsec|pptp|openvpn)
    echo "[1/3] Installing/verifying ${KEY}..."
    bash "$SCRIPT_DIR/setup_core_protocol.sh" "$KEY"
    ;;
  vmess|vless)
    echo "[1/3] Installing/verifying Xray ${KEY}..."
    bash "$SCRIPT_DIR/setup_xray.sh" "--protocol=${KEY}" "$@"
    ;;
  infrastructure)
    echo "[1/3] Checking kernel/network infrastructure..."
    bash "$SCRIPT_DIR/setup_infrastructure.sh"
    ;;
  *)
    echo "ERROR: unsupported protocol key: $KEY" >&2
    exit 2
    ;;
esac

if [ "$KEY" = "infrastructure" ]; then
  echo "[2/3] Infrastructure repaired; protocol services were left untouched."
elif [ -x /opt/vpn-panel/backend/venv/bin/python ] && [ -d /opt/vpn-panel/backend/app ]; then
  echo "[2/3] Synchronising panel users and applying saved protocol settings..."
  cd /opt/vpn-panel/backend
  mapfile -t PROTO_ARGS < <(/opt/vpn-panel/backend/venv/bin/python - <<'PYSETTINGS'
from app.database import SessionLocal
from app.models import Setting
from app.services.vpn_manager import sync_chap_secrets

db = SessionLocal()
def get(key, default):
    row = db.query(Setting).filter(Setting.key == key).first()
    return row.value if row else default
try:
    sync_chap_secrets(db)
    values = [
        get("l2tp_enabled", "1"), get("l2tp_port", "1701"),
        get("pptp_enabled", "1"),
        get("openvpn_enabled", "1"), get("openvpn_udp_port", "1194"), get("openvpn_tcp_port", "1194"),
        get("vpn_domain", ""), get("l2tp_mtu", "1400"), get("l2tp_mru", "1400"),
        get("sstp_enabled", "1"), get("sstp_port", "4433"), get("ikev2_enabled", "1"),
        get("openvpn_dns1", "1.1.1.1"), get("openvpn_dns2", "8.8.8.8"),
    ]
    for value in values:
        print(value)
finally:
    db.close()
PYSETTINGS
  )
  if [ "$KEY" = "vmess" ] || [ "$KEY" = "vless" ]; then
    (cd /opt/vpn-panel/backend && /opt/vpn-panel/backend/venv/bin/python -m app.xray_cli sync --protocol "$KEY")
  elif [ "$KEY" = "openconnect" ]; then
    # setup_openconnect.sh already applied the saved port/DNS values.  Do not
    # restart every other VPN backend just because ocserv was installed.
    echo "OpenConnect configuration already applied; unrelated services left untouched."
  else
    # The fifteenth argument selects the one backend being repaired.  This
    # keeps a per-card install from disconnecting users on unrelated protocols.
    bash "$SCRIPT_DIR/configure_vpn_protocols.sh" "${PROTO_ARGS[@]}" "$KEY"
  fi
else
  echo "[2/3] Panel backend is not installed; skipped database synchronisation."
fi

# Reapply the database-authoritative structured settings after every install or
# repair. Setup helpers may need to recreate a missing config with safe defaults;
# this final pass restores the exact DNS/MTU/pool values saved in the panel.
# DNS2="" is intentional and must remain a single-resolver configuration.
if [ "$KEY" != "infrastructure" ] && [ "$KEY" != "ipsec" ] && [ "$KEY" != "vmess" ] && [ "$KEY" != "vless" ] \
   && [ -x /opt/vpn-panel/backend/venv/bin/python ] && [ -d /opt/vpn-panel/backend/app ]; then
  echo "[settings] Restoring authoritative saved DNS and structured options for ${KEY}..."
  (cd /opt/vpn-panel/backend && /opt/vpn-panel/backend/venv/bin/python - "$KEY" <<'PYAUTHORITATIVE'
import sys
from app.database import SessionLocal
from app.models import Setting
from app.schemas import VpnProtocolSettings
from app.services.protocol_dns import apply_protocol_dns_settings
from app.services.protocol_options import apply_protocol_options

key = sys.argv[1]
db = SessionLocal()
try:
    rows = {row.key: row.value for row in db.query(Setting).all()}
finally:
    db.close()

def coerce(name, default):
    if name not in rows or rows[name] is None:
        return default
    raw = rows[name]
    if isinstance(default, bool):
        return str(raw).strip().lower() in {"1", "true", "yes", "on"}
    if isinstance(default, int):
        try:
            return int(raw)
        except (TypeError, ValueError):
            return default
    return str(raw)

defaults = VpnProtocolSettings().model_dump()
payload = VpnProtocolSettings(**{name: coerce(name, value) for name, value in defaults.items()})
# L2TP/PPTP read DNS per new PPP session, so their options handler performs the
# only daemon restart. Other protocols defer restart to the transactional DNS
# path so OpenVPN extra listeners are restarted too.
restart_in_options = key in {"l2tp", "pptp"}
ok, detail = apply_protocol_options(payload, target=key, restart_services=restart_in_options)
if not ok:
    raise SystemExit(f"AUTHORITATIVE_OPTIONS_FAILED {key}: {detail}")
ok, detail = apply_protocol_dns_settings(payload, key, apply_runtime=True)
if not ok:
    if key == "sstp" and "libdns.so" in detail:
        print(f"AUTHORITATIVE_DNS_WARNING {key}: {detail}", file=sys.stderr)
    else:
        raise SystemExit(f"AUTHORITATIVE_DNS_FAILED {key}: {detail}")
else:
    print(detail)
PYAUTHORITATIVE
  )
fi

if [ "$KEY" != "infrastructure" ] && [ -x /opt/vpn-panel/backend/venv/bin/python ]; then
  echo "[health] Verifying process, listener, configuration and permissions..."
  if ! (cd /opt/vpn-panel/backend && /opt/vpn-panel/backend/venv/bin/python - "$KEY" <<'PYHEALTH'
import sys
from app.database import SessionLocal
from app.models import Setting
from app.services.protocol_admin import get_protocol_center

key = sys.argv[1]
db = SessionLocal()
def flag(name, default="1"):
    row = db.query(Setting).filter(Setting.key == name).first()
    return (row.value if row else default) == "1"
try:
    row = next((item for item in get_protocol_center(db) if item["key"] == key), None)
    if not row:
        raise SystemExit(f"RUNTIME_HEALTH_FAILED: protocol {key} not found")
    if key == "ipsec":
        enabled = flag("l2tp_enabled") or flag("ikev2_enabled")
    elif key == "openconnect":
        enabled = True
    else:
        enabled = flag(f"{key}_enabled")
    print(f"RUNTIME_HEALTH {key}: state={row['state']} process={row['health']['process']} ports={row['health']['ports']} config={row['health']['config']} permissions={row['health']['permissions']} enabled={enabled}")
    if enabled and row["state"] != "active":
        detail = row.get("last_error") or row.get("health")
        raise SystemExit(f"RUNTIME_HEALTH_FAILED: {key} is enabled but not ready: {detail}")
    if not enabled:
        print(f"RUNTIME_HEALTH_NOTICE: {key} is installed/configured but intentionally disabled in panel settings; use Start or enable it in Edit to make it listen.")
finally:
    db.close()
PYHEALTH
  ); then
    echo "[3/3] Installation/repair failed runtime readiness verification." >&2
    exit 7
  fi
fi

echo "[3/3] Installation/repair finished. Enabled protocols passed runtime readiness; disabled protocols remain intentionally stopped."
