#!/bin/bash
# Apply the 2.3.137 L2TP/PPTP/SSTP repair to an existing installation.
# This entry point intentionally does not invoke OpenVPN, OpenConnect, IKEv2,
# Xray/VMess/VLESS, firewall-wide, frontend, database, or node repair jobs.
set -Eeuo pipefail

[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root" >&2; exit 1; }
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALL_DIR="/opt/vpn-panel"
[ -d "$INSTALL_DIR/backend/app/services" ] || {
  echo "ERROR: $INSTALL_DIR is not an installed VPN Panel instance" >&2
  exit 2
}

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="$INSTALL_DIR/update-backups/classic-ppp-2.3.137-$STAMP"
mkdir -p "$BACKUP_DIR"

backup_path() {
  local path="$1" relative
  [ -e "$path" ] || return 0
  relative="${path#/}"
  mkdir -p "$BACKUP_DIR/$(dirname "$relative")"
  cp -a "$path" "$BACKUP_DIR/$relative"
}

for path in \
  "$INSTALL_DIR/backend/app/services/protocol_options.py" \
  /etc/xl2tpd/xl2tpd.conf /etc/ppp/options.xl2tpd \
  /etc/pptpd.conf /etc/ppp/pptpd-options \
  /etc/accel-ppp/sstp.conf \
  /etc/systemd/system/pptpd.service \
  /etc/systemd/system/accel-ppp-sstp.service; do
  backup_path "$path"
done

echo "[*] Backup created: $BACKUP_DIR"

# Deploy only the backend option editor and helpers belonging to these three
# protocols. No unrelated protocol implementation is copied or executed.
copy_file() {
  local mode="$1" src="$2" dst="$3"
  [ -f "$src" ] || return 0
  if [ "$(readlink -f "$src")" != "$(readlink -f "$dst" 2>/dev/null || echo "$dst")" ]; then
    install -m "$mode" "$src" "$dst"
  fi
}

install -d -m 0755 "$INSTALL_DIR/scripts" "$INSTALL_DIR/backend/app/scripts"
copy_file 0644 \
  "$PROJECT_ROOT/backend/app/services/protocol_options.py" \
  "$INSTALL_DIR/backend/app/services/protocol_options.py"
for helper in setup_core_protocol.sh setup_pptp.sh setup_sstp.sh repair_classic_ppp_protocols.sh; do
  copy_file 0755 "$SCRIPT_DIR/$helper" "$INSTALL_DIR/scripts/$helper"
done

for hook in sstp_ip_up.sh sstp_ip_down.sh admission_guard.sh ensure_session_networking.sh; do
  src="$PROJECT_ROOT/backend/app/scripts/$hook"
  [ -f "$src" ] || continue
  copy_file 0755 "$src" "$INSTALL_DIR/backend/app/scripts/$hook"
  copy_file 0755 "$src" "$INSTALL_DIR/scripts/$hook"
done

# setup_sstp verifies/rebuilds only accel-ppp SSTP modules and then heals its
# own config. The current listener port is retained.
SSTP_PORT="4433"
if [ -f /etc/accel-ppp/sstp.conf ]; then
  detected_port=$(awk -F= '/^[[:space:]]*port[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' /etc/accel-ppp/sstp.conf)
  if [[ "${detected_port:-}" =~ ^[0-9]+$ ]]; then
    SSTP_PORT="$detected_port"
  fi
fi
"$SCRIPT_DIR/setup_sstp.sh" "--port=$SSTP_PORT"
"$SCRIPT_DIR/repair_classic_ppp_protocols.sh"

printf '2.3.137\n' > "$INSTALL_DIR/VERSION"
systemctl restart vpn-panel-api

echo "[✓] L2TP/PPTP/SSTP hotfix applied. Other protocol repair/install scripts were not run."
