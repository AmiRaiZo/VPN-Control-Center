#!/bin/bash
set -euo pipefail

XRAY_VERSION="${XRAY_VERSION:-v26.6.27}"
PROTOCOL="both"
FORCE=0
for arg in "$@"; do
  case "$arg" in
    --protocol=vmess|--protocol=vless) PROTOCOL="${arg#*=}" ;;
    --force) FORCE=1 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root" >&2; exit 1; }
STARTED=$(date +%s)
ARCH=$(dpkg --print-architecture)
case "$ARCH" in
  amd64) ASSET="Xray-linux-64.zip" ;;
  arm64) ASSET="Xray-linux-arm64-v8a.zip" ;;
  armhf) ASSET="Xray-linux-arm32-v7a.zip" ;;
  *) echo "ERROR: unsupported architecture: $ARCH" >&2; exit 2 ;;
esac

ROOT=/etc/vpn-panel/xray
LOGROOT=/var/log/vpn-panel/xray
BACKUP="/var/backups/vpn-panel/xray-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$ROOT/vmess" "$ROOT/vless" "$LOGROOT" "$BACKUP"

PREV_ACTIVE_VMESS=0
PREV_ACTIVE_VLESS=0
systemctl is-active --quiet vpn-panel-xray-vmess 2>/dev/null && PREV_ACTIVE_VMESS=1 || true
systemctl is-active --quiet vpn-panel-xray-vless 2>/dev/null && PREV_ACTIVE_VLESS=1 || true
[ -f "$ROOT/vmess/config.json" ] && cp -a "$ROOT/vmess/config.json" "$BACKUP/vmess-config.json" || true
[ -f "$ROOT/vless/config.json" ] && cp -a "$ROOT/vless/config.json" "$BACKUP/vless-config.json" || true
[ -f /etc/systemd/system/vpn-panel-xray-vmess.service ] && cp -a /etc/systemd/system/vpn-panel-xray-vmess.service "$BACKUP/" || true
[ -f /etc/systemd/system/vpn-panel-xray-vless.service ] && cp -a /etc/systemd/system/vpn-panel-xray-vless.service "$BACKUP/" || true
TMP=""
RESTORE_ON_ERROR=1
cleanup_xray_setup() {
  rc=$?
  trap - EXIT
  [ -n "${TMP:-}" ] && rm -rf "$TMP" || true
  if [ "$rc" -ne 0 ] && [ "$RESTORE_ON_ERROR" = "1" ]; then
    echo "[!] Xray repair failed; restoring the last working configs/services." >&2
    [ -f "$BACKUP/vmess-config.json" ] && cp -a "$BACKUP/vmess-config.json" "$ROOT/vmess/config.json" || true
    [ -f "$BACKUP/vless-config.json" ] && cp -a "$BACKUP/vless-config.json" "$ROOT/vless/config.json" || true
    [ -f "$BACKUP/vpn-panel-xray-vmess.service" ] && cp -a "$BACKUP/vpn-panel-xray-vmess.service" /etc/systemd/system/ || true
    [ -f "$BACKUP/vpn-panel-xray-vless.service" ] && cp -a "$BACKUP/vpn-panel-xray-vless.service" /etc/systemd/system/ || true
    systemctl daemon-reload 2>/dev/null || true
    [ "$PREV_ACTIVE_VMESS" = "1" ] && systemctl restart vpn-panel-xray-vmess 2>/dev/null || true
    [ "$PREV_ACTIVE_VLESS" = "1" ] && systemctl restart vpn-panel-xray-vless 2>/dev/null || true
  fi
  exit "$rc"
}
trap cleanup_xray_setup EXIT

if ! id vpn-xray >/dev/null 2>&1; then
  useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin vpn-xray
fi

# /etc/vpn-panel is shared by OpenVPN's drop user and vpn-xray.  Grouping the
# parent to either service with 0750 blocks the other one.  Keep only traversal
# on the shared parent and enforce confidentiality on each child file/tree.
install -d -o root -g root -m 0711 /etc/vpn-panel
install -d -o root -g vpn-xray -m 0750 "$ROOT" "$ROOT/vmess" "$ROOT/vless"

CURRENT=""
if [ -x /usr/local/bin/xray ]; then
  CURRENT=$(/usr/local/bin/xray version 2>/dev/null | head -1 || true)
fi
if [ "$FORCE" -eq 0 ] && echo "$CURRENT" | grep -q "${XRAY_VERSION#v}"; then
  echo "[1/5] Xray ${XRAY_VERSION} is already installed; binary download skipped."
else
  echo "[1/5] Downloading official Xray ${XRAY_VERSION} release..."
  TMP=$(mktemp -d)
  BASE="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}"
  curl --fail --location --retry 3 --connect-timeout 15 -o "$TMP/$ASSET" "$BASE/$ASSET"
  curl --fail --location --retry 3 --connect-timeout 15 -o "$TMP/$ASSET.dgst" "$BASE/$ASSET.dgst"
  EXPECTED=$(awk 'BEGIN{IGNORECASE=1} /SHA2-256|SHA256/{for(i=1;i<=NF;i++) if($i ~ /^[0-9a-fA-F]{64}$/){print tolower($i); exit}}' "$TMP/$ASSET.dgst")
  [ -n "$EXPECTED" ] || { echo "ERROR: SHA-256 not found in official digest file" >&2; exit 3; }
  ACTUAL=$(sha256sum "$TMP/$ASSET" | awk '{print $1}')
  [ "$EXPECTED" = "$ACTUAL" ] || { echo "ERROR: Xray checksum mismatch" >&2; exit 4; }
  unzip -q "$TMP/$ASSET" -d "$TMP/unpacked"
  [ -x "$TMP/unpacked/xray" ] || chmod +x "$TMP/unpacked/xray"
  if [ -x /usr/local/bin/xray ]; then cp -a /usr/local/bin/xray "$BACKUP/xray"; fi
  install -m 0755 "$TMP/unpacked/xray" /usr/local/bin/xray.new
  mv /usr/local/bin/xray.new /usr/local/bin/xray
  mkdir -p /usr/local/share/xray
  [ -f "$TMP/unpacked/geoip.dat" ] && install -m 0644 "$TMP/unpacked/geoip.dat" /usr/local/share/xray/geoip.dat
  [ -f "$TMP/unpacked/geosite.dat" ] && install -m 0644 "$TMP/unpacked/geosite.dat" /usr/local/share/xray/geosite.dat
  echo "$XRAY_VERSION $ACTUAL" > "$ROOT/VERSION"
fi

for proto in vmess vless; do
  cat > "/etc/systemd/system/vpn-panel-xray-${proto}.service" <<EOF
[Unit]
Description=VPN Panel Xray ${proto^^}
After=network-online.target vpn-panel-api.service
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=8

[Service]
Type=simple
User=vpn-xray
Group=vpn-xray
ExecStartPre=/usr/bin/test -r /etc/vpn-panel/xray/${proto}/config.json
ExecStart=/usr/local/bin/xray run -config /etc/vpn-panel/xray/${proto}/config.json
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/vpn-panel/xray
ReadOnlyPaths=/etc/vpn-panel/xray /usr/local/share/xray

[Install]
WantedBy=multi-user.target
EOF
done
systemctl daemon-reload
# Do not stop healthy Xray services before the new binary/configs have passed
# validation. A failed repair must not leave VMess/VLESS offline.

echo "[2/5] Generating isolated VMess/VLESS configurations from panel database..."
if [ -x /opt/vpn-panel/backend/venv/bin/python ] && [ -d /opt/vpn-panel/backend/app ]; then
  (cd /opt/vpn-panel/backend && /opt/vpn-panel/backend/venv/bin/python -m app.xray_cli generate)
else
  echo "ERROR: VPN Panel backend is not installed" >&2
  exit 5
fi

(cd /opt/vpn-panel/backend && /opt/vpn-panel/backend/venv/bin/python - <<'PYPERMS'
from app.services.xray_manager import ensure_runtime_permissions
ensure_runtime_permissions()
PYPERMS
)
chown -R root:vpn-xray "$ROOT"
find "$ROOT" -type d -exec chmod 0750 {} +
find "$ROOT" -type f -exec chmod 0640 {} +
chown -R vpn-xray:vpn-xray "$LOGROOT"
chmod 0750 "$LOGROOT"

echo "[3/5] Validating generated configurations..."
for proto in vmess vless; do
  runuser -u vpn-xray -- /usr/bin/test -r "$ROOT/$proto/config.json"
  runuser -u vpn-xray -- /usr/local/bin/xray run -test -config "$ROOT/$proto/config.json"
done

echo "[4/5] Applying saved enabled state..."
for proto in vmess vless; do
  # Installing or repairing one protocol must not stop the sibling Xray unit.
  # The ``both`` mode is used only by an explicit full Xray repair.
  if [ "$PROTOCOL" != "both" ] && [ "$PROTOCOL" != "$proto" ]; then
    continue
  fi
  enabled=$(cd /opt/vpn-panel/backend && /opt/vpn-panel/backend/venv/bin/python - "$proto" <<'PY'
import sys
from app.database import SessionLocal
from app.models import Setting
p=sys.argv[1]
db=SessionLocal()
try:
    row=db.query(Setting).filter(Setting.key==f"{p}_enabled").first()
    print(row.value if row else "missing")
finally: db.close()
PY
)
  if [ "$enabled" = "missing" ]; then
    previous_var="PREV_ACTIVE_${proto^^}"
    previous_active="${!previous_var:-0}"
    enabled="$previous_active"
    (cd /opt/vpn-panel/backend && /opt/vpn-panel/backend/venv/bin/python - "$proto" "$enabled" <<'PYSET'
import sys
from app.database import SessionLocal
from app.models import Setting
p, value = sys.argv[1], sys.argv[2]
db=SessionLocal()
try:
    db.add(Setting(key=f"{p}_enabled", value="1" if value == "1" else "0"))
    db.commit()
finally: db.close()
PYSET
)
    echo "  • ${proto} enabled setting was missing; preserved previous service state=${enabled}"
  fi
  if [ "$enabled" = "1" ]; then
    systemctl reset-failed "vpn-panel-xray-$proto" >/dev/null 2>&1 || true
    systemctl enable "vpn-panel-xray-$proto" >/dev/null 2>&1 || true
    systemctl restart "vpn-panel-xray-$proto"
    port=$(cd /opt/vpn-panel/backend && /opt/vpn-panel/backend/venv/bin/python - "$proto" <<'PYPORT'
import sys
from app.database import SessionLocal
from app.services.xray_manager import get_protocol_settings
p=sys.argv[1]
db=SessionLocal()
try: print(get_protocol_settings(db,p)["port"])
finally: db.close()
PYPORT
)
    ready=0
    for _ in $(seq 1 30); do
      if systemctl is-active --quiet "vpn-panel-xray-$proto" && ss -H -lnt 2>/dev/null | awk -v p=":$port" '$4 ~ p"$" {found=1} END{exit !found}'; then
        ready=1
        break
      fi
      sleep 0.5
    done
    if [ "$ready" -ne 1 ]; then
      echo "ERROR: $proto was enabled but did not become active on TCP/$port" >&2
      systemctl status "vpn-panel-xray-$proto" --no-pager -l >&2 || true
      journalctl -u "vpn-panel-xray-$proto" -n 80 --no-pager >&2 || true
      exit 6
    fi
    echo "  ✓ $proto is active and listening on TCP/$port"
  else
    systemctl disable --now "vpn-panel-xray-$proto" >/dev/null 2>&1 || true
    echo "  • $proto is disabled by saved panel settings"
  fi
done

RESTORE_ON_ERROR=0
echo "[5/5] Xray installation/repair completed in $(( $(date +%s) - STARTED )) seconds."
