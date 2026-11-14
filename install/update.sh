#!/bin/bash
# Version 2.3.267 preserves deployment choices pre-collected by the licensed bootstrap during role conversion.
# Version 2.3.259 keeps only the OpenVPN friendly-name metadata comment and ships a compact full online installer.
# Version 2.3.257 adds ordered OpenVPN primary-to-fallback failover, safe same-endpoint reconnect handover, ALL-username filenames, and per-protocol log clearing.
# Version 2.3.256 fixes missing runtime imports in the OpenVPN live-status cache while preserving the 2.3.255 frontend bundle.
# Version 2.3.241 fixes the Users runtime Promise/component collision and disables automatic crash reload loops.

# 2.3.253: live VPN transports are never restarted by presence/watchdog probes.
# Version 2.3.240 adds isolated per-user status refresh and fixes action-button rendering.
# Version 2.3.238 restores truly responsive user-card columns based on the actual content width.
# Version 2.3.235 keeps offline timestamps inside user cards and places the RTL online indicator beside, not over, the label.
# Version 2.3.233 adds desktop-only glass user cards, explicit online glow, and polished user actions.
# Version 2.3.230 replaces the broken users table runtime with responsive cards and adds one-time admin credential reset/reveal.
# Version 2.3.229 makes Telegram audit logs precise for admin changes, dual-stack login IPs and enabled protocols only.
# Version 2.3.228 stabilizes the user table layout and separates account/connection status.
# Version 2.3.227 publishes a fresh frontend graph and caps user protocol badges at three per row.
###############################################################################
# Safe in-place panel update.
## Version 2.3.223 enforces each user max_devices budget fleet-wide across the controller, every node and every VPN protocol with atomic controller reservations.
## Version 2.3.222 keeps L2TP/PPTP reconnect handovers from consuming a second max_devices slot while preserving limits for different endpoints/protocols.
## Version 2.3.220 makes DNS changes database-authoritative and transactional across L2TP, PPTP, OpenVPN (including extra listeners), SSTP, IKEv2 and OpenConnect; the immutable v23218 frontend graph is retained.
## Version 2.3.210 self-heals stale runtime authentication stores on managed nodes.
## Version 2.3.204 switches backups to directly restorable plain gzip JSON while retaining bounded imports, integrity checks, licensing, rate limits and SSH host-key verification.
## Version 2.3.191 normalizes rebuildable legacy OpenVPN extra-listener backup warnings while retaining version-insensitive ZIP/SHA-256 updates.
# Version 2.3.190 makes update version metadata informational only while retaining ZIP and SHA-256 integrity verification.
# Version 2.3.188 treats missing server-side client keys as non-fatal when EasyRSA/PKI preserves active profiles, backs up the full OpenVPN server tree, and verifies complete settings/runtime coverage for every registered node.
# Version 2.3.187 restores the original login form side, changes only the desktop hero background, and fixes frontend manifest verification.
# Version 2.3.186 repairs missing OpenVPN client material before backup, verifies every node-local full backup, and hardens the detached updater.
# Version 2.3.185 removes the synthetic first-paint/login shell, applies language direction before first paint, and preloads the real login/dashboard routes.
# Version 2.3.179 adds server timezone/clock controls and exposes exact backup-health warnings in Telegram; 2.3.178 added themed Telegram QR rendering and replaced the checker background.
# Version 2.3.173 adds instant cached route paint, delayed background refresh, per-node IPsec PSK fixes and faster OpenVPN failover.
# Version 2.3.167 removes the visible boot card, loads external fonts asynchronously, and hard-locks every panel control while an update is running.
# The database, .env, certificates, saved ports and user settings are preserved.
# Version 2.3.148 keeps password reveal controls inside the input and prevents stale frontend caches from hiding new Telegram controls.
# Version 2.3.147 restores Python 3.10/3.11 compatibility for the Telegram controller.
# Version 2.3.146 automatically delivers each new Telegram-created user's
# clickable subscription URL and a PNG QR that opens the exact URL when scanned;
# the user card can resend the same link/QR later with one inline button.
# Version 2.3.145 button-first controller behavior remains intact.
# Version 2.3.144 login-eye and authenticated controller security remain intact.
# Version 2.3.143 exact full-cluster disaster recovery remains unchanged.
# Existing data, keys, certificates, saved ports, settings and VPN configs remain.
###############################################################################
set -Eeuo pipefail

if [ "${EUID}" -ne 0 ]; then
  echo "Please run this script as root (sudo bash update.sh)" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALL_DIR="/opt/vpn-panel"
WEB_DIR="/var/www/vpn-panel"
MAIN_NGINX_SITE="/etc/nginx/sites-available/vpn-panel"
UPDATE_PROGRESS_FILE="$INSTALL_DIR/update-progress.json"
PUBLIC_UPDATE_PROGRESS_FILE="$INSTALL_DIR/update-progress-public.json"
WHEEL_DIR="$PROJECT_ROOT/vendor/wheels"
WHEEL_MANIFEST="$PROJECT_ROOT/vendor/wheels.sha256"
BACKUP_ROOT="$INSTALL_DIR/update-backups"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="$BACKUP_ROOT/$STAMP"
API_STOPPED=0
UPDATE_OK=0
PROGRESS_BRIDGE_PID=0
BACKGROUND_UNIT="/etc/systemd/system/vpn-panel-background.service"
API_BACKGROUND_DROPIN="/etc/systemd/system/vpn-panel-api.service.d/20-background-jobs.conf"

phase() { printf '[update-phase] %s\n' "$*"; }
phase "Update bootstrap started"
restart_api_best_effort() {
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl restart vpn-panel-api >/dev/null 2>&1 || true
  if [ -f "$BACKGROUND_UNIT" ]; then
    systemctl enable vpn-panel-background >/dev/null 2>&1 || true
    systemctl restart vpn-panel-background >/dev/null 2>&1 || true
  fi
}
rollback() {
  echo "[!] Rolling back panel code/static files after update failure..." >&2
  systemctl stop vpn-panel-background >/dev/null 2>&1 || true
  if [ -f "$BACKUP_DIR/background-unit.existed" ]; then
    install -d -m 0755 "$(dirname "$BACKGROUND_UNIT")"
    cp -a "$BACKUP_DIR/vpn-panel-background.service" "$BACKGROUND_UNIT"
  else
    rm -f "$BACKGROUND_UNIT"
  fi
  if [ -f "$BACKUP_DIR/api-background-dropin.existed" ]; then
    install -d -m 0755 "$(dirname "$API_BACKGROUND_DROPIN")"
    cp -a "$BACKUP_DIR/20-background-jobs.conf" "$API_BACKGROUND_DROPIN"
  else
    rm -f "$API_BACKGROUND_DROPIN"
    rmdir "$(dirname "$API_BACKGROUND_DROPIN")" 2>/dev/null || true
  fi
  if [ -d "$BACKUP_DIR/backend-app" ]; then
    rm -rf "$INSTALL_DIR/backend/app"
    cp -a "$BACKUP_DIR/backend-app" "$INSTALL_DIR/backend/app"
  fi
  [ -f "$BACKUP_DIR/requirements.txt" ] && cp -a "$BACKUP_DIR/requirements.txt" "$INSTALL_DIR/backend/requirements.txt"
  if [ -d "$BACKUP_DIR/web" ]; then
    mkdir -p "$WEB_DIR"
    rm -rf "${WEB_DIR:?}"/*
    cp -a "$BACKUP_DIR/web/." "$WEB_DIR/"
  fi
  [ -f "$BACKUP_DIR/VERSION" ] && cp -a "$BACKUP_DIR/VERSION" "$INSTALL_DIR/VERSION"
  [ -f "$BACKUP_DIR/panel.env" ] && cp -a "$BACKUP_DIR/panel.env" "$INSTALL_DIR/panel.env"
  [ -f "$BACKUP_DIR/backend.env" ] && cp -a "$BACKUP_DIR/backend.env" "$INSTALL_DIR/backend/.env"
  if [ -d "$BACKUP_DIR/openvpn-server" ]; then
    install -d -m 0755 /etc/openvpn/server
    cp -a "$BACKUP_DIR/openvpn-server/." /etc/openvpn/server/
    systemctl restart openvpn-server@server-udp >/dev/null 2>&1 || true
    systemctl restart openvpn-server@server-tcp >/dev/null 2>&1 || true
  fi
  if [ -d "$BACKUP_DIR/nginx-sites" ]; then
    for saved in "$BACKUP_DIR/nginx-sites"/*; do
      [ -f "$saved" ] || continue
      cp -a "$saved" "/etc/nginx/sites-available/$(basename "$saved")"
    done
    nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
  fi
  if [ -x "$INSTALL_DIR/scripts/refresh_openvpn_runtime_env.sh" ]; then
    "$INSTALL_DIR/scripts/refresh_openvpn_runtime_env.sh" >/dev/null 2>&1 || true
  fi
  if [ -s "$BACKUP_DIR/settings.json" ] && [ -x "$INSTALL_DIR/backend/venv/bin/python" ]; then
    (cd "$INSTALL_DIR/backend" && "$INSTALL_DIR/backend/venv/bin/python" - "$BACKUP_DIR/settings.json" <<'PYROLLBACKSETTINGS'
import json, sys
from app.database import SessionLocal
from app.models import Setting
data = json.load(open(sys.argv[1]))
db = SessionLocal()
try:
    for key, value in data.items():
        row = db.query(Setting).filter(Setting.key == key).first()
        if row:
            row.value = value
        else:
            db.add(Setting(key=key, value=value))
    db.commit()
finally:
    db.close()
PYROLLBACKSETTINGS
    ) || true
  fi
  restart_api_best_effort
}
on_exit() {
  rc=$?
  if [ "$PROGRESS_BRIDGE_PID" -gt 0 ]; then
    kill "$PROGRESS_BRIDGE_PID" >/dev/null 2>&1 || true
    wait "$PROGRESS_BRIDGE_PID" 2>/dev/null || true
    PROGRESS_BRIDGE_PID=0
  fi
  if [ "$rc" -ne 0 ] && [ "$UPDATE_OK" -ne 1 ]; then
    rollback || true
  elif [ "$API_STOPPED" -eq 1 ]; then
    restart_api_best_effort
  fi
  exit "$rc"
}
trap on_exit EXIT

[ -d "$INSTALL_DIR/backend/app" ] || { echo "ERROR: existing panel installation not found at $INSTALL_DIR" >&2; exit 1; }
[ -f "$PROJECT_ROOT/frontend/dist/index.html" ] || { echo "ERROR: bundled frontend dist/index.html is missing" >&2; exit 1; }
[ -f "$PROJECT_ROOT/frontend/dist.sha256" ] || { echo "ERROR: bundled frontend checksum manifest is missing" >&2; exit 1; }
WHEELHOUSE_AVAILABLE=0
if [ -d "$WHEEL_DIR" ] && [ -s "$WHEEL_MANIFEST" ]; then
  WHEELHOUSE_AVAILABLE=1
fi
[ -f "$SCRIPT_DIR/npm_safe.sh" ] || { echo "ERROR: npm_safe.sh helper is missing" >&2; exit 1; }
source "$SCRIPT_DIR/npm_safe.sh"

phase "Preflight: verifying bundled frontend"
vpn_panel_verify_bundled_frontend "$PROJECT_ROOT/frontend" || {
  echo "ERROR: release frontend checksum verification failed; npm fallback is disabled for production updates" >&2
  exit 1
}

if [ "$WHEELHOUSE_AVAILABLE" -eq 1 ]; then
  phase "Preflight: verifying bundled Python dependencies"
  (cd "$PROJECT_ROOT/vendor" && sha256sum -c wheels.sha256 >/dev/null) || {
    echo "ERROR: bundled Python wheel checksum verification failed" >&2
    exit 1
  }
else
  phase "Preflight: compact full online package"
  echo "    wheelhouse omitted; the healthy existing virtualenv is reused, and missing/changed dependencies are downloaded when required."
fi

phase "Creating rollback snapshot"
mkdir -p "$BACKUP_DIR"
cp -a "$INSTALL_DIR/backend/app" "$BACKUP_DIR/backend-app"
[ -f "$INSTALL_DIR/backend/requirements.txt" ] && cp -a "$INSTALL_DIR/backend/requirements.txt" "$BACKUP_DIR/requirements.txt"
[ -f "$INSTALL_DIR/VERSION" ] && cp -a "$INSTALL_DIR/VERSION" "$BACKUP_DIR/VERSION"
if [ -d "$WEB_DIR" ]; then
  mkdir -p "$BACKUP_DIR/web"
  cp -a "$WEB_DIR/." "$BACKUP_DIR/web/"
fi
[ -f "$INSTALL_DIR/panel.env" ] && cp -a "$INSTALL_DIR/panel.env" "$BACKUP_DIR/panel.env"
[ -f "$INSTALL_DIR/backend/.env" ] && cp -a "$INSTALL_DIR/backend/.env" "$BACKUP_DIR/backend.env"
if [ -f "$BACKGROUND_UNIT" ]; then
  cp -a "$BACKGROUND_UNIT" "$BACKUP_DIR/vpn-panel-background.service"
  touch "$BACKUP_DIR/background-unit.existed"
fi
if [ -f "$API_BACKGROUND_DROPIN" ]; then
  cp -a "$API_BACKGROUND_DROPIN" "$BACKUP_DIR/20-background-jobs.conf"
  touch "$BACKUP_DIR/api-background-dropin.existed"
fi
if [ -d /etc/openvpn/server ]; then
  mkdir -p "$BACKUP_DIR/openvpn-server"
  cp -a /etc/openvpn/server/. "$BACKUP_DIR/openvpn-server/"
fi
mkdir -p "$BACKUP_DIR/nginx-sites"
for site in vpn-panel vpn-panel-sub vpn-panel-xray-sub; do
  [ -f "/etc/nginx/sites-available/$site" ] && cp -a "/etc/nginx/sites-available/$site" "$BACKUP_DIR/nginx-sites/$site"
done
find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d -printf '%T@ %p\n' 2>/dev/null \
  | sort -nr | tail -n +4 | cut -d' ' -f2- | xargs -r rm -rf

# Database rows are not supposed to change during a code-only update. Keep an
# explicit settings snapshot anyway: it protects custom panel/sub/VPN domains,
# ports, branding and Node mode from a broken migration or an accidental seed.
CURRENT_PY="$INSTALL_DIR/backend/venv/bin/python"
if [ -x "$CURRENT_PY" ]; then
  (cd "$INSTALL_DIR/backend" && "$CURRENT_PY" - "$BACKUP_DIR/settings.json" <<'PYSETTINGS'
import json, sys
from app.database import SessionLocal
from app.models import Setting
db = SessionLocal()
try:
    json.dump({r.key: r.value for r in db.query(Setting).all()}, open(sys.argv[1], "w"), ensure_ascii=False)
finally:
    db.close()
PYSETTINGS
  ) || echo "[!] Warning: settings snapshot could not be created" >&2
fi

phase "Enabling API-independent live update progress"
# The browser normally reads /api/backup/update/status. During the deliberate
# vpn-panel-api restart, an exact Nginx location falls back to a sanitized JSON
# file instead of returning 502. This keeps the real percentage moving for the
# tab that launched this very update, including the first upgrade from r4.
if [ -f "$MAIN_NGINX_SITE" ] && [ -f "$SCRIPT_DIR/update_progress_fallback.sh" ]; then
  PROGRESS_NGINX_BACKUP="$BACKUP_DIR/vpn-panel.nginx.before-progress"
  cp -a "$MAIN_NGINX_SITE" "$PROGRESS_NGINX_BACKUP"
  if bash "$SCRIPT_DIR/update_progress_fallback.sh" "$MAIN_NGINX_SITE" \
      && nginx -t >/dev/null 2>&1; then
    systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1 || true
    echo "    live update progress fallback enabled"
  else
    cp -a "$PROGRESS_NGINX_BACKUP" "$MAIN_NGINX_SITE"
    nginx -t >/dev/null 2>&1 && systemctl reload nginx >/dev/null 2>&1 || true
    echo "[!] Warning: live progress Nginx fallback could not be enabled; update safety is unaffected" >&2
  fi
else
  echo "[!] Warning: panel Nginx site was not found; using frontend heartbeat during API restart" >&2
fi

# A tiny sidecar mirrors only safe status fields. It deliberately does not
# expose the real update.log while authentication is temporarily unavailable.
python3 - "$UPDATE_PROGRESS_FILE" "$PUBLIC_UPDATE_PROGRESS_FILE" <<'PYPROGRESSBRIDGE' &
from pathlib import Path
import json
import os
import sys
import time

source = Path(sys.argv[1])
target = Path(sys.argv[2])
while True:
    try:
        raw = json.loads(source.read_text(encoding="utf-8"))
        percent = max(0, min(100, int(raw.get("percent") or 0)))
        state = str(raw.get("state") or "running")
        message = str(raw.get("message") or "Applying safe update")
        phase = message.split(" — ", 1)[0].strip()
        payload = {
            "percent": percent,
            "state": state,
            "message": phase,
            "run_id": raw.get("run_id"),
            "unit_name": raw.get("unit_name"),
            "updated_at": raw.get("updated_at"),
            "log_tail": (
                "[live-update] The panel API is restarting safely.\n"
                f"[{percent}%] {phase}\n"
                "[live-update] Real progress is still being received; do not close this page."
            ),
        }
        temporary = target.with_name(f"{target.name}.tmp.{os.getpid()}")
        temporary.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        os.chmod(temporary, 0o644)
        os.replace(temporary, target)
    except Exception:
        pass
    time.sleep(1)
PYPROGRESSBRIDGE
PROGRESS_BRIDGE_PID=$!
for _ in 1 2 3 4 5; do
  [ -s "$PUBLIC_UPDATE_PROGRESS_FILE" ] && break
  sleep 0.2
done

OLD_REQ_HASH=""
[ -f "$INSTALL_DIR/backend/requirements.txt" ] && OLD_REQ_HASH="$(sha256sum "$INSTALL_DIR/backend/requirements.txt" | awk '{print $1}')"
NEW_REQ_HASH="$(sha256sum "$PROJECT_ROOT/backend/requirements.txt" | awk '{print $1}')"

phase "Stopping API and background jobs briefly"
timeout 25 systemctl stop vpn-panel-background >/dev/null 2>&1 || true
timeout 25 systemctl stop vpn-panel-api || true
API_STOPPED=1

phase "Deploying backend code"
mkdir -p "$INSTALL_DIR/backend/app" "$INSTALL_DIR/scripts"
cp -a "$PROJECT_ROOT/backend/app/." "$INSTALL_DIR/backend/app/"
cp -a "$PROJECT_ROOT/backend/requirements.txt" "$INSTALL_DIR/backend/requirements.txt"
# Branding uploads live outside the code tree so updates cannot delete them.
install -d -m 0755 /var/lib/vpn-panel/branding

phase "Backfilling independent data-encryption and fail-closed security settings"
python3 - "$INSTALL_DIR/backend/.env" "$STAMP" <<'PYSECURITYENV'
from pathlib import Path
import os
import secrets
import sys

env_path = Path(sys.argv[1])
stamp = sys.argv[2]
text = env_path.read_text(encoding="utf-8") if env_path.exists() else ""
lines = text.splitlines()
values = {}
for line in lines:
    stripped = line.strip()
    if not stripped or stripped.startswith("#") or "=" not in stripped:
        continue
    key, value = stripped.split("=", 1)
    values[key.strip()] = value.strip().strip('"').strip("'")

# Backup files are plain gzip JSON from v2.3.204 onward. Remove obsolete
# decryption settings from existing installations.
obsolete_backup_keys = {
    "BACKUP_ENCRYPTION_KEY",
    "BACKUP_RECOVERY_KEY_PATH",
    "ALLOW_LEGACY_UNENCRYPTED_BACKUP_IMPORT",
}
for key in obsolete_backup_keys:
    values.pop(key, None)

changed = {}
insecure = {"", "change-me", "changeme", "default", "secret", "password", "test"}

def secret_ok(value: str, minimum: int = 32) -> bool:
    return str(value or "").strip().lower() not in insecure and len(str(value or "").strip()) >= minimum

def set_value(key: str, value: str, *, replace: bool = True) -> None:
    old = values.get(key)
    if old == value:
        return
    if old is not None and not replace:
        return
    values[key] = value
    changed[key] = {"old": old, "new": value}

for key in ("JWT_SECRET", "INTERNAL_API_TOKEN", "DATA_ENCRYPTION_KEY"):
    if not secret_ok(values.get(key, "")):
        set_value(key, secrets.token_hex(32))

if not secret_ok(values.get("IPSEC_PSK", ""), 16):
    set_value("IPSEC_PSK", secrets.token_hex(24))

# Same-origin is the secure default. Never carry a wildcard with credentials.
if values.get("CORS_ALLOWED_ORIGINS", "").strip() == "*":
    set_value("CORS_ALLOWED_ORIGINS", "")
else:
    set_value("CORS_ALLOWED_ORIGINS", values.get("CORS_ALLOWED_ORIGINS", ""), replace=False)
set_value("CORS_ALLOW_CREDENTIALS", values.get("CORS_ALLOW_CREDENTIALS", "true") or "true", replace=False)
set_value("BACKUP_MAX_COMPRESSED_BYTES", values.get("BACKUP_MAX_COMPRESSED_BYTES", "134217728") or "134217728", replace=False)
set_value("BACKUP_MAX_DECOMPRESSED_BYTES", values.get("BACKUP_MAX_DECOMPRESSED_BYTES", "805306368") or "805306368", replace=False)
set_value("SSH_KNOWN_HOSTS_PATH", values.get("SSH_KNOWN_HOSTS_PATH", "/var/lib/vpn-panel/ssh_known_hosts") or "/var/lib/vpn-panel/ssh_known_hosts", replace=False)
set_value("SSH_HOST_KEY_POLICY", values.get("SSH_HOST_KEY_POLICY", "tofu") or "tofu", replace=False)
set_value("LICENSE_FAIL_CLOSED", "true")
set_value("LICENSE_ALLOW_UNLICENSED_DEVELOPMENT", "false")

# Preserve comments/order while replacing known keys, then append new keys.
seen = set()
out = []
for line in lines:
    stripped = line.strip()
    if stripped and not stripped.startswith("#") and "=" in stripped:
        key = stripped.split("=", 1)[0].strip()
        if key in obsolete_backup_keys:
            continue
        if key in values:
            out.append(f"{key}={values[key]}")
            seen.add(key)
            continue
    out.append(line)
for key, value in values.items():
    if key not in seen:
        out.append(f"{key}={value}")
env_path.parent.mkdir(parents=True, exist_ok=True)
env_path.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")
os.chmod(env_path, 0o640)

recovery_dir = Path("/root/.vpn-panel")
recovery_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
os.chmod(recovery_dir, 0o700)

if changed:
    report = recovery_dir / f"security-migration-{stamp}.txt"
    safe_lines = [
        "VPN Panel automatic security migration",
        "======================================",
        "The following settings were created or repaired:",
    ]
    for key in changed:
        if key == "IPSEC_PSK":
            safe_lines.append(f"{key}={values[key]}  (update every L2TP client if this key changed)")
        else:
            safe_lines.append(f"{key}=generated/policy-updated (value kept in backend/.env)")
    report.write_text("\n".join(safe_lines) + "\n", encoding="utf-8")
    os.chmod(report, 0o600)
PYSECURITYENV
# The recovery-key feature was explicitly removed. New backups are plain
# .json.gz files, so the historical key note has no remaining purpose.
rm -f /root/.vpn-panel/backup-recovery-key.txt 2>/dev/null || true
chown root:nogroup "$INSTALL_DIR/backend/.env" 2>/dev/null || true
chmod 0640 "$INSTALL_DIR/backend/.env"
install -d -m 0700 /var/lib/vpn-panel
[ -e /var/lib/vpn-panel/ssh_known_hosts ] || install -m 0600 /dev/null /var/lib/vpn-panel/ssh_known_hosts
chmod 0600 /var/lib/vpn-panel/ssh_known_hosts 2>/dev/null || true

# Restore the exact pre-update settings snapshot before the new API starts.
# Upsert is intentional: new releases may add keys, while every existing key
# must keep its previous value byte-for-byte.
if [ -s "$BACKUP_DIR/settings.json" ] && [ -x "$CURRENT_PY" ]; then
  (cd "$INSTALL_DIR/backend" && "$CURRENT_PY" - "$BACKUP_DIR/settings.json" <<'PYRESTORE'
import json, sys
from app.database import SessionLocal
from app.models import Setting
data = json.load(open(sys.argv[1]))
db = SessionLocal()
try:
    for key, value in data.items():
        row = db.query(Setting).filter(Setting.key == key).first()
        if row:
            row.value = value
        else:
            db.add(Setting(key=key, value=value))
    db.commit()
finally:
    db.close()
PYRESTORE
  ) || { echo "ERROR: failed to restore preserved panel settings" >&2; exit 1; }
fi

phase "Deploying helper scripts without running protocol installers"
for helper in \
  configure_vpn_protocols.sh setup_domain_ssl.sh setup_sub_domain_ssl.sh \
  setup_xray_sub_domain_ssl.sh setup_vpn_domain_ssl.sh setup_ikev2.sh \
  setup_ikev2_ssl.sh setup_openconnect.sh change_panel_port.sh \
  change_sub_domain_port.sh change_xray_sub_domain_port.sh \
  disable_xray_sub_domain.sh reset_admin_password.sh check_vpn_domain.sh \
  manage_openvpn_extra_ports.sh install_protocol.sh \
  update_progress_fallback.sh \
  apt_preflight.sh npm_safe.sh setup_infrastructure.sh setup_core_protocol.sh \
  setup_pptp.sh setup_sstp.sh setup_xray.sh repair_classic_ppp_protocols.sh apply_classic_ppp_hotfix.sh repair_protocols_after_update.sh \
  recover_stuck_update.sh check_xray_user_controls.sh connect_node_controller.sh \
  bootstrap_host.sh node_registration_retry.sh repair_panel_access.sh \
  repair_node_public_access.sh reconfigure_deployment.sh ensure_openvpn_controller_pki.sh \
  repair_all_protocols_node.sh repair_vpn_ingress.sh audit_protocol_dns.sh; do
  [ -f "$SCRIPT_DIR/$helper" ] && cp -a "$SCRIPT_DIR/$helper" "$INSTALL_DIR/scripts/$helper"
done

# Never truncate/overwrite the updater while it is the currently running shell
# script. Stage the next runner and atomically rename it only after the safe
# update has completed. Replacing the pathname with mv preserves the old inode
# for the active bash process and avoids the unexpected-EOF false failure.
if [ -f "$SCRIPT_DIR/update_from_license.sh" ]; then
  cp -a "$SCRIPT_DIR/update_from_license.sh" "$INSTALL_DIR/scripts/update_from_license.sh.next"
  chmod +x "$INSTALL_DIR/scripts/update_from_license.sh.next"
fi

chmod +x "$INSTALL_DIR/scripts/"*.sh 2>/dev/null || true
if compgen -G "$INSTALL_DIR/backend/app/scripts/*.sh" >/dev/null; then
  cp -a "$INSTALL_DIR/backend/app/scripts/"*.sh "$INSTALL_DIR/scripts/"
  chmod +x "$INSTALL_DIR/scripts/"*.sh
fi

# Repair the OpenVPN authentication path before any subsequent service work.
# Older nodes often have panel.env mode 0600/root:root; the new hooks use a
# dedicated minimal file readable by OpenVPN's actual drop gid instead.
if [ -x "$INSTALL_DIR/scripts/refresh_openvpn_runtime_env.sh" ]; then
  "$INSTALL_DIR/scripts/refresh_openvpn_runtime_env.sh"
fi

phase "Repairing shared OpenVPN and Xray runtime permissions"
if [ -x "$INSTALL_DIR/scripts/repair_xray_runtime_permissions.sh" ]; then
  "$INSTALL_DIR/scripts/repair_xray_runtime_permissions.sh" --restart-enabled || {
    echo "[!] Warning: Xray runtime permission repair could not be completed" >&2
  }
fi

# /etc/ppp/ip-up.d and ip-down.d contain physical copies, not symlinks into
# /opt/vpn-panel/scripts. Older updates refreshed the source file only, leaving
# L2TP/PPTP on the stale hook forever. Reinstall the hooks on every update so
# admission, PID tracking and immediate per-session routing actually take effect.
if [ -f "$INSTALL_DIR/scripts/ppp_ip_up.sh" ] && [ -f "$INSTALL_DIR/scripts/ppp_ip_down.sh" ]; then
  install -d -m 0755 /etc/ppp/ip-up.d /etc/ppp/ip-down.d

  # Some very old releases used alternate names (for example 99-vpn-panel)
  # and left those physical copies behind. run-parts executes every matching
  # file, so one PPP session could hit /api/internal/connect twice and the two
  # admission calls would race/terminate each other. Remove only hooks that
  # unmistakably call the panel's internal connect/disconnect endpoints.
  for hook in /etc/ppp/ip-up.d/*; do
    [ -f "$hook" ] || continue
    [ "$hook" = /etc/ppp/ip-up.d/vpn-panel ] && continue
    if grep -Eq '/api/internal/connect|vpn_panel_admission_request|ppp_ip_up\.sh' "$hook" 2>/dev/null; then
      rm -f "$hook"
    fi
  done
  for hook in /etc/ppp/ip-down.d/*; do
    [ -f "$hook" ] || continue
    [ "$hook" = /etc/ppp/ip-down.d/vpn-panel ] && continue
    if grep -Eq '/api/internal/disconnect|ppp_ip_down\.sh' "$hook" 2>/dev/null; then
      rm -f "$hook"
    fi
  done

  install -m 0755 "$INSTALL_DIR/scripts/ppp_ip_up.sh" /etc/ppp/ip-up.d/vpn-panel
  install -m 0755 "$INSTALL_DIR/scripts/ppp_ip_down.sh" /etc/ppp/ip-down.d/vpn-panel
fi

phase "Restoring authoritative L2TP DNS and MTU settings"
# Releases up to 2.3.218 could write the saved 1400 value correctly and then
# overwrite the live PPP file with 1280 from repair_runtime_networking.sh.
# Reapply only the four L2TP values from the preserved database before running
# compatibility/network repairs. This does not touch ports, PSK, pools or any
# other protocol and does not restart a service. New PPP sessions negotiate the
# corrected value; existing sessions keep their already-negotiated MTU.
if [ -x "$CURRENT_PY" ] && [ -f /etc/ppp/options.xl2tpd ]; then
  (cd "$INSTALL_DIR/backend" && "$CURRENT_PY" <<'PYL2TPAUTHORITY'
import ipaddress
import re
from pathlib import Path
from app.database import SessionLocal
from app.models import Setting

path = Path('/etc/ppp/options.xl2tpd')
db = SessionLocal()
try:
    rows = {row.key: row.value for row in db.query(Setting).filter(Setting.key.in_((
        'l2tp_mtu', 'l2tp_mru', 'l2tp_dns1', 'l2tp_dns2',
    ))).all()}
finally:
    db.close()

def bounded_int(key, default):
    try:
        value = int(str(rows.get(key, default)).strip())
    except (TypeError, ValueError):
        value = default
    return value if 576 <= value <= 1460 else default

def valid_dns(key, default):
    raw = str(rows.get(key, default) or '').strip()
    if not raw:
        return ''
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return default

mtu = bounded_int('l2tp_mtu', 1400)
mru = bounded_int('l2tp_mru', 1400)
dns_values = []
for value in (valid_dns('l2tp_dns1', '1.1.1.1'), valid_dns('l2tp_dns2', '8.8.8.8')):
    if value and value not in dns_values:
        dns_values.append(value)

text = path.read_text(encoding='utf-8', errors='replace')
text = re.sub(r'(?m)^\s*ms-dns\s+.*\n?', '', text)
text = re.sub(r'(?m)^\s*mtu\s+.*$', f'mtu {mtu}', text, count=1)
if not re.search(r'(?m)^\s*mtu\s+', text):
    text = text.rstrip() + f'\nmtu {mtu}\n'
text = re.sub(r'(?m)^\s*mru\s+.*$', f'mru {mru}', text, count=1)
if not re.search(r'(?m)^\s*mru\s+', text):
    text = text.rstrip() + f'\nmru {mru}\n'
for dns in dns_values:
    text = text.rstrip() + f'\nms-dns {dns}\n'
path.write_text(text.rstrip() + '\n', encoding='utf-8')
PYL2TPAUTHORITY
  ) || { echo "ERROR: failed to restore authoritative L2TP DNS/MTU settings" >&2; exit 1; }
fi

phase "Repairing L2TP, PPTP and SSTP compatibility"
if [ -x "$INSTALL_DIR/scripts/setup_sstp.sh" ] && [ -f /etc/accel-ppp/sstp.conf ]; then
  CURRENT_SSTP_PORT=$(awk -F= '/^port=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' /etc/accel-ppp/sstp.conf)
  CURRENT_SSTP_PORT=${CURRENT_SSTP_PORT:-4433}
  "$INSTALL_DIR/scripts/setup_sstp.sh" "--port=${CURRENT_SSTP_PORT}" || \
    echo "[!] Warning: SSTP module/config heal could not be completed" >&2
fi
if [ -x "$INSTALL_DIR/scripts/repair_classic_ppp_protocols.sh" ]; then
  "$INSTALL_DIR/scripts/repair_classic_ppp_protocols.sh" --no-restart || \
    echo "[!] Warning: L2TP/PPTP/SSTP repair could not be completed" >&2
fi

phase "Repairing OpenVPN helper access and live VPN routing"
if [ -x "$INSTALL_DIR/scripts/repair_runtime_networking.sh" ]; then
  "$INSTALL_DIR/scripts/repair_runtime_networking.sh" --apply-config || echo "[!] Warning: runtime networking repair could not be completed" >&2
  cat > /etc/systemd/system/vpn-panel-network-repair.service <<EOF
[Unit]
Description=VPN Panel runtime routing repair for all VPN pools
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${INSTALL_DIR}/scripts/repair_runtime_networking.sh --network-only
EOF
  cat > /etc/systemd/system/vpn-panel-network-repair.timer <<'EOF'
[Unit]
Description=Periodically verify VPN Panel routing

[Timer]
OnBootSec=20s
OnUnitActiveSec=5min
AccuracySec=5s
Persistent=true
Unit=vpn-panel-network-repair.service

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now vpn-panel-network-repair.timer >/dev/null 2>&1 || true
fi

phase "Stabilizing OpenVPN keepalive on existing listeners"
OPENVPN_KEEPALIVE_CHANGED=0
if [ -d /etc/openvpn/server ]; then
  while IFS= read -r -d '' conf; do
    [ -f "$conf" ] || continue
    KEEPALIVE_COUNT="$(grep -Ec '^[[:space:]]*keepalive[[:space:]]+[0-9]+[[:space:]]+[0-9]+[[:space:]]*$' "$conf" 2>/dev/null || true)"
    STABLE_COUNT="$(grep -Ec '^[[:space:]]*keepalive[[:space:]]+10[[:space:]]+60[[:space:]]*$' "$conf" 2>/dev/null || true)"
    EXPLICIT_PING_COUNT="$(grep -Ec '^[[:space:]]*(ping|ping-restart)[[:space:]]+[0-9]+' "$conf" 2>/dev/null || true)"
    if [ "$KEEPALIVE_COUNT" -ne 1 ] || [ "$STABLE_COUNT" -ne 1 ] || [ "$EXPLICIT_PING_COUNT" -ne 0 ]; then
      # ``keepalive`` expands to ping/ping-restart. Remove old explicit or
      # duplicate directives first so a later legacy line cannot silently
      # restore the two-second timeout after this migration.
      sed -i -E '/^[[:space:]]*(keepalive|ping|ping-restart)[[:space:]]+[0-9]+([[:space:]]+[0-9]+)?[[:space:]]*$/d' "$conf"
      printf '\nkeepalive 10 60\n' >> "$conf"
      OPENVPN_KEEPALIVE_CHANGED=1
      echo "    keepalive normalized: $conf"
    fi
  done < <(find /etc/openvpn/server -maxdepth 1 -type f -name 'server*.conf' -print0 2>/dev/null)
fi
if [ "$OPENVPN_KEEPALIVE_CHANGED" -eq 1 ]; then
  # A controlled restart is required for server-side keepalive directives.
  # Existing tunnels reconnect once during this update, then remain stable.
  systemctl restart openvpn-server@server-udp 2>/dev/null || true
  systemctl restart openvpn-server@server-tcp 2>/dev/null || true
  while IFS= read -r unit; do
    [ -n "$unit" ] && systemctl restart "$unit" 2>/dev/null || true
  done < <(systemctl list-unit-files 'openvpn-server@server-extra-*.service' --no-legend 2>/dev/null | awk '{print $1}')
fi

phase "Restoring authoritative DNS for every configured VPN protocol"
if [ -x "$CURRENT_PY" ]; then
  (cd "$INSTALL_DIR/backend" && "$CURRENT_PY" <<'PYALLDNSAUTHORITY'
from app.database import SessionLocal
from app.models import Setting
from app.schemas import VpnProtocolSettings
from app.services.protocol_dns import apply_protocol_dns_settings
from app.services.protocol_options import apply_protocol_options

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
ok, detail = apply_protocol_options(payload, target="all", restart_services=False)
if not ok:
    raise SystemExit(f"ALL_PROTOCOL_OPTIONS_RESTORE_FAILED: {detail}")
print(detail)
for key in ("l2tp", "pptp", "openvpn", "sstp", "ikev2", "openconnect"):
    ok, detail = apply_protocol_dns_settings(payload, key, apply_runtime=True)
    if ok:
        print(detail)
        continue
    # A protocol may be intentionally not installed on an older node. Keep the
    # update usable, but make the exact omission visible in update.log.
    if "پیدا نشد" in detail or (key == "sstp" and "libdns.so" in detail):
        print(f"DNS_AUTHORITY_WARNING protocol={key}: {detail}")
        continue
    raise SystemExit(f"DNS_AUTHORITY_FAILED protocol={key}: {detail}")
PYALLDNSAUTHORITY
  ) || { echo "ERROR: failed to restore authoritative DNS settings for all protocols" >&2; exit 1; }
fi

if [ -x "$INSTALL_DIR/scripts/audit_protocol_dns.sh" ]; then
  phase "Auditing final DNS state for all configured VPN protocols"
  "$INSTALL_DIR/scripts/audit_protocol_dns.sh" || { echo "ERROR: final protocol DNS audit failed" >&2; exit 1; }
fi

phase "Repairing OpenVPN/L2TP public ingress and host firewall"
if [ -x "$INSTALL_DIR/scripts/repair_vpn_ingress.sh" ]; then
  "$INSTALL_DIR/scripts/repair_vpn_ingress.sh" || {
    echo "[!] Warning: local VPN ingress remains incomplete; see listener/firewall details above" >&2
  }
fi

# ocserv 1.2.x does not recognise the old `no-compress` option. Remove it
# from existing installations so every worker stops emitting the warning.
if [ -f /etc/ocserv/ocserv.conf ] && grep -qE '^[[:space:]]*no-compress[[:space:]]*=' /etc/ocserv/ocserv.conf; then
  sed -i -E '/^[[:space:]]*no-compress[[:space:]]*=/d' /etc/ocserv/ocserv.conf
fi

phase "Checking Python runtime"
VENV_PY="$INSTALL_DIR/backend/venv/bin/python"
VENV_PIP="$INSTALL_DIR/backend/venv/bin/pip"
[ -x "$VENV_PY" ] || { echo "ERROR: Python virtualenv is missing" >&2; exit 1; }
vpn_panel_python_import_health() {
  "$VENV_PY" - <<'PYHEALTH' >/dev/null 2>&1
import fastapi, starlette, uvicorn, sqlalchemy, pymysql, cryptography
import jwt
from jwt.exceptions import PyJWTError
import passlib, bcrypt, multipart, pydantic, pydantic_settings
import apscheduler, psutil, dotenv, requests, qrcode, paramiko
PYHEALTH
}

if vpn_panel_python_import_health && [ "$OLD_REQ_HASH" = "$NEW_REQ_HASH" ]; then
  echo "    requirements unchanged and imports healthy; offline pip skipped."
else
  [ -x "$VENV_PIP" ] || { echo "ERROR: pip is missing from virtualenv" >&2; exit 1; }
  if [ "$WHEELHOUSE_AVAILABLE" -eq 1 ]; then
    phase "Installing verified bundled Python dependencies"
    timeout --signal=TERM --kill-after=15 240 \
      "$VENV_PIP" install --disable-pip-version-check --no-input \
      --no-index --find-links "$WHEEL_DIR" --only-binary=:all: \
      -r "$INSTALL_DIR/backend/requirements.txt"
  else
    phase "Downloading required Python dependencies"
    timeout --signal=TERM --kill-after=20 600 \
      "$VENV_PIP" install --disable-pip-version-check --no-input \
      -r "$INSTALL_DIR/backend/requirements.txt"
  fi
fi
vpn_panel_python_import_health || {
  echo "ERROR: Python dependencies are still incomplete after update dependency check" >&2
  exit 1
}
"$VENV_PIP" check
printf '%s' "$NEW_REQ_HASH" > "$INSTALL_DIR/.backend-requirements.sha256"

phase "Validating backend syntax and runtime settings"
"$VENV_PY" -m compileall -q "$INSTALL_DIR/backend/app"
(
  cd "$INSTALL_DIR/backend"
  "$VENV_PY" - <<'PYBACKENDPREFLIGHT'
from app.config import get_settings
from app.database import engine
from app.services.security_hardening import validate_runtime_security
settings = get_settings()
validate_runtime_security(settings)
with engine.connect() as connection:
    connection.exec_driver_sql("SELECT 1")
print(f"settings-ok db={settings.DB_HOST}:{settings.DB_PORT}/{settings.DB_NAME} backend_port={settings.BACKEND_PORT}")
PYBACKENDPREFLIGHT
) || { echo "ERROR: updated backend settings/database preflight failed" >&2; exit 1; }

phase "Deploying verified frontend; npm is not used"
mkdir -p "$WEB_DIR"
vpn_panel_deploy_bundled_frontend "$PROJECT_ROOT/frontend" "$WEB_DIR"
BUNDLE_HASH="$(sha256sum "$PROJECT_ROOT/frontend/dist.sha256" | awk '{print $1}')"
printf '%s' "$BUNDLE_HASH" > "$INSTALL_DIR/.frontend-bundle.sha256"

phase "Applying frontend cache policy"
# Older Nginx configs did not explicitly disable caching for index.html. A
# browser could therefore keep the old Vite entry page while the backend and
# VERSION file were already current, making newly added controls appear to be
# missing. Patch only the main panel site and restore it if nginx validation
# fails.
if [ -f "$MAIN_NGINX_SITE" ] && ! grep -q 'VPN Panel frontend cache policy v2.3.148' "$MAIN_NGINX_SITE"; then
  CACHE_POLICY_BACKUP="$BACKUP_DIR/vpn-panel.nginx.before-cache-policy"
  cp -a "$MAIN_NGINX_SITE" "$CACHE_POLICY_BACKUP"
  "$VENV_PY" - "$MAIN_NGINX_SITE" <<'PYCACHEPOLICY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
pattern = re.compile(
    r"(?P<indent>^[ \t]*)location\s+/\s*\{\s*\n"
    r"(?P=indent)[ \t]+try_files\s+\$uri\s+\$uri/\s+/index\.html;\s*\n"
    r"(?P=indent)\}",
    re.MULTILINE,
)
match = pattern.search(text)
if match:
    indent = match.group("indent")
    inner = indent + "    "
    lines = [
        indent + "# VPN Panel frontend cache policy v2.3.148",
        indent + "location = /index.html {",
        inner + 'add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0" always;',
        inner + 'add_header Pragma "no-cache" always;',
        inner + 'add_header Expires "0" always;',
        inner + "try_files /index.html =404;",
        indent + "}",
        "",
        indent + "location ^~ /assets/ {",
        inner + 'add_header Cache-Control "public, max-age=31536000, immutable" always;',
        inner + "try_files $uri =404;",
        indent + "}",
        "",
        indent + "location / {",
        inner + 'add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0" always;',
        inner + "try_files $uri $uri/ /index.html;",
        indent + "}",
    ]
    path.write_text(text[:match.start()] + "\n".join(lines) + text[match.end():], encoding="utf-8")
PYCACHEPOLICY
  if ! nginx -t; then
    cp -a "$CACHE_POLICY_BACKUP" "$MAIN_NGINX_SITE"
    nginx -t >/dev/null 2>&1 || true
    echo "[!] Nginx cache-policy patch was reverted; panel update continues." >&2
  else
    systemctl reload nginx >/dev/null 2>&1 || true
  fi
fi

# Existing installations may already contain the older cache-policy marker, so
# the block above is intentionally followed by an idempotent repair. SPA route
# responses must never be stored; only hashed /assets files are immutable.
if [ -f "$MAIN_NGINX_SITE" ]; then
  sed -i 's/add_header Cache-Control "no-cache" always;/add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0" always;/g' "$MAIN_NGINX_SITE"
  if nginx -t >/dev/null 2>&1; then
    systemctl reload nginx >/dev/null 2>&1 || true
  fi
fi

phase "Refreshing API service while preserving its listener and environment"
# The running systemd unit is the authority for the API listener. Older
# installations can have a stale BACKEND_PORT in panel.env while ExecStart
# uses a custom port (for example 18000). Preferring panel.env made the updater
# probe the wrong port, declare a healthy API dead, and roll the release back.
UNIT_FILE="$(systemctl show -p FragmentPath --value vpn-panel-api 2>/dev/null || true)"
UNIT_EXEC="$(systemctl show -p ExecStart --value vpn-panel-api 2>/dev/null || true)"
UNIT_PORT="$(printf '%s\n' "$UNIT_EXEC" | grep -oE -- '--port([=[:space:]])+[0-9]+' | grep -oE '[0-9]+' | tail -n1 || true)"
if [ -z "$UNIT_PORT" ] && [ -n "$UNIT_FILE" ] && [ -f "$UNIT_FILE" ]; then
  UNIT_PORT="$(grep -oE -- '--port([=[:space:]])+[0-9]+' "$UNIT_FILE" 2>/dev/null | grep -oE '[0-9]+' | tail -n1 || true)"
fi
ENV_PORT=""
if [ -r "$INSTALL_DIR/panel.env" ]; then
  ENV_PORT="$(sed -nE "s/^[[:space:]]*BACKEND_PORT[[:space:]]*=[[:space:]]*['\"]?([0-9]+)['\"]?[[:space:]]*$/\1/p" "$INSTALL_DIR/panel.env" | tail -n1 || true)"
fi
BACKEND_PORT="${UNIT_PORT:-${ENV_PORT:-8000}}"
echo "    API health target: 127.0.0.1:${BACKEND_PORT} (unit=${UNIT_PORT:-unset}, env=${ENV_PORT:-unset})"

# Never overwrite an existing unit during an update. Existing installations
# may rely on EnvironmentFile, User/Group, hardening, custom backend ports, or
# database credentials declared in that unit. Recreating it caused the API to
# start without its environment and made otherwise-valid updates roll back.
if [ -z "$UNIT_FILE" ] || [ ! -f "$UNIT_FILE" ]; then
  cat > /etc/systemd/system/vpn-panel-api.service <<EOF
[Unit]
Description=VPN Panel API
After=network.target mysql.service

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}/backend
EnvironmentFile=-${INSTALL_DIR}/backend/.env
EnvironmentFile=-${INSTALL_DIR}/panel.env
Environment="PATH=${INSTALL_DIR}/backend/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="RUN_BACKGROUND_JOBS=0"
ExecStart=${INSTALL_DIR}/backend/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port ${BACKEND_PORT} --workers 1
Restart=always
RestartSec=3
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
EOF
fi

# Preserve custom API units and isolate only the background workload through a
# minimal drop-in.  This keeps local auth responsive without changing custom
# ports, users, hardening or database environment.
install -d -m 0755 "$(dirname "$API_BACKGROUND_DROPIN")"
cat > "$API_BACKGROUND_DROPIN" <<'EOFAPIBG'
[Service]
Environment="RUN_BACKGROUND_JOBS=0"
EOFAPIBG

cat > "$BACKGROUND_UNIT" <<EOFBACKGROUND
[Unit]
Description=VPN Panel background scheduler and Telegram controller
After=network-online.target mysql.service vpn-panel-api.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}/backend
EnvironmentFile=-${INSTALL_DIR}/backend/.env
EnvironmentFile=-${INSTALL_DIR}/panel.env
Environment="PATH=${INSTALL_DIR}/backend/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="PYTHONPATH=${INSTALL_DIR}/backend"
ExecStart=${INSTALL_DIR}/backend/venv/bin/python -m app.background_runner
Restart=always
RestartSec=5
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOFBACKGROUND

systemctl daemon-reload
systemctl enable vpn-panel-background >/dev/null 2>&1
systemctl restart vpn-panel-api
systemctl restart vpn-panel-background
API_STOPPED=0

# Keep the Node registration helper in the same backend import context as the
# API service.  Older units started the helper from / and embedded Python then
# failed with: ModuleNotFoundError: No module named 'app'.  A drop-in avoids
# replacing customized unit files while making both fresh and upgraded Nodes
# self-register without manual intervention.
if [ -f /etc/systemd/system/vpn-panel-node-register.service ] \
   || systemctl cat vpn-panel-node-register.service >/dev/null 2>&1; then
  install -d -m 0755 /etc/systemd/system/vpn-panel-node-register.service.d
  cat > /etc/systemd/system/vpn-panel-node-register.service.d/backend-context.conf <<EOF
[Service]
WorkingDirectory=${INSTALL_DIR}/backend
Environment="PYTHONPATH=${INSTALL_DIR}/backend"
EOF
  systemctl daemon-reload
fi

phase "Waiting for API health"
HEALTH_OK=0
# Startup performs database/license migrations and may briefly reconcile Xray.
# Allow enough time on small VPSes, but fail early when systemd marks the unit
# failed. The target port above is always derived from the actual unit first.
for _ in $(seq 1 90); do
  if curl -fsS --connect-timeout 1 --max-time 2 "http://127.0.0.1:${BACKEND_PORT}/api/health" >/dev/null 2>&1; then
    HEALTH_OK=1
    break
  fi
  if systemctl is-failed --quiet vpn-panel-api; then
    break
  fi
  sleep 1
done
[ "$HEALTH_OK" -eq 1 ] || {
  echo "ERROR: updated API did not become healthy on 127.0.0.1:${BACKEND_PORT}; journal follows" >&2
  echo "Resolved systemd ExecStart: ${UNIT_EXEC:-unknown}" >&2
  systemctl status vpn-panel-api --no-pager -l >&2 || true
  journalctl -u vpn-panel-api -n 120 --no-pager >&2 || true
  exit 1
}
if ! systemctl is-active --quiet vpn-panel-background; then
  echo "ERROR: dedicated background service did not become active" >&2
  systemctl status vpn-panel-background --no-pager -l >&2 || true
  journalctl -u vpn-panel-background -n 120 --no-pager >&2 || true
  exit 1
fi
phase "API healthy; background jobs isolated from authentication worker"

# Recreate active OpenVPN fallback listeners from the durable database after the
# API restart. A transient inactive unit must never be interpreted as an admin
# request to switch that port off; the DB flags remain unchanged even when one
# listener cannot be restored and the exact runtime warning is kept in update.log.
phase "Restoring active OpenVPN extra ports"
(
  cd "$INSTALL_DIR/backend"
  "$VENV_PY" - <<'PYOPENVPNEXTRAS'
from app.database import SessionLocal
from app.models import OpenvpnExtraPort, Setting
from app.services.vpn_manager import sync_openvpn_extra_ports

def setting_int(db, key, default):
    row = db.query(Setting).filter(Setting.key == key).first()
    try:
        return int(row.value) if row and row.value not in (None, "") else default
    except (TypeError, ValueError):
        return default

db = SessionLocal()
try:
    rows = (
        db.query(OpenvpnExtraPort)
        .filter(OpenvpnExtraPort.is_active == True)  # noqa: E712
        .order_by(OpenvpnExtraPort.port, OpenvpnExtraPort.protocol)
        .all()
    )
    if not rows:
        print("    no active extra ports")
    else:
        ports = [(int(row.port), str(row.protocol)) for row in rows]
        ok, log = sync_openvpn_extra_ports(
            ports,
            setting_int(db, "openvpn_udp_port", 1194),
            setting_int(db, "openvpn_tcp_port", 1194),
        )
        print(log[-4000:])
        if not ok:
            raise RuntimeError("one or more active OpenVPN extra listeners could not be restored")
finally:
    db.close()
PYOPENVPNEXTRAS
) || echo "[!] Warning: active OpenVPN extra-port flags were preserved, but one or more listeners need attention; see the lines above." >&2

phase "Reloading Nginx"
NGINX_CHANGED=0
for site in \
  /etc/nginx/sites-available/vpn-panel \
  /etc/nginx/sites-available/vpn-panel-sub \
  /etc/nginx/sites-available/vpn-panel-xray-sub; do
  [ -f "$site" ] || continue
  if [ "$site" = "/etc/nginx/sites-available/vpn-panel" ]; then
    sed -i -E "s#proxy_pass http://127\.0\.0\.1:[0-9]+/api/#proxy_pass http://127.0.0.1:${BACKEND_PORT}/api/#g" "$site"
    sed -i -E "s#proxy_pass http://127\.0\.0\.1:[0-9]+/api/backup/update/status;#proxy_pass http://127.0.0.1:${BACKEND_PORT}/api/backup/update/status;#g" "$site"
    # Nginx defaults to a 1 MB request body, while branding images allow up to
    # 10 MB. Repair existing vhosts in-place so uploads do not fail with 413.
    if grep -q 'client_max_body_size' "$site"; then
      sed -i -E 's/client_max_body_size[[:space:]]+[^;]+;/client_max_body_size 256m;/g' "$site"
    else
      sed -i '/location \/api\/ {/a\        client_max_body_size 256m;' "$site"
    fi
    if grep -q 'client_body_timeout' "$site"; then
      sed -i -E 's/client_body_timeout[[:space:]]+[^;]+;/client_body_timeout 120s;/g' "$site"
    else
      sed -i '/location \/api\/ {/a\        client_body_timeout 120s;' "$site"
    fi
  fi
  # Preserve the incoming custom port. `$host` drops it; `$http_host` keeps it.
  sed -i 's/proxy_set_header Host $host;/proxy_set_header Host $http_host;/g' "$site"
  if ! grep -q 'proxy_set_header X-Forwarded-Host' "$site"; then
    sed -i '/proxy_set_header Host $http_host;/a\        proxy_set_header X-Forwarded-Host $http_host;\n        proxy_set_header X-Forwarded-Port $server_port;' "$site"
  fi
  # Preserve Cloudflare's original visitor-IP headers. The backend only trusts
  # them when X-Real-IP belongs to Cloudflare's published proxy ranges.
  if ! grep -q 'proxy_set_header CF-Connecting-IP' "$site"; then
    sed -i '/proxy_set_header X-Real-IP/a\        proxy_set_header CF-Connecting-IP $http_cf_connecting_ip;\n        proxy_set_header True-Client-IP $http_true_client_ip;' "$site"
  fi
  NGINX_CHANGED=1
done
if [ "$NGINX_CHANGED" -eq 1 ]; then
  nginx -t
  systemctl reload nginx 2>/dev/null || systemctl restart nginx
fi

phase "Repairing and verifying panel web access"
[ -x "$INSTALL_DIR/scripts/repair_panel_access.sh" ] || {
  echo "ERROR: panel access repair helper is missing" >&2
  exit 1
}
PUBLIC_IP=""
for _url in "https://ifconfig.me" "https://icanhazip.com" "https://api.ipify.org"; do
  _candidate=$(curl -fsS -4 --connect-timeout 3 --max-time 5 "$_url" 2>/dev/null | tr -d '[:space:]' || true)
  if [[ "$_candidate" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]]; then
    PUBLIC_IP="$_candidate"
    break
  fi
done
[ -z "$PUBLIC_IP" ] && PUBLIC_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
ACTUAL_PANEL_PORT=$("$INSTALL_DIR/scripts/repair_panel_access.sh" "$PUBLIC_IP" "" "$BACKEND_PORT" | tail -n1)
[[ "$ACTUAL_PANEL_PORT" =~ ^[0-9]+$ ]] || {
  echo "ERROR: panel access helper did not return a valid public port" >&2
  exit 1
}
VERIFIED_PANEL_URL=$(awk -F= '/^[[:space:]]*PANEL_URL[[:space:]]*=/{v=$0; sub(/^[^=]*=/,"",v); print v}' /var/lib/vpn-panel/install-result.env 2>/dev/null | tail -n1 || true)
echo "    Verified panel URL: ${VERIFIED_PANEL_URL:-http://${PUBLIC_IP}:${ACTUAL_PANEL_PORT}}"

phase "Repairing the advertised Node endpoint"
if [ -x "$INSTALL_DIR/scripts/repair_node_public_access.sh" ]; then
  if ! "$INSTALL_DIR/scripts/repair_node_public_access.sh"; then
    echo "[!] Warning: the local panel update succeeded, but the advertised Node URL is not healthy yet." >&2
    echo "    The node registration timer will retry SSL/public access automatically." >&2
  fi
fi

# Retry only after the API, Nginx and advertised Node endpoint have been
# repaired. This prevents a harmless early failure during the API restart and
# gives a pending fresh Node the best chance to appear immediately.
if [ -r /var/lib/vpn-panel/node-registration.env ] \
   && [ ! -s /var/lib/vpn-panel/node-registration.ok ] \
   && systemctl cat vpn-panel-node-register.service >/dev/null 2>&1; then
  phase "Retrying pending Node registration"
  systemctl enable --now vpn-panel-node-register.timer >/dev/null 2>&1 || true
  if ! systemctl restart vpn-panel-node-register.service; then
    echo "[!] Node registration is still pending; the timer will retry automatically." >&2
  fi
fi

SERVER_ROLE_VALUE=$(awk -F= '/^[[:space:]]*SERVER_ROLE[[:space:]]*=/{v=$0; sub(/^[^=]*=/,"",v); gsub(/[[:space:]"\047]/,"",v); print tolower(v)}' "$INSTALL_DIR/panel.env" 2>/dev/null | tail -n1 || true)
if [ "${SERVER_ROLE_VALUE:-main}" = "main" ]; then
  phase "Preparing one canonical OpenVPN PKI and synchronizing every node"
  "$INSTALL_DIR/scripts/ensure_openvpn_controller_pki.sh" --prepare-only
  (
    cd "$INSTALL_DIR/backend"
    "$VENV_PY" - <<'PYOPENVPNMULTINODE'
from app.database import SessionLocal
from app.models import VpnUser
from app.services.cert_manager import (
    ensure_controller_openvpn_pki,
    pki_bundle_fingerprint,
    repair_or_generate_client_cert,
)
from app.services.node_manager import sync_all_nodes

db = SessionLocal()
try:
    bundle = ensure_controller_openvpn_pki(db)
    print("    Shared OpenVPN fingerprint:", pki_bundle_fingerprint(bundle))
    repaired = 0
    failed = []
    for user in db.query(VpnUser).filter(VpnUser.enable_openvpn == True).order_by(VpnUser.id).all():  # noqa: E712
        try:
            _pair, status = repair_or_generate_client_cert(user.username)
            if status != "existing":
                repaired += 1
                print(f"    OpenVPN user material {status}: {user.username}")
        except Exception as exc:
            failed.append(f"{user.username}: {exc}")
    print(f"    OpenVPN user certificate repair complete: repaired={repaired} failed={len(failed)}")
    for item in failed[:10]:
        # The currently installed updater may still be an older build that
        # truncates progress output by raw bytes. Keep this migration warning
        # ASCII-safe so upgrading from that build cannot split a Persian UTF-8
        # sequence and crash its progress JSON writer.
        safe_item = item.encode("ascii", "backslashreplace").decode("ascii")
        print("    WARNING:", safe_item)
finally:
    db.close()
# Wait for every enabled node to import/reload the exact bundle before this
# update is reported complete. Synchronization itself is concurrent.
sync_all_nodes()
PYOPENVPNMULTINODE
  ) || {
    echo "ERROR: shared OpenVPN PKI preparation/synchronization failed" >&2
    exit 1
  }
fi

phase "Recording version"
if [ -f "$PROJECT_ROOT/VERSION" ]; then
  cp -a "$PROJECT_ROOT/VERSION" "$INSTALL_DIR/VERSION"
  sed -i 's/[[:space:]]*$//' "$INSTALL_DIR/VERSION"
fi

# Atomically publish the staged update runner. This is intentionally the final
# filesystem change so the currently executing old runner can finish normally.
if [ -f "$INSTALL_DIR/scripts/update_from_license.sh.next" ]; then
  mv -f "$INSTALL_DIR/scripts/update_from_license.sh.next" "$INSTALL_DIR/scripts/update_from_license.sh"
  chmod +x "$INSTALL_DIR/scripts/update_from_license.sh"
fi

# Keep a complete, verified release bundle on the controller so the Nodes page
# can install this exact version on a fresh VPS over SSH without needing an
# external download URL. The archive lives outside PROJECT_ROOT to avoid
# recursive inclusion and is replaced atomically after a successful update.
phase "Preparing reusable node installation bundle"
tar --exclude='./frontend/node_modules' --exclude='./backend/venv' --exclude='*.pyc' --exclude='__pycache__'   -czf "$INSTALL_DIR/release-source.tar.gz.tmp" -C "$PROJECT_ROOT" .
mv -f "$INSTALL_DIR/release-source.tar.gz.tmp" "$INSTALL_DIR/release-source.tar.gz"
chmod 0600 "$INSTALL_DIR/release-source.tar.gz"

# Update an already-installed Telegram bot from this release's nested bot/
# directory. The helper is non-interactive and owns its code/service rollback;
# its persistent .env, var/, backups/ and dedicated venv are excluded from sync.
if [ -f "$PROJECT_ROOT/bot/pyproject.toml" ] && \
  [ "$(systemctl show -p LoadState --value vpn-manager-bot 2>/dev/null || true)" = "loaded" ]; then
  phase "Updating the independent Telegram bot service"
  BOT_SOURCE_DIR="$PROJECT_ROOT/bot" APP_DIR="/opt/vpn-control-center" SERVICE_USER="vpnmanager" \
    bash "$PROJECT_ROOT/bot/update-local.sh"
fi

UPDATE_OK=1
phase "Update complete; enabled VPN ingress was verified and repaired"
echo "[*] Safe update completed successfully."
