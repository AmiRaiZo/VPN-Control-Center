#!/usr/bin/env bash
set -Eeuo pipefail
APP_DIR="${APP_DIR:-/opt/vpn-control-center}"
SERVICE_NAME="${SERVICE_NAME:-vpn-manager-bot}"
ARCHIVE="${1:?Usage: sudo bash restore.sh /path/to/backup.tar.gz}"
[[ -f "${ARCHIVE}" ]] || { echo "Backup not found" >&2; exit 1; }
tar -tzf "${ARCHIVE}" | grep -Eq '(^|/)\.env$' || { echo "Archive does not contain .env" >&2; exit 1; }
systemctl stop "${SERVICE_NAME}"
tar -xzf "${ARCHIVE}" -C "${APP_DIR}"
chmod 0600 "${APP_DIR}/.env"
chown "${SERVICE_USER:-vpnmanager}:${SERVICE_USER:-vpnmanager}" "${APP_DIR}/.env"
chown -R "${SERVICE_USER:-vpnmanager}:${SERVICE_USER:-vpnmanager}" "${APP_DIR}/var"
for database_file in vpn_manager.db vpn_manager.db-wal vpn_manager.db-shm; do
  [[ -f "${APP_DIR}/${database_file}" ]] && chown "${SERVICE_USER:-vpnmanager}:${SERVICE_USER:-vpnmanager}" "${APP_DIR}/${database_file}"
done
systemctl start "${SERVICE_NAME}"
systemctl is-active --quiet "${SERVICE_NAME}"

