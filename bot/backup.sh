#!/usr/bin/env bash
set -Eeuo pipefail
APP_DIR="${APP_DIR:-/opt/vpn-control-center}"
DEST="${1:-${APP_DIR}/backups}"
SERVICE_NAME="${SERVICE_NAME:-vpn-manager-bot}"
install -d -m 0700 "${DEST}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
WAS_ACTIVE=0
if systemctl is-active --quiet "${SERVICE_NAME}"; then WAS_ACTIVE=1; systemctl stop "${SERVICE_NAME}"; fi
restart_service() { [[ "${WAS_ACTIVE}" == 1 ]] && systemctl start "${SERVICE_NAME}" || true; }
trap restart_service EXIT
backup_paths=(.env var)
for database_file in vpn_manager.db vpn_manager.db-wal vpn_manager.db-shm; do
  [[ -f "${APP_DIR}/${database_file}" ]] && backup_paths+=("${database_file}")
done
tar --exclude='.venv' --exclude='__pycache__' -czf "${DEST}/vpn-manager-${STAMP}.tar.gz" -C "${APP_DIR}" "${backup_paths[@]}"
chmod 0600 "${DEST}/vpn-manager-${STAMP}.tar.gz"
chown "$(stat -c '%U:%G' "${APP_DIR}/.env" 2>/dev/null || echo root:root)" "${DEST}/vpn-manager-${STAMP}.tar.gz" 2>/dev/null || true
echo "Backup created: ${DEST}/vpn-manager-${STAMP}.tar.gz"

