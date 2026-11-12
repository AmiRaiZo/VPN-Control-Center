#!/usr/bin/env bash
set -Eeuo pipefail
APP_DIR="${APP_DIR:-/opt/vpn-control-center}"
ARCHIVE="${1:?Usage: sudo bash restore.sh /path/to/backup.tar.gz}"
[[ -f "${ARCHIVE}" ]] || { echo "Backup not found" >&2; exit 1; }
tar -tzf "${ARCHIVE}" | grep -Eq '(^|/)\.env$' || { echo "Archive does not contain .env" >&2; exit 1; }
systemctl stop vpn-manager-api
tar -xzf "${ARCHIVE}" -C "${APP_DIR}"
chmod 0600 "${APP_DIR}/.env"
systemctl start vpn-manager-api

