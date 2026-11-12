#!/usr/bin/env bash
set -Eeuo pipefail
APP_DIR="${APP_DIR:-/opt/vpn-control-center}"
DEST="${1:-${APP_DIR}/backups}"
install -d -m 0700 "${DEST}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
tar --exclude='.venv' --exclude='__pycache__' -czf "${DEST}/vpn-manager-${STAMP}.tar.gz" -C "${APP_DIR}" .env var
chmod 0600 "${DEST}/vpn-manager-${STAMP}.tar.gz"
echo "Backup created: ${DEST}/vpn-manager-${STAMP}.tar.gz"

