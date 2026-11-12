#!/usr/bin/env bash
set -Eeuo pipefail
APP_DIR="${APP_DIR:-/opt/vpn-control-center}"
systemctl stop vpn-manager-api
"${APP_DIR}/.venv/bin/pip" install --upgrade "${APP_DIR}"
cd "${APP_DIR}"
"${APP_DIR}/.venv/bin/alembic" upgrade head
systemctl start vpn-manager-api
systemctl is-active --quiet vpn-manager-api
curl --fail --silent http://127.0.0.1:8080/health/live

