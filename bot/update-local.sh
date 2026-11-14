#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="${APP_DIR:-/opt/vpn-control-center}"
SERVICE_USER="${SERVICE_USER:-vpnmanager}"
SERVICE_NAME="vpn-manager-bot"
SOURCE_DIR="${BOT_SOURCE_DIR:-}"
PYTHON="${APP_DIR}/.venv/bin/python"
UNIT_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

[[ "${EUID}" -eq 0 ]] || { echo "Run as root." >&2; exit 1; }
[[ -n "${SOURCE_DIR}" && -f "${SOURCE_DIR}/pyproject.toml" && -f "${SOURCE_DIR}/alembic.ini" && -f "${SOURCE_DIR}/systemd/vpn-manager-bot.service.in" ]] || {
  echo "BOT_SOURCE_DIR must point to the nested bot/ source directory." >&2; exit 1;
}
[[ "$(systemctl show -p LoadState --value "${SERVICE_NAME}" 2>/dev/null || true)" == loaded ]] || {
  echo "Bot service is not installed; skipping bot update."; exit 0;
}
[[ -x "${PYTHON}" ]] || { echo "Bot virtualenv is missing: ${PYTHON}" >&2; exit 1; }
"${PYTHON}" -c 'import sys; raise SystemExit(0 if (3, 12) <= sys.version_info[:2] < (3, 15) else 1)' || {
  echo "Bot virtualenv must use Python >=3.12,<3.15." >&2; exit 1;
}
[[ -f "${APP_DIR}/.env" && -d "${APP_DIR}/var" ]] || {
  echo "Bot .env or var/ data directory is missing; refusing update." >&2; exit 1;
}
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0700 "${APP_DIR}/backups"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP_DIR="${APP_DIR}/backups/panel-update-${STAMP}"
mkdir -m 0700 -p "${BACKUP_DIR}"
CODE_BACKUP="${BACKUP_DIR}/source.tar.gz"
tar --exclude='./.env' --exclude='./var' --exclude='./backups' --exclude='./.venv' \
  --exclude='./vpn_manager.db' --exclude='./vpn_manager.db-wal' --exclude='./vpn_manager.db-shm' \
  -czf "${CODE_BACKUP}" -C "${APP_DIR}" .
chmod 0600 "${CODE_BACKUP}"
UNIT_EXISTED=0
if [[ -f "${UNIT_FILE}" ]]; then cp -a "${UNIT_FILE}" "${BACKUP_DIR}/vpn-manager-bot.service"; UNIT_EXISTED=1; fi
printf '%s\n' "${UNIT_EXISTED}" > "${BACKUP_DIR}/unit.existed"

bash "${APP_DIR}/backup.sh" "${APP_DIR}/backups"
systemctl stop "${SERVICE_NAME}"
systemctl is-active --quiet "${SERVICE_NAME}" && { echo "Bot did not stop cleanly." >&2; exit 1; } || true

rollback() {
  local rc=$?
  trap - ERR
  echo "Bot update failed; restoring previous code and service unit." >&2
  local restore_dir
  restore_dir="$(mktemp -d)"
  tar -xzf "${CODE_BACKUP}" -C "${restore_dir}"
  rsync -a --delete --exclude='.env' --exclude='var/' --exclude='backups/' --exclude='.venv/' --exclude='.release-tag' \
    --exclude='vpn_manager.db' --exclude='vpn_manager.db-wal' --exclude='vpn_manager.db-shm' \
    "${restore_dir}/" "${APP_DIR}/"
  rm -rf "${restore_dir}"
  if [[ "${UNIT_EXISTED}" == 1 ]]; then cp -a "${BACKUP_DIR}/vpn-manager-bot.service" "${UNIT_FILE}"; else rm -f "${UNIT_FILE}"; fi
  chown -R "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}"
  systemctl daemon-reload
  systemctl start "${SERVICE_NAME}" || true
  echo "Persistent .env, var/, backups/ and virtualenv were left in place. Recovery snapshot: ${BACKUP_DIR}" >&2
  exit "${rc}"
}
trap rollback ERR

rsync -a --delete --exclude='.env' --exclude='var/' --exclude='backups/' --exclude='.venv/' --exclude='.release-tag' \
  --exclude='vpn_manager.db' --exclude='vpn_manager.db-wal' --exclude='vpn_manager.db-shm' \
  "${SOURCE_DIR}/" "${APP_DIR}/"
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0750 "${APP_DIR}/var"
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0700 "${APP_DIR}/backups"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}"
chmod 0600 "${APP_DIR}/.env"
chmod 0755 "${APP_DIR}/vpn-help.sh" "${APP_DIR}/backup.sh" "${APP_DIR}/restore.sh"
runuser -u "${SERVICE_USER}" -- "${PYTHON}" -m pip install --disable-pip-version-check --no-input "${APP_DIR}"
runuser -u "${SERVICE_USER}" -- bash -c "cd '${APP_DIR}' && '${PYTHON}' -m alembic upgrade head"
sed -e "s|@SERVICE_USER@|${SERVICE_USER}|g" -e "s|@APP_DIR@|${APP_DIR}|g" \
  "${SOURCE_DIR}/systemd/vpn-manager-bot.service.in" > "${UNIT_FILE}"
systemctl daemon-reload
systemctl start "${SERVICE_NAME}"
systemctl is-active --quiet "${SERVICE_NAME}"
trap - ERR
echo "Bot updated successfully. Persistent data retained; recovery snapshot: ${BACKUP_DIR}"
