#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="${APP_DIR:-/opt/vpn-control-center}"
SERVICE_USER="${SERVICE_USER:-vpnmanager}"
SERVICE_NAME="vpn-manager-bot"
REPOSITORY="${REPOSITORY:-AmiRaiZo/VPN-Control-Center}"
ENV_FILE="${APP_DIR}/.env"
PYTHON="${APP_DIR}/.venv/bin/python"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then echo "Run this command with sudo." >&2; exit 1; fi
}

pause_menu() { echo; read -r -p "Press Enter to return to the menu..." _ || true; }

service_load_state() {
  systemctl show -p LoadState --value "${SERVICE_NAME}" 2>/dev/null || true
}

secure_env_file() {
  [[ -f "${ENV_FILE}" ]] || { echo "Configuration file not found: ${ENV_FILE}" >&2; return 1; }
  chown "${SERVICE_USER}:${SERVICE_USER}" "${ENV_FILE}" || {
    echo "Failed to set configuration file ownership." >&2
    return 1
  }
  chmod 0600 "${ENV_FILE}" || {
    echo "Failed to set configuration file permissions." >&2
    return 1
  }
}

restart_bot() {
  local load_state
  load_state="$(service_load_state)"
  if [[ "${load_state}" != "loaded" ]]; then
    echo "The systemd service is not installed yet. Settings were saved, but the bot is not running." >&2
    echo "Complete installation by running the official install command again." >&2
    return 1
  fi
  if ! systemctl restart "${SERVICE_NAME}"; then
    echo "The bot service could not be restarted. Check: journalctl -u ${SERVICE_NAME} -n 100 --no-pager" >&2
    return 1
  fi
  if ! systemctl is-active --quiet "${SERVICE_NAME}"; then
    echo "The bot service is not active after restart. Check: journalctl -u ${SERVICE_NAME} -n 100 --no-pager" >&2
    return 1
  fi
}

change_owner() {
  local current new_id confirm
  current="$(sed -n 's/^ADMIN_TELEGRAM_IDS=//p' "${ENV_FILE}" | head -n1)"
  echo "Current Super Admin ID: ${current:-NOT SET}"
  read -r -p "New Super Admin Telegram numeric ID: " new_id || { echo "Input cancelled." >&2; return 1; }
  if [[ ! "${new_id}" =~ ^[1-9][0-9]{4,19}$ ]]; then echo "Invalid Telegram ID." >&2; return 1; fi
  read -r -p "Confirm the new ID: " confirm || { echo "Input cancelled." >&2; return 1; }
  [[ "${confirm}" == "${new_id}" ]] || { echo "The confirmation did not match." >&2; return 1; }
  if ! printf '%s\n' "${new_id}" | VPN_MANAGER_ENV_FILE="${ENV_FILE}" "${PYTHON}" -m vpn_manager.setup_bot --set-admin-id; then
    echo "Failed to save the Super Admin ID. No success was reported." >&2
    return 1
  fi
  secure_env_file || return 1
  restart_bot || return 1
  echo "Super Admin ID updated and the bot service is active."
}

change_token() {
  local token
  printf '%s' "New Telegram bot token (visible input): "
  read -r token || { echo "Input cancelled." >&2; return 1; }
  echo
  [[ -n "${token}" ]] || { echo "The bot token cannot be empty." >&2; return 1; }
  if ! printf '%s\n' "${token}" | VPN_MANAGER_ENV_FILE="${ENV_FILE}" "${PYTHON}" -m vpn_manager.setup_bot --set-token; then
    unset token
    echo "Token verification or saving failed. The existing configuration was not changed." >&2
    return 1
  fi
  unset token
  secure_env_file || return 1
  restart_bot || return 1
  echo "Telegram bot token updated and the bot service is active."
}

update_panel() {
  local latest tag staging archive backup stamp rollback_dir current_tag newest
  echo "Checking the latest GitHub Release from ${REPOSITORY} ..."
  latest="$(curl --fail --location --silent --show-error \
    -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' \
    "https://api.github.com/repos/${REPOSITORY}/releases/latest")"
  tag="$(printf '%s' "${latest}" | jq -r '.tag_name // empty')"
  if [[ ! "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "The latest Release does not have a valid X.Y.Z version tag; update aborted."; return 1
  fi
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  current_tag="$(cat "${APP_DIR}/.release-tag" 2>/dev/null || true)"
  if [[ "${current_tag}" == "${tag}" ]]; then
    echo "The latest version (${tag}) is already installed."; return 0
  fi
  if [[ "${current_tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    newest="$(printf '%s\n%s\n' "${current_tag#v}" "${tag#v}" | sort -V | tail -n1)"
    if [[ "${newest}" == "${current_tag#v}" ]]; then
      echo "The installed version (${current_tag}) is newer than the latest Release (${tag}); downgrade was skipped."
      return 0
    fi
  fi
  archive="$(mktemp)"
  staging="$(mktemp -d)"
  backup="${APP_DIR}/backups/source-${stamp}.tar.gz"
  mkdir -p "${APP_DIR}/backups"
  bash "${APP_DIR}/backup.sh" "${APP_DIR}/backups"
  tar --exclude='.venv' --exclude='var' --exclude='backups' --exclude='.env' \
    -czf "${backup}" -C "${APP_DIR}" .
  chmod 0600 "${backup}"
  curl --fail --location --silent --show-error \
    "https://github.com/${REPOSITORY}/archive/refs/tags/${tag}.tar.gz" -o "${archive}"
  tar -xzf "${archive}" --strip-components=1 -C "${staging}"
  [[ -f "${staging}/pyproject.toml" && -f "${staging}/alembic.ini" ]] || {
    echo "The Release archive is incomplete; no update was installed."; rm -rf "${staging}" "${archive}"; return 1;
  }
  if [[ "$(service_load_state)" != "loaded" ]]; then
    echo "The systemd service is not installed. Complete installation before using the update action." >&2
    rm -rf "${staging}" "${archive}"
    return 1
  fi
  systemctl stop "${SERVICE_NAME}"
  rollback_dir="$(mktemp -d)"
  rollback_update() {
    echo "The update failed; restoring the previous application source ..."
    tar -xzf "${backup}" -C "${rollback_dir}"
    rsync -a --delete --exclude='.env' --exclude='var/' --exclude='.venv/' \
      --exclude='backups/' "${rollback_dir}/" "${APP_DIR}/"
    chown -R "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}"
    runuser -u "${SERVICE_USER}" -- "${PYTHON}" -m pip install --disable-pip-version-check --upgrade "${APP_DIR}" || true
    systemctl start "${SERVICE_NAME}" || true
    rm -rf "${staging}" "${archive}" "${rollback_dir}"
    echo "The previous source was restored. Source/data backup: ${backup}"
  }
  if ! rsync -a --delete --exclude='.env' --exclude='var/' --exclude='.venv/' \
    --exclude='backups/' "${staging}/" "${APP_DIR}/"; then
    rollback_update; return 1
  fi
  chmod 0755 "${APP_DIR}/vpn-help.sh"
  chown -R "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}"
  if ! runuser -u "${SERVICE_USER}" -- "${PYTHON}" -m pip install --disable-pip-version-check --upgrade "${APP_DIR}" \
    || ! runuser -u "${SERVICE_USER}" -- bash -c "cd '${APP_DIR}' && '${PYTHON}' -m alembic upgrade head"; then
    rollback_update; return 1
  fi
  printf '%s\n' "${tag}" > "${APP_DIR}/.release-tag"
  chown "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}/.release-tag"
  if ! systemctl start "${SERVICE_NAME}" || ! systemctl is-active --quiet "${SERVICE_NAME}"; then
    rollback_update; return 1
  fi
  rm -rf "${staging}" "${archive}" "${rollback_dir}"
  echo "Update to ${tag} completed. Data and source backups are stored in ${APP_DIR}/backups."
}

uninstall_all() {
  echo "WARNING: This removes the service, configuration, database, application files, and local backups."
  read -r -p "Type REMOVE exactly to confirm full removal: " confirm || { echo "Input cancelled."; return 1; }
  [[ "${confirm}" == "REMOVE" ]] || { echo "Removal cancelled."; return 0; }
  systemctl disable --now "${SERVICE_NAME}" 2>/dev/null || true
  rm -f "/etc/systemd/system/${SERVICE_NAME}.service" /usr/local/bin/vpn-help
  systemctl daemon-reload
  rm -rf "${APP_DIR}" /var/backups/vpn-control-center
  if id "${SERVICE_USER}" >/dev/null 2>&1; then userdel "${SERVICE_USER}" 2>/dev/null || true; fi
  getent group "${SERVICE_USER}" >/dev/null 2>&1 && groupdel "${SERVICE_USER}" 2>/dev/null || true
  echo "VPN Control Center and its local data have been removed."
}

add_subordinate_admin() {
  local telegram_id role
  read -r -p "New administrator Telegram numeric ID: " telegram_id || { echo "Input cancelled." >&2; return 1; }
  [[ "${telegram_id}" =~ ^[1-9][0-9]{4,19}$ ]] || { echo "Invalid Telegram ID." >&2; return 1; }
  echo "Select a role: 1) Operations admin  2) Finance  3) Support"
  read -r -p "Role: " role || { echo "Input cancelled." >&2; return 1; }
  case "${role}" in
    1) role="admin" ;;
    2) role="finance" ;;
    3) role="support" ;;
    *) echo "Invalid role." >&2; return 1 ;;
  esac
  if ! runuser -u "${SERVICE_USER}" -- bash -c \
    "cd '${APP_DIR}' && '${PYTHON}' -m vpn_manager.admin_cli add-admin --telegram-id '${telegram_id}' --role '${role}'"; then
    echo "Failed to add the administrator. Check the bot configuration and database." >&2
    return 1
  fi
  echo "Administrator added. Manage detailed permissions in Telegram: Admin Panel > Bot Administrators."
}

main() {
  require_root
  [[ -x "${PYTHON}" && -f "${ENV_FILE}" ]] || { echo "A valid installation was not found in ${APP_DIR}." >&2; exit 1; }
  while true; do
    clear || true
    echo "====================================="
    echo "       VPN Control Center Help"
    echo "====================================="
    if [[ "$(service_load_state)" == "loaded" ]]; then
      if systemctl is-active --quiet "${SERVICE_NAME}"; then
        echo "Bot service status: ACTIVE"
      else
        echo "Bot service status: INSTALLED, NOT ACTIVE"
      fi
    else
      echo "Bot service status: NOT INSTALLED (installation is incomplete)"
    fi
    echo
    echo "1) Change Super Admin Telegram ID"
    echo "2) Add a subordinate administrator"
    echo "3) Change Telegram bot token"
    echo "4) Check and install the latest panel Release"
    echo "5) Uninstall the application and all local data"
    echo "0) Exit"
    echo
    read -r -p "Select an option: " choice || break
    case "${choice}" in
      1) change_owner || true; pause_menu ;;
      2) add_subordinate_admin || true; pause_menu ;;
      3) change_token || true; pause_menu ;;
      4) update_panel || true; pause_menu ;;
      5) uninstall_all; break ;;
      0) break ;;
      *) echo "Invalid option."; pause_menu ;;
    esac
  done
}

main "$@"
