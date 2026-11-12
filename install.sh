#!/usr/bin/env bash
set -Eeuo pipefail

REPOSITORY="${REPOSITORY:-AmiRaiZo/VPN-Control-Center}"
BRANCH="${BRANCH:-main}"
APP_DIR="${APP_DIR:-/opt/vpn-control-center}"
SERVICE_USER="${SERVICE_USER:-vpnmanager}"
PYTHON_BIN="${PYTHON_BIN:-python3}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this installer as root: curl -fsSL https://raw.githubusercontent.com/${REPOSITORY}/${BRANCH}/install.sh | sudo bash" >&2
  exit 1
fi
if [[ ! -r /dev/tty || ! -w /dev/tty ]]; then
  echo "An interactive terminal is required to enter the Telegram bot token and admin ID." >&2
  exit 1
fi

on_install_interrupt() {
  unset bot_token admin_ids
  echo >&2
  echo "Installation interrupted; no Telegram credentials were saved by this step." >&2
  exit 130
}
trap on_install_interrupt INT
trap 'unset bot_token admin_ids; exit 143' TERM

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl jq rsync tar gzip python3 python3-venv python3-pip

if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  echo "${PYTHON_BIN} was not found after installing Ubuntu's Python runtime packages." >&2
  exit 1
fi
PYTHON_BIN="$(command -v "${PYTHON_BIN}")"
if ! "${PYTHON_BIN}" -c 'import sys; raise SystemExit(0 if (3, 12) <= sys.version_info[:2] < (3, 15) else 1)'; then
  python_version="$("${PYTHON_BIN}" -c 'import platform; print(platform.python_version())')"
  echo "Python ${python_version} is not supported. This release requires Python >=3.12 and <3.15." >&2
  echo "Install a supported Python runtime or set PYTHON_BIN to its executable and rerun." >&2
  exit 1
fi
echo "Using Python $("${PYTHON_BIN}" --version 2>&1) (${PYTHON_BIN})."

install -d -m 0755 "${APP_DIR}"
archive="$(mktemp)"
staging="$(mktemp -d)"
trap 'rm -f "${archive}"; rm -rf "${staging}"' EXIT
release_json="$(curl --fail --location --silent --show-error \
  -H 'Accept: application/vnd.github+json' \
  "https://api.github.com/repos/${REPOSITORY}/releases/latest")"
release_tag="$(printf '%s' "${release_json}" | jq -r '.tag_name // empty')"
if [[ ! "${release_tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "GitHub latest Release tag is missing or invalid; refusing an unpinned install." >&2
  exit 1
fi
curl --fail --location --silent --show-error \
  "https://github.com/${REPOSITORY}/archive/refs/tags/${release_tag}.tar.gz" \
  --output "${archive}"
tar -xzf "${archive}" --strip-components=1 -C "${staging}"
if [[ ! -f "${staging}/pyproject.toml" || ! -f "${staging}/.env.example" ]]; then
  echo "The downloaded repository is incomplete; refusing to continue." >&2
  exit 1
fi
# Refresh source even after an interrupted prior install. Preserve local secrets,
# persistent data, the existing venv, and backups while replacing release files.
rsync -a --exclude='.env' --exclude='var/' --exclude='.venv/' --exclude='backups/' \
  "${staging}/" "${APP_DIR}/"
printf '%s\n' "${release_tag}" > "${APP_DIR}/.release-tag"

if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
  useradd --system --home "${APP_DIR}" --shell /usr/sbin/nologin "${SERVICE_USER}"
fi
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0750 "${APP_DIR}/var"
if [[ ! -f "${APP_DIR}/.env" ]]; then
  install -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0600 "${APP_DIR}/.env.example" "${APP_DIR}/.env"
fi
chmod 0600 "${APP_DIR}/.env"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}"
chmod 0755 "${APP_DIR}/vpn-help.sh"
ln -sfn "${APP_DIR}/vpn-help.sh" /usr/local/bin/vpn-help

if [[ -x "${APP_DIR}/.venv/bin/python" ]] && \
  ! "${APP_DIR}/.venv/bin/python" -c 'import sys; raise SystemExit(0 if (3, 12) <= sys.version_info[:2] < (3, 15) else 1)'; then
  echo "Existing virtual environment uses an unsupported Python version; recreating it."
  rm -rf "${APP_DIR}/.venv"
fi
if [[ ! -x "${APP_DIR}/.venv/bin/python" ]]; then
  runuser -u "${SERVICE_USER}" -- "${PYTHON_BIN}" -m venv "${APP_DIR}/.venv"
fi
runuser -u "${SERVICE_USER}" -- "${APP_DIR}/.venv/bin/python" -m pip install --disable-pip-version-check --upgrade pip
runuser -u "${SERVICE_USER}" -- "${APP_DIR}/.venv/bin/python" -m pip install --disable-pip-version-check "${APP_DIR}"

echo
echo "Enter the Telegram bot credentials. The bot token will be visible while you type or paste it."
printf '%s' "Bot token (visible input): " >/dev/tty
IFS= read -r bot_token </dev/tty || {
  echo >&2 "Could not read the Telegram bot token from the terminal."
  exit 1
}
printf '\n' >/dev/tty
printf '%s' "Main admin Telegram numeric ID: " >/dev/tty
IFS= read -r admin_ids </dev/tty || {
  unset bot_token
  echo >&2 "Could not read the main admin ID from the terminal."
  exit 1
}
if ! printf '%s\n%s\n' "${bot_token}" "${admin_ids}" | \
  runuser -u "${SERVICE_USER}" -- env VPN_MANAGER_ENV_FILE="${APP_DIR}/.env" \
    "${APP_DIR}/.venv/bin/python" -m vpn_manager.setup_bot --stdin; then
  unset bot_token admin_ids
  echo >&2 "Telegram credential setup did not complete; the bot service was not enabled."
  exit 1
fi
unset bot_token admin_ids

runuser -u "${SERVICE_USER}" -- bash -c \
  "cd '${APP_DIR}' && '${APP_DIR}/.venv/bin/alembic' upgrade head"

cat > /etc/systemd/system/vpn-manager-bot.service <<EOF
[Unit]
Description=VPN Control Center Telegram Bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${APP_DIR}
EnvironmentFile=${APP_DIR}/.env
ExecStart=${APP_DIR}/.venv/bin/python -m vpn_manager.bot
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${APP_DIR}/var

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now vpn-manager-bot
systemctl is-active --quiet vpn-manager-bot
echo
echo "Telegram bot service is active. Check logs with: journalctl -u vpn-manager-bot -f"
echo "Configuration file: ${APP_DIR}/.env (permissions: 0600)"
echo "Maintenance menu: sudo vpn-help"
