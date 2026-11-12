#!/usr/bin/env bash
set -Eeuo pipefail

REPOSITORY="${REPOSITORY:-AmiRaiZo/VPN-Control-Center}"
BRANCH="${BRANCH:-main}"
APP_DIR="${APP_DIR:-/opt/vpn-control-center}"
SERVICE_USER="${SERVICE_USER:-vpnmanager}"
PYTHON_BIN="${PYTHON_BIN:-python3.12}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this installer as root: curl -fsSL https://raw.githubusercontent.com/${REPOSITORY}/${BRANCH}/install.sh | sudo bash" >&2
  exit 1
fi
if [[ ! -r /dev/tty ]]; then
  echo "An interactive terminal is required to enter the Telegram bot token and admin ID." >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl python3.12 python3.12-venv

if ! command -v "${PYTHON_BIN}" >/dev/null 2>&1; then
  echo "${PYTHON_BIN} is required. Set PYTHON_BIN to a Python 3.12 executable." >&2
  exit 1
fi

install -d -m 0755 "${APP_DIR}"
if [[ ! -f "${APP_DIR}/pyproject.toml" ]]; then
  archive="$(mktemp)"
  trap 'rm -f "${archive}"' EXIT
  curl --fail --location --silent --show-error \
    "https://github.com/${REPOSITORY}/archive/refs/heads/${BRANCH}.tar.gz" \
    --output "${archive}"
  tar -xzf "${archive}" --strip-components=1 -C "${APP_DIR}"
fi

if [[ ! -f "${APP_DIR}/pyproject.toml" || ! -f "${APP_DIR}/.env.example" ]]; then
  echo "The downloaded repository is incomplete; refusing to continue." >&2
  exit 1
fi

if ! id "${SERVICE_USER}" >/dev/null 2>&1; then
  useradd --system --home "${APP_DIR}" --shell /usr/sbin/nologin "${SERVICE_USER}"
fi
install -d -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0750 "${APP_DIR}/var"
if [[ ! -f "${APP_DIR}/.env" ]]; then
  install -o "${SERVICE_USER}" -g "${SERVICE_USER}" -m 0600 "${APP_DIR}/.env.example" "${APP_DIR}/.env"
fi
chmod 0600 "${APP_DIR}/.env"
chown -R "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}"

if [[ ! -x "${APP_DIR}/.venv/bin/python" ]]; then
runuser -u "${SERVICE_USER}" -- "${PYTHON_BIN}" -m venv "${APP_DIR}/.venv"
fi
runuser -u "${SERVICE_USER}" -- "${APP_DIR}/.venv/bin/pip" install --disable-pip-version-check "${APP_DIR}"

echo
echo "Enter the Telegram bot credentials. The token is not echoed or written to shell history."
runuser -u "${SERVICE_USER}" -- env VPN_MANAGER_ENV_FILE="${APP_DIR}/.env" \
  "${APP_DIR}/.venv/bin/python" -m vpn_manager.setup_bot </dev/tty

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
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now vpn-manager-bot
systemctl is-active --quiet vpn-manager-bot
echo
echo "Telegram bot service is active. Check logs with: journalctl -u vpn-manager-bot -f"
echo "Configuration file: ${APP_DIR}/.env (permissions: 0600)"
