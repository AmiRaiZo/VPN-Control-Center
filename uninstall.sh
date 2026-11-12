#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${EUID}" -ne 0 ]]; then echo "Run with sudo" >&2; exit 1; fi
echo "This removes the bot service, application, database and local backups."
read -r -p "Type REMOVE to continue: " confirm
[[ "${confirm}" == "REMOVE" ]] || { echo "Cancelled."; exit 0; }
systemctl disable --now vpn-manager-bot 2>/dev/null || true
rm -f /etc/systemd/system/vpn-manager-bot.service /usr/local/bin/vpn-help
systemctl daemon-reload
rm -rf "${APP_DIR:-/opt/vpn-control-center}" /var/backups/vpn-control-center
id vpnmanager >/dev/null 2>&1 && userdel vpnmanager 2>/dev/null || true
getent group vpnmanager >/dev/null 2>&1 && groupdel vpnmanager 2>/dev/null || true
echo "VPN Control Center and its local data were removed."
14