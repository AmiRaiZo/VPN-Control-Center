#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${EUID}" -ne 0 ]]; then echo "Run with sudo" >&2; exit 1; fi
systemctl disable --now vpn-manager-api 2>/dev/null || true
rm -f /etc/systemd/system/vpn-manager-api.service
systemctl daemon-reload
echo "Service removed. Application data was preserved under /opt/vpn-control-center."

