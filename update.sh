#!/usr/bin/env bash
set -Eeuo pipefail
if [[ "${EUID}" -ne 0 ]]; then echo "Run with sudo" >&2; exit 1; fi
exec /usr/local/bin/vpn-help


