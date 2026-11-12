#!/usr/bin/env bash
set -Eeuo pipefail
systemctl is-active --quiet vpn-manager-api
curl --fail --silent http://127.0.0.1:8080/health/live


