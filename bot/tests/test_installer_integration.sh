#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BOT="${ROOT}/bot"
fail() { echo "FAIL: $*" >&2; exit 1; }
contains() { grep -Fq -- "$2" "$1" || fail "$1 does not contain: $2"; }

contains "${ROOT}/install/install.sh" 'BOT_SOURCE_DIR="$PROJECT_ROOT/bot"'
contains "${ROOT}/install/update.sh" 'bash "$PROJECT_ROOT/bot/update-local.sh"'
contains "${BOT}/install.sh" 'python3.12'
contains "${BOT}/install.sh" '3, 12) <= sys.version_info[:2] < (3, 15)'
contains "${BOT}/install.sh" "--exclude='.env' --exclude='var/' --exclude='.venv/' --exclude='backups/'"
contains "${BOT}/update-local.sh" 'rsync -a --delete --exclude='
contains "${BOT}/update-local.sh" 'Persistent .env, var/, backups/ and virtualenv were left in place.'
contains "${BOT}/update-local.sh" "--exclude='vpn_manager.db'"
contains "${BOT}/update-local.sh" 'vpn-manager-bot.service'
contains "${BOT}/systemd/vpn-manager-bot.service.in" 'ReadWritePaths=@APP_DIR@/var @APP_DIR@/backups'
contains "${BOT}/backup.sh" 'vpn_manager.db-wal'
contains "${BOT}/restore.sh" 'SERVICE_NAME="${SERVICE_NAME:-vpn-manager-bot}"'
contains "${BOT}/restore.sh" 'systemctl stop "${SERVICE_NAME}"'
contains "${BOT}/vpn-help.sh" 'bot_source="${staging}/bot"'
contains "${BOT}/vpn-help.sh" 'bash "${bot_source}/update-local.sh"'

if grep -Fq 'vpn-manager-api' "${BOT}/restore.sh"; then fail 'restore script references the wrong systemd unit'; fi
if grep -Fq 'backend/venv' "${BOT}/install.sh" "${BOT}/update-local.sh"; then fail 'bot installer references the panel virtualenv'; fi

for script in \
  "${ROOT}/install/install.sh" "${ROOT}/install/update.sh" \
  "${BOT}/install.sh" "${BOT}/update-local.sh" "${BOT}/backup.sh" \
  "${BOT}/restore.sh" "${BOT}/vpn-help.sh"; do
  bash -n "${script}" || fail "bash syntax check failed: ${script}"
done

echo "PASS: installer integration assertions and bash syntax checks"
