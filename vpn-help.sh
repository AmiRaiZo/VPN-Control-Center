#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="${APP_DIR:-/opt/vpn-control-center}"
SERVICE_USER="${SERVICE_USER:-vpnmanager}"
SERVICE_NAME="vpn-manager-bot"
REPOSITORY="${REPOSITORY:-AmiRaiZo/VPN-Control-Center}"
ENV_FILE="${APP_DIR}/.env"
PYTHON="${APP_DIR}/.venv/bin/python"

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then echo "این فرمان را با sudo اجرا کنید." >&2; exit 1; fi
}

pause_menu() { echo; read -r -p "برای بازگشت Enter بزنید..." _; }

restart_bot() {
  systemctl restart "${SERVICE_NAME}"
  systemctl is-active --quiet "${SERVICE_NAME}"
}

change_owner() {
  local current token new_id
  current="$(sed -n 's/^ADMIN_TELEGRAM_IDS=//p' "${ENV_FILE}" | head -n1)"
  token="$(sed -n 's/^BOT_TOKEN=//p' "${ENV_FILE}" | head -n1)"
  echo "شناسه فعلی مالک: ${current}"
  read -r -p "شناسه عددی جدید Super Admin: " new_id
  if [[ ! "${new_id}" =~ ^[1-9][0-9]{4,19}$ ]]; then echo "شناسه معتبر نیست."; return 1; fi
  read -r -p "برای تأیید، شناسه جدید را دوباره وارد کنید: " confirm
  [[ "${confirm}" == "${new_id}" ]] || { echo "تأیید مطابقت نداشت."; return 1; }
  printf '%s\n%s\n' "${token}" "${new_id}" | VPN_MANAGER_ENV_FILE="${ENV_FILE}" "${PYTHON}" -c \
    'import os,sys; from pathlib import Path; from vpn_manager.setup_bot import save_bot_settings; token=sys.stdin.readline().rstrip("\n"); admin=sys.stdin.readline().strip(); save_bot_settings(Path(os.environ["VPN_MANAGER_ENV_FILE"]), token, admin)'
  chown "${SERVICE_USER}:${SERVICE_USER}" "${ENV_FILE}"
  chmod 0600 "${ENV_FILE}"
  restart_bot
  echo "شناسه Super Admin تغییر کرد و سرویس فعال است."
}

change_token() {
  local token admin_ids
  admin_ids="$(sed -n 's/^ADMIN_TELEGRAM_IDS=//p' "${ENV_FILE}" | head -n1)"
  read -r -s -p "توکن جدید ربات (ورودی مخفی): " token; echo
  [[ -n "${token}" ]] || { echo "توکن خالی است."; return 1; }
  printf '%s\n' "${token}" | "${PYTHON}" -c \
    'import sys; from vpn_manager.setup_bot import verify_bot_token; token=sys.stdin.readline().rstrip("\n"); print("توکن معتبر است؛ ربات:", "@" + verify_bot_token(token))'
  printf '%s\n%s\n' "${token}" "${admin_ids}" | VPN_MANAGER_ENV_FILE="${ENV_FILE}" "${PYTHON}" -c \
    'import os,sys; from pathlib import Path; from vpn_manager.setup_bot import save_bot_settings; token=sys.stdin.readline().rstrip("\n"); admin=sys.stdin.readline().strip(); save_bot_settings(Path(os.environ["VPN_MANAGER_ENV_FILE"]), token, admin)'
  chown "${SERVICE_USER}:${SERVICE_USER}" "${ENV_FILE}"
  chmod 0600 "${ENV_FILE}"
  unset token
  restart_bot
  echo "توکن جدید اعتبارسنجی و ذخیره شد؛ سرویس فعال است."
}

update_panel() {
  local latest tag staging archive backup stamp rollback_dir current_tag newest
  echo "در حال بررسی آخرین GitHub Release از ${REPOSITORY} ..."
  latest="$(curl --fail --location --silent --show-error \
    -H 'Accept: application/vnd.github+json' -H 'X-GitHub-Api-Version: 2022-11-28' \
    "https://api.github.com/repos/${REPOSITORY}/releases/latest")"
  tag="$(printf '%s' "${latest}" | jq -r '.tag_name // empty')"
  if [[ ! "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "آخرین Release تگ نسخه معتبر X.Y.Z ندارد؛ عملیات متوقف شد."; return 1
  fi
  stamp="$(date -u +%Y%m%dT%H%M%SZ)"
  current_tag="$(cat "${APP_DIR}/.release-tag" 2>/dev/null || true)"
  if [[ "${current_tag}" == "${tag}" ]]; then
    echo "آخرین نسخه (${tag}) هم‌اکنون نصب است."; return 0
  fi
  if [[ "${current_tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    newest="$(printf '%s\n%s\n' "${current_tag#v}" "${tag#v}" | sort -V | tail -n1)"
    if [[ "${newest}" == "${current_tag#v}" ]]; then
      echo "نسخه نصب‌شده (${current_tag}) از آخرین Release (${tag}) جدیدتر است؛ Downgrade انجام نمی‌شود."
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
    echo "محتوای Release ناقص است؛ نصب انجام نشد."; rm -rf "${staging}" "${archive}"; return 1;
  }
  systemctl stop "${SERVICE_NAME}"
  rollback_dir="$(mktemp -d)"
  rollback_update() {
    echo "به‌روزرسانی ناموفق بود؛ در حال بازگردانی سورس قبلی ..."
    tar -xzf "${backup}" -C "${rollback_dir}"
    rsync -a --delete --exclude='.env' --exclude='var/' --exclude='.venv/' \
      --exclude='backups/' "${rollback_dir}/" "${APP_DIR}/"
    chown -R "${SERVICE_USER}:${SERVICE_USER}" "${APP_DIR}"
    runuser -u "${SERVICE_USER}" -- "${PYTHON}" -m pip install --disable-pip-version-check --upgrade "${APP_DIR}" || true
    systemctl start "${SERVICE_NAME}" || true
    rm -rf "${staging}" "${archive}" "${rollback_dir}"
    echo "سورس قبلی بازیابی شد. پشتیبان داده/سورس: ${backup}"
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
  echo "به‌روزرسانی به ${tag} کامل شد. پشتیبان داده و سورس در ${APP_DIR}/backups قرار دارد."
}

uninstall_all() {
  echo "هشدار: این کار سرویس، تنظیمات، دیتابیس، فایل‌ها و پشتیبان‌های داخل برنامه را حذف می‌کند."
  read -r -p "برای حذف کامل دقیقاً REMOVE را وارد کنید: " confirm
  [[ "${confirm}" == "REMOVE" ]] || { echo "لغو شد."; return 0; }
  systemctl disable --now "${SERVICE_NAME}" 2>/dev/null || true
  rm -f "/etc/systemd/system/${SERVICE_NAME}.service" /usr/local/bin/vpn-help
  systemctl daemon-reload
  rm -rf "${APP_DIR}" /var/backups/vpn-control-center
  if id "${SERVICE_USER}" >/dev/null 2>&1; then userdel "${SERVICE_USER}" 2>/dev/null || true; fi
  getent group "${SERVICE_USER}" >/dev/null 2>&1 && groupdel "${SERVICE_USER}" 2>/dev/null || true
  echo "VPN Control Center و داده‌های محلی آن حذف شدند."
}

add_subordinate_admin() {
  local telegram_id role
  read -r -p "Telegram numeric ID مدیر جدید: " telegram_id
  [[ "${telegram_id}" =~ ^[1-9][0-9]{4,19}$ ]] || { echo "شناسه معتبر نیست."; return 1; }
  echo "نقش را انتخاب کنید: 1) مدیر عملیات  2) مالی  3) پشتیبانی"
  read -r -p "نقش: " role
  case "${role}" in
    1) role="admin" ;;
    2) role="finance" ;;
    3) role="support" ;;
    *) echo "نقش نامعتبر است."; return 1 ;;
  esac
  runuser -u "${SERVICE_USER}" -- bash -c \
    "cd '${APP_DIR}' && '${PYTHON}' -m vpn_manager.admin_cli add-admin --telegram-id '${telegram_id}' --role '${role}'"
  echo "مدیر اضافه شد. جزئیات و مجوزهای اختصاصی را از ربات → پنل ادمین → مدیران ربات کنترل کنید."
}

main() {
  require_root
  [[ -x "${PYTHON}" && -f "${ENV_FILE}" ]] || { echo "نصب معتبر در ${APP_DIR} پیدا نشد."; exit 1; }
  while true; do
    clear || true
    echo "====================================="
    echo "       VPN Control Center Help"
    echo "====================================="
    echo "1) تغییر شناسه Super Admin"
    echo "2) اضافه کردن ادمین زیرمجموعه"
    echo "3) تغییر توکن ربات تلگرام"
    echo "4) بررسی و نصب آخرین نسخه Release پنل"
    echo "5) حذف کامل برنامه و اطلاعات"
    echo "0) خروج"
    echo
    read -r -p "انتخاب شما: " choice
    case "${choice}" in
      1) change_owner || true; pause_menu ;;
      2) add_subordinate_admin || true; pause_menu ;;
      3) change_token || true; pause_menu ;;
      4) update_panel || true; pause_menu ;;
      5) uninstall_all; break ;;
      0) break ;;
      *) echo "گزینه نامعتبر است."; pause_menu ;;
    esac
  done
}

main "$@"

