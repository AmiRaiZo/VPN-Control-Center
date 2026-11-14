#!/bin/bash
###############################################################################
# VPN Panel installer (all managed protocols; Ubuntu 24.04 recovery hardened)
# For Ubuntu 20.04 / 22.04 / 24.04 (x86_64)
#
# Usage:
#   sudo bash install.sh
###############################################################################

###############################################################################
# LICENSING
#
# Never embed the license API key in a distributable installer. The protected
# license bootstrap must export both values before executing this script. For
# a manual install, read the key without echo and preserve only these variables
# through sudo (see README.md).
# Production remains fail-closed when either value is absent. Local development
# requires the explicit VPN_PANEL_ALLOW_UNLICENSED_INSTALL=1 opt-in.
###############################################################################
LICENSE_SERVER_URL="${LICENSE_SERVER_URL:-}"
LICENSE_API_KEY="${LICENSE_API_KEY:-}"
ALLOW_UNLICENSED_INSTALL="${VPN_PANEL_ALLOW_UNLICENSED_INSTALL:-0}"
LICENSE_DEV_MODE=false
[ "$ALLOW_UNLICENSED_INSTALL" = "1" ] && LICENSE_DEV_MODE=true

###############################################################################
# UNATTENDED MODE (used by the license-server's one-line bootstrap installer;
# irrelevant for a normal manual "sudo bash install.sh" run).
#
# When UNATTENDED=1 is exported before running this script, every interactive
# question below is skipped and these env vars (or their defaults) are used
# instead: SERVER_IP (autodetected if empty), PANEL_PORT (default 8080),
# ADMIN_USER (default admin), ADMIN_PASS (securely generated if empty), LICENSE_KEY.
# IMPORTANT: unattended mode must never wipe an existing panel automatically.
# A destructive reinstall now requires VPN_PANEL_FORCE_FRESH_INSTALL=1.
###############################################################################
UNATTENDED="${UNATTENDED:-0}"
GENERATED_ADMIN_PASS=0
FORCE_FRESH_INSTALL="${VPN_PANEL_FORCE_FRESH_INSTALL:-0}"
SERVER_ROLE="${SERVER_ROLE:-main}"
CONTROLLER_URL="${CONTROLLER_URL:-}"
CONTROLLER_TOKEN="${CONTROLLER_TOKEN:-}"
CONTROLLER_VERIFY_TLS="${CONTROLLER_VERIFY_TLS:-1}"
NODE_NAME="${NODE_NAME:-}"
NODE_PUBLIC_URL="${NODE_PUBLIC_URL:-}"
NODE_VERIFY_TLS="${NODE_VERIFY_TLS:-1}"
# 1 = install VPN daemons on this host; 0 = controller/management UI only.
INSTALL_LOCAL_SERVICES="${INSTALL_LOCAL_SERVICES:-1}"
# The license-server bootstrap launches this installer with UNATTENDED=1 so it
# can keep the public one-line command compact.  Fresh installs still need the
# operator to choose controller/node role and whether local VPN daemons belong
# on the controller.  In auto mode we ask those role questions directly on the
# controlling terminal even though stdin is the curl pipe.  Set
# VPN_PANEL_ROLE_PROMPTS=0 only for genuinely headless automation.
ROLE_PROMPT_POLICY="${VPN_PANEL_ROLE_PROMPTS:-auto}"
ROLE_PROMPTS_ACTIVE=0
PRECOLLECTED_CHOICES="${VPN_PANEL_CHOICES_PRECOLLECTED:-0}"
PRESELECTED_EXISTING_ACTION="${VPN_PANEL_EXISTING_ACTION:-}"

vpn_panel_tty_available() {
  [ -c /dev/tty ] && { : </dev/tty; } 2>/dev/null && { : >/dev/tty; } 2>/dev/null
}

vpn_panel_should_prompt_role() {
  case "${ROLE_PROMPT_POLICY,,}" in
    0|no|false|never|off) return 1 ;;
    1|yes|true|always|on) vpn_panel_tty_available ;;
    auto|"")
      # Manual installs always ask. The licensed curl|bash bootstrap also asks
      # when an SSH/console TTY exists, but remains non-interactive in CI/cloud-init.
      [ "$UNATTENDED" != "1" ] || vpn_panel_tty_available
      ;;
    *)
      echo "[!] Unknown VPN_PANEL_ROLE_PROMPTS value '${ROLE_PROMPT_POLICY}'; using auto mode." >&2
      [ "$UNATTENDED" != "1" ] || vpn_panel_tty_available
      ;;
  esac
}

vpn_panel_tty_print() {
  if vpn_panel_tty_available; then
    printf '%s\n' "$*" > /dev/tty
  else
    printf '%s\n' "$*"
  fi
}

vpn_panel_require_license_configuration() {
  if [ -n "$LICENSE_SERVER_URL" ] && [ -n "$LICENSE_API_KEY" ]; then
    return 0
  fi
  if [ "$ALLOW_UNLICENSED_INSTALL" = "1" ]; then
    echo "[!] Explicit unlicensed development install enabled. Never use this mode in production." >&2
    return 0
  fi
  echo "ERROR: LICENSE_SERVER_URL and LICENSE_API_KEY must be supplied through the protected installer environment." >&2
  echo "       For local development only, set VPN_PANEL_ALLOW_UNLICENSED_INSTALL=1." >&2
  return 1
}

vpn_panel_tty_read() {
  local __var_name="$1" __prompt="$2" __value=""
  if vpn_panel_tty_available; then
    printf '%s' "$__prompt" > /dev/tty
    IFS= read -r __value < /dev/tty || return 1
  else
    IFS= read -r -p "$__prompt" __value || return 1
  fi
  printf -v "$__var_name" '%s' "$__value"
}

vpn_panel_detect_existing_license() {
  local python_bin="/opt/vpn-panel/backend/venv/bin/python3"
  local backend_dir="/opt/vpn-panel/backend"
  [ -x "$python_bin" ] || python_bin="/opt/vpn-panel/backend/venv/bin/python"
  [ -x "$python_bin" ] && [ -d "$backend_dir/app" ] || return 0
  (
    cd "$backend_dir" || exit 0
    PYTHONPATH="$backend_dir" "$python_bin" - <<'PYLICENSE' 2>/dev/null || true
from app.database import SessionLocal
from app.services.license_manager import get_license_key

db = SessionLocal()
try:
    print((get_license_key(db) or "").strip())
finally:
    db.close()
PYLICENSE
  ) | tail -n1 | tr -d '\r\n'
}

vpn_panel_choose_existing_license() {
  local existing_license="" answer="" new_license=""
  existing_license="$(vpn_panel_detect_existing_license)"
  [ -n "$existing_license" ] || return 0

  if ! vpn_panel_tty_available; then
    export LICENSE_KEY="$existing_license"
    return 0
  fi

  vpn_panel_tty_print ""
  vpn_panel_tty_print "=============================================="
  vpn_panel_tty_print " Existing panel license detected"
  vpn_panel_tty_print "=============================================="
  vpn_panel_tty_print " Existing license: $existing_license"
  vpn_panel_tty_read answer "Continue using this license? [Y/n]: " || answer="y"
  if [[ "${answer:-y}" =~ ^[Nn]$ ]]; then
    vpn_panel_tty_read new_license "Enter a new license code: " || new_license=""
    if [ -n "$new_license" ]; then
      export LICENSE_KEY="$new_license"
    else
      unset LICENSE_KEY || true
    fi
  else
    export LICENSE_KEY="$existing_license"
  fi
}



vpn_panel_prompt_deployment_role() {
  local current_role="${SERVER_ROLE:-main}"
  local current_local="${INSTALL_LOCAL_SERVICES:-1}"
  local default_choice=1
  [ "$current_role" = "node" ] && default_choice=2

  ROLE_PROMPTS_ACTIVE=1
  vpn_panel_tty_print ""
  vpn_panel_tty_print "=============================================="
  vpn_panel_tty_print " Server deployment role"
  vpn_panel_tty_print "=============================================="
  vpn_panel_tty_print "  1) Main panel / controller"
  vpn_panel_tty_print "  2) Node server (connect it to an existing main panel)"
  vpn_panel_tty_read ROLE_CHOICE "Selection [${default_choice}]: "
  ROLE_CHOICE=${ROLE_CHOICE:-$default_choice}
  if [ "$ROLE_CHOICE" = "2" ]; then
    SERVER_ROLE="node"
    INSTALL_LOCAL_SERVICES=1
    vpn_panel_tty_read CONTROLLER_URL_INPUT "Main panel URL${CONTROLLER_URL:+ [${CONTROLLER_URL}]}: "
    CONTROLLER_URL=${CONTROLLER_URL_INPUT:-${CONTROLLER_URL:-}}
    vpn_panel_tty_read CONTROLLER_TOKEN_INPUT "Connection token from the main panel Nodes section${CONTROLLER_TOKEN:+ [keep current]}: "
    CONTROLLER_TOKEN=${CONTROLLER_TOKEN_INPUT:-${CONTROLLER_TOKEN:-}}
    vpn_panel_tty_read NODE_NAME_INPUT "Node name [${NODE_NAME:-$(hostname -s)}]: "
    NODE_NAME=${NODE_NAME_INPUT:-${NODE_NAME:-$(hostname -s)}}
    vpn_panel_tty_read CONTROLLER_TLS_ANS "Does the main panel URL use a valid HTTPS certificate? (Y/n): "
    [[ "${CONTROLLER_TLS_ANS:-y}" =~ ^[Nn]$ ]] && CONTROLLER_VERIFY_TLS=0 || CONTROLLER_VERIFY_TLS=1
  else
    SERVER_ROLE="main"
    vpn_panel_tty_print ""
    local default_answer="Y/n"
    [ "$current_local" = "0" ] && default_answer="y/N"
    vpn_panel_tty_read LOCAL_SERVICES_ANS "Install VPN services on this main panel too? (${default_answer}): "
    if [ "$current_local" = "0" ]; then
      [[ "${LOCAL_SERVICES_ANS:-n}" =~ ^[Yy]$ ]] && INSTALL_LOCAL_SERVICES=1 || INSTALL_LOCAL_SERVICES=0
    else
      [[ "${LOCAL_SERVICES_ANS:-y}" =~ ^[Nn]$ ]] && INSTALL_LOCAL_SERVICES=0 || INSTALL_LOCAL_SERVICES=1
    fi
    if [ "$INSTALL_LOCAL_SERVICES" = "0" ]; then
      vpn_panel_tty_print "[*] Management-only mode selected. VPN services will not be installed now and can be installed later from Protocol Management."
    fi
  fi
}

vpn_panel_existing_install_action() {
  local default_action="1" action=""
  if [ "$FORCE_FRESH_INSTALL" = "1" ]; then
    printf '3'
    return 0
  fi
  # The public license wrapper can collect this answer before it starts the
  # percentage renderer. Honour that choice here and never prompt underneath
  # an active progress bar.
  case "$PRESELECTED_EXISTING_ACTION" in
    1|2|3)
      printf '%s' "$PRESELECTED_EXISTING_ACTION"
      return 0
      ;;
  esac
  if ! vpn_panel_should_prompt_role; then
    printf '1'
    return 0
  fi
  vpn_panel_tty_print ""
  vpn_panel_tty_print "=============================================="
  vpn_panel_tty_print " Existing installation detected"
  vpn_panel_tty_print "=============================================="
  vpn_panel_tty_print "  1) Repair/update the current installation (default)"
  vpn_panel_tty_print "  2) Change server role / local VPN services, then repair/update"
  vpn_panel_tty_print "  3) Full wipe and fresh installation"
  vpn_panel_tty_print "=============================================="
  vpn_panel_tty_read action "Selection [${default_action}]: " || action="$default_action"
  action=${action:-$default_action}
  case "$action" in 1|2|3) printf '%s' "$action" ;; *) printf '1' ;; esac
}

# Destructive package recovery is allowed only on a genuinely clean box or
# when an operator explicitly requested a full reinstall. This prevents the
# license-server bootstrap from turning an update into a fresh installation.
if [ "$UNATTENDED" = "1" ] && { [ "$FORCE_FRESH_INSTALL" = "1" ] || { [ ! -d /opt/vpn-panel ] && [ ! -f /etc/systemd/system/vpn-panel-api.service ]; }; }; then
  export VPN_PANEL_ALLOW_DESTRUCTIVE_VPN_PACKAGE_RECOVERY=1
fi

set -e

# ---------------------------------------------------------------------------
# 0) Basic checks
# ---------------------------------------------------------------------------
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script as root (sudo bash install.sh)"
  exit 1
fi

# Keep a persistent, line-buffered installer log even when the license
# bootstrap renders only a compact percentage bar.  This makes every slow
# package-manager phase observable instead of looking frozen at 3%.
VPN_PANEL_INSTALL_LOG="${VPN_PANEL_INSTALL_LOG:-/var/log/vpn-panel-install.log}"
mkdir -p "$(dirname "$VPN_PANEL_INSTALL_LOG")"
touch "$VPN_PANEL_INSTALL_LOG"
chmod 600 "$VPN_PANEL_INSTALL_LOG" 2>/dev/null || true
exec > >(tee -a "$VPN_PANEL_INSTALL_LOG") 2>&1
printf '
===== VPN Panel install started at %s =====
' "$(date -Is)"

if ! grep -qi ubuntu /etc/os-release; then
  echo "This script has only been tested on Ubuntu."
  if [ "$UNATTENDED" = "1" ]; then
    ans="y"
  else
    read -p "Continue anyway? (y/n) " ans
  fi
  [ "$ans" != "y" ] && exit 1
fi

# ---------------------------------------------------------------------------
# 0b) Safe APT/dpkg recovery. Package post-install scripts are temporarily
# prevented from starting strongSwan/xl2tpd before valid panel configs exist.
# This also repairs a server left half-configured by a previous failed run.
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RELEASE_VERSION=$(tr -d '[:space:]' < "$PROJECT_ROOT/VERSION" 2>/dev/null || true)
[ -n "$RELEASE_VERSION" ] && vpn_panel_tty_print "[*] VPN Panel release ${RELEASE_VERSION}"
if [ ! -r "$SCRIPT_DIR/apt_preflight.sh" ]; then
  echo "ERROR: missing installer helper: $SCRIPT_DIR/apt_preflight.sh" >&2
  exit 1
fi
# shellcheck source=apt_preflight.sh
source "$SCRIPT_DIR/apt_preflight.sh"
# shellcheck source=bootstrap_host.sh
if [ ! -r "$SCRIPT_DIR/bootstrap_host.sh" ]; then
  echo "ERROR: missing installer helper: $SCRIPT_DIR/bootstrap_host.sh" >&2
  exit 1
fi
source "$SCRIPT_DIR/bootstrap_host.sh"
if [ ! -r "$SCRIPT_DIR/npm_safe.sh" ]; then
  echo "ERROR: missing frontend helper: $SCRIPT_DIR/npm_safe.sh" >&2
  exit 1
fi
# shellcheck source=npm_safe.sh
source "$SCRIPT_DIR/npm_safe.sh"

_VPNP_INSTALL_HEARTBEAT_PID=""
_VPNP_INSTALL_STATE_FILE="${VPN_PANEL_INSTALL_STATE_FILE:-/tmp/vpn-panel-install-state}"
_VPNP_COMPACT_PROGRESS="${VPN_PANEL_COMPACT_PROGRESS:-0}"

vpn_panel_console_status() {
  local message="$*"
  printf '[install-phase] %s\n' "$message"
  printf '%s\n' "$message" > "$_VPNP_INSTALL_STATE_FILE" 2>/dev/null || true
  # The protected license bootstrap may redirect stdout while drawing its own
  # progress bar.  Writing major phase changes to the controlling terminal
  # keeps the operator informed without requiring another SSH session.
  if [ "$_VPNP_COMPACT_PROGRESS" != "1" ] && [ ! -t 1 ] && [ -c /dev/tty ] && [ -w /dev/tty ]; then
    printf '\r\033[K[install-phase] %s\n' "$message" 2>/dev/null > /dev/tty || true
  fi
}

vpn_panel_stop_heartbeat() {
  if [ -n "${_VPNP_INSTALL_HEARTBEAT_PID:-}" ]; then
    kill "$_VPNP_INSTALL_HEARTBEAT_PID" 2>/dev/null || true
    wait "$_VPNP_INSTALL_HEARTBEAT_PID" 2>/dev/null || true
    _VPNP_INSTALL_HEARTBEAT_PID=""
  fi
}

vpn_panel_start_heartbeat() {
  local label="$1"
  vpn_panel_stop_heartbeat
  (
    local elapsed=0
    while sleep 15; do
      elapsed=$((elapsed + 15))
      vpn_panel_console_status "${label} is still running (${elapsed}s elapsed)."
    done
  ) &
  _VPNP_INSTALL_HEARTBEAT_PID=$!
}

vpn_panel_run_phase() {
  local label="$1"
  shift
  local rc=0
  vpn_panel_console_status "${label}..."
  vpn_panel_start_heartbeat "$label"
  if "$@"; then
    rc=0
  else
    rc=$?
  fi
  vpn_panel_stop_heartbeat
  if [ "$rc" -eq 0 ]; then
    vpn_panel_console_status "${label} completed."
  else
    vpn_panel_console_status "${label} failed with exit code ${rc}. See ${VPN_PANEL_INSTALL_LOG}."
  fi
  return "$rc"
}

trap 'vpn_panel_stop_heartbeat; vpn_panel_restore_apt_automation' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_for_apt_lock() {
  vpn_panel_wait_for_apt_lock 600
}

apt_package_available() {
  local package_name="$1"
  local candidate
  candidate=$(apt-cache policy "$package_name" 2>/dev/null | awk '/Candidate:/ {print $2; exit}')
  [ -n "$candidate" ] && [ "$candidate" != "(none)" ]
}

# Return success only when a TCP port can be bound on all IPv4 addresses.
# A real bind test is more reliable than parsing ss/netstat output and also
# catches listeners bound only to 127.0.0.1, which would still conflict with
# Nginx binding 0.0.0.0 on the same port.
tcp_port_is_free() {
  local port="$1"
  python3 - "$port" <<'PYEOF'
import socket, sys
port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
try:
    s.bind(("0.0.0.0", port))
except OSError:
    raise SystemExit(1)
finally:
    s.close()
PYEOF
}

select_public_panel_port() {
  local requested="$1"
  local candidate
  if tcp_port_is_free "$requested"; then
    printf '%s' "$requested"
    return 0
  fi

  echo "[!] Requested panel port tcp/${requested} is already occupied." >&2
  # The product default is 8080. On shared servers it is commonly used by
  # another web UI, so use 8000 exactly as the documented automatic fallback.
  if [ "$requested" = "8080" ]; then
    for candidate in 8000 $(seq 8001 8099); do
      if tcp_port_is_free "$candidate"; then
        echo "[*] Panel port automatically changed: 8080 -> ${candidate}" >&2
        printf '%s' "$candidate"
        return 0
      fi
    done
  fi

  echo "ERROR: tcp/${requested} is occupied and no safe fallback port is available." >&2
  return 1
}

select_internal_backend_port() {
  local public_port="$1"
  local candidate
  # Keep the private FastAPI listener away from the public 8000/8080 range so
  # the panel can safely fall back to public tcp/8000 without colliding with
  # Uvicorn. It remains loopback-only and is never opened in the firewall.
  for candidate in $(seq 18000 18099); do
    [ "$candidate" = "$public_port" ] && continue
    if tcp_port_is_free "$candidate"; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  echo "ERROR: no free loopback port was found for the VPN Panel API." >&2
  return 1
}

INSTALL_DIR="/opt/vpn-panel"
WEB_DIR="/var/www/vpn-panel"
DB_NAME="vpn_panel"
DB_USER="vpn_panel"

# IMPORTANT: decide update-vs-fresh-install before running APT.  Older builds
# performed a full dpkg repair and package bootstrap first, so an ordinary
# update could appear frozen at 3% for many minutes even though no fresh host
# preparation was required.

# ---------------------------------------------------------------------------
# نصب قبلی؟ از کاربر بپرس پاک‌سازی کامل (نصب از صفر) یا فقط آپدیت (حفظ اطلاعات)
# ---------------------------------------------------------------------------
if [ -d "$INSTALL_DIR" ] || [ -f /etc/systemd/system/vpn-panel-api.service ] || [ -d /etc/openvpn/easy-rsa ]; then
  # Load the current deployment choices so the reconfiguration prompt uses
  # the installed values as defaults rather than silently reverting to all-in-one.
  if [ -r "$INSTALL_DIR/panel.env" ]; then
    CURRENT_ROLE=$(awk -F= '/^[[:space:]]*SERVER_ROLE[[:space:]]*=/{v=$0; sub(/^[^=]*=/,"",v); gsub(/[[:space:]"\047]/,"",v); print v}' "$INSTALL_DIR/panel.env" 2>/dev/null | tail -n1 || true)
    CURRENT_LOCAL=$(awk -F= '/^[[:space:]]*INSTALL_LOCAL_SERVICES[[:space:]]*=/{v=$0; sub(/^[^=]*=/,"",v); gsub(/[[:space:]"\047]/,"",v); print v}' "$INSTALL_DIR/panel.env" 2>/dev/null | tail -n1 || true)

    # The licensed bootstrap may have already collected an explicit new role
    # before starting the progress renderer. In that case the old panel.env is
    # historical state only and must never overwrite the operator's selection.
    if [ "$PRECOLLECTED_CHOICES" != "1" ]; then
      [ -n "$CURRENT_ROLE" ] && SERVER_ROLE="$CURRENT_ROLE"
      [ -n "$CURRENT_LOCAL" ] && INSTALL_LOCAL_SERVICES="$CURRENT_LOCAL"
    else
      case "$SERVER_ROLE" in
        main|node) ;;
        *) echo "ERROR: invalid pre-collected SERVER_ROLE: $SERVER_ROLE" >&2; exit 2 ;;
      esac
      case "$INSTALL_LOCAL_SERVICES" in
        0|1) ;;
        *) echo "ERROR: invalid pre-collected INSTALL_LOCAL_SERVICES: $INSTALL_LOCAL_SERVICES" >&2; exit 2 ;;
      esac
      [ "$SERVER_ROLE" = "node" ] && INSTALL_LOCAL_SERVICES=1
      echo "[*] Preserving pre-collected deployment choice over installed defaults: role=${SERVER_ROLE} local_services=${INSTALL_LOCAL_SERVICES}."
    fi
  fi

  EXISTING_ACTION=$(vpn_panel_existing_install_action)
  SELF_SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  case "$EXISTING_ACTION" in
    1)
      echo "[*] Repair/update selected; existing users, database, certificates and settings will be preserved."
      vpn_panel_console_status "Starting safe update of the existing installation"
      exec stdbuf -oL -eL bash "$SELF_SCRIPT_DIR/update.sh"
      ;;
    2)
      if [ "$PRECOLLECTED_CHOICES" != "1" ]; then
        vpn_panel_prompt_deployment_role
      else
        echo "[*] Using deployment choices collected before the installation progress started: role=${SERVER_ROLE} local_services=${INSTALL_LOCAL_SERVICES}."
      fi
      if [ "$SERVER_ROLE" = "node" ] && [ "$PRECOLLECTED_CHOICES" != "1" ]; then
        CURRENT_NODE_URL=""
        if [ -r /var/lib/vpn-panel/install-result.env ]; then
          CURRENT_NODE_URL=$(awk -F= '/^[[:space:]]*PANEL_URL[[:space:]]*=/{v=$0; sub(/^[^=]*=/,"",v); print v}' /var/lib/vpn-panel/install-result.env | tail -n1 || true)
        fi
        [ -z "$CURRENT_NODE_URL" ] && CURRENT_NODE_URL="${NODE_PUBLIC_URL:-}"
        vpn_panel_tty_read NODE_PUBLIC_URL_INPUT "Public URL for this node${CURRENT_NODE_URL:+ [${CURRENT_NODE_URL}]}: "
        NODE_PUBLIC_URL=${NODE_PUBLIC_URL_INPUT:-$CURRENT_NODE_URL}
        vpn_panel_tty_read NODE_TLS_ANS "Does this node URL use a valid HTTPS certificate? (Y/n): "
        [[ "${NODE_TLS_ANS:-y}" =~ ^[Nn]$ ]] && NODE_VERIFY_TLS=0 || NODE_VERIFY_TLS=1
      fi
      echo "[*] Updating the panel before applying the new deployment mode..."
      vpn_panel_console_status "Starting safe update before deployment reconfiguration"
      stdbuf -oL -eL bash "$SELF_SCRIPT_DIR/update.sh"
      vpn_panel_console_status "Panel code update completed; applying deployment settings"
      [ -x "$SELF_SCRIPT_DIR/reconfigure_deployment.sh" ] || {
        echo "ERROR: missing deployment reconfiguration helper." >&2
        exit 1
      }
      stdbuf -oL -eL bash "$SELF_SCRIPT_DIR/reconfigure_deployment.sh" \
        --role "$SERVER_ROLE" \
        --local-services "$INSTALL_LOCAL_SERVICES" \
        --controller-url "$CONTROLLER_URL" \
        --controller-token "$CONTROLLER_TOKEN" \
        --controller-verify-tls "$CONTROLLER_VERIFY_TLS" \
        --node-name "$NODE_NAME" \
        --node-public-url "$NODE_PUBLIC_URL" \
        --node-verify-tls "$NODE_VERIFY_TLS" \
        --install-now 0
      exit 0
      ;;
    3)
      vpn_panel_require_license_configuration || exit 1
      echo "[!] Full wipe selected. Users, database, certificates and all current settings will be deleted."
      if [ "$PRECOLLECTED_CHOICES" = "1" ]; then
        echo "[*] Fresh deployment choices were already collected: role=${SERVER_ROLE} local_services=${INSTALL_LOCAL_SERVICES}."
      fi
      ;;
  esac

  echo "[*] Completely removing the previous installation..."

  systemctl stop vpn-panel-background vpn-panel-api 2>/dev/null || true
  systemctl disable vpn-panel-background vpn-panel-api 2>/dev/null || true
  rm -f /etc/systemd/system/vpn-panel-background.service
  rm -f /etc/systemd/system/vpn-panel-api.service
  rm -rf /etc/systemd/system/vpn-panel-api.service.d
  systemctl daemon-reload

  systemctl stop nginx 2>/dev/null || true
  rm -f /etc/nginx/sites-enabled/vpn-panel /etc/nginx/sites-available/vpn-panel
  rm -f /etc/nginx/sites-enabled/vpn-panel-sub /etc/nginx/sites-available/vpn-panel-sub

  systemctl stop xl2tpd pptpd 2>/dev/null || true
  systemctl stop openvpn-server@server-udp 2>/dev/null || systemctl stop openvpn@server-udp 2>/dev/null || true
  systemctl stop openvpn-server@server-tcp 2>/dev/null || systemctl stop openvpn@server-tcp 2>/dev/null || true
  systemctl stop openvpn-server@server 2>/dev/null || systemctl stop openvpn@server 2>/dev/null || true
  systemctl disable openvpn-server@server 2>/dev/null || systemctl disable openvpn@server 2>/dev/null || true
  systemctl reset-failed openvpn-server@server 2>/dev/null || systemctl reset-failed openvpn@server 2>/dev/null || true
  for u in $(systemctl list-unit-files 2>/dev/null | grep -oE '^openvpn(-server)?@server-extra-[^ ]+\.service'); do
    inst="${u%.service}"
    inst="${inst#*@}"
    if [ ! -f "/etc/openvpn/server/${inst}.conf" ]; then
      systemctl stop "$u" 2>/dev/null || true
      systemctl disable "$u" 2>/dev/null || true
      systemctl reset-failed "$u" 2>/dev/null || true
    fi
  done
  systemctl stop strongswan-starter 2>/dev/null || systemctl stop strongswan 2>/dev/null || true

  for unit in accel-ppp-sstp ocserv vpn-panel-xray-vmess vpn-panel-xray-vless; do
    systemctl stop "$unit" 2>/dev/null || true
    systemctl disable "$unit" 2>/dev/null || true
    systemctl reset-failed "$unit" 2>/dev/null || true
  done
  sleep 1
  pkill -x accel-pppd 2>/dev/null || true
  pkill -x ocserv-main 2>/dev/null || true
  pkill -x xray 2>/dev/null || true

  if command -v mysql >/dev/null 2>&1 && systemctl is-active --quiet mysql 2>/dev/null; then
    mysql -u root -e "DROP DATABASE IF EXISTS ${DB_NAME}; DROP USER IF EXISTS '${DB_USER}'@'localhost'; DROP USER IF EXISTS '${DB_USER}'@'127.0.0.1'; FLUSH PRIVILEGES;" 2>/dev/null || true
  fi

  rm -rf /etc/openvpn/easy-rsa /etc/openvpn/server
  rm -f /etc/ppp/chap-secrets
  rm -f /etc/ppp/ip-up.d/vpn-panel /etc/ppp/ip-down.d/vpn-panel
  rm -rf "$INSTALL_DIR"
  rm -rf /var/lib/vpn-panel/branding
  rm -rf "${WEB_DIR:?}"

  echo "[*] Full cleanup completed. Starting a fresh installation..."
fi

vpn_panel_require_license_configuration || exit 1
vpn_panel_console_status "Preparing APT/dpkg and pausing automatic package jobs"
vpn_panel_pause_apt_automation
vpn_panel_run_phase "Checking and repairing the package database" vpn_panel_repair_dpkg
# VPN kernel modules/sysctl are deferred until the installer knows whether this
# is a management-only controller or a host that will actually run VPN daemons.
vpn_panel_run_phase "Installing core operating-system prerequisites" vpn_panel_bootstrap_base 0

PUBLIC_IP=""
for _url in "https://ifconfig.me" "https://icanhazip.com" "https://api.ipify.org"; do
  _try=$(curl -s -f -4 --max-time 5 "$_url" 2>/dev/null | tr -d '[:space:]')
  if [[ "$_try" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    PUBLIC_IP="$_try"
    break
  fi
done
[ -z "$PUBLIC_IP" ] && PUBLIC_IP=$(hostname -I | awk '{print $1}')

echo "=============================================="
echo " VPN Panel Installer"
echo " Detected public IP: ${PUBLIC_IP}"
echo "=============================================="

EXISTING_LICENSE_KEY="$(vpn_panel_detect_existing_license)"

# The protected license bootstrap supplies the basic values, but role selection
# is intentionally independent from UNATTENDED.  This is what makes
# `curl .../install.sh | sudo bash` ask the two deployment questions instead of
# silently assuming a full all-in-one VPN server.
if [ "$UNATTENDED" = "1" ]; then
  PUBLIC_IP="${SERVER_IP:-$PUBLIC_IP}"
  PANEL_PORT="${PANEL_PORT:-8080}"
  ADMIN_USER="${ADMIN_USER:-admin}"
  ADMIN_PASS="${ADMIN_PASS:-}"
  LICENSE_KEY="${LICENSE_KEY:-$EXISTING_LICENSE_KEY}"
  SERVER_ROLE="${SERVER_ROLE:-main}"
fi

if vpn_panel_should_prompt_role; then
  vpn_panel_prompt_deployment_role
else
  # Headless/cloud-init installs remain deterministic through environment vars.
  [ "$SERVER_ROLE" = "node" ] && INSTALL_LOCAL_SERVICES=1
fi

if [ "$UNATTENDED" != "1" ]; then
  read -p "Confirm/enter the server's public IP [${PUBLIC_IP}]: " INPUT_IP
  PUBLIC_IP=${INPUT_IP:-$PUBLIC_IP}

  read -p "Port for the web panel [8080]: " PANEL_PORT
  PANEL_PORT=${PANEL_PORT:-8080}

  read -p "Panel admin username [admin]: " ADMIN_USER
  ADMIN_USER=${ADMIN_USER:-admin}

  while true; do
    read -s -p "Panel admin password: " ADMIN_PASS; echo
    read -s -p "Confirm password: " ADMIN_PASS2; echo
    [ "$ADMIN_PASS" == "$ADMIN_PASS2" ] && [ -n "$ADMIN_PASS" ] && break
    echo "Passwords do not match or are empty, try again."
  done

  LICENSE_KEY=""
  if [ -n "$LICENSE_SERVER_URL" ]; then
    echo ""
    echo "This panel requires a license key to operate."
    if [ -n "$EXISTING_LICENSE_KEY" ]; then
      echo "Existing license: $EXISTING_LICENSE_KEY"
      read -p "Continue using this license? [Y/n]: " LICENSE_ANSWER
      if [[ "${LICENSE_ANSWER:-y}" =~ ^[Nn]$ ]]; then
        read -p "Enter a new license code: " LICENSE_KEY
      else
        LICENSE_KEY="$EXISTING_LICENSE_KEY"
      fi
    else
      read -p "License key (leave empty to activate later from inside the panel): " LICENSE_KEY
    fi
  fi
fi

REQUESTED_PANEL_PORT="$PANEL_PORT"
PANEL_PORT=$(select_public_panel_port "$REQUESTED_PANEL_PORT")
BACKEND_PORT=$(select_internal_backend_port "$PANEL_PORT")
if [ "$UNATTENDED" = "1" ]; then
  [ "$SERVER_ROLE" = "node" ] && INSTALL_LOCAL_SERVICES=1
  echo "[*] Unattended install - role=${SERVER_ROLE} local_services=${INSTALL_LOCAL_SERVICES} IP=${PUBLIC_IP} panel port=${PANEL_PORT} API loopback port=${BACKEND_PORT} admin user=${ADMIN_USER}"
else
  echo "[*] Selected panel port: ${PANEL_PORT}"
  echo "[*] Selected private API port: 127.0.0.1:${BACKEND_PORT}"
fi

if [ "$INSTALL_LOCAL_SERVICES" = "1" ]; then
  echo "[*] Preparing VPN kernel modules, TUN/PPP and forwarding sysctls..."
  vpn_panel_bootstrap_kernel
else
  echo "[*] Management-only controller: VPN kernel modules and forwarding sysctls were not installed/applied."
fi

if [ "$SERVER_ROLE" = "node" ]; then
  DEFAULT_NODE_PUBLIC_URL="http://${PUBLIC_IP}:${PANEL_PORT}"
  if [ "$ROLE_PROMPTS_ACTIVE" = "1" ]; then
    vpn_panel_tty_read NODE_PUBLIC_URL_INPUT "Public URL for this node, reachable by the main panel [${DEFAULT_NODE_PUBLIC_URL}]: "
    NODE_PUBLIC_URL=${NODE_PUBLIC_URL_INPUT:-$DEFAULT_NODE_PUBLIC_URL}
    vpn_panel_tty_read NODE_TLS_ANS "Does this node URL use a valid HTTPS certificate? (Y/n): "
    [[ "${NODE_TLS_ANS:-y}" =~ ^[Nn]$ ]] && NODE_VERIFY_TLS=0 || NODE_VERIFY_TLS=1
  else
    NODE_PUBLIC_URL=${NODE_PUBLIC_URL:-$DEFAULT_NODE_PUBLIC_URL}
    NODE_NAME=${NODE_NAME:-$(hostname -s)}
  fi
  CONTROLLER_URL="${CONTROLLER_URL%/}"
  CONTROLLER_URL="${CONTROLLER_URL%/api}"
fi

DB_PASS=$(openssl rand -hex 16)
JWT_SECRET=$(openssl rand -hex 32)
INTERNAL_TOKEN=$(openssl rand -hex 32)
DATA_ENCRYPTION_KEY=$(openssl rand -hex 32)
IPSEC_PSK=$(openssl rand -hex 24)
if [ "$UNATTENDED" = "1" ] && [ -z "$ADMIN_PASS" ]; then
  ADMIN_PASS=$(openssl rand -hex 18)
  GENERATED_ADMIN_PASS=1
fi

L2TP_SUBNET="192.168.42"
PPTP_SUBNET="192.168.43"
# OpenVPN همیشه دو پروسه‌ی هم‌زمان (UDP و TCP) است؛ هرکدام سابنت جدای خودشان
# را دارند تا احتمال تخصیص یک IP یکسان به دو کلاینت مختلف (یکی از UDP، یکی از
# TCP) به‌طور هم‌زمان وجود نداشته باشد.
OVPN_SUBNET_UDP="10.8.0.0"
OVPN_SUBNET_TCP="10.8.1.0"
OVPN_NETMASK="255.255.255.0"

PPTP_SETUP_OK=0

vpn_panel_console_status "Installer choices are ready; starting system package installation"

# ---------------------------------------------------------------------------
# 1) System packages (Node.js is installed separately below to avoid a file
#    conflict between Ubuntu's default nodejs/libnode-dev and NodeSource)
# ---------------------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
wait_for_apt_lock
if [ "${VPN_PANEL_BOOTSTRAP_APT_READY:-0}" != "1" ]; then
  vpn_panel_apt_get update
fi
# Child installers in this same full-install process reuse the fresh APT index.
# When executed directly they still update normally because this variable is unset.
export SKIP_APT_UPDATE=1

# Install in deterministic groups. Service auto-start is suppressed only while
# packages are configured; the panel starts each daemon after writing its files.
vpn_panel_console_status "Installing base panel packages"
vpn_panel_install_packages \
  iptables-persistent mysql-server \
  python3 python3-venv python3-pip nginx certbot python3-certbot-nginx \
  curl wget git openssl netcat-openbsd unzip dnsutils ca-certificates

if [ "$INSTALL_LOCAL_SERVICES" = "1" ]; then
  vpn_panel_console_status "Installing VPN service packages"
  vpn_panel_install_packages ppp openvpn easy-rsa
  vpn_panel_console_status "Installing strongSwan/IPsec packages"
  vpn_panel_install_packages \
    strongswan strongswan-pki libcharon-extra-plugins libstrongswan-extra-plugins
  vpn_panel_console_status "Installing the L2TP server package"
  vpn_panel_install_packages xl2tpd
else
  # A management-only controller still owns the canonical OpenVPN CA and
  # tls-auth key used by every node and every combined client profile. Install
  # only the tooling here; no listener is configured, enabled, or exposed.
  vpn_panel_console_status "Installing shared OpenVPN PKI tools"
  vpn_panel_install_packages openvpn easy-rsa
  echo "[*] Management-only mode: VPN listeners skipped; shared OpenVPN PKI tools installed."
fi

# Restore normal package service policy before the panel deliberately starts
# configured services later in this script.
vpn_panel_policy_rcd_disable

vpn_panel_console_status "Base system packages installed"

# Defaults also exist in management-only mode so the database and later
# Protocol Center install jobs have deterministic starting values.
L2TP_INSTALL_PORT="${L2TP_INSTALL_PORT:-1701}"
OVPN_UDP_INSTALL_PORT="${OVPN_UDP_INSTALL_PORT:-1194}"
OVPN_TCP_INSTALL_PORT="${OVPN_TCP_INSTALL_PORT:-1194}"
SSTP_INSTALL_PORT="${SSTP_INSTALL_PORT:-4433}"
OPENCONNECT_INSTALL_PORT="${OPENCONNECT_INSTALL_PORT:-8443}"
SSTP_SETUP_OK=0
IKEV2_SETUP_OK=0
OPENCONNECT_SETUP_OK=0
XRAY_SETUP_OK=0

if [ "$INSTALL_LOCAL_SERVICES" = "1" ]; then
# Install the PPTP server automatically on every supported Ubuntu release.
# When APT has pptpd we use it; Ubuntu 24.04/Noble uses the verified upstream
# source-build fallback implemented in setup_pptp.sh.
echo "[*] Installing PPTP server infrastructure..."
if bash "$SCRIPT_DIR/setup_pptp.sh" --install-only; then
  PPTP_SETUP_OK=1
  echo "[*] PPTP infrastructure ready."
else
  echo "[!] WARNING: PPTP installation failed. The panel installation will continue so the failure can be repaired from Protocol Center." >&2
  PPTP_SETUP_OK=0
fi

fi

# ---------------------------------------------------------------------------
# 1b) Node.js 20.x via NodeSource (remove conflicting distro package first)
# ---------------------------------------------------------------------------
NODE_MAJOR=$(node -v 2>/dev/null | sed 's/v//' | cut -d. -f1)
if [ -z "$NODE_MAJOR" ] || [ "$NODE_MAJOR" -lt 18 ]; then
  vpn_panel_console_status "Installing Node.js 20.x"
  wait_for_apt_lock
  vpn_panel_apt_get remove nodejs npm libnode-dev libnode72 2>/dev/null || true
  wait_for_apt_lock
  vpn_panel_apt_get autoremove
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  wait_for_apt_lock
  vpn_panel_install_packages nodejs
fi
echo "[*] Node.js version: $(node -v)"
vpn_panel_console_status "All system packages installed"

if [ "$INSTALL_LOCAL_SERVICES" = "1" ]; then
# ---------------------------------------------------------------------------
# 1c) Fresh-install protocol port preflight.  A shared server may already have
# listeners on one of the product defaults.  Select an actually free port for
# every movable protocol before any configuration is written, then persist a
# visible notice in the database later in this installer.  IPsec/IKEv2
# UDP/500+4500 and PPTP TCP/1723+GRE remain standards-fixed and are never
# silently remapped.
# ---------------------------------------------------------------------------
INSTALL_PORT_ENV="/tmp/vpn-panel-install-ports.env"
INSTALL_PORT_NOTICES="/tmp/vpn-panel-install-port-notices.json"
export PANEL_PORT BACKEND_PORT INSTALL_PORT_ENV INSTALL_PORT_NOTICES
python3 - <<'PYPORTS'
import json, os, random, re, shlex, socket, subprocess
from pathlib import Path

env_path = Path(os.environ["INSTALL_PORT_ENV"])
notice_path = Path(os.environ["INSTALL_PORT_NOTICES"])
try:
    raw = subprocess.run(["/usr/bin/ss", "-H", "-lntup"], capture_output=True, text=True, timeout=8, check=False).stdout
except Exception:
    raw = ""
rows = []
for line in raw.splitlines():
    parts = line.split()
    if len(parts) < 5:
        continue
    proto = parts[0].lower()
    match = re.search(r"(?:\]|:)(\d+)$", parts[4])
    if not match:
        continue
    rows.append({
        "proto": proto,
        "port": int(match.group(1)),
        "names": sorted(set(re.findall(r'\("([^"]+)"', line))),
        "pids": sorted({int(v) for v in re.findall(r"pid=(\d+)", line)}),
    })

def occupants(transports, port):
    return [r for r in rows if r["proto"] in transports and r["port"] == port]

def bind_available(transports, port):
    sockets = []
    try:
        for proto in transports:
            kind = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
            sock = socket.socket(socket.AF_INET, kind)
            sockets.append(sock)
            sock.bind(("0.0.0.0", int(port)))
        return True
    except OSError:
        return False
    finally:
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass

def owner_text(items):
    names = sorted({n for item in items for n in item["names"]})
    pids = sorted({pid for item in items for pid in item["pids"]})
    text = ", ".join(names) or "unknown process"
    if pids:
        text += " (pid " + ",".join(map(str, pids)) + ")"
    return text

specs = [
    ("L2TP_INSTALL_PORT", "l2tp", ("udp",), 1701),
    ("OVPN_UDP_INSTALL_PORT", "openvpn", ("udp",), 1194),
    ("OVPN_TCP_INSTALL_PORT", "openvpn", ("tcp",), 1194),
    ("SSTP_INSTALL_PORT", "sstp", ("tcp",), 4433),
    ("OPENCONNECT_INSTALL_PORT", "openconnect", ("tcp", "udp"), 8443),
]
# Never allocate product control/fixed-standard ports as fallbacks.
reserved = {
    ("tcp", int(os.environ.get("PANEL_PORT", "8080"))),
    ("tcp", int(os.environ.get("BACKEND_PORT", "18000"))),
    ("tcp", 80), ("tcp", 443), ("tcp", 1723),
    ("udp", 500), ("udp", 4500),
}
for _, _, transports, default in specs:
    reserved.update((proto, default) for proto in transports)

rng = random.SystemRandom()
selected = {}
notices = []
for env_name, protocol, transports, default in specs:
    busy = occupants(transports, default)
    bind_busy = not bind_available(transports, default)
    if not busy and not bind_busy:
        chosen = default
    else:
        chosen = None
        for _ in range(5000):
            candidate = rng.randint(20000, 55000)
            if all(not occupants((proto,), candidate) and (proto, candidate) not in reserved for proto in transports) and bind_available(transports, candidate):
                chosen = candidate
                break
        if chosen is None:
            for candidate in range(20000, 55001):
                if all(not occupants((proto,), candidate) and (proto, candidate) not in reserved for proto in transports) and bind_available(transports, candidate):
                    chosen = candidate
                    break
        if chosen is None:
            raise SystemExit(f"No free fallback port for {protocol}")
        notices.append({
            "protocol": protocol,
            "setting": {
                "l2tp": "l2tp_port",
                "sstp": "sstp_port",
                "openconnect": "openconnect_port",
            }.get(protocol, "openvpn_udp_port" if env_name == "OVPN_UDP_INSTALL_PORT" else "openvpn_tcp_port"),
            "transport": "both" if len(transports) == 2 else transports[0],
            "old_port": default,
            "new_port": chosen,
            "owner": owner_text(busy),
            "owner_pids": sorted({pid for item in busy for pid in item["pids"]}),
            "warning": "Native L2TP clients must be configured to use the custom server port." if protocol == "l2tp" else "",
        })
    selected[env_name] = chosen
    reserved.update((proto, chosen) for proto in transports)

env_path.write_text("".join(f"{key}={shlex.quote(str(value))}\n" for key, value in selected.items()), encoding="utf-8")
notice_path.write_text(json.dumps(notices, ensure_ascii=False), encoding="utf-8")
PYPORTS
# shellcheck disable=SC1090
source "$INSTALL_PORT_ENV"
for pair in \
  "L2TP/UDP:${L2TP_INSTALL_PORT}" \
  "OpenVPN/UDP:${OVPN_UDP_INSTALL_PORT}" \
  "OpenVPN/TCP:${OVPN_TCP_INSTALL_PORT}" \
  "SSTP/TCP:${SSTP_INSTALL_PORT}" \
  "OpenConnect/TCP+UDP:${OPENCONNECT_INSTALL_PORT}"; do
  echo "[*] Fresh-install listener ${pair}"
done
if [ -s "$INSTALL_PORT_NOTICES" ] && [ "$(cat "$INSTALL_PORT_NOTICES")" != "[]" ]; then
  echo "[!] One or more default protocol ports were occupied; free replacements were selected." >&2
  python3 - "$INSTALL_PORT_NOTICES" <<'PYNOTICE'
import json, sys
for item in json.load(open(sys.argv[1], encoding="utf-8")):
    print(f"[port] {item['protocol']}: {item['old_port']}/{item['transport'].upper()} occupied by {item['owner']} -> {item['new_port']}")
    if item.get("warning"):
        print(f"[port] WARNING: {item['warning']}")
PYNOTICE
fi

# ---------------------------------------------------------------------------
# 2) Enable IP forwarding
# ---------------------------------------------------------------------------
sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.conf
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -p

NET_IFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
echo "[*] Main network interface: ${NET_IFACE}"

# ---------------------------------------------------------------------------
# 3) strongSwan config for L2TP/IPsec
# ---------------------------------------------------------------------------
cat > /etc/ipsec.conf << EOF
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

conn %default
    ikelifetime=60m
    keylife=20m
    rekeymargin=3m
    keyingtries=1
    keyexchange=ikev1

conn L2TP-PSK
    authby=secret
    left=%defaultroute
    leftprotoport=17/${L2TP_INSTALL_PORT}
    right=%any
    rightprotoport=17/%any
    type=transport
    # اغلب سرورهای ابری پشت نوعی NAT مجازی قرار دارند؛ بدون forceencaps فاز
    # IKE/IPsec ممکن است بی‌صدا شکست بخورد و از دید کلاینت مثل این باشد که
    # هیچ‌چیزی روی سرور در حال گوش دادن نیست (تایم‌اوت کامل).
    forceencaps=yes
    auto=add
EOF

cat > /etc/ipsec.secrets << EOF
: PSK "${IPSEC_PSK}"
EOF
chmod 600 /etc/ipsec.secrets

# ---------------------------------------------------------------------------
# 3b) L2TP kernel modules — xl2tpd needs l2tp_ppp/l2tp_netlink (which pull in
# l2tp_core) to open its tunnel socket. On a lot of stock cloud-VPS kernels
# these aren't loaded by default, which makes the xl2tpd unit fail to start
# with a generic "control process exited with error code" (no useful detail
# in the journal beyond that). Load them now AND persist via
# /etc/modules-load.d so they come back automatically after every reboot,
# not just on this install run.
# ---------------------------------------------------------------------------
cat > /etc/modules-load.d/l2tp.conf << EOF
l2tp_ppp
l2tp_netlink
EOF
modprobe l2tp_ppp 2>/dev/null || true
modprobe l2tp_netlink 2>/dev/null || true
if ! lsmod | grep -q '^l2tp_ppp'; then
  echo "[!] WARNING: l2tp_ppp kernel module could not be loaded. This kernel" >&2
  echo "    may lack L2TP support (common on some OpenVZ/LXC-based VPS" >&2
  echo "    providers) - xl2tpd will fail to start until this is resolved" >&2
  echo "    at the host/kernel level." >&2
fi

# ---------------------------------------------------------------------------
# 4) xl2tpd config
# ---------------------------------------------------------------------------
mkdir -p /etc/xl2tpd
cat > /etc/xl2tpd/xl2tpd.conf << EOF
[global]
port = ${L2TP_INSTALL_PORT}
; xl2tpd's kernel-mode L2TP (pppol2tp.so plugin) has a known incompatibility
; where pppd cannot resolve the negotiated local/remote IP through the kernel
; offload path, causing CHAP/MSCHAPv2 auth to fail with "couldn't find any
; suitable secret" regardless of chap-secrets content. Forcing userspace mode
; avoids this; CPU overhead is negligible at the scale this panel targets.
force userspace = yes
; هر کلاینت L2TP هنگام برقراری تونل (پیام SCCRQ) دو AVP اختیاری «Host Name» و
; «Vendor Name» می‌فرستد که پیاده‌سازی خودش را معرفی می‌کند - مثلاً روترهای
; MikroTik هر دو را دقیقاً "MikroTik" می‌فرستند. با روشن‌بودن این گزینه xl2tpd
; مقدار همین AVPها را در syslog/journal چاپ می‌کند (خط‌هایی مثل
; "vendor_avp: peer reports vendor 'MikroTik'")؛ ppp_ip_up.sh همان خط را
; می‌خواند تا پلتفرم واقعیِ اعلام‌شده توسط کلاینت L2TP را هم (مثل کاری که
; OpenVPN با IV_PLAT انجام می‌دهد) در پنل ثبت کند. سربار این گزینه ناچیز است.
debug avp = yes
; برخی مودم‌های embedded مانند X28 پیام Hello دوره‌ای xl2tpd را ACK نمی‌کنند؛
; مقدار پایین باعث می‌شود سرور دقیقاً حدود دو دقیقه بعد تونل سالم را ببندد.
; پنل handover را جداگانه و بعد از آماده‌شدن PPP جدید انجام می‌دهد، بنابراین
; retry بالا از سکته‌ی دوره‌ای جلوگیری می‌کند و تونل قدیمی نیز بعد از جایگزینی پاک می‌شود.
max retries = 100
cap backoff = 60

[lns default]
ip range = ${L2TP_SUBNET}.10-${L2TP_SUBNET}.250
local ip = ${L2TP_SUBNET}.1
require chap = yes
refuse pap = yes
require authentication = yes
name = VPNPanelL2TP
ppp debug = no
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
; نکته: «ipparam» (بدون فاصله) خودش یک فیلد معتبر داخل xl2tpd.conf نیست
; (پارس‌کننده‌ی خودِ xl2tpd با «Unknown field 'ipparam'» کل فایل را رد می‌کند
; و سرویس اصلاً بالا نمی‌آید - یک نسخه‌ی قدیمی‌تر پنل دقیقاً همین اشتباه را
; داشت). نام درستِ گزینه‌ای که واقعاً همین کار (پاس‌دادن آی‌پی پابلیک واقعی
; کلاینت به pppd به‌عنوان ipparam، یعنی همان $6 در ppp_ip_up.sh) را انجام
; می‌دهد طبق مستندات رسمی xl2tpd «pass peer» است. طبق همان مستندات این گزینه
; پیش‌فرض روشن است، اما در عمل (مخصوصاً با IPsec NAT-T/forceencaps) دیده شده
; که به این پیش‌فرض ضمنی نمی‌شود اعتماد کرد - پس اینجا صریح ست می‌شود.
pass peer = yes
EOF

cat > /etc/ppp/options.xl2tpd << EOF
name l2tpd
require-mschap-v2
ms-dns 1.1.1.1
ms-dns 8.8.8.8
auth
hide-password
ipcp-accept-local
ipcp-accept-remote
nodefaultroute
asyncmap 0
proxyarp
# Echo فقط هنگام بیکاربودن تونل ارسال می‌شود؛ پس ترافیک واقعی DUX28/OpenWrt
# هرگز به‌خاطر keepalive قطع نمی‌شود، ولی اگر روتر بدون اجرای ip-down ناپدید
# شود pppd حداکثر ظرف حدود ۳۰ ثانیه خارج می‌شود و پنل آن را آفلاین می‌کند.
lcp-echo-interval 30
lcp-echo-failure 10
lcp-echo-adaptive
# فشرده‌سازی‌های قدیمی PPP غیرفعال می‌شوند تا دو سر تونل روی مذاکره‌ی یکسان
# و قابل‌پیش‌بینی قرار بگیرند.
nobsdcomp
nodeflate
novj
novjccomp
nopcomp
noaccomp
# L2TP/IPsec سربار زیادی به هر پکت اضافه می‌کند (IP+UDP+ESP+L2TP+PPP، حدود
# ۴۰-۶۰ بایت)، پس MTU واقعی تونل کمتر از ۱۵۰۰ است. بدون اعلام صریح این مقدار
# به کلاینت، پکت‌های بزرگ (مثلاً موقع آپلود) باید فرگمنت شوند یا با ICMP
# "Fragmentation Needed" به کلاینت خبر داده شود؛ خیلی از فایروال/NATها این
# ICMP را بلاک می‌کنند و پکت به‌سادگی گم می‌شود (PMTU black hole) که باعث
# قطع ناگهانی session هنگام آپلود فایل‌های نسبتاً بزرگ می‌شود.
mtu 1400
mru 1400
EOF

# ---------------------------------------------------------------------------
# 5) pptpd config (optional; unavailable on Ubuntu releases without pptpd)
# ---------------------------------------------------------------------------
if [ "$PPTP_SETUP_OK" = "1" ]; then
  cat > /etc/pptpd.conf << EOF
option /etc/ppp/pptpd-options
logwtmp
localip ${PPTP_SUBNET}.1
remoteip ${PPTP_SUBNET}.10-250
EOF

  cat > /etc/ppp/pptpd-options << EOF
name pptpd
ipcp-accept-local
ipcp-accept-remote
nodefaultroute
asyncmap 0
lock
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
require-mppe-128
ms-dns 1.1.1.1
ms-dns 8.8.8.8
proxyarp
nobsdcomp
novj
novjccomp
nologfd
mtu 1400
mru 1400
nodeflate
nopcomp
noaccomp
EOF
  echo "[*] L2TP/IPsec and PPTP configured."
else
  echo "[*] L2TP/IPsec configured. PPTP skipped because pptpd is unavailable."
fi

# ---------------------------------------------------------------------------
# 6) Initial chap-secrets file (auto-generated block managed by the panel)
# ---------------------------------------------------------------------------
touch /etc/ppp/chap-secrets
chmod 600 /etc/ppp/chap-secrets
if ! grep -q "BEGIN-VPN-PANEL-USERS" /etc/ppp/chap-secrets 2>/dev/null; then
  cat >> /etc/ppp/chap-secrets << EOF
# BEGIN-VPN-PANEL-USERS (auto-generated, do not edit manually)
# END-VPN-PANEL-USERS
EOF
fi

# ---------------------------------------------------------------------------
# 7) NAT (routing only, not firewall exposure). This is required for VPN
#    clients to actually reach the internet through the server, regardless
#    of what INPUT/firewall policy the server has - it is NOT the same
#    thing as "opening a port".
# ---------------------------------------------------------------------------
iptables -t nat -C POSTROUTING -s ${L2TP_SUBNET}.0/24 -o ${NET_IFACE} -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s ${L2TP_SUBNET}.0/24 -o ${NET_IFACE} -j MASQUERADE
iptables -t nat -C POSTROUTING -s ${PPTP_SUBNET}.0/24 -o ${NET_IFACE} -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s ${PPTP_SUBNET}.0/24 -o ${NET_IFACE} -j MASQUERADE
iptables -t nat -C POSTROUTING -s ${OVPN_SUBNET_UDP%.*}.0/24 -o ${NET_IFACE} -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s ${OVPN_SUBNET_UDP%.*}.0/24 -o ${NET_IFACE} -j MASQUERADE
iptables -t nat -C POSTROUTING -s ${OVPN_SUBNET_TCP%.*}.0/24 -o ${NET_IFACE} -j MASQUERADE 2>/dev/null || \
  iptables -t nat -A POSTROUTING -s ${OVPN_SUBNET_TCP%.*}.0/24 -o ${NET_IFACE} -j MASQUERADE

# NAT does not override a DROP policy on the FORWARD chain.  Explicitly allow
# traffic out of each panel-managed tunnel and established return traffic.
for subnet in "${L2TP_SUBNET}.0/24" "${PPTP_SUBNET}.0/24" "${OVPN_SUBNET_UDP%.*}.0/24" "${OVPN_SUBNET_TCP%.*}.0/24"; do
  safe_tag=$(echo "$subnet" | tr './' '--')
  iptables -C FORWARD -s "$subnet" -m comment --comment "vpnpanel-${safe_tag}-forward-out" -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -s "$subnet" -m comment --comment "vpnpanel-${safe_tag}-forward-out" -j ACCEPT
  iptables -C FORWARD -d "$subnet" -m conntrack --ctstate ESTABLISHED,RELATED \
    -m comment --comment "vpnpanel-${safe_tag}-forward-in" -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -d "$subnet" -m conntrack --ctstate ESTABLISHED,RELATED \
      -m comment --comment "vpnpanel-${safe_tag}-forward-in" -j ACCEPT
done

# پکت‌های بزرگ TCP (مثلاً موقع آپلود فایل) داخل تونل به سربار L2TP/PPTP/OpenVPN
# می‌خورند و MTU مسیر را رد می‌کنند؛ اگر کلاینت با ICMP "Fragmentation Needed"
# خبردار نشود (که خیلی از فایروال/NATها این ICMP را بلاک می‌کنند) پکت بی‌صدا
# گم می‌شود و اتصال قطع می‌شود. این قانون به‌جای تکیه بر PMTUD، مقدار MSS هر
# اتصال TCP را مستقیماً هنگام عبور از تونل کلمپ (محدود) می‌کند - مستقل از
# پروتکل/سابنت است و روی هر ترافیک فورواردشده اعمال می‌شود.
iptables -t mangle -C FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
  iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

netfilter-persistent save

# ---------------------------------------------------------------------------
# The services below are started and listening on these ports; the actual
# host firewall (INPUT chain) opening for all of them happens further down,
# in step 17b, via configure_vpn_protocols.sh (whichever backend is active -
# ufw/firewalld/plain iptables), plus the panel/SSL ports right after it:
#   - L2TP/IPsec: udp/500, udp/4500, udp/1701
#   - PPTP:       tcp/1723, protocol GRE
#   - OpenVPN:    udp/1194, tcp/1194 (defaults - see Settings > VPN Protocols)
#   - SSTP:       tcp/4433 (default - see Settings > VPN Protocols; kept off
#                 tcp/443 on purpose since that's the panel's own nginx/HTTPS port)
#   - Panel:      tcp/${PANEL_PORT}
#   - SSL/HTTP-01 (certbot, only if you set up a domain later): tcp/80, tcp/443
# This only reaches the machine's own firewall - a cloud provider's network
# firewall (AWS Security Group, Hetzner Cloud Firewall, etc.) still needs
# these same ports opened by hand there.
# ---------------------------------------------------------------------------
echo "[*] NAT/routing configured. Firewall ports for all protocols + the panel"
echo "    will be opened automatically further down."

# ---------------------------------------------------------------------------
# 8) OpenVPN PKI and server config
# ---------------------------------------------------------------------------
EASYRSA_DIR="/etc/openvpn/easy-rsa"
mkdir -p /etc/openvpn/server
# اگر یک اجرای قبلی و ناقص همین اسکریپت تا اینجا رسیده و بعد جایی دیگر شکست
# خورده باشد، ممکن است این پوشه از قبل با یک PKI ناقص وجود داشته باشد.
# make-cadir در آن صورت با «Aborting» شکست می‌خورد، و بدتر از آن،
# «easyrsa init-pki» روی یک PKI از قبل موجود یک تاییدیه‌ی تعاملی
# («Confirm removal: yes») می‌خواهد که وقتی از طریق curl | bash اجرا شده
# (بدون ترمینال واقعی) هرگز نمی‌رسد، اسکریپت را همان‌جا با شکست متوقف
# می‌کند. برای همین همیشه اول از صفر پاک می‌کنیم تا این مرحله idempotent
# باشد (چه این اولین اجرا باشد چه یک retry).
rm -rf "$EASYRSA_DIR"
make-cadir "$EASYRSA_DIR"
cd "$EASYRSA_DIR"

cat > vars << EOF
set_var EASYRSA_ALGO ec
set_var EASYRSA_DIGEST "sha512"
EOF

# EASYRSA_BATCH=1 هم یک لایه‌ی محافظتی اضافه است: حتی اگر به هر دلیل دیگری
# PKI از قبل موجود باشد، easyrsa به‌جای نمایش تاییدیه‌ی تعاملی، خودش آن را
# به‌صورت خودکار «yes» فرض می‌کند به‌جای این‌که منتظر ورودی‌ای بماند که
# هرگز نمی‌رسد.
export EASYRSA_BATCH=1
./easyrsa init-pki
EASYRSA_REQ_CN="VPN-Panel-CA" ./easyrsa build-ca nopass
./easyrsa gen-req server nopass
echo yes | ./easyrsa sign-req server server
./easyrsa gen-dh
openvpn --genkey secret ta.key || openvpn --genkey --secret ta.key
./easyrsa gen-crl

cp pki/ca.crt pki/private/server.key pki/issued/server.crt pki/dh.pem ta.key pki/crl.pem /etc/openvpn/server/
# crl.pem بعد از drop-privileges سرور (کاربر nobody) هم باید خوانده شود؛ محرمانه
# نیست (فقط لیست سریال سرتیفیکیت‌های باطل‌شده)، پس world-readable مشکلی ندارد.
chmod 644 /etc/openvpn/server/crl.pem

mkdir -p /etc/openvpn/server/ccd

# ---------------------------------------------------------------------------
# OpenVPN always runs as TWO simultaneous processes - UDP and TCP - sharing
# the same PKI/CCD/subnet but with their own port, systemd instance,
# management port and status log, so both are independently monitorable and
# restartable. This gives clients a TCP fallback (better at getting through
# restrictive firewalls/DPI) without giving up UDP's lower latency as the
# default choice.
# ---------------------------------------------------------------------------
COMMON_OVPN_CONF="
dev tun

ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0

topology subnet
client-config-dir ccd

push \"redirect-gateway def1 bypass-dhcp\"
push \"dhcp-option DNS 1.1.1.1\"
push \"dhcp-option DNS 8.8.8.8\"

# قبلاً keepalive 10 30 بود (حداکثر ۴۰ ثانیه طول می‌کشید سرور بفهمد کلاینت
# واقعاً قطع شده - در UDP که کلاینت هیچ پیام خداحافظی‌ای نمی‌فرستد این تنها
# راه تشخیص است). با 10/60 پینگ سبک هر ۱۰ ثانیه فرستاده می‌شود و فقط پس از ۶۰ ثانیه
# سکوت واقعی تونل بازنشانی می‌شود؛ این مقدار روی اینترنت موبایل و مسیرهای
# ناپایدار از قطع‌و‌وصل کاذب جلوگیری می‌کند.
keepalive 10 60
cipher AES-256-GCM
auth SHA256
user nobody
group nogroup
persist-key
persist-tun

# Each user gets their own client certificate (issued by the panel via
# easy-rsa, see cert_manager.py) - this is ALWAYS required. verify-client-cert
# defaults to \"required\" once cert/key/ca are set, so no directive is needed
# for that; crl-verify makes sure a deleted user's old .ovpn file stops
# working even if they kept a copy. enable/active/expiry/quota/max-devices
# checks happen in client-connect (openvpn_connect.sh -> panel API).
#
# auth-user-pass-verify adds an OPTIONAL per-user second layer on top of the
# certificate (VpnUser.openvpn_auth_mode, panel Users form). It runs for every
# client (cert_only users just have their own username/password silently
# embedded in their .ovpn so they are never prompted - see
# vpn_manager.build_client_ovpn) and, critically, checks that the submitted
# username matches the Common Name of the certificate that same client just
# TLS-handshaked with (openvpn_auth.sh -> /api/internal/openvpn-auth) - so a
# username/password leaking never lets someone connect as another user
# without also having that user's own certificate.
crl-verify crl.pem
script-security 3
auth-user-pass-verify /opt/vpn-panel/scripts/openvpn_auth.sh via-env
client-connect /opt/vpn-panel/scripts/openvpn_connect.sh
client-disconnect /opt/vpn-panel/scripts/openvpn_disconnect.sh

# بدون این خط، OpenVPN به‌صورت پیش‌فرض اجازه نمی‌دهد دو کلاینت هم‌زمان با
# همان certificate/CN (یعنی همان فایل .ovpn/همان یوزرنیم) وصل باشند: به محض
# اتصال دومی، خودِ OpenVPN (در لایه‌ی TLS، قبل از رسیدن به منطق max_devices
# در openvpn_connect.sh) بلافاصله سشن اولی را قطع می‌کند - مستقل از اینکه
# max_devices کاربر در پنل چند تنظیم شده. duplicate-cn این محدودیت داخلی را
# غیرفعال می‌کند تا محدودیت واقعی فقط همان چیزی باشد که در پنل (max_devices)
# تنظیم شده.
duplicate-cn

log-append /var/log/openvpn.log
verb 3"

cat > /etc/openvpn/server/server-udp.conf << EOF
port ${OVPN_UDP_INSTALL_PORT}
proto udp
server ${OVPN_SUBNET_UDP} ${OVPN_NETMASK}
${COMMON_OVPN_CONF}
ifconfig-pool-persist ipp-udp.txt
management 127.0.0.1 7505
status /etc/openvpn/server/openvpn-status-udp.log 10
explicit-exit-notify 1
EOF

cat > /etc/openvpn/server/server-tcp.conf << EOF
port ${OVPN_TCP_INSTALL_PORT}
proto tcp-server
server ${OVPN_SUBNET_TCP} ${OVPN_NETMASK}
${COMMON_OVPN_CONF}
ifconfig-pool-persist ipp-tcp.txt
management 127.0.0.1 7506
status /etc/openvpn/server/openvpn-status-tcp.log 10
EOF

cd "$PROJECT_ROOT"
echo "[*] OpenVPN configured (UDP ${OVPN_UDP_INSTALL_PORT}, TCP ${OVPN_TCP_INSTALL_PORT})."

# ---------------------------------------------------------------------------
# 8b) SSTP infrastructure (accel-ppp) - optional protocol, best for Windows.
# این یک اسکریپت جدا و idempotent است (install/setup_sstp.sh)؛ کامپایل از
# سورس چند دقیقه طول می‌کشد. اگر به هر دلیلی (مثلاً قطعی شبکه یا خطای
# کامپایل) شکست بخورد، نصب پنل را متوقف نمی‌کند - فقط SSTP غیرفعال می‌ماند و
# بعداً می‌توان دستی با «sudo bash install/setup_sstp.sh» دوباره امتحان کرد.
# ---------------------------------------------------------------------------
echo "[*] Setting up SSTP infrastructure (accel-ppp, this can take a few minutes)..."
SSTP_SETUP_OK=1
bash "$SCRIPT_DIR/setup_sstp.sh" --port="${SSTP_INSTALL_PORT}" || SSTP_SETUP_OK=0
if [ "$SSTP_SETUP_OK" = "1" ]; then
  echo "[*] SSTP infrastructure ready."
else
  echo "[!] SSTP setup failed - continuing without it. The rest of the panel"
  echo "    (L2TP/PPTP/OpenVPN) will still be installed normally. Retry later"
  echo "    with: sudo bash install/setup_sstp.sh"
fi

# ---------------------------------------------------------------------------
# 8c) IKEv2/IPsec (EAP-MSCHAPv2) infrastructure - optional protocol, built on
# top of the strongSwan instance already installed above for L2TP. Same
# idempotent/non-fatal pattern as SSTP: failure here doesn't stop the rest of
# the install.
# ---------------------------------------------------------------------------
echo "[*] Setting up IKEv2/IPsec (EAP-MSCHAPv2) infrastructure..."
IKEV2_SETUP_OK=1
bash "$SCRIPT_DIR/setup_ikev2.sh" || IKEV2_SETUP_OK=0
if [ "$IKEV2_SETUP_OK" = "1" ]; then
  echo "[*] IKEv2 infrastructure ready."
else
  echo "[!] IKEv2 setup failed - continuing without it. Retry later with:"
  echo "    sudo bash install/setup_ikev2.sh"
fi

# ---------------------------------------------------------------------------
# 8d) OpenConnect (ocserv) infrastructure - optional protocol, compatible with
# the Cisco AnyConnect client and the open-source OpenConnect client. Same
# idempotent/non-fatal pattern as SSTP/IKEv2: failure here doesn't stop the
# rest of the install. Unlike SSTP, ocserv installs directly via apt (no
# source build needed).
# ---------------------------------------------------------------------------
echo "[*] Setting up OpenConnect (ocserv) infrastructure..."
OPENCONNECT_SETUP_OK=1
bash "$SCRIPT_DIR/setup_openconnect.sh" --port="${OPENCONNECT_INSTALL_PORT}" || OPENCONNECT_SETUP_OK=0
if [ "$OPENCONNECT_SETUP_OK" = "1" ]; then
  echo "[*] OpenConnect infrastructure ready."
else
  echo "[!] OpenConnect setup failed - continuing without it. Retry later with:"
  echo "    sudo bash install/setup_openconnect.sh"
fi

else
  echo "[*] Management-only mode: protocol provisioning/configuration skipped."
fi

# ---------------------------------------------------------------------------
# 9) MySQL database
# ---------------------------------------------------------------------------
systemctl enable mysql
systemctl start mysql

mysql -u root << EOF
CREATE DATABASE IF NOT EXISTS ${DB_NAME} CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
ALTER USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'localhost';
CREATE USER IF NOT EXISTS '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';
ALTER USER '${DB_USER}'@'127.0.0.1' IDENTIFIED BY '${DB_PASS}';
GRANT ALL PRIVILEGES ON ${DB_NAME}.* TO '${DB_USER}'@'127.0.0.1';
FLUSH PRIVILEGES;
EOF

echo "[*] MySQL database ready."

# ---------------------------------------------------------------------------
# 10) Deploy backend
# ---------------------------------------------------------------------------
mkdir -p "$INSTALL_DIR"
# OpenVPN auth/connect helpers run as nobody:nogroup and must be able to
# traverse the install directory to read panel.env (the file itself remains
# root:nogroup 0640).
chmod o+x "$INSTALL_DIR"
rm -rf "$INSTALL_DIR/backend"
cp -r "$PROJECT_ROOT/backend" "$INSTALL_DIR/backend"

# نسخه‌ی نصب‌شده فقط از فایل VERSION داخل خود بسته گرفته می‌شود.
# فیلدهای نمایشی پنل لایسنس حق ندارند این مقدار را بازنویسی کنند؛ در غیر
# این صورت برچسب‌هایی مثل «5» باعث می‌شوند پنل برای همیشه آپدیت جدید نشان دهد.
if [ -f "$PROJECT_ROOT/VERSION" ]; then
  cp "$PROJECT_ROOT/VERSION" "$INSTALL_DIR/VERSION"
else
  echo "0.0.0" > "$INSTALL_DIR/VERSION"
fi
sed -i 's/[[:space:]]*$//' "$INSTALL_DIR/VERSION"
if printf '%s' "${VPN_PANEL_PACKAGE_SHA256:-}" | grep -Eq '^[0-9a-fA-F]{64}$'; then
  printf '%s\n' "${VPN_PANEL_PACKAGE_SHA256,,}" > "$INSTALL_DIR/.last-applied-package.sha256"
  chmod 0600 "$INSTALL_DIR/.last-applied-package.sha256"
fi

mkdir -p "$INSTALL_DIR/scripts"
cp "$INSTALL_DIR/backend/app/scripts/"*.sh "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/setup_domain_ssl.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/setup_sub_domain_ssl.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/setup_xray_sub_domain_ssl.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/setup_vpn_domain_ssl.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/setup_ikev2.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/setup_ikev2_ssl.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/setup_openconnect.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/change_panel_port.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/change_sub_domain_port.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/change_xray_sub_domain_port.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/disable_xray_sub_domain.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/reset_admin_password.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/configure_vpn_protocols.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/check_vpn_domain.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/manage_openvpn_extra_ports.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/update_from_license.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/install_protocol.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/apt_preflight.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/npm_safe.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/setup_infrastructure.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/setup_core_protocol.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/setup_pptp.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/setup_sstp.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/setup_xray.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/repair_classic_ppp_protocols.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/audit_protocol_dns.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/apply_classic_ppp_hotfix.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/repair_protocols_after_update.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/connect_node_controller.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/bootstrap_host.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/node_registration_retry.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/repair_node_public_access.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/repair_panel_access.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/reconfigure_deployment.sh" "$INSTALL_DIR/scripts/"
cp "$SCRIPT_DIR/ensure_openvpn_controller_pki.sh" "$INSTALL_DIR/scripts/"
chmod +x "$INSTALL_DIR/scripts/"*.sh

# Fresh management-only controllers have no local OpenVPN listener, but they
# must still create the one canonical PKI that all future nodes will receive.
if [ "$SERVER_ROLE" = "main" ] && [ "$INSTALL_LOCAL_SERVICES" = "0" ]; then
  echo "[*] Preparing controller-wide OpenVPN PKI for multi-node profiles..."
  "$INSTALL_DIR/scripts/ensure_openvpn_controller_pki.sh" --generate-if-missing
fi

cat > "$INSTALL_DIR/panel.env" << EOF
INTERNAL_API_TOKEN=${INTERNAL_TOKEN}
PANEL_PORT=${PANEL_PORT}
BACKEND_PORT=${BACKEND_PORT}
SERVER_ROLE=${SERVER_ROLE}
DEPLOYMENT_ROLE=${SERVER_ROLE}
INSTALL_LOCAL_SERVICES=${INSTALL_LOCAL_SERVICES}
NODE_CONTROLLER_URL=${CONTROLLER_URL}
NODE_PUBLIC_URL=${NODE_PUBLIC_URL}
EOF
chown root:nogroup "$INSTALL_DIR/panel.env"
chmod 640 "$INSTALL_DIR/panel.env"
# Repair only L2TP/PPTP/SSTP after all of their hooks and helper scripts are
# present. Other protocol configurations are deliberately excluded.
if [ -x "$INSTALL_DIR/scripts/repair_classic_ppp_protocols.sh" ]; then
  "$INSTALL_DIR/scripts/repair_classic_ppp_protocols.sh" || \
    echo "[!] Warning: classic PPP repair could not be completed during install" >&2
fi

# NOTE: OpenVPN's server process drops privileges to user 'nobody'/group 'nogroup'
# (see "user nobody" / "group nogroup" in server.conf below). openvpn_connect.sh runs
# as that user and needs to read this file to get INTERNAL_API_TOKEN. 600 root:root
# would make it unreadable for that process, and every connection would then get
# rejected by openvpn_connect.sh's own HTTP-code check (treated as "denied").
# 640 root:nogroup keeps it unreadable to other users while still letting the
# OpenVPN process (group nogroup) read it.

cat > "$INSTALL_DIR/backend/.env" << EOF
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=${DB_NAME}
DB_USER=${DB_USER}
DB_PASSWORD=${DB_PASS}

JWT_SECRET=${JWT_SECRET}
JWT_ALGORITHM=HS256
JWT_EXPIRE_MINUTES=1440

INTERNAL_API_TOKEN=${INTERNAL_TOKEN}
DATA_ENCRYPTION_KEY=${DATA_ENCRYPTION_KEY}
BACKUP_MAX_COMPRESSED_BYTES=134217728
BACKUP_MAX_DECOMPRESSED_BYTES=805306368
BACKEND_PORT=${BACKEND_PORT}

PUBLIC_SERVER_IP=${PUBLIC_IP}
SERVER_ROLE=${SERVER_ROLE}
DEPLOYMENT_ROLE=${SERVER_ROLE}
INSTALL_LOCAL_SERVICES=${INSTALL_LOCAL_SERVICES}
NODE_CONTROLLER_URL=${CONTROLLER_URL}
IPSEC_PSK=${IPSEC_PSK}

CHAP_SECRETS_PATH=/etc/ppp/chap-secrets
OPENVPN_STATUS_LOG=/etc/openvpn/server/openvpn-status.log
OPENVPN_CCD_DIR=/etc/openvpn/server/ccd

MONITOR_INTERVAL_SECONDS=4

LICENSE_SERVER_URL=${LICENSE_SERVER_URL}
LICENSE_API_KEY=${LICENSE_API_KEY}
LICENSE_CHECK_INTERVAL_SECONDS=3
LICENSE_GRACE_PERIOD_HOURS=72
LICENSE_FAIL_CLOSED=true
LICENSE_ALLOW_UNLICENSED_DEVELOPMENT=${LICENSE_DEV_MODE}

CORS_ALLOWED_ORIGINS=
CORS_ALLOW_CREDENTIALS=true
SSH_KNOWN_HOSTS_PATH=/var/lib/vpn-panel/ssh_known_hosts
SSH_HOST_KEY_POLICY=tofu
EOF
chown root:nogroup "$INSTALL_DIR/backend/.env"
chmod 0640 "$INSTALL_DIR/backend/.env"

# OpenVPN runs auth/connect hooks as an unprivileged account. Generate a
# minimal, group-readable runtime file instead of requiring access to the full
# panel.env. This also avoids nogroup/nobody naming differences across distros.
if [ -x "$INSTALL_DIR/scripts/refresh_openvpn_runtime_env.sh" ]; then
  "$INSTALL_DIR/scripts/refresh_openvpn_runtime_env.sh"
fi

cd "$INSTALL_DIR/backend"
python3 -m venv venv
source venv/bin/activate
WHEEL_DIR="$PROJECT_ROOT/vendor/wheels"
WHEEL_MANIFEST="$PROJECT_ROOT/vendor/wheels.sha256"
if [ -d "$WHEEL_DIR" ] && [ -s "$WHEEL_MANIFEST" ]; then
  echo "[*] Installing verified bundled Python dependencies..."
  (cd "$PROJECT_ROOT/vendor" && sha256sum -c wheels.sha256 >/dev/null) || {
    echo "ERROR: bundled Python wheel checksum verification failed" >&2
    exit 1
  }
  pip install --disable-pip-version-check --no-input \
    --no-index --find-links "$WHEEL_DIR" --only-binary=:all: \
    -r requirements.txt
else
  echo "[*] Compact full package detected; downloading Python dependencies..."
  pip install --disable-pip-version-check --no-input --upgrade pip setuptools wheel
  pip install --disable-pip-version-check --no-input -r requirements.txt
fi
pip check
sha256sum requirements.txt | awk '{print $1}' > "$INSTALL_DIR/.backend-requirements.sha256"
deactivate

# Fail here with the actual Python/database error instead of starting a
# restart-looping systemd service and reporting only a generic 78% failure.
echo "[*] Validating backend settings and database connectivity..."
if ! (
  cd "$INSTALL_DIR/backend"
  ./venv/bin/python - <<'PYBACKENDPREFLIGHT'
from app.config import get_settings
from app.database import engine
from app.services.security_hardening import validate_runtime_security
settings = get_settings()
validate_runtime_security(settings)
with engine.connect() as connection:
    connection.exec_driver_sql("SELECT 1")
print(f"settings-ok db={settings.DB_HOST}:{settings.DB_PORT}/{settings.DB_NAME} backend_port={settings.BACKEND_PORT}")
PYBACKENDPREFLIGHT
); then
  echo "ERROR: backend settings/database preflight failed." >&2
  echo "       Check $INSTALL_DIR/backend/.env and the MySQL service above." >&2
  exit 1
fi
cd "$PROJECT_ROOT"

echo "[*] Backend deployed and validated."

# ---------------------------------------------------------------------------
# 11) Hook ppp and openvpn connect/disconnect scripts
# ---------------------------------------------------------------------------
if [ "$INSTALL_LOCAL_SERVICES" = "1" ]; then
  mkdir -p /etc/ppp/ip-up.d /etc/ppp/ip-down.d
  cp "$INSTALL_DIR/scripts/ppp_ip_up.sh" /etc/ppp/ip-up.d/vpn-panel
  cp "$INSTALL_DIR/scripts/ppp_ip_down.sh" /etc/ppp/ip-down.d/vpn-panel
  chmod +x /etc/ppp/ip-up.d/vpn-panel /etc/ppp/ip-down.d/vpn-panel
  echo "[*] Connection hook scripts installed."
else
  echo "[*] Management-only mode: connection hooks skipped."
fi

# Branding images are persistent data, not application code. Prepare the
# directory before the API starts so image uploads work on a fresh server.
install -d -m 0755 /var/lib/vpn-panel/branding

# ---------------------------------------------------------------------------
# 12) systemd service for the backend (FastAPI/uvicorn)
# ---------------------------------------------------------------------------
cat > /etc/systemd/system/vpn-panel-api.service << EOF
[Unit]
Description=VPN Panel API
After=network.target mysql.service

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}/backend
EnvironmentFile=-${INSTALL_DIR}/backend/.env
EnvironmentFile=-${INSTALL_DIR}/panel.env
Environment="PATH=${INSTALL_DIR}/backend/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="RUN_BACKGROUND_JOBS=0"
ExecStart=${INSTALL_DIR}/backend/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port ${BACKEND_PORT} --workers 1
Restart=always
RestartSec=3
TimeoutStopSec=20

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/vpn-panel-background.service << EOF
[Unit]
Description=VPN Panel background scheduler and Telegram controller
After=network-online.target mysql.service vpn-panel-api.service
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}/backend
EnvironmentFile=-${INSTALL_DIR}/backend/.env
EnvironmentFile=-${INSTALL_DIR}/panel.env
Environment="PATH=${INSTALL_DIR}/backend/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="PYTHONPATH=${INSTALL_DIR}/backend"
ExecStart=${INSTALL_DIR}/backend/venv/bin/python -m app.background_runner
Restart=always
RestartSec=5
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable vpn-panel-api vpn-panel-background
systemctl restart vpn-panel-api
systemctl restart vpn-panel-background
HEALTH_OK=0
for _ in $(seq 1 90); do
  if curl -fsS --connect-timeout 1 --max-time 2 "http://127.0.0.1:${BACKEND_PORT}/api/health" >/dev/null 2>&1; then
    HEALTH_OK=1
    break
  fi
  if systemctl is-failed --quiet vpn-panel-api; then
    break
  fi
  sleep 1
done
if [ "$HEALTH_OK" -ne 1 ]; then
  echo "ERROR: VPN Panel API failed to become healthy on 127.0.0.1:${BACKEND_PORT}." >&2
  systemctl status vpn-panel-api --no-pager -l >&2 || true
  journalctl -u vpn-panel-api -n 160 --no-pager -l >&2 || true
  echo "[*] Direct backend import diagnostic:" >&2
  (cd "$INSTALL_DIR/backend" && ./venv/bin/python -c 'import app.main; print("app.main import ok")') >&2 || true
  exit 1
fi

if ! systemctl is-active --quiet vpn-panel-background; then
  echo "ERROR: VPN Panel background service failed to start." >&2
  systemctl status vpn-panel-background --no-pager -l >&2 || true
  journalctl -u vpn-panel-background -n 160 --no-pager -l >&2 || true
  exit 1
fi
echo "[*] API is healthy and background jobs are isolated in vpn-panel-background.service."

# Keep forwarding/NAT for every installed VPN pool ahead of provider/UFW
# rule changes after reboots. The script discovers live configs and is safe
# when only a subset of protocols is installed.
if [ "$INSTALL_LOCAL_SERVICES" = "1" ] && [ -x "$INSTALL_DIR/scripts/repair_runtime_networking.sh" ]; then
  cat > /etc/systemd/system/vpn-panel-network-repair.service << EOF
[Unit]
Description=VPN Panel runtime routing repair for all VPN pools
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${INSTALL_DIR}/scripts/repair_runtime_networking.sh --network-only
EOF
  cat > /etc/systemd/system/vpn-panel-network-repair.timer << 'EOF'
[Unit]
Description=Periodically verify VPN Panel routing

[Timer]
OnBootSec=20s
OnUnitActiveSec=5min
AccuracySec=5s
Persistent=true
Unit=vpn-panel-network-repair.service

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  systemctl enable --now vpn-panel-network-repair.timer >/dev/null 2>&1 || true
  systemctl start vpn-panel-network-repair.service || true
  if [ -x "$INSTALL_DIR/scripts/repair_vpn_ingress.sh" ]; then
    "$INSTALL_DIR/scripts/repair_vpn_ingress.sh" || echo "[!] VPN ingress verification reported an incomplete listener/firewall state" >&2
  fi
fi

# ---------------------------------------------------------------------------
# 13) Deploy frontend
# ---------------------------------------------------------------------------
cd "$PROJECT_ROOT/frontend"
if vpn_panel_verify_bundled_frontend "$PROJECT_ROOT/frontend"; then
  echo "[*] Verified bundled production frontend; npm build skipped."
  vpn_panel_deploy_bundled_frontend "$PROJECT_ROOT/frontend" "$WEB_DIR"
  sha256sum dist.sha256 | awk '{print $1}' > "$INSTALL_DIR/.frontend-bundle.sha256"
else
  echo "[!] Bundled frontend is unavailable or invalid; falling back to a local npm build." >&2
  vpn_panel_npm_install_frontend "$PROJECT_ROOT/frontend"
  vpn_panel_npm_build_frontend "$PROJECT_ROOT/frontend"
  mkdir -p "$WEB_DIR"
  rm -rf "${WEB_DIR:?}"/*
  cp -a dist/. "$WEB_DIR/"
fi
cat package.json package-lock.json 2>/dev/null | sha256sum | awk '{print $1}' > "$INSTALL_DIR/.frontend-dependencies.sha256"
find src -type f -print0 | sort -z | xargs -0 cat | cat - index.html vite.config.js tailwind.config.js postcss.config.js 2>/dev/null | sha256sum | awk '{print $1}' > "$INSTALL_DIR/.frontend-source.sha256"
cd "$PROJECT_ROOT"

echo "[*] Frontend built and deployed."

# ---------------------------------------------------------------------------
# 14) Nginx config (IP-based, HTTP only for now — SSL/domain is set up later
#     from inside the panel under Settings > Domain & SSL)
# ---------------------------------------------------------------------------
cat > /etc/nginx/sites-available/vpn-panel << EOF
server {
    listen ${PANEL_PORT};
    listen [::]:${PANEL_PORT};
    server_name _;

    root ${WEB_DIR};
    index index.html;

    location /api/ {
        client_max_body_size 256m;
        client_body_timeout 120s;
        proxy_pass http://127.0.0.1:${BACKEND_PORT}/api/;
        proxy_set_header Host \$http_host;
        proxy_set_header X-Forwarded-Host \$http_host;
        proxy_set_header X-Forwarded-Port \$server_port;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header CF-Connecting-IP \$http_cf_connecting_ip;
        proxy_set_header True-Client-IP \$http_true_client_ip;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 200s;
        proxy_send_timeout 200s;
        proxy_read_timeout 200s;
    }

    # VPN Panel frontend cache policy v2.3.148
    location = /index.html {
        add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0" always;
        add_header Pragma "no-cache" always;
        add_header Expires "0" always;
        try_files /index.html =404;
    }

    location ^~ /assets/ {
        add_header Cache-Control "public, max-age=31536000, immutable" always;
        try_files \$uri =404;
    }

    location / {
        add_header Cache-Control "no-store, no-cache, must-revalidate, max-age=0" always;
        try_files \$uri \$uri/ /index.html;
    }
}
EOF

ln -sf /etc/nginx/sites-available/vpn-panel /etc/nginx/sites-enabled/vpn-panel
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable nginx
if ! systemctl restart nginx; then
  echo "ERROR: Nginx could not start on the selected panel port tcp/${PANEL_PORT}." >&2
  echo "[diagnostic] Current listeners on tcp/${PANEL_PORT}:" >&2
  ss -ltnp 2>/dev/null | grep -E ":${PANEL_PORT}[[:space:]]" >&2 || true
  echo "[diagnostic] Recent Nginx log:" >&2
  journalctl -u nginx -n 40 --no-pager >&2 || true
  exit 1
fi

echo "[*] Nginx configured on public tcp/${PANEL_PORT}."

# Open every host-level port used by the panel and installed VPN protocols.
# This is idempotent and supports UFW, firewalld and plain iptables.
if [ "$INSTALL_LOCAL_SERVICES" = "1" ]; then
  vpn_panel_prepare_firewall \
    "$PANEL_PORT" "$L2TP_INSTALL_PORT" "$OVPN_UDP_INSTALL_PORT" "$OVPN_TCP_INSTALL_PORT" \
    "$SSTP_INSTALL_PORT" "$OPENCONNECT_INSTALL_PORT"
else
  echo "[*] Management-only mode: VPN firewall ports were left closed; panel web ports are handled below."
fi

# ---------------------------------------------------------------------------
# 15) Create initial panel admin
# ---------------------------------------------------------------------------
cd "$INSTALL_DIR/backend"
source venv/bin/activate
python3 -m app.init_admin "${ADMIN_USER}" "${ADMIN_PASS}"
if [ -n "$LICENSE_SERVER_URL" ]; then
  echo "[*] Checking license..."
  python3 -m app.init_license "${LICENSE_KEY}" || true
fi
python3 - << PYEOF
from app.database import SessionLocal
from app.models import Setting
db = SessionLocal()
defaults = {
    "panel_port": "${PANEL_PORT}",
    "backend_port": "${BACKEND_PORT}",
    "server_role": "${SERVER_ROLE}",
    "deployment_role": "${SERVER_ROLE}",
    "local_services_mode": "${INSTALL_LOCAL_SERVICES}",
    "node_controller_url": "${CONTROLLER_URL}",
    "node_public_url": "${NODE_PUBLIC_URL}",
    "l2tp_enabled": "${INSTALL_LOCAL_SERVICES}",
    "l2tp_port": "${L2TP_INSTALL_PORT}",
    "pptp_enabled": "${PPTP_SETUP_OK}",
    "openvpn_enabled": "${INSTALL_LOCAL_SERVICES}",
    "openvpn_udp_port": "${OVPN_UDP_INSTALL_PORT}",
    "openvpn_tcp_port": "${OVPN_TCP_INSTALL_PORT}",
    "openvpn_dns1": "1.1.1.1",
    "openvpn_dns2": "8.8.8.8",
    "openconnect_enabled": "${OPENCONNECT_SETUP_OK}",
    "openconnect_port": "${OPENCONNECT_INSTALL_PORT}",
    "openconnect_dns1": "8.8.8.8",
    "openconnect_dns2": "1.1.1.1",
    "ikev2_enabled": "${IKEV2_SETUP_OK}",
    "sstp_enabled": "${SSTP_SETUP_OK}",
    "sstp_port": "${SSTP_INSTALL_PORT}",
    "vmess_enabled": "0",
    "vless_enabled": "0",
    "auto_port_fallback_enabled": "1",
    "auto_port_fallback_min": "20000",
    "auto_port_fallback_max": "55000",
}
for key, value in defaults.items():
    if not db.query(Setting).filter(Setting.key == key).first():
        db.add(Setting(key=key, value=value))

# Keep fresh-install port replacements visible on the corresponding protocol
# cards after the installer exits.
import json, os
notice_path = os.environ.get("INSTALL_PORT_NOTICES", "")
try:
    items = json.load(open(notice_path, encoding="utf-8")) if notice_path else []
except Exception:
    items = []
by_protocol = {}
for item in items:
    by_protocol.setdefault(item.get("protocol", ""), []).append(item)
from datetime import datetime, timezone
for protocol, changes in by_protocol.items():
    if not protocol:
        continue
    key = f"protocol_port_notice_{protocol}"
    payload = json.dumps({
        "protocol": protocol,
        "changed": changes,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }, ensure_ascii=False)
    row = db.query(Setting).filter(Setting.key == key).first()
    if row:
        row.value = payload
    else:
        db.add(Setting(key=key, value=payload))
db.commit()
db.close()
PYEOF
deactivate
cd "$PROJECT_ROOT"

# Register this installation on the selected controller. DNS propagation or a
# provider firewall may not be ready at this exact second, so a secure systemd
# retry timer is installed. No manual command is required after installation.
if [ "$SERVER_ROLE" = "node" ]; then
  cat > /etc/systemd/system/vpn-panel-node-register.service <<EOF
[Unit]
Description=Register VPN Panel node on its main controller
After=network-online.target vpn-panel-api.service nginx.service
Wants=network-online.target

[Service]
Type=oneshot
WorkingDirectory=${INSTALL_DIR}/backend
Environment="PYTHONPATH=${INSTALL_DIR}/backend"
ExecStart=${INSTALL_DIR}/scripts/node_registration_retry.sh
TimeoutStartSec=420
EOF
  cat > /etc/systemd/system/vpn-panel-node-register.timer <<'EOF'
[Unit]
Description=Retry VPN Panel node registration until it succeeds

[Timer]
OnBootSec=90s
OnUnitActiveSec=2min
RandomizedDelaySec=20s
Persistent=true
Unit=vpn-panel-node-register.service

[Install]
WantedBy=timers.target
EOF
  systemctl daemon-reload
  echo "[*] Registering this server as a node on ${CONTROLLER_URL} ..."
  if [ -z "$CONTROLLER_URL" ] || [ -z "$CONTROLLER_TOKEN" ] || [ -z "$NODE_PUBLIC_URL" ]; then
    echo "ERROR: node mode requires controller URL, controller token and node public URL." >&2
    exit 1
  elif "$INSTALL_DIR/scripts/connect_node_controller.sh" "$CONTROLLER_URL" "$CONTROLLER_TOKEN" "${NODE_NAME:-$(hostname -s)}" "$NODE_PUBLIC_URL" "$CONTROLLER_VERIFY_TLS" "$NODE_VERIFY_TLS"; then
    date -u +%FT%TZ > /var/lib/vpn-panel/node-registration.ok
    chmod 0600 /var/lib/vpn-panel/node-registration.ok
    systemctl disable --now vpn-panel-node-register.timer >/dev/null 2>&1 || true
    echo "[*] Node connected to the main panel successfully."
  else
    systemctl enable --now vpn-panel-node-register.timer
    echo "[!] Immediate node registration is pending. The panel will retry automatically every two minutes until DNS/network access is ready." >&2
  fi
fi

if [ "$INSTALL_LOCAL_SERVICES" = "1" ]; then
# ---------------------------------------------------------------------------
# 15b) Xray binary and isolated VMess/VLESS services.  Both protocol services
# are installed and validated now, but remain stopped until enabled from the
# panel (their fresh-install database defaults are intentionally 0).
# ---------------------------------------------------------------------------
echo "[*] Installing Xray infrastructure for VMess and VLESS..."
XRAY_SETUP_OK=1
if ! bash "$SCRIPT_DIR/setup_xray.sh" --protocol=both; then
  XRAY_SETUP_OK=0
  echo "[!] WARNING: Xray installation failed. The rest of the panel will continue; retry from Protocol Center." >&2
fi

# ---------------------------------------------------------------------------
# 16) Sample OpenVPN client profile (generic only - each real user needs
#     their own certificate, downloaded per-user from the panel)
# ---------------------------------------------------------------------------
mkdir -p "$INSTALL_DIR/client-templates"
CA_CONTENT=$(cat /etc/openvpn/server/ca.crt)
TA_CONTENT=$(cat /etc/openvpn/server/ta.key)

cat > "$INSTALL_DIR/client-templates/client.ovpn" << EOF
# این یک نمونه‌ی عمومی است و به‌تنهایی کار نمی‌کند: هر کاربر یک سرتیفیکیت
# اختصاصی لازم دارد (بدون یوزر/پس - فقط سرتیفیکیت). فایل .ovpn واقعی هر
# کاربر را از پنل > کاربران > دانلود کانفیگ OpenVPN همان کاربر بگیرید.
client
dev tun
remote ${PUBLIC_IP} ${OVPN_UDP_INSTALL_PORT} udp
remote ${PUBLIC_IP} ${OVPN_TCP_INSTALL_PORT} tcp-client
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
verb 3

<ca>
${CA_CONTENT}
</ca>

<tls-auth>
${TA_CONTENT}
</tls-auth>
key-direction 1
EOF

echo "[*] Sample OpenVPN profile written to ${INSTALL_DIR}/client-templates/client.ovpn"

# ---------------------------------------------------------------------------
# 17) Start all services
# ---------------------------------------------------------------------------
systemctl restart strongswan-starter 2>/dev/null || systemctl restart strongswan 2>/dev/null || ipsec restart
# ---------------------------------------------------------------------------
# OpenVPN's stock systemd unit (shipped by the distro's openvpn package) sets
# LimitNPROC=10 for the openvpn-server@ template. That RLIMIT_NPROC applies
# to the "nobody" UID that OpenVPN drops privileges to (user nobody/group
# nogroup above) - and it's shared across ALL instances (UDP, TCP, any extra
# ports) system-wide, since RLIMIT_NPROC is per-UID, not per-service. With
# client-connect/client-disconnect/auth-user-pass-verify each forking a
# bash+curl process on every connection attempt, 10 is nowhere near enough:
# it fills up almost immediately and every subsequent connect fails with
# "openvpn_execve: unable to fork: Resource temporarily unavailable
# (errno=11)" - the client hangs at "Getting client configuration" until it
# gives up, with nothing OpenVPN-specific to blame in the log. Raise it via
# a drop-in (applies to the whole @ template, so every current/future
# instance gets it) instead of patching the package's own unit file.
# ---------------------------------------------------------------------------
mkdir -p /etc/systemd/system/openvpn-server@.service.d
cat > /etc/systemd/system/openvpn-server@.service.d/override.conf << 'EOF'
[Service]
LimitNPROC=2048
EOF
mkdir -p /etc/systemd/system/openvpn@.service.d
cat > /etc/systemd/system/openvpn@.service.d/override.conf << 'EOF'
[Service]
LimitNPROC=2048
EOF
systemctl daemon-reload

# ---------------------------------------------------------------------------
# xl2tpd/pptpd are optional protocols (a user can run this box with only
# OpenVPN, say) - they must never be allowed to abort the whole install via
# set -e. If the first restart fails, clean up stale pid/socket files (the
# most common cause of a silent "status=1/FAILURE" with nothing useful in the
# journal - see /var/run/xl2tpd.pid surviving an unclean previous shutdown)
# and retry once before giving up and just warning.
# ---------------------------------------------------------------------------
systemctl enable xl2tpd 2>/dev/null || true
if ! systemctl restart xl2tpd; then
  echo "[!] xl2tpd start failed on the first try - cleaning stale state and retrying..." >&2
  systemctl stop xl2tpd 2>/dev/null || true
  mkdir -p /var/run/xl2tpd
  rm -f /var/run/xl2tpd.pid /var/run/xl2tpd/*.pid 2>/dev/null || true
  sleep 1
  if ! systemctl restart xl2tpd; then
    echo "[!] WARNING: xl2tpd still won't start - L2TP/IPsec will be unavailable." >&2
    echo "    Debug it after install with: sudo systemctl stop xl2tpd && sudo /usr/sbin/xl2tpd -D -c /etc/xl2tpd/xl2tpd.conf" >&2
    echo "    Continuing with the rest of the install." >&2
  fi
fi

if [ "$PPTP_SETUP_OK" = "1" ]; then
  systemctl enable pptpd 2>/dev/null || true
  if ! systemctl restart pptpd; then
    PPTP_SETUP_OK=0
    echo "[!] WARNING: pptpd failed to start - PPTP will be unavailable. Continuing with the rest of the install." >&2
  fi
fi
systemctl enable openvpn-server@server-udp 2>/dev/null || systemctl enable openvpn@server-udp 2>/dev/null || true
systemctl enable openvpn-server@server-tcp 2>/dev/null || systemctl enable openvpn@server-tcp 2>/dev/null || true
systemctl restart openvpn-server@server-udp 2>/dev/null || systemctl restart openvpn@server-udp 2>/dev/null \
  || echo "[!] WARNING: OpenVPN UDP failed to start - check 'journalctl -xeu openvpn-server@server-udp'. Continuing." >&2
systemctl restart openvpn-server@server-tcp 2>/dev/null || systemctl restart openvpn@server-tcp 2>/dev/null \
  || echo "[!] WARNING: OpenVPN TCP failed to start - check 'journalctl -xeu openvpn-server@server-tcp'. Continuing." >&2
systemctl restart vpn-panel-api

# ---------------------------------------------------------------------------
# 17b) Apply protocol settings once via configure_vpn_protocols.sh.
#
# این تنها جایی است که این اسکریپت طی نصب اجرا می‌شود (تا الان فقط از پنل >
# تنظیمات صدا زده می‌شد). این اسکریپت حالا برای هر پروتکل فعال (L2TP, PPTP,
# OpenVPN, SSTP) پورت لازمش را هم روی فایروال هاست (ufw/firewalld/iptables،
# هرکدام فعال باشد) باز می‌کند - قبلاً فقط SSTP این‌طور بود و بقیه باید دستی
# باز می‌شدند؛ الان همه یکجا و خودکار. با همان مقادیر پیش‌فرضی که همین بالا
# در دیتابیس ذخیره شد صدا زده می‌شود تا وضعیت واقعی سرویس‌ها/فایروال با
# تنظیمات ثبت‌شده در پنل هماهنگ باشد.
# ---------------------------------------------------------------------------
bash "$INSTALL_DIR/scripts/configure_vpn_protocols.sh" \
  1 "${L2TP_INSTALL_PORT}" "${PPTP_SETUP_OK}" 1 "${OVPN_UDP_INSTALL_PORT}" "${OVPN_TCP_INSTALL_PORT}" "" 1400 1400 "${SSTP_SETUP_OK}" "${SSTP_INSTALL_PORT}" "${IKEV2_SETUP_OK}" 1.1.1.1 8.8.8.8 \
  || echo "[!] هشدار: اعمال اولیه‌ی تنظیمات پروتکل‌ها (از جمله باز کردن پورت‌های فایروال) ناموفق بود - می‌توانید بعداً یک‌بار از پنل > تنظیمات > پروتکل‌ها و پورت‌ها دوباره ذخیره کنید."

else
  XRAY_SETUP_OK=0
  echo "[*] Management-only mode: Xray/OpenVPN samples and local VPN service startup skipped."
  systemctl restart vpn-panel-api
fi

# ---------------------------------------------------------------------------
# 17c) Open the panel port itself + tcp/80+443 (needed later for certbot if
# you set up a domain) on the same host firewall - configure_vpn_protocols.sh
# above only manages VPN protocol ports, not the panel's own port. Same
# ufw > firewalld > plain iptables detection, tagged so it's safe to re-run
# (e.g. from change_panel_port.sh whenever the panel port changes later).
# ---------------------------------------------------------------------------
FW_BACKEND="none"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "^Status: active"; then
  FW_BACKEND="ufw"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q "running"; then
  FW_BACKEND="firewalld"
elif command -v iptables >/dev/null 2>&1; then
  FW_BACKEND="iptables"
fi
case "$FW_BACKEND" in
  ufw)
    ufw allow "${PANEL_PORT}/tcp" comment "vpnpanel-panel" >/dev/null 2>&1 || true
    ufw allow "80/tcp" comment "vpnpanel-web" >/dev/null 2>&1 || true
    ufw allow "443/tcp" comment "vpnpanel-web" >/dev/null 2>&1 || true
    ;;
  firewalld)
    mkdir -p /var/lib/vpn-panel/firewall
    printf '%s' "$PANEL_PORT" > /var/lib/vpn-panel/firewall/vpnpanel-panel-tcp.port
    firewall-cmd --permanent --add-port="${PANEL_PORT}/tcp" >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port="80/tcp" >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port="443/tcp" >/dev/null 2>&1 || true
    firewall-cmd --reload >/dev/null 2>&1 || true
    ;;
  iptables)
    iptables -I INPUT -p tcp --dport "${PANEL_PORT}" -m comment --comment "vpnpanel-panel" -j ACCEPT
    iptables -I INPUT -p tcp --dport 80 -m comment --comment "vpnpanel-web" -j ACCEPT
    iptables -I INPUT -p tcp --dport 443 -m comment --comment "vpnpanel-web" -j ACCEPT
    if iptables -C INPUT -j VPN-PANEL-BANS 2>/dev/null; then
      iptables -D INPUT -j VPN-PANEL-BANS 2>/dev/null || true
      iptables -I INPUT 1 -j VPN-PANEL-BANS
    fi
    command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
    ;;
  *)
    echo "[!] No supported firewall tool detected - open tcp/${PANEL_PORT} (panel), tcp/80, tcp/443 yourself." >&2
    ;;
esac

# A successful service restart is not enough: a partial previous install can
# leave the Nginx vhost missing while the API itself is healthy. Rebuild the
# public vhost, open the OS firewall, and require both frontend and /api/health
# to work through Nginx before the licensed bootstrap is allowed to print 100%.
echo "[*] Verifying real panel web access..."
[ -x "$INSTALL_DIR/scripts/repair_panel_access.sh" ] || {
  echo "ERROR: panel access repair helper is missing" >&2
  exit 1
}
PANEL_PORT_RESULT=$("$INSTALL_DIR/scripts/repair_panel_access.sh" "$PUBLIC_IP" "$PANEL_PORT" "$BACKEND_PORT" | tail -n1)
[[ "$PANEL_PORT_RESULT" =~ ^[0-9]+$ ]] || {
  echo "ERROR: panel access verification did not return a valid port" >&2
  exit 1
}
PANEL_PORT="$PANEL_PORT_RESULT"
PANEL_URL_RESULT=$(awk -F= '/^[[:space:]]*PANEL_URL[[:space:]]*=/{v=$0; sub(/^[^=]*=/,"",v); print v}' /var/lib/vpn-panel/install-result.env 2>/dev/null | tail -n1 || true)
[ -n "$PANEL_URL_RESULT" ] || PANEL_URL_RESULT="http://${PUBLIC_IP}:${PANEL_PORT}"
if [ "$SERVER_ROLE" = "node" ] && [ -n "$NODE_PUBLIC_URL" ]; then
  PANEL_URL_RESULT="${NODE_PUBLIC_URL%/}"
fi
echo "[*] Panel frontend and API proxy verified on ${PANEL_URL_RESULT}"

# The Telegram control bot is an independent service with its own Python
# runtime and persistent directory. It is initialized only on this fresh
# install path; existing panel installations exit through update.sh above.
if [ "$SERVER_ROLE" = "main" ] && [ -d "$PROJECT_ROOT/bot" ] && [ -x "$PROJECT_ROOT/bot/install.sh" ]; then
  BOT_PYTHON_CANDIDATE=""
  for candidate in python3.14 python3.13 python3.12 python3; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; raise SystemExit(0 if (3, 12) <= sys.version_info[:2] < (3, 15) else 1)' 2>/dev/null; then
      BOT_PYTHON_CANDIDATE="$(command -v "$candidate")"
      break
    fi
  done
  if [ -z "$BOT_PYTHON_CANDIDATE" ]; then
    echo "[!] Skipping Telegram bot installation: Python >=3.12,<3.15 is not installed."
    echo "    Install a supported Python runtime, then run: sudo env BOT_SOURCE_DIR='$PROJECT_ROOT/bot' PYTHON_BIN=python3.12 bash '$PROJECT_ROOT/bot/install.sh'"
  elif [ ! -c /dev/tty ] || [ ! -r /dev/tty ] || [ ! -w /dev/tty ]; then
    echo "[!] Skipping first-time Telegram bot setup: an interactive terminal is required."
    echo "    To install later, run: sudo env BOT_SOURCE_DIR='$PROJECT_ROOT/bot' bash '$PROJECT_ROOT/bot/install.sh'"
  else
    echo "[*] Installing the independent Telegram bot service (separate Python 3.12-3.14 venv)..."
    if BOT_SOURCE_DIR="$PROJECT_ROOT/bot" PYTHON_BIN="$BOT_PYTHON_CANDIDATE" APP_DIR="/opt/vpn-control-center" SERVICE_USER="vpnmanager" \
      bash "$PROJECT_ROOT/bot/install.sh"; then
      echo "[*] Independent Telegram bot service installed successfully."
    else
      echo "[!] VPN Panel is installed, but Telegram bot setup did not complete."
      echo "    You can retry later with: sudo env BOT_SOURCE_DIR='$PROJECT_ROOT/bot' bash '$PROJECT_ROOT/bot/install.sh'"
    fi
  fi
fi

# Save the complete release as the source for future one-click node installs.
# This is intentionally outside PROJECT_ROOT, so the archive never includes
# itself. Virtualenv/node_modules are rebuilt by the destination installer.
tar --exclude='./frontend/node_modules' --exclude='./backend/venv' --exclude='*.pyc' --exclude='__pycache__'   -czf "$INSTALL_DIR/release-source.tar.gz.tmp" -C "$PROJECT_ROOT" .
mv -f "$INSTALL_DIR/release-source.tar.gz.tmp" "$INSTALL_DIR/release-source.tar.gz"
chmod 0600 "$INSTALL_DIR/release-source.tar.gz"

# Persist the resolved runtime endpoint for the license bootstrap and future
# repair/update tools.  Do not include secrets in this result file.
install -d -m 0750 /var/lib/vpn-panel
cat > /var/lib/vpn-panel/install-result.env << EOF
SERVER_IP=${PUBLIC_IP}
PANEL_PORT=${PANEL_PORT}
BACKEND_PORT=${BACKEND_PORT}
PANEL_URL=${PANEL_URL_RESULT}
ADMIN_USER=${ADMIN_USER}
SERVER_ROLE=${SERVER_ROLE}
DEPLOYMENT_ROLE=${SERVER_ROLE}
INSTALL_LOCAL_SERVICES=${INSTALL_LOCAL_SERVICES}
NODE_CONTROLLER_URL=${CONTROLLER_URL}
NODE_PUBLIC_URL=${NODE_PUBLIC_URL}
EOF
chmod 0600 /var/lib/vpn-panel/install-result.env

echo ""
echo "=================================================================="
echo " Installation finished successfully"
echo "=================================================================="
echo " Panel URL:              ${PANEL_URL_RESULT}"
echo " Private API listener:   127.0.0.1:${BACKEND_PORT}"
echo " Admin username:          ${ADMIN_USER}"
[ "$GENERATED_ADMIN_PASS" = "1" ] && echo " Generated admin password: ${ADMIN_PASS}"
echo " Server role:             ${SERVER_ROLE}"
echo " Local VPN services:      $([ "$INSTALL_LOCAL_SERVICES" = "1" ] && echo installed || echo management-only)"
[ "$SERVER_ROLE" = "node" ] && echo " Main controller:         ${CONTROLLER_URL}" || true
echo " ------------------------------------------------------------------"
if [ "$INSTALL_LOCAL_SERVICES" = "1" ]; then
  echo " L2TP/IPsec shared PSK:   ${IPSEC_PSK}"
  echo "   (enter this in users' L2TP client settings)"
  echo " PPTP/L2TP server:        ${PUBLIC_IP}"
  echo " Sample OpenVPN profile:  ${INSTALL_DIR}/client-templates/client.ovpn"
else
  echo " Mode:                    management-only; install services later from Protocol Center"
fi
echo " ------------------------------------------------------------------"
if [ "$SSTP_SETUP_OK" = "1" ]; then
  echo " SSTP:                    فعال روی پورت ${SSTP_INSTALL_PORT} (از پنل > تنظیمات قابل تغییر است)"
else
  echo " SSTP:                    نصب نشد (خطا در کامپایل accel-ppp) - غیرفعال"
  echo "   برای تلاش دوباره:      sudo bash install/setup_sstp.sh"
fi
if [ "${PPTP_SETUP_OK}" = "1" ]; then
  echo " PPTP:                    installed and configured"
else
  echo " PPTP:                    installation failed - repair from Protocol Center"
fi
if [ "${XRAY_SETUP_OK:-0}" = "1" ]; then
  echo " VMess/VLESS (Xray):      installed; disabled until enabled in Protocol Center"
else
  echo " VMess/VLESS (Xray):      installation failed - repair from Protocol Center"
fi
echo " ------------------------------------------------------------------"
if [ -z "$LICENSE_SERVER_URL" ] || [ -z "$LICENSE_API_KEY" ]; then
  echo " License:                 ERROR - server/API key missing; API will fail closed"
elif [ -n "$LICENSE_KEY" ]; then
  echo " License:                 کد لایسنس وارد شد - وضعیت را از پنل > (پیام قفل در صورت بروز) بررسی کنید"
else
  echo " License:                 هنوز کد لایسنسی وارد نشده - پنل قفل بالا می‌آید تا از داخل خودش کد وارد شود"
fi
echo " ------------------------------------------------------------------"
echo " Database credentials (if you need them):"
echo "   DB=${DB_NAME}  USER=${DB_USER}  PASS=${DB_PASS}"
echo " Also saved in ${INSTALL_DIR}/backend/.env"
echo "   Copy that file to a secure offline password manager now."
echo " ------------------------------------------------------------------"
echo " Want a domain + free SSL for the panel instead of http://IP?"
echo " Point an A record for your subdomain at ${PUBLIC_IP}, then go to"
echo " Settings > Domain & SSL inside the panel and enter it there."
echo " ------------------------------------------------------------------"
echo " Locked out of the panel? Reset the admin password via SSH:"
echo "   sudo bash ${INSTALL_DIR}/scripts/reset_admin_password.sh <username> <new_password>"
echo " Change the panel port via SSH (only works while using IP, not domain/SSL):"
echo "   sudo bash ${INSTALL_DIR}/scripts/change_panel_port.sh <port>"
echo "=================================================================="
