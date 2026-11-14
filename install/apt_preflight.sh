#!/bin/bash
# Shared APT/dpkg recovery helper for VPN Panel installers.
# Designed for interrupted installs and Ubuntu package post-install scripts
# that try to start VPN daemons before the panel has written valid configs.

_VPNP_APT_AUTOMATION_PAUSED="${_VPNP_APT_AUTOMATION_PAUSED:-0}"
_VPNP_POLICY_ACTIVE="${_VPNP_POLICY_ACTIVE:-0}"
_VPNP_POLICY_BACKUP="${_VPNP_POLICY_BACKUP:-}"
_VPNP_APT_DAILY_TIMER_WAS_ACTIVE="${_VPNP_APT_DAILY_TIMER_WAS_ACTIVE:-0}"
_VPNP_APT_UPGRADE_TIMER_WAS_ACTIVE="${_VPNP_APT_UPGRADE_TIMER_WAS_ACTIVE:-0}"

# Destructive recovery is intentionally opt-in and is enabled only by the
# unattended fresh installer. Update/protocol repair paths never purge packages.
VPN_PANEL_ALLOW_DESTRUCTIVE_VPN_PACKAGE_RECOVERY="${VPN_PANEL_ALLOW_DESTRUCTIVE_VPN_PACKAGE_RECOVERY:-0}"
_VPNP_LAST_DPKG_LOG="${_VPNP_LAST_DPKG_LOG:-/tmp/vpn-panel-dpkg-repair.log}"
_VPNP_RECOVERY_BACKUP_DIR="${_VPNP_RECOVERY_BACKUP_DIR:-}"

VPN_PANEL_STRONGSWAN_L2TP_PACKAGES=(
  strongswan strongswan-starter strongswan-charon strongswan-libcharon
  strongswan-pki libstrongswan libstrongswan-standard-plugins
  libstrongswan-extra-plugins libcharon-extauth-plugins
  libcharon-extra-plugins xl2tpd
)

vpn_panel_wait_for_apt_lock() {
  local max_wait="${1:-600}" waited=0
  while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 \
     || fuser /var/lib/dpkg/lock >/dev/null 2>&1 \
     || fuser /var/cache/apt/archives/lock >/dev/null 2>&1 \
     || fuser /var/lib/apt/lists/lock >/dev/null 2>&1; do
    if [ "$waited" -eq 0 ]; then
      echo "[*] Waiting for the APT/dpkg lock to become available..."
    elif [ $((waited % 20)) -eq 0 ]; then
      echo "[*] APT/dpkg is still busy (${waited}s elapsed). Lock owners:"
      fuser -v /var/lib/dpkg/lock-frontend /var/lib/dpkg/lock \
        /var/cache/apt/archives/lock /var/lib/apt/lists/lock 2>&1 || true
    fi
    if [ "$waited" -ge "$max_wait" ]; then
      echo "ERROR: APT/dpkg remained locked for ${max_wait} seconds." >&2
      ps aux | grep -E '[a]pt|[d]pkg|unattended' >&2 || true
      return 1
    fi
    sleep 2
    waited=$((waited + 2))
  done
}

vpn_panel_pause_apt_automation() {
  [ "$_VPNP_APT_AUTOMATION_PAUSED" = "1" ] && return 0
  _VPNP_APT_DAILY_TIMER_WAS_ACTIVE=0
  _VPNP_APT_UPGRADE_TIMER_WAS_ACTIVE=0
  systemctl is-active --quiet apt-daily.timer 2>/dev/null && _VPNP_APT_DAILY_TIMER_WAS_ACTIVE=1
  systemctl is-active --quiet apt-daily-upgrade.timer 2>/dev/null && _VPNP_APT_UPGRADE_TIMER_WAS_ACTIVE=1
  _VPNP_APT_AUTOMATION_PAUSED=1
  export _VPNP_APT_AUTOMATION_PAUSED \
    _VPNP_APT_DAILY_TIMER_WAS_ACTIVE _VPNP_APT_UPGRADE_TIMER_WAS_ACTIVE
  timeout 25s systemctl stop unattended-upgrades.service 2>/dev/null || true
  timeout 25s systemctl stop apt-daily.service apt-daily-upgrade.service 2>/dev/null || true
  timeout 15s systemctl stop apt-daily.timer apt-daily-upgrade.timer 2>/dev/null || true
}

vpn_panel_restore_apt_automation() {
  vpn_panel_policy_rcd_disable || true
  [ "$_VPNP_APT_AUTOMATION_PAUSED" = "1" ] || return 0
  [ "$_VPNP_APT_DAILY_TIMER_WAS_ACTIVE" = "1" ] && systemctl start apt-daily.timer 2>/dev/null || true
  [ "$_VPNP_APT_UPGRADE_TIMER_WAS_ACTIVE" = "1" ] && systemctl start apt-daily-upgrade.timer 2>/dev/null || true
  _VPNP_APT_AUTOMATION_PAUSED=0
  _VPNP_APT_DAILY_TIMER_WAS_ACTIVE=0
  _VPNP_APT_UPGRADE_TIMER_WAS_ACTIVE=0
  export _VPNP_APT_AUTOMATION_PAUSED \
    _VPNP_APT_DAILY_TIMER_WAS_ACTIVE _VPNP_APT_UPGRADE_TIMER_WAS_ACTIVE
}

vpn_panel_policy_rcd_enable() {
  [ "$_VPNP_POLICY_ACTIVE" = "1" ] && return 0
  mkdir -p /var/lib/vpn-panel/installer
  if [ -e /usr/sbin/policy-rc.d ]; then
    _VPNP_POLICY_BACKUP="/var/lib/vpn-panel/installer/policy-rc.d.backup.$$.${RANDOM}"
    cp -a /usr/sbin/policy-rc.d "$_VPNP_POLICY_BACKUP"
  else
    _VPNP_POLICY_BACKUP=""
  fi
  cat > /usr/sbin/policy-rc.d <<'POLICY'
#!/bin/sh
# VPN Panel temporarily prevents package postinst scripts from starting
# half-configured VPN daemons. The panel starts them after writing configs.
exit 101
POLICY
  chmod 755 /usr/sbin/policy-rc.d
  _VPNP_POLICY_ACTIVE=1
  export _VPNP_POLICY_ACTIVE _VPNP_POLICY_BACKUP
}

vpn_panel_policy_rcd_disable() {
  [ "$_VPNP_POLICY_ACTIVE" = "1" ] || return 0
  if [ -n "$_VPNP_POLICY_BACKUP" ] && [ -e "$_VPNP_POLICY_BACKUP" ]; then
    cp -a "$_VPNP_POLICY_BACKUP" /usr/sbin/policy-rc.d
    rm -f "$_VPNP_POLICY_BACKUP"
  else
    rm -f /usr/sbin/policy-rc.d
  fi
  _VPNP_POLICY_ACTIVE=0
  _VPNP_POLICY_BACKUP=""
  export _VPNP_POLICY_ACTIVE _VPNP_POLICY_BACKUP
}

vpn_panel_apt_get() {
  local command_timeout=3600
  [ "${1:-}" = "update" ] && command_timeout=900
  DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
  timeout --foreground "${command_timeout}s" apt-get \
    -o Dpkg::Use-Pty=0 \
    -o DPkg::Lock::Timeout=600 \
    -o Acquire::Retries=4 \
    -o Acquire::http::Timeout=30 \
    -o Acquire::https::Timeout=30 \
    -o Acquire::ftp::Timeout=30 \
    -o APT::Get::Assume-Yes=true \
    -o Dpkg::Options::=--force-confdef \
    -o Dpkg::Options::=--force-confold \
    "$@"
}

vpn_panel_capture_command() {
  # Keep the real stderr/stdout from dpkg visible at the end of bootstrap logs.
  # The old helper printed /var/log/dpkg.log afterwards, which pushed the actual
  # maintainer-script error out of the last-lines diagnostic.
  local logfile="$1"; shift
  local had_errexit=0 rc
  [[ $- == *e* ]] && had_errexit=1
  : > "$logfile"
  set +e
  "$@" 2>&1 | tee -a "$logfile"
  rc=${PIPESTATUS[0]}
  [ "$had_errexit" -eq 1 ] && set -e || true
  return "$rc"
}

vpn_panel_append_command() {
  local logfile="$1"; shift
  local had_errexit=0 rc
  [[ $- == *e* ]] && had_errexit=1
  set +e
  "$@" 2>&1 | tee -a "$logfile"
  rc=${PIPESTATUS[0]}
  [ "$had_errexit" -eq 1 ] && set -e || true
  return "$rc"
}

vpn_panel_known_vpn_packages_broken() {
  local pkg status
  for pkg in "${VPN_PANEL_STRONGSWAN_L2TP_PACKAGES[@]}"; do
    status=$(dpkg-query -W -f='${db:Status-Abbrev}' "$pkg" 2>/dev/null || true)
    case "$status" in
      ii*) ;;
      '') ;;
      *) return 0 ;;
    esac
  done
  return 1
}

vpn_panel_backup_and_quarantine_vpn_configs() {
  local stamp item rel dest
  stamp=$(date +%Y%m%d-%H%M%S)
  _VPNP_RECOVERY_BACKUP_DIR="/var/backups/vpn-panel-package-recovery-${stamp}"
  mkdir -p "$_VPNP_RECOVERY_BACKUP_DIR"
  for item in \
    /etc/ipsec.conf /etc/ipsec.secrets /etc/strongswan.conf \
    /etc/strongswan.d /etc/xl2tpd /etc/default/xl2tpd; do
    [ -e "$item" ] || [ -L "$item" ] || continue
    rel="${item#/}"
    dest="$_VPNP_RECOVERY_BACKUP_DIR/$rel"
    mkdir -p "$(dirname "$dest")"
    mv "$item" "$dest"
  done
  printf '%s\n' "$_VPNP_RECOVERY_BACKUP_DIR" > /var/lib/vpn-panel/installer/last-package-recovery-backup
  echo "[*] Broken VPN package configuration was backed up to: $_VPNP_RECOVERY_BACKUP_DIR"
}

vpn_panel_disable_known_maintainer_scripts() {
  # Last-resort cleanup for packages stuck in reinstreq/half-configured state.
  # Scripts are backed up, never deleted, and only known VPN packages are touched.
  local pkg file backup_dir="$_VPNP_RECOVERY_BACKUP_DIR/dpkg-info"
  mkdir -p "$backup_dir"
  for pkg in "${VPN_PANEL_STRONGSWAN_L2TP_PACKAGES[@]}"; do
    for file in /var/lib/dpkg/info/"$pkg".{preinst,postinst,prerm,postrm}; do
      [ -f "$file" ] || continue
      cp -a "$file" "$backup_dir/$(basename "$file")"
      printf '#!/bin/sh\nexit 0\n' > "$file"
      chmod 755 "$file"
    done
  done
}

vpn_panel_destructive_vpn_package_recovery() {
  [ "$VPN_PANEL_ALLOW_DESTRUCTIVE_VPN_PACKAGE_RECOVERY" = "1" ] || return 1
  vpn_panel_known_vpn_packages_broken || return 1

  echo "[!] strongSwan/xl2tpd packages are stuck in a partial dpkg state." >&2
  echo "[*] Starting targeted fresh-install recovery for VPN packages..."
  vpn_panel_policy_rcd_enable
  systemctl stop strongswan-starter strongswan xl2tpd 2>/dev/null || true
  systemctl reset-failed strongswan-starter strongswan xl2tpd nginx 2>/dev/null || true
  vpn_panel_backup_and_quarantine_vpn_configs

  local present=() pkg rc=0
  for pkg in "${VPN_PANEL_STRONGSWAN_L2TP_PACKAGES[@]}"; do
    dpkg-query -W "$pkg" >/dev/null 2>&1 && present+=("$pkg")
  done

  if [ "${#present[@]}" -gt 0 ]; then
    set +e
    dpkg --purge --force-remove-reinstreq --force-depends "${present[@]}" \
      2>&1 | tee -a "$_VPNP_LAST_DPKG_LOG"
    rc=${PIPESTATUS[0]}
    set -e
    if [ "$rc" -ne 0 ]; then
      echo "[!] Normal forced purge failed; neutralizing only the broken packages' maintainer scripts and retrying." >&2
      vpn_panel_disable_known_maintainer_scripts
      dpkg --purge --force-all "${present[@]}" 2>&1 | tee -a "$_VPNP_LAST_DPKG_LOG" || true
    fi
  fi

  rm -rf /var/lib/strongswan /run/charon /run/xl2tpd /var/run/xl2tpd 2>/dev/null || true
  mkdir -p /run/xl2tpd
  rm -f /run/xl2tpd/xl2tpd.pid /var/run/xl2tpd.pid 2>/dev/null || true

  echo "[*] Repairing dependencies after targeted package cleanup..."
  rc=0
  DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
    vpn_panel_append_command "$_VPNP_LAST_DPKG_LOG" timeout 1800s apt-get \
      -o Dpkg::Use-Pty=0 -o DPkg::Lock::Timeout=600 \
      -o Acquire::Retries=4 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o APT::Get::Assume-Yes=true \
      -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold --fix-broken install || rc=$?
  [ "$rc" -eq 0 ] || return "$rc"

  rc=0
  DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
    vpn_panel_append_command "$_VPNP_LAST_DPKG_LOG" timeout 1200s dpkg --force-confdef --force-confold --configure -a || rc=$?
  [ "$rc" -eq 0 ] || return "$rc"

  echo "[*] Targeted dpkg recovery completed; packages will now be installed cleanly."
  return 0
}

vpn_panel_dpkg_diagnostics() {
  echo "[diagnostic] Actual dpkg/APT error output:" >&2
  tail -120 "$_VPNP_LAST_DPKG_LOG" >&2 2>/dev/null || true
  echo "[diagnostic] Packages not fully configured:" >&2
  dpkg --audit >&2 || true
  echo "[diagnostic] Package states for strongSwan/L2TP:" >&2
  dpkg-query -W -f='${binary:Package} ${db:Status-Abbrev} ${Version}\n' \
    "${VPN_PANEL_STRONGSWAN_L2TP_PACKAGES[@]}" >&2 2>/dev/null || true
  echo "[diagnostic] Package maintainer-script failures from journal:" >&2
  journalctl --no-pager -n 120 -u strongswan-starter -u strongswan -u xl2tpd >&2 2>/dev/null || true
  echo "[diagnostic] Failed systemd units:" >&2
  systemctl --failed --no-pager >&2 2>/dev/null || true
  echo "[diagnostic] Recent kernel OOM messages:" >&2
  dmesg -T 2>/dev/null | grep -Ei 'out of memory|oom|killed process' | tail -20 >&2 || true
}

vpn_panel_repair_dpkg() {
  local rc=0 attempt policy_was_active="$_VPNP_POLICY_ACTIVE"
  vpn_panel_wait_for_apt_lock 600 || return 1
  vpn_panel_policy_rcd_enable
  : > "$_VPNP_LAST_DPKG_LOG"

  for attempt in 1 2; do
    rc=0
    DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
      vpn_panel_capture_command "$_VPNP_LAST_DPKG_LOG" timeout 1200s dpkg --force-confdef --force-confold --configure -a || rc=$?
    [ "$rc" -eq 0 ] && break
    echo "[!] dpkg configuration attempt ${attempt} failed with exit code ${rc}." >&2
    sleep 3
  done

  if [ "$rc" -ne 0 ]; then
    echo "[*] Repairing broken package dependencies..."
    rc=0
    DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
      vpn_panel_capture_command "$_VPNP_LAST_DPKG_LOG" timeout 1800s apt-get \
        -o Dpkg::Use-Pty=0 -o DPkg::Lock::Timeout=600 -o Acquire::Retries=4 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 \
        -o APT::Get::Assume-Yes=true \
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
        --fix-broken install || rc=$?
    if [ "$rc" -eq 0 ]; then
      rc=0
      DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
        vpn_panel_capture_command "$_VPNP_LAST_DPKG_LOG" timeout 1200s dpkg --force-confdef --force-confold --configure -a || rc=$?
    fi
  fi

  if [ "$rc" -ne 0 ] && [ "$VPN_PANEL_ALLOW_DESTRUCTIVE_VPN_PACKAGE_RECOVERY" = "1" ]; then
    echo "[*] Standard dpkg repair was not enough; checking for a partial VPN-package transaction..."
    rc=0
    vpn_panel_destructive_vpn_package_recovery || rc=$?
  fi

  if [ "$policy_was_active" = "0" ]; then
    vpn_panel_policy_rcd_disable
  fi
  if [ "$rc" -ne 0 ]; then
    vpn_panel_dpkg_diagnostics
    return "$rc"
  fi
  return 0
}

vpn_panel_install_packages() {
  [ "$#" -gt 0 ] || return 0
  local rc=0 policy_was_active="$_VPNP_POLICY_ACTIVE"
  vpn_panel_wait_for_apt_lock 600 || return 1
  vpn_panel_policy_rcd_enable

  rc=0
  DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
    vpn_panel_append_command "$_VPNP_LAST_DPKG_LOG" timeout 3600s apt-get \
      -o Dpkg::Use-Pty=0 -o DPkg::Lock::Timeout=600 \
      -o Acquire::Retries=4 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o APT::Get::Assume-Yes=true \
      -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install "$@" || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "[!] Package installation failed (exit ${rc}); repairing dpkg and retrying once..." >&2
    vpn_panel_repair_dpkg || true
    rc=0
    DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
      vpn_panel_append_command "$_VPNP_LAST_DPKG_LOG" timeout 3600s apt-get \
        -o Dpkg::Use-Pty=0 -o DPkg::Lock::Timeout=600 \
        -o Acquire::Retries=4 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o APT::Get::Assume-Yes=true \
        -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold --fix-broken install || rc=$?
    if [ "$rc" -eq 0 ]; then
      rc=0
      DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a \
        vpn_panel_append_command "$_VPNP_LAST_DPKG_LOG" timeout 3600s apt-get \
          -o Dpkg::Use-Pty=0 -o DPkg::Lock::Timeout=600 \
          -o Acquire::Retries=4 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o APT::Get::Assume-Yes=true \
          -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold install --reinstall "$@" || rc=$?
    fi
  fi

  if [ "$policy_was_active" = "0" ]; then
    vpn_panel_policy_rcd_disable
  fi
  if [ "$rc" -ne 0 ]; then
    vpn_panel_dpkg_diagnostics
    return "$rc"
  fi
  return 0
}

vpn_panel_protocol_preflight() {
  if [ "${VPN_PANEL_PROTOCOL_PREFLIGHT_DONE:-0}" = "1" ]; then
    return 0
  fi
  VPN_PANEL_PROTOCOL_PREFLIGHT_DONE=1
  export VPN_PANEL_PROTOCOL_PREFLIGHT_DONE

  mkdir -p /run/lock
  exec 9>/run/lock/vpn-panel-protocol-install.lock
  if ! flock -w 60 9; then
    echo "ERROR: another VPN protocol installation/repair is already running." >&2
    return 1
  fi

  vpn_panel_pause_apt_automation
  vpn_panel_repair_dpkg
}
