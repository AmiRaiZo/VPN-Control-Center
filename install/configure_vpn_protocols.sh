#!/bin/bash
###############################################################################
# Called by the panel backend (as root) from Settings > VPN Protocols & Ports,
# and once at the end of install.sh/update.sh with the current DB settings.
# Applies enable/disable + port/protocol changes to xl2tpd, pptpd, OpenVPN and
# SSTP, AND keeps the host firewall (ufw/firewalld/plain iptables - whichever
# is actually active) open on exactly the ports each *enabled* protocol needs,
# closing them again if a protocol is disabled or its port changes. This is
# what makes "install/update opens its own ports" true for every protocol,
# not just SSTP like before.
#
# This still cannot reach a cloud provider's network firewall (AWS Security
# Group, Hetzner Cloud Firewall, etc.) - that remains a manual step outside
# the machine itself.
#
# Usage:
#   configure_vpn_protocols.sh <l2tp_enabled 0|1> <l2tp_port> <pptp_enabled 0|1> \
#                               <openvpn_enabled 0|1> <openvpn_udp_port> <openvpn_tcp_port> \
#                               [vpn_domain] [l2tp_mtu] [l2tp_mru] \
#                               [sstp_enabled 0|1] [sstp_port] [ikev2_enabled 0|1] \
#                               [openvpn_dns1] [openvpn_dns2] \
#                               [target all|l2tp|ipsec|pptp|openvpn|sstp|ikev2]
#
# SSTP (10th/11th args, default enabled/4433) only has an effect if the SSTP
# infrastructure was set up separately via install/setup_sstp.sh (accel-ppp).
# If /etc/accel-ppp/sstp.conf doesn't exist, the SSTP block below is a no-op.
#
# OpenVPN always runs as TWO simultaneous processes - one UDP, one TCP - each
# with its own port/config/systemd unit. openvpn_enabled turns both on/off
# together; there is no separate "protocol" choice anymore.
#
# vpn_domain (optional, 7th arg) is a hostname dedicated to the VPN protocols
# themselves (separate from the panel's own domain under Settings > Domain &
# SSL). When set, it is used as the "remote" host in the generated OpenVPN
# client profile instead of the raw server IP. Pass an empty string to fall
# back to the IP.
#
# l2tp_mtu/l2tp_mru (optional, 8th/9th args, default 1400 each) are written to
# /etc/ppp/options.xl2tpd only (not PPTP/OpenVPN) - lower than the standard
# 1500 to account for L2TP/IPsec's per-packet overhead, so large TCP packets
# (e.g. during an upload) don't get silently dropped (PMTU black hole) instead
# of being sent at the right size from the start.
###############################################################################
set -e

L2TP_ENABLED="$1"
L2TP_PORT="$2"
PPTP_ENABLED="$3"
OPENVPN_ENABLED="$4"
OPENVPN_UDP_PORT="$5"
OPENVPN_TCP_PORT="$6"
VPN_DOMAIN="$7"
L2TP_MTU="${8:-1400}"
L2TP_MRU="${9:-1400}"
SSTP_ENABLED="${10:-1}"
# پیش‌فرض 4433 است، نه 443 - چون setup_sstp.sh خود accel-ppp را روی 4433
# نصب می‌کند (443 برای nginx/HTTPS خود پنل رزرو است). اگر این‌جا 443 پاس
# داده شود، accel-ppp-sstp سعی می‌کند روی همان پورتی bind شود که nginx از
# قبل گرفته -> "Address already in use" -> کل سرویس SSTP crash می‌کند.
SSTP_PORT="${11:-4433}"
# IKEv2/IPsec (MSCHAPv2) - فقط اگر زیرساختش با install/setup_ikev2.sh نصب شده
# باشد اثر واقعی دارد (یعنی conn IKEv2-MSCHAPv2 داخل /etc/ipsec.conf موجود
# باشد)؛ پورت جداگانه ندارد چون طبق استاندارد پروتکل IKEv2 همیشه udp/500
# (IKE) + udp/4500 (NAT-T) است - دقیقاً همان دو پورتی که L2TP/IPsec هم لازم
# دارد، پس اشتراکی است.
IKEV2_ENABLED="${12:-1}"
OPENVPN_DNS1="${13:-1.1.1.1}"
OPENVPN_DNS2="${14:-8.8.8.8}"
# Optional 15th argument limits the operation to one backend.  The classic
# install/update path omits it and still applies all protocols.  The Protocol
# Center uses it so editing one card does not restart/disconnect unrelated VPNs.
TARGET="${15:-all}"
case "$TARGET" in
  all|l2tp|ipsec|pptp|openvpn|sstp|ikev2) ;;
  *) echo "Invalid target protocol: $TARGET" >&2; exit 2 ;;
esac
selected() { [ "$TARGET" = "all" ] || [ "$TARGET" = "$1" ]; }

FAILURES=""
IPSEC_RESTART_NEEDED=0
L2TP_DAEMON_CONFIG_CHANGED=0
PENDING_DIR="/var/lib/vpn-panel/pending"
PENDING_XL2TPD_RESTART="$PENDING_DIR/xl2tpd-restart"
mkdir -p "$PENDING_DIR"

active_l2tp_sessions() {
  pgrep -af 'pppd.*(options\.xl2tpd|/etc/ppp/options\.xl2tpd)' >/dev/null 2>&1
}

mark_xl2tpd_restart_pending() {
  printf '%s\n' "$(date -u +%FT%TZ)" > "$PENDING_XL2TPD_RESTART"
  chmod 0600 "$PENDING_XL2TPD_RESTART" 2>/dev/null || true
}

# Re-adopt strongSwan into systemd instead of trusting a stale PID file or an
# orphaned charon/starter process.  This fixes the common state where
# strongswan-starter is shown as inactive while UDP/500 and UDP/4500 are owned
# by daemons left over from a previous manual `ipsec start`.
restart_strongswan_managed() {
  local unit=""
  if systemctl list-unit-files 2>/dev/null | grep -q '^strongswan-starter\.service'; then
    unit="strongswan-starter"
  elif systemctl list-unit-files 2>/dev/null | grep -q '^strongswan\.service'; then
    unit="strongswan"
  fi

  /usr/sbin/ipsec stop >/dev/null 2>&1 || true
  systemctl stop strongswan-starter strongswan >/dev/null 2>&1 || true
  sleep 0.5

  for proc in charon charon-systemd starter; do
    if pgrep -x "$proc" >/dev/null 2>&1; then
      pkill -TERM -x "$proc" >/dev/null 2>&1 || true
    fi
  done
  for _i in 1 2 3 4 5 6; do
    if ! pgrep -x charon >/dev/null 2>&1 && \
       ! pgrep -x charon-systemd >/dev/null 2>&1 && \
       ! pgrep -x starter >/dev/null 2>&1; then
      break
    fi
    sleep 0.5
  done
  for proc in charon charon-systemd starter; do
    if pgrep -x "$proc" >/dev/null 2>&1; then
      pkill -KILL -x "$proc" >/dev/null 2>&1 || true
    fi
  done

  rm -f /run/charon.pid /var/run/charon.pid \
        /run/starter.charon.pid /var/run/starter.charon.pid

  if [ -n "$unit" ]; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    systemctl enable "$unit" >/dev/null 2>&1 || true
    systemctl start "$unit" || return 1
  else
    /usr/sbin/ipsec start || return 1
  fi

  for _i in 1 2 3 4 5 6 7 8 9 10; do
    if { pgrep -x charon >/dev/null 2>&1 || pgrep -x charon-systemd >/dev/null 2>&1; } && \
       ss -H -lunp 2>/dev/null | grep -Eq ':(500|4500)[[:space:]]'; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}

# xl2tpd is a SysV-generated unit on Ubuntu 24.04 and can legitimately display
# `active (exited)`.  Its process and UDP listener are the source of truth.
# Stop duplicate/orphaned daemons before starting so the init script does not
# repeatedly report "There's already a xl2tpd server running".
restart_xl2tpd_managed() {
  systemctl stop xl2tpd >/dev/null 2>&1 || true
  sleep 0.4
  if pgrep -x xl2tpd >/dev/null 2>&1; then
    pkill -TERM -x xl2tpd >/dev/null 2>&1 || true
    sleep 0.5
  fi
  if pgrep -x xl2tpd >/dev/null 2>&1; then
    pkill -KILL -x xl2tpd >/dev/null 2>&1 || true
  fi
  rm -f /run/xl2tpd/xl2tpd.pid /var/run/xl2tpd/xl2tpd.pid /var/run/xl2tpd.pid
  systemctl reset-failed xl2tpd >/dev/null 2>&1 || true
  systemctl enable xl2tpd >/dev/null 2>&1 || true
  systemctl start xl2tpd || return 1
  for _i in 1 2 3 4 5 6 7 8 9 10; do
    if pgrep -x xl2tpd >/dev/null 2>&1 && \
       ss -H -lunp 2>/dev/null | grep -Eq ":${L2TP_PORT}[[:space:]]"; then
      return 0
    fi
    sleep 0.5
  done
  return 1
}


if [ -z "$OPENVPN_TCP_PORT" ]; then
  echo "Usage: configure_vpn_protocols.sh <l2tp_enabled> <l2tp_port> <pptp_enabled> <openvpn_enabled> <openvpn_udp_port> <openvpn_tcp_port> [vpn_domain]" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# NAT-T fix for L2TP/IPsec and IKEv2: most cloud VPS providers place the
# server behind some form of NAT/virtual networking, and without forceencaps
# the IKE/IPsec phase can fail silently on those hosts (client sees a plain
# timeout or a generic "Unsuccessful", as if nothing were listening at all).
# This is idempotent and safe to re-apply.
#
# قبلاً این چک روی کل فایل بود (grep روی همه‌ی ipsec.conf)، نه هر conn
# جداگانه - یعنی از لحظه‌ای که conn L2TP-PSK این خط را داشت (از همان
# install.sh)، این شرط برای همیشه false می‌شد و دیگر هیچ‌وقت conn
# IKEv2-MSCHAPv2 (که جدا و بعداً توسط setup_ikev2.sh اضافه می‌شود) را چک/ترمیم
# نمی‌کرد - IKEv2 همیشه بدون forceencaps می‌ماند. حالا هر conn جداگانه چک
# می‌شود.
# ---------------------------------------------------------------------------
if selected l2tp || selected ipsec || selected ikev2; then
  if [ -f /etc/ipsec.conf ]; then
    if { selected l2tp || selected ipsec; } && grep -q "^conn L2TP-PSK" /etc/ipsec.conf && ! sed -n '/^conn L2TP-PSK/,/^conn /p' /etc/ipsec.conf | grep -q "forceencaps=yes"; then
      sed -i '/^conn L2TP-PSK/a\    forceencaps=yes' /etc/ipsec.conf
      IPSEC_RESTART_NEEDED=1
    fi
    if { selected ikev2 || selected ipsec; } && grep -q "^conn IKEv2-MSCHAPv2" /etc/ipsec.conf && ! sed -n '/^conn IKEv2-MSCHAPv2/,/^conn /p' /etc/ipsec.conf | grep -q "forceencaps=yes"; then
      sed -i '/^conn IKEv2-MSCHAPv2/a\    forceencaps=yes' /etc/ipsec.conf
      IPSEC_RESTART_NEEDED=1
    fi
  fi
fi

# ---------------------------------------------------------------------------
# IKEv2/IPsec (MSCHAPv2) — فقط اگر install/setup_ikev2.sh قبلاً روی این سرور
# اجرا شده باشد (یعنی conn IKEv2-MSCHAPv2 داخل ipsec.conf وجود دارد) اثر
# واقعی دارد. روشن/خاموش‌کردن با auto=add (بدون route خودکار، ولی همچنان
# قابل قبول برای اتصال ورودی) در مقابل auto=ignore انجام می‌شود - چون این کانکشن
# جدا از L2TP-PSK است و نباید با خاموش/روشن‌کردن L2TP قاطی شود.
# ---------------------------------------------------------------------------
if selected ikev2 && [ -f /etc/ipsec.conf ] && grep -q "^conn IKEv2-MSCHAPv2" /etc/ipsec.conf; then
  WANTED_IKEV2_AUTO="ignore"
  [ "$IKEV2_ENABLED" = "1" ] && WANTED_IKEV2_AUTO="add"
  CURRENT_IKEV2_AUTO=$(sed -n '/^conn IKEv2-MSCHAPv2/,/^conn /s/^[[:space:]]*auto=//p' /etc/ipsec.conf | head -1 | tr -d '[:space:]')
  if [ "$CURRENT_IKEV2_AUTO" != "$WANTED_IKEV2_AUTO" ]; then
    sed -i "/^conn IKEv2-MSCHAPv2/,/^conn /{s/^[[:space:]]*auto=.*/    auto=${WANTED_IKEV2_AUTO}/}" /etc/ipsec.conf
    IPSEC_RESTART_NEEDED=1
  fi
fi

# Reloading strongSwan keeps established SAs alive. A full stop/start is only
# used when charon is not running. Never destroy active L2TP tunnels merely to
# re-read a text configuration file.
IPSEC_SHOULD_RUN=0
if { selected l2tp || selected ipsec || selected ikev2; } && { [ "$L2TP_ENABLED" = "1" ] || [ "$IKEV2_ENABLED" = "1" ]; }; then
  IPSEC_SHOULD_RUN=1
fi
if [ "$IPSEC_SHOULD_RUN" = "1" ]; then
  if pgrep -x charon >/dev/null 2>&1 || pgrep -x charon-systemd >/dev/null 2>&1; then
    if [ "$IPSEC_RESTART_NEEDED" = "1" ]; then
      if ! /usr/sbin/ipsec reload >/dev/null 2>&1; then
        if active_l2tp_sessions; then
          echo '[i] strongSwan full restart skipped: active L2TP sessions; existing SAs kept alive'
        elif ! restart_strongswan_managed; then
          ERR="[!] strongSwan reload/restart failed:
$(systemctl status strongswan-starter strongswan --no-pager 2>&1 | tail -25)
$(journalctl -u strongswan-starter -u strongswan -n 30 --no-pager 2>&1)"
          echo "$ERR" >&2
          FAILURES="${FAILURES}${ERR}
"
        fi
      fi
    fi
  elif ! restart_strongswan_managed; then
    ERR="[!] strongSwan start/health-check failed:
$(systemctl status strongswan-starter strongswan --no-pager 2>&1 | tail -25)
$(journalctl -u strongswan-starter -u strongswan -n 30 --no-pager 2>&1)"
    echo "$ERR" >&2
    FAILURES="${FAILURES}${ERR}
"
  fi
fi

# ---------------------------------------------------------------------------
# L2TP/IPsec (xl2tpd) — port is configurable, though most native OS L2TP
# clients hardcode UDP/1701, so changing it may break built-in clients.
# ---------------------------------------------------------------------------
if selected l2tp; then
if [ -f /etc/xl2tpd/xl2tpd.conf ]; then
  CURRENT_L2TP_PORT=$(awk -F= '/^[[:space:]]*port[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' /etc/xl2tpd/xl2tpd.conf 2>/dev/null || true)
  if [ "$CURRENT_L2TP_PORT" != "$L2TP_PORT" ]; then
    L2TP_DAEMON_CONFIG_CHANGED=1
    sed -i "s/^[[:space:]]*port[[:space:]]*=.*/port = ${L2TP_PORT}/" /etc/xl2tpd/xl2tpd.conf
    if ! grep -qE "^[[:space:]]*port[[:space:]]*=[[:space:]]*${L2TP_PORT}[[:space:]]*$" /etc/xl2tpd/xl2tpd.conf; then
      sed -i "0,/\[global\]/s//[global]\nport = ${L2TP_PORT}/" /etc/xl2tpd/xl2tpd.conf
    fi
  fi
fi

# فقط L2TP (نه PPTP/OpenVPN) - سربار L2TP/IPsec باعث می‌شود MTU واقعی تونل
# کمتر از 1500 استاندارد باشد؛ بدون این، پکت‌های بزرگ TCP (مثلاً هنگام آپلود)
# ممکن است بی‌صدا گم شوند (PMTU black hole) و باعث قطع اتصال شوند.
if [ -f /etc/ppp/options.xl2tpd ]; then
  if grep -q "^mtu " /etc/ppp/options.xl2tpd; then
    sed -i "s/^mtu .*/mtu ${L2TP_MTU}/" /etc/ppp/options.xl2tpd
  else
    echo "mtu ${L2TP_MTU}" >> /etc/ppp/options.xl2tpd
  fi
  if grep -q "^mru " /etc/ppp/options.xl2tpd; then
    sed -i "s/^mru .*/mru ${L2TP_MRU}/" /etc/ppp/options.xl2tpd
  else
    echo "mru ${L2TP_MRU}" >> /etc/ppp/options.xl2tpd
  fi
fi


if [ "$L2TP_ENABLED" = "1" ]; then
  # اگه به هر دلیلی (مثلاً یک kernel update بدون ری‌استارت کامل) ماژول‌های
  # L2TP از کرنل خارج شده باشن، xl2tpd با ارور مبهم «control process exited
  # with error code» بالا نمیاد. قبل از هر تلاش برای استارت/ری‌استارت، اول
  # مطمئن می‌شیم لود هستن (idempotent - اگه از قبل لود باشن بی‌اثره).
  modprobe l2tp_ppp 2>/dev/null || true
  modprobe l2tp_netlink 2>/dev/null || true
  systemctl enable xl2tpd >/dev/null 2>&1 || true
  # قبلاً بدون محافظ بود: به‌خاطر «set -e» بالای فایل، اگر xl2tpd (مثلاً به
  # دلیل کانفیگ خراب/تداخل پورت/بالا نبودن strongSwan) نتواند ری‌استارت شود،
  # کل اسکریپت همان‌جا متوقف می‌شد - یعنی قوانین فایروال L2TP و حتی
  # PPTP/OpenVPN/SSTP که پایین‌تر هستند هرگز اجرا نمی‌شدند، و ادمین فقط یک
  # خطای ۵۰۰ کلی می‌دید بدون این‌که دلیل واقعی (خطای خودِ xl2tpd) جایی نشان
  # داده شود. حالا خطا لاگ می‌شود ولی بقیه‌ی اسکریپت (بقیه‌ی پروتکل‌ها و
  # فایروال) همچنان اجرا می‌شود؛ شکست واقعی در انتهای اسکریپت گزارش می‌شود.
  if pgrep -x xl2tpd >/dev/null 2>&1; then
    if [ "$L2TP_DAEMON_CONFIG_CHANGED" = "1" ]; then
      if active_l2tp_sessions; then
        mark_xl2tpd_restart_pending
        echo '[i] xl2tpd restart deferred: active L2TP sessions detected; current tunnels remain untouched'
      elif ! restart_xl2tpd_managed; then
        ERR="[!] xl2tpd idle restart/health-check failed:
$(systemctl status xl2tpd --no-pager 2>&1 | tail -15)
$(journalctl -u xl2tpd -n 20 --no-pager 2>&1)"
        echo "$ERR" >&2
        FAILURES="${FAILURES}${ERR}
"
      else
        rm -f "$PENDING_XL2TPD_RESTART"
      fi
    else
      # chap-secrets and options.xl2tpd are consumed by new pppd sessions.
      # Re-saving unchanged settings must not erase xl2tpd's live tunnel table.
      rm -f "$PENDING_XL2TPD_RESTART"
    fi
  elif ! restart_xl2tpd_managed; then
    ERR="[!] xl2tpd start/health-check failed:
$(systemctl status xl2tpd --no-pager 2>&1 | tail -15)
$(journalctl -u xl2tpd -n 20 --no-pager 2>&1)"
    echo "$ERR" >&2
    FAILURES="${FAILURES}${ERR}
"
  fi
else
  systemctl disable xl2tpd >/dev/null 2>&1 || true
  systemctl stop xl2tpd 2>/dev/null || true
fi
fi

# ---------------------------------------------------------------------------
# PPTP (pptpd) — the PPTP control channel is always TCP/1723 per the protocol
# spec and virtually every client hardcodes it, so only enable/disable is
# offered (no port field).
# ---------------------------------------------------------------------------
if selected pptp; then
if [ "$PPTP_ENABLED" = "1" ]; then
  if ! command -v pptpd >/dev/null 2>&1 && ! systemctl list-unit-files 2>/dev/null | grep -q '^pptpd\.service'; then
    ERR="[!] PPTP is enabled in settings, but the pptpd server is not installed or is unavailable on this Ubuntu release."
    echo "$ERR" >&2
    FAILURES="${FAILURES}${ERR}
"
  else
  systemctl enable pptpd >/dev/null 2>&1 || true
  if ! systemctl restart pptpd; then
    ERR="[!] pptpd restart failed:
$(systemctl status pptpd --no-pager 2>&1 | tail -15)
$(journalctl -u pptpd -n 20 --no-pager 2>&1)"
    echo "$ERR" >&2
    FAILURES="${FAILURES}${ERR}
"
  fi
  fi
else
  systemctl disable pptpd >/dev/null 2>&1 || true
  systemctl stop pptpd 2>/dev/null || true
fi
fi

# ---------------------------------------------------------------------------
# OpenVPN — always TWO simultaneous processes (UDP + TCP), each with its own
# port and systemd instance (server-udp.conf / server-tcp.conf), sharing the
# same PKI (ca/cert/key/dh/ta/crl) and client-config-dir.
#
# NOTE: OpenVPN (2.6, shipped with Ubuntu 24.04) rejects a bare "proto tcp"
# in a server config as ambiguous — it must be "tcp-server" explicitly, or
# the daemon refuses to start at all ("control process exited with error
# code"). "explicit-exit-notify" is UDP-only and must not be present in the
# TCP instance's config.
# ---------------------------------------------------------------------------
OVPN_DIR="/etc/openvpn/server"
UDP_CONF="${OVPN_DIR}/server-udp.conf"
TCP_CONF="${OVPN_DIR}/server-tcp.conf"

if selected openvpn; then
OVPN_BACKUP_DIR="$(mktemp -d /tmp/vpnpanel-openvpn-port.XXXXXX)"
[ -f "$UDP_CONF" ] && cp -a "$UDP_CONF" "$OVPN_BACKUP_DIR/server-udp.conf"
[ -f "$TCP_CONF" ] && cp -a "$TCP_CONF" "$OVPN_BACKUP_DIR/server-tcp.conf"
OLD_OPENVPN_UDP_PORT=$(awk '/^[[:space:]]*port[[:space:]]+[0-9]+/{print $2; exit}' "$OVPN_BACKUP_DIR/server-udp.conf" 2>/dev/null || true)
OLD_OPENVPN_TCP_PORT=$(awk '/^[[:space:]]*port[[:space:]]+[0-9]+/{print $2; exit}' "$OVPN_BACKUP_DIR/server-tcp.conf" 2>/dev/null || true)
[ -n "$OLD_OPENVPN_UDP_PORT" ] || OLD_OPENVPN_UDP_PORT="$OPENVPN_UDP_PORT"
[ -n "$OLD_OPENVPN_TCP_PORT" ] || OLD_OPENVPN_TCP_PORT="$OPENVPN_TCP_PORT"

OPENVPN_CONFIG_ERROR=""
if [ ! -s "$UDP_CONF" ] || [ ! -s "$TCP_CONF" ]; then
  OPENVPN_CONFIG_ERROR="OpenVPN base config is missing: UDP=${UDP_CONF}, TCP=${TCP_CONF}"
else
  # Change the ports and normalize directives required by OpenVPN 2.6.
  if grep -qE '^[[:space:]]*port[[:space:]]+' "$UDP_CONF"; then
    sed -i "s/^[[:space:]]*port[[:space:]].*/port ${OPENVPN_UDP_PORT}/" "$UDP_CONF"
  else
    sed -i "1i port ${OPENVPN_UDP_PORT}" "$UDP_CONF"
  fi
  if grep -qE '^[[:space:]]*port[[:space:]]+' "$TCP_CONF"; then
    sed -i "s/^[[:space:]]*port[[:space:]].*/port ${OPENVPN_TCP_PORT}/" "$TCP_CONF"
  else
    sed -i "1i port ${OPENVPN_TCP_PORT}" "$TCP_CONF"
  fi
  if grep -qE '^[[:space:]]*proto[[:space:]]+' "$UDP_CONF"; then
    sed -i 's/^[[:space:]]*proto[[:space:]].*/proto udp/' "$UDP_CONF"
  else
    sed -i '2i proto udp' "$UDP_CONF"
  fi
  if grep -qE '^[[:space:]]*proto[[:space:]]+' "$TCP_CONF"; then
    sed -i 's/^[[:space:]]*proto[[:space:]].*/proto tcp-server/' "$TCP_CONF"
  else
    sed -i '2i proto tcp-server' "$TCP_CONF"
  fi
  # explicit-exit-notify is valid only for UDP.
  sed -i '/^[[:space:]]*explicit-exit-notify\([[:space:]]\|$\)/d' "$TCP_CONF"
  grep -qE '^[[:space:]]*explicit-exit-notify[[:space:]]+1[[:space:]]*$' "$UDP_CONF" || echo 'explicit-exit-notify 1' >> "$UDP_CONF"
fi

# DNS pushed to OpenVPN clients. Only the panel-managed block is replaced;
# unrelated custom directives stay untouched.
update_openvpn_dns() {
  local conf="$1" tmp
  [ -f "$conf" ] || return 0
  tmp=$(mktemp)
  awk '
    BEGIN { inside=0 }
    /^# BEGIN VPN PANEL DNS$/ { inside=1; next }
    /^# END VPN PANEL DNS$/ { inside=0; next }
    inside == 1 { next }
    /^push "dhcp-option DNS / { next }
    { print }
  ' "$conf" > "$tmp"
  {
    cat "$tmp"
    echo ""
    echo "# BEGIN VPN PANEL DNS"
    [ -n "$OPENVPN_DNS1" ] && printf 'push "dhcp-option DNS %s"\n' "$OPENVPN_DNS1"
    [ -n "$OPENVPN_DNS2" ] && printf 'push "dhcp-option DNS %s"\n' "$OPENVPN_DNS2"
    echo "# END VPN PANEL DNS"
  } > "${tmp}.new"
  cat "${tmp}.new" > "$conf"
  rm -f "$tmp" "${tmp}.new"
}
[ -z "$OPENVPN_CONFIG_ERROR" ] && update_openvpn_dns "$UDP_CONF"
[ -z "$OPENVPN_CONFIG_ERROR" ] && update_openvpn_dns "$TCP_CONF"

OVPN_PREFIX="openvpn-server@"
systemctl list-unit-files 2>/dev/null | grep -q '^openvpn@' && ! systemctl list-unit-files 2>/dev/null | grep -q '^openvpn-server@' && OVPN_PREFIX="openvpn@"
OVPN_UDP_UNIT="${OVPN_PREFIX}server-udp"
OVPN_TCP_UNIT="${OVPN_PREFIX}server-tcp"

openvpn_listener_present() {
  local proto="$1" port="$2"
  if [ "$proto" = "udp" ]; then
    ss -H -lun 2>/dev/null | grep -Eq "(^|[[:space:]])([^[:space:]]*:|\\[.*\\]:)${port}([[:space:]]|$)"
  else
    ss -H -ltn 2>/dev/null | grep -Eq "(^|[[:space:]])([^[:space:]]*:|\\[.*\\]:)${port}([[:space:]]|$)"
  fi
}

openvpn_pair_ready() {
  local expected_udp="$1" expected_tcp="$2"
  systemctl is-active --quiet "$OVPN_UDP_UNIT" &&
  systemctl is-active --quiet "$OVPN_TCP_UNIT" &&
  openvpn_listener_present udp "$expected_udp" &&
  openvpn_listener_present tcp "$expected_tcp"
}

stop_openvpn_pair_cleanly() {
  systemctl stop "$OVPN_UDP_UNIT" "$OVPN_TCP_UNIT" >/dev/null 2>&1 || true
  # Wait for the two management sockets and base processes to disappear. This
  # prevents the second start from racing the just-stopped OpenVPN processes.
  for _i in $(seq 1 30); do
    if ! pgrep -af '[o]penvpn' | grep -Eq 'server-(udp|tcp)\.conf' &&
       ! ss -H -lnt 2>/dev/null | grep -Eq ':(7505|7506)[[:space:]]'; then
      return 0
    fi
    sleep 0.2
  done
  # Kill only orphan base instances; extra-port instances have different names.
  pgrep -af '[o]penvpn' | grep -E 'server-(udp|tcp)\.conf' | awk '{print $1}' | xargs -r kill -TERM 2>/dev/null || true
  sleep 0.5
  pgrep -af '[o]penvpn' | grep -E 'server-(udp|tcp)\.conf' | awk '{print $1}' | xargs -r kill -KILL 2>/dev/null || true
}

start_openvpn_pair() {
  local expected_udp="$1" expected_tcp="$2"
  systemctl reset-failed "$OVPN_UDP_UNIT" "$OVPN_TCP_UNIT" >/dev/null 2>&1 || true
  systemctl enable "$OVPN_UDP_UNIT" "$OVPN_TCP_UNIT" >/dev/null 2>&1 || true
  systemctl start "$OVPN_UDP_UNIT" || return 1
  systemctl start "$OVPN_TCP_UNIT" || return 1
  for _i in $(seq 1 30); do
    openvpn_pair_ready "$expected_udp" "$expected_tcp" && return 0
    sleep 0.2
  done
  return 1
}

restore_openvpn_configs() {
  [ -f "$OVPN_BACKUP_DIR/server-udp.conf" ] && cp -a "$OVPN_BACKUP_DIR/server-udp.conf" "$UDP_CONF"
  [ -f "$OVPN_BACKUP_DIR/server-tcp.conf" ] && cp -a "$OVPN_BACKUP_DIR/server-tcp.conf" "$TCP_CONF"
}

if [ "$OPENVPN_ENABLED" = "1" ]; then
  OPENVPN_START_FAILED=0
  [ -n "$OPENVPN_CONFIG_ERROR" ] && OPENVPN_START_FAILED=1
  if [ "$OPENVPN_START_FAILED" = "0" ]; then
    stop_openvpn_pair_cleanly
    start_openvpn_pair "$OPENVPN_UDP_PORT" "$OPENVPN_TCP_PORT" || OPENVPN_START_FAILED=1
  fi

  if [ "$OPENVPN_START_FAILED" = "1" ]; then
    NEW_ERROR="${OPENVPN_CONFIG_ERROR}
$(systemctl status "$OVPN_UDP_UNIT" "$OVPN_TCP_UNIT" --no-pager 2>&1 | tail -40)
$(journalctl -u "${OVPN_UDP_UNIT}.service" -u "${OVPN_TCP_UNIT}.service" -n 80 --no-pager 2>&1)"

    # Never leave a previously working OpenVPN installation down because a new
    # port/config failed. Restore both old configs and bring the old listeners
    # back before reporting the error to the panel.
    stop_openvpn_pair_cleanly
    restore_openvpn_configs
    ROLLBACK_STATUS="rollback restart failed"
    if start_openvpn_pair "$OLD_OPENVPN_UDP_PORT" "$OLD_OPENVPN_TCP_PORT"; then
      ROLLBACK_STATUS="previous OpenVPN configuration restored and restarted"
    fi
    ERR="[!] OpenVPN apply failed; ${ROLLBACK_STATUS}:
${NEW_ERROR}"
    echo "$ERR" >&2
    FAILURES="${FAILURES}${ERR}
"
  fi
else
  systemctl disable "$OVPN_UDP_UNIT" "$OVPN_TCP_UNIT" >/dev/null 2>&1 || true
  stop_openvpn_pair_cleanly
fi
rm -rf "$OVPN_BACKUP_DIR"
fi
# ---------------------------------------------------------------------------
# SSTP (accel-ppp) — only touched if install/setup_sstp.sh was run on this
# server; otherwise /etc/accel-ppp/sstp.conf doesn't exist and this whole
# block is silently skipped.
# ---------------------------------------------------------------------------
SSTP_CONF="/etc/accel-ppp/sstp.conf"
if selected sstp && [ -f "$SSTP_CONF" ]; then
  sed -i "s/^port=.*/port=${SSTP_PORT}/" "$SSTP_CONF"

  if [ "$SSTP_ENABLED" = "1" ]; then
    systemctl enable accel-ppp-sstp >/dev/null 2>&1 || true
    # systemctl restart = stop و start تقریباً پشت‌سرهم؛ وقتی پورت عوض شده
    # (یا حتی وقتی عوض نشده ولی پروسه‌ی قبلی هنوز کامل soket را آزاد نکرده)،
    # start می‌تواند با "Address already in use" شکست بخورد - و چون این یک
    # شکست واقعیِ سرویس است (نه یک خطای موقت پنل)، سرویس واقعاً پایین می‌ماند
    # تا ادمین دستی دوباره از پنل روشنش کند؛ دقیقاً همان چیزی که به‌نظر می‌رسد
    # «SSTP با تغییر پورت خودش خاموش می‌شود». برای رفع این مسابقه: صریحاً
    # stop می‌کنیم، منتظر آزاد شدن واقعیِ پورت (چه پورت قبلی چه پورت تازه)
    # می‌مانیم (حداکثر ۵ ثانیه) و بعد start.
    systemctl stop accel-ppp-sstp 2>/dev/null || true
    if command -v ss >/dev/null 2>&1; then
      for _i in 1 2 3 4 5 6 7 8 9 10; do
        ss -H -ltn "sport = :${SSTP_PORT}" 2>/dev/null | grep -q . || break
        sleep 0.5
      done
    fi
    if ! systemctl start accel-ppp-sstp; then
      ERR="[!] accel-ppp-sstp start failed:
$(systemctl status accel-ppp-sstp --no-pager 2>&1 | tail -15)"
      echo "$ERR" >&2
      FAILURES="${FAILURES}${ERR}
"
    fi
  else
    systemctl disable accel-ppp-sstp >/dev/null 2>&1 || true
    systemctl stop accel-ppp-sstp 2>/dev/null || true
  fi
fi

# ---------------------------------------------------------------------------
# Auto-open/close every VPN protocol's port on the server's own host
# firewall (INPUT chain), for whichever protocol is currently *enabled* -
# and close it again if the protocol gets disabled or its port changes.
# Detects whichever backend is actually active (ufw > firewalld > plain
# iptables). Every rule this script adds is tagged with its own unique
# comment, so on every run we first remove only OUR OWN previous rule for
# that exact protocol (never touching anything you or anything else added
# by hand) and then, only if the protocol is enabled, add the current port.
# This is the same idea SSTP already used, now applied to L2TP/PPTP/OpenVPN
# too - so a fresh install (or an update on top of an older install) no
# longer requires manually opening udp/500, udp/4500, udp/1701, tcp/1723,
# GRE, udp/1194 or tcp/1194 by hand.
# ---------------------------------------------------------------------------
FW_BACKEND="none"
if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "^Status: active"; then
  FW_BACKEND="ufw"
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q "running"; then
  FW_BACKEND="firewalld"
elif command -v iptables >/dev/null 2>&1; then
  FW_BACKEND="iptables"
fi

FW_STATE_DIR="/var/lib/vpn-panel/firewall"
mkdir -p "$FW_STATE_DIR"

# fw_apply_port <tag> <tcp|udp> <port> <enabled 0|1>
fw_apply_port() {
  local tag="$1" proto="$2" port="$3" enabled="$4"
  case "$FW_BACKEND" in
    ufw)
      while true; do
        local rule_num
        rule_num=$(ufw status numbered 2>/dev/null | grep "# ${tag}$" | tail -n1 | grep -oE '^\[[0-9]+\]' | tr -d '[]')
        [ -z "$rule_num" ] && break
        yes | ufw delete "$rule_num" >/dev/null 2>&1 || break
      done
      if [ "$enabled" = "1" ]; then
        ufw allow "${port}/${proto}" comment "${tag}" >/dev/null 2>&1 || true
      fi
      ;;
    firewalld)
      # firewalld has no comment field for plain port rules.  Persist the last
      # panel-managed port per tag so changing a port closes the old rule too.
      local state_file="${FW_STATE_DIR}/${tag}-${proto}.port" old_port=""
      [ -f "$state_file" ] && old_port=$(cat "$state_file" 2>/dev/null || true)
      if [ -n "$old_port" ]; then
        firewall-cmd --permanent --remove-port="${old_port}/${proto}" >/dev/null 2>&1 || true
      fi
      firewall-cmd --permanent --remove-port="${port}/${proto}" >/dev/null 2>&1 || true
      if [ "$enabled" = "1" ]; then
        firewall-cmd --permanent --add-port="${port}/${proto}" >/dev/null 2>&1 || true
      fi
      printf '%s' "$port" > "$state_file"
      ;;
    iptables)
      if command -v iptables-save >/dev/null 2>&1; then
        while IFS= read -r rule; do
          [ -z "$rule" ] && continue
          local del_rule="${rule/-A INPUT/-D INPUT}"
          # shellcheck disable=SC2086
          iptables $del_rule 2>/dev/null || true
        done < <(iptables-save 2>/dev/null | grep -- "--comment \"${tag}\"")
      fi
      if [ "$enabled" = "1" ]; then
        iptables -I INPUT -p "${proto}" --dport "${port}" -m comment --comment "${tag}" -j ACCEPT
      fi
      ;;
  esac
}

# fw_apply_gre <tag> <enabled 0|1> — PPTP's GRE control channel has no port,
# so it needs its own protocol-level rule instead of fw_apply_port.
fw_apply_gre() {
  local tag="$1" enabled="$2"
  case "$FW_BACKEND" in
    ufw)
      while true; do
        local rule_num
        rule_num=$(ufw status numbered 2>/dev/null | grep "# ${tag}$" | tail -n1 | grep -oE '^\[[0-9]+\]' | tr -d '[]')
        [ -z "$rule_num" ] && break
        yes | ufw delete "$rule_num" >/dev/null 2>&1 || break
      done
      if [ "$enabled" = "1" ]; then
        ufw allow proto gre comment "${tag}" >/dev/null 2>&1 || true
      fi
      ;;
    firewalld)
      firewall-cmd --permanent --remove-protocol=gre >/dev/null 2>&1 || true
      if [ "$enabled" = "1" ]; then
        firewall-cmd --permanent --add-protocol=gre >/dev/null 2>&1 || true
      fi
      ;;
    iptables)
      if command -v iptables-save >/dev/null 2>&1; then
        while IFS= read -r rule; do
          [ -z "$rule" ] && continue
          local del_rule="${rule/-A INPUT/-D INPUT}"
          # shellcheck disable=SC2086
          iptables $del_rule 2>/dev/null || true
        done < <(iptables-save 2>/dev/null | grep -- "--comment \"${tag}\"")
      fi
      if [ "$enabled" = "1" ]; then
        iptables -I INPUT -p gre -m comment --comment "${tag}" -j ACCEPT
      fi
      ;;
  esac
}

# L2TP/IPsec: udp/500 (IKE) + udp/4500 (NAT-T) are fixed by the IPsec
# protocol itself; udp/${L2TP_PORT} is the L2TP data channel (configurable).
# IKEv2 shares the same udp/500 + udp/4500 (it has no separate data-channel
# port), so these two stay open if EITHER L2TP or IKEv2 is enabled.
IKE_PORTS_ENABLED="0"
{ [ "$L2TP_ENABLED" = "1" ] || [ "$IKEV2_ENABLED" = "1" ]; } && IKE_PORTS_ENABLED="1"
if selected l2tp || selected ikev2 || selected ipsec; then
  fw_apply_port "vpnpanel-l2tp-ike" udp 500 "$IKE_PORTS_ENABLED"
  fw_apply_port "vpnpanel-l2tp-natt" udp 4500 "$IKE_PORTS_ENABLED"
fi
if selected l2tp; then
  fw_apply_port "vpnpanel-l2tp-port" udp "$L2TP_PORT" "$L2TP_ENABLED"
fi

# PPTP: tcp/1723 control channel + GRE (protocol 47) data channel.
if selected pptp; then
  fw_apply_port "vpnpanel-pptp" tcp 1723 "$PPTP_ENABLED"
  fw_apply_gre "vpnpanel-pptp-gre" "$PPTP_ENABLED"
fi

# OpenVPN: one rule per running instance (UDP + TCP).
if selected openvpn; then
  fw_apply_port "vpnpanel-ovpn-udp" udp "$OPENVPN_UDP_PORT" "$OPENVPN_ENABLED"
  fw_apply_port "vpnpanel-ovpn-tcp" tcp "$OPENVPN_TCP_PORT" "$OPENVPN_ENABLED"
fi

# SSTP: only meaningful if the accel-ppp infrastructure actually exists.
if selected sstp && [ -f "$SSTP_CONF" ]; then
  fw_apply_port "vpnpanel-sstp" tcp "$SSTP_PORT" "$SSTP_ENABLED"
fi

# ---------------------------------------------------------------------------
# مهم: هر کدام از fw_apply_port/fw_apply_gre بالا برای بک‌اند iptables، رول
# ACCEPT خودشان را با «iptables -I INPUT» (بدون شماره‌ی صریح رول) اضافه
# می‌کنند - که یعنی همیشه در رأس INPUT (رول شماره ۱) قرار می‌گیرند. چین بن
# آی‌پی (VPN-PANEL-BANS، در بک‌اند/vpn_manager.py ساخته می‌شود) هم قبلاً دقیقاً
# همین‌جا یعنی رول ۱ وصل شده بود - پس هر بار این اسکریپت اجرا شود (هر ذخیره‌ی
# تنظیمات پروتکل‌ها از پنل، یا هر بار install.sh/update.sh)، رول‌های تازه‌ی
# پروتکل‌ها چین بن را از رأس INPUT به پایین هل می‌دهند. نتیجه: بعد از اولین
# اجرا، ترافیک L2TP/PPTP/OpenVPN/SSTP از رول ACCEPT خودِ همان پروتکل عبور
# می‌کند و اصلاً به چین بن نمی‌رسد - یعنی یک آی‌پیِ بن‌شده باز هم می‌تواند وصل
# شود. برای همین اینجا، بعد از تمام تغییرات بالا، چین بن (اگر از قبل وصل شده
# باشد) از هر جای INPUT که هست حذف و دوباره دقیقاً در رأس (رول ۱) وصل می‌شود -
# idempotent و بی‌ضرر اگر قبلاً هم بالا بوده.
if [ "$FW_BACKEND" = "iptables" ]; then
  BAN_CHAIN="VPN-PANEL-BANS"
  if iptables -C INPUT -j "$BAN_CHAIN" 2>/dev/null; then
    iptables -D INPUT -j "$BAN_CHAIN" 2>/dev/null || true
    iptables -I INPUT 1 -j "$BAN_CHAIN"
  fi
fi

if [ "$FW_BACKEND" = "firewalld" ]; then
  firewall-cmd --reload >/dev/null 2>&1 || true
fi
if [ "$FW_BACKEND" = "iptables" ] && command -v netfilter-persistent >/dev/null 2>&1; then
  netfilter-persistent save >/dev/null 2>&1 || true
fi
if [ "$FW_BACKEND" = "none" ]; then
  echo "[!] No supported firewall tool (ufw/firewalld/iptables) detected - VPN protocol ports were NOT opened automatically; open them yourself." >&2
fi

# regenerate the sample client profile so it matches the new port/protocol
CA_FILE="/etc/openvpn/server/ca.crt"
TA_FILE="/etc/openvpn/server/ta.key"
ENV_FILE="/opt/vpn-panel/backend/.env"
if selected openvpn && [ -f "$CA_FILE" ] && [ -f "$TA_FILE" ] && [ -f "$ENV_FILE" ]; then
  if [ -n "$VPN_DOMAIN" ]; then
    REMOTE_HOST="$VPN_DOMAIN"
  else
    REMOTE_HOST=$(grep -E '^PUBLIC_SERVER_IP=' "$ENV_FILE" | cut -d= -f2-)
    if ! [[ "$REMOTE_HOST" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
      REMOTE_HOST=""
      for _url in "https://ifconfig.me" "https://icanhazip.com" "https://api.ipify.org"; do
        _try=$(curl -s -f -4 --max-time 5 "$_url" 2>/dev/null | tr -d '[:space:]')
        if [[ "$_try" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
          REMOTE_HOST="$_try"
          break
        fi
      done
    fi
  fi
  mkdir -p /opt/vpn-panel/client-templates
  cat > /opt/vpn-panel/client-templates/client.ovpn << EOF
# این یک نمونه‌ی عمومی است و به‌تنهایی کار نمی‌کند: هر کاربر یک سرتیفیکیت
# اختصاصی لازم دارد (بدون یوزر/پس - فقط سرتیفیکیت). برای هر کاربر، فایل
# .ovpn واقعی و کامل (شامل سرتیفیکیت خودش) را از پنل > صفحه‌ی «کاربران» >
# دکمه‌ی دانلود کانفیگ OpenVPN همان کاربر بگیرید - نه از این فایل نمونه.
client
dev tun
remote ${REMOTE_HOST} ${OPENVPN_UDP_PORT} udp
remote ${REMOTE_HOST} ${OPENVPN_TCP_PORT} tcp-client
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
verb 3

<ca>
$(cat "$CA_FILE")
</ca>

<tls-auth>
$(cat "$TA_FILE")
</tls-auth>
key-direction 1
EOF
fi

if [ -n "$FAILURES" ]; then
  echo "$FAILURES" >&2
  echo "VPN_PROTOCOLS_PARTIAL_FAILURE" >&2
  exit 1
fi

echo "VPN_PROTOCOLS_OK"
