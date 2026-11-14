#!/usr/bin/env bash
# Repair inbound transport for L2TP/IPsec and OpenVPN without changing admin intent.
# Safe to run repeatedly on the controller or a managed node.
set -Eeuo pipefail

[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root" >&2; exit 1; }
INSTALL_DIR="${VPN_PANEL_INSTALL_DIR:-/opt/vpn-panel}"
BACKEND_DIR="$INSTALL_DIR/backend"
VENV_PY="$BACKEND_DIR/venv/bin/python"
STATE_DIR="/var/lib/vpn-panel/manual-protocol-stop"
LOCK_FILE="/run/vpn-panel/ingress-repair.lock"
mkdir -p /run/vpn-panel "$STATE_DIR"
exec 9>"$LOCK_FILE"
flock -w 15 9 || { echo "INGRESS_REPAIR_SKIPPED lock-timeout"; exit 0; }

bool01() { case "${1:-}" in 1|true|TRUE|yes|YES|on|ON) echo 1;; *) echo 0;; esac; }
manual_stopped() { [ -e "$STATE_DIR/$1" ]; }

# Read authoritative switches and ports from the database. Fall back to live
# configuration files so the emergency script still works while the API is down.
L2TP_ENABLED=1
IKEV2_ENABLED=0
OPENVPN_ENABLED=1
PPTP_ENABLED=1
PPTP_PORT=1723
L2TP_PORT="$(awk -F= '/^[[:space:]]*port[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' /etc/xl2tpd/xl2tpd.conf 2>/dev/null || true)"
L2TP_PORT="${L2TP_PORT:-1701}"
OVPN_UDP_PORT="$(awk '/^[[:space:]]*port[[:space:]]+[0-9]+/{print $2; exit}' /etc/openvpn/server/server-udp.conf 2>/dev/null || true)"
OVPN_TCP_PORT="$(awk '/^[[:space:]]*port[[:space:]]+[0-9]+/{print $2; exit}' /etc/openvpn/server/server-tcp.conf 2>/dev/null || true)"
OVPN_UDP_PORT="${OVPN_UDP_PORT:-1194}"
OVPN_TCP_PORT="${OVPN_TCP_PORT:-1194}"
VPN_DOMAIN=""
PUBLIC_IP=""

if [ -x "$VENV_PY" ] && [ -f "$BACKEND_DIR/app/main.py" ]; then
  eval "$(cd "$BACKEND_DIR" && "$VENV_PY" - <<'PY'
import shlex
from app.database import SessionLocal
from app.models import Setting
from app.config import get_settings

db = SessionLocal()
try:
    rows = {r.key: r.value for r in db.query(Setting).all()}
    def b(key, default=False):
        raw = rows.get(key)
        if raw is None:
            return default
        return str(raw).strip().lower() in {'1','true','yes','on'}
    def i(key, default):
        try:
            value = int(rows.get(key, default))
            return value if 1 <= value <= 65535 else default
        except Exception:
            return default
    data = {
        'L2TP_ENABLED': '1' if b('l2tp_enabled', True) else '0',
        'IKEV2_ENABLED': '1' if b('ikev2_enabled', False) else '0',
        'OPENVPN_ENABLED': '1' if b('openvpn_enabled', True) else '0',
        'PPTP_ENABLED': '1' if b('pptp_enabled', True) else '0',
        'PPTP_PORT': str(i('pptp_port', 1723)),
        'L2TP_PORT': str(i('l2tp_port', 1701)),
        'OVPN_UDP_PORT': str(i('openvpn_udp_port', 1194)),
        'OVPN_TCP_PORT': str(i('openvpn_tcp_port', 1194)),
        'VPN_DOMAIN': str(rows.get('vpn_domain') or '').strip(),
        'PUBLIC_IP': str(get_settings().PUBLIC_SERVER_IP or '').strip(),
    }
    for key, value in data.items():
        print(f'{key}={shlex.quote(value)}')
finally:
    db.close()
PY
)" || true
fi

for value in "$L2TP_PORT" "$PPTP_PORT" "$OVPN_UDP_PORT" "$OVPN_TCP_PORT"; do
  [[ "$value" =~ ^[0-9]+$ ]] && [ "$value" -ge 1 ] && [ "$value" -le 65535 ] || {
    echo "ERROR: invalid configured VPN port: $value" >&2
    exit 2
  }
done

# With a single protocol selected, ss omits the redundant Netid column;
# the local address is field 4 for both UDP and TCP. The old UDP probe read
# field 5 (peer address), falsely declared every healthy UDP listener missing,
# and restarted OpenVPN/IPsec/xl2tpd on every watchdog pass.
listener_udp() { ss -H -lun 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)$1$"; }
listener_tcp() { ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)$1$"; }
unit_exists() { systemctl show "$1" -p LoadState --value 2>/dev/null | grep -qx loaded; }
active() { systemctl is-active --quiet "$1" 2>/dev/null; }

find_ipsec_unit() {
  local unit
  for unit in strongswan-starter strongswan ipsec; do
    unit_exists "$unit" && { printf '%s' "$unit"; return 0; }
  done
  return 1
}
find_ovpn_unit() {
  local instance="$1" unit
  for unit in "openvpn-server@${instance}" "openvpn@${instance}"; do
    unit_exists "$unit" && { printf '%s' "$unit"; return 0; }
  done
  printf 'openvpn-server@%s' "$instance"
}

restart_unit_if_needed() {
  local key="$1" unit="$2" proto="$3" port="$4"
  manual_stopped "$key" && { echo "SKIP $key manually-stopped"; return 0; }

  # A transient ss/listener probe must never flap an active VPN daemon. For
  # xl2tpd specifically, restarting destroys the in-memory tunnel table and
  # causes the new PID to flood "Can not find tunnel" for every old packet.
  if [ "$key" = "l2tp" ] && pgrep -x xl2tpd >/dev/null 2>&1; then
    return 0
  fi
  if [ "$key" = "pptp" ] && pgrep -x pptpd >/dev/null 2>&1; then
    return 0
  fi
  if active "$unit"; then
    if { [ "$proto" = udp ] && ! listener_udp "$port"; } || { [ "$proto" = tcp ] && ! listener_tcp "$port"; }; then
      echo "WARN $key unit=$unit is active but listener probe missed ${proto}/${port}; restart suppressed"
    fi
    return 0
  fi

  echo "REPAIR $key unit=$unit expected=${proto}/${port}"
  systemctl reset-failed "$unit" >/dev/null 2>&1 || true
  systemctl enable "$unit" >/dev/null 2>&1 || true
  systemctl start "$unit" >/dev/null 2>&1 || true
  for _ in $(seq 1 20); do
    if active "$unit"; then
      if [ "$proto" = udp ] && listener_udp "$port"; then return 0; fi
      if [ "$proto" = tcp ] && listener_tcp "$port"; then return 0; fi
    fi
    sleep 0.25
  done
  echo "ERROR $key did not expose ${proto}/${port}" >&2
  systemctl status "$unit" --no-pager -l 2>&1 | tail -n 25 >&2 || true
  return 1
}

FAILED=0
if [ "$(bool01 "$L2TP_ENABLED")" = 1 ] || [ "$(bool01 "$IKEV2_ENABLED")" = 1 ]; then
  if ! manual_stopped ipsec; then
    IPSEC_UNIT="$(find_ipsec_unit || true)"
    if [ -n "$IPSEC_UNIT" ]; then
      if active "$IPSEC_UNIT" || pgrep -x charon >/dev/null 2>&1 || pgrep -x charon-systemd >/dev/null 2>&1; then
        if ! listener_udp 500 || ! listener_udp 4500; then
          echo "WARN ipsec daemon is active but listener probe missed udp/500 or udp/4500; restart suppressed"
        fi
      else
        echo "REPAIR ipsec unit=$IPSEC_UNIT expected=udp/500,udp/4500"
        systemctl reset-failed "$IPSEC_UNIT" >/dev/null 2>&1 || true
        systemctl enable "$IPSEC_UNIT" >/dev/null 2>&1 || true
        systemctl start "$IPSEC_UNIT" >/dev/null 2>&1 || true
      fi
    elif command -v ipsec >/dev/null 2>&1; then
      echo "REPAIR ipsec command=ipsec expected=udp/500,udp/4500"
      ipsec restart >/dev/null 2>&1 || true
    else
      echo "ERROR no strongSwan service or ipsec command is installed" >&2
      FAILED=1
    fi
    for _ in $(seq 1 20); do listener_udp 500 && listener_udp 4500 && break; sleep 0.25; done
    listener_udp 500 && listener_udp 4500 || { echo "ERROR IPsec listeners 500/4500 are missing" >&2; FAILED=1; }
  fi
fi
if [ "$(bool01 "$L2TP_ENABLED")" = 1 ]; then
  restart_unit_if_needed l2tp xl2tpd udp "$L2TP_PORT" || FAILED=1
fi

if [ "$(bool01 "$PPTP_ENABLED")" = 1 ]; then
  # PPTP has two transports: TCP/1723 for control and IP protocol 47 (GRE)
  # for PPP frames. A working TCP control session without GRE stalls at LCP.
  modprobe ip_gre >/dev/null 2>&1 || true
  modprobe nf_conntrack_pptp >/dev/null 2>&1 || true
  modprobe nf_nat_pptp >/dev/null 2>&1 || true
  restart_unit_if_needed pptp pptpd tcp "$PPTP_PORT" || FAILED=1
fi

if [ "$(bool01 "$OPENVPN_ENABLED")" = 1 ]; then
  OVPN_UDP_UNIT="$(find_ovpn_unit server-udp)"
  OVPN_TCP_UNIT="$(find_ovpn_unit server-tcp)"
  restart_unit_if_needed openvpn_udp "$OVPN_UDP_UNIT" udp "$OVPN_UDP_PORT" || FAILED=1
  restart_unit_if_needed openvpn_tcp "$OVPN_TCP_UNIT" tcp "$OVPN_TCP_PORT" || FAILED=1
fi

# Dedicated top-of-INPUT chain. This survives UFW/provider terminal DROP rules
# better than appending individual ACCEPT rules near the end of INPUT.
apply_plain_iptables() {
  command -v iptables >/dev/null 2>&1 || return 0
  iptables -w 5 -N VPNPANEL_INPUT 2>/dev/null || true
  iptables -w 5 -F VPNPANEL_INPUT
  while iptables -w 5 -C INPUT -j VPNPANEL_INPUT 2>/dev/null; do iptables -w 5 -D INPUT -j VPNPANEL_INPUT || break; done
  # Keep the panel's explicit per-IP deny chains ahead of transport ACCEPTs.
  # Otherwise an ingress self-heal could accidentally let a banned IP bypass
  # VPN-PANEL-CUTS / VPN-PANEL-BANS.
  insert_pos=1
  for guard_chain in VPN-PANEL-CUTS VPN-PANEL-BANS; do
    if iptables -w 5 -S "$guard_chain" >/dev/null 2>&1; then
      while iptables -w 5 -C INPUT -j "$guard_chain" 2>/dev/null; do
        iptables -w 5 -D INPUT -j "$guard_chain" || break
      done
      iptables -w 5 -I INPUT "$insert_pos" -j "$guard_chain"
      insert_pos=$((insert_pos + 1))
    fi
  done
  iptables -w 5 -I INPUT "$insert_pos" -j VPNPANEL_INPUT
  iptables -w 5 -A VPNPANEL_INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  if { [ "$(bool01 "$L2TP_ENABLED")" = 1 ] || [ "$(bool01 "$IKEV2_ENABLED")" = 1 ]; } && ! manual_stopped ipsec; then
    iptables -w 5 -A VPNPANEL_INPUT -p udp --dport 500 -m comment --comment vpnpanel-ingress-ike -j ACCEPT
    iptables -w 5 -A VPNPANEL_INPUT -p udp --dport 4500 -m comment --comment vpnpanel-ingress-natt -j ACCEPT
    iptables -w 5 -A VPNPANEL_INPUT -p esp -m comment --comment vpnpanel-ingress-esp -j ACCEPT
  fi
  if [ "$(bool01 "$L2TP_ENABLED")" = 1 ] && ! manual_stopped l2tp; then
    iptables -w 5 -A VPNPANEL_INPUT -p udp --dport "$L2TP_PORT" -m comment --comment vpnpanel-ingress-l2tp -j ACCEPT
  fi
  if [ "$(bool01 "$PPTP_ENABLED")" = 1 ] && ! manual_stopped pptp; then
    iptables -w 5 -A VPNPANEL_INPUT -p tcp --dport "$PPTP_PORT" -m comment --comment vpnpanel-ingress-pptp-control -j ACCEPT
    iptables -w 5 -A VPNPANEL_INPUT -p gre -m comment --comment vpnpanel-ingress-pptp-gre -j ACCEPT
  fi
  if [ "$(bool01 "$OPENVPN_ENABLED")" = 1 ]; then
    manual_stopped openvpn_udp || iptables -w 5 -A VPNPANEL_INPUT -p udp --dport "$OVPN_UDP_PORT" -m comment --comment vpnpanel-ingress-ovpn-udp -j ACCEPT
    manual_stopped openvpn_tcp || iptables -w 5 -A VPNPANEL_INPUT -p tcp --dport "$OVPN_TCP_PORT" -m comment --comment vpnpanel-ingress-ovpn-tcp -j ACCEPT
  fi
}

if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi '^Status: active'; then
  { [ "$(bool01 "$L2TP_ENABLED")" = 1 ] || [ "$(bool01 "$IKEV2_ENABLED")" = 1 ]; } && ! manual_stopped ipsec && {
    ufw allow 500/udp comment vpnpanel-ingress-ike >/dev/null 2>&1 || true
    ufw allow 4500/udp comment vpnpanel-ingress-natt >/dev/null 2>&1 || true
    ufw allow proto esp from any to any comment vpnpanel-ingress-esp >/dev/null 2>&1 || true
  }
  [ "$(bool01 "$L2TP_ENABLED")" = 1 ] && ! manual_stopped l2tp && ufw allow "$L2TP_PORT/udp" comment vpnpanel-ingress-l2tp >/dev/null 2>&1 || true
  [ "$(bool01 "$PPTP_ENABLED")" = 1 ] && ! manual_stopped pptp && ufw allow "$PPTP_PORT/tcp" comment vpnpanel-ingress-pptp-control >/dev/null 2>&1 || true
  [ "$(bool01 "$PPTP_ENABLED")" = 1 ] && ! manual_stopped pptp && ufw allow proto gre from any to any comment vpnpanel-ingress-pptp-gre >/dev/null 2>&1 || true
  [ "$(bool01 "$OPENVPN_ENABLED")" = 1 ] && ! manual_stopped openvpn_udp && ufw allow "$OVPN_UDP_PORT/udp" comment vpnpanel-ingress-ovpn-udp >/dev/null 2>&1 || true
  [ "$(bool01 "$OPENVPN_ENABLED")" = 1 ] && ! manual_stopped openvpn_tcp && ufw allow "$OVPN_TCP_PORT/tcp" comment vpnpanel-ingress-ovpn-tcp >/dev/null 2>&1 || true
  # Also install the dedicated iptables chain because UFW may have a terminal
  # drop before late user rules on upgraded hosts.
  apply_plain_iptables
elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state 2>/dev/null | grep -q running; then
  { [ "$(bool01 "$L2TP_ENABLED")" = 1 ] || [ "$(bool01 "$IKEV2_ENABLED")" = 1 ]; } && ! manual_stopped ipsec && {
    firewall-cmd --permanent --add-port=500/udp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-port=4500/udp >/dev/null 2>&1 || true
    firewall-cmd --permanent --add-protocol=esp >/dev/null 2>&1 || true
  }
  [ "$(bool01 "$L2TP_ENABLED")" = 1 ] && ! manual_stopped l2tp && firewall-cmd --permanent --add-port="$L2TP_PORT/udp" >/dev/null 2>&1 || true
  [ "$(bool01 "$PPTP_ENABLED")" = 1 ] && ! manual_stopped pptp && firewall-cmd --permanent --add-port="$PPTP_PORT/tcp" >/dev/null 2>&1 || true
  [ "$(bool01 "$PPTP_ENABLED")" = 1 ] && ! manual_stopped pptp && firewall-cmd --permanent --add-protocol=gre >/dev/null 2>&1 || true
  [ "$(bool01 "$OPENVPN_ENABLED")" = 1 ] && ! manual_stopped openvpn_udp && firewall-cmd --permanent --add-port="$OVPN_UDP_PORT/udp" >/dev/null 2>&1 || true
  [ "$(bool01 "$OPENVPN_ENABLED")" = 1 ] && ! manual_stopped openvpn_tcp && firewall-cmd --permanent --add-port="$OVPN_TCP_PORT/tcp" >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
else
  apply_plain_iptables
fi
command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true

# Detect stale/proxied protocol domains. The backend will automatically publish
# the raw public IP while this condition exists, so new L2TP cards/OpenVPN files
# do not point at a CDN edge that cannot carry raw VPN traffic.
if [ -n "$VPN_DOMAIN" ] && [ -n "$PUBLIC_IP" ]; then
  RESOLVED="$(getent ahostsv4 "$VPN_DOMAIN" 2>/dev/null | awk '{print $1}' | sort -u | paste -sd, - || true)"
  case ",$RESOLVED," in
    *",$PUBLIC_IP,"*) echo "DOMAIN_OK $VPN_DOMAIN -> $PUBLIC_IP" ;;
    *) echo "DOMAIN_FALLBACK $VPN_DOMAIN resolves=${RESOLVED:-none}; profiles must use raw-ip=$PUBLIC_IP" ;;
  esac
fi

# Final proof: listeners plus top-of-chain ingress jump.
if [ "$(bool01 "$OPENVPN_ENABLED")" = 1 ]; then
  manual_stopped openvpn_udp || listener_udp "$OVPN_UDP_PORT" || FAILED=1
  manual_stopped openvpn_tcp || listener_tcp "$OVPN_TCP_PORT" || FAILED=1
fi
if [ "$(bool01 "$L2TP_ENABLED")" = 1 ]; then
  manual_stopped l2tp || listener_udp "$L2TP_PORT" || FAILED=1
fi
if [ "$(bool01 "$PPTP_ENABLED")" = 1 ]; then
  manual_stopped pptp || listener_tcp "$PPTP_PORT" || FAILED=1
fi
if { [ "$(bool01 "$L2TP_ENABLED")" = 1 ] || [ "$(bool01 "$IKEV2_ENABLED")" = 1 ]; } && ! manual_stopped ipsec; then
  listener_udp 500 && listener_udp 4500 || FAILED=1
fi
if command -v iptables >/dev/null 2>&1; then
  iptables -w 5 -C INPUT -j VPNPANEL_INPUT 2>/dev/null || FAILED=1
fi

printf 'INGRESS_STATUS l2tp=%s:%s pptp=%s:%s openvpn_udp=%s:%s openvpn_tcp=%s:%s result=%s\n' \
  "$L2TP_ENABLED" "$L2TP_PORT" "$PPTP_ENABLED" "$PPTP_PORT" "$OPENVPN_ENABLED" "$OVPN_UDP_PORT" "$OPENVPN_ENABLED" "$OVPN_TCP_PORT" \
  "$([ "$FAILED" -eq 0 ] && echo ok || echo failed)"
exit "$FAILED"
