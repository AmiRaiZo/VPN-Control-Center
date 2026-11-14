#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -r "$SCRIPT_DIR/apt_preflight.sh" ]; then
  # shellcheck source=apt_preflight.sh
  source "$SCRIPT_DIR/apt_preflight.sh"
fi

KEY="${1:-}"
if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root" >&2
  exit 1
fi
case "$KEY" in
  l2tp|ipsec|pptp|openvpn) ;;
  *) echo "Unsupported core protocol: $KEY" >&2; exit 2 ;;
esac

export DEBIAN_FRONTEND=noninteractive

wait_for_apt() {
  if declare -F vpn_panel_wait_for_apt_lock >/dev/null 2>&1; then
    vpn_panel_wait_for_apt_lock 600
    vpn_panel_repair_dpkg
  else
    local n=0
    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
      n=$((n+1))
      [ "$n" -le 300 ] || { echo "ERROR: apt/dpkg lock did not clear after 600 seconds" >&2; return 1; }
      sleep 2
    done
    dpkg --force-confdef --force-confold --configure -a
  fi
}

apt_package_available() {
  local package_name="$1"
  local candidate
  candidate=$(apt-cache policy "$package_name" 2>/dev/null | awk '/Candidate:/ {print $2; exit}')
  [ -n "$candidate" ] && [ "$candidate" != "(none)" ]
}

ensure_forwarding() {
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  mkdir -p /etc/sysctl.d
  echo 'net.ipv4.ip_forward=1' > /etc/sysctl.d/99-vpn-panel-forwarding.conf
}

restart_strongswan() {
  local unit=""
  if systemctl list-unit-files 2>/dev/null | grep -q '^strongswan-starter\.service'; then
    unit="strongswan-starter"
  elif systemctl list-unit-files 2>/dev/null | grep -q '^strongswan\.service'; then
    unit="strongswan"
  fi

  # A previous manual `ipsec start` can leave charon/starter outside the
  # systemd cgroup. Stop every owner, remove only stale runtime PID files, and
  # start one systemd-managed instance.
  command -v ipsec >/dev/null 2>&1 && ipsec stop >/dev/null 2>&1 || true
  systemctl stop strongswan-starter strongswan >/dev/null 2>&1 || true
  sleep 0.7
  for proc in charon charon-systemd starter; do
    pgrep -x "$proc" >/dev/null 2>&1 && pkill -TERM -x "$proc" >/dev/null 2>&1 || true
  done
  sleep 0.7
  for proc in charon charon-systemd starter; do
    pgrep -x "$proc" >/dev/null 2>&1 && pkill -KILL -x "$proc" >/dev/null 2>&1 || true
  done
  rm -f /run/charon.pid /var/run/charon.pid /run/starter.charon.pid /var/run/starter.charon.pid

  if [ -n "$unit" ]; then
    systemctl daemon-reload
    systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    systemctl enable "$unit" >/dev/null 2>&1 || true
    systemctl start "$unit"
  elif command -v ipsec >/dev/null 2>&1; then
    ipsec start
  else
    echo "ERROR: no usable strongSwan service was found" >&2
    return 1
  fi

  for _i in 1 2 3 4 5 6 7 8 9 10; do
    if { pgrep -x charon >/dev/null 2>&1 || pgrep -x charon-systemd >/dev/null 2>&1; } \
       && ss -H -lun 2>/dev/null | grep -Eq ':500([[:space:]]|$)' \
       && ss -H -lun 2>/dev/null | grep -Eq ':4500([[:space:]]|$)'; then
      return 0
    fi
    sleep 0.5
  done
  echo "ERROR: strongSwan did not become ready on UDP/500 and UDP/4500" >&2
  journalctl -u "${unit:-strongswan-starter}" -n 60 --no-pager >&2 || true
  return 1
}

restart_xl2tpd() {
  local l2tp_port
  l2tp_port=$(awk -F= '/^[[:space:]]*port[[:space:]]*=/{gsub(/[[:space:]]/, "", $2); print $2; exit}' /etc/xl2tpd/xl2tpd.conf 2>/dev/null || true)
  l2tp_port="${l2tp_port:-1701}"
  systemctl stop xl2tpd >/dev/null 2>&1 || true
  sleep 0.4
  pgrep -x xl2tpd >/dev/null 2>&1 && pkill -TERM -x xl2tpd >/dev/null 2>&1 || true
  sleep 0.5
  pgrep -x xl2tpd >/dev/null 2>&1 && pkill -KILL -x xl2tpd >/dev/null 2>&1 || true
  rm -f /run/xl2tpd/xl2tpd.pid /var/run/xl2tpd/xl2tpd.pid /var/run/xl2tpd.pid
  systemctl reset-failed xl2tpd >/dev/null 2>&1 || true
  systemctl enable xl2tpd >/dev/null 2>&1 || true
  systemctl start xl2tpd
  for _i in 1 2 3 4 5 6 7 8 9 10; do
    if pgrep -x xl2tpd >/dev/null 2>&1 && ss -H -lun 2>/dev/null | grep -Eq ":${l2tp_port}([[:space:]]|$)"; then
      return 0
    fi
    sleep 0.5
  done
  echo "ERROR: xl2tpd did not become ready on UDP/${l2tp_port}" >&2
  journalctl -u xl2tpd -n 60 --no-pager >&2 || true
  return 1
}

ensure_ipsec_base() {
  mkdir -p /etc
  if [ ! -s /etc/ipsec.conf ]; then
    cat > /etc/ipsec.conf <<'IPSECBASE'
config setup
    uniqueids=no
IPSECBASE
  elif ! grep -q '^config setup' /etc/ipsec.conf; then
    tmp=$(mktemp)
    printf 'config setup\n    uniqueids=no\n\n' > "$tmp"
    cat /etc/ipsec.conf >> "$tmp"
    cat "$tmp" > /etc/ipsec.conf
    rm -f "$tmp"
  fi
  touch /etc/ipsec.secrets
  chmod 600 /etc/ipsec.secrets
}

ensure_l2tp_conn() {
  if ! grep -q '^conn L2TP-PSK' /etc/ipsec.conf; then
    cat >> /etc/ipsec.conf <<'L2TPCONN'

conn L2TP-PSK
    keyexchange=ikev1
    authby=secret
    type=transport
    left=%defaultroute
    leftprotoport=17/1701
    right=%any
    rightprotoport=17/%any
    forceencaps=yes
    auto=add
L2TPCONN
  fi
  if ! grep -qE '^\s*:\s*PSK\s+"' /etc/ipsec.secrets; then
    printf ': PSK "%s"\n' "$(openssl rand -hex 16)" >> /etc/ipsec.secrets
  fi
  chmod 600 /etc/ipsec.secrets
}

ensure_masquerade() {
  local subnet="$1" iface
  iface=$(ip route show default 2>/dev/null | awk 'NR==1{print $5}')
  if [ -z "$iface" ]; then
    echo "ERROR: could not detect the default network interface for NAT" >&2
    return 1
  fi
  iptables -t nat -C POSTROUTING -s "$subnet" -o "$iface" \
    -m comment --comment "vpnpanel-${KEY}-nat" -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -s "$subnet" -o "$iface" \
      -m comment --comment "vpnpanel-${KEY}-nat" -j MASQUERADE

  # NAT alone is insufficient on hosts whose FORWARD policy is DROP (a very
  # common UFW/cloud baseline): the tunnel connects but clients have no
  # internet.  Permit traffic originating from this VPN subnet and only
  # established return traffic back into it.
  iptables -C FORWARD -s "$subnet" -m comment --comment "vpnpanel-${KEY}-forward-out" -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -s "$subnet" -m comment --comment "vpnpanel-${KEY}-forward-out" -j ACCEPT
  iptables -C FORWARD -d "$subnet" -m conntrack --ctstate ESTABLISHED,RELATED \
    -m comment --comment "vpnpanel-${KEY}-forward-in" -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -d "$subnet" -m conntrack --ctstate ESTABLISHED,RELATED \
      -m comment --comment "vpnpanel-${KEY}-forward-in" -j ACCEPT
  iptables -t mangle -C FORWARD -s "$subnet" -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
    iptables -t mangle -A FORWARD -s "$subnet" -p tcp --tcp-flags SYN,RST SYN \
      -j TCPMSS --clamp-mss-to-pmtu
  command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true
}

ensure_ipsec() {
  vpn_panel_install_packages strongswan strongswan-pki libcharon-extra-plugins libstrongswan-extra-plugins iptables-persistent
  ensure_ipsec_base
  restart_strongswan
}

ensure_l2tp() {
  vpn_panel_install_packages strongswan strongswan-pki libcharon-extra-plugins libstrongswan-extra-plugins xl2tpd ppp iptables-persistent
  ensure_ipsec_base
  ensure_l2tp_conn
  mkdir -p /etc/xl2tpd /etc/ppp
  if [ ! -s /etc/xl2tpd/xl2tpd.conf ]; then
    cat > /etc/xl2tpd/xl2tpd.conf <<'L2TPD'
[global]
port = 1701

[lns default]
ip range = 192.168.42.10-192.168.42.250
local ip = 192.168.42.1
require authentication = yes
require chap = yes
refuse pap = yes
ppp debug = no
pppoptfile = /etc/ppp/options.xl2tpd
length bit = yes
pass peer = yes
L2TPD
  fi
  if [ ! -s /etc/ppp/options.xl2tpd ]; then
    cat > /etc/ppp/options.xl2tpd <<'PPPL2TP'
name l2tpd
ipcp-accept-local
ipcp-accept-remote
nodefaultroute
asyncmap 0
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
require-mppe-128
ms-dns 1.1.1.1
ms-dns 8.8.8.8
proxyarp
nobsdcomp
nodeflate
novj
novjccomp
nopcomp
noaccomp
lcp-echo-interval 30
lcp-echo-failure 10
lcp-echo-adaptive
mtu 1400
mru 1400
PPPL2TP
  fi
  # Older panel builds created a valid-looking PPP file without the
  # identity marker used by pppd and by runtime health checks. Repair it in
  # place instead of treating the protocol as not installed.
  if ! grep -Eq '^[[:space:]]*name[[:space:]]+l2tpd([[:space:]]|$)' /etc/ppp/options.xl2tpd; then
    tmp=$(mktemp)
    printf 'name l2tpd
' > "$tmp"
    cat /etc/ppp/options.xl2tpd >> "$tmp"
    cat "$tmp" > /etc/ppp/options.xl2tpd
    rm -f "$tmp"
  fi
  chmod 600 /etc/ppp/options.xl2tpd
  touch /etc/ppp/chap-secrets
  chmod 600 /etc/ppp/chap-secrets
  cat > /etc/modules-load.d/l2tp.conf <<'MODULES'
l2tp_ppp
l2tp_netlink
MODULES
  modprobe l2tp_ppp 2>/dev/null || true
  modprobe l2tp_netlink 2>/dev/null || true
  restart_strongswan
  restart_xl2tpd
  ensure_masquerade '192.168.42.0/24'
}

ensure_pptp() {
  [ -x "$SCRIPT_DIR/setup_pptp.sh" ] || { echo "ERROR: setup_pptp.sh is missing" >&2; exit 3; }
  vpn_panel_install_packages ppp iptables-persistent python3
  mkdir -p /etc/ppp
  if [ ! -s /etc/pptpd.conf ]; then
    cat > /etc/pptpd.conf <<'PPTPD'
option /etc/ppp/pptpd-options
localip 192.168.43.1
remoteip 192.168.43.10-192.168.43.250
PPTPD
  fi
  if [ ! -s /etc/ppp/pptpd-options ]; then
    cat > /etc/ppp/pptpd-options <<'PPPPPTP'
name pptpd
ipcp-accept-local
ipcp-accept-remote
nodefaultroute
asyncmap 0
refuse-pap
refuse-chap
refuse-mschap
require-mschap-v2
require-mppe-128
ms-dns 8.8.8.8
ms-dns 8.8.4.4
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
PPPPPTP
  fi
  touch /etc/ppp/chap-secrets
  chmod 600 /etc/pptpd.conf /etc/ppp/pptpd-options /etc/ppp/chap-secrets
  modprobe ppp_mppe 2>/dev/null || true
  modprobe nf_conntrack_pptp 2>/dev/null || true
  modprobe ip_gre 2>/dev/null || true

  # Always run the panel-owned PPTP repair helper, even when a binary and unit
  # already exist. Old installs may contain a stale listen address, duplicate
  # pool directives, an ABI-incompatible logwtmp plugin, an orphaned daemon or
  # the obsolete forking/PID-file unit. The helper normalizes all of those and
  # verifies both the process and TCP/1723 before returning success.
  if ! SKIP_APT_UPDATE=1 bash "$SCRIPT_DIR/setup_pptp.sh" --start; then
    echo "[repair] Initial PPTP start failed; reinstalling the daemon and retrying once..." >&2
    SKIP_APT_UPDATE=1 bash "$SCRIPT_DIR/setup_pptp.sh" --force --install-only
    SKIP_APT_UPDATE=1 bash "$SCRIPT_DIR/setup_pptp.sh" --start
  fi
  ensure_masquerade '192.168.43.0/24'
}

ensure_openvpn() {
  vpn_panel_install_packages openvpn easy-rsa iptables-persistent
  mkdir -p /etc/openvpn/server/ccd
  if [ ! -s /etc/openvpn/server/ca.crt ] || [ ! -s /etc/openvpn/server/server.crt ] || [ ! -s /etc/openvpn/server/server.key ]; then
    echo "[*] Creating a missing OpenVPN PKI..."
    rm -rf /etc/openvpn/easy-rsa
    make-cadir /etc/openvpn/easy-rsa
    cd /etc/openvpn/easy-rsa
    cat > vars <<'EOF'
set_var EASYRSA_ALGO ec
set_var EASYRSA_DIGEST "sha512"
EOF
    export EASYRSA_BATCH=1
    ./easyrsa init-pki
    EASYRSA_REQ_CN="VPN-Panel-CA" ./easyrsa build-ca nopass
    ./easyrsa gen-req server nopass
    ./easyrsa sign-req server server
    ./easyrsa gen-dh
    openvpn --genkey secret ta.key 2>/dev/null || openvpn --genkey --secret ta.key
    ./easyrsa gen-crl
    cp pki/ca.crt pki/private/server.key pki/issued/server.crt pki/dh.pem ta.key pki/crl.pem /etc/openvpn/server/
    chmod 600 /etc/openvpn/server/server.key /etc/openvpn/server/ta.key
    chmod 644 /etc/openvpn/server/crl.pem
  fi
  common='ca ca.crt
cert server.crt
key server.key
dh dh.pem
tls-auth ta.key 0
topology subnet
client-config-dir ccd
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"
keepalive 10 60
cipher AES-256-GCM
auth SHA256
user nobody
group nogroup
persist-key
persist-tun
crl-verify crl.pem
script-security 3
auth-user-pass-verify /opt/vpn-panel/scripts/openvpn_auth.sh via-env
client-connect /opt/vpn-panel/scripts/openvpn_connect.sh
client-disconnect /opt/vpn-panel/scripts/openvpn_disconnect.sh
duplicate-cn
log-append /var/log/openvpn.log
verb 3'
  if [ ! -s /etc/openvpn/server/server-udp.conf ]; then
    cat > /etc/openvpn/server/server-udp.conf <<OPENVPNUDP
port 1194
proto udp
dev tun
server 10.8.0.0 255.255.255.0
$common
ifconfig-pool-persist ipp-udp.txt
management 127.0.0.1 7505
status /etc/openvpn/server/openvpn-status-udp.log 10
explicit-exit-notify 1
OPENVPNUDP
  fi
  if [ ! -s /etc/openvpn/server/server-tcp.conf ]; then
    cat > /etc/openvpn/server/server-tcp.conf <<OPENVPNTCP
port 1194
proto tcp-server
dev tun
server 10.8.1.0 255.255.255.0
$common
ifconfig-pool-persist ipp-tcp.txt
management 127.0.0.1 7506
status /etc/openvpn/server/openvpn-status-tcp.log 10
OPENVPNTCP
  fi
  local prefix='openvpn-server@'
  systemctl list-unit-files 2>/dev/null | grep -q '^openvpn@' && ! systemctl list-unit-files 2>/dev/null | grep -q '^openvpn-server@' && prefix='openvpn@'
  systemctl enable "${prefix}server-udp" "${prefix}server-tcp" >/dev/null 2>&1 || true
  systemctl restart "${prefix}server-udp"
  systemctl restart "${prefix}server-tcp"
  ensure_masquerade '10.8.0.0/24'
  ensure_masquerade '10.8.1.0/24'
}

wait_for_apt
if [ "${SKIP_APT_UPDATE:-0}" != "1" ]; then vpn_panel_apt_get update; fi
ensure_forwarding
case "$KEY" in
  ipsec) ensure_ipsec ;;
  l2tp) ensure_l2tp ;;
  pptp) ensure_pptp ;;
  openvpn) ensure_openvpn ;;
esac

echo "CORE_PROTOCOL_OK $KEY"
