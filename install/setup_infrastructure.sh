#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -r "$SCRIPT_DIR/apt_preflight.sh" ]; then
  # shellcheck source=apt_preflight.sh
  source "$SCRIPT_DIR/apt_preflight.sh"
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "Please run as root" >&2
  exit 1
fi

echo "[*] Enabling IPv4 forwarding..."
sysctl -w net.ipv4.ip_forward=1
mkdir -p /etc/sysctl.d
cat > /etc/sysctl.d/99-vpn-panel-forwarding.conf <<'EOF'
net.ipv4.ip_forward=1
EOF

echo "[*] Installing networking utilities..."
export DEBIAN_FRONTEND=noninteractive
wait_for_apt() {
  local n=0
  while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
    n=$((n+1))
    if [ "$n" -gt 60 ]; then
      echo "ERROR: apt/dpkg lock did not clear after 120 seconds" >&2
      exit 1
    fi
    echo "[*] Waiting for apt/dpkg lock..."
    sleep 2
  done
  dpkg --force-confdef --force-confold --configure -a || true
}
wait_for_apt
if [ "${SKIP_APT_UPDATE:-0}" != "1" ]; then vpn_panel_apt_get update; fi
vpn_panel_install_packages iproute2 iptables iptables-persistent nftables ppp kmod procps curl ca-certificates

echo "[*] Loading persistent kernel modules..."
modules=(ppp_generic l2tp_ppp l2tp_netlink nf_conntrack_pptp ip_gre ppp_mppe tun af_key esp4 xfrm_user)
: > /etc/modules-load.d/vpn-panel.conf
module_ready() {
  local module="$1"
  local normalized="${module//-/_}"
  [ -d "/sys/module/$normalized" ] || modprobe "$module" 2>/dev/null
}

missing_modules=()
for module in "${modules[@]}"; do
  if module_ready "$module"; then
    echo "$module" >> /etc/modules-load.d/vpn-panel.conf
    printf '  ✓ %s\n' "$module"
  else
    missing_modules+=("$module")
    printf '  ! %s (first load attempt failed)\n' "$module"
  fi
done

# Ubuntu cloud/minimal kernels often keep TUN/PPP helpers in the matching
# linux-modules-extra package.  Install it only when modules are genuinely
# unavailable; on Debian or custom kernels where the package does not exist,
# the check is harmless and the final verification below remains authoritative.
if [ "${#missing_modules[@]}" -gt 0 ]; then
  extra_pkg="linux-modules-extra-$(uname -r)"
  if apt-cache show "$extra_pkg" >/dev/null 2>&1; then
    echo "[*] Installing missing kernel module bundle: $extra_pkg"
    vpn_panel_install_packages "$extra_pkg"
    depmod -a || true
  fi
fi

still_missing=()
for module in "${modules[@]}"; do
  if module_ready "$module"; then
    grep -qxF "$module" /etc/modules-load.d/vpn-panel.conf || echo "$module" >> /etc/modules-load.d/vpn-panel.conf
  else
    still_missing+=("$module")
  fi
done

# /dev/net/tun can be absent in a minimal container even when the kernel TUN
# driver is available.  Create the standard device node before health checks.
if module_ready tun; then
  mkdir -p /dev/net
  [ -e /dev/net/tun ] || mknod /dev/net/tun c 10 200
  chmod 0666 /dev/net/tun || true
fi

critical_modules=(ppp_generic l2tp_ppp ip_gre ppp_mppe tun esp4 xfrm_user)
critical_missing=()
optional_missing=()
for module in "${still_missing[@]}"; do
  is_critical=0
  for required in "${critical_modules[@]}"; do
    if [ "$module" = "$required" ]; then is_critical=1; break; fi
  done
  if [ "$is_critical" -eq 1 ]; then critical_missing+=("$module"); else optional_missing+=("$module"); fi
done
if [ "${#optional_missing[@]}" -gt 0 ]; then
  echo "[!] Optional kernel helpers unavailable (continuing): ${optional_missing[*]}"
fi
if [ "${#critical_missing[@]}" -gt 0 ]; then
  echo "ERROR: required VPN kernel modules are unavailable: ${critical_missing[*]}" >&2
  echo "Install a kernel with PPP/TUN/IPsec support (or its matching linux-modules-extra package) and reboot, then run this repair again." >&2
  exit 8
fi

NET_IFACE=$(ip route show default | awk 'NR==1{print $5}')
if [ -n "$NET_IFACE" ]; then
  echo "[*] Default interface: $NET_IFACE"
fi

echo "[*] Repairing forwarding rules for installed VPN backends..."
FORWARD_SUBNETS=()
[ -f /etc/xl2tpd/xl2tpd.conf ] && FORWARD_SUBNETS+=("192.168.42.0/24")
[ -f /etc/pptpd.conf ] && FORWARD_SUBNETS+=("192.168.43.0/24")
[ -f /etc/openvpn/server/server-udp.conf ] && FORWARD_SUBNETS+=("10.8.0.0/24")
[ -f /etc/openvpn/server/server-tcp.conf ] && FORWARD_SUBNETS+=("10.8.1.0/24")
[ -f /etc/accel-ppp/sstp.conf ] && FORWARD_SUBNETS+=("192.168.45.0/24")
if [ -s /etc/ocserv/ocserv.conf ]; then
  OCSERV_LIVE_CIDR=$(python3 - /etc/ocserv/ocserv.conf <<'PYOCNET'
from pathlib import Path
import ipaddress, sys
vals = {}
for raw in Path(sys.argv[1]).read_text(encoding='utf-8', errors='replace').splitlines():
    line = raw.strip()
    if not line or line.startswith('#') or '=' not in line:
        continue
    key, value = (part.strip() for part in line.split('=', 1))
    if key in {'ipv4-network', 'ipv4-netmask'}:
        vals[key] = value.strip('"\'')
network = vals.get('ipv4-network', '')
mask = vals.get('ipv4-netmask', '255.255.255.0')
try:
    candidate = network if '/' in network else f"{network}/{mask}"
    print(ipaddress.ip_network(candidate, strict=False))
except Exception:
    pass
PYOCNET
  )
  [ -n "$OCSERV_LIVE_CIDR" ] && FORWARD_SUBNETS+=("$OCSERV_LIVE_CIDR")
fi
grep -q '^conn IKEv2-MSCHAPv2' /etc/ipsec.conf 2>/dev/null && FORWARD_SUBNETS+=("10.10.11.0/24")
for subnet in "${FORWARD_SUBNETS[@]}"; do
  safe_tag=$(echo "$subnet" | tr './' '--')
  iptables -C FORWARD -s "$subnet" -m comment --comment "vpnpanel-${safe_tag}-forward-out" -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 1 -s "$subnet" -m comment --comment "vpnpanel-${safe_tag}-forward-out" -j ACCEPT
  iptables -C FORWARD -d "$subnet" -m conntrack --ctstate ESTABLISHED,RELATED \
    -m comment --comment "vpnpanel-${safe_tag}-forward-in" -j ACCEPT 2>/dev/null || \
    iptables -I FORWARD 1 -d "$subnet" -m conntrack --ctstate ESTABLISHED,RELATED \
      -m comment --comment "vpnpanel-${safe_tag}-forward-in" -j ACCEPT
  iptables -t mangle -C FORWARD -s "$subnet" -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null || \
    iptables -t mangle -A FORWARD -s "$subnet" -p tcp --tcp-flags SYN,RST SYN \
      -j TCPMSS --clamp-mss-to-pmtu
done
netfilter-persistent save >/dev/null 2>&1 || true

echo "INFRASTRUCTURE_OK"
