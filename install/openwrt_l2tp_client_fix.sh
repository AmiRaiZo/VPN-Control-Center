#!/bin/sh
# Run on the OpenWrt router itself (not on the VPN server).
# Usage: sh openwrt_l2tp_client_fix.sh [network_interface_name]
set -eu

TARGET_IF="${1:-}"
if [ -z "$TARGET_IF" ]; then
  TARGET_IF="$(uci show network 2>/dev/null | sed -n "s/^network\.\([A-Za-z0-9_]*\)\.proto='l2tp'$/\1/p" | head -n1)"
fi
if [ -z "$TARGET_IF" ]; then
  echo "ERROR: no OpenWrt network interface with proto=l2tp was found." >&2
  exit 1
fi

case "$TARGET_IF" in
  *[!A-Za-z0-9_]*) echo "ERROR: invalid interface section: $TARGET_IF" >&2; exit 1 ;;
esac

printf '%s\n' "$TARGET_IF" > /etc/vpn-panel-l2tp-interface

# Keep the global WAN default route intact so the L2TP control channel can
# always reach the VPN server. LAN traffic is sent through a dedicated policy
# table below; this also avoids a recursive/default-route loop.
# DNS and MTU are normalised to avoid ISP-DNS and PMTU black holes.
uci set "network.${TARGET_IF}.defaultroute=0"
uci set "network.${TARGET_IF}.peerdns=0"
uci -q delete "network.${TARGET_IF}.dns" || true
uci add_list "network.${TARGET_IF}.dns=1.1.1.1"
uci add_list "network.${TARGET_IF}.dns=8.8.8.8"
uci set "network.${TARGET_IF}.metric=5"
uci set "network.${TARGET_IF}.mtu=1280"

# OpenWrt maps the two keepalive values to:
#   lcp-echo-failure <first>  +  lcp-echo-interval <second>
# A number of cellular/NAT routers briefly delay or reorder L2TP control
# traffic. The old/default aggressive LCP watchdog can then redial a healthy
# tunnel at a fixed cadence (commonly around two minutes). Use a tolerant
# watchdog and adaptive echoes so real payload traffic itself proves that the
# link is alive instead of being interrupted by false LCP failures.
uci set "network.${TARGET_IF}.keepalive=10 30"
OLD_PPPD_OPTIONS="$(uci -q get "network.${TARGET_IF}.pppd_options" 2>/dev/null || true)"
case " $OLD_PPPD_OPTIONS " in
  *" lcp-echo-adaptive "*) : ;;
  *) uci set "network.${TARGET_IF}.pppd_options=${OLD_PPPD_OPTIONS:+$OLD_PPPD_OPTIONS }lcp-echo-adaptive" ;;
esac

# Dedicated firewall zone: LAN -> L2TP, with masquerade and MSS fixing.
uci -q delete firewall.vpnl2tp || true
uci set firewall.vpnl2tp='zone'
uci set firewall.vpnl2tp.name='vpnl2tp'
uci add_list "firewall.vpnl2tp.network=${TARGET_IF}"
uci set firewall.vpnl2tp.input='REJECT'
uci set firewall.vpnl2tp.output='ACCEPT'
uci set firewall.vpnl2tp.forward='REJECT'
uci set firewall.vpnl2tp.masq='1'
uci set firewall.vpnl2tp.mtu_fix='1'

uci -q delete firewall.lan_to_vpnl2tp || true
uci set firewall.lan_to_vpnl2tp='forwarding'
uci set firewall.lan_to_vpnl2tp.src='lan'
uci set firewall.lan_to_vpnl2tp.dest='vpnl2tp'

# Force ordinary LAN DNS through a public resolver over the VPN instead of an
# ISP-only DNS address that becomes unreachable after the tunnel route changes.
uci -q delete firewall.vpnl2tp_dns || true
uci set firewall.vpnl2tp_dns='redirect'
uci set firewall.vpnl2tp_dns.name='VPN-L2TP-DNS'
uci set firewall.vpnl2tp_dns.src='lan'
uci set firewall.vpnl2tp_dns.src_dport='53'
uci set firewall.vpnl2tp_dns.proto='tcp udp'
uci set firewall.vpnl2tp_dns.dest='vpnl2tp'
uci set firewall.vpnl2tp_dns.dest_ip='1.1.1.1'
uci set firewall.vpnl2tp_dns.dest_port='53'
uci set firewall.vpnl2tp_dns.target='DNAT'

# A policy table makes LAN traffic prefer the VPN without replacing the WAN
# default route needed to reach the L2TP server itself. It is rebuilt whenever
# the interface reconnects and removed automatically on ifdown.
mkdir -p /etc/hotplug.d/iface
cat > /etc/hotplug.d/iface/99-vpn-panel-l2tp <<'HOTPLUG'
#!/bin/sh
TARGET_IF="$(cat /etc/vpn-panel-l2tp-interface 2>/dev/null || true)"
[ -n "$TARGET_IF" ] || exit 0
[ "${INTERFACE:-}" = "$TARGET_IF" ] || exit 0
TABLE=124
PREF=11240

LAN_DEV="$(ubus call network.interface.lan status 2>/dev/null | jsonfilter -e '@.l3_device' 2>/dev/null || true)"
[ -n "$LAN_DEV" ] || LAN_DEV=br-lan
LAN_CIDR="$(ip -4 route show dev "$LAN_DEV" proto kernel 2>/dev/null | awk '$1 ~ /\// {print $1; exit}')"
[ -n "$LAN_CIDR" ] || exit 0

while ip -4 rule del pref "$PREF" 2>/dev/null; do :; done
ip -4 route flush table "$TABLE" 2>/dev/null || true

if [ "${ACTION:-}" = "ifup" ]; then
  VPN_DEV="$(ubus call "network.interface.${TARGET_IF}" status 2>/dev/null | jsonfilter -e '@.l3_device' 2>/dev/null || true)"
  [ -n "$VPN_DEV" ] || exit 0
  ip -4 route replace default dev "$VPN_DEV" table "$TABLE"
  ip -4 rule add pref "$PREF" from "$LAN_CIDR" lookup "$TABLE"
  ip -4 route flush cache 2>/dev/null || true
fi
HOTPLUG
chmod 0755 /etc/hotplug.d/iface/99-vpn-panel-l2tp

uci commit network
uci commit firewall
/etc/init.d/firewall restart
ifdown "$TARGET_IF" 2>/dev/null || true
sleep 2
ifup "$TARGET_IF"
sleep 4
INTERFACE="$TARGET_IF" ACTION=ifup /etc/hotplug.d/iface/99-vpn-panel-l2tp || true

echo "OK: OpenWrt L2TP full-tunnel/firewall routing applied to network.${TARGET_IF}"
