#!/bin/bash
# Fast per-session routing guard. The periodic full repair owns persistent pool
# rules; this helper gives a just-created tunnel an immediate /32 forwarding and
# NAT path before the protocol hook returns.
set -u
[ "$(id -u)" -eq 0 ] || exit 0

MODE="${1:-}"
PROTO="${2:-unknown}"
VIF="${3:-}"
TUNNEL_IP="${4:-}"
TRANSITION="${5:-fresh}"
case "$MODE" in --up|--down) ;; *) exit 0 ;; esac
case "$TRANSITION" in fresh|handover) ;; *) TRANSITION="fresh" ;; esac

[[ "$VIF" =~ ^[A-Za-z0-9_.:@+-]{1,32}$ ]] || exit 0
/usr/bin/python3 - "$TUNNEL_IP" <<'PY' >/dev/null 2>&1 || exit 0
import ipaddress, sys
ip = ipaddress.ip_address(sys.argv[1])
raise SystemExit(0 if ip.version == 4 else 1)
PY

command -v iptables >/dev/null 2>&1 || exit 0
ROUTE_INFO=$(ip -4 route get 1.1.1.1 2>/dev/null | head -n1)
NET_IFACE=$(printf '%s\n' "$ROUTE_INFO" | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
EGRESS_IP=$(printf '%s\n' "$ROUTE_INFO" | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')
ROUTE_TABLE=$(printf '%s\n' "$ROUTE_INFO" | awk '{for(i=1;i<=NF;i++) if($i=="table"){print $(i+1); exit}}')
[ -n "$ROUTE_TABLE" ] || ROUTE_TABLE=main
[[ "$ROUTE_TABLE" =~ ^[A-Za-z0-9_.-]+$ ]] || ROUTE_TABLE=main
if [[ "$NET_IFACE" =~ ^(ppp|tun|tap|vpns|sstp) ]]; then
  NET_IFACE=""
fi
[ -n "$NET_IFACE" ] || NET_IFACE=$(ip -4 route show default 2>/dev/null | awk '$1=="default" && $5 !~ /^(ppp|tun|tap|vpns|sstp)/ {print $5; exit}')
[ -n "$NET_IFACE" ] || exit 0

mkdir -p /run/vpn-panel 2>/dev/null || true
exec 9>/run/vpn-panel/network-repair.lock
flock -w 1 9 || exit 0
IPT="$(command -v iptables)"
ipt() { "$IPT" -w 2 "$@"; }

# The full repair normally creates these chains. Create them lazily so the very
# first connection after a reboot/update is not left without Internet.
ipt -N VPNPANEL_FORWARD 2>/dev/null || true
ipt -t nat -N VPNPANEL_NAT 2>/dev/null || true
ipt -t nat -N VPNPANEL_DNS 2>/dev/null || true
ipt -t mangle -N VPNPANEL_MSS 2>/dev/null || true
ipt -t mangle -N VPNPANEL_ROUTE 2>/dev/null || true
ipt -C FORWARD -j VPNPANEL_FORWARD 2>/dev/null || ipt -I FORWARD 1 -j VPNPANEL_FORWARD
ipt -t nat -C POSTROUTING -j VPNPANEL_NAT 2>/dev/null || ipt -t nat -I POSTROUTING 1 -j VPNPANEL_NAT
ipt -t nat -C PREROUTING -j VPNPANEL_DNS 2>/dev/null || ipt -t nat -I PREROUTING 1 -j VPNPANEL_DNS
ipt -t mangle -C FORWARD -j VPNPANEL_MSS 2>/dev/null || ipt -t mangle -I FORWARD 1 -j VPNPANEL_MSS
ipt -t mangle -C PREROUTING -j VPNPANEL_ROUTE 2>/dev/null || ipt -t mangle -I PREROUTING 1 -j VPNPANEL_ROUTE

# Some VPS images keep the usable default route in a provider-specific policy
# table. Forwarded VPN packets still carry their private tunnel source during
# route lookup, so they can miss that table even though MASQUERADE is correct.
# Mark only VPN client traffic before lookup and send it through the exact table
# that the host itself uses for Internet access.
ROUTE_MARK=0x52a00000
ROUTE_MASK=0xffff0000
ip -4 rule show 2>/dev/null | grep -q "fwmark 0x52a00000/0xffff0000.*lookup ${ROUTE_TABLE}" || \
  ip -4 rule add pref 11520 fwmark "${ROUTE_MARK}/${ROUTE_MASK}" lookup "$ROUTE_TABLE" 2>/dev/null || true

SAFE_PROTO=$(printf '%s' "$PROTO" | tr -cd 'A-Za-z0-9_-')
SAFE_IFACE=$(printf '%s' "$VIF" | tr -cd 'A-Za-z0-9_.-')
TAG="vpnpanel-session-${SAFE_PROTO}-${SAFE_IFACE}-${TUNNEL_IP}"

remove_tagged() {
  local table="$1" chain="$2" line
  if [ "$table" = filter ]; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      line="${line/-A /-D }"
      eval "ipt $line" >/dev/null 2>&1 || true
    done < <(ipt -S "$chain" 2>/dev/null | grep -F -- "$TAG" || true)
  else
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      line="${line/-A /-D }"
      eval "ipt -t $table $line" >/dev/null 2>&1 || true
    done < <(ipt -t "$table" -S "$chain" 2>/dev/null | grep -F -- "$TAG" || true)
  fi
}

remove_tagged filter VPNPANEL_FORWARD
remove_tagged nat VPNPANEL_NAT
remove_tagged nat VPNPANEL_DNS
remove_tagged mangle VPNPANEL_MSS
remove_tagged mangle VPNPANEL_ROUTE
# Older/direct emergency rules live in the parent chains rather than the
# managed child chains. Remove only this session's tagged copies.
remove_tagged filter FORWARD
remove_tagged nat POSTROUTING
remove_tagged nat PREROUTING
remove_tagged mangle PREROUTING
remove_tagged mangle FORWARD
[ "$MODE" = "--down" ] && exit 0

# PPP normally installs this peer host route itself. Reasserting it is harmless
# and protects upgraded/policy-routed hosts where a stale route briefly points
# the assigned client IP at an older pppN interface.
ip -4 route replace "${TUNNEL_IP}/32" dev "$VIF" scope link 2>/dev/null || true

sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
for knob in "/proc/sys/net/ipv4/conf/all/rp_filter" "/proc/sys/net/ipv4/conf/default/rp_filter" "/proc/sys/net/ipv4/conf/${VIF}/rp_filter" "/proc/sys/net/ipv4/conf/${NET_IFACE}/rp_filter"; do
  [ -w "$knob" ] && printf '0\n' > "$knob" || true
done
for knob in "/proc/sys/net/ipv4/conf/${VIF}/forwarding" "/proc/sys/net/ipv4/conf/${NET_IFACE}/forwarding"; do
  [ -w "$knob" ] && printf '1\n' > "$knob" || true
done

# Mark before route lookup so policy-routed providers use the same table as the
# host's own traffic.
ipt -t mangle -I VPNPANEL_ROUTE 1 -i "$VIF" -s "${TUNNEL_IP}/32" \
  -m comment --comment "$TAG-route" -j MARK --set-xmark "${ROUTE_MARK}/${ROUTE_MASK}"

# L2TP/PPTP clients such as OpenWrt can keep an ISP-only DNS address even after
# the tunnel becomes the default route. Transparently send classic DNS through
# public resolvers, matching OpenConnect's tunnel-all-dns behavior.
ipt -t nat -I VPNPANEL_DNS 1 -i "$VIF" -s "${TUNNEL_IP}/32" -p udp --dport 53 \
  -m comment --comment "$TAG-dns-udp" -j DNAT --to-destination 1.1.1.1:53
ipt -t nat -I VPNPANEL_DNS 1 -i "$VIF" -s "${TUNNEL_IP}/32" -p tcp --dport 53 \
  -m comment --comment "$TAG-dns-tcp" -j DNAT --to-destination 1.1.1.1:53

ipt -I VPNPANEL_FORWARD 1 -i "$VIF" -s "${TUNNEL_IP}/32" -o "$NET_IFACE" \
  -m comment --comment "$TAG-out" -j ACCEPT
ipt -I VPNPANEL_FORWARD 1 -i "$NET_IFACE" -o "$VIF" -d "${TUNNEL_IP}/32" \
  -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment "$TAG-in" -j ACCEPT
if [[ "$EGRESS_IP" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
  ipt -t nat -I VPNPANEL_NAT 1 -s "${TUNNEL_IP}/32" -o "$NET_IFACE" \
    -m comment --comment "$TAG-nat" -j SNAT --to-source "$EGRESS_IP"
else
  ipt -t nat -I VPNPANEL_NAT 1 -s "${TUNNEL_IP}/32" -o "$NET_IFACE" \
    -m comment --comment "$TAG-nat" -j MASQUERADE
fi
ipt -t mangle -I VPNPANEL_MSS 1 -i "$VIF" -s "${TUNNEL_IP}/32" -p tcp --tcp-flags SYN,RST SYN \
  -m comment --comment "$TAG-mss" -j TCPMSS --clamp-mss-to-pmtu

# Parent chains contain one stable jump to the managed chains. Session-specific
# duplicates in FORWARD/POSTROUTING/PREROUTING used to grow the ruleset and made
# every connect mutate global hot-path chains.

# A true reconnect handover must preserve established NAT/conntrack state until
# the replacement PPP has taken over. Purging it here is exactly what makes an
# active speed test or TCP download freeze for a moment. Fresh sessions still
# clear stale state so a recycled pool address cannot inherit another client
# flow.
if [ "$TRANSITION" != "handover" ] && command -v conntrack >/dev/null 2>&1; then
  conntrack -D -s "$TUNNEL_IP" >/dev/null 2>&1 || true
  conntrack -D -d "$TUNNEL_IP" >/dev/null 2>&1 || true
fi

logger -t vpn-panel-network-repair "session routing ready protocol=$PROTO iface=$VIF tunnel_ip=$TUNNEL_IP transition=$TRANSITION egress=$NET_IFACE src=${EGRESS_IP:-auto} table=$ROUTE_TABLE"
exit 0
