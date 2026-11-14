#!/bin/bash
# Idempotent routing/NAT repair for every classic VPN protocol managed by the
# panel.  It intentionally reads the *live* protocol configs instead of using
# installer defaults, because admins can change address pools later from the
# panel (for example L2TP 192.168.42.0/24 -> 10.10.10.0/24).  A tunnel can
# authenticate successfully yet have no Internet when MASQUERADE/FORWARD rules
# still point at the old pool; this helper repairs that drift without touching
# connected sessions.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || exit 1

# Serialize timer, update and per-session hook repairs. Concurrent iptables
# mutations can otherwise leave a half-built chain for a newly connected user.
mkdir -p /run/vpn-panel 2>/dev/null || true
exec 9>/run/vpn-panel/network-repair.lock
flock -w 20 9 || { logger -t vpn-panel-network-repair "repair skipped: lock timeout"; exit 0; }

INSTALL_DIR="/opt/vpn-panel"
APPLY_CONFIG=0
case "${1:-}" in
  --apply-config) APPLY_CONFIG=1 ;;
  --network-only|"") APPLY_CONFIG=0 ;;
  *) echo "Usage: $0 [--network-only|--apply-config]" >&2; exit 2 ;;
esac

# OpenVPN drops privileges before invoking its auth/connect hooks. Do not
# expose the full panel.env to that account; publish a minimal dedicated file
# containing only BACKEND_PORT and INTERNAL_API_TOKEN. Numeric group fallback
# handles distributions that call gid 65534 either "nogroup" or "nobody".
if [ "$APPLY_CONFIG" -eq 1 ] && [ -x "$INSTALL_DIR/scripts/refresh_openvpn_runtime_env.sh" ]; then
  "$INSTALL_DIR/scripts/refresh_openvpn_runtime_env.sh" || \
    logger -t vpn-panel-openvpn-auth "runtime env refresh failed during config repair"
fi
if [ -d "$INSTALL_DIR" ]; then chmod o+x "$INSTALL_DIR" 2>/dev/null || true; fi
for helper in refresh_openvpn_runtime_env.sh openvpn_auth.sh openvpn_connect.sh openvpn_disconnect.sh admission_guard.sh ensure_session_networking.sh; do
  [ -f "$INSTALL_DIR/scripts/$helper" ] && chmod 0755 "$INSTALL_DIR/scripts/$helper" || true
done

command -v iptables >/dev/null 2>&1 || exit 0

# Resolve the real Internet egress on policy-routed hosts.
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
[ -n "$NET_IFACE" ] || { logger -t vpn-panel-network-repair "routing repair skipped: no IPv4 egress interface"; exit 0; }

# Keep routed VPN packets from being rejected by strict reverse-path checks.
sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.src_valid_mark=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.src_valid_mark=1 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null 2>&1 || true
sysctl -w net.ipv4.conf.default.send_redirects=0 >/dev/null 2>&1 || true
for knob in /proc/sys/net/ipv4/conf/*/rp_filter; do
  [ -w "$knob" ] && printf '0\n' > "$knob" || true
done
cat > /etc/sysctl.d/99-vpn-panel-routing.conf <<'SYSCTL'
net.ipv4.ip_forward=1
net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.default.rp_filter=0
net.ipv4.conf.all.src_valid_mark=1
net.ipv4.conf.default.src_valid_mark=1
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
SYSCTL

# In apply-config mode, retain the OpenConnect full-tunnel normalization from
# earlier releases.  Never restart ocserv while a vpns* session is active.
OCSERV_CONFIG_CHANGED=0
OCSERV_RESTART_DEFERRED=0
OCSERV_CONF="/etc/ocserv/ocserv.conf"
if [ "$APPLY_CONFIG" -eq 1 ] && [ -s "$OCSERV_CONF" ]; then
  CONF_HASH_BEFORE=$(sha256sum "$OCSERV_CONF" 2>/dev/null | awk '{print $1}' || true)
  /usr/bin/python3 - "$OCSERV_CONF" <<'PYOC'
from pathlib import Path
import re, sys
path = Path(sys.argv[1])
lines = path.read_text(encoding='utf-8', errors='replace').splitlines()
managed = {
    'route': 'route = default',
    'tunnel-all-dns': 'tunnel-all-dns = true',
    'switch-to-tcp-timeout': 'switch-to-tcp-timeout = 8',
}
out, seen = [], set()
for raw in lines:
    stripped = raw.strip()
    match = re.match(r'^([A-Za-z0-9_-]+)\s*=.*$', stripped)
    key = match.group(1) if match else ''
    if key == 'no-compress':
        continue
    if key in managed:
        if key not in seen:
            out.append(managed[key]); seen.add(key)
        continue
    out.append(raw)
for key, value in managed.items():
    if key not in seen:
        out.append(value)
while out and not out[-1].strip():
    out.pop()
path.write_text('\n'.join(out) + '\n', encoding='utf-8')
PYOC
  CONF_HASH_AFTER=$(sha256sum "$OCSERV_CONF" 2>/dev/null | awk '{print $1}' || true)
  [ "$CONF_HASH_BEFORE" != "$CONF_HASH_AFTER" ] && OCSERV_CONFIG_CHANGED=1
fi

# In apply-config mode, normalize the full-tunnel pieces that must be present on
# each node. This repairs old nodes that could authenticate users but either did
# not advertise DNS/default routing or used an overly aggressive PPP echo setup.
if [ "$APPLY_CONFIG" -eq 1 ]; then
  /usr/bin/python3 <<'PYFULL'
from pathlib import Path
import re

def read(path):
    p = Path(path)
    try: return p, p.read_text(encoding='utf-8', errors='replace')
    except OSError: return p, ''

def write_if_changed(path, before, after):
    if before and before != after:
        path.write_text(after.rstrip() + '\n', encoding='utf-8')

def ensure_line(text, pattern, line):
    rx = re.compile(pattern, re.M)
    if rx.search(text):
        return rx.sub(line, text, count=1)
    return text.rstrip() + '\n' + line + '\n'

# L2TP/PPTP compatibility: preserve the DNS and MTU/MRU values selected in
# the panel. Older releases treated this repair helper as an installer and
# forcibly rewrote L2TP to MTU/MRU 1280 plus public DNS defaults. Because this
# helper runs after updates/repairs, that silently overrode an administrator's
# saved 1400 (or custom DNS) and made only the repaired node negotiate a lower
# Actual MTU. The repair helper now owns only missing defaults and compatibility
# flags; the structured protocol settings remain authoritative.
for path in ('/etc/ppp/options.xl2tpd', '/etc/ppp/pptpd-options'):
    p, text = read(path)
    if not text: continue
    out = text
    if not re.search(r'(?m)^\s*ms-dns\s+\S+', out):
        out = out.rstrip() + '\nms-dns 1.1.1.1\nms-dns 8.8.8.8\n'
    if not re.search(r'(?m)^\s*mtu\s+\d+\s*$', out):
        out = out.rstrip() + '\nmtu 1400\n'
    if not re.search(r'(?m)^\s*mru\s+\d+\s*$', out):
        out = out.rstrip() + '\nmru 1400\n'
    # Adaptive echo stays silent while real packets are flowing, so it avoids
    # the old OpenWrt false-disconnect problem while still retiring an
    # abandoned L2TP process after an unclean router disconnect.
    out = re.sub(r'(?m)^\s*lcp-echo-(?:interval|failure|adaptive)\b.*\n?', '', out)
    if path.endswith('options.xl2tpd'):
        out = out.rstrip() + '\nlcp-echo-interval 30\nlcp-echo-failure 10\nlcp-echo-adaptive\n'
    for option in ('nobsdcomp', 'nodeflate', 'novj', 'novjccomp', 'nopcomp', 'noaccomp'):
        if not re.search(rf'(?m)^\s*{re.escape(option)}\s*$', out):
            out = out.rstrip() + f'\n{option}\n'
    write_if_changed(p, text, out)

# Do not let an unacknowledged xl2tpd Hello tear down a data-carrying tunnel.
# Some embedded L2TP clients keep forwarding payload traffic but mishandle the
# 60-second control Hello; a low retry budget causes the exact 2-minute pause.
# Handover cleanup is owned by the panel after the replacement PPP is usable.
p, text = read('/etc/xl2tpd/xl2tpd.conf')
if text:
    lines = text.splitlines()
    section = ''
    replaced = False
    inserted = False
    out = []
    for raw in lines:
        stripped = raw.strip()
        if stripped.startswith('[') and stripped.endswith(']'):
            if section == 'global' and not replaced and not inserted:
                out.append('max retries = 100')
                inserted = True
            section = stripped[1:-1].strip().lower()
        if section == 'global' and re.match(r'^max\s+retries\s*=', stripped, re.I):
            if not replaced:
                out.append('max retries = 100')
                replaced = True
            continue
        out.append(raw)
    if section == 'global' and not replaced and not inserted:
        out.append('max retries = 100')
    repaired = '\n'.join(out)
    # Bound the exponential retry delay so a genuinely dead peer is still
    # revisited regularly while the high retry budget protects X28-class peers.
    if re.search(r'(?mi)^\s*cap\s+backoff\s*=', repaired):
        repaired = re.sub(r'(?mi)^\s*cap\s+backoff\s*=.*$', 'cap backoff = 60', repaired, count=1)
    else:
        repaired = repaired.rstrip() + '\ncap backoff = 60'
    write_if_changed(p, text, repaired)

# OpenVPN must push a full default route and DNS on every server in a combined
# profile. Preserve all other crypto/PKI settings.
for path in list(Path('/etc/openvpn/server').glob('*.conf')) + list(Path('/etc/openvpn').glob('server-*.conf')):
    try: text = path.read_text(encoding='utf-8', errors='replace')
    except OSError: continue
    out = text
    if not re.search(r'(?m)^\s*push\s+"redirect-gateway\b', out):
        out = out.rstrip() + '\npush "redirect-gateway def1 bypass-dhcp"\n'
    if not re.search(r'(?m)^\s*push\s+"dhcp-option DNS\s+', out):
        out = out.rstrip() + '\npush "dhcp-option DNS 1.1.1.1"\npush "dhcp-option DNS 8.8.8.8"\n'
    write_if_changed(path, text, out)

# accel-ppp sends peer DNS only from the documented [dns] section and requires
# its dns module. Repair old SSTP configs that had dns1/dns2 in the wrong place.
p, text = read('/etc/accel-ppp/sstp.conf')
if text:
    dns_plugin = any(Path(root).exists() and any(Path(root).rglob('libdns.so')) for root in ('/usr/lib','/usr/lib64','/usr/local/lib'))
    lines = text.splitlines()
    out, section = [], ''
    module_has_dns = False
    had_dns_section = any(raw.strip().lower() == '[dns]' for raw in lines)
    dns1, dns2 = None, None
    for raw in lines:
        stripped = raw.strip()
        if stripped.startswith('[') and stripped.endswith(']'):
            section = stripped[1:-1].strip().lower()
        if section == 'modules' and stripped == 'dns':
            module_has_dns = True
        if dns_plugin and re.match(r'^dns1\s*=', stripped):
            value = stripped.split('=',1)[1].strip()
            if value:
                dns1 = value
            if section != 'dns':
                continue
        if dns_plugin and re.match(r'^dns2\s*=', stripped):
            value = stripped.split('=',1)[1].strip()
            if value:
                dns2 = value
            if section != 'dns':
                continue
        out.append(raw)
    if dns_plugin and not dns1:
        dns1 = '1.1.1.1'
    if dns_plugin and not had_dns_section and not dns2:
        dns2 = '8.8.8.8'
    if dns_plugin and not module_has_dns:
        # Insert immediately after [modules], before the next section.
        inserted = False
        rebuilt = []
        for idx, raw in enumerate(out):
            rebuilt.append(raw)
            if raw.strip().lower() == '[modules]':
                rebuilt.append('dns'); inserted = True
        out = rebuilt if inserted else ['[modules]', 'dns', *out]
    joined = '\n'.join(out)
    if dns_plugin and re.search(r'(?m)^\[dns\]\s*$', joined):
        block = re.search(r'(?ms)^\[dns\]\s*\n.*?(?=^\[|\Z)', joined)
        value = block.group(0) if block else '[dns]\n'
        value = re.sub(r'(?m)^\s*dns1\s*=.*$', f'dns1={dns1}', value)
        if dns2:
            value = re.sub(r'(?m)^\s*dns2\s*=.*$', f'dns2={dns2}', value)
        else:
            value = re.sub(r'(?m)^\s*dns2\s*=.*\n?', '', value)
        if not re.search(r'(?m)^\s*dns1\s*=', value): value += f'\ndns1={dns1}'
        if dns2 and not re.search(r'(?m)^\s*dns2\s*=', value): value += f'\ndns2={dns2}'
        joined = joined[:block.start()] + value.rstrip() + '\n\n' + joined[block.end():]
    elif dns_plugin:
        joined = joined.rstrip() + f'\n\n[dns]\ndns1={dns1}' + (f'\ndns2={dns2}' if dns2 else '') + '\n'
    # A full pair of /1 ranges includes the 192.168.45.x tunnel pool and
    # triggers "requested IP cannot be assigned" after successful auth. Replace
    # the whole section with accel-ppp's disable-check sentinel.
    range_lines = joined.splitlines()
    rebuilt = []
    section = ''
    found_range = False
    for raw in range_lines:
        stripped = raw.strip()
        if stripped.startswith('[') and stripped.endswith(']'):
            section = stripped[1:-1].strip().lower()
            rebuilt.append(raw)
            if section == 'client-ip-range':
                found_range = True
                rebuilt.append('0.0.0.0/0')
            continue
        if section == 'client-ip-range':
            continue
        rebuilt.append(raw)
    if not found_range:
        rebuilt += ['', '[client-ip-range]', '0.0.0.0/0']
    joined = '\n'.join(rebuilt)
    # accel-ppp adaptive echo uses lcp-echo-timeout with interval.
    if re.search(r'(?m)^\s*lcp-echo-interval\s*=', joined):
        joined = re.sub(r'(?m)^\s*lcp-echo-interval\s*=.*$', 'lcp-echo-interval=2', joined, count=1)
    else:
        joined += '\nlcp-echo-interval=2\n'
    if re.search(r'(?m)^\s*lcp-echo-timeout\s*=', joined):
        joined = re.sub(r'(?m)^\s*lcp-echo-timeout\s*=.*$', 'lcp-echo-timeout=12', joined, count=1)
    else:
        # Put it in the ppp section when possible.
        joined = re.sub(r'(?m)^(\[ppp\])[ \t]*$', r'\1\nlcp-echo-timeout=12', joined, count=1)
    write_if_changed(p, text, joined)

# IKEv2 full tunnel: preserve the connection but ensure all client traffic is
# selected and public DNS is advertised.
p, text = read('/etc/ipsec.conf')
if text:
    block = re.search(r'(?ms)^\s*conn\s+IKEv2-MSCHAPv2\b.*?(?=^\s*conn\s+|\Z)', text)
    if block:
        value = block.group(0)
        value = ensure_line(value, r'(?m)^\s*leftsubnet\s*=.*$', '    leftsubnet=0.0.0.0/0')
        if not re.search(r'(?m)^\s*rightdns\s*=', value):
            value = value.rstrip() + '\n    rightdns=1.1.1.1,8.8.8.8\n'
        out = text[:block.start()] + value + text[block.end():]
        write_if_changed(p, text, out)
PYFULL
fi

# Discover every live IPv4 client pool from its actual config.  Output format:
#   protocol|CIDR
# The parser accepts full ranges and abbreviated PPTP ranges such as
# 10.20.20.10-250, CIDR values, and network+netmask pairs.
mapfile -t VPN_POOLS < <(/usr/bin/python3 <<'PYPOOLS'
from pathlib import Path
import glob, ipaddress, re

seen = set()

def emit(proto, network):
    try:
        net = ipaddress.ip_network(str(network), strict=False)
    except Exception:
        return
    if net.version != 4:
        return
    key = (proto, str(net))
    if key not in seen:
        seen.add(key)
        print(f"{proto}|{net}")

def read(path):
    try:
        return Path(path).read_text(encoding='utf-8', errors='replace')
    except OSError:
        return ''

def expand_range(raw):
    raw = str(raw or '').strip().strip('"\'')
    if not raw:
        return None
    if '/' in raw and '-' not in raw:
        try: return ipaddress.ip_network(raw, strict=False)
        except Exception: return None
    left = raw.split('-', 1)[0].strip()
    try:
        ip = ipaddress.ip_address(left)
        return ipaddress.ip_network(f"{ip}/24", strict=False)
    except Exception:
        return None

# L2TP/xl2tpd
text = read('/etc/xl2tpd/xl2tpd.conf')
m = re.search(r'(?mi)^\s*ip\s+range\s*=\s*([^\r\n#;]+)', text)
if m: emit('l2tp', expand_range(m.group(1)))

# PPTP
text = read('/etc/pptpd.conf')
m = re.search(r'(?mi)^\s*remoteip\s+([^\r\n#;]+)', text)
if m: emit('pptp', expand_range(m.group(1)))

# OpenVPN: include every installed server instance/pool.
for path in sorted(set(glob.glob('/etc/openvpn/server/*.conf') + glob.glob('/etc/openvpn/server-*.conf'))):
    text = read(path)
    for match in re.finditer(r'(?mi)^\s*server\s+([0-9.]+)\s+([0-9.]+)\s*$', text):
        try: emit('openvpn', ipaddress.ip_network(f"{match.group(1)}/{match.group(2)}", strict=False))
        except Exception: pass
    for match in re.finditer(r'(?mi)^\s*server\s+([0-9.]+/[0-9]+)\s*$', text):
        emit('openvpn', match.group(1))

# SSTP accel-ppp: prefer the range inside [ip-pool], fall back to gw address.
text = read('/etc/accel-ppp/sstp.conf')
section = ''
sstp_range = None
sstp_gw = None
for raw in text.splitlines():
    line = raw.strip()
    if not line or line.startswith(('#',';')): continue
    if line.startswith('[') and line.endswith(']'):
        section = line[1:-1].strip().lower(); continue
    if 'gw-ip-address' in line and '=' in line:
        sstp_gw = line.split('=',1)[1].strip()
    if section == 'ip-pool' and '=' not in line and '-' in line:
        sstp_range = line
if sstp_range: emit('sstp', expand_range(sstp_range))
elif sstp_gw: emit('sstp', expand_range(sstp_gw))

# IKEv2 strongSwan
text = read('/etc/ipsec.conf')
block = re.search(r'(?ms)^\s*conn\s+IKEv2-MSCHAPv2\b.*?(?=^\s*conn\s+|\Z)', text)
if block:
    m = re.search(r'(?mi)^\s*rightsourceip\s*=\s*([^\r\n#;]+)', block.group(0))
    if m: emit('ikev2', expand_range(m.group(1)))

# OpenConnect/ocserv.  Keep the OCSERV_CIDR semantics used by prior releases.
text = read('/etc/ocserv/ocserv.conf')
vals = {}
for raw in text.splitlines():
    line = raw.strip()
    if not line or line.startswith('#') or '=' not in line: continue
    key, value = (part.strip() for part in line.split('=',1))
    if key in {'ipv4-network','ipv4-netmask'}: vals[key] = value.strip('"\'')
network = vals.get('ipv4-network','')
mask = vals.get('ipv4-netmask','255.255.255.0')
if network:
    candidate = network if '/' in network else f"{network}/{mask}"
    emit('openconnect', candidate)
PYPOOLS
)

IPT="$(command -v iptables)"

ipt() { "$IPT" -w 5 "$@"; }

# A timer is a verifier, not a traffic-path reinstaller. Older builds flushed
# five top-level chains every minute and saved the complete netfilter ruleset,
# briefly serialising packet processing on xtables. Skip all mutation when the
# desired pools/egress are unchanged and the managed jumps still exist.
STATE_FILE="/run/vpn-panel/network-repair.state"
RULESET_REVISION="v23252"
DESIRED_STATE=$(printf '%s\n' \
  "revision=${RULESET_REVISION}" \
  "iface=${NET_IFACE}" \
  "src=${EGRESS_IP:-auto}" \
  "table=${ROUTE_TABLE}" \
  "pools=$(printf '%s,' "${VPN_POOLS[@]:-}")" | sha256sum | awk '{print $1}')

managed_rules_healthy() {
  ipt -S VPNPANEL_FORWARD >/dev/null 2>&1 || return 1
  ipt -t nat -S VPNPANEL_NAT >/dev/null 2>&1 || return 1
  ipt -t nat -S VPNPANEL_DNS >/dev/null 2>&1 || return 1
  ipt -t mangle -S VPNPANEL_MSS >/dev/null 2>&1 || return 1
  ipt -t mangle -S VPNPANEL_ROUTE >/dev/null 2>&1 || return 1
  ipt -C FORWARD -j VPNPANEL_FORWARD >/dev/null 2>&1 || return 1
  ipt -t nat -C POSTROUTING -j VPNPANEL_NAT >/dev/null 2>&1 || return 1
  ipt -t nat -C PREROUTING -j VPNPANEL_DNS >/dev/null 2>&1 || return 1
  ipt -t mangle -C FORWARD -j VPNPANEL_MSS >/dev/null 2>&1 || return 1
  ipt -t mangle -C PREROUTING -j VPNPANEL_ROUTE >/dev/null 2>&1 || return 1
  ip -4 rule show 2>/dev/null | grep -q "fwmark 0x52a00000/0xffff0000.*lookup ${ROUTE_TABLE}"
}

if [ "$APPLY_CONFIG" -eq 0 ] && [ -s "$STATE_FILE" ] \
   && [ "$(cat "$STATE_FILE" 2>/dev/null || true)" = "$DESIRED_STATE" ] \
   && managed_rules_healthy; then
  logger -t vpn-panel-network-repair "routing already healthy; no netfilter mutation"
  exit 0
fi

ensure_chain() {
  local table="$1" chain="$2" parent="$3"
  if [ "$table" = "filter" ]; then
    ipt -N "$chain" 2>/dev/null || true
    ipt -F "$chain"
    while ipt -C "$parent" -j "$chain" 2>/dev/null; do ipt -D "$parent" -j "$chain" || break; done
    ipt -I "$parent" 1 -j "$chain"
  else
    ipt -t "$table" -N "$chain" 2>/dev/null || true
    ipt -t "$table" -F "$chain"
    while ipt -t "$table" -C "$parent" -j "$chain" 2>/dev/null; do ipt -t "$table" -D "$parent" -j "$chain" || break; done
    ipt -t "$table" -I "$parent" 1 -j "$chain"
  fi
}

# Clamp SYN MSS to the actual route PMTU. The previous fixed 1280 value cut
# useful TCP payload size even on healthy 1400-byte L2TP/IPsec paths and was a
# direct throughput regression.
# A dedicated top-of-chain jump makes ACCEPT final before UFW/provider terminal
# rules. Direct rules appended by old releases could sit after a DROP policy and
# therefore never match even though `iptables -S` looked correct.
ensure_chain filter VPNPANEL_FORWARD FORWARD
ensure_chain nat VPNPANEL_NAT POSTROUTING
ensure_chain nat VPNPANEL_DNS PREROUTING
ensure_chain mangle VPNPANEL_MSS FORWARD
ensure_chain mangle VPNPANEL_ROUTE PREROUTING

ROUTE_MARK=0x52a00000
ROUTE_MASK=0xffff0000
while ip -4 rule del fwmark "${ROUTE_MARK}/${ROUTE_MASK}" 2>/dev/null; do :; done
ip -4 rule add pref 11520 fwmark "${ROUTE_MARK}/${ROUTE_MASK}" lookup "$ROUTE_TABLE" 2>/dev/null || true

# Existing connections must keep working while the pool list is rebuilt.
ipt -A VPNPANEL_FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

apply_pool_rules() {
  local proto="$1" cidr="$2"
  ipt -t mangle -A VPNPANEL_ROUTE -s "$cidr" \
    -m comment --comment "vpnpanel-${proto}-route-live" \
    -j MARK --set-xmark "${ROUTE_MARK}/${ROUTE_MASK}"
  # Keep full-tunnel clients from continuing to query an ISP/private DNS that
  # is unreachable after the VPN route takes over. This is the classic-protocol
  # equivalent of OpenConnect tunnel-all-dns.
  ipt -t nat -A VPNPANEL_DNS -s "$cidr" -p udp --dport 53 \
    -m comment --comment "vpnpanel-${proto}-dns-udp-live" \
    -j DNAT --to-destination 1.1.1.1:53
  ipt -t nat -A VPNPANEL_DNS -s "$cidr" -p tcp --dport 53 \
    -m comment --comment "vpnpanel-${proto}-dns-tcp-live" \
    -j DNAT --to-destination 1.1.1.1:53
  if [[ "$EGRESS_IP" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
    ipt -t nat -A VPNPANEL_NAT -s "$cidr" -o "$NET_IFACE" \
      -m comment --comment "vpnpanel-${proto}-nat-live" -j SNAT --to-source "$EGRESS_IP"
  else
    ipt -t nat -A VPNPANEL_NAT -s "$cidr" -o "$NET_IFACE" \
      -m comment --comment "vpnpanel-${proto}-nat-live" -j MASQUERADE
  fi
  ipt -A VPNPANEL_FORWARD -s "$cidr" -o "$NET_IFACE" \
    -m comment --comment "vpnpanel-${proto}-forward-out-live" -j ACCEPT
  ipt -A VPNPANEL_FORWARD -i "$NET_IFACE" -d "$cidr" \
    -m conntrack --ctstate ESTABLISHED,RELATED \
    -m comment --comment "vpnpanel-${proto}-forward-in-live" -j ACCEPT
  ipt -t mangle -A VPNPANEL_MSS -s "$cidr" -p tcp --tcp-flags SYN,RST SYN \
    -m comment --comment "vpnpanel-${proto}-mss-out-live" -j TCPMSS --clamp-mss-to-pmtu
  ipt -t mangle -A VPNPANEL_MSS -d "$cidr" -p tcp --tcp-flags SYN,RST SYN \
    -m comment --comment "vpnpanel-${proto}-mss-in-live" -j TCPMSS --clamp-mss-to-pmtu
}

REPAIRED=""
OCSERV_CIDR=""
for entry in "${VPN_POOLS[@]:-}"; do
  [ -n "$entry" ] || continue
  proto="${entry%%|*}"
  cidr="${entry#*|}"
  [ "$proto" = "$entry" ] && continue
  apply_pool_rules "$proto" "$cidr"
  [ "$proto" = "openconnect" ] && OCSERV_CIDR="$cidr"
  REPAIRED="${REPAIRED}${REPAIRED:+,}${proto}:${cidr}"
done

# Live session interfaces are handled by ensure_session_networking.sh at
# connect/disconnect time. Rebuilding interface-specific rules in the periodic
# verifier caused avoidable rule churn and stale ppp/tun entries.

# PPTP helpers are harmless when PPTP is not installed and required on kernels
# that do not auto-assign the GRE conntrack helper.
for module in nf_conntrack nf_conntrack_pptp nf_nat_pptp ip_gre; do modprobe "$module" 2>/dev/null || true; done

# Persist only after this invocation actually changed the managed ruleset.
command -v netfilter-persistent >/dev/null 2>&1 && netfilter-persistent save >/dev/null 2>&1 || true

# Verify the exact jump/rule set instead of treating a zero exit from one
# command as proof that internet routing is usable.
VERIFY_OK=1
ipt -C FORWARD -j VPNPANEL_FORWARD 2>/dev/null || VERIFY_OK=0
ipt -t nat -C POSTROUTING -j VPNPANEL_NAT 2>/dev/null || VERIFY_OK=0
ipt -t nat -C PREROUTING -j VPNPANEL_DNS 2>/dev/null || VERIFY_OK=0
ipt -t mangle -C FORWARD -j VPNPANEL_MSS 2>/dev/null || VERIFY_OK=0
ipt -t mangle -C PREROUTING -j VPNPANEL_ROUTE 2>/dev/null || VERIFY_OK=0
ip -4 rule show 2>/dev/null | grep -q "fwmark 0x52a00000/0xffff0000.*lookup ${ROUTE_TABLE}" || VERIFY_OK=0
[ "$VERIFY_OK" -eq 1 ] || { logger -t vpn-panel-network-repair "routing repair verification failed"; exit 1; }
printf '%s\n' "$DESIRED_STATE" > "$STATE_FILE"

if [ "$OCSERV_CONFIG_CHANGED" -eq 1 ] && systemctl is-active --quiet ocserv 2>/dev/null; then
  ACTIVE_TUNNELS=$(ip -o link show 2>/dev/null | awk -F': ' '$2 ~ /^vpns[0-9]+(@|$)/ {n++} END {print n+0}')
  if [ "${ACTIVE_TUNNELS:-0}" -eq 0 ]; then
    systemctl restart ocserv
  else
    OCSERV_RESTART_DEFERRED=1
  fi
fi

logger -t vpn-panel-network-repair \
  "VPN routing repaired pools=${REPAIRED:-none} iface=$NET_IFACE src=${EGRESS_IP:-auto} table=$ROUTE_TABLE chains=VPNPANEL_FORWARD,VPNPANEL_NAT,VPNPANEL_DNS,VPNPANEL_MSS,VPNPANEL_ROUTE mode=$([ "$APPLY_CONFIG" -eq 1 ] && echo apply-config || echo network-only) config_changed=$OCSERV_CONFIG_CHANGED restart_deferred=$OCSERV_RESTART_DEFERRED"
