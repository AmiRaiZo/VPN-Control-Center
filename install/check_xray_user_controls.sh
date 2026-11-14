#!/usr/bin/env bash
set -u

ok=0
warn=0
say_ok(){ printf '[OK] %s\n' "$*"; ok=$((ok+1)); }
say_warn(){ printf '[WARN] %s\n' "$*"; warn=$((warn+1)); }

for unit in vpn-panel-xray-vmess vpn-panel-xray-vless; do
  if systemctl is-active --quiet "$unit" 2>/dev/null; then
    say_ok "$unit is active"
  else
    say_warn "$unit is not active"
  fi
done

for proto in vmess vless; do
  cfg="/etc/vpn-panel/xray/$proto/config.json"
  if [[ -s "$cfg" ]]; then
    say_ok "$cfg exists"
    if grep -q '"tag": "user-[0-9]' "$cfg"; then
      grep -q '"mark"' "$cfg" && say_ok "$proto contains marked per-user outbounds" || say_warn "$proto has per-user outbounds but no sockopt mark"
      grep -q '"user"' "$cfg" && say_ok "$proto contains per-user routing rules" || say_warn "$proto has no per-user routing rules"
    else
      say_warn "$proto currently has no active users in config"
    fi
    if grep -q 'vpnpanel-internet-block-' "$cfg"; then
      say_ok "$proto contains persistent user internet-block rule(s)"
    fi
  else
    say_warn "$cfg is missing"
  fi
done

if command -v nft >/dev/null 2>&1; then
  if nft list table inet vpn_panel_rate >/tmp/vpn-panel-rate-check.$$ 2>/dev/null; then
    say_ok 'nftables table vpn_panel_rate is active'
    grep -q 'xray-.*-user-.*-download' /tmp/vpn-panel-rate-check.$$ && say_ok 'per-user Xray download rules are present' || say_warn 'no per-user Xray download rules are currently present'
    grep -q 'xray-.*-user-.*-upload' /tmp/vpn-panel-rate-check.$$ && say_ok 'per-user Xray upload rules are present' || say_warn 'no per-user Xray upload rules are currently present'
    grep -q 'internet-block' /tmp/vpn-panel-rate-check.$$ && say_ok 'secondary Xray internet-block rules are present' || true
    grep -q 'counter packets' /tmp/vpn-panel-rate-check.$$ && say_ok 'rate-rule counters are readable' || say_warn 'rate-rule counters have not recorded traffic yet'
  else
    say_warn 'nftables table vpn_panel_rate is not active (normal only when no Xray/IKEv2 rule is needed)'
  fi
  rm -f /tmp/vpn-panel-rate-check.$$
else
  say_warn 'nft command is not installed'
fi

for unit in vpn-panel-xray-vmess vpn-panel-xray-vless; do
  caps=$(systemctl show "$unit" -p AmbientCapabilities --value 2>/dev/null || true)
  if [[ "$caps" == *CAP_NET_ADMIN* ]]; then
    say_ok "$unit has CAP_NET_ADMIN for per-user socket marks"
  else
    say_warn "$unit is missing CAP_NET_ADMIN; save an Xray user to trigger self-heal"
  fi
done

if iptables -C INPUT -j VPN-PANEL-BANS >/dev/null 2>&1; then
  say_ok 'VPN-PANEL-BANS is attached to INPUT'
else
  say_warn 'VPN-PANEL-BANS is not attached to INPUT'
fi

printf '\nLive Xray runtime checks:\n'
for proto in vmess vless; do
  unit="vpn-panel-xray-${proto}"
  api_port=10085
  [[ "$proto" == "vless" ]] && api_port=10086
  pid=$(systemctl show "$unit" -p MainPID --value 2>/dev/null || true)
  if [[ "$pid" =~ ^[1-9][0-9]*$ ]] && [[ -r "/proc/$pid/status" ]]; then
    cap_hex=$(awk '/^CapEff:/ {print $2}' "/proc/$pid/status")
    if python3 - "$cap_hex" <<'PYEOF'
import sys
try:
    value=int(sys.argv[1],16)
except Exception:
    raise SystemExit(1)
raise SystemExit(0 if value & (1 << 12) else 1)
PYEOF
    then
      say_ok "$unit live process has effective CAP_NET_ADMIN"
    else
      say_warn "$unit live process is missing CAP_NET_ADMIN"
    fi
  fi
  xray_bin=$(command -v xray || true)
  [[ -z "$xray_bin" && -x /usr/local/bin/xray ]] && xray_bin=/usr/local/bin/xray
  if [[ -n "$xray_bin" ]]; then
    stats_file="/tmp/vpnpanel-${proto}-stats.$$"
    # Bare statsquery is the most compatible form across Xray releases. Several
    # builds reject -reset=false or one of the pattern flag spellings.
    if "$xray_bin" api statsquery --server="127.0.0.1:${api_port}" >"$stats_file" 2>&1; then
      say_ok "$proto StatsService API responds"
      if grep -q 'user>>>vpn-user-' "$stats_file"; then
        say_ok "$proto per-user counters are present"
      else
        say_warn "$proto StatsService returned no per-user counters"
      fi
      printf '
--- %s raw stats (first 80 lines) ---
' "$proto"
      sed -n '1,80p' "$stats_file"
    else
      say_warn "$proto StatsService API failed: $(tail -n 3 "$stats_file" | tr '\n' ' ')"
    fi
    rm -f "$stats_file"
  fi
done



printf '
Live sockets and recent Xray logs:
'
for proto in vmess vless; do
  unit="vpn-panel-xray-${proto}"
  port=0
  cfg="/etc/vpn-panel/xray/${proto}/config.json"
  if [[ -r "$cfg" ]]; then
    if grep -A2 -B1 '"tag"[[:space:]]*:[[:space:]]*"api"' "$cfg" 2>/dev/null | grep -q '"protocol"[[:space:]]*:[[:space:]]*"freedom"'; then
      say_warn "$proto config contains a normal outbound tagged api (recursive StatsService loop)"
    else
      say_ok "$proto reserved API tag is not shadowed by an outbound"
    fi
    port=$(python3 - "$cfg" <<'PYEOF' 2>/dev/null || true
import json,sys
try:
    data=json.load(open(sys.argv[1], encoding="utf-8"))
    for inbound in data.get("inbounds", []):
        if inbound.get("tag") in {"vmess-in", "vless-in"}:
            print(int(inbound.get("port") or 0)); break
except Exception:
    pass
PYEOF
)
  fi
  printf '
--- %s service/listener ---
' "$proto"
  systemctl --no-pager --full status "$unit" 2>&1 | sed -n '1,22p' || true
  if [[ "$port" =~ ^[1-9][0-9]*$ ]]; then
    ss -Hntup 2>/dev/null | awk -v p=":$port" '$5 ~ p || $4 ~ p {print}' | tail -n 40 || true
  fi
  for log in "/var/log/vpn-panel/xray/${proto}-access.log" "/var/log/vpn-panel/xray/${proto}-error.log"; do
    if [[ -r "$log" ]]; then
      printf '
--- tail %s ---
' "$log"
      tail -n 40 "$log" || true
    fi
  done
done

printf '
Persistent Xray control rules:
'
for proto in vmess vless; do
  cfg="/etc/vpn-panel/xray/${proto}/config.json"
  [[ -r "$cfg" ]] || continue
  printf '
--- %s blackhole/max-device rules ---
' "$proto"
  grep -nE 'vpnpanel-(internet-block|maxdev)|"outboundTag"[[:space:]]*:[[:space:]]*"blocked"' "$cfg" | tail -n 100 || true
done

if command -v nft >/dev/null 2>&1; then
  printf '
--- nftables vpn_panel_rate (with counters) ---
'
  nft -a list table inet vpn_panel_rate 2>&1 | sed -n '1,260p' || true
fi

printf '\nSummary: %d checks passed, %d warnings.\n' "$ok" "$warn"
exit 0
