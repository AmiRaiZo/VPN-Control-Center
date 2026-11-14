#!/bin/bash
# Repair only the classic PPP VPN stack managed by this panel:
# L2TP/xl2tpd, PPTP/pptpd and SSTP/accel-ppp.
# No OpenVPN, IKEv2, OpenConnect, VMess or VLESS configuration is changed.
set -Eeuo pipefail

[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root" >&2; exit 1; }
RESTART=1
for arg in "$@"; do
  case "$arg" in
    --no-restart) RESTART=0 ;;
    *) echo "ERROR: unknown argument: $arg" >&2; exit 2 ;;
  esac
done

changed_l2tp=0
changed_pptp=0
changed_sstp=0
changed_unit=0

install_if_changed() {
  local tmp="$1" dst="$2"
  if [ ! -e "$dst" ] || ! cmp -s "$tmp" "$dst"; then
    install -D -m "${3:-0600}" "$tmp" "$dst"
    return 0
  fi
  return 1
}

repair_ppp_options() {
  local path="$1" kind="$2" tmp
  [ -f "$path" ] || return 1
  tmp=$(mktemp)
  python3 - "$path" "$kind" > "$tmp" <<'PY'
import re, sys
from pathlib import Path
path, kind = Path(sys.argv[1]), sys.argv[2]
text = path.read_text(encoding="utf-8", errors="replace")
lines = []
for raw in text.splitlines():
    stripped = raw.strip()
    # A fixed ppp unit/interface makes concurrent users contend for ppp0.
    if re.match(r"^(?:unit|ifname)\s+", stripped, re.I):
        continue
    # A positional local:remote pair pins every session to one tunnel IP.
    if re.fullmatch(r"[0-9a-f:.]+:[0-9a-f:.]+", stripped, re.I):
        continue
    lines.append(raw)

def ensure(option: str) -> None:
    if not any(re.match(rf"^\s*{re.escape(option)}(?:\s|$)", line, re.I) for line in lines):
        lines.append(option)

ensure("ipcp-accept-local")
ensure("ipcp-accept-remote")
ensure("nodefaultroute")
ensure("asyncmap 0")
if kind == "l2tp":
    lines = [
        line for line in lines
        if not re.match(r"^\s*lcp-echo-(?:interval|failure|adaptive)\b", line, re.I)
    ]
    lines.extend(("lcp-echo-interval 30", "lcp-echo-failure 10", "lcp-echo-adaptive"))
if kind == "pptp":
    ensure("lock")
print("\n".join(lines).rstrip() + "\n", end="")
PY
  if install_if_changed "$tmp" "$path" 0600; then
    rm -f "$tmp"
    return 0
  fi
  rm -f "$tmp"
  return 1
}

# L2TP: preserve every valid custom value, but remove settings that force all
# sessions onto one PPP interface/IP and make the pool multi-session capable.
if [ -f /etc/xl2tpd/xl2tpd.conf ]; then
  tmp=$(mktemp)
  python3 - /etc/xl2tpd/xl2tpd.conf > "$tmp" <<'PY'
import ipaddress, re, sys
from pathlib import Path
p = Path(sys.argv[1])
text = p.read_text(encoding="utf-8", errors="replace")

def set_line(text, pattern, value, section=None):
    lines = text.splitlines()
    current = ""
    for i, raw in enumerate(lines):
        s = raw.strip()
        if s.startswith("[") and s.endswith("]"):
            current = s[1:-1].strip().lower()
        if (section is None or current == section) and re.match(pattern, s, re.I):
            lines[i] = value
            return "\n".join(lines).rstrip() + "\n"
    if section:
        for i, raw in enumerate(lines):
            if raw.strip().lower() == f"[{section}]":
                lines.insert(i + 1, value)
                return "\n".join(lines).rstrip() + "\n"
    lines.append(value)
    return "\n".join(lines).rstrip() + "\n"

m = re.search(r"(?mi)^\s*ip\s+range\s*=\s*([^\r\n#;]+)", text)
valid_pool = False
if m:
    raw = m.group(1).strip()
    try:
        left, right = [ipaddress.ip_address(x.strip()) for x in raw.split("-", 1)]
        valid_pool = left.version == right.version and int(right) > int(left)
    except Exception:
        valid_pool = False
if not valid_pool:
    local_m = re.search(r"(?mi)^\s*local\s+ip\s*=\s*([^\s#;]+)", text)
    try:
        local = ipaddress.ip_address(local_m.group(1)) if local_m else ipaddress.ip_address("10.10.10.1")
        network = ipaddress.ip_network(f"{local}/24", strict=False)
        start = network.network_address + 10
        end = network.network_address + 250
        text = set_line(text, r"^ip\s+range\s*=", f"ip range = {start}-{end}", "lns default")
    except Exception:
        text = set_line(text, r"^ip\s+range\s*=", "ip range = 10.10.10.10-10.10.10.250", "lns default")
text = set_line(text, r"^force\s+userspace\s*=", "force userspace = yes", "global")
# Default five retries use 1+2+4+8+16 seconds of backoff. One hundred retries keep an otherwise healthy data tunnel alive while
# broken embedded L2TP clients fail to acknowledge xl2tpd Hello packets. The
# panel performs an explicit, graceful PPP handover when a real replacement is
# ready, so control-plane loss cannot create a two-minute traffic pause.
text = set_line(text, r"^max\s+retries\s*=", "max retries = 100", "global")
text = set_line(text, r"^cap\s+backoff\s*=", "cap backoff = 60", "global")
text = set_line(text, r"^pass\s+peer\s*=", "pass peer = yes", "lns default")
text = set_line(text, r"^length\s+bit\s*=", "length bit = yes", "lns default")
print(text, end="")
PY
  if install_if_changed "$tmp" /etc/xl2tpd/xl2tpd.conf 0600; then changed_l2tp=1; fi
  rm -f "$tmp"
fi
if repair_ppp_options /etc/ppp/options.xl2tpd l2tp; then changed_l2tp=1; fi

# PPTP: keep the configured address pool, but remove fixed PPP unit/IP options.
if [ -f /etc/pptpd.conf ]; then
  tmp=$(mktemp)
  python3 - /etc/pptpd.conf > "$tmp" <<'PY'
import ipaddress, re, sys
from pathlib import Path
p = Path(sys.argv[1]); text = p.read_text(encoding="utf-8", errors="replace")
m = re.search(r"(?mi)^\s*remoteip\s+([^\r\n#;]+)", text)
valid = False
if m:
    raw = m.group(1).strip()
    try:
        if "," in raw:
            valid = len([x for x in raw.split(",") if x.strip()]) > 1
        elif "-" in raw:
            left_s, right_s = [x.strip() for x in raw.split("-", 1)]
            left = ipaddress.ip_address(left_s)
            if "." not in right_s and left.version == 4:
                right = ipaddress.ip_address(".".join(left_s.split(".")[:-1] + [right_s]))
            else:
                right = ipaddress.ip_address(right_s)
            valid = int(right) > int(left)
    except Exception:
        valid = False
if not valid:
    lm = re.search(r"(?mi)^\s*localip\s+([^\s#;]+)", text)
    try:
        local = ipaddress.ip_address(lm.group(1)) if lm else ipaddress.ip_address("10.20.20.1")
        net = ipaddress.ip_network(f"{local}/24", strict=False)
        replacement = f"remoteip {net.network_address + 10}-{net.network_address + 250}"
    except Exception:
        replacement = "remoteip 10.20.20.10-10.20.20.250"
    if m:
        text = text[:m.start()] + replacement + text[m.end():]
    else:
        text = text.rstrip() + "\n" + replacement + "\n"
print(text if text.endswith("\n") else text + "\n", end="")
PY
  if install_if_changed "$tmp" /etc/pptpd.conf 0600; then changed_pptp=1; fi
  rm -f "$tmp"
fi
if repair_ppp_options /etc/ppp/pptpd-options pptp; then changed_pptp=1; fi
# The panel records sessions itself. Remove the optional legacy logwtmp plugin
# because distro upgrades can leave an ABI-incompatible plugin that prevents
# pptpd from starting at all.
sed -i -E '/^[[:space:]]*logwtmp([[:space:]]|$)/Id;/pptpd-logwtmp/Id' /etc/pptpd.conf /etc/ppp/pptpd-options 2>/dev/null || true

# Run pptpd in the foreground under systemd.  This removes the stale/invalid
# PID-file state seen with Type=forking while preserving the daemon and config.
if [ -x /usr/sbin/pptpd ]; then
  tmp=$(mktemp)
  cat > "$tmp" <<'UNIT'
[Unit]
Description=PoPToP Point to Point Tunneling Server
Documentation=man:pptpd(8) man:pptpd.conf(5)
After=network-online.target
Wants=network-online.target
ConditionPathExists=/etc/pptpd.conf

[Service]
Type=simple
ExecStartPre=/bin/rm -f /run/pptpd.pid /var/run/pptpd.pid /run/pptpd/pptpd.pid
ExecStart=/usr/sbin/pptpd --fg
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=3
TimeoutStartSec=20
TimeoutStopSec=10
KillMode=control-group
RuntimeDirectory=pptpd
RuntimeDirectoryMode=0755
PrivateTmp=true
ProtectHome=true
NoNewPrivileges=true
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT
  if install_if_changed "$tmp" /etc/systemd/system/pptpd.service 0644; then
    changed_unit=1
    changed_pptp=1
  fi
  rm -f "$tmp"
fi

# SSTP: client-ip-range is a core section, not a loadable module.  Loading it
# as a module causes "loader: 'client-ip-range' not found".  Also ensure the
# auth modules and unique interface naming required by MikroTik/Windows peers.
if [ -f /etc/accel-ppp/sstp.conf ]; then
  tmp=$(mktemp)
  dns_available=0
  if find /usr/lib /usr/lib64 /usr/local/lib -type f -name "libdns.so" -print -quit 2>/dev/null | grep -q .; then
    dns_available=1
  fi
  python3 - /etc/accel-ppp/sstp.conf "$dns_available" > "$tmp" <<'PY'
import re, sys
from pathlib import Path
p = Path(sys.argv[1]); lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
dns_available = sys.argv[2] == "1"
original_has_dns_section = any(raw.strip().lower() == "[dns]" for raw in lines)
original_has_dns1 = False
section_probe = ""
for raw in lines:
    stripped_probe = raw.strip()
    if stripped_probe.startswith("[") and stripped_probe.endswith("]"):
        section_probe = stripped_probe[1:-1].strip().lower()
    elif section_probe == "dns" and re.match(r"^dns1\s*=", stripped_probe, re.I):
        original_has_dns1 = True
sections = []
section = ""
skip_dns_section = False
for raw in lines:
    s = raw.strip()
    if s.startswith("[") and s.endswith("]"):
        section = s[1:-1].strip().lower()
        skip_dns_section = section == "dns" and not dns_available
        if skip_dns_section:
            continue
    if skip_dns_section:
        continue
    if section == "modules" and (s == "client-ip-range" or (s == "dns" and not dns_available)):
        continue
    sections.append(raw)
lines = sections

def ensure_module(name):
    section = ""
    for raw in lines:
        s = raw.strip()
        if s.startswith("[") and s.endswith("]"):
            section = s[1:-1].strip().lower()
        elif section == "modules" and s == name:
            return
    for i, raw in enumerate(lines):
        if raw.strip().lower() == "[modules]":
            lines.insert(i + 1, name); return
    lines[:0] = ["[modules]", name, ""]

def set_option(section_name, key, value):
    target = section_name.lower(); section = ""; start = None; end = len(lines); idx = None
    for i, raw in enumerate(lines):
        s = raw.strip()
        if s.startswith("[") and s.endswith("]"):
            current = s[1:-1].strip().lower()
            if section == target and end == len(lines): end = i
            section = current
            if current == target and start is None: start = i
        elif section == target and re.match(rf"^{re.escape(key)}\s*=", s):
            idx = i
    line = f"{key}={value}"
    if idx is not None: lines[idx] = line
    elif start is not None: lines.insert(end if end != len(lines) else len(lines), line)
    else:
        if lines and lines[-1].strip(): lines.append("")
        lines.extend([f"[{section_name}]", line])

for module in ("sstp", "chap-secrets", "auth_pap", "auth_chap_md5", "auth_mschap_v1", "auth_mschap_v2", "ippool", "sigchld", "pppd_compat"):
    ensure_module(module)
if dns_available:
    ensure_module("dns")
    # Preserve the panel's authoritative DNS values. Only create defaults when
    # an old/fresh config has no [dns] section at all; an intentionally blank
    # DNS2 must stay blank across update/repair runs.
    if not original_has_dns_section:
        set_option("dns", "dns1", "1.1.1.1")
        set_option("dns", "dns2", "8.8.8.8")
    elif not original_has_dns1:
        set_option("dns", "dns1", "1.1.1.1")
set_option("sstp", "ifname", "sstp%d")
set_option("ppp", "ipv4", "require")
set_option("ppp", "ipv6", "deny")
set_option("pppd-compat", "ip-up", "/opt/vpn-panel/scripts/sstp_ip_up.sh")
set_option("pppd-compat", "ip-down", "/opt/vpn-panel/scripts/sstp_ip_down.sh")
# [client-ip-range] contains bare CIDR entries rather than key=value options.
# Two /1 networks include the server's own SSTP pool and make accel-ppp reject
# every negotiated 192.168.45.x address. The 0.0.0.0/0 sentinel disables this
# overlap guard and keeps dynamic pooled SSTP working.
section = ""
normalized = []
found = False
for raw in lines:
    s = raw.strip()
    if s.startswith("[") and s.endswith("]"):
        section = s[1:-1].strip().lower()
        normalized.append(raw)
        if section == "client-ip-range":
            found = True
            normalized.append("0.0.0.0/0")
        continue
    if section == "client-ip-range":
        continue
    normalized.append(raw)
lines = normalized
if not found:
    lines += ["", "[client-ip-range]", "0.0.0.0/0"]
print("\n".join(lines).rstrip()+"\n", end="")
PY
  if install_if_changed "$tmp" /etc/accel-ppp/sstp.conf 0600; then changed_sstp=1; fi
  rm -f "$tmp"
fi

# Install SSTP hooks before the daemon is (re)started.
install -d -m 0755 /opt/vpn-panel/scripts
for hook in sstp_ip_up.sh sstp_ip_down.sh admission_guard.sh ensure_session_networking.sh; do
  src="/opt/vpn-panel/backend/app/scripts/$hook"
  [ -f "$src" ] || continue
  if [ ! -f "/opt/vpn-panel/scripts/$hook" ] || ! cmp -s "$src" "/opt/vpn-panel/scripts/$hook"; then
    install -m 0755 "$src" "/opt/vpn-panel/scripts/$hook"
    changed_sstp=1
  fi
done

# The distro xl2tpd package is an LSB-generated unit. On some releases its stop
# action returns before the daemon/pppd children have exited, then systemd starts
# a second instance in the same cgroup. Kill the whole cgroup and wait for a
# clean stop so stale tunnels cannot flood the new daemon.
install -d -m 0755 /etc/systemd/system/xl2tpd.service.d
xl2tp_override=$(mktemp)
cat > "$xl2tp_override" <<'EOF_XL2TP_SYSTEMD'
[Service]
KillMode=control-group
TimeoutStopSec=12s
SendSIGKILL=yes
EOF_XL2TP_SYSTEMD
if install_if_changed "$xl2tp_override" /etc/systemd/system/xl2tpd.service.d/vpn-panel-clean-stop.conf 0644; then
  changed_unit=1
fi
rm -f "$xl2tp_override"

if [ "$changed_unit" -eq 1 ]; then systemctl daemon-reload; fi
if [ "$RESTART" -eq 1 ]; then
  if [ "$changed_l2tp" -eq 1 ] && systemctl cat xl2tpd.service >/dev/null 2>&1; then
    # Never interrupt active users merely because an update normalized a file.
    # New PPP sessions read the new options automatically. A later idle repair
    # applies daemon-level xl2tpd changes safely.
    if pgrep -af 'pppd.*(options\.xl2tpd|/etc/ppp/options\.xl2tpd)' >/dev/null 2>&1; then
      echo '[i] xl2tpd restart deferred: active L2TP sessions detected'
    else
      systemctl restart xl2tpd
    fi
  fi
  if [ "$changed_pptp" -eq 1 ] && systemctl cat pptpd.service >/dev/null 2>&1; then systemctl restart pptpd; fi
  if [ "$changed_sstp" -eq 1 ] && systemctl cat accel-ppp-sstp.service >/dev/null 2>&1; then systemctl restart accel-ppp-sstp; fi
fi

printf '[✓] classic PPP repair complete: l2tp=%s pptp=%s sstp=%s\n' "$changed_l2tp" "$changed_pptp" "$changed_sstp"
