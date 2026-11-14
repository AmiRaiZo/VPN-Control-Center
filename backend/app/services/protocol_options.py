from __future__ import annotations

import ipaddress
import os
import re
import shutil
import shlex
import subprocess
import tempfile
from pathlib import Path
from typing import Iterable

from app.services.protocol_dns import rewrite_ikev2_dns, rewrite_ppp_dns, rewrite_sstp_dns


TARGET_PATHS: dict[str, tuple[Path, ...]] = {
    "l2tp": (Path("/etc/ppp/options.xl2tpd"), Path("/etc/xl2tpd/xl2tpd.conf")),
    "pptp": (Path("/etc/pptpd.conf"), Path("/etc/ppp/pptpd-options")),
    "openvpn": (
        Path("/etc/openvpn/server/server-udp.conf"), Path("/etc/openvpn/server/server-tcp.conf"),
        Path("/etc/openvpn/server-udp.conf"), Path("/etc/openvpn/server-tcp.conf"),
    ),
    "sstp": (Path("/etc/accel-ppp/sstp.conf"),),
    "ikev2": (Path("/etc/ipsec.conf"),),
    "openconnect": (Path("/etc/ocserv/ocserv.conf"),),
}


def _backup(path: Path) -> Path | None:
    if not path.is_file():
        return None
    backup = path.with_name(path.name + '.vpnpanel-options.bak')
    shutil.copy2(path, backup)
    return backup


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix='.' + path.name + '-', dir=str(path.parent))
    try:
        with open(fd, 'w', encoding='utf-8', closefd=True) as handle:
            handle.write(content)
        if path.exists():
            shutil.copymode(path, tmp_name)
        else:
            Path(tmp_name).chmod(0o600)
        Path(tmp_name).replace(path)
    finally:
        Path(tmp_name).unlink(missing_ok=True)


def _line(text: str, key_pattern: str, replacement: str, *, append: bool = True) -> str:
    pattern = re.compile(rf'(?m)^\s*{key_pattern}.*$')
    if pattern.search(text):
        return pattern.sub(replacement, text, count=1)
    if append:
        return text.rstrip() + '\n' + replacement + '\n'
    return text


def _toggle_line(text: str, key_pattern: str, line: str, enabled: bool) -> str:
    pattern = re.compile(rf'(?m)^\s*#?\s*{key_pattern}.*$')
    text = pattern.sub('', text)
    text = re.sub(r'\n{3,}', '\n\n', text).rstrip() + '\n'
    if enabled:
        text += line + '\n'
    return text


def _ensure_ini_module(text: str, module: str) -> str:
    """Ensure one accel-ppp module line exists inside [modules]."""
    lines = text.splitlines()
    section = ""
    for raw in lines:
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
        elif section == "modules" and stripped == module:
            return text
    for index, raw in enumerate(lines):
        if raw.strip().lower() == "[modules]":
            lines.insert(index + 1, module)
            return "\n".join(lines).rstrip() + "\n"
    return f"[modules]\n{module}\n\n" + text.lstrip()


def _remove_ini_module(text: str, module: str) -> str:
    """Remove a module token only when it appears inside [modules]."""
    lines = []
    section = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
        if section == "modules" and stripped == module:
            continue
        lines.append(raw)
    return "\n".join(lines).rstrip() + "\n"


def _remove_ini_section(text: str, section_name: str) -> str:
    """Remove one complete INI section without altering module tokens."""
    target = section_name.strip().lower()
    output: list[str] = []
    skipping = False
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            skipping = stripped[1:-1].strip().lower() == target
            if skipping:
                continue
        if skipping:
            continue
        output.append(raw)
    return "\n".join(output).rstrip() + "\n"


def _accel_module_available(module: str) -> bool:
    filename = f"lib{module}.so"
    for root in (Path("/usr/lib"), Path("/usr/lib64"), Path("/usr/local/lib")):
        if not root.is_dir():
            continue
        try:
            if next(root.rglob(filename), None) is not None:
                return True
        except OSError:
            continue
    return False


def _ensure_ini_bare_value(text: str, section_name: str, value: str) -> str:
    """Ensure a bare accel-ppp section value such as an IPv4 CIDR."""
    lines = text.splitlines()
    target = section_name.strip().lower()
    section = ""
    section_start = None
    section_end = len(lines)
    for index, raw in enumerate(lines):
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped[1:-1].strip().lower()
            if section == target and section_end == len(lines):
                section_end = index
            section = current
            if current == target and section_start is None:
                section_start = index
        elif section == target and stripped == value:
            return text
    if section_start is not None:
        lines.insert(section_end if section_end != len(lines) else len(lines), value)
    else:
        if lines and lines[-1].strip():
            lines.append("")
        lines.extend([f"[{section_name}]", value])
    return "\n".join(lines).rstrip() + "\n"


def _normalize_sstp_client_ranges(text: str) -> str:
    """Disable accel-ppp's source-IP overlap guard for dynamically pooled SSTP.

    accel-ppp rejects a negotiated tunnel address when it falls inside any
    configured ``client-ip-range``.  Covering all IPv4 with two /1 networks
    therefore also covers the panel's own 192.168.45.0/24 pool and produces
    ``requested IP cannot be assigned`` immediately after successful auth.
    The documented sentinel ``0.0.0.0/0`` disables that guard and is the safe
    setting for this standalone SSTP server.
    """
    lines = text.splitlines()
    output: list[str] = []
    in_target = False
    found = False
    for raw in lines:
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_target = stripped[1:-1].strip().lower() == "client-ip-range"
            output.append(raw)
            if in_target:
                found = True
                output.append("0.0.0.0/0")
            continue
        if in_target:
            continue
        output.append(raw)
    if not found:
        if output and output[-1].strip():
            output.append("")
        output.extend(["[client-ip-range]", "0.0.0.0/0"])
    return "\n".join(output).rstrip() + "\n"


def _sanitize_multi_session_ppp(text: str, *, pptp: bool = False) -> str:
    """Remove options that pin every PPP login to one interface or IP pair."""
    lines: list[str] = []
    for raw in text.splitlines():
        stripped = raw.strip()
        if re.match(r"^(?:unit|ifname)\s+", stripped, re.I):
            continue
        if re.fullmatch(r"[0-9a-f:.]+:[0-9a-f:.]+", stripped, re.I):
            continue
        lines.append(raw)
    required = ["ipcp-accept-local", "ipcp-accept-remote", "nodefaultroute", "asyncmap 0"]
    if pptp:
        required.append("lock")
    for option in required:
        key = option.split()[0]
        if not any(re.match(rf"^\s*{re.escape(key)}(?:\s|$)", line, re.I) for line in lines):
            lines.append(option)
    return "\n".join(lines).rstrip() + "\n"


def _set_ini_option(text: str, section_name: str, key: str, value: str) -> str:
    """Set an option only in the requested accel-ppp INI section."""
    lines = text.splitlines()
    target = section_name.strip().lower()
    section = ""
    section_start = None
    section_end = len(lines)
    option_index = None
    for index, raw in enumerate(lines):
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped[1:-1].strip().lower()
            if section == target and section_end == len(lines):
                section_end = index
            section = current
            if current == target and section_start is None:
                section_start = index
        elif section == target and re.match(rf"^{re.escape(key)}\s*=", stripped):
            option_index = index
    line = f"{key}={value}"
    if option_index is not None:
        lines[option_index] = line
    elif section_start is not None:
        insert_at = section_end if section_end != len(lines) else len(lines)
        lines.insert(insert_at, line)
    else:
        if lines and lines[-1].strip():
            lines.append("")
        lines.extend([f"[{section_name}]", line])
    return "\n".join(lines).rstrip() + "\n"


def _valid_ip(value: str, fallback: str) -> str:
    value = (value or '').strip()
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        return fallback


def _valid_network(value: str, fallback: str) -> str:
    value = (value or '').strip()
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return fallback


def _valid_range(value: str, fallback: str) -> str:
    value = (value or '').strip()
    if re.fullmatch(r'[0-9a-fA-F:.]+\s*-\s*[0-9a-fA-F:.]+', value):
        left, right = [x.strip() for x in value.split('-', 1)]
        try:
            ipaddress.ip_address(left); ipaddress.ip_address(right)
            return f'{left}-{right}'
        except ValueError:
            pass
    return fallback


def _l2tp_pppd_is_live() -> bool:
    """True when at least one pppd child belongs to xl2tpd."""
    try:
        result = subprocess.run(
            ["/usr/bin/pgrep", "-af", r"pppd.*(options\.xl2tpd|/etc/ppp/options\.xl2tpd)"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        return result.returncode == 0 and bool((result.stdout or "").strip())
    except Exception:
        # Fail safe: inability to prove idleness must never disconnect users.
        return True


def _defer_xl2tpd_restart() -> None:
    marker = Path("/var/lib/vpn-panel/pending/xl2tpd-restart")
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("advanced-options-change\n", encoding="utf-8")
    marker.chmod(0o600)


def _restart(units: Iterable[str]) -> tuple[bool, str]:
    details=[]
    ok=True
    for unit in units:
        if not unit:
            continue
        if unit == "xl2tpd" and _l2tp_pppd_is_live():
            _defer_xl2tpd_restart()
            details.append("xl2tpd: restart deferred until all L2TP sessions are offline")
            continue
        action = "reload" if unit in {"strongswan-starter", "strongswan", "ipsec"} else "restart"
        result=subprocess.run(['/usr/bin/systemctl',action,unit],capture_output=True,text=True,timeout=45,check=False)
        out=((result.stdout or '')+'\n'+(result.stderr or '')).strip()
        if result.returncode != 0:
            ok=False
            details.append(f'{unit}: {out}')
    return ok, '\n'.join(details)


def _range_network(value: str, fallback: str) -> str:
    raw = _valid_range(value, fallback)
    left = raw.split("-", 1)[0].strip()
    address = ipaddress.ip_address(left)
    prefix = 24 if address.version == 4 else 64
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def _sync_client_to_client(comment: str, network: str, enabled: bool) -> None:
    binary = shutil.which("iptables")
    if not binary:
        raise RuntimeError("iptables is required to apply client-to-client routing")
    listed = subprocess.run([binary, "-S", "FORWARD"], capture_output=True, text=True, timeout=10, check=False)
    for line in (listed.stdout or "").splitlines():
        if comment not in line or not line.startswith("-A FORWARD "):
            continue
        args = shlex.split(line)
        args[0] = "-D"
        subprocess.run([binary, *args], capture_output=True, text=True, timeout=10, check=False)
    if enabled:
        result = subprocess.run(
            [binary, "-I", "FORWARD", "1", "-s", network, "-d", network,
             "-m", "comment", "--comment", comment, "-j", "ACCEPT"],
            capture_output=True, text=True, timeout=10, check=False,
        )
        if result.returncode != 0:
            raise RuntimeError((result.stderr or result.stdout or "failed to apply client-to-client firewall rule").strip())
    persist = shutil.which("netfilter-persistent")
    if persist:
        subprocess.run([persist, "save"], capture_output=True, text=True, timeout=20, check=False)


def _apply_l2tp(payload) -> tuple[list[Path], tuple[str,...]]:
    changed=[]
    options=Path('/etc/ppp/options.xl2tpd')
    if options.is_file():
        text=options.read_text(encoding='utf-8',errors='replace')
        text=_sanitize_multi_session_ppp(text)
        text=rewrite_ppp_dns(
            text,
            tuple(value for value in (payload.l2tp_dns1, payload.l2tp_dns2) if value),
        )
        text=_line(text, r'mtu\s+', f'mtu {payload.l2tp_mtu}')
        text=_line(text, r'mru\s+', f'mru {payload.l2tp_mru}')
        text=re.sub(r'(?m)^\s*lcp-echo-(?:interval|failure|adaptive)\b.*\n?', '', text)
        text=text.rstrip()+'\nlcp-echo-interval 30\nlcp-echo-failure 10\nlcp-echo-adaptive\n'
        _atomic_write(options,text); changed.append(options)
    conf=Path('/etc/xl2tpd/xl2tpd.conf')
    if conf.is_file():
        text=conf.read_text(encoding='utf-8',errors='replace')
        text=_line(text,r'local ip\s*=\s*',f'local ip = {_valid_ip(payload.l2tp_local_ip,"10.10.10.1")}')
        text=_line(text,r'ip range\s*=\s*',f'ip range = {_valid_range(payload.l2tp_ip_range,"10.10.10.10-10.10.10.250")}')
        # Some embedded L2TP clients forward payload traffic but fail to ACK
        # xl2tpd's periodic control Hello. A low retry count then closes a
        # healthy tunnel at the 2-minute mark. Keep the control tunnel alive;
        # the panel retires an old PPP only after its replacement is ready.
        text=_set_ini_option(text, 'global', 'max retries', '100')
        text=_set_ini_option(text, 'global', 'cap backoff', '60')
        _atomic_write(conf,text); changed.append(conf)
    _sync_client_to_client(
        'vpn-panel-l2tp-client-to-client',
        _range_network(payload.l2tp_ip_range, '10.10.10.10-10.10.10.250'),
        bool(payload.l2tp_client_to_client),
    )
    return changed, ('xl2tpd',)


def _apply_pptp(payload) -> tuple[list[Path], tuple[str,...]]:
    changed=[]
    conf=Path('/etc/pptpd.conf')
    if conf.is_file():
        text=conf.read_text(encoding='utf-8',errors='replace')
        text=_line(text,r'localip\s+',f'localip {_valid_ip(payload.pptp_local_ip,"10.20.20.1")}')
        text=_line(text,r'remoteip\s+',f'remoteip {_valid_range(payload.pptp_ip_range,"10.20.20.10-10.20.20.250")}')
        _atomic_write(conf,text); changed.append(conf)
    opts=Path('/etc/ppp/pptpd-options')
    if opts.is_file():
        text=opts.read_text(encoding='utf-8',errors='replace')
        text=_sanitize_multi_session_ppp(text, pptp=True)
        text=rewrite_ppp_dns(
            text,
            tuple(value for value in (payload.pptp_dns1, payload.pptp_dns2) if value),
        )
        text=_line(text,r'mtu\s+',f'mtu {payload.pptp_mtu}')
        text=_line(text,r'mru\s+',f'mru {payload.pptp_mru}')
        _atomic_write(opts,text); changed.append(opts)
    _sync_client_to_client(
        'vpn-panel-pptp-client-to-client',
        _range_network(payload.pptp_ip_range, '10.20.20.10-10.20.20.250'),
        bool(payload.pptp_client_to_client),
    )
    return changed, ('pptpd',)


def _openvpn_units() -> tuple[str,...]:
    out=subprocess.run(['/usr/bin/systemctl','list-unit-files'],capture_output=True,text=True,timeout=10,check=False).stdout or ''
    if 'openvpn-server@server-udp.service' in out:
        return ('openvpn-server@server-udp','openvpn-server@server-tcp')
    return ('openvpn@server-udp','openvpn@server-tcp')


def _apply_openvpn(payload) -> tuple[list[Path], tuple[str,...]]:
    changed=[]
    candidates=[Path('/etc/openvpn/server/server-udp.conf'),Path('/etc/openvpn/server/server-tcp.conf'),Path('/etc/openvpn/server-udp.conf'),Path('/etc/openvpn/server-tcp.conf')]
    for conf in candidates:
        if not conf.is_file(): continue
        text=conf.read_text(encoding='utf-8',errors='replace')
        text=_line(text,r'tun-mtu\s+',f'tun-mtu {payload.openvpn_mtu}')
        cipher=(payload.openvpn_cipher or 'AES-256-GCM').strip()
        text=_line(text,r'data-ciphers\s+',f'data-ciphers {cipher}:AES-128-GCM:CHACHA20-POLY1305')
        text=_line(text,r'cipher\s+',f'cipher {cipher}')
        text=_toggle_line(text,r'client-to-client\b','client-to-client',payload.openvpn_client_to_client)
        text=_toggle_line(text,r'push\s+"redirect-gateway','push "redirect-gateway def1 bypass-dhcp"',payload.openvpn_redirect_gateway)
        _atomic_write(conf,text); changed.append(conf)
    return changed, _openvpn_units()


def _apply_sstp(payload) -> tuple[list[Path], tuple[str,...]]:
    conf=Path('/etc/accel-ppp/sstp.conf')
    if not conf.is_file(): return [], ('accel-ppp-sstp',)
    text=conf.read_text(encoding='utf-8',errors='replace')
    # client-ip-range is a core section, not a shared-object module. Older
    # versions added it to [modules], producing a loader error on every start.
    text=_remove_ini_module(text, 'client-ip-range')
    for module in ('sstp', 'chap-secrets', 'auth_pap', 'auth_chap_md5',
                   'auth_mschap_v1', 'auth_mschap_v2', 'ippool',
                   'sigchld', 'pppd_compat'):
        text=_ensure_ini_module(text, module)
    dns_available = _accel_module_available('dns')
    if dns_available:
        text=_ensure_ini_module(text, 'dns')
    else:
        text=_remove_ini_module(text, 'dns')
        text=_remove_ini_section(text, 'dns')
    text=_normalize_sstp_client_ranges(text)
    text=_set_ini_option(text, 'sstp', 'ifname', 'sstp%d')
    text=_set_ini_option(text, 'ppp', 'ipv4', 'require')
    text=_set_ini_option(text, 'ppp', 'ipv6', 'deny')
    text=_set_ini_option(text, 'pppd-compat', 'ip-up', '/opt/vpn-panel/scripts/sstp_ip_up.sh')
    text=_set_ini_option(text, 'pppd-compat', 'ip-down', '/opt/vpn-panel/scripts/sstp_ip_down.sh')
    # accel-ppp reads peer DNS from an optional plugin. Advertising ``dns``
    # when libdns.so is absent makes the whole daemon configuration fail.
    text=_set_ini_option(text, 'ppp', 'mtu', str(payload.sstp_mtu))
    text=_set_ini_option(text, 'ppp', 'mru', str(payload.sstp_mru))
    text=_set_ini_option(text, 'ppp', 'lcp-echo-interval', '2')
    text=_set_ini_option(text, 'ppp', 'lcp-echo-timeout', '12')
    if dns_available:
        text=rewrite_sstp_dns(
            text,
            tuple(value for value in (payload.sstp_dns1, payload.sstp_dns2) if value),
        )
    # Remove obsolete global/misplaced DNS keys left by older panel versions.
    lines=[]
    section=''
    for raw in text.splitlines():
        stripped=raw.strip()
        if stripped.startswith('[') and stripped.endswith(']'):
            section=stripped[1:-1].strip().lower()
        if section != 'dns' and re.match(r'^dns[12]\s*=', stripped):
            continue
        if section == 'ppp' and re.match(r'^lcp-echo-failure\s*=', stripped):
            continue
        lines.append(raw)
    text='\n'.join(lines).rstrip()+'\n'
    _atomic_write(conf,text)
    return [conf], ('accel-ppp-sstp',)


def _apply_ikev2(payload) -> tuple[list[Path], tuple[str,...]]:
    conf=Path('/etc/ipsec.conf')
    if not conf.is_file(): return [], ('strongswan-starter',)
    text=conf.read_text(encoding='utf-8',errors='replace')
    block=re.search(r'(?ms)^conn IKEv2-MSCHAPv2\b.*?(?=^conn\s+|\Z)',text)
    if block:
        value=block.group(0)
        value=_line(value,r'rightsourceip\s*=\s*',f'    rightsourceip={payload.ikev2_ip_pool}')
        text=text[:block.start()]+value+text[block.end():]
        text=rewrite_ikev2_dns(
            text,
            tuple(value for value in (payload.ikev2_dns1, payload.ikev2_dns2) if value),
        )
        _atomic_write(conf,text)
        return [conf], ('strongswan-starter',)
    return [], ('strongswan-starter',)


def _apply_openconnect(payload) -> tuple[list[Path], tuple[str,...]]:
    conf=Path('/etc/ocserv/ocserv.conf')
    if not conf.is_file(): return [], ('ocserv',)
    text=conf.read_text(encoding='utf-8',errors='replace')
    text=_line(text,r'ipv4-network\s*=\s*',f'ipv4-network = {_valid_network(payload.openconnect_ipv4_network,"10.30.0.0/24")}')
    text=_line(text,r'mtu\s*=\s*',f'mtu = {payload.openconnect_mtu}')
    text=_line(text,r'route\s*=\s*','route = default')
    text=_line(text,r'tunnel-all-dns\s*=\s*',f'tunnel-all-dns = {"true" if payload.openconnect_tunnel_all_dns else "false"}')
    text=_line(text,r'switch-to-tcp-timeout\s*=\s*','switch-to-tcp-timeout = 8')
    _atomic_write(conf,text)
    return [conf], ('ocserv',)


def apply_protocol_options(payload, target: str = 'all', *, restart_services: bool = True) -> tuple[bool, str]:
    handlers={
        'l2tp': _apply_l2tp,
        'pptp': _apply_pptp,
        'openvpn': _apply_openvpn,
        'sstp': _apply_sstp,
        'ikev2': _apply_ikev2,
        'openconnect': _apply_openconnect,
    }
    targets=list(handlers) if target == 'all' else [target]
    backups=[]
    changed=[]
    units=[]
    try:
        # Back up every existing target before a handler performs its first atomic write.
        # The previous implementation copied files after they had already been changed,
        # which made rollback restore the new content instead of the original one.
        seen_backup: set[Path] = set()
        for key in targets:
            for path in TARGET_PATHS.get(key, ()):
                if path in seen_backup:
                    continue
                seen_backup.add(path)
                backup = _backup(path)
                if backup:
                    backups.append((path, backup))
        for key in targets:
            handler=handlers.get(key)
            if not handler: continue
            paths, restart_units=handler(payload)
            changed.extend(str(path) for path in paths)
            units.extend(restart_units)
        if restart_services:
            ok, detail=_restart(dict.fromkeys(units))
            if not ok:
                raise RuntimeError(detail or 'service restart failed')
            # Any pool change (L2TP/PPTP/IKEv2/OpenConnect) can leave the
            # host NAT/FORWARD rules pointing at the old subnet.  OpenVPN and
            # SSTP also need the same self-healing after provider/UFW rule
            # reloads.  Reconcile every live classic-VPN pool after an options
            # save; the helper is network-only and does not restart sessions.
            repair = Path('/opt/vpn-panel/scripts/repair_runtime_networking.sh')
            if repair.is_file() and any(
                key in {'l2tp', 'pptp', 'openvpn', 'sstp', 'ikev2', 'openconnect'}
                for key in targets
            ):
                result = subprocess.run([str(repair), "--network-only"], capture_output=True, text=True, timeout=45, check=False)
                if result.returncode != 0:
                    raise RuntimeError((result.stderr or result.stdout or 'VPN routing repair failed').strip())
        suffix = '' if restart_services else ' (restart deferred to the main protocol apply step)'
        return True, 'Applied structured options: ' + (', '.join(changed) if changed else 'no existing config files required changes') + suffix
    except Exception as exc:
        for path, backup in reversed(backups):
            try: shutil.copy2(backup,path)
            except OSError: pass
        if restart_services:
            _restart(dict.fromkeys(units))
        return False, str(exc)
