from __future__ import annotations

"""Safe, isolated DNS updates for classic VPN protocols.

Changing DNS must never reconfigure ports, firewall rules, routing, PKI or an
unrelated protocol.  This module edits only the DNS directives owned by the
panel, validates the result, applies the smallest runtime action needed by the
selected daemon, and rolls the files/runtime back when that action fails.
"""

import fcntl
import ipaddress
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Callable, Iterable


_LOCK_PATH = Path("/run/lock/vpn-panel-protocol-dns.lock")

_DEFAULT_PATHS: dict[str, tuple[Path, ...]] = {
    "l2tp": (Path("/etc/ppp/options.xl2tpd"),),
    "pptp": (Path("/etc/ppp/pptpd-options"),),
    "openvpn": (
        Path("/etc/openvpn/server/server-udp.conf"),
        Path("/etc/openvpn/server/server-tcp.conf"),
        Path("/etc/openvpn/server-udp.conf"),
        Path("/etc/openvpn/server-tcp.conf"),
    ),
    "sstp": (Path("/etc/accel-ppp/sstp.conf"),),
    "ikev2": (Path("/etc/ipsec.conf"),),
    "openconnect": (Path("/etc/ocserv/ocserv.conf"),),
}

_IPV4_ONLY = {"l2tp", "pptp", "sstp"}
_IKEV2_CONNECTION_RE = re.compile(
    r"(?ms)^\s*conn\s+IKEv2-MSCHAPv2\b.*?(?=^\s*conn\s+|\Z)"
)


class ProtocolDnsError(RuntimeError):
    pass


def normalize_dns_servers(protocol: str, dns1: str, dns2: str = "") -> tuple[str, ...]:
    """Return canonical, deduplicated DNS IPs for one protocol.

    PPP MS-DNS and accel-ppp's DNS plugin are IPv4-only in the panel's current
    IPv4 pools, so an IPv6 value is rejected before any config is touched.
    """
    protocol = str(protocol or "").strip().lower()
    if protocol not in _DEFAULT_PATHS:
        raise ProtocolDnsError(f"unsupported protocol DNS target: {protocol}")

    raw_values = [str(dns1 or "").strip(), str(dns2 or "").strip()]
    if not raw_values[0]:
        raise ProtocolDnsError("DNS اول الزامی است")

    normalized: list[str] = []
    for index, raw in enumerate(raw_values, start=1):
        if not raw:
            continue
        try:
            address = ipaddress.ip_address(raw)
        except ValueError as exc:
            raise ProtocolDnsError(f"DNS {index} یک IP معتبر نیست: {raw}") from exc
        if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local:
            raise ProtocolDnsError(f"DNS {index} قابل استفاده نیست: {raw}")
        if protocol in _IPV4_ONLY and address.version != 4:
            raise ProtocolDnsError(f"{protocol.upper()} در این پنل فقط DNS نوع IPv4 می‌پذیرد")
        value = str(address)
        if value not in normalized:
            normalized.append(value)
    return tuple(normalized)


def _strip_managed_block(text: str, begin: str, end: str) -> str:
    output: list[str] = []
    inside = False
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped == begin:
            inside = True
            continue
        if stripped == end:
            inside = False
            continue
        if not inside:
            output.append(raw)
    return "\n".join(output).rstrip() + "\n"


def rewrite_ppp_dns(text: str, servers: Iterable[str]) -> str:
    begin = "# BEGIN VPN PANEL DNS"
    end = "# END VPN PANEL DNS"
    text = _strip_managed_block(text, begin, end)
    # Migrate every unmarked DNS line written by older panel builds so there is
    # one authoritative block and no stale resolver can win by ordering.
    text = re.sub(r"(?mi)^\s*ms-dns\b.*$", "", text)
    text = re.sub(r"\n{3,}", "\n\n", text).rstrip()
    block = [begin, *(f"ms-dns {value}" for value in servers), end]
    return text + "\n\n" + "\n".join(block) + "\n"


def rewrite_openvpn_dns(text: str, servers: Iterable[str]) -> str:
    begin = "# BEGIN VPN PANEL DNS"
    end = "# END VPN PANEL DNS"
    text = _strip_managed_block(text, begin, end)
    text = re.sub(r'(?mi)^\s*push\s+"?dhcp-option\s+DNS\b.*$', "", text)
    text = re.sub(r"\n{3,}", "\n\n", text).rstrip()
    block = [begin, *(f'push "dhcp-option DNS {value}"' for value in servers), end]
    return text + "\n\n" + "\n".join(block) + "\n"


def _ensure_ini_module(text: str, module: str) -> str:
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


def _set_ini_option(text: str, section_name: str, key: str, value: str) -> str:
    lines = text.splitlines()
    target = section_name.lower()
    section = ""
    start: int | None = None
    end = len(lines)
    option: int | None = None
    for index, raw in enumerate(lines):
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            current = stripped[1:-1].strip().lower()
            if section == target and end == len(lines):
                end = index
            section = current
            if current == target and start is None:
                start = index
        elif section == target and re.match(rf"^{re.escape(key)}\s*=", stripped, re.I):
            option = index
    line = f"{key}={value}"
    if option is not None:
        lines[option] = line
    elif start is not None:
        lines.insert(end if end != len(lines) else len(lines), line)
    else:
        if lines and lines[-1].strip():
            lines.append("")
        lines.extend([f"[{section_name}]", line])
    return "\n".join(lines).rstrip() + "\n"


def rewrite_sstp_dns(text: str, servers: Iterable[str]) -> str:
    values = list(servers)
    text = _ensure_ini_module(text, "dns")
    # Remove duplicate legacy keys first; accel-ppp can otherwise keep the
    # first stale resolver even though the panel displays the newer value.
    cleaned: list[str] = []
    section = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
        if section == "dns" and re.match(r"^dns[12]\s*=", stripped, re.I):
            continue
        cleaned.append(raw)
    text = "\n".join(cleaned).rstrip() + "\n"
    text = _set_ini_option(text, "dns", "dns1", values[0])
    if len(values) > 1:
        text = _set_ini_option(text, "dns", "dns2", values[1])
    else:
        lines: list[str] = []
        section = ""
        for raw in text.splitlines():
            stripped = raw.strip()
            if stripped.startswith("[") and stripped.endswith("]"):
                section = stripped[1:-1].strip().lower()
            if section == "dns" and re.match(r"^dns2\s*=", stripped, re.I):
                continue
            lines.append(raw)
        text = "\n".join(lines).rstrip() + "\n"
    # Remove legacy DNS keys that were accidentally written outside [dns].
    lines = []
    section = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
        if section != "dns" and re.match(r"^dns[12]\s*=", stripped, re.I):
            continue
        lines.append(raw)
    return "\n".join(lines).rstrip() + "\n"


def rewrite_ikev2_dns(text: str, servers: Iterable[str]) -> str:
    values = list(servers)
    block = _IKEV2_CONNECTION_RE.search(text)
    if not block:
        raise ProtocolDnsError("کانکشن IKEv2-MSCHAPv2 در ipsec.conf پیدا نشد")
    lines = block.group(0).splitlines()
    # Remove every legacy/duplicate rightdns line. strongSwan accepts repeated
    # keys inconsistently across releases, so one stale line can override the
    # value displayed by the panel.
    lines = [line for line in lines if not re.match(r"^\s*rightdns\s*=", line, re.I)]
    replacement = "    rightdns=" + ",".join(values)
    insert_at = len(lines)
    for index, line in enumerate(lines):
        if re.match(r"^\s*rightsourceip\s*=", line, re.I):
            insert_at = index + 1
            break
    else:
        for index, line in enumerate(lines):
            if re.match(r"^\s*(?:eap_identity|auto)\s*=", line, re.I):
                insert_at = index
                break
    lines.insert(insert_at, replacement)
    current = "\n".join(lines).rstrip() + "\n"
    return text[: block.start()] + current + text[block.end() :]


def rewrite_openconnect_dns(text: str, servers: Iterable[str]) -> str:
    begin = "# BEGIN VPN PANEL DNS"
    end = "# END VPN PANEL DNS"
    text = _strip_managed_block(text, begin, end)
    # setup_openconnect.sh also migrates legacy unmarked directives. Keep the
    # same rule here so a DNS-only save cannot leave duplicate resolvers.
    text = re.sub(r"(?mi)^\s*dns\s*=.*$", "", text)
    text = re.sub(r"\n{3,}", "\n\n", text).rstrip()
    block = [begin, *(f"dns = {value}" for value in servers), end]
    return text + "\n\n" + "\n".join(block) + "\n"


_REWRITERS: dict[str, Callable[[str, Iterable[str]], str]] = {
    "l2tp": rewrite_ppp_dns,
    "pptp": rewrite_ppp_dns,
    "openvpn": rewrite_openvpn_dns,
    "sstp": rewrite_sstp_dns,
    "ikev2": rewrite_ikev2_dns,
    "openconnect": rewrite_openconnect_dns,
}


def _contains_ikev2_connection(path: Path) -> bool:
    """Return whether an ipsec.conf actually owns the panel's IKEv2 conn.

    L2TP and IKEv2 intentionally share /etc/ipsec.conf.  File existence alone
    therefore cannot prove that IKEv2 is installed.  An unreadable file is kept
    in the result so the caller reports the real permission/read failure instead
    of incorrectly treating the protocol as absent.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return True
    return _IKEV2_CONNECTION_RE.search(text) is not None


def _resolve_paths(
    target: str, path_overrides: dict[str, tuple[Path, ...]] | None
) -> tuple[Path, ...]:
    if path_overrides is not None:
        paths = tuple(path for path in path_overrides.get(target, ()) if path.is_file())
    else:
        paths = tuple(path for path in _DEFAULT_PATHS.get(target, ()) if path.is_file())

    # /etc/ipsec.conf may exist only because L2TP is installed.  IKEv2 is a
    # configured DNS target only when its dedicated connection block exists.
    # This prevents update-time DNS audit from failing on L2TP-only nodes.
    if target == "ikev2":
        return tuple(path for path in paths if _contains_ikev2_connection(path))

    if target != "openvpn":
        return paths

    # Prefer the modern primary pair and include every canonical extra-listener
    # config. Existing extra listeners are independent OpenVPN processes and
    # must receive the same DNS push as the primary UDP/TCP pair.
    modern = tuple(path for path in paths if "/server/" in str(path))
    legacy = tuple(path for path in paths if "/server/" not in str(path))
    primary = modern if len(modern) >= 2 else legacy
    extras = tuple(sorted(Path("/etc/openvpn/server").glob("server-extra-*.conf")))
    unique: list[Path] = []
    seen: set[str] = set()
    for path in (*primary, *extras):
        try:
            identity = str(path.resolve())
        except OSError:
            identity = str(path)
        if identity not in seen and path.is_file():
            seen.add(identity)
            unique.append(path)
    return tuple(unique)


def _atomic_write(path: Path, content: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.dns-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(name, mode if mode is not None else 0o600)
        os.replace(name, path)
    finally:
        try:
            os.unlink(name)
        except FileNotFoundError:
            pass


def _dns_module_available() -> bool:
    for root in (Path("/usr/lib"), Path("/usr/lib64"), Path("/usr/local/lib")):
        if not root.is_dir():
            continue
        try:
            if next(root.rglob("libdns.so"), None) is not None:
                return True
        except OSError:
            continue
    return False


def _read_port(path: Path, pattern: str, fallback: int) -> int:
    try:
        match = re.search(pattern, path.read_text(encoding="utf-8", errors="replace"), re.M)
        if match:
            value = int(match.group(1))
            if 1 <= value <= 65535:
                return value
    except (OSError, ValueError):
        pass
    return fallback


def _listener_present(proto: str, port: int) -> bool:
    command = ["/usr/bin/ss", "-H", "-lun" if proto == "udp" else "-ltn"]
    try:
        output = subprocess.run(command, capture_output=True, text=True, timeout=5, check=False).stdout or ""
    except Exception:
        return False
    return bool(re.search(rf"(?:^|\s)(?:\[[^\]]+\]|[^\s:]+|\*):{int(port)}(?:\s|$)", output))


def _systemctl_active(unit: str) -> bool:
    try:
        result = subprocess.run(
            ["/usr/bin/systemctl", "is-active", unit],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        return (result.stdout or "").strip() == "active"
    except Exception:
        return False


def _openvpn_unit_for_config(path: Path) -> str | None:
    name = path.stem
    candidates = (f"openvpn-server@{name}", f"openvpn@{name}")
    for unit in candidates:
        if _systemctl_active(unit):
            return unit
    if name in {"server-udp", "server-tcp"}:
        unit_files = subprocess.run(
            ["/usr/bin/systemctl", "list-unit-files"],
            capture_output=True, text=True, timeout=10, check=False,
        ).stdout or ""
        prefix = "openvpn-server@" if "openvpn-server@" in unit_files else "openvpn@"
        return prefix + name
    return None


def _openvpn_proto(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "tcp" if "tcp" in path.name else "udp"
    match = re.search(r"(?mi)^\s*proto\s+(\S+)", text)
    value = (match.group(1).lower() if match else "")
    return "tcp" if value.startswith("tcp") else "udp"


def _restart_and_verify_openvpn(paths: tuple[Path, ...]) -> None:
    primary = tuple(path for path in paths if path.stem in {"server-udp", "server-tcp"})
    if len(primary) < 2:
        raise ProtocolDnsError("فایل‌های سرور UDP/TCP اوپن‌وی‌پی‌ان کامل نیستند")

    units: list[tuple[str, str, int]] = []
    for path in paths:
        unit = _openvpn_unit_for_config(path)
        # Inactive extra-port configs are updated on disk but intentionally not
        # started by a DNS edit. Primary units are always included when the
        # protocol itself is enabled.
        if unit is None:
            continue
        proto = _openvpn_proto(path)
        port = _read_port(path, r"^\s*port\s+(\d+)\s*$", 1194)
        units.append((unit, proto, port))

    if not units:
        raise ProtocolDnsError("هیچ سرویس فعال OpenVPN برای اعمال DNS پیدا نشد")
    result = subprocess.run(
        ["/usr/bin/systemctl", "restart", *(unit for unit, _, _ in units)],
        capture_output=True, text=True, timeout=75, check=False,
    )
    if result.returncode != 0:
        raise ProtocolDnsError((result.stderr or result.stdout or "OpenVPN restart failed").strip())
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if all(_systemctl_active(unit) and _listener_present(proto, port) for unit, proto, port in units):
            return
        time.sleep(0.25)
    missing = ", ".join(f"{unit}:{proto}/{port}" for unit, proto, port in units if not (_systemctl_active(unit) and _listener_present(proto, port)))
    raise ProtocolDnsError(f"OpenVPN بعد از تغییر DNS کامل آماده نشد: {missing}")


def _restart_and_verify_sstp(path: Path) -> None:
    port = _read_port(path, r"^\s*port\s*=\s*(\d+)\s*$", 4433)
    result = subprocess.run(
        ["/usr/bin/systemctl", "restart", "accel-ppp-sstp"],
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )
    if result.returncode != 0:
        raise ProtocolDnsError((result.stderr or result.stdout or "SSTP restart failed").strip())
    deadline = time.monotonic() + 7
    while time.monotonic() < deadline:
        if _systemctl_active("accel-ppp-sstp") and _listener_present("tcp", port):
            return
        time.sleep(0.25)
    raise ProtocolDnsError(f"SSTP بعد از تغییر DNS روی TCP/{port} آماده نشد")


def _reload_and_verify_ikev2() -> None:
    ipsec = shutil.which("ipsec") or "/usr/sbin/ipsec"
    attempts = ([ipsec, "reload"], ["/usr/bin/systemctl", "reload", "strongswan-starter"])
    detail = ""
    for command in attempts:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False)
        except OSError as exc:
            detail = str(exc)
            continue
        detail = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
        if result.returncode == 0:
            break
    else:
        raise ProtocolDnsError(detail or "strongSwan reload failed")
    # A reload must not kill L2TP, and the shared IKE/NAT-T listeners must stay up.
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline:
        if _listener_present("udp", 500) and _listener_present("udp", 4500):
            return
        time.sleep(0.25)
    raise ProtocolDnsError("strongSwan پس از reload روی UDP/500 و UDP/4500 آماده نیست")


def _reload_and_verify_openconnect(path: Path) -> None:
    port = _read_port(path, r"^\s*(?:tcp-port|server-port)\s*=\s*(\d+)\s*$", 8443)
    commands = (
        ["/usr/bin/systemctl", "reload", "ocserv"],
        ["/usr/bin/systemctl", "kill", "-s", "HUP", "--kill-who=main", "ocserv"],
    )
    detail = ""
    for command in commands:
        result = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
        detail = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
        if result.returncode == 0:
            break
    else:
        raise ProtocolDnsError(detail or "ocserv reload failed")
    deadline = time.monotonic() + 6
    while time.monotonic() < deadline:
        if _systemctl_active("ocserv") and (_listener_present("tcp", port) or _listener_present("udp", port)):
            return
        time.sleep(0.25)
    raise ProtocolDnsError(f"OpenConnect پس از تغییر DNS روی پورت {port} آماده نیست")


def _runtime_should_apply(payload, protocol: str) -> bool:
    enabled_field = f"{protocol}_enabled"
    if hasattr(payload, enabled_field) and not bool(getattr(payload, enabled_field)):
        return False
    if protocol == "openconnect" and not _systemctl_active("ocserv"):
        return False
    return True


def _apply_runtime(payload, protocol: str, paths: tuple[Path, ...]) -> str:
    # pppd reads these option files when each new PPTP/L2TP session starts.
    # Existing sessions keep their old DNS until reconnect.
    if protocol in {"l2tp", "pptp"}:
        return "DNS saved; new PPP sessions use it without a daemon restart"
    if not _runtime_should_apply(payload, protocol):
        return "DNS saved; protocol is stopped so runtime start/restart was skipped"
    if protocol == "openvpn":
        _restart_and_verify_openvpn(paths)
        return "OpenVPN primary and active extra listeners restarted and verified"
    if protocol == "sstp":
        _restart_and_verify_sstp(paths[0])
        return "SSTP restarted and listener verified"
    if protocol == "ikev2":
        _reload_and_verify_ikev2()
        return "strongSwan reloaded without a hard restart"
    if protocol == "openconnect":
        _reload_and_verify_openconnect(paths[0])
        return "ocserv reloaded and listener verified"
    raise ProtocolDnsError(f"unsupported runtime target: {protocol}")


def _verify_written(protocol: str, text: str, servers: tuple[str, ...]) -> None:
    if protocol in {"l2tp", "pptp"}:
        found = tuple(re.findall(r"(?mi)^\s*ms-dns\s+(\S+)\s*$", text))
        if found != servers:
            raise ProtocolDnsError(f"DNS فایل PPP دقیق نیست: expected={servers} found={found}")
        return
    if protocol == "openvpn":
        found = tuple(re.findall(r'(?mi)^\s*push\s+"dhcp-option\s+DNS\s+([^"\r\n]+)"\s*$', text))
        if found != servers:
            raise ProtocolDnsError(f"DNS فایل OpenVPN دقیق نیست: expected={servers} found={found}")
        return
    if protocol == "sstp":
        block = re.search(r"(?ms)^\[dns\]\s*$.*?(?=^\[|\Z)", text)
        if not block:
            raise ProtocolDnsError("بخش [dns] در SSTP پیدا نشد")
        values = []
        for key in ("dns1", "dns2"):
            match = re.search(rf"(?mi)^\s*{key}\s*=\s*(\S+)\s*$", block.group(0))
            if match:
                values.append(match.group(1))
        if tuple(values) != servers:
            raise ProtocolDnsError(f"DNS فایل SSTP دقیق نیست: expected={servers} found={tuple(values)}")
        return
    if protocol == "ikev2":
        block = _IKEV2_CONNECTION_RE.search(text)
        found = re.findall(r"(?mi)^\s*rightdns\s*=\s*(.*?)\s*$", block.group(0) if block else "")
        expected = ",".join(servers)
        if found != [expected]:
            raise ProtocolDnsError(f"rightdns فایل IKEv2 دقیق نیست: expected={expected} found={found}")
        return
    if protocol == "openconnect":
        found = tuple(re.findall(r"(?mi)^\s*dns\s*=\s*(\S+)\s*$", text))
        if found != servers:
            raise ProtocolDnsError(f"DNS فایل OpenConnect دقیق نیست: expected={servers} found={found}")
        return
    raise ProtocolDnsError(f"unsupported DNS verification target: {protocol}")


def apply_protocol_dns_settings(
    payload,
    target: str,
    *,
    path_overrides: dict[str, tuple[Path, ...]] | None = None,
    apply_runtime: bool = True,
) -> tuple[bool, str]:
    """Apply DNS for exactly one protocol with file/runtime rollback."""
    target = str(target or "").strip().lower()
    dns1 = getattr(payload, f"{target}_dns1", "")
    dns2 = getattr(payload, f"{target}_dns2", "")
    try:
        servers = normalize_dns_servers(target, dns1, dns2)
    except ProtocolDnsError as exc:
        return False, str(exc)

    existing = _resolve_paths(target, path_overrides)
    if not existing:
        return False, f"فایل تنظیمات {target} روی این نود پیدا نشد"
    if target == "sstp" and not _dns_module_available() and path_overrides is None:
        return False, "ماژول DNS سرویس SSTP (libdns.so) روی این نود نصب نیست؛ فایل دست‌نخورده باقی ماند"

    _LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
    lock_fd = os.open(_LOCK_PATH, os.O_CREAT | os.O_RDWR, 0o600)
    snapshots: dict[Path, tuple[bytes, int]] = {}
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX)
        for path in existing:
            stat = path.stat()
            snapshots[path] = (path.read_bytes(), stat.st_mode & 0o7777)

        rewriter = _REWRITERS[target]
        for path in existing:
            original = snapshots[path][0].decode("utf-8", errors="replace")
            updated = rewriter(original, servers)
            _verify_written(target, updated, servers)
            if updated != original:
                _atomic_write(path, updated, snapshots[path][1])

        runtime_detail = "runtime validation skipped"
        if apply_runtime:
            runtime_detail = _apply_runtime(payload, target, existing)
        return True, f"DNS_SAFE_APPLY_OK protocol={target} dns={','.join(servers)}; {runtime_detail}"
    except Exception as exc:
        for path, (content, mode) in snapshots.items():
            try:
                _atomic_write(path, content.decode("utf-8", errors="replace"), mode)
            except Exception:
                pass
        if apply_runtime and snapshots:
            try:
                _apply_runtime(payload, target, existing)
            except Exception:
                pass
        return False, f"DNS_SAFE_APPLY_ROLLBACK protocol={target}: {exc}"
    finally:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
        finally:
            os.close(lock_fd)
