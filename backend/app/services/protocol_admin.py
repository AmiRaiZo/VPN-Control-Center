from __future__ import annotations

import json
import logging
import os
import re
import shutil
import stat
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable

from sqlalchemy.orm import Session

from app.models import ConnectionLog, Setting
from app.proc_utils import BASH, SYSTEMCTL


logger = logging.getLogger("vpn-panel.protocol_admin")


@dataclass(frozen=True)
class ConfigFileSpec:
    id: str
    label: str
    path: str
    required_markers: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProtocolSpec:
    key: str
    label: str
    backend: str
    packages: tuple[str, ...]
    units: tuple[str, ...]
    version_commands: tuple[tuple[str, ...], ...]
    configs: tuple[ConfigFileSpec, ...]
    session_protocols: tuple[str, ...]
    install_key: str


# OpenVPN's systemd template differs between Ubuntu releases.  We resolve the
# active template at runtime instead of hardcoding one generation.
def _openvpn_units() -> tuple[str, str]:
    candidates = (
        ("openvpn-server@server-udp", "openvpn-server@server-tcp"),
        ("openvpn@server-udp", "openvpn@server-tcp"),
    )
    unit_files = _run_text([SYSTEMCTL, "list-unit-files"], timeout=8)
    for pair in candidates:
        if any(unit in unit_files for unit in pair):
            return pair
    return candidates[0]


def _ipsec_unit() -> str:
    unit_files = _run_text([SYSTEMCTL, "list-unit-files"], timeout=8)
    for candidate in ("strongswan-starter", "strongswan", "ipsec"):
        if candidate in unit_files:
            return candidate
    return "strongswan-starter"


def _protocol_specs() -> dict[str, ProtocolSpec]:
    ovpn_udp, ovpn_tcp = _openvpn_units()
    ipsec_unit = _ipsec_unit()
    return {
        "l2tp": ProtocolSpec(
            key="l2tp",
            label="L2TP",
            backend="xl2tpd + pppd",
            packages=("xl2tpd", "ppp"),
            units=("xl2tpd",),
            version_commands=(("xl2tpd", "-v"),),
            configs=(
                ConfigFileSpec("xl2tpd", "xl2tpd.conf", "/etc/xl2tpd/xl2tpd.conf", ("[lns default]",)),
                ConfigFileSpec("ppp", "PPP options", "/etc/ppp/options.xl2tpd", ("name l2tpd",)),
            ),
            session_protocols=("l2tp",),
            install_key="l2tp",
        ),
        "ipsec": ProtocolSpec(
            key="ipsec",
            label="IPsec",
            backend="strongSwan (charon)",
            packages=("strongswan",),
            units=(ipsec_unit,),
            version_commands=(("ipsec", "--version"),),
            configs=(ConfigFileSpec("ipsec", "ipsec.conf", "/etc/ipsec.conf", ("config setup",)),),
            session_protocols=("l2tp", "ikev2"),
            install_key="ipsec",
        ),
        "pptp": ProtocolSpec(
            key="pptp",
            label="PPTP",
            backend="pptpd + pppd",
            packages=("pptpd",),
            units=("pptpd",),
            version_commands=(("pptpd", "--version"),),
            configs=(
                ConfigFileSpec("pptpd", "pptpd.conf", "/etc/pptpd.conf", ("option /etc/ppp/pptpd-options",)),
                ConfigFileSpec("ppp", "PPP options", "/etc/ppp/pptpd-options", ("name pptpd",)),
            ),
            session_protocols=("pptp",),
            install_key="pptp",
        ),
        "openvpn": ProtocolSpec(
            key="openvpn",
            label="OpenVPN",
            backend="OpenVPN",
            packages=("openvpn",),
            units=(ovpn_udp, ovpn_tcp),
            version_commands=(("openvpn", "--version"),),
            configs=(
                ConfigFileSpec("udp", "server-udp.conf", "/etc/openvpn/server/server-udp.conf", ("proto udp", "server ")),
                ConfigFileSpec("tcp", "server-tcp.conf", "/etc/openvpn/server/server-tcp.conf", ("proto tcp-server", "server ")),
            ),
            session_protocols=("openvpn",),
            install_key="openvpn",
        ),
        "openconnect": ProtocolSpec(
            key="openconnect",
            label="OpenConnect (Cisco)",
            backend="ocserv",
            packages=("ocserv",),
            units=("ocserv",),
            version_commands=(("ocserv", "--version"),),
            configs=(ConfigFileSpec("ocserv", "ocserv.conf", "/etc/ocserv/ocserv.conf", ("auth =", "tcp-port =", "udp-port =")),),
            session_protocols=("openconnect",),
            install_key="openconnect",
        ),
        "sstp": ProtocolSpec(
            key="sstp",
            label="SSTP",
            backend="accel-ppp",
            packages=(),
            units=("accel-ppp-sstp",),
            version_commands=(("accel-pppd", "--version"),),
            configs=(ConfigFileSpec("sstp", "sstp.conf", "/etc/accel-ppp/sstp.conf", ("[sstp]", "[ppp]")),),
            session_protocols=("sstp",),
            install_key="sstp",
        ),
        "ikev2": ProtocolSpec(
            key="ikev2",
            label="IKEv2",
            backend="strongSwan (charon)",
            packages=("strongswan",),
            units=(ipsec_unit,),
            version_commands=(("ipsec", "--version"),),
            configs=(ConfigFileSpec("ipsec", "ipsec.conf", "/etc/ipsec.conf", ("conn IKEv2-MSCHAPv2",)),),
            session_protocols=("ikev2",),
            install_key="ikev2",
        ),
        "vmess": ProtocolSpec(
            key="vmess",
            label="VMess",
            backend="Xray-core",
            packages=(),
            units=("vpn-panel-xray-vmess",),
            version_commands=(("xray", "version"), ("/usr/local/bin/xray", "version")),
            configs=(ConfigFileSpec("xray", "config.json", "/etc/vpn-panel/xray/vmess/config.json", ('"inbounds"', '"vmess"')),),
            session_protocols=("vmess",),
            install_key="vmess",
        ),
        "vless": ProtocolSpec(
            key="vless",
            label="VLESS",
            backend="Xray-core",
            packages=(),
            units=("vpn-panel-xray-vless",),
            version_commands=(("xray", "version"), ("/usr/local/bin/xray", "version")),
            configs=(ConfigFileSpec("xray", "config.json", "/etc/vpn-panel/xray/vless/config.json", ('"inbounds"', '"vless"')),),
            session_protocols=("vless",),
            install_key="vless",
        ),
    }


def _run_text(args: Iterable[str], timeout: int = 10) -> str:
    try:
        result = subprocess.run(list(args), capture_output=True, text=True, timeout=timeout, check=False)
        return ((result.stdout or "") + ("\n" + result.stderr if result.stderr else "")).strip()
    except Exception:
        return ""


def _unit_exists(unit: str) -> bool:
    try:
        result = subprocess.run(
            [SYSTEMCTL, "show", unit, "--property=LoadState", "--value"],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        return (result.stdout or "").strip() not in ("", "not-found")
    except (OSError, subprocess.SubprocessError):
        return False


def _unit_state(unit: str) -> str:
    try:
        result = subprocess.run(
            [SYSTEMCTL, "is-active", unit], capture_output=True, text=True, timeout=8, check=False
        )
        return (result.stdout or "").strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def _unit_details(unit: str) -> dict[str, str]:
    props = (
        "LoadState", "ActiveState", "SubState", "Result", "NRestarts",
        "ExecMainStatus", "MainPID", "FragmentPath",
    )
    try:
        result = subprocess.run(
            [SYSTEMCTL, "show", unit, *[f"--property={name}" for name in props]],
            capture_output=True, text=True, timeout=8, check=False,
        )
        data: dict[str, str] = {}
        for line in (result.stdout or "").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                data[key] = value
        return data
    except (OSError, subprocess.SubprocessError):
        return {}


def _process_running(*names: str) -> bool:
    for name in names:
        executable = shutil.which("pgrep") or "/usr/bin/pgrep"
        try:
            result = subprocess.run([executable, "-x", name], capture_output=True, timeout=5, check=False)
            if result.returncode == 0:
                return True
        except Exception:
            pass
    return False


def _listener_snapshot() -> str:
    ss = shutil.which("ss") or "/usr/bin/ss"
    return _run_text((ss, "-H", "-lntu"), timeout=8)


def _proc_listener_present(transport: str, port: int) -> bool:
    """Fallback listener detection from /proc/net.

    ``ss`` output differs between iproute2 builds and can be empty inside a
    restricted service context.  /proc/net is kernel-owned and avoids the
    false OpenVPN failures where both daemons are active and the tunnel log
    says Initialization Sequence Completed but the panel reports ports=False.
    """
    names = ("tcp", "tcp6") if transport == "tcp" else ("udp", "udp6")
    wanted = f"{int(port):04X}"
    for name in names:
        try:
            lines = Path(f"/proc/net/{name}").read_text(errors="replace").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 4 or ":" not in parts[1]:
                continue
            local_port = parts[1].rsplit(":", 1)[-1].upper()
            state = parts[3].upper()
            if local_port != wanted:
                continue
            if transport == "tcp" and state != "0A":  # TCP_LISTEN
                continue
            return True
    return False


def _listener_present(snapshot: str, transport: str, port: int) -> bool:
    transport = transport.lower()
    for line in snapshot.splitlines():
        parts = line.split()
        if not parts or parts[0].lower() != transport:
            continue
        local = parts[4] if len(parts) > 4 else line
        if re.search(rf"(?:\]|:){int(port)}$", local):
            return True
        if re.search(rf"(?:\]|:){int(port)}(?:\s|$)", line):
            return True
    return _proc_listener_present(transport, int(port))



def _openvpn_config_port(paths: tuple[str, ...], fallback: int) -> int:
    for raw_path in paths:
        try:
            content = Path(raw_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        match = re.search(r"(?m)^\s*port\s+(\d+)\s*$", content)
        if match:
            try:
                value = int(match.group(1))
                if 1 <= value <= 65535:
                    return value
            except ValueError:
                pass
    return fallback


def _expected_listeners(db: Session, key: str) -> list[tuple[str, int]]:
    try:
        if key == "l2tp":
            return [
                ("udp", _configured_port(db, "l2tp_port", 1701)),
                ("udp", 500),
                ("udp", 4500),
            ]
        if key in {"ipsec", "ikev2"}:
            return [("udp", 500), ("udp", 4500)]
        if key == "pptp":
            return [("tcp", 1723)]
        if key == "openvpn":
            # During a port edit the files and services are changed before the
            # endpoint commits the DB setting. Runtime health must therefore
            # trust the just-written configs, otherwise it checks the old DB
            # port and falsely reports degraded although the new socket is live.
            db_udp = _configured_port(db, "openvpn_udp_port", 1194)
            db_tcp = _configured_port(db, "openvpn_tcp_port", 1194)
            udp = _openvpn_config_port(("/etc/openvpn/server/server-udp.conf", "/etc/openvpn/server-udp.conf"), db_udp)
            tcp = _openvpn_config_port(("/etc/openvpn/server/server-tcp.conf", "/etc/openvpn/server-tcp.conf"), db_tcp)
            return [("udp", udp), ("tcp", tcp)]
        if key == "openconnect":
            port = _configured_port(db, "openconnect_port", 8443)
            return [("tcp", port), ("udp", port)]
        if key == "sstp":
            return [("tcp", _configured_port(db, "sstp_port", 4433))]
        if key == "vmess":
            return [("tcp", int(_setting(db, "vmess_port", "10000")))]
        if key == "vless":
            return [("tcp", int(_setting(db, "vless_port", "10001")))]
    except (TypeError, ValueError):
        return []
    return []


def _last_error(unit: str) -> str:
    output = _run_text(("/usr/bin/journalctl", "-u", unit, "-n", "60", "--no-pager", "--output=cat"), timeout=10)
    candidates = []
    benign = (
        "death_handler: fatal signal 15 received",
        "sigterm received",
        "sigint received",
        "deactivated successfully",
        "stopped successfully",
        "already a xl2tpd server running",
        "charon is already running",
        "starter is already running",
        # Optional strongSwan plugins are not required for L2TP/IKEv2 and can
        # be built for a different libc by third-party packages. When charon
        # itself is healthy these warnings must not paint the whole card red.
        "plugin 'vici' failed to load",
        "plugin 'attr-sql' failed to load",
        "plugin 'sqlite' failed to load",
        "plugin 'eap-sim' failed to load",
        "plugin 'eap-sim-file' failed to load",
        "plugin 'eap-simaka-pseudonym' failed to load",
        "plugin 'eap-simaka-reauth' failed to load",
        "plugin 'eap-aka-3gpp2' failed to load",
        # Normal client disconnect/noise, not a daemon startup failure.
        "the tls connection was non-properly terminated",
        "sstp: read: input/output error",
        "the feature vmess",
        "deprecated, not recommended",
        "received invalid ike header",
        "failed to load: libc.musl",
    )
    for line in output.splitlines():
        lower = line.lower()
        if any(token in lower for token in benign):
            continue
        if any(token in lower for token in ("permission denied", "failed", "error", "fatal", "address already in use", "cannot", "invalid")):
            candidates.append(line.strip())
    return (candidates[-1] if candidates else "")[-700:]


def _xray_permissions_ok(key: str) -> bool:
    try:
        from app.services.xray_manager import config_path, service_account_can_read
        return service_account_can_read(config_path(key))
    except Exception:
        return False


def _runtime_health(db: Session, key: str, spec: ProtocolSpec, installed: bool, snapshot: str) -> dict:
    details = {unit: _unit_details(unit) for unit in spec.units}
    states = {unit: (data.get("ActiveState") or _unit_state(unit)) for unit, data in details.items()}
    expected = _expected_listeners(db, key)
    listener_checks = {f"{proto}/{port}": _listener_present(snapshot, proto, port) for proto, port in expected}
    ports_ok = all(listener_checks.values()) if listener_checks else True
    config_ok = bool(spec.configs) and all(_config_marker_exists(item) for item in spec.configs)
    restart_count = max([int(data.get("NRestarts") or 0) for data in details.values()] or [0])
    exit_status = max([int(data.get("ExecMainStatus") or 0) for data in details.values()] or [0])
    unit_failed = any(state == "failed" or data.get("Result") == "exit-code" for unit, state in states.items() for data in [details[unit]])
    unit_active = all(state == "active" for state in states.values()) if states else False
    unit_starting = any(state in {"activating", "reloading"} for state in states.values())
    process_ok = unit_active
    # OpenVPN stays active only after successfully creating the TUN interface
    # and binding its socket. Some Ubuntu/systemd contexts hide listeners from
    # ``ss`` and even expose an incomplete /proc/net view to the API service.
    # Active UDP+TCP instances plus matching config are therefore an
    # authoritative fallback and must not be shown as a failed start.
    if key == "openvpn" and unit_active and config_ok:
        ports_ok = True
        listener_checks = {name: True for name in listener_checks}
    permission_ok = True

    if key == "l2tp":
        process_ok = _process_running("xl2tpd") and _process_running("charon", "charon-systemd")
        config_ok = config_ok and "conn L2TP-PSK" in _run_text(("/usr/bin/sed", "-n", "1,500p", "/etc/ipsec.conf"), timeout=8)
    elif key in {"ipsec", "ikev2"}:
        process_ok = _process_running("charon", "charon-systemd") or "Security Associations" in _run_text(("/usr/sbin/ipsec", "status"), timeout=8)
    elif key == "pptp":
        process_ok = _process_running("pptpd")
    elif key == "openconnect":
        process_ok = _process_running("ocserv-main", "ocserv")
    elif key == "sstp":
        process_ok = _process_running("accel-pppd")
    elif key in {"vmess", "vless"}:
        process_ok = _process_running("xray") and unit_active
        permission_ok = _xray_permissions_ok(key)

    error = ""
    for unit in spec.units:
        error = _last_error(unit) or error
    if not config_ok and not error:
        missing = [item.label for item in spec.configs if not _config_marker_exists(item)]
        if key == "l2tp" and "conn L2TP-PSK" not in _run_text(("/usr/bin/sed", "-n", "1,500p", "/etc/ipsec.conf"), timeout=8):
            missing.append("L2TP-PSK IPsec connection")
        error = "Missing or incomplete configuration: " + ", ".join(missing or ["required markers"])

    if not installed:
        state = "not_installed"
    elif key in {"vmess", "vless"} and not permission_ok:
        state, error = "failed", f"vpn-xray cannot read /etc/vpn-panel/xray/{key}/config.json"
    elif key in {"l2tp", "ipsec", "ikev2"} and process_ok and ports_ok and config_ok:
        # SysV xl2tpd units legitimately report active(exited), while an already
        # running charon may make strongswan-starter exit successfully. Runtime
        # process/listener health is authoritative for these shared daemons.
        state = "active"
    elif unit_failed or exit_status != 0 or (unit_starting and restart_count >= 2):
        state = "failed"
    elif process_ok and ports_ok and config_ok:
        state = "active"
    elif unit_starting and restart_count < 2:
        state = "activating"
    elif process_ok and config_ok:
        state = "degraded"
    elif all(state == "inactive" for state in states.values()) and not process_ok:
        state = "inactive"
    else:
        state = "failed" if error else "degraded"

    # Journal history is not current health. Once a protocol is ready, stopped
    # intentionally, or not installed, suppress old errors from previous repair
    # attempts so the UI reflects the current runtime rather than stale logs.
    if state in {"active", "inactive", "not_installed"}:
        error = ""

    return {
        "state": state,
        "unit_states": states,
        "unit_details": details,
        "process": process_ok,
        "ports": listener_checks,
        "ports_ok": ports_ok,
        "config": config_ok,
        "permissions": permission_ok,
        "restart_count": restart_count,
        "exit_status": exit_status,
        "managed": unit_active or unit_starting,
        "last_error": error,
    }


def _package_version(packages: tuple[str, ...]) -> str:
    for package in packages:
        result = subprocess.run(
            ["/usr/bin/dpkg-query", "-W", "-f=${Version}", package],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        value = (result.stdout or "").strip()
        if result.returncode == 0 and value:
            return value
    return ""


def _command_version(commands: tuple[tuple[str, ...], ...]) -> str:
    for command in commands:
        executable = shutil.which(command[0])
        if not executable:
            continue
        output = _run_text((executable, *command[1:]), timeout=8)
        if output:
            first = next((line.strip() for line in output.splitlines() if line.strip()), "")
            first = re.sub(r"\s+", " ", first)
            return first[:120]
    return ""


def _setting(db: Session, key: str, default: str = "") -> str:
    row = db.query(Setting).filter(Setting.key == key).first()
    return row.value if row and row.value is not None else default


def _configured_port(db: Session, setting_key: str, default: int) -> int:
    """Return a validated configured listener port for runtime/control paths.

    This helper intentionally lives at module scope.  Protocol status and
    service-control code are separate functions, so a nested helper caused
    ``NameError: configured_port is not defined`` when restarting OpenVPN and
    when probing L2TP/OpenConnect/SSTP listeners.
    """
    try:
        value = int(_setting(db, setting_key, str(default)))
    except (TypeError, ValueError):
        return default
    return value if 1 <= value <= 65535 else default


def _port_text(db: Session, key: str) -> str:
    if key == "l2tp":
        return f"UDP {_setting(db, 'l2tp_port', '1701')}"
    if key == "ipsec" or key == "ikev2":
        return "UDP 500 / 4500"
    if key == "pptp":
        return "TCP 1723 + GRE"
    if key == "openvpn":
        return f"UDP {_setting(db, 'openvpn_udp_port', '1194')} / TCP {_setting(db, 'openvpn_tcp_port', '1194')}"
    if key == "openconnect":
        port = _setting(db, "openconnect_port", "8443")
        return f"TCP+UDP {port}"
    if key == "sstp":
        return f"TCP {_setting(db, 'sstp_port', '4433')}"
    if key == "vmess":
        return f"TCP {_setting(db, 'vmess_port', '10000')}"
    if key == "vless":
        return f"TCP {_setting(db, 'vless_port', '10001')}"
    return "—"


def _config_marker_exists(item: ConfigFileSpec) -> bool:
    path = Path(item.path)
    if not path.is_file():
        return False
    if not item.required_markers:
        return True
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    normalized = re.sub(r"[\t ]+", " ", content)
    return all(marker in content or re.sub(r"[\t ]+", " ", marker) in normalized for marker in item.required_markers)


def _port_notice(db: Session, key: str) -> dict | None:
    raw = _setting(db, f"protocol_port_notice_{key}", "")
    if not raw:
        return None
    try:
        value = json.loads(raw)
        return value if isinstance(value, dict) else None
    except (TypeError, ValueError):
        return None


def get_protocol_center(db: Session) -> list[dict]:
    rows: list[dict] = []
    snapshot = _listener_snapshot()
    for key, spec in _protocol_specs().items():
        unit_installed = all(_unit_exists(unit) for unit in spec.units)
        binary_installed = any(shutil.which(command[0]) or Path(command[0]).is_file() for command in spec.version_commands)
        # Installation and configuration health are separate concepts. A broken
        # or incomplete config must be reported as degraded/failed, not as
        # "not installed" while its daemon and listeners are already present.
        installed = bool(unit_installed or binary_installed)
        health = _runtime_health(db, key, spec, installed, snapshot)
        online = (
            db.query(ConnectionLog)
            .filter(ConnectionLog.protocol.in_(spec.session_protocols), ConnectionLog.is_online == True)  # noqa: E712
            .count()
        )
        version = _package_version(spec.packages) or _command_version(spec.version_commands) or "—"
        rows.append({
            "key": key, "label": spec.label, "backend": spec.backend,
            "units": list(spec.units), "unit": ", ".join(spec.units),
            "state": health["state"], "unit_states": health["unit_states"],
            "installed": installed, "version": version, "inbounds": online,
            "listen": _port_text(db, key), "health": health,
            "last_error": health["last_error"], "restart_count": health["restart_count"],
            "port_notice": _port_notice(db, key),
            "config_files": [
                {"id": item.id, "label": item.label, "path": item.path, "exists": Path(item.path).exists()}
                for item in spec.configs
            ],
        })
    return rows


_RUNTIME_SUMMARY_CACHE_LOCK = threading.Lock()
_RUNTIME_SUMMARY_CACHE: dict[str, object] = {"generated_at": 0.0, "rows": []}
_RUNTIME_SUMMARY_TTL_SECONDS = 8.0


def _bulk_unit_runtime(units: set[str]) -> dict[str, dict[str, str]]:
    """Read LoadState/ActiveState for all dashboard units in one systemctl call."""
    if not units:
        return {}
    ordered = sorted(units)
    try:
        result = subprocess.run(
            [SYSTEMCTL, "show", *ordered, "--property=Id", "--property=LoadState", "--property=ActiveState"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        output = result.stdout or ""
    except Exception:
        output = ""

    parsed: dict[str, dict[str, str]] = {}
    current: dict[str, str] = {}
    for line in [*output.splitlines(), ""]:
        if not line.strip():
            unit_id = current.get("Id", "")
            if unit_id:
                parsed[unit_id.removesuffix(".service")] = dict(current)
            current = {}
            continue
        if "=" in line:
            key, value = line.split("=", 1)
            current[key] = value

    # Older/minimal systemctl builds can omit Id when several units are queried.
    # Fall back only for unresolved rows; the normal path is still one process.
    for unit in ordered:
        if unit not in parsed:
            details = _unit_details(unit)
            if details:
                parsed[unit] = details
    return parsed


def get_protocol_runtime_summary(db: Session, *, force: bool = False) -> list[dict]:
    """Return a fast cached daemon/listener snapshot for Node Agent health.

    Registration and controller health polling have tight timeouts.  Calling the
    full protocol-center probe here would also run package/version/config checks
    for nine protocols every four seconds.  This summary uses one bulk systemd
    read, one listener snapshot and lightweight process checks, then caches the
    result for eight seconds.
    """
    now = time.monotonic()
    with _RUNTIME_SUMMARY_CACHE_LOCK:
        generated_at = float(_RUNTIME_SUMMARY_CACHE.get("generated_at") or 0.0)
        cached = _RUNTIME_SUMMARY_CACHE.get("rows") or []
        if not force and cached and now - generated_at <= _RUNTIME_SUMMARY_TTL_SECONDS:
            return [dict(row, unit_states=dict(row.get("unit_states") or {})) for row in cached]

    ovpn_groups = (
        ("openvpn-server@server-udp", "openvpn@server-udp"),
        ("openvpn-server@server-tcp", "openvpn@server-tcp"),
    )
    ipsec_group = ("strongswan-starter", "strongswan", "ipsec")
    specs = {
        "l2tp": {"label": "L2TP", "backend": "xl2tpd + pppd", "groups": (("xl2tpd",),), "sessions": ("l2tp",), "configs": ("/etc/xl2tpd/xl2tpd.conf",)},
        "ipsec": {"label": "IPsec", "backend": "strongSwan (charon)", "groups": (ipsec_group,), "sessions": ("l2tp", "ikev2"), "configs": ("/etc/ipsec.conf",)},
        "pptp": {"label": "PPTP", "backend": "pptpd + pppd", "groups": (("pptpd",),), "sessions": ("pptp",), "configs": ("/etc/pptpd.conf",)},
        "openvpn": {"label": "OpenVPN", "backend": "OpenVPN", "groups": ovpn_groups, "sessions": ("openvpn",), "configs": ("/etc/openvpn/server/server-udp.conf", "/etc/openvpn/server/server-tcp.conf")},
        "openconnect": {"label": "OpenConnect (Cisco)", "backend": "ocserv", "groups": (("ocserv",),), "sessions": ("openconnect",), "configs": ("/etc/ocserv/ocserv.conf",)},
        "sstp": {"label": "SSTP", "backend": "accel-ppp", "groups": (("accel-ppp-sstp",),), "sessions": ("sstp",), "configs": ("/etc/accel-ppp/sstp.conf",)},
        "ikev2": {"label": "IKEv2", "backend": "strongSwan (charon)", "groups": (ipsec_group,), "sessions": ("ikev2",), "configs": ("/etc/ipsec.conf",)},
        "vmess": {"label": "VMess", "backend": "Xray-core", "groups": (("vpn-panel-xray-vmess",),), "sessions": ("vmess",), "configs": ("/etc/vpn-panel/xray/vmess/config.json",)},
        "vless": {"label": "VLESS", "backend": "Xray-core", "groups": (("vpn-panel-xray-vless",),), "sessions": ("vless",), "configs": ("/etc/vpn-panel/xray/vless/config.json",)},
    }
    all_units = {unit for spec in specs.values() for group in spec["groups"] for unit in group}
    unit_runtime = _bulk_unit_runtime(all_units)
    listeners = _listener_snapshot()

    def choose_unit(group: tuple[str, ...]) -> str:
        for unit in group:
            if unit_runtime.get(unit, {}).get("ActiveState") in {"active", "activating"}:
                return unit
        for unit in group:
            if unit_runtime.get(unit, {}).get("LoadState") not in {None, "", "not-found"}:
                return unit
        return group[0]

    charon_ready = _process_running("charon", "charon-systemd") and _listener_present(listeners, "udp", 500) and _listener_present(listeners, "udp", 4500)
    rows: list[dict] = []
    for key, spec in specs.items():
        selected_units = [choose_unit(group) for group in spec["groups"]]
        states = {
            unit: (unit_runtime.get(unit, {}).get("ActiveState") or "unknown")
            for unit in selected_units
        }
        loaded = any(unit_runtime.get(unit, {}).get("LoadState") not in {None, "", "not-found"} for unit in selected_units)
        config_exists = any(Path(path).is_file() for path in spec["configs"])
        installed = bool(loaded or config_exists)
        any_active = any(value == "active" for value in states.values())
        any_activating = any(value == "activating" for value in states.values())
        any_failed = any(value == "failed" for value in states.values())

        if key == "l2tp":
            ready = _process_running("xl2tpd") and _listener_present(listeners, "udp", _configured_port(db, "l2tp_port", 1701))
        elif key in {"ipsec", "ikev2"}:
            ready = charon_ready
        elif key == "pptp":
            ready = _process_running("pptpd") and _listener_present(listeners, "tcp", 1723)
        elif key == "openvpn":
            udp_port = _configured_port(db, "openvpn_udp_port", 1194)
            tcp_port = _configured_port(db, "openvpn_tcp_port", 1194)
            ready = any_active and (_listener_present(listeners, "udp", udp_port) or _listener_present(listeners, "tcp", tcp_port))
        elif key == "openconnect":
            port = _configured_port(db, "openconnect_port", 8443)
            ready = _process_running("ocserv-main", "ocserv") and _listener_present(listeners, "tcp", port)
        elif key == "sstp":
            port = _configured_port(db, "sstp_port", 4433)
            ready = _process_running("accel-pppd") and _listener_present(listeners, "tcp", port)
        else:
            ready = any_active

        if ready:
            state = "active"
        elif any_activating:
            state = "activating"
        elif any_failed:
            state = "failed"
        elif any_active:
            state = "degraded"
        elif installed:
            state = "inactive"
        else:
            state = "not_installed"

        online = (
            db.query(ConnectionLog)
            .filter(ConnectionLog.protocol.in_(spec["sessions"]), ConnectionLog.is_online == True)  # noqa: E712
            .count()
        )
        rows.append({
            "key": key,
            "label": spec["label"],
            "backend": spec["backend"],
            "state": state,
            "installed": installed,
            "inbounds": int(online),
            "listen": _port_text(db, key),
            "unit_states": states,
            "last_error": "",
        })

    with _RUNTIME_SUMMARY_CACHE_LOCK:
        _RUNTIME_SUMMARY_CACHE["generated_at"] = now
        _RUNTIME_SUMMARY_CACHE["rows"] = rows
    return [dict(row, unit_states=dict(row.get("unit_states") or {})) for row in rows]


def _repair_xray_before_start(key: str) -> tuple[bool, str]:
    try:
        from app.services.xray_manager import config_path, ensure_runtime_permissions, validate_config
        ensure_runtime_permissions(key)
        path = config_path(key)
        valid, detail = validate_config(path)
        if not valid:
            return False, detail
        subprocess.run([SYSTEMCTL, "reset-failed", f"vpn-panel-xray-{key}"], capture_output=True, timeout=10, check=False)
        return True, detail
    except Exception as exc:
        return False, str(exc)


def _strongswan_ready() -> bool:
    snapshot = _listener_snapshot()
    return (
        _process_running("charon", "charon-systemd")
        and _listener_present(snapshot, "udp", 500)
        and _listener_present(snapshot, "udp", 4500)
    )


def _control_strongswan(action: str) -> tuple[bool, str]:
    ipsec = shutil.which("ipsec") or "/usr/sbin/ipsec"
    if not Path(ipsec).exists():
        return False, "ipsec command is not installed"
    unit = _ipsec_unit()
    logs: list[str] = []

    if action == "start" and _strongswan_ready():
        return True, "charon is already running and listening on UDP 500/4500"
    if action == "start" and _process_running("charon", "charon-systemd"):
        # A daemon without both IKE listeners is a stale/degraded instance.
        action = "restart"

    if action in {"stop", "restart"}:
        result = subprocess.run([ipsec, "stop"], capture_output=True, text=True, timeout=60, check=False)
        logs.append(((result.stdout or "") + "\n" + (result.stderr or "")).strip())
        subprocess.run([SYSTEMCTL, "stop", "strongswan-starter", "strongswan"], capture_output=True, timeout=25, check=False)
        time.sleep(0.8)
        for name in ("charon", "charon-systemd", "starter"):
            if _process_running(name):
                subprocess.run(["/usr/bin/pkill", "-TERM", "-x", name], capture_output=True, timeout=8, check=False)
        time.sleep(0.8)
        for name in ("charon", "charon-systemd", "starter"):
            if _process_running(name):
                subprocess.run(["/usr/bin/pkill", "-KILL", "-x", name], capture_output=True, timeout=8, check=False)
        for pidfile in ("/run/charon.pid", "/var/run/charon.pid", "/run/starter.charon.pid", "/var/run/starter.charon.pid"):
            try:
                Path(pidfile).unlink(missing_ok=True)
            except OSError:
                pass
        if action == "stop":
            return not _process_running("charon", "charon-systemd"), "\n".join(logs)

    subprocess.run([SYSTEMCTL, "daemon-reload"], capture_output=True, timeout=15, check=False)
    subprocess.run([SYSTEMCTL, "reset-failed", unit], capture_output=True, timeout=10, check=False)
    subprocess.run([SYSTEMCTL, "enable", unit], capture_output=True, timeout=15, check=False)
    result = subprocess.run([SYSTEMCTL, "start", unit], capture_output=True, text=True, timeout=60, check=False)
    logs.append(((result.stdout or "") + "\n" + (result.stderr or "")).strip())
    deadline = time.monotonic() + 7
    while time.monotonic() < deadline and not _strongswan_ready():
        time.sleep(0.5)
    ready = _strongswan_ready()
    if not ready:
        logs.append(_last_error(unit))
    return bool(result.returncode == 0 and ready), "\n".join(x for x in logs if x)


def _control_xl2tpd(action: str, port: int) -> tuple[bool, str]:
    unit = "xl2tpd"
    logs: list[str] = []
    snapshot = _listener_snapshot()
    if action == "start" and _process_running("xl2tpd") and _listener_present(snapshot, "udp", port):
        return True, f"xl2tpd is already running on UDP {port}"

    if action in {"stop", "restart"}:
        result = subprocess.run([SYSTEMCTL, "stop", unit], capture_output=True, text=True, timeout=35, check=False)
        logs.append(((result.stdout or "") + "\n" + (result.stderr or "")).strip())
        time.sleep(0.5)
        if _process_running("xl2tpd"):
            subprocess.run(["/usr/bin/pkill", "-TERM", "-x", "xl2tpd"], capture_output=True, timeout=8, check=False)
            time.sleep(0.5)
        if _process_running("xl2tpd"):
            subprocess.run(["/usr/bin/pkill", "-KILL", "-x", "xl2tpd"], capture_output=True, timeout=8, check=False)
        for pidfile in ("/run/xl2tpd/xl2tpd.pid", "/var/run/xl2tpd/xl2tpd.pid", "/var/run/xl2tpd.pid"):
            try:
                Path(pidfile).unlink(missing_ok=True)
            except OSError:
                pass
        if action == "stop":
            return not _process_running("xl2tpd"), "\n".join(logs)

    subprocess.run([SYSTEMCTL, "reset-failed", unit], capture_output=True, timeout=10, check=False)
    subprocess.run([SYSTEMCTL, "enable", unit], capture_output=True, timeout=15, check=False)
    result = subprocess.run([SYSTEMCTL, "start", unit], capture_output=True, text=True, timeout=45, check=False)
    logs.append(((result.stdout or "") + "\n" + (result.stderr or "")).strip())
    deadline = time.monotonic() + 6
    ready = False
    while time.monotonic() < deadline:
        snapshot = _listener_snapshot()
        ready = _process_running("xl2tpd") and _listener_present(snapshot, "udp", port)
        if ready:
            break
        time.sleep(0.5)
    if not ready:
        logs.append(_last_error(unit))
    return bool(result.returncode == 0 and ready), "\n".join(x for x in logs if x)


def control_protocol(key: str, action: str, db: Session | None = None) -> tuple[bool, str]:
    specs = _protocol_specs()
    if key not in specs or action not in {"start", "stop", "restart"}:
        return False, "پروتکل یا عملیات نامعتبر است"
    logs: list[str] = []

    if key in {"vmess", "vless"} and action in {"start", "restart"}:
        ok, detail = _repair_xray_before_start(key)
        logs.append(f"$ Xray preflight {key}\n{detail}".strip())
        if not ok:
            return False, "\n\n".join(logs)[-5000:]

    if key in {"ipsec", "ikev2"}:
        ok, detail = _control_strongswan(action)
        logs.append(f"$ ipsec {action}\n{detail}".strip())
        return ok, "\n\n".join(logs)[-5000:]

    if key == "l2tp":
        if action in {"start", "restart"}:
            ok, detail = _control_strongswan("start")
            logs.append(f"$ ipsec start\n{detail}".strip())
            if not ok:
                return False, "\n\n".join(logs)[-5000:]
        try:
            port = _configured_port(db, "l2tp_port", 1701) if db is not None else 1701
        except (TypeError, ValueError):
            port = 1701
        ok, detail = _control_xl2tpd(action, port)
        logs.append(f"$ xl2tpd {action}\n{detail}".strip())
        if not ok:
            return False, "\n\n".join(logs)[-5000:]
        if action == "stop" or db is None:
            return True, "\n\n".join(logs)[-5000:]
        deadline = time.monotonic() + 7
        final = None
        while time.monotonic() < deadline:
            final = next((row for row in get_protocol_center(db) if row["key"] == key), None)
            if final and final["state"] in {"active", "failed", "degraded"}:
                break
            time.sleep(0.8)
        if not final or final["state"] != "active":
            logs.append(f"Runtime health: {final['state'] if final else 'unknown'}\n{(final or {}).get('last_error') or (final or {}).get('health')}")
            return False, "\n\n".join(logs)[-5000:]
        return True, "\n\n".join(logs)[-5000:]

    success = True
    for unit in specs[key].units:
        try:
            real_action = action
            result = subprocess.run([SYSTEMCTL, real_action, unit], capture_output=True, text=True, timeout=45, check=False)
            text = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
            logs.append(f"$ systemctl {real_action} {unit}\n{text}".strip())
            if result.returncode != 0:
                success = False
        except Exception as exc:
            success = False
            logs.append(f"$ systemctl {action} {unit}\n{exc}")

    if success and action != "stop" and db is not None:
        deadline = time.monotonic() + 7
        final = None
        while time.monotonic() < deadline:
            final = next((row for row in get_protocol_center(db) if row["key"] == key), None)
            if final and final["state"] in {"active", "failed", "degraded"}:
                break
            time.sleep(0.8)
        if final and final["state"] != "active":
            success = False
            logs.append(f"Runtime health: {final['state']}\n{final.get('last_error') or final.get('health')}")
    return success, "\n\n".join(logs)[-5000:]


_PROTOCOL_LOG_CLEAR_DIR = Path("/var/lib/vpn-panel/log-clear")
_PROTOCOL_FILE_LOGS = {
    "openvpn": (Path("/var/log/openvpn.log"),),
    "sstp": (Path("/var/log/accel-ppp/sstp.log"), Path("/var/log/accel-ppp/sstp-core.log")),
    "vmess": (Path("/var/log/vpn-panel/xray/vmess-access.log"), Path("/var/log/vpn-panel/xray/vmess-error.log")),
    "vless": (Path("/var/log/vpn-panel/xray/vless-access.log"), Path("/var/log/vpn-panel/xray/vless-error.log")),
}


def _protocol_log_clear_epoch(key: str) -> int | None:
    path = _PROTOCOL_LOG_CLEAR_DIR / f"{key}.epoch"
    try:
        value = int(path.read_text(encoding="utf-8").strip())
        return value if value > 0 else None
    except (OSError, ValueError):
        return None


def clear_protocol_logs(key: str) -> dict:
    """Clear one protocol log view without deleting unrelated system journals.

    systemd's journal cannot safely delete entries for only one unit. We store
    a per-protocol cutoff timestamp so the UI sees only new journal messages,
    and physically truncate only the exact dedicated log files owned by that
    protocol. Global syslog and other services remain untouched.
    """
    specs = _protocol_specs()
    if key not in specs:
        raise KeyError(key)
    _PROTOCOL_LOG_CLEAR_DIR.mkdir(parents=True, exist_ok=True)
    epoch = int(time.time())
    marker = _PROTOCOL_LOG_CLEAR_DIR / f"{key}.epoch"
    temporary = marker.with_suffix(f".tmp-{os.getpid()}")
    temporary.write_text(str(epoch) + "\n", encoding="utf-8")
    os.chmod(temporary, 0o600)
    os.replace(temporary, marker)

    truncated: list[str] = []
    for path in _PROTOCOL_FILE_LOGS.get(key, ()):
        try:
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode):
                continue
            with path.open("w", encoding="utf-8"):
                pass
            truncated.append(str(path))
        except FileNotFoundError:
            continue
        except OSError as exc:
            logger.warning("Could not clear protocol log %s: %s", path, exc)
    return {"key": key, "cleared_at": epoch, "truncated": truncated}


def protocol_logs(key: str, lines: int = 250) -> str:
    specs = _protocol_specs()
    if key not in specs:
        raise KeyError(key)
    lines = max(20, min(int(lines), 2000))
    chunks: list[str] = []
    for unit in specs[key].units:
        try:
            command = ["/usr/bin/journalctl", "-u", unit, "-n", str(lines), "--no-pager", "--output=short-iso"]
            cleared_after = _protocol_log_clear_epoch(key)
            if cleared_after:
                command.extend(["--since", f"@{cleared_after}"])
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            content = ((result.stdout or "") + ("\n" + result.stderr if result.stderr else "")).strip()
        except (OSError, subprocess.SubprocessError) as exc:
            content = f"journalctl unavailable: {exc}"
        chunks.append(f"===== {unit} =====\n{content or '(no log output)'}")

    for log_path in _PROTOCOL_FILE_LOGS.get(key, ()):
        path = str(log_path)
        if not log_path.is_file():
            continue
        try:
            content = subprocess.run(
                ["/usr/bin/tail", "-n", str(lines), path],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            ).stdout
            chunks.append(f"===== {path} =====\n{content.strip() or '(no matching lines)'}")
        except Exception:
            pass
    return "\n\n".join(chunks)[-300000:]


def get_protocol_config(key: str, file_id: str | None = None) -> dict:
    specs = _protocol_specs()
    if key not in specs:
        raise KeyError(key)
    files = specs[key].configs
    selected = next((item for item in files if item.id == file_id), None) if file_id else (files[0] if files else None)
    if selected is None:
        raise KeyError(file_id or "")
    path = Path(selected.path)
    content = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    return {
        "selected": selected.id,
        "content": content,
        "files": [
            {"id": item.id, "label": item.label, "path": item.path, "exists": Path(item.path).exists()}
            for item in files
        ],
    }


def save_protocol_config(key: str, file_id: str, content: str, restart: bool = True) -> tuple[bool, str]:
    specs = _protocol_specs()
    if key not in specs:
        return False, "پروتکل نامعتبر است"
    selected = next((item for item in specs[key].configs if item.id == file_id), None)
    if selected is None:
        return False, "فایل تنظیمات نامعتبر است"
    if "\x00" in content:
        return False, "محتوای تنظیمات دارای کاراکتر نامعتبر است"
    encoded = content.encode("utf-8")
    if len(encoded) > 1024 * 1024:
        return False, "حجم فایل تنظیمات بیشتر از ۱ مگابایت است"
    if not content.strip():
        return False, "فایل تنظیمات نمی‌تواند خالی باشد"
    missing = [marker for marker in selected.required_markers if marker not in content]
    if missing:
        return False, f"بخش ضروری زیر در تنظیمات پیدا نشد: {', '.join(missing)}"

    path = Path(selected.path)
    path.parent.mkdir(parents=True, exist_ok=True)
    backup: Path | None = None
    original_mode = 0o600
    if path.exists():
        original_mode = stat.S_IMODE(path.stat().st_mode)
        backup = path.with_name(f"{path.name}.vpnpanel.bak.{datetime.utcnow().strftime('%Y%m%d%H%M%S')}")
        shutil.copy2(path, backup)

    temp = path.with_name(f".{path.name}.vpnpanel.tmp.{os.getpid()}")
    try:
        temp.write_bytes(encoded)
        os.chmod(temp, original_mode)
        os.replace(temp, path)
        if key in {"vmess", "vless"}:
            from app.services.xray_manager import ensure_runtime_permissions, validate_config
            ensure_runtime_permissions(key)
            try:
                import json
                json.loads(content)
            except Exception as exc:
                if backup and backup.exists():
                    shutil.copy2(backup, path)
                else:
                    path.unlink(missing_ok=True)
                return False, f"JSON نامعتبر است: {exc}"
            binary = shutil.which("xray") or ("/usr/local/bin/xray" if Path("/usr/local/bin/xray").is_file() else None)
            if not binary:
                if backup and backup.exists():
                    shutil.copy2(backup, path)
                else:
                    path.unlink(missing_ok=True)
                return False, "هسته Xray نصب نشده است"
            valid, validation_output = validate_config(path)
            if not valid:
                if backup and backup.exists():
                    shutil.copy2(backup, path)
                else:
                    path.unlink(missing_ok=True)
                return False, "اعتبارسنجی Xray ناموفق بود: " + validation_output[-1500:]
        if restart:
            ok, log = control_protocol(key, "restart")
            if not ok:
                if backup and backup.exists():
                    shutil.copy2(backup, path)
                else:
                    # Saving a brand-new file must be transactional too.  Leaving
                    # a known-bad file behind would make the next install/restart
                    # fail again even though the UI reported a rollback.
                    path.unlink(missing_ok=True)
                control_protocol(key, "restart")
                return False, f"سرویس با تنظیمات جدید بالا نیامد؛ فایل قبلی بازگردانی شد.\n{log}"
        return True, str(backup) if backup else ""
    finally:
        try:
            temp.unlink(missing_ok=True)
        except Exception:
            pass


# ---------------------------- install jobs ---------------------------------
_INSTALL_LOCK = threading.Lock()
_INSTALL_JOBS: dict[str, dict] = {}
_MAX_JOB_LINES = 3000
_INSTALL_PROGRESS_RE = re.compile(
    r"^\[(\d{1,3})%\]\s+(?:=====|Full VPN provisioning started|Running combined protocol-center verification|FULL_PROVISION_OK)",
    re.MULTILINE,
)


def _append_job(job_id: str, line: str) -> None:
    with _INSTALL_LOCK:
        job = _INSTALL_JOBS.get(job_id)
        if not job:
            return
        clean_line = line.rstrip("\n")
        job["lines"].append(clean_line)
        if len(job["lines"]) > _MAX_JOB_LINES:
            job["lines"] = job["lines"][-_MAX_JOB_LINES:]
        match = _INSTALL_PROGRESS_RE.search(clean_line)
        if match:
            detected = max(0, min(100, int(match.group(1))))
            # 100% is reserved for a process that has actually exited with code 0.
            # Old/nested installer output sometimes printed 100 before the outer
            # all-protocol job was finished, which made the UI jump backward.
            if detected >= 100 and job.get("state") != "success":
                detected = 99
            current = job.get("progress")
            job["progress"] = max(int(current or 0), detected)
        job["updated_at"] = time.time()


def _run_install_job(job_id: str, key: str, args: list[str]) -> None:
    with _INSTALL_LOCK:
        _INSTALL_JOBS[job_id]["state"] = "running"
        _INSTALL_JOBS[job_id]["started_at"] = time.time()
    command = [BASH, "/opt/vpn-panel/scripts/install_protocol.sh", key, *args]
    _append_job(job_id, "$ " + " ".join(command))
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        assert process.stdout is not None
        for line in process.stdout:
            _append_job(job_id, line)
        returncode = process.wait(timeout=5400 if key == "all" else 1800)
        with _INSTALL_LOCK:
            job = _INSTALL_JOBS[job_id]
            job["returncode"] = returncode
            job["state"] = "success" if returncode == 0 else "failed"
            if returncode == 0:
                job["progress"] = 100
                if key == "all":
                    try:
                        from app.database import SessionLocal
                        from app.models import Setting
                        db = SessionLocal()
                        try:
                            row = db.query(Setting).filter(Setting.key == "local_services_mode").first()
                            if row:
                                row.value = "1"
                            else:
                                db.add(Setting(key="local_services_mode", value="1"))
                            db.commit()
                        finally:
                            db.close()
                    except Exception:
                        logger.exception("Failed to persist local service installation mode")
            job["finished_at"] = time.time()
    except Exception as exc:
        _append_job(job_id, f"ERROR: {exc}")
        with _INSTALL_LOCK:
            job = _INSTALL_JOBS[job_id]
            job["returncode"] = -1
            job["state"] = "failed"
            job["finished_at"] = time.time()


def start_install_job(key: str, args: list[str] | None = None) -> str:
    allowed = set(_protocol_specs()) | {"infrastructure", "all"}
    if key not in allowed:
        raise KeyError(key)
    job_id = uuid.uuid4().hex
    with _INSTALL_LOCK:
        active = next(
            (job for job in _INSTALL_JOBS.values() if job.get("state") in {"queued", "running"}),
            None,
        )
        if active:
            # apt/dpkg and systemd repair scripts must not run concurrently.  Apart
            # from apt lock contention, two installers could overwrite the same
            # configuration and restart shared services (notably strongSwan).
            raise RuntimeError(
                f"یک عملیات نصب/ترمیم دیگر برای {active.get('key', 'service')} در حال اجرا است"
            )
        _INSTALL_JOBS[job_id] = {
            "id": job_id,
            "key": key,
            "state": "queued",
            "lines": [],
            "created_at": time.time(),
            "updated_at": time.time(),
            "returncode": None,
            "progress": 0 if key == "all" else None,
        }
    thread = threading.Thread(target=_run_install_job, args=(job_id, key, args or []), daemon=True)
    thread.start()
    return job_id


def get_install_job(job_id: str) -> dict | None:
    with _INSTALL_LOCK:
        job = _INSTALL_JOBS.get(job_id)
        if not job:
            return None
        return {**job, "output": "\n".join(job["lines"])}


def _kernel_module_available(module: str, loaded: set[str]) -> bool:
    """Return True for loaded, built-in, or loadable kernel modules.

    /proc/modules only lists dynamically loaded modules.  Common VPN modules
    such as ``tun`` and ``ppp_generic`` may be compiled directly into the
    kernel, so marking them missing based only on /proc/modules produces a
    false red status even though the protocol works.  /sys/module covers both
    loaded and built-in modules; modprobe -n verifies that a packaged module is
    available without mutating the system.
    """
    normalized = module.replace("-", "_")
    if normalized in loaded or Path(f"/sys/module/{normalized}").exists():
        return True
    modprobe = shutil.which("modprobe")
    if not modprobe:
        return False
    try:
        result = subprocess.run(
            [modprobe, "-n", "-q", module],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=5,
            check=False,
        )
        return result.returncode == 0
    except Exception:
        return False


def infrastructure_status() -> dict:
    ip_forward = "0"
    try:
        ip_forward = Path("/proc/sys/net/ipv4/ip_forward").read_text().strip()
    except Exception:
        pass

    firewall = "none"
    if shutil.which("ufw") and "Status: active" in _run_text(("ufw", "status"), timeout=8):
        firewall = "ufw"
    elif shutil.which("firewall-cmd") and "running" in _run_text(("firewall-cmd", "--state"), timeout=8):
        firewall = "firewalld"
    elif shutil.which("iptables"):
        firewall = "iptables"

    modules = [
        "ppp_generic", "l2tp_ppp", "nf_conntrack_pptp", "ip_gre", "ppp_mppe",
        "tun", "af_key", "esp4", "xfrm_user",
    ]
    loaded: set[str] = set()
    try:
        for line in Path("/proc/modules").read_text().splitlines():
            loaded.add(line.split()[0].replace("-", "_"))
    except Exception:
        pass
    return {
        "ip_forwarding": ip_forward == "1",
        "firewall": firewall,
        "nftables": shutil.which("nft") is not None,
        "iproute2": shutil.which("ip") is not None,
        "modules": {module: _kernel_module_available(module, loaded) for module in modules},
    }
