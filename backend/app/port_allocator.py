from __future__ import annotations

import json
import re
import secrets
import socket
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from app.database import SessionLocal
from app.models import OpenvpnExtraPort, Setting

SS = "/usr/bin/ss"
SYSTEMCTL = "/usr/bin/systemctl"


@dataclass(frozen=True)
class PortRequest:
    setting_key: str
    transport: str
    default: int
    allowed_processes: tuple[str, ...]
    service_units: tuple[str, ...] = ()


REQUESTS: dict[str, tuple[PortRequest, ...]] = {
    "l2tp": (PortRequest("l2tp_port", "udp", 1701, ("xl2tpd",), ("xl2tpd",)),),
    "openvpn": (
        PortRequest("openvpn_udp_port", "udp", 1194, ("openvpn",), ("openvpn-server@server-udp", "openvpn@server-udp")),
        PortRequest("openvpn_tcp_port", "tcp", 1194, ("openvpn",), ("openvpn-server@server-tcp", "openvpn@server-tcp")),
    ),
    "openconnect": (
        PortRequest("openconnect_port", "both", 8443, ("ocserv-main", "ocserv-worker", "ocserv"), ("ocserv",)),
    ),
    "sstp": (PortRequest("sstp_port", "tcp", 4433, ("accel-pppd",), ("accel-ppp-sstp",)),),
    "vmess": (PortRequest("vmess_port", "tcp", 10000, ("xray",), ("vpn-panel-xray-vmess",)),),
    "vless": (PortRequest("vless_port", "tcp", 10001, ("xray",), ("vpn-panel-xray-vless",)),),
}

FIXED_PROTOCOLS = {
    "pptp": {
        "message": "PPTP uses the client-standard TCP/1723 and GRE and cannot be moved transparently.",
        "requests": (PortRequest("pptp_fixed_port", "tcp", 1723, ("pptpd",), ("pptpd",)),),
    },
    "ipsec": {
        "message": "IPsec/IKE uses client-standard UDP/500 and UDP/4500 and cannot be moved transparently.",
        "requests": (
            PortRequest("ipsec_ike_port", "udp", 500, ("charon", "charon-systemd", "starter"), ("strongswan-starter", "strongswan", "strongswan-swanctl")),
            PortRequest("ipsec_natt_port", "udp", 4500, ("charon", "charon-systemd", "starter"), ("strongswan-starter", "strongswan", "strongswan-swanctl")),
        ),
    },
    "ikev2": {
        "message": "IKEv2 uses client-standard UDP/500 and UDP/4500 and cannot be moved transparently.",
        "requests": (
            PortRequest("ikev2_ike_port", "udp", 500, ("charon", "charon-systemd", "starter"), ("strongswan-starter", "strongswan", "strongswan-swanctl")),
            PortRequest("ikev2_natt_port", "udp", 4500, ("charon", "charon-systemd", "starter"), ("strongswan-starter", "strongswan", "strongswan-swanctl")),
        ),
    },
}


def _get(db, key: str, default: str) -> str:
    row = db.query(Setting).filter(Setting.key == key).first()
    return row.value if row and row.value is not None else default


def _set(db, key: str, value: str) -> None:
    row = db.query(Setting).filter(Setting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(Setting(key=key, value=value))


def _bool(db, key: str, default: bool) -> bool:
    raw = _get(db, key, "1" if default else "0")
    return raw == "1"


def _int(db, key: str, default: int) -> int:
    try:
        return int(_get(db, key, str(default)))
    except (TypeError, ValueError):
        return default


def _unit_pids(units: Iterable[str]) -> set[int]:
    """Return every PID owned by the supplied systemd units.

    MainPID alone is insufficient for services such as strongSwan: systemd
    tracks the starter process as MainPID while UDP/500 and UDP/4500 are bound
    by its child `charon`.  Read the complete unit cgroup so child listeners are
    recognised as panel-owned instead of being reported as external conflicts.
    """
    result: set[int] = set()
    for unit in units:
        try:
            proc = subprocess.run(
                [SYSTEMCTL, "show", unit, "--property=MainPID,ControlGroup", "--value"],
                capture_output=True, text=True, timeout=4, check=False,
            )
            values = [line.strip() for line in (proc.stdout or "").splitlines()]
            if values:
                try:
                    pid = int(values[0] or 0)
                    if pid > 0:
                        result.add(pid)
                except (TypeError, ValueError):
                    pass
            control_group = values[1] if len(values) > 1 else ""
            if control_group:
                root = Path("/sys/fs/cgroup") / control_group.lstrip("/")
                if root.is_dir():
                    for procs_file in [root / "cgroup.procs", *root.rglob("cgroup.procs")]:
                        try:
                            for raw in procs_file.read_text(encoding="utf-8", errors="ignore").split():
                                pid = int(raw)
                                if pid > 0:
                                    result.add(pid)
                        except (OSError, TypeError, ValueError):
                            pass
        except Exception:
            pass
    return result


def _unit_active(units: Iterable[str]) -> bool:
    for unit in units:
        try:
            proc = subprocess.run(
                [SYSTEMCTL, "is-active", "--quiet", unit],
                timeout=4, check=False,
            )
            if proc.returncode == 0:
                return True
        except Exception:
            pass
    return False


def _listeners() -> list[dict]:
    try:
        proc = subprocess.run([SS, "-H", "-lntup"], capture_output=True, text=True, timeout=8, check=False)
        text = proc.stdout or ""
    except Exception:
        text = ""
    rows: list[dict] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        transport = parts[0].lower()
        local = parts[4]
        match = re.search(r"(?:\]|:)(\d+)$", local)
        if not match:
            continue
        names = set(re.findall(r'\("([^\"]+)"', line))
        pids = {int(value) for value in re.findall(r"pid=(\d+)", line)}
        rows.append({"transport": transport, "port": int(match.group(1)), "names": names, "pids": pids, "line": line})
    return rows


def _occupants(rows: list[dict], transport: str, port: int) -> list[dict]:
    transports = {"tcp", "udp"} if transport == "both" else {transport}
    return [row for row in rows if row["transport"] in transports and row["port"] == port]


def _bind_available(transport: str, port: int) -> bool:
    protocols = ("tcp", "udp") if transport == "both" else (transport,)
    sockets = []
    try:
        for proto in protocols:
            kind = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
            sock = socket.socket(socket.AF_INET, kind)
            sockets.append(sock)
            sock.bind(("0.0.0.0", int(port)))
        return True
    except OSError:
        return False
    finally:
        for sock in sockets:
            try:
                sock.close()
            except OSError:
                pass


def _is_own(rows: list[dict], request: PortRequest, port: int) -> bool:
    matches = _occupants(rows, request.transport, port)
    if not matches:
        return False
    unit_pids = _unit_pids(request.service_units)
    if unit_pids and all(bool(unit_pids.intersection(row["pids"])) for row in matches):
        return True

    # strongSwan's systemd MainPID is commonly `starter`, while the sockets are
    # held by child `charon`.  Some distributions do not expose every child in
    # MainPID and may briefly hide cgroup membership during a restart.  If an
    # expected strongSwan unit is active and every listener identifies itself
    # as charon/charon-systemd, it is our own standard IKE listener.
    allowed = set(request.allowed_processes)
    names_match = all(bool(row["names"]) and row["names"].issubset(allowed) for row in matches)
    strongswan_listener = bool(allowed.intersection({"charon", "charon-systemd", "starter"}))
    if strongswan_listener and names_match and _unit_active(request.service_units):
        return True

    # Process-name-only matching is unsafe for multi-instance daemons such as
    # Xray/OpenVPN.  Keep their ownership check strictly PID/cgroup based.
    if request.allowed_processes in {("xray",), ("openvpn",)}:
        return False
    return names_match


def _configured_ports(db, exclude_keys: set[str]) -> set[tuple[str, int]]:
    pairs: set[tuple[str, int]] = set()
    mapping = (
        ("panel_port", "tcp", 80),
        ("sub_domain_port", "tcp", 443),
        ("l2tp_port", "udp", 1701),
        ("openvpn_udp_port", "udp", 1194),
        ("openvpn_tcp_port", "tcp", 1194),
        ("openconnect_port", "both", 8443),
        ("sstp_port", "tcp", 4433),
        ("vmess_port", "tcp", 10000),
        ("vless_port", "tcp", 10001),
    )
    for key, transport, default in mapping:
        if key in exclude_keys:
            continue
        port = _int(db, key, default)
        if transport == "both":
            pairs.add(("tcp", port)); pairs.add(("udp", port))
        else:
            pairs.add((transport, port))
    pairs.update({("udp", 500), ("udp", 4500), ("tcp", 1723)})
    for item in db.query(OpenvpnExtraPort).filter(OpenvpnExtraPort.is_active == True).all():  # noqa: E712
        if item.protocol in {"tcp", "both"}:
            pairs.add(("tcp", int(item.port)))
        if item.protocol in {"udp", "both"}:
            pairs.add(("udp", int(item.port)))
    return pairs


def _replace_port_line(path: str, expression: str, replacement: str) -> None:
    target = Path(path)
    if not target.is_file():
        return
    try:
        content = target.read_text(encoding="utf-8", errors="replace")
        updated, count = re.subn(expression, replacement, content, count=1, flags=re.MULTILINE)
        if count:
            target.write_text(updated, encoding="utf-8")
    except OSError:
        pass


def _patch_existing_config(protocol: str, setting_key: str, new_port: int) -> None:
    # Core installers may restart an existing daemon before the later database
    # synchronisation step. Patch only its managed listener line now so that
    # the repair does not fail on the old occupied port. The full renderer runs
    # immediately afterwards and remains the authoritative configuration.
    if protocol == "l2tp":
        _replace_port_line(
            "/etc/xl2tpd/xl2tpd.conf",
            r"^[ \t]*port[ \t]*=[ \t]*\d+[ \t]*$",
            f"port = {new_port}",
        )
    elif protocol == "openvpn" and setting_key == "openvpn_udp_port":
        _replace_port_line("/etc/openvpn/server/server-udp.conf", r"^[ \t]*port[ \t]+\d+[ \t]*$", f"port {new_port}")
    elif protocol == "openvpn" and setting_key == "openvpn_tcp_port":
        _replace_port_line("/etc/openvpn/server/server-tcp.conf", r"^[ \t]*port[ \t]+\d+[ \t]*$", f"port {new_port}")


def _candidate_free(rows: list[dict], configured: set[tuple[str, int]], transport: str, port: int) -> bool:
    transports = ("tcp", "udp") if transport == "both" else (transport,)
    return (
        all(not _occupants(rows, proto, port) and (proto, port) not in configured for proto in transports)
        and _bind_available(transport, port)
    )


def _choose(rows: list[dict], configured: set[tuple[str, int]], transport: str, minimum: int, maximum: int) -> int:
    rng = secrets.SystemRandom()
    span = maximum - minimum + 1
    for _ in range(min(span, 5000)):
        candidate = minimum + rng.randrange(span)
        if _candidate_free(rows, configured, transport, candidate):
            return candidate
    for candidate in range(minimum, maximum + 1):
        if _candidate_free(rows, configured, transport, candidate):
            return candidate
    raise RuntimeError(f"no free port found in range {minimum}-{maximum}")


def resolve(protocol: str) -> dict:
    db = SessionLocal()
    try:
        if protocol in FIXED_PROTOCOLS:
            definition = FIXED_PROTOCOLS[protocol]
            rows = _listeners()
            blocked = []
            for request in definition["requests"]:
                matches = _occupants(rows, request.transport, request.default)
                if not matches and not _bind_available(request.transport, request.default):
                    matches = [{"names": set(), "pids": set(), "transport": request.transport, "port": request.default}]
                if matches and not _is_own(rows, request, request.default):
                    blocked.append({
                        "transport": request.transport,
                        "port": request.default,
                        "owner": ", ".join(sorted({name for row in matches for name in row["names"]})) or "unknown process",
                        "owner_pids": sorted({pid for row in matches for pid in row["pids"]}),
                        "reason": definition["message"],
                    })
            notice_key = f"protocol_port_notice_{protocol}"
            if blocked:
                _set(db, notice_key, json.dumps({
                    "protocol": protocol,
                    "fixed": True,
                    "blocked": blocked,
                    "created_at": datetime.now(timezone.utc).isoformat(),
                }, ensure_ascii=False))
                db.commit()
            else:
                row = db.query(Setting).filter(Setting.key == notice_key).first()
                if row and '"blocked"' in (row.value or ""):
                    row.value = ""
                    db.commit()
            return {
                "protocol": protocol, "changed": [], "fixed": True,
                "message": definition["message"], "blocked": blocked,
            }
        requests = REQUESTS.get(protocol, ())
        if not requests:
            return {"protocol": protocol, "changed": [], "fixed": False}
        if not _bool(db, "auto_port_fallback_enabled", True):
            return {"protocol": protocol, "changed": [], "disabled": True}

        minimum = max(1024, _int(db, "auto_port_fallback_min", 20000))
        maximum = min(65535, _int(db, "auto_port_fallback_max", 55000))
        if minimum > maximum:
            minimum, maximum = 20000, 55000

        rows = _listeners()
        exclude = {request.setting_key for request in requests}
        configured = _configured_ports(db, exclude)
        changes = []
        for request in requests:
            old_port = _int(db, request.setting_key, request.default)
            transports = ("tcp", "udp") if request.transport == "both" else (request.transport,)
            occupants = _occupants(rows, request.transport, old_port)
            if not occupants and not _bind_available(request.transport, old_port):
                occupants = [{"names": set(), "pids": set(), "transport": request.transport, "port": old_port}]
            configured_conflict = any((proto, old_port) in configured for proto in transports)
            if not configured_conflict and (not occupants or _is_own(rows, request, old_port)):
                # Reserve the port for the next field in this same protocol.
                configured.update((proto, old_port) for proto in transports)
                continue
            new_port = _choose(rows, configured, request.transport, minimum, maximum)
            transports = ("tcp", "udp") if request.transport == "both" else (request.transport,)
            configured.update((proto, new_port) for proto in transports)
            owner_names = sorted({name for row in occupants for name in row["names"]})
            owner_pids = sorted({pid for row in occupants for pid in row["pids"]})
            if configured_conflict and not owner_names:
                owner_names = ["another configured panel listener"]
            _set(db, request.setting_key, str(new_port))
            _patch_existing_config(protocol, request.setting_key, new_port)
            changes.append({
                "setting": request.setting_key,
                "transport": request.transport,
                "old_port": old_port,
                "new_port": new_port,
                "owner": ", ".join(owner_names) or "unknown process",
                "owner_pids": owner_pids,
                "warning": "Native clients must use the new custom port." if protocol == "l2tp" else "",
            })
        if changes:
            notice = {
                "protocol": protocol,
                "changed": changes,
                "created_at": datetime.now(timezone.utc).isoformat(),
            }
            _set(db, f"protocol_port_notice_{protocol}", json.dumps(notice, ensure_ascii=False))
            db.commit()
        return {"protocol": protocol, "changed": changes, "fixed": False}
    finally:
        db.close()


def main() -> int:
    protocol = (sys.argv[1] if len(sys.argv) > 1 else "").strip().lower()
    try:
        result = resolve(protocol)
    except Exception as exc:
        print(f"[port] Automatic port preflight failed: {exc}", file=sys.stderr)
        return 2
    if result.get("fixed"):
        if result.get("blocked"):
            for conflict in result["blocked"]:
                pids = ",".join(str(pid) for pid in conflict.get("owner_pids", []))
                suffix = f" (pid {pids})" if pids else ""
                print(
                    f"[port] ERROR: required {conflict['transport'].upper()}/{conflict['port']} is occupied by "
                    f"{conflict['owner']}{suffix}. {conflict['reason']}",
                    file=sys.stderr,
                )
            return 3
        print(f"[port] Standard listener ports are free or already owned by this protocol. {result['message']}")
    elif result.get("disabled"):
        print("[port] Automatic fallback is disabled in Settings.")
    elif result.get("changed"):
        for change in result["changed"]:
            print(
                f"[port] {change['old_port']}/{change['transport'].upper()} was occupied by "
                f"{change['owner']}; selected free port {change['new_port']} instead."
            )
            if change.get("warning"):
                print(f"[port] WARNING: {change['warning']}")
    else:
        print("[port] Requested protocol ports are available (or already owned by this protocol).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
