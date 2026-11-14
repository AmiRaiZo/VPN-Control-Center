from __future__ import annotations

import base64
import grp
import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid
from datetime import date, datetime, timedelta
from pathlib import Path
from typing import Iterable
from urllib.parse import quote

from sqlalchemy.orm import Session

from app.config import get_settings
from app.models import BannedIP, ConnectionLog, Setting, VpnUser, XrayUsageCounter
from app.services.server_targets import user_selected_for_local, local_assignment_enabled
from app.services.rate_limiter import user_rate_mark
from app.services.user_lifecycle import ensure_first_connect

XRAY_BINARY = os.environ.get("XRAY_BINARY", "/usr/local/bin/xray")
XRAY_ROOT = Path(os.environ.get("XRAY_CONFIG_ROOT", "/etc/vpn-panel/xray"))
XRAY_LOG_ROOT = Path(os.environ.get("XRAY_LOG_ROOT", "/var/log/vpn-panel/xray"))
PROTOCOLS = ("vmess", "vless")
API_PORTS = {"vmess": 10085, "vless": 10086}
UNITS = {"vmess": "vpn-panel-xray-vmess", "vless": "vpn-panel-xray-vless"}
XRAY_ACTIVITY_GRACE_SECONDS = max(2, int(os.environ.get("XRAY_ACTIVITY_GRACE_SECONDS", "5")))
XRAY_FORCED_DISCONNECT_SUPPRESS_SECONDS = max(5, int(os.environ.get("XRAY_FORCED_DISCONNECT_SUPPRESS_SECONDS", "5")))
# Two consecutive presence misses are required before a row becomes offline.
# The dedicated fast pass runs every two seconds, so normal disconnects are
# retired in roughly four seconds without treating idle traffic as offline.
XRAY_PRESENCE_FAILURE_LIMIT = max(2, int(os.environ.get("XRAY_PRESENCE_FAILURE_LIMIT", "2")))
# A lightweight stats-only pass runs every two seconds. Two misses therefore
# retire a disconnected VMess/VLESS session in roughly four seconds without
# waiting for the heavier traffic/accounting reconciliation.
XRAY_FAST_PRESENCE_INTERVAL_SECONDS = max(1, int(os.environ.get("XRAY_FAST_PRESENCE_INTERVAL_SECONDS", "4")))
# Source TCP ports are per-stream, not per-device. A single Xray client can
# open many ephemeral ports, so using them as device identities creates phantom
# sessions and breaks max_devices. Keep the old environment variable ignored
# for backward compatibility with existing .env files.
XRAY_STRICT_SAME_NAT = False

# Xray online stats and kernel sockets can remain visible for a few seconds
# after an administrator terminates a session. Keep a short in-process tombstone
# so the next 4-second poll cannot recreate the just-closed ConnectionLog from
# stale stats. A genuine reconnect appears again after the short window.
_FORCED_DISCONNECT_UNTIL: dict[tuple[int, str, str], float] = {}
_LAST_RATE_CONFIG_VERIFY = 0.0
_XRAY_SAMPLE_LOCK = threading.Lock()
_MAX_DEVICE_RULES_KEY = "xray_max_device_rules_v1"
_MAX_DEVICE_DESIRED_RULES_KEY = "xray_max_device_desired_rules_v1"
_MAX_DEVICE_LEASES_KEY = "xray_device_leases_v1"
_MAX_DEVICE_STATE_KEY = "xray_connection_admission_v8"
_MAX_DEVICE_RULE_PIDS: dict[str, int] = {}
_MAX_DEVICE_RULES_INITIALIZED = False
_XRAY_LIVE_COUNTS: dict[tuple[int, str], int] = {}
# Direct TCP/WS peers keyed by user/protocol. Source ports remain diagnostic
# only; one protocol+public-IP is one Xray tunnel. Sibling VMess/VLESS tunnels
# from the same public IP may both consume slots when max_devices permits it.
_XRAY_LIVE_ENDPOINTS: dict[tuple[int, str], list[tuple[str, int | None, datetime]]] = {}
# Cache which CLI variant works on the installed Xray build. Unsupported
# per-user online APIs are retried only periodically so one missing command
# cannot stall the four-second monitor for every account.
_XRAY_API_VARIANTS: dict[tuple[str, str], int] = {}
_XRAY_API_RETRY_AFTER: dict[tuple[str, str], float] = {}
_XRAY_STATS_SUPPORTED: dict[str, bool] = {}
# Fast stats sampler remembers the last cumulative byte total per identity so
# an actively-used tunnel does not flip to "idle" between the heavier five-
# second accounting passes.
_XRAY_FAST_TRAFFIC_TOTALS: dict[tuple[int, str], int] = {}
# A latency/config test is a real but usually one-shot Xray request. Publishing
# it immediately as an online VPN session starts first-connect expiry, paints a
# green dot and can leave a ghost row when the client keeps its probe transport
# open. New identities therefore remain in a lightweight in-memory candidate
# state until the same user/IP produces *subsequent* traffic or another access
# event. Already-confirmed sessions still remain visible while their exact
# transport socket is established, even when idle.
_XRAY_PENDING_ENDPOINTS: dict[tuple[int, str, str], dict[str, object]] = {}
# The candidate must still produce traffic after this debounce window. A
# one-shot latency test normally finishes inside the window, even when the
# client keeps its transport socket pooled afterwards.
XRAY_ONLINE_CONFIRM_SECONDS = max(
    5.0, float(os.environ.get("XRAY_ONLINE_CONFIRM_SECONDS", "8"))
)
XRAY_PENDING_ENDPOINT_TTL_SECONDS = max(
    20, int(os.environ.get("XRAY_PENDING_ENDPOINT_TTL_SECONDS", "45"))
)
# The full and fast samplers use separate scheduler locks. Serialize shared
# max-device enforcement so two concurrent passes cannot replace each other
#'s nftables/routing state.
_XRAY_MAX_DEVICE_LOCK = threading.Lock()
_MAX_DEVICE_NFT_TABLE = "vpn_panel_xray_devices"
_MAX_DEVICE_NFT_SIGNATURE: str | None = None
logger = logging.getLogger("vpn-panel.xray")


def _remember_forced_disconnect(user_id: int, protocol: str, ip_address: str | None) -> None:
    now = time.monotonic()
    normalized = _normalize_ip(ip_address or "") if ip_address else None
    if normalized:
        _FORCED_DISCONNECT_UNTIL[(int(user_id), protocol, normalized)] = now + XRAY_FORCED_DISCONNECT_SUPPRESS_SECONDS
        # Short wildcard covers Xray builds that briefly report online=1 but do
        # not expose the source IP immediately after the termination call.
        _FORCED_DISCONNECT_UNTIL[(int(user_id), protocol, "*")] = now + min(4, XRAY_FORCED_DISCONNECT_SUPPRESS_SECONDS)
    else:
        _FORCED_DISCONNECT_UNTIL[(int(user_id), protocol, "*")] = now + XRAY_FORCED_DISCONNECT_SUPPRESS_SECONDS


def _forced_disconnect_suppressed(user_id: int, protocol: str, ips: Iterable[str] | None = None) -> bool:
    now = time.monotonic()
    for key, expires in list(_FORCED_DISCONNECT_UNTIL.items()):
        if expires <= now:
            _FORCED_DISCONNECT_UNTIL.pop(key, None)
    if _FORCED_DISCONNECT_UNTIL.get((int(user_id), protocol, "*"), 0) > now:
        return True
    for raw in ips or ():
        normalized = _normalize_ip(raw or "")
        if normalized and _FORCED_DISCONNECT_UNTIL.get((int(user_id), protocol, normalized), 0) > now:
            return True
    return False


def _rate_limited(user: VpnUser) -> bool:
    return int(getattr(user, "download_limit_mbps", 0) or 0) > 0 or int(getattr(user, "upload_limit_mbps", 0) or 0) > 0


def _build_outbound(settings: dict, tag: str, mark: int | None = None) -> dict:
    if settings["external_proxy_enabled"]:
        outbound: dict = {
            "tag": tag,
            "protocol": "socks",
            "settings": {
                "servers": [{
                    "address": settings["external_proxy_address"],
                    "port": settings["external_proxy_port"],
                }]
            },
        }
    else:
        outbound = {"tag": tag, "protocol": "freedom", "settings": {}}
    if mark is not None:
        # Xray applies this SO_MARK to the user's internet-side sockets. The
        # isolated nftables rate table then enforces aggregate upload/download
        # limits for VMess/VLESS without changing the shared listener port.
        outbound["streamSettings"] = {"sockopt": {"mark": int(mark)}}
    return outbound


def ensure_xray_rate_limit_capability() -> bool:
    """Allow Xray's dedicated service account to set SO_MARK safely.

    A systemd drop-in is used instead of editing the main unit, so protocol
    repair and future updates keep the setting deterministic.
    """
    content = (
        "[Service]\n"
        "AmbientCapabilities=\n"
        "AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_NET_ADMIN\n"
        "CapabilityBoundingSet=\n"
        "CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_NET_ADMIN\n"
    )
    changed = False
    for unit in UNITS.values():
        if not Path(f"/etc/systemd/system/{unit}.service").exists():
            continue
        root = Path(f"/etc/systemd/system/{unit}.service.d")
        root.mkdir(parents=True, exist_ok=True)
        target = root / "rate-limit.conf"
        if not target.exists() or target.read_text(encoding="utf-8", errors="ignore") != content:
            target.write_text(content, encoding="utf-8")
            os.chmod(target, 0o644)
            changed = True
    if changed:
        subprocess.run(["/usr/bin/systemctl", "daemon-reload"], capture_output=True, text=True, timeout=20, check=False)
    return changed


def _service_has_cap_net_admin(protocol: str) -> bool:
    """Check the live Xray process, not just the systemd unit text."""
    unit = UNITS.get(protocol)
    if not unit:
        return False
    try:
        result = subprocess.run(
            ["/usr/bin/systemctl", "show", unit, "-p", "MainPID", "--value"],
            capture_output=True, text=True, timeout=8, check=False,
        )
        pid = int((result.stdout or "0").strip() or 0)
        if result.returncode != 0 or pid <= 0:
            return False
        status = Path(f"/proc/{pid}/status").read_text(encoding="utf-8", errors="ignore")
        match = re.search(r"^CapEff:\s*([0-9A-Fa-f]+)$", status, re.M)
        if not match:
            return False
        # CAP_NET_ADMIN is Linux capability number 12.
        return bool(int(match.group(1), 16) & (1 << 12))
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return False


def _xray_identity() -> tuple[int, int] | None:
    """Return the dedicated service uid/gid when it exists."""
    try:
        import pwd
        account = pwd.getpwnam("vpn-xray")
        return account.pw_uid, account.pw_gid
    except (KeyError, ImportError):
        return None


def ensure_runtime_permissions(protocol: str | None = None) -> None:
    """Make generated Xray files readable by the systemd service account.

    ``/etc/vpn-panel`` is shared by the unprivileged OpenVPN hooks and the
    dedicated ``vpn-xray`` service.  Older releases changed the parent
    directory group to OpenVPN's drop group and mode 0750.  That made the
    Xray files themselves look correct (``root:vpn-xray 0640``) while the
    service still could not traverse the parent directory.

    Keep the shared parent execute-only (0711) and protect every child with
    its own owner/group.  The directory cannot be listed by service users, but
    both OpenVPN and Xray can reach their explicitly permitted files.
    """
    identities = _xray_identity()
    targets = (protocol,) if protocol in PROTOCOLS else PROTOCOLS
    shared_parent = XRAY_ROOT.parent
    shared_parent.mkdir(parents=True, exist_ok=True)
    if shared_parent.name == "vpn-panel":
        try:
            os.chown(shared_parent, 0, 0)
            os.chmod(shared_parent, 0o711)
        except OSError as exc:
            logger.warning("could not repair shared runtime parent %s: %s", shared_parent, exc)
    XRAY_ROOT.mkdir(parents=True, exist_ok=True)
    XRAY_LOG_ROOT.mkdir(parents=True, exist_ok=True)
    uid_gid = identities
    for proto in targets:
        root = XRAY_ROOT / proto
        root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(root, 0o750)
            if uid_gid:
                os.chown(root, 0, uid_gid[1])
        except OSError:
            pass
        for item in root.rglob("*"):
            try:
                if item.is_dir():
                    os.chmod(item, 0o750)
                    if uid_gid:
                        os.chown(item, 0, uid_gid[1])
                elif item.is_file():
                    os.chmod(item, 0o640)
                    if uid_gid:
                        os.chown(item, 0, uid_gid[1])
            except OSError:
                pass
    try:
        os.chmod(XRAY_ROOT, 0o750)
        if uid_gid:
            os.chown(XRAY_ROOT, 0, uid_gid[1])
            os.chown(XRAY_LOG_ROOT, uid_gid[0], uid_gid[1])
        os.chmod(XRAY_LOG_ROOT, 0o750)
    except OSError:
        pass


def service_account_can_read(path: Path) -> bool:
    identity = _xray_identity()
    if not identity:
        return os.access(path, os.R_OK)
    runuser = shutil.which("runuser") or "/usr/sbin/runuser"
    if not Path(runuser).exists():
        return os.access(path, os.R_OK)

    def _check() -> bool:
        result = subprocess.run(
            [runuser, "-u", "vpn-xray", "--", "/usr/bin/test", "-r", str(path)],
            capture_output=True, text=True, timeout=8, check=False,
        )
        return result.returncode == 0

    if _check():
        return True
    # A root API process can safely self-heal the ownership/traversal mismatch
    # once before declaring the protocol failed.  This also repairs atomic
    # replacements created by older builds without requiring a full reinstall.
    if os.geteuid() == 0:
        protocol = path.parent.name if path.parent.name in PROTOCOLS else None
        ensure_runtime_permissions(protocol)
        return _check()
    return False


def _get(db: Session, key: str, default: str = "") -> str:
    row = db.query(Setting).filter(Setting.key == key).first()
    return row.value if row and row.value is not None else default


def _set(db: Session, key: str, value: str) -> None:
    row = db.query(Setting).filter(Setting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(Setting(key=key, value=value))


def _bool(db: Session, key: str, default: bool = False) -> bool:
    return _get(db, key, "1" if default else "0").lower() in {"1", "true", "yes", "on"}


def _int(db: Session, key: str, default: int) -> int:
    try:
        return int(_get(db, key, str(default)))
    except (TypeError, ValueError):
        return default


def _json_setting(db: Session, key: str) -> dict:
    try:
        value = json.loads(_get(db, key, "{}") or "{}")
        return value if isinstance(value, dict) else {}
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}


def _save_json_setting(db: Session, key: str, value: dict) -> None:
    _set(db, key, json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


def _xray_main_pid(protocol: str) -> int:
    unit = UNITS.get(protocol)
    if not unit:
        return 0
    try:
        result = subprocess.run(
            ["/usr/bin/systemctl", "show", unit, "-p", "MainPID", "--value"],
            capture_output=True, text=True, timeout=6, check=False,
        )
        return max(0, int((result.stdout or "0").strip() or 0))
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return 0


def _internet_block_rule_tag(user_id: int, protocol: str) -> str:
    return f"vpnpanel-internet-block-{int(user_id)}-{protocol}"


def _xray_email(protocol: str, user_id: int) -> str:
    """Return a protocol-scoped Xray identity.

    Older releases used the same ``vpn-user-N`` email in both VMess and VLESS.
    Several Xray builds and reverse-proxy topologies then leaked online/stat
    evidence between sibling processes, allowing a real VMess connection to be
    attributed as VLESS.  A protocol-scoped identity makes that impossible at
    the Xray API, routing-rule and access-log layers.
    """
    if protocol not in PROTOCOLS:
        raise ValueError("Unsupported Xray protocol")
    return f"vpn-{protocol}-user-{int(user_id)}"


def _internet_block_rule_payload(user_id: int, protocol: str, rule_tag: str) -> dict:
    return {
        "routing": {
            "rules": [{
                "type": "field",
                "user": [_xray_email(protocol, int(user_id))],
                "inboundTag": [f"{protocol}-in"],
                "outboundTag": "blocked",
                "ruleTag": rule_tag,
            }]
        }
    }


def _add_internet_block_rule(protocol: str, user_id: int) -> bool:
    """Install a live identity-wide blackhole rule through RoutingService."""
    binary = shutil.which(XRAY_BINARY) or (XRAY_BINARY if Path(XRAY_BINARY).is_file() else None)
    if not binary or protocol not in PROTOCOLS:
        return False
    rule_tag = _internet_block_rule_tag(user_id, protocol)
    payload = _internet_block_rule_payload(user_id, protocol, rule_tag)
    fd, path = tempfile.mkstemp(prefix="vpn-panel-internet-block-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
        server = f"127.0.0.1:{API_PORTS[protocol]}"
        # Deterministic tag makes repeated clicks and backend restarts idempotent.
        subprocess.run(
            [binary, "api", "rmrules", f"--server={server}", rule_tag],
            capture_output=True, text=True, timeout=8, check=False,
        )
        for command in (
            [binary, "api", "adrules", f"--server={server}", path],
            [binary, "api", "adrules", f"-s={server}", path],
        ):
            result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
            if result.returncode == 0:
                return True
        return False
    except (OSError, subprocess.TimeoutExpired):
        return False
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _remove_internet_block_rule(protocol: str, user_id: int) -> bool:
    binary = shutil.which(XRAY_BINARY) or (XRAY_BINARY if Path(XRAY_BINARY).is_file() else None)
    if not binary or protocol not in PROTOCOLS:
        return False
    server = f"127.0.0.1:{API_PORTS[protocol]}"
    rule_tag = _internet_block_rule_tag(user_id, protocol)
    for command in (
        [binary, "api", "rmrules", f"--server={server}", rule_tag],
        [binary, "api", "rmrules", f"-s={server}", rule_tag],
    ):
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0:
            return True
        output = ((result.stdout or "") + "\n" + (result.stderr or "")).lower()
        if "not found" in output or "no rule" in output:
            return True
    return False


def _max_device_rule_tag(user_id: int, protocol: str, ip_address: str, source_port: int | None = None) -> str:
    identity = f"{ip_address}:{int(source_port)}" if source_port else ip_address
    digest = hashlib.sha256(f"{int(user_id)}|{protocol}|{identity}".encode("utf-8")).hexdigest()[:12]
    return f"vpnpanel-maxdev-{int(user_id)}-{protocol}-{digest}"


def _max_device_aggregate_rule_tag(user_id: int, protocol: str) -> str:
    return f"vpnpanel-maxdev-{int(user_id)}-{protocol}-aggregate"


def _max_device_rule_payload(
    user_id: int, protocol: str, ip_address: str | None, rule_tag: str, source_port: int | None = None,
) -> dict:
    """Build a user + protocol + public-IP blackhole rule.

    Source ports are intentionally ignored because a single device opens many
    ephemeral TCP streams. Stock VMess/VLESS does not provide a stable device
    ID that can safely replace the public-IP identity.
    """
    rule = {
        "type": "field",
        "user": [_xray_email(protocol, int(user_id))],
        "inboundTag": [f"{protocol}-in"],
        "outboundTag": "blocked",
        "ruleTag": rule_tag,
    }
    if ip_address:
        rule["sourceIP"] = [ip_address]
    # Do not add sourcePort: it is an ephemeral stream identifier, not a
    # device identifier, and would block only one of many streams.
    return {"routing": {"rules": [rule]}}


def _add_max_device_rule(
    protocol: str, user_id: int, ip_address: str | None, rule_tag: str, source_port: int | None = None,
) -> bool:
    binary = shutil.which(XRAY_BINARY) or (XRAY_BINARY if Path(XRAY_BINARY).is_file() else None)
    if not binary:
        return False
    payload = _max_device_rule_payload(user_id, protocol, ip_address, rule_tag, source_port)
    fd, path = tempfile.mkstemp(prefix="vpn-panel-maxdev-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
        server = f"127.0.0.1:{API_PORTS[protocol]}"
        # Replacing an existing deterministic tag is safer after backend/Xray
        # restarts than trusting an in-memory cache.
        subprocess.run(
            [binary, "api", "rmrules", f"--server={server}", rule_tag],
            capture_output=True, text=True, timeout=8, check=False,
        )
        variants = (
            [binary, "api", "adrules", f"--server={server}", path],
            [binary, "api", "adrules", f"-s={server}", path],
        )
        for command in variants:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
            if result.returncode == 0:
                return True
        return False
    except (OSError, subprocess.TimeoutExpired):
        return False
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _remove_max_device_rule(protocol: str, rule_tag: str) -> bool:
    binary = shutil.which(XRAY_BINARY) or (XRAY_BINARY if Path(XRAY_BINARY).is_file() else None)
    if not binary:
        return False
    server = f"127.0.0.1:{API_PORTS[protocol]}"
    for command in (
        [binary, "api", "rmrules", f"--server={server}", rule_tag],
        [binary, "api", "rmrules", f"-s={server}", rule_tag],
    ):
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0:
            return True
        output = ((result.stdout or "") + "\n" + (result.stderr or "")).lower()
        if "not found" in output or "no rule" in output:
            return True
    return False



def _kick_xray_source_ip(protocol: str, ip_address: str) -> bool:
    """Terminate current transports from one source IP after admission denial.

    The persistent user+sourceIP routing rule is installed separately. This
    short-lived source block only forces existing streams to reconnect so the
    new identity-aware rule takes effect immediately.
    """
    binary = shutil.which(XRAY_BINARY) or (XRAY_BINARY if Path(XRAY_BINARY).is_file() else None)
    normalized = _normalize_ip(ip_address or "")
    if not binary or protocol not in PROTOCOLS or not normalized:
        return False
    server = f"--server=127.0.0.1:{API_PORTS[protocol]}"
    tag = f"vpnpanel-maxdev-kick-{uuid.uuid4().hex}"
    variants = (
        [binary, "api", "sib", server, "-outbound=blocked", f"-inbound={protocol}-in", f"-ruletag={tag}", normalized],
        [binary, "api", "sib", f"-s=127.0.0.1:{API_PORTS[protocol]}", "-outbound=blocked", f"-inbound={protocol}-in", f"-ruletag={tag}", normalized],
    )
    success = False
    for command in variants:
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0:
            success = True
            break
    if success:
        time.sleep(0.25)
        _remove_max_device_rule(protocol, tag)
    return success


def _apply_max_device_endpoint_firewall(db: Session, desired_rules: dict[str, dict]) -> bool:
    """Hard-drop over-limit Xray transports by public source IP.

    RoutingService rules provide identity-aware blackholing for new streams.
    The nftables listener rule terminates existing transport traffic immediately.
    Source ports are optional diagnostics only because one client opens many
    ephemeral TCP streams and they are not stable device identifiers.
    """
    global _MAX_DEVICE_NFT_SIGNATURE
    nft = shutil.which("nft") or ("/usr/sbin/nft" if Path("/usr/sbin/nft").exists() else None)
    if not nft:
        return False
    items: list[dict] = []
    for tag, meta in desired_rules.items():
        ip = _normalize_ip(str((meta or {}).get("ip") or ""))
        source_port = int((meta or {}).get("source_port") or 0)
        protocol = str((meta or {}).get("protocol") or "")
        if protocol not in PROTOCOLS or not ip:
            continue
        items.append({
            "tag": str(tag), "protocol": protocol, "ip": ip,
            "source_port": source_port,
            "listener_port": int(get_protocol_settings(db, protocol)["port"]),
        })
    items.sort(key=lambda item: (item["protocol"], item["ip"], item["source_port"]))
    signature = hashlib.sha256(json.dumps(items, sort_keys=True).encode("utf-8")).hexdigest()

    listed = subprocess.run(
        [nft, "list", "table", "inet", _MAX_DEVICE_NFT_TABLE],
        capture_output=True, text=True, timeout=10, check=False,
    )
    if signature == _MAX_DEVICE_NFT_SIGNATURE:
        body = listed.stdout or ""
        if (not items and listed.returncode != 0) or all(item["tag"] in body for item in items):
            return True

    if not items:
        if listed.returncode == 0:
            subprocess.run(
                [nft, "delete", "table", "inet", _MAX_DEVICE_NFT_TABLE],
                capture_output=True, text=True, timeout=10, check=False,
            )
        _MAX_DEVICE_NFT_SIGNATURE = signature
        return True

    lines = [
        f"table inet {_MAX_DEVICE_NFT_TABLE} {{",
        "  chain input {",
        "    type filter hook input priority -5; policy accept;",
    ]
    for item in items:
        family = "ip6" if ":" in item["ip"] else "ip"
        safe_comment = re.sub(r"[^A-Za-z0-9_.:-]", "-", item["tag"])[:120]
        source_match = ''
        lines.append(
            f'    {family} saddr {item["ip"]} {source_match}'
            f'tcp dport {item["listener_port"]} counter drop comment "{safe_comment}"'
        )
    lines += ["  }", "}", ""]
    script = "\n".join(lines)
    fd, path = tempfile.mkstemp(prefix="vpn-panel-maxdev-", suffix=".nft")
    check_path = path + ".check"
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(script)
        Path(check_path).write_text(
            script.replace(
                f"table inet {_MAX_DEVICE_NFT_TABLE}",
                f"table inet {_MAX_DEVICE_NFT_TABLE}_check", 1,
            ),
            encoding="utf-8",
        )
        checked = subprocess.run([nft, "-c", "-f", check_path], capture_output=True, text=True, timeout=15, check=False)
        if checked.returncode != 0:
            logger.error("max-device nft validation failed: %s", checked.stderr or checked.stdout)
            return False
        if listed.returncode == 0:
            subprocess.run([nft, "delete", "table", "inet", _MAX_DEVICE_NFT_TABLE], capture_output=True, text=True, timeout=10, check=False)
        applied = subprocess.run([nft, "-f", path], capture_output=True, text=True, timeout=15, check=False)
        if applied.returncode != 0:
            logger.error("max-device nft apply failed: %s", applied.stderr or applied.stdout)
            return False
        verified = subprocess.run([nft, "list", "table", "inet", _MAX_DEVICE_NFT_TABLE], capture_output=True, text=True, timeout=10, check=False)
        body = verified.stdout or ""
        ok = verified.returncode == 0 and all(item["tag"] in body for item in items)
        if ok:
            _MAX_DEVICE_NFT_SIGNATURE = signature
        return ok
    except (OSError, subprocess.TimeoutExpired):
        logger.exception("max-device nft endpoint enforcement failed")
        return False
    finally:
        for target in (path, check_path):
            try:
                os.unlink(target)
            except OSError:
                pass

def _reconcile_xray_max_devices(
    db: Session,
    live_peers: dict[int, dict[str, set[str]]],
    now: datetime,
) -> bool:
    """Enforce the shared tunnel cap and one-protocol-per-public-IP policy.

    ``max_devices`` is the number of simultaneous admitted tunnels across every
    protocol.  VMess/VLESS raw TCP streams are collapsed to one tunnel per
    protocol+public-IP, but sibling protocols never collapse together: when one
    public IP already owns VMess, a newer VLESS tunnel from the same account/IP
    is denied even if another global slot is still free.
    """
    global _MAX_DEVICE_RULES_INITIALIZED

    persisted_rules = _json_setting(db, _MAX_DEVICE_RULES_KEY)
    previous_desired_rules = _json_setting(db, _MAX_DEVICE_DESIRED_RULES_KEY)
    states = _json_setting(db, _MAX_DEVICE_STATE_KEY)

    if not _MAX_DEVICE_RULES_INITIALIZED:
        for tag, meta in list(persisted_rules.items()):
            proto = str((meta or {}).get("protocol") or "")
            if proto in PROTOCOLS:
                _remove_max_device_rule(proto, tag)
        persisted_rules = {}
        _MAX_DEVICE_RULES_INITIALIZED = True

    for protocol in PROTOCOLS:
        pid = _xray_main_pid(protocol)
        previous = _MAX_DEVICE_RULE_PIDS.get(protocol)
        if previous is not None and pid != previous:
            persisted_rules = {
                tag: meta for tag, meta in persisted_rules.items()
                if str((meta or {}).get("protocol") or "") != protocol
            }
        _MAX_DEVICE_RULE_PIDS[protocol] = pid

    online_logs = (
        db.query(ConnectionLog)
        .filter(ConnectionLog.is_online == True)  # noqa: E712
        .order_by(ConnectionLog.connect_time.asc(), ConnectionLog.id.asc())
        .all()
    )
    online_user_ids = {int(log.user_id) for log in online_logs}
    online_user_ids.update(int(user_id) for user_id in live_peers)
    users = db.query(VpnUser).filter(VpnUser.id.in_(online_user_ids)).all() if online_user_ids else []
    users_by_id = {int(user.id): user for user in users}

    for log in db.query(ConnectionLog).filter(
        ConnectionLog.protocol.in_(PROTOCOLS),
        ConnectionLog.device_limit_blocked == True,  # noqa: E712
    ).all():
        log.device_limit_blocked = False

    # user -> candidate key -> one concurrent tunnel. Hook-based VPNs already
    # have one ConnectionLog per tunnel. Xray can expose many TCP stream rows,
    # so only those rows collapse to one protocol+public-IP tunnel.
    candidate_map: dict[int, dict[str, dict]] = {}

    def ensure_candidate(
        user_id: int,
        key: str,
        connected_at: datetime,
        public_ip: str | None = None,
    ) -> dict:
        bucket = candidate_map.setdefault(int(user_id), {})
        item = bucket.get(key)
        if item is None:
            item = {
                "key": key,
                "connected_at": connected_at or now,
                "public_ip": _normalize_ip(public_ip or ""),
                "nonxray_logs": [],
                "xray_peers": [],
            }
            bucket[key] = item
        elif connected_at and connected_at < item["connected_at"]:
            item["connected_at"] = connected_at
        if not item.get("public_ip") and public_ip:
            item["public_ip"] = _normalize_ip(public_ip)
        return item

    # Every hook-based tunnel is one slot. Public IP is stored separately so a
    # second simultaneous protocol from the same public endpoint can be denied
    # without merging the two tunnels into one max_devices candidate.
    for log in online_logs:
        if log.protocol in PROTOCOLS or bool(getattr(log, "device_limit_blocked", False)):
            continue
        public_ip = _normalize_ip(log.ip_address or "")
        key = f"session:{int(log.id)}"
        item = ensure_candidate(int(log.user_id), key, log.connect_time or now, public_ip)
        item["nonxray_logs"].append(int(log.id))

    # Preserve first-connection ordering from the tracked Xray rows. Access-log
    # activity timestamps represent recent traffic, not the age of the tunnel;
    # using them would occasionally reject the older VMess session and keep the
    # newer VLESS session merely because its key sorts first.
    xray_log_started: dict[tuple[int, str, str, int], datetime] = {}
    for log in online_logs:
        if log.protocol not in PROTOCOLS:
            continue
        normalized = _normalize_ip(log.ip_address or "")
        if not normalized:
            continue
        source_port = int(getattr(log, "source_port", 0) or 0) if XRAY_STRICT_SAME_NAT else 0
        key = (int(log.user_id), str(log.protocol), normalized, source_port)
        stamp = log.connect_time or now
        previous = xray_log_started.get(key)
        if previous is None or stamp < previous:
            xray_log_started[key] = stamp

    xray_pairs: set[tuple[int, str]] = set()
    # Probing rows remain admitted until the second failed five-second probe.
    # Keeping them in the candidate set prevents a one-tick socket/API hiccup
    # from freeing the global slot and admitting a second device.
    for log in online_logs:
        if log.protocol in PROTOCOLS and _xray_log_has_strong_protocol_evidence(log):
            xray_pairs.add((int(log.user_id), str(log.protocol)))
    for user_id, by_protocol in live_peers.items():
        for protocol in by_protocol:
            if protocol in PROTOCOLS:
                xray_pairs.add((int(user_id), protocol))

    for uid, protocol in sorted(xray_pairs):
        endpoints = list(_XRAY_LIVE_ENDPOINTS.get((uid, protocol), []) or [])
        endpoint_by_key: dict[tuple[str, int], datetime] = {}
        for raw_ip, raw_port, connected_at in endpoints:
            ip_address = _normalize_ip(raw_ip or "")
            if not ip_address:
                continue
            source_port = int(raw_port or 0) if XRAY_STRICT_SAME_NAT else 0
            key = (ip_address, source_port)
            stamp = connected_at or now
            previous = endpoint_by_key.get(key)
            if previous is None or stamp < previous:
                endpoint_by_key[key] = stamp
        for raw_ip in set((live_peers.get(uid) or {}).get(protocol) or set()):
            ip_address = _normalize_ip(raw_ip or "")
            if ip_address and not any(key_ip == ip_address for key_ip, _port in endpoint_by_key):
                endpoint_by_key[(ip_address, 0)] = xray_log_started.get((uid, protocol, ip_address, 0), now)

        # Preserve tracked idle/probing endpoints until their second miss.
        for log in online_logs:
            if int(log.user_id) != uid or str(log.protocol) != protocol:
                continue
            if not _xray_log_has_strong_protocol_evidence(log):
                continue
            ip_address = _normalize_ip(log.ip_address or "")
            if not ip_address:
                continue
            source_port = int(getattr(log, "source_port", 0) or 0) if XRAY_STRICT_SAME_NAT else 0
            endpoint_by_key.setdefault(
                (ip_address, source_port),
                log.connect_time or xray_log_started.get((uid, protocol, ip_address, source_port), now),
            )

        for (ip_address, source_port), connected_at in endpoint_by_key.items():
            tracked_started = xray_log_started.get((uid, protocol, ip_address, source_port))
            if tracked_started is not None:
                connected_at = tracked_started
            # One VMess/VLESS protocol at one public IP is one tunnel even if
            # the client opens many TCP streams. Sibling protocols deliberately
            # use different keys and therefore consume separate max_devices
            # slots, even when both arrive through the same public NAT address.
            item = ensure_candidate(
                uid,
                f"xray:{protocol}:ip:{ip_address}",
                connected_at,
                ip_address,
            )
            peer = {"protocol": protocol, "ip": ip_address, "source_port": source_port or None}
            if peer not in item["xray_peers"]:
                item["xray_peers"].append(peer)

        # If Xray confirms more online identities than can be mapped to an
        # endpoint, retain anonymous candidates so the global cap still errs on
        # the safe side.
        # Raw Xray online counters can be TCP-stream counts and, on some
        # builds, can leak across sibling protocol probes. They are diagnostics
        # only and never consume a shared device slot without an attributed,
        # identity-verified endpoint.

    # Ask the authoritative controller for one fleet-wide decision per Xray
    # tunnel identity. Hook-based protocols reserve their slot before the local
    # ConnectionLog is created; Xray is observed asynchronously, so this batch
    # blocks/admits the current candidates after exact protocol evidence exists.
    from app.services.cluster_admission import (
        build_xray_cluster_session_key, reconcile_cluster_xray_candidates,
    )
    cluster_candidates: list[dict] = []
    cluster_key_to_local_key: dict[str, str] = {}
    for user_id, by_key in candidate_map.items():
        user = users_by_id.get(int(user_id))
        if user is None:
            continue
        for item in by_key.values():
            if not item["xray_peers"]:
                continue
            peer = item["xray_peers"][0]
            protocol = str(peer.get("protocol") or "")
            public_ip = _normalize_ip(str(peer.get("ip") or ""))
            if protocol not in PROTOCOLS or not public_ip:
                continue
            cluster_key = build_xray_cluster_session_key(user.username, protocol, public_ip)
            cluster_key_to_local_key[cluster_key] = str(item["key"])
            cluster_candidates.append({
                "username": user.username,
                "protocol": protocol,
                "ip_address": public_ip,
                "session_key": cluster_key,
                "connect_time": item["connected_at"].isoformat() + "Z",
                "max_devices": int(user.max_devices or 0),
            })
    denied_cluster_keys = reconcile_cluster_xray_candidates(db, cluster_candidates)
    cluster_denied_local_keys = {
        cluster_key_to_local_key[key]
        for key in denied_cluster_keys
        if key in cluster_key_to_local_key
    }

    desired_rules: dict[str, dict] = {}
    next_states: dict[str, dict[str, list[str]]] = {}
    denied_nonxray_log_ids: list[int] = []

    for user_id, by_key in candidate_map.items():
        user = users_by_id.get(int(user_id))
        if not user:
            continue
        entries = sorted(by_key.values(), key=lambda item: (item["connected_at"], item["key"]))
        limit = max(0, int(user.max_devices or 0))
        current_keys = {item["key"] for item in entries}
        old = states.get(str(user_id), {}) if isinstance(states.get(str(user_id), {}), dict) else {}
        old_admitted_order = [
            key for key in old.get("admitted", [])
            if isinstance(key, str) and key in current_keys
        ]
        old_denied = {
            key for key in old.get("denied", [])
            if isinstance(key, str) and key in current_keys
        }
        admitted: list[str] = []
        denied: list[str] = []

        # Keep previously admitted tunnels first, then consider remaining live
        # candidates by original connect time. A formerly denied live tunnel may
        # be promoted automatically after the older tunnel disconnects.
        ordered_keys: list[str] = []
        for key in old_admitted_order:
            if key not in ordered_keys:
                ordered_keys.append(key)
        for item in entries:
            if item["key"] not in ordered_keys:
                ordered_keys.append(item["key"])
        by_key_lookup = {item["key"]: item for item in entries}

        for key in ordered_keys:
            item = by_key_lookup.get(key)
            if item is None:
                continue
            if key in cluster_denied_local_keys:
                denied.append(key)
                continue
            if key in old_denied and key not in old_admitted_order:
                denied.append(key)
                continue
            # Public IP does not create an additional uniqueness rule. Each
            # candidate tunnel consumes one slot until max_devices is reached.
            if limit > 0 and len(admitted) >= limit:
                denied.append(key)
                continue
            admitted.append(key)

        next_states[str(user_id)] = {
            "admitted": [key for key in admitted if key.startswith(("session:", "xray:", "xray-unknown:"))],
            "denied": [key for key in denied if key.startswith(("session:", "xray:", "xray-unknown:"))],
        }
        denied_set = set(denied)
        admitted_xray_protocols = {
            str(peer.get("protocol") or "")
            for item in entries if item["key"] not in denied_set
            for peer in item["xray_peers"]
            if str(peer.get("protocol") or "") in PROTOCOLS
        }

        for item in entries:
            if item["key"] not in denied_set:
                continue
            denied_nonxray_log_ids.extend(int(log_id) for log_id in item["nonxray_logs"])
            for peer in item["xray_peers"]:
                protocol = str(peer.get("protocol") or "")
                ip_address = _normalize_ip(str(peer.get("ip") or ""))
                if protocol not in PROTOCOLS or not ip_address:
                    logger.warning(
                        "max_devices exceeded but Xray did not expose a source IP: user_id=%s protocol=%s",
                        user_id, protocol,
                    )
                    continue
                source_port = int(peer.get("source_port") or 0) or None
                # When the whole sibling protocol is over the shared cap (for
                # example VMess admitted and VLESS newly denied), install a
                # protocol-wide user rule. This remains enforceable behind
                # Nginx/CDN reverse proxies where the Xray listener sees only
                # loopback and a public-source-IP firewall rule cannot match.
                aggregate = protocol not in admitted_xray_protocols
                for log in db.query(ConnectionLog).filter(
                    ConnectionLog.user_id == int(user_id),
                    ConnectionLog.protocol == protocol,
                    ConnectionLog.is_online == True,  # noqa: E712
                ).all():
                    same_ip = _normalize_ip(log.ip_address or "") == ip_address
                    same_port = not source_port or int(getattr(log, "source_port", 0) or 0) == source_port
                    if aggregate or (same_ip and same_port):
                        log.device_limit_blocked = True
                if aggregate:
                    tag = _max_device_aggregate_rule_tag(int(user_id), protocol)
                    desired_rules[tag] = {
                        "user_id": int(user_id),
                        "protocol": protocol,
                        "ip": None,
                        "source_port": None,
                        "aggregate": True,
                    }
                else:
                    tag = _max_device_rule_tag(int(user_id), protocol, ip_address, source_port)
                    desired_rules[tag] = {
                        "user_id": int(user_id),
                        "protocol": protocol,
                        "ip": ip_address,
                        "source_port": source_port,
                        "aggregate": False,
                    }

    # Publish the desired set before writing Xray configs. Aggregate sibling
    # denials are embedded statically as a deterministic fallback when the
    # installed Xray build lacks live RoutingService adrules support.
    _save_json_setting(db, _MAX_DEVICE_DESIRED_RULES_KEY, desired_rules)
    db.flush()

    old_aggregate_by_protocol = {
        protocol: sorted(
            (tag, meta) for tag, meta in previous_desired_rules.items()
            if isinstance(meta, dict) and bool(meta.get("aggregate"))
            and str(meta.get("protocol") or "") == protocol
        )
        for protocol in PROTOCOLS
    }
    new_aggregate_by_protocol = {
        protocol: sorted(
            (tag, meta) for tag, meta in desired_rules.items()
            if isinstance(meta, dict) and bool(meta.get("aggregate"))
            and str(meta.get("protocol") or "") == protocol
        )
        for protocol in PROTOCOLS
    }
    static_protocols_changed = {
        protocol for protocol in PROTOCOLS
        if old_aggregate_by_protocol[protocol] != new_aggregate_by_protocol[protocol]
    }

    # Hard-drop current denied endpoint packets. Stock VMess/VLESS does not
    # expose a stable device identifier behind one NAT, so enforcement is
    # public-IP based and never guesses from ephemeral source ports.
    _apply_max_device_endpoint_firewall(db, desired_rules)

    changed = False
    newly_blocked: set[tuple[str, str, int]] = set()
    for tag, meta in list(persisted_rules.items()):
        if tag in desired_rules:
            continue
        protocol = str((meta or {}).get("protocol") or "")
        if protocol in PROTOCOLS and _remove_max_device_rule(protocol, tag):
            persisted_rules.pop(tag, None)
            changed = True

    for tag, meta in desired_rules.items():
        if persisted_rules.get(tag) == meta:
            continue
        source_port = int(meta.get("source_port") or 0) or None
        installed = (
            _add_max_device_rule(meta["protocol"], meta["user_id"], meta.get("ip"), tag, source_port)
            if source_port
            else _add_max_device_rule(meta["protocol"], meta["user_id"], meta.get("ip"), tag)
        )
        if installed:
            persisted_rules[tag] = meta
            if meta.get("ip"):
                newly_blocked.add((str(meta["protocol"]), str(meta["ip"]), int(meta.get("source_port") or 0)))
            changed = True
        else:
            logger.error(
                "Failed to enforce max_devices user_id=%s protocol=%s ip=%s",
                meta["user_id"], meta["protocol"], meta.get("ip"),
            )

    restart_protocols: set[str] = set()
    for protocol, ip_address, source_port in sorted(newly_blocked):
        # Endpoint-scoped nftables already terminates the denied same-NAT
        # transport. An IP-wide kick would also kill the admitted endpoint.
        if source_port:
            continue
        if not _kick_xray_source_ip(protocol, ip_address):
            restart_protocols.add(protocol)

    # Fallback for Xray builds without `sib`: restart only the affected Xray
    # daemon, then restore every desired dynamic rule because runtime rules are
    # cleared by a process restart.
    for protocol in sorted(restart_protocols):
        if not _bool(db, f"{protocol}_enabled", False):
            continue
        ok, _output = _systemctl("restart", protocol)
        if not ok:
            continue
        _wait_ready(protocol, get_protocol_settings(db, protocol)["port"], timeout=15.0)
        _MAX_DEVICE_RULE_PIDS[protocol] = _xray_main_pid(protocol)
        for tag, meta in desired_rules.items():
            if str(meta.get("protocol")) == protocol:
                source_port = int(meta.get("source_port") or 0) or None
                if source_port:
                    _add_max_device_rule(protocol, int(meta["user_id"]), meta.get("ip"), tag, source_port)
                else:
                    _add_max_device_rule(protocol, int(meta["user_id"]), meta.get("ip"), tag)

    # Apply/remove protocol-wide static fallback rules only when the aggregate
    # denied set changed. Restarting the denied sibling daemon does not disturb
    # the already-admitted VMess/VLESS daemon and makes max_devices effective
    # even when live RoutingService commands are unsupported.
    for protocol in sorted(static_protocols_changed):
        try:
            target = write_config(db, protocol)
            valid, detail = validate_config(target)
            if not valid:
                logger.error("max-device static config invalid protocol=%s: %s", protocol, detail)
                continue
            if _bool(db, f"{protocol}_enabled", False):
                ok, output = _systemctl("restart", protocol)
                if not ok:
                    logger.error("max-device static restart failed protocol=%s: %s", protocol, output)
                    continue
                _wait_ready(protocol, int(get_protocol_settings(db, protocol)["port"]), timeout=15.0)
                # A restart clears live API rules; the static config is now the
                # source of truth and the next pass may repopulate API rules.
                persisted_rules = {
                    tag: meta for tag, meta in persisted_rules.items()
                    if str((meta or {}).get("protocol") or "") != protocol
                }
                _MAX_DEVICE_RULE_PIDS[protocol] = _xray_main_pid(protocol)
        except Exception:
            logger.exception("max-device static fallback failed protocol=%s", protocol)

    _save_json_setting(db, _MAX_DEVICE_RULES_KEY, persisted_rules)
    _save_json_setting(db, _MAX_DEVICE_STATE_KEY, next_states)
    _save_json_setting(db, _MAX_DEVICE_LEASES_KEY, {})
    db.commit()

    if denied_nonxray_log_ids:
        from app.services.vpn_manager import (
            kill_single_ppp_session,
            kill_single_sstp_session,
            kill_single_openvpn_session,
            kill_single_ikev2_session,
            kill_single_openconnect_session,
        )
        for log_id in dict.fromkeys(denied_nonxray_log_ids):
            log = db.query(ConnectionLog).filter(ConnectionLog.id == log_id).first()
            if not log or not log.is_online:
                continue
            try:
                if log.protocol in ("l2tp", "pptp"):
                    kill_single_ppp_session(db, log)
                elif log.protocol == "sstp":
                    kill_single_sstp_session(db, log)
                elif log.protocol == "openvpn":
                    kill_single_openvpn_session(db, log)
                elif log.protocol == "ikev2":
                    kill_single_ikev2_session(db, log)
                elif log.protocol == "openconnect":
                    kill_single_openconnect_session(db, log)
            except Exception:
                logger.exception("Failed to terminate over-limit session id=%s", log_id)

    return changed or bool(denied_nonxray_log_ids)


def default_settings(protocol: str) -> dict:
    if protocol not in PROTOCOLS:
        raise ValueError("Unsupported Xray protocol")
    return {
        "protocol": protocol,
        "enabled": False,
        "port": 10000 if protocol == "vmess" else 10001,
        "bind_address": "0.0.0.0",
        "transport": "tcp",
        "ws_path": f"/{protocol}",
        "tls_enabled": False,
        "tls_domain": "",
        "flow": "" if protocol == "vmess" else "",
        "server_address": "",
        "remark": protocol.upper(),
        "sniffing_enabled": True,
        "sniffing_route_only": True,
        "accept_proxy_protocol": False,
        "tcp_fast_open": False,
        "external_proxy_enabled": False,
        "external_proxy_address": "127.0.0.1",
        "external_proxy_port": 1080,
    }


def get_protocol_settings(db: Session, protocol: str) -> dict:
    defaults = default_settings(protocol)
    return {
        "protocol": protocol,
        "enabled": _bool(db, f"{protocol}_enabled", defaults["enabled"]),
        "port": _int(db, f"{protocol}_port", defaults["port"]),
        "bind_address": _get(db, f"{protocol}_bind_address", defaults["bind_address"]),
        "transport": _get(db, f"{protocol}_transport", defaults["transport"]),
        "ws_path": _get(db, f"{protocol}_ws_path", defaults["ws_path"]),
        "tls_enabled": _bool(db, f"{protocol}_tls_enabled", defaults["tls_enabled"]),
        "tls_domain": _get(db, f"{protocol}_tls_domain", defaults["tls_domain"]),
        "flow": _get(db, f"{protocol}_flow", defaults["flow"]),
        "server_address": _get(db, f"{protocol}_server_address", defaults["server_address"]),
        "remark": _get(db, f"{protocol}_remark", defaults["remark"]),
        "sniffing_enabled": _bool(db, f"{protocol}_sniffing_enabled", defaults["sniffing_enabled"]),
        "sniffing_route_only": _bool(db, f"{protocol}_sniffing_route_only", defaults["sniffing_route_only"]),
        "accept_proxy_protocol": _bool(db, f"{protocol}_accept_proxy_protocol", defaults["accept_proxy_protocol"]),
        "tcp_fast_open": _bool(db, f"{protocol}_tcp_fast_open", defaults["tcp_fast_open"]),
        "external_proxy_enabled": _bool(db, f"{protocol}_external_proxy_enabled", defaults["external_proxy_enabled"]),
        "external_proxy_address": _get(db, f"{protocol}_external_proxy_address", defaults["external_proxy_address"]),
        "external_proxy_port": _int(db, f"{protocol}_external_proxy_port", defaults["external_proxy_port"]),
    }


def _eligible(user: VpnUser, protocol: str, *, local_enabled: bool = True) -> bool:
    enabled = bool(getattr(user, f"enable_{protocol}", False))
    expired = user.expire_date is not None and user.expire_date < date.today()
    over_quota = user.quota_bytes > 0 and user.used_bytes >= user.quota_bytes
    return enabled and user.is_active and local_enabled and user_selected_for_local(user) and not expired and not over_quota and bool(user.xray_uuid)


def _client(user: VpnUser, protocol: str) -> dict:
    email = _xray_email(protocol, user.id)
    if protocol == "vmess":
        return {"id": user.xray_uuid, "alterId": 0, "email": email, "level": 0}
    return {"id": user.xray_uuid, "email": email, "level": 0}


def _tls_certificate_paths(domain: str, protocol: str) -> tuple[str, str]:
    cert = XRAY_ROOT / protocol / "tls" / "fullchain.pem"
    key = XRAY_ROOT / protocol / "tls" / "privkey.pem"
    return str(cert), str(key)


def _prepare_tls_files(settings: dict, protocol: str) -> None:
    """Copy a selected Let's Encrypt certificate into Xray's isolated tree.

    Xray runs as the dedicated ``vpn-xray`` account and therefore must never be
    granted traversal access to ``/etc/letsencrypt/live`` or its private archive.
    A protocol-local copy also makes config validation and rollback deterministic.
    """
    if not settings.get("tls_enabled"):
        return
    domain = str(settings.get("tls_domain") or "").strip()
    if not domain or not re.fullmatch(r"[A-Za-z0-9.-]+", domain):
        raise RuntimeError("A valid TLS domain is required")
    live = Path("/etc/letsencrypt/live") / domain
    source_cert = live / "fullchain.pem"
    source_key = live / "privkey.pem"
    if not source_cert.is_file() or not source_key.is_file():
        raise RuntimeError(f"TLS certificate for {domain} was not found")
    tls_dir = XRAY_ROOT / protocol / "tls"
    tls_dir.mkdir(parents=True, exist_ok=True)
    target_cert = tls_dir / "fullchain.pem"
    target_key = tls_dir / "privkey.pem"
    shutil.copy2(source_cert, target_cert)
    shutil.copy2(source_key, target_key)
    os.chmod(tls_dir, 0o750)
    os.chmod(target_cert, 0o640)
    os.chmod(target_key, 0o640)
    try:
        gid = grp.getgrnam("vpn-xray").gr_gid
        os.chown(tls_dir, 0, gid)
        os.chown(target_cert, 0, gid)
        os.chown(target_key, 0, gid)
    except (KeyError, PermissionError, OSError):
        # During offline validation/tests the service account may not exist yet.
        # setup_xray.sh applies the final ownership before enabling the units.
        pass


def build_config(db: Session, protocol: str, exclude_user_ids: set[int] | None = None) -> dict:
    settings = get_protocol_settings(db, protocol)
    exclude_user_ids = exclude_user_ids or set()
    users = (
        db.query(VpnUser)
        .filter(getattr(VpnUser, f"enable_{protocol}") == True)  # noqa: E712
        .order_by(VpnUser.id)
        .all()
    )
    eligible_users = [u for u in users if u.id not in exclude_user_ids and _eligible(u, protocol, local_enabled=local_assignment_enabled(db))]
    clients = [_client(u, protocol) for u in eligible_users]
    # Every eligible identity receives its own marked outbound. This lets the
    # panel apply a hard internet block or speed limit without closing the
    # VMess/VLESS transport connection.
    marked_users = list(eligible_users)
    eligible_ids = {int(user.id) for user in marked_users}
    max_device_rules: list[dict] = []
    for tag, meta in _json_setting(db, _MAX_DEVICE_DESIRED_RULES_KEY).items():
        if not isinstance(meta, dict) or str(meta.get("protocol") or "") != protocol:
            continue
        try:
            user_id = int(meta.get("user_id"))
        except (TypeError, ValueError):
            continue
        if user_id not in eligible_ids:
            continue
        rule = _max_device_rule_payload(
            user_id, protocol, _normalize_ip(str(meta.get("ip") or "")), str(tag),
            int(meta.get("source_port") or 0) or None,
        )["routing"]["rules"][0]
        max_device_rules.append(rule)

    inbound_settings: dict = {"clients": clients}
    if protocol == "vmess":
        inbound_settings["disableInsecureEncryption"] = True
    else:
        inbound_settings["decryption"] = "none"
        flow = settings.get("flow") or ""
        if flow:
            for client in clients:
                client["flow"] = flow

    stream: dict = {"network": settings["transport"], "security": "none"}
    if settings["transport"] == "ws":
        stream["wsSettings"] = {"path": settings["ws_path"]}
    else:
        stream["tcpSettings"] = {"header": {"type": "none"}}

    inbound_sockopt: dict = {}
    if settings["tcp_fast_open"]:
        inbound_sockopt.update({"tcpFastOpen": True, "tcpNoDelay": True})
    if settings["accept_proxy_protocol"]:
        inbound_sockopt["acceptProxyProtocol"] = True
    # For WebSocket behind the panel's local Nginx, preserve the real client IP
    # so Xray online statistics do not collapse every user into 127.0.0.1.
    if settings["transport"] == "ws":
        inbound_sockopt["trustedXForwardedFor"] = ["X-Forwarded-For", "X-Real-IP"]
    if inbound_sockopt:
        stream["sockopt"] = inbound_sockopt
    if settings["tls_enabled"]:
        domain = settings["tls_domain"].strip()
        cert, key = _tls_certificate_paths(domain, protocol)
        stream["security"] = "tls"
        stream["tlsSettings"] = {
            "serverName": domain,
            "minVersion": "1.2",
            "certificates": [{"certificateFile": cert, "keyFile": key}],
        }

    api_port = API_PORTS[protocol]
    access_log = str(XRAY_LOG_ROOT / f"{protocol}-access.log")
    error_log = str(XRAY_LOG_ROOT / f"{protocol}-error.log")
    return {
        "log": {"access": access_log, "error": error_log, "loglevel": "warning"},
        "api": {"tag": "api", "services": ["HandlerService", "LoggerService", "StatsService", "RoutingService"]},
        "stats": {},
        "policy": {
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True, "statsUserOnline": True}},
            "system": {"statsInboundUplink": True, "statsInboundDownlink": True, "statsOutboundUplink": True, "statsOutboundDownlink": True},
        },
        "inbounds": [
            {
                "tag": f"{protocol}-in",
                "listen": settings["bind_address"],
                "port": settings["port"],
                "protocol": protocol,
                "settings": inbound_settings,
                "streamSettings": stream,
                "sniffing": {"enabled": settings["sniffing_enabled"], "destOverride": ["http", "tls", "quic"], "routeOnly": settings["sniffing_route_only"]},
            },
            {
                "tag": "api",
                "listen": "127.0.0.1",
                "port": api_port,
                "protocol": "dokodemo-door",
                "settings": {"address": "127.0.0.1"},
            },
        ],
        "outbounds": [
            _build_outbound(settings, "direct"),
            *[
                ({"tag": f"user-{u.id}", "protocol": "blackhole", "settings": {}}
                 if bool(getattr(u, f"{protocol}_internet_blocked", False))
                 else _build_outbound(settings, f"user-{u.id}", user_rate_mark(int(u.id), protocol)))
                for u in marked_users
            ],
            {"tag": "blocked", "protocol": "blackhole", "settings": {}},
        ],
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "rules": [
                {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
                *max_device_rules,
                *[
                    {
                        "type": "field",
                        "user": [_xray_email(protocol, u.id)],
                        "inboundTag": [f"{protocol}-in"],
                        "outboundTag": "blocked",
                        "ruleTag": _internet_block_rule_tag(int(u.id), protocol),
                    }
                    for u in marked_users
                    if bool(getattr(u, f"{protocol}_internet_blocked", False))
                ],
                {"type": "field", "protocol": ["bittorrent"], "outboundTag": "blocked"},
                *[
                    {
                        "type": "field",
                        "user": [_xray_email(protocol, u.id)],
                        "outboundTag": f"user-{u.id}",
                    }
                    for u in marked_users
                ],
            ],
        },
    }


def config_path(protocol: str) -> Path:
    return XRAY_ROOT / protocol / "config.json"


def write_config(db: Session, protocol: str, exclude_user_ids: set[int] | None = None) -> Path:
    target = config_path(protocol)
    target.parent.mkdir(parents=True, exist_ok=True)
    XRAY_LOG_ROOT.mkdir(parents=True, exist_ok=True)
    _prepare_tls_files(get_protocol_settings(db, protocol), protocol)
    payload = build_config(db, protocol, exclude_user_ids=exclude_user_ids)
    fd, tmp = tempfile.mkstemp(prefix=f".{protocol}-", suffix=".json", dir=str(target.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        os.chmod(tmp, 0o640)
        os.replace(tmp, target)
        ensure_runtime_permissions(protocol)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return target


def validate_config(path: Path) -> tuple[bool, str]:
    try:
        json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"Invalid JSON: {exc}"
    binary = shutil.which(XRAY_BINARY) or (XRAY_BINARY if Path(XRAY_BINARY).is_file() else None)
    if not binary:
        return False, "Xray binary is not installed"
    if not service_account_can_read(path):
        return False, f"vpn-xray cannot read {path}; run protocol repair to restore ownership"
    raw_variants = ([binary, "run", "-test", "-config", str(path)], [binary, "-test", "-config", str(path)])
    runuser = shutil.which("runuser") or "/usr/sbin/runuser"
    as_service = _xray_identity() is not None and Path(runuser).exists() and os.geteuid() == 0
    variants = [([runuser, "-u", "vpn-xray", "--", *cmd] if as_service else list(cmd)) for cmd in raw_variants]
    messages: list[str] = []
    for command in variants:
        result = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
        output = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
        if result.returncode == 0:
            return True, output or "Configuration valid"
        messages.append(output)
    return False, "\n".join(x for x in messages if x)[-2000:]


def _systemctl(action: str, protocol: str) -> tuple[bool, str]:
    result = subprocess.run(
        ["/usr/bin/systemctl", action, UNITS[protocol]], capture_output=True, text=True, timeout=30, check=False
    )
    output = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
    return result.returncode == 0, output


def _sync_firewall(protocol: str, enabled: bool, port: int) -> None:
    iptables = shutil.which("iptables")
    if not iptables:
        return
    comment = f"vpn-panel-xray-{protocol}"
    # Remove only rules owned by this integration. Existing ban chains and
    # rules for all other protocols stay untouched.
    save = subprocess.run([iptables + "-save"] if Path(iptables + "-save").exists() else ["/usr/sbin/iptables-save"], capture_output=True, text=True, timeout=10, check=False)
    for line in (save.stdout or "").splitlines():
        if comment not in line or not line.startswith("-A INPUT "):
            continue
        args = line.split()
        args[0] = "-D"
        subprocess.run([iptables, *args], capture_output=True, timeout=10, check=False)
    if enabled:
        subprocess.run(
            [iptables, "-A", "INPUT", "-p", "tcp", "--dport", str(port), "-m", "comment", "--comment", comment, "-j", "ACCEPT"],
            capture_output=True, timeout=10, check=False,
        )
    persistent = shutil.which("netfilter-persistent")
    if persistent:
        subprocess.run([persistent, "save"], capture_output=True, timeout=20, check=False)



def _wait_ready(protocol: str, port: int, timeout: float = 12.0) -> tuple[bool, str]:
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        state = subprocess.run(["/usr/bin/systemctl", "is-active", UNITS[protocol]], capture_output=True, text=True, check=False).stdout.strip()
        listeners = subprocess.run([shutil.which("ss") or "/usr/bin/ss", "-H", "-lnt"], capture_output=True, text=True, check=False).stdout
        listening = bool(re.search(rf"(?:\]|:){int(port)}(?:\s|$)", listeners or ""))
        if state == "active" and listening:
            return True, "active and listening"
        last = f"state={state or 'unknown'}, tcp/{port} listening={listening}"
        time.sleep(0.5)
    status = subprocess.run(["/usr/bin/systemctl", "status", UNITS[protocol], "--no-pager", "-l"], capture_output=True, text=True, check=False)
    journal = subprocess.run(["/usr/bin/journalctl", "-u", UNITS[protocol], "-n", "40", "--no-pager"], capture_output=True, text=True, check=False)
    return False, (last + "\n" + (status.stdout or status.stderr or "") + "\n" + (journal.stdout or journal.stderr or ""))[-5000:]

def sync_xray_users(db: Session, protocols: Iterable[str] | None = None, restart: bool = True) -> dict[str, str]:
    results: dict[str, str] = {}
    for protocol in protocols or PROTOCOLS:
        if protocol not in PROTOCOLS:
            continue
        if not Path(XRAY_BINARY).is_file() and not shutil.which("xray"):
            results[protocol] = "not-installed"
            continue
        if db.query(VpnUser).filter(
            getattr(VpnUser, f"enable_{protocol}") == True  # noqa: E712
        ).all():
            # All active Xray identities use marked outbounds so limits and the
            # per-protocol internet switch work immediately.
            marked = any(_eligible(u, protocol, local_enabled=local_assignment_enabled(db)) for u in db.query(VpnUser).all())
            if marked:
                ensure_xray_rate_limit_capability()
        target = write_config(db, protocol)
        valid, detail = validate_config(target)
        if not valid:
            raise RuntimeError(f"{protocol} configuration validation failed: {detail}")
        if restart:
            enabled = _bool(db, f"{protocol}_enabled", False)
            action = "restart" if enabled else "stop"
            ok, output = _systemctl(action, protocol)
            if not ok and enabled:
                raise RuntimeError(f"{protocol} service {action} failed: {output}")
            if enabled:
                ready, health = _wait_ready(protocol, get_protocol_settings(db, protocol)["port"])
                if not ready:
                    raise RuntimeError(f"{protocol} did not become ready after restart: {health}")
        results[protocol] = "ok"
    return results



def ensure_xray_rate_configuration(db: Session, *, force: bool = False) -> bool:
    """Self-heal per-user marked Xray outbounds.

    Every eligible VMess/VLESS identity is routed through a protocol-specific
    SO_MARK outbound. This is required both for directional speed limits and for
    suspending internet access while the client remains connected.
    """
    global _LAST_RATE_CONFIG_VERIFY
    now = time.monotonic()
    if not force and now - _LAST_RATE_CONFIG_VERIFY < 30:
        return False
    _LAST_RATE_CONFIG_VERIFY = now

    marked_by_protocol: dict[str, list[VpnUser]] = {}
    sync_protocols: list[str] = []
    all_users = db.query(VpnUser).order_by(VpnUser.id).all()
    for protocol in PROTOCOLS:
        users = [user for user in all_users if _eligible(user, protocol, local_enabled=local_assignment_enabled(db))]
        marked_by_protocol[protocol] = users
        if not _bool(db, f"{protocol}_enabled", False):
            continue

        # A running data listener without its loopback API was the direct cause
        # of false offline state, missing usage and unenforced connection caps.
        # Treat the API socket as part of the required runtime configuration and
        # rebuild/restart this one protocol when it disappears.
        api_ready = False
        if _xray_main_pid(protocol) > 0:
            try:
                with socket.create_connection(("127.0.0.1", API_PORTS[protocol]), timeout=0.35):
                    api_ready = True
            except OSError:
                api_ready = False
        if not api_ready:
            sync_protocols.append(protocol)

        try:
            payload = json.loads(config_path(protocol).read_text(encoding="utf-8"))
        except Exception:
            sync_protocols.append(protocol)
            continue

        # Self-heal online tracking settings on existing installations too.
        # Safe code updates intentionally do not run protocol installers, so
        # without this check an old WS config would never gain trusted XFF.
        level0 = ((payload.get("policy") or {}).get("levels") or {}).get("0") or {}
        main_inbound = next((
            item for item in payload.get("inbounds", [])
            if isinstance(item, dict) and item.get("tag") == f"{protocol}-in"
        ), {})
        stream = main_inbound.get("streamSettings") or {}
        sockopt = stream.get("sockopt") or {}
        needs_online_repair = not bool(level0.get("statsUserOnline"))
        if stream.get("network") == "ws" and not sockopt.get("trustedXForwardedFor"):
            needs_online_repair = True
        if needs_online_repair:
            sync_protocols.append(protocol)

        if not users:
            continue
        outbounds = {item.get("tag"): item for item in payload.get("outbounds", []) if isinstance(item, dict)}
        rules = payload.get("routing", {}).get("rules", [])
        # Older panel builds accidentally created a normal freedom outbound with
        # the reserved tag ``api``. That shadows Xray's internal API dispatcher
        # and recursively connects 127.0.0.1:10085/10086 back into itself. The
        # result is a flooded access log, huge CPU/RAM usage, false active
        # connection counts and a StatsService that cannot be queried. Rebuild
        # such configs immediately after a safe code update.
        api_outbound = outbounds.get("api")
        if isinstance(api_outbound, dict) and api_outbound.get("protocol"):
            sync_protocols.append(protocol)
        for user in users:
            tag = f"user-{user.id}"
            outbound = outbounds.get(tag) or {}
            mark = (((outbound.get("streamSettings") or {}).get("sockopt") or {}).get("mark"))
            routed = any(
                isinstance(rule, dict)
                and rule.get("outboundTag") == tag
                and _xray_email(protocol, user.id) in (rule.get("user") or [])
                for rule in rules
            )
            blocked_expected = bool(getattr(user, f"{protocol}_internet_blocked", False))
            blocked_routed = any(
                isinstance(rule, dict)
                and rule.get("outboundTag") == "blocked"
                and rule.get("ruleTag") == _internet_block_rule_tag(int(user.id), protocol)
                and _xray_email(protocol, user.id) in (rule.get("user") or [])
                for rule in rules
            )
            if (
                int(mark or 0) != user_rate_mark(int(user.id), protocol)
                or not routed
                or blocked_routed != blocked_expected
            ):
                sync_protocols.append(protocol)
                break

    marked_any = any(marked_by_protocol.values())
    capability_changed = ensure_xray_rate_limit_capability() if marked_any else False
    for protocol, users in marked_by_protocol.items():
        if users and _bool(db, f"{protocol}_enabled", False) and not _service_has_cap_net_admin(protocol):
            sync_protocols.append(protocol)

    sync_protocols = list(dict.fromkeys(sync_protocols))
    if sync_protocols:
        # Rebuild marked outbounds and restart the live process so the capability
        # and SO_MARK configuration are effective immediately, not merely present
        # on disk.
        sync_xray_users(db, protocols=sync_protocols, restart=True)
        return True
    if capability_changed:
        for protocol, users in marked_by_protocol.items():
            if users and _bool(db, f"{protocol}_enabled", False):
                _systemctl("restart", protocol)
        return True
    return False

def save_protocol_settings(db: Session, protocol: str, payload: dict) -> dict:
    if protocol not in PROTOCOLS:
        raise ValueError("Unsupported Xray protocol")
    old = get_protocol_settings(db, protocol)
    target = config_path(protocol)
    backup = target.with_suffix(f".json.bak-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}")
    if target.is_file():
        shutil.copy2(target, backup)

    mapping = {
        f"{protocol}_enabled": "1" if payload["enabled"] else "0",
        f"{protocol}_port": str(payload["port"]),
        f"{protocol}_bind_address": payload["bind_address"],
        f"{protocol}_transport": payload["transport"],
        f"{protocol}_ws_path": payload["ws_path"],
        f"{protocol}_tls_enabled": "1" if payload["tls_enabled"] else "0",
        f"{protocol}_tls_domain": payload["tls_domain"],
        f"{protocol}_flow": payload.get("flow", ""),
        f"{protocol}_server_address": payload.get("server_address", ""),
        f"{protocol}_remark": payload.get("remark", ""),
        f"{protocol}_sniffing_enabled": "1" if payload.get("sniffing_enabled", True) else "0",
        f"{protocol}_sniffing_route_only": "1" if payload.get("sniffing_route_only", True) else "0",
        f"{protocol}_accept_proxy_protocol": "1" if payload.get("accept_proxy_protocol", False) else "0",
        f"{protocol}_tcp_fast_open": "1" if payload.get("tcp_fast_open", False) else "0",
        f"{protocol}_external_proxy_enabled": "1" if payload.get("external_proxy_enabled", False) else "0",
        f"{protocol}_external_proxy_address": payload.get("external_proxy_address", "127.0.0.1"),
        f"{protocol}_external_proxy_port": str(payload.get("external_proxy_port", 1080)),
    }
    try:
        for key, value in mapping.items():
            _set(db, key, value)
        db.flush()
        candidate = write_config(db, protocol)
        valid, detail = validate_config(candidate)
        if not valid:
            raise RuntimeError(detail)
        ok, output = _systemctl("restart" if payload["enabled"] else "stop", protocol)
        if payload["enabled"] and not ok:
            raise RuntimeError(output or "service restart failed")
        if payload["enabled"]:
            ready, health = _wait_ready(protocol, int(payload["port"]), timeout=15.0)
            if not ready:
                raise RuntimeError(f"{protocol} did not become ready after applying settings: {health}")
        _sync_firewall(protocol, bool(payload["enabled"]), int(payload["port"]))
        db.commit()
        return get_protocol_settings(db, protocol)
    except Exception:
        db.rollback()
        for key, value in {
            f"{protocol}_enabled": "1" if old["enabled"] else "0",
            f"{protocol}_port": str(old["port"]),
            f"{protocol}_bind_address": old["bind_address"],
            f"{protocol}_transport": old["transport"],
            f"{protocol}_ws_path": old["ws_path"],
            f"{protocol}_tls_enabled": "1" if old["tls_enabled"] else "0",
            f"{protocol}_tls_domain": old["tls_domain"],
            f"{protocol}_flow": old["flow"],
            f"{protocol}_server_address": old["server_address"],
            f"{protocol}_remark": old["remark"],
            f"{protocol}_sniffing_enabled": "1" if old["sniffing_enabled"] else "0",
            f"{protocol}_sniffing_route_only": "1" if old["sniffing_route_only"] else "0",
            f"{protocol}_accept_proxy_protocol": "1" if old["accept_proxy_protocol"] else "0",
            f"{protocol}_tcp_fast_open": "1" if old["tcp_fast_open"] else "0",
            f"{protocol}_external_proxy_enabled": "1" if old["external_proxy_enabled"] else "0",
            f"{protocol}_external_proxy_address": old["external_proxy_address"],
            f"{protocol}_external_proxy_port": str(old["external_proxy_port"]),
        }.items():
            _set(db, key, value)
        db.commit()
        if backup.is_file():
            shutil.copy2(backup, target)
            _systemctl("restart" if old["enabled"] else "stop", protocol)
        _sync_firewall(protocol, bool(old["enabled"]), int(old["port"]))
        raise


def _run_api_variants(
    protocol: str,
    capability: str,
    variants: Iterable[list[str]],
    *,
    timeout: float = 2.5,
    cooldown_seconds: float = 45.0,
) -> tuple[bool, str]:
    """Run one Xray API command without letting unsupported variants block monitoring.

    Xray releases differ in short/long flag spelling and in whether output is
    JSON or protobuf text. The successful variant is remembered. If a command
    family is unavailable, it is skipped for a short cooldown instead of being
    retried once per user on every four-second tick.
    """
    binary = shutil.which(XRAY_BINARY) or (XRAY_BINARY if Path(XRAY_BINARY).is_file() else None)
    if not binary or protocol not in PROTOCOLS:
        return False, ""
    key = (protocol, capability)
    now = time.monotonic()
    if _XRAY_API_RETRY_AFTER.get(key, 0.0) > now:
        return False, ""
    choices = list(variants)
    preferred = _XRAY_API_VARIANTS.get(key)
    order = ([preferred] if preferred is not None and 0 <= preferred < len(choices) else []) + [
        index for index in range(len(choices)) if index != preferred
    ]
    server = f"--server=127.0.0.1:{API_PORTS[protocol]}"
    for index in order:
        try:
            result = subprocess.run(
                [binary, "api", *choices[index], server],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        output = ((result.stdout or "") + "\n" + (result.stderr or "")).strip()
        if result.returncode == 0:
            _XRAY_API_VARIANTS[key] = index
            _XRAY_API_RETRY_AFTER.pop(key, None)
            return True, output
    _XRAY_API_RETRY_AFTER[key] = now + max(5.0, cooldown_seconds)
    return False, ""


def _parse_stats_output(raw: str, protocol: str | None = None) -> dict[int, dict[str, int | bool | str]]:
    """Parse JSON/protobuf stats from several Xray generations.

    Canonical ``user>>>vpn-user-N`` traffic counters are preferred. Some Xray
    releases expose only the panel's per-user outbound counters instead. Those
    are retained as a last-resort source, while nftables remains the preferred
    accounting fallback when canonical user counters are absent.
    """
    result: dict[int, dict[str, int | bool | str]] = {}
    legacy_user_traffic_re = re.compile(r"^user>>>vpn-user-(\d+)>>>traffic>>>(uplink|downlink)$")
    scoped_user_traffic_re = re.compile(r"^user>>>vpn-(vmess|vless)-user-(\d+)>>>traffic>>>(uplink|downlink)$")
    outbound_traffic_re = re.compile(r"^outbound>>>user-(\d+)>>>traffic>>>(uplink|downlink)$")
    legacy_online_re = re.compile(r"^user>>>vpn-user-(\d+)>>>online$")
    scoped_online_re = re.compile(r"^user>>>vpn-(vmess|vless)-user-(\d+)>>>online$")

    def bucket(user_id: int) -> dict[str, int | bool | str]:
        return result.setdefault(user_id, {
            "uplink": 0, "downlink": 0, "online": 0,
            "online_supported": False, "traffic_supported": False,
            "traffic_source": "none",
        })

    def consume(name: str, value) -> None:
        try:
            number = max(0, int(value or 0))
        except (TypeError, ValueError):
            number = 0
        name = str(name or "")
        scoped = scoped_user_traffic_re.match(name)
        if scoped:
            row_protocol, raw_user_id, direction = scoped.groups()
            if protocol is not None and row_protocol != protocol:
                return
            target = bucket(int(raw_user_id))
            target[direction] = number
            target["traffic_supported"] = True
            target["traffic_source"] = "user"
            return
        match = legacy_user_traffic_re.match(name)
        if match:
            target = bucket(int(match.group(1)))
            target[match.group(2)] = number
            target["traffic_supported"] = True
            target["traffic_source"] = "user-legacy"
            return
        match = outbound_traffic_re.match(name)
        if match:
            target = bucket(int(match.group(1)))
            # Never overwrite canonical per-user counters with outbound rows.
            if target.get("traffic_source") != "user":
                target[match.group(2)] = number
                target["traffic_supported"] = True
                target["traffic_source"] = "outbound"
            return
        scoped = scoped_online_re.match(name)
        if scoped:
            row_protocol, raw_user_id = scoped.groups()
            if protocol is not None and row_protocol != protocol:
                return
            target = bucket(int(raw_user_id))
            target["online"] = number
            target["online_supported"] = True
            return
        match = legacy_online_re.match(name)
        if match:
            target = bucket(int(match.group(1)))
            target["online"] = number
            target["online_supported"] = True

    text = (raw or "").strip()
    if not text:
        return result
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = None
    if isinstance(payload, dict):
        rows = payload.get("stat") or payload.get("stats") or []
        if isinstance(rows, dict):
            rows = [rows]
        for row in rows if isinstance(rows, list) else []:
            if isinstance(row, dict):
                consume(row.get("name", ""), row.get("value", 0))
    elif isinstance(payload, list):
        for row in payload:
            if isinstance(row, dict):
                consume(row.get("name", ""), row.get("value", 0))

    if payload is None:
        for block in re.finditer(
            r'(?:stat\s*:\s*)?\{?[^{}]*?name\s*:\s*"([^"]+)"[^{}]*?(?:value\s*:\s*"?(\d+)"?)?[^{}]*?\}?',
            text, re.S,
        ):
            consume(block.group(1), block.group(2) or 0)
        for match in re.finditer(
            r'((?:user>>>vpn-(?:vmess|vless)-user-|user>>>vpn-user-|outbound>>>user-)\d+>>>(?:traffic>>>(?:uplink|downlink)|online))[^\n\r]*?(?:value\s*[:=]\s*)?(\d+)?\s*$',
            text, re.M,
        ):
            consume(match.group(1), match.group(2) or 0)
        # Protobuf text may use angle brackets instead of JSON braces.
        # Parse each line greedily so an optional value group cannot settle on
        # zero before reaching the actual ``value: N`` token.
        for line in text.splitlines():
            name_match = re.search(r'name\s*:\s*"([^"]+)"', line)
            if not name_match:
                continue
            value_match = re.search(r'value\s*:\s*"?(\d+)"?', line)
            consume(name_match.group(1), value_match.group(1) if value_match else 0)
    return result


def _stats(protocol: str) -> dict[int, dict[str, int | bool | str]]:
    # The official and most compatible form is a bare statsquery call. Some
    # Xray builds reject explicit --reset=false or pattern flag spellings, which
    # previously made the panel silently receive an empty snapshot forever.
    supported, raw = _run_api_variants(
        protocol,
        "statsquery",
        (
            ["statsquery"],
            ["statsquery", "--pattern", "user>>>"],
            ["statsquery", "-pattern", "user>>>"],
            ["statsquery", "--pattern=user>>>"],
            ["statsquery", "-pattern=user>>>"],
        ),
        timeout=3.5,
        cooldown_seconds=12.0,
    )
    _XRAY_STATS_SUPPORTED[protocol] = bool(supported)
    return _parse_stats_output(raw, protocol=protocol) if supported else {}


def xray_live_count(user_id: int, protocol: str) -> int:
    """Return a device-like Xray presence count, never a TCP-stream count.

    Xray's ``online`` statistic and listener socket table can report multiple
    concurrent TCP streams for one phone.  Counting those values as devices is
    what produced 11 phantom VLESS rows.  Public IP is the only stable
    transparent identity exposed by stock VMess/VLESS clients, so one
    protocol/public-IP pair is one visible session.  If Xray confirms activity
    but no peer IP is available, return a conservative single anonymous
    presence instead of the raw stream count.
    """
    if protocol not in PROTOCOLS:
        return 0
    key = (int(user_id), protocol)
    ips = {
        ip
        for raw_ip, _raw_port, _stamp in (_XRAY_LIVE_ENDPOINTS.get(key, []) or [])
        if (ip := _normalize_ip(raw_ip or ""))
    }
    if ips:
        return len(ips)
    return 1 if int(_XRAY_LIVE_COUNTS.get(key, 0) or 0) > 0 else 0


def _normalize_ip(value: str) -> str | None:
    """Normalize an IP or an IP:port token emitted by Xray/ss.

    Xray CLI output is not stable across releases: JSON, protobuf text, bracketed
    IPv6 and ``tcp:IP:port`` forms have all existed.  Keep brackets until the
    optional port is removed; the previous implementation stripped them too
    early and silently lost bracketed IPv6 peers.
    """
    candidate = (value or "").strip().strip("\"',;")
    if candidate.startswith(("tcp:", "udp:")):
        candidate = candidate[4:]
    if candidate.startswith("["):
        close = candidate.find("]")
        if close > 0:
            host = candidate[1:close]
            tail = candidate[close + 1:]
            if not tail or (tail.startswith(":") and tail[1:].isdigit()):
                candidate = host
    elif candidate.count(":") == 1:
        host, _, port = candidate.rpartition(":")
        if port.isdigit():
            candidate = host
    candidate = candidate.strip("[]")
    try:
        parsed = ipaddress.ip_address(candidate)
        if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
            return str(parsed.ipv4_mapped)
        return str(parsed)
    except ValueError:
        return None


def _extract_ips_from_api_output(raw: str) -> list[str]:
    """Parse online-IP output from JSON and protobuf-text Xray releases."""
    values: set[str] = set()
    raw = (raw or "").strip()
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = None

    def collect(value) -> None:
        if isinstance(value, dict):
            for item in value.values():
                collect(item)
        elif isinstance(value, (list, tuple, set)):
            for item in value:
                collect(item)
        elif isinstance(value, str):
            for token in re.split(r"[\s,]+", value.strip()):
                normalized = _normalize_ip(token)
                if normalized:
                    values.add(normalized)

    if data is not None:
        collect(data)

    # Current/older binaries may print protobuf text such as
    # ``ips: \"203.0.113.10\"`` instead of JSON.  Scan quoted and bare tokens,
    # but only accept values that ipaddress validates.
    for token in re.findall(
        r"(?:tcp:|udp:)?(?:\[[0-9A-Fa-f:.]+\](?::\d+)?|(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?|[0-9A-Fa-f:]{2,})",
        raw,
    ):
        normalized = _normalize_ip(token)
        if normalized:
            values.add(normalized)
    return sorted(values)


def _parse_online_count(raw: str) -> int | None:
    """Return an online count from JSON/protobuf text, or None if unparseable."""
    raw = (raw or "").strip()
    if not raw:
        return 0
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = None

    def walk(value):
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, (int, float)):
            return max(0, int(value))
        if isinstance(value, dict):
            # Prefer the canonical value field before recursively scanning.
            for key in ("value", "online", "count"):
                if key in value:
                    parsed = walk(value[key])
                    if parsed is not None:
                        return parsed
            for item in value.values():
                parsed = walk(item)
                if parsed is not None:
                    return parsed
        if isinstance(value, list):
            for item in value:
                parsed = walk(item)
                if parsed is not None:
                    return parsed
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
        return None

    parsed = walk(data) if data is not None else None
    if parsed is not None:
        return parsed
    match = re.search(r"(?:value|online|count)\s*[:=]\s*\"?(\d+)", raw, re.I)
    return int(match.group(1)) if match else None


def _run_xray_api(
    protocol: str,
    variants: Iterable[list[str]],
    *,
    capability: str,
    timeout: float = 1.4,
) -> tuple[bool, str]:
    return _run_api_variants(
        protocol, capability, variants, timeout=timeout, cooldown_seconds=45.0
    )


def _online_count_snapshot(protocol: str, user_id: int) -> tuple[bool, int]:
    email = _xray_email(protocol, user_id)
    supported, raw = _run_xray_api(protocol, (
        ["statsonline", "--email", email],
        ["statsonline", f"--email={email}"],
        ["statsonline", "-email", email],
    ), capability="statsonline")
    if not supported:
        return False, 0
    count = _parse_online_count(raw)
    return (count is not None), max(0, int(count or 0))


def _online_ip_snapshot(protocol: str, user_id: int) -> tuple[bool, list[str]]:
    """Return current online source IPs, preserving empty-success semantics."""
    email = _xray_email(protocol, user_id)
    supported, raw = _run_xray_api(protocol, (
        ["statsonlineiplist", "--email", email],
        ["statsonlineiplist", f"--email={email}"],
        ["statsonlineiplist", "-email", email],
    ), capability="statsonlineiplist")
    return supported, _extract_ips_from_api_output(raw) if supported else []


def _online_ips(protocol: str, user_id: int) -> list[str]:
    # Compatibility wrapper used by diagnostics and older tests.
    return _online_ip_snapshot(protocol, user_id)[1]

def _split_socket_endpoint(value: str) -> tuple[str, int] | None:
    value = (value or "").strip()
    if not value:
        return None
    if value.startswith("[") and "]:" in value:
        host, _, raw_port = value[1:].rpartition("]:")
    else:
        host, _, raw_port = value.rpartition(":")
    if not raw_port.isdigit():
        return None
    host = host.strip("[]")
    normalized = _normalize_ip(host)
    if normalized:
        host = normalized
    return host, int(raw_port)


def _decode_proc_socket_address(raw_host: str, *, ipv6: bool) -> str | None:
    """Decode the address layout used by /proc/net/tcp{,6}."""
    try:
        packed = bytes.fromhex(raw_host)
        if ipv6:
            if len(packed) != 16:
                return None
            # tcp6 stores four host-endian 32-bit words.
            packed = b"".join(packed[index:index + 4][::-1] for index in range(0, 16, 4))
            return _normalize_ip(socket.inet_ntop(socket.AF_INET6, packed))
        if len(packed) != 4:
            return None
        return _normalize_ip(socket.inet_ntoa(packed[::-1]))
    except (OSError, ValueError):
        return None


def _proc_established_endpoint_snapshot(port: int) -> tuple[bool, set[tuple[str, int]]]:
    """Kernel fallback when ``ss`` is missing, blocked, or formats output oddly.

    Xray's online API can retain an IP after the transport has disappeared.  A
    direct read of /proc/net/tcp is therefore a valuable authoritative signal
    and keeps the four-second offline check working even on minimal hosts.
    """
    peers: set[tuple[str, int]] = set()
    readable = False
    for path, ipv6 in ((Path("/proc/net/tcp"), False), (Path("/proc/net/tcp6"), True)):
        try:
            lines = path.read_text(encoding="ascii", errors="ignore").splitlines()[1:]
            readable = True
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 4 or parts[3] != "01":  # TCP_ESTABLISHED
                continue
            try:
                local_host, local_port_hex = parts[1].split(":", 1)
                remote_host, remote_port_hex = parts[2].split(":", 1)
                local_port = int(local_port_hex, 16)
                remote_port = int(remote_port_hex, 16)
            except (ValueError, IndexError):
                continue
            if local_port != int(port) or remote_port <= 0:
                continue
            remote_ip = _decode_proc_socket_address(remote_host, ipv6=ipv6)
            if remote_ip:
                peers.add((remote_ip, remote_port))
    return readable, peers


def _active_remote_endpoint_snapshot(port: int) -> tuple[bool, set[tuple[str, int]]]:
    """Return current source IP+port pairs connected to one Xray listener.

    ``ss`` remains the primary source, while /proc is always merged as a cheap
    independent fallback. Returning ``supported=True`` with an empty set is an
    authoritative "no established transport" result. Two consecutive
    five-second misses close the tracked Xray row within about ten seconds.
    """
    peers: set[tuple[str, int]] = set()
    ss_supported = False
    ss = shutil.which("ss") or "/usr/bin/ss"
    try:
        result = subprocess.run(
            [ss, "-Hnt", "state", "established"],
            capture_output=True, text=True, timeout=3, check=False,
        )
        if result.returncode == 0:
            ss_supported = True
            for line in (result.stdout or "").splitlines():
                parts = line.split()
                if len(parts) < 2:
                    continue
                local = _split_socket_endpoint(parts[-2])
                peer = _split_socket_endpoint(parts[-1])
                if local and peer and local[1] == int(port):
                    peers.add((peer[0], int(peer[1])))
    except (OSError, subprocess.TimeoutExpired):
        pass

    proc_supported, proc_peers = _proc_established_endpoint_snapshot(int(port))
    peers.update(proc_peers)
    return bool(ss_supported or proc_supported), peers


def _active_remote_ip_snapshot(port: int) -> tuple[bool, set[str]]:
    supported, endpoints = _active_remote_endpoint_snapshot(port)
    return supported, {ip for ip, _source_port in endpoints}


def _active_remote_ips(port: int) -> set[str]:
    return _active_remote_ip_snapshot(port)[1]

def _source_endpoint_from_access_line(line: str) -> tuple[str, int] | None:
    """Extract the original source IP and ephemeral port from an access line."""
    before = line.split(" accepted ", 1)[0]
    patterns = (
        r"(?:^|\s)from\s+(?:tcp:|udp:)?(\[[0-9a-fA-F:.]+\]|[0-9a-fA-F:.]+):(\d+)\s*$",
        r"(?:^|\s)(?:tcp:|udp:)?(\[[0-9a-fA-F:.]+\]|[0-9a-fA-F:.]+):(\d+)\s*$",
    )
    for pattern in patterns:
        match = re.search(pattern, before)
        if not match:
            continue
        normalized = _normalize_ip(match.group(1))
        port = int(match.group(2))
        if normalized and 1 <= port <= 65535:
            return normalized, port
    return None


def _access_line_belongs_to_user(line: str, user_id: int, protocol: str | None = None) -> bool:
    """Recognise one exact Xray user without accepting a sibling protocol.

    Dedicated access files remain the primary boundary, but upgrades, log
    rotation mistakes and reverse-proxy setups can leave mixed lines behind.
    Whenever a route annotation names an inbound, it must match the protocol
    being sampled.  Protocol-scoped emails are preferred; legacy emails remain
    readable only for the matching inbound during the transition.
    """
    uid = int(user_id)
    route = re.search(r"\[([^\]]+)\]", line)
    route_text = route.group(1).lower() if route else ""
    if protocol in PROTOCOLS:
        expected_inbound = f"{protocol}-in"
        sibling_inbound = f"{'vless' if protocol == 'vmess' else 'vmess'}-in"
        if sibling_inbound in route_text and expected_inbound not in route_text:
            return False
        scoped = _xray_email(protocol, uid)
        if scoped in line or re.search(rf"(?:email|user)\s*[:=]\s*[\"']?{re.escape(scoped)}(?:\b|[\"'])", line, re.I):
            return expected_inbound in route_text if route_text and ("vmess-in" in route_text or "vless-in" in route_text) else True
    legacy = f"vpn-user-{uid}"
    identity_match = bool(
        legacy in line
        or re.search(rf"(?:email|user)\s*[:=]\s*[\"']?{re.escape(legacy)}(?:\b|[\"'])", line, re.I)
    )
    if not identity_match:
        # Restrict outbound-tag matching to the route annotation.
        identity_match = bool(route and re.search(rf"(?:^|\s)(?:>>|->)\s*user-{uid}(?:\s|$)", route_text))
    if not identity_match:
        return False
    if protocol in PROTOCOLS and route_text and ("vmess-in" in route_text or "vless-in" in route_text):
        return f"{protocol}-in" in route_text
    return True


def _recent_log_endpoints(
    protocol: str, user_id: int, max_lines: int = 4000, max_age_seconds: int | None = 12,
) -> list[tuple[str, int, datetime]]:
    path = XRAY_LOG_ROOT / f"{protocol}-access.log"
    if not path.is_file():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-max_lines:]
    except OSError:
        return []
    cutoff = datetime.utcnow() - timedelta(seconds=max_age_seconds) if max_age_seconds else None
    stamp_re = re.compile(r"^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)")
    found: dict[tuple[str, int], datetime] = {}
    for line in lines:
        if " accepted " not in line or not _access_line_belongs_to_user(line, user_id, protocol):
            continue
        stamp_match = stamp_re.match(line)
        try:
            stamp = datetime.strptime(stamp_match.group(1), "%Y/%m/%d %H:%M:%S.%f" if "." in stamp_match.group(1) else "%Y/%m/%d %H:%M:%S") if stamp_match else datetime.utcnow()
        except ValueError:
            stamp = datetime.utcnow()
        if cutoff is not None and stamp < cutoff:
            continue
        endpoint = _source_endpoint_from_access_line(line)
        if endpoint:
            found[endpoint] = min(found.get(endpoint, stamp), stamp)
    return [(ip, port, found[(ip, port)]) for ip, port in sorted(found, key=lambda item: found[item])]


def _recent_log_activity_summary(
    protocol: str,
    user_id: int,
    max_lines: int = 12000,
    max_age_seconds: int | None = 45,
) -> tuple[datetime | None, int]:
    """Return the newest access event and event count for one Xray identity.

    This is queried only while a brand-new endpoint is awaiting confirmation,
    so normal confirmed-session sampling keeps the previous cost profile.
    """
    path = XRAY_LOG_ROOT / f"{protocol}-access.log"
    if not path.is_file():
        return None, 0
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-max_lines:]
    except OSError:
        return None, 0
    cutoff = datetime.utcnow() - timedelta(seconds=max_age_seconds) if max_age_seconds else None
    stamp_re = re.compile(r"^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)")
    latest: datetime | None = None
    count = 0
    for line in lines:
        if " accepted " not in line or not _access_line_belongs_to_user(line, user_id, protocol):
            continue
        stamp_match = stamp_re.match(line)
        if not stamp_match:
            continue
        raw = stamp_match.group(1)
        try:
            fmt = "%Y/%m/%d %H:%M:%S.%f" if "." in raw else "%Y/%m/%d %H:%M:%S"
            stamp = datetime.strptime(raw, fmt)
        except ValueError:
            continue
        if cutoff is not None and stamp < cutoff:
            continue
        if _source_endpoint_from_access_line(line) is None:
            continue
        count += 1
        if latest is None or stamp > latest:
            latest = stamp
    return latest, count


def _source_ip_from_access_line(line: str) -> str | None:
    """Extract the client source IP from known Xray access-log layouts."""
    # Current Xray examples include either:
    #   from tcp:1.2.3.4:1234 accepted ... email: user
    #   from 1.2.3.4:1234 accepted ... email: user
    #   1.2.3.4:1234 accepted ... email: user
    # IPv6 can be bracketed or unbracketed. Restrict the search to the portion
    # before " accepted " so destination endpoints are never mistaken as clients.
    before = line.split(" accepted ", 1)[0]
    patterns = (
        r"(?:^|\s)from\s+(?:tcp:|udp:)?(\[[0-9a-fA-F:.]+\]|[0-9a-fA-F:.]+):\d+\s*$",
        r"(?:^|\s)(?:tcp:|udp:)?(\[[0-9a-fA-F:.]+\]|[0-9a-fA-F:.]+):\d+\s*$",
    )
    for pattern in patterns:
        match = re.search(pattern, before)
        if match:
            normalized = _normalize_ip(match.group(1))
            if normalized:
                return normalized
    return None


def _recent_log_ips(
    protocol: str,
    user_id: int,
    max_lines: int = 2500,
    max_age_seconds: int | None = None,
) -> list[str]:
    """Return source IPs from Xray access records for one panel user.

    The parser supports both the old and current access-log layouts. The caller
    intersects historical addresses with live kernel sockets before using them as
    a persistent online signal, preventing a stale log line from keeping a user
    online forever.
    """
    path = XRAY_LOG_ROOT / f"{protocol}-access.log"
    if not path.is_file():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-max_lines:]
    except OSError:
        return []
    cutoff = datetime.utcnow() - timedelta(seconds=max_age_seconds) if max_age_seconds else None
    ips: set[str] = set()
    stamp_re = re.compile(r"^(\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?)")
    for line in lines:
        if " accepted " not in line or not _access_line_belongs_to_user(line, user_id, protocol):
            continue
        if cutoff is not None:
            stamp_match = stamp_re.match(line)
            if not stamp_match:
                continue
            raw = stamp_match.group(1)
            try:
                fmt = "%Y/%m/%d %H:%M:%S.%f" if "." in raw else "%Y/%m/%d %H:%M:%S"
                if datetime.strptime(raw, fmt) < cutoff:
                    continue
            except ValueError:
                continue
        source_ip = _source_ip_from_access_line(line)
        if source_ip:
            ips.add(source_ip)
    return sorted(ips)


def set_xray_internet_block(db: Session, user: VpnUser, protocol: str, blocked: bool) -> bool:
    """Apply an identity-wide Xray blackhole and close old routed streams.

    RoutingService rules affect newly-routed streams, but an already established
    outbound may continue until it closes. To make the panel button deterministic,
    the selected VMess/VLESS service is restarted after the static config is
    written. Clients may reconnect immediately; the identity then remains
    connected at transport level but all internet streams route to blackhole.
    """
    if protocol not in PROTOCOLS:
        raise ValueError("Unsupported Xray protocol")
    old_value = bool(getattr(user, f"{protocol}_internet_blocked", False))
    wanted = bool(blocked)
    setattr(user, f"{protocol}_internet_blocked", wanted)
    try:
        db.flush()
        target = write_config(db, protocol)
        valid, detail = validate_config(target)
        if not valid:
            raise RuntimeError(f"Xray config validation failed: {detail}")

        # Best-effort live update reduces the interruption window. The service
        # restart below is still required to terminate pre-existing routed flows.
        if wanted:
            _add_internet_block_rule(protocol, int(user.id))
        else:
            _remove_internet_block_rule(protocol, int(user.id))

        if _bool(db, f"{protocol}_enabled", False):
            ok, output = _systemctl("restart", protocol)
            if not ok:
                raise RuntimeError(output or "Xray restart failed while applying internet access rule")
            ready, health = _wait_ready(protocol, get_protocol_settings(db, protocol)["port"], timeout=18.0)
            if not ready:
                raise RuntimeError(health)

        # The static Xray routing rule is authoritative. The fwmark/nftables
        # layer is only a defence-in-depth accelerator and is not available on
        # every kernel/container. Never roll back a working Xray blackhole just
        # because that optional layer cannot be installed.
        try:
            from app.services.rate_limiter import reconcile_shared_rate_limits, xray_internet_block_installed
            nft_ok = bool(reconcile_shared_rate_limits(db, force=True))
            verified = bool(xray_internet_block_installed(int(user.id), protocol, wanted)) if nft_ok else False
            if not nft_ok or not verified:
                logger.warning(
                    "Optional nftables Xray internet-block verification failed; static routing remains active "
                    "user_id=%s protocol=%s wanted=%s nft_ok=%s verified=%s",
                    int(user.id), protocol, wanted, nft_ok, verified,
                )
        except Exception:
            logger.exception(
                "Optional nftables Xray internet-block layer failed; static routing remains active "
                "user_id=%s protocol=%s wanted=%s",
                int(user.id), protocol, wanted,
            )

        db.commit()
        return wanted
    except Exception:
        db.rollback()
        current = db.query(VpnUser).filter(VpnUser.id == int(user.id)).first()
        if current is not None:
            setattr(current, f"{protocol}_internet_blocked", old_value)
            db.commit()
            try:
                write_config(db, protocol)
                if _bool(db, f"{protocol}_enabled", False):
                    _systemctl("restart", protocol)
            except Exception:
                logger.exception("Failed to restore Xray internet rule after rollback")
        raise

def _dedupe_active_xray_logs(db: Session, user_id: int, protocol: str, now: datetime) -> list[ConnectionLog]:
    """Collapse Xray TCP streams into one public-IP session row.

    Source ports are intentionally ignored: browsers, mobile clients and mux
    implementations routinely open several ephemeral TCP streams for one
    device.  Existing 2.3.73 rows are repaired in-place on the first five-second
    sampling pass after upgrade.
    """
    rows = (
        db.query(ConnectionLog)
        .filter(
            ConnectionLog.user_id == int(user_id),
            ConnectionLog.protocol == protocol,
            ConnectionLog.is_online == True,  # noqa: E712
        )
        .order_by(ConnectionLog.connect_time.asc(), ConnectionLog.id.asc())
        .all()
    )
    concrete = {_normalize_ip(row.ip_address or "") for row in rows if _normalize_ip(row.ip_address or "")}
    kept: dict[str, ConnectionLog] = {}
    result: list[ConnectionLog] = []
    for row in rows:
        normalized = _normalize_ip(row.ip_address or "")
        # Once a concrete peer is known, an old anonymous placeholder is stale.
        if not normalized and concrete:
            row.is_online = False
            row.disconnect_time = row.disconnect_time or now
            continue
        key = normalized or "*"
        previous = kept.get(key)
        if previous is None:
            # Keep one representative live source port for protocol-safe socket
            # matching. It is not part of the device fingerprint or max-device
            # count; it only prevents a socket from a sibling protocol/user on
            # the same public IP from keeping this row alive.
            row.device_fingerprint = _xray_endpoint_fingerprint(protocol, normalized or None, None)
            kept[key] = row
            result.append(row)
            continue
        previous.bytes_in = max(int(previous.bytes_in or 0), int(row.bytes_in or 0))
        previous.bytes_out = max(int(previous.bytes_out or 0), int(row.bytes_out or 0))
        if not int(getattr(previous, "source_port", 0) or 0) and int(getattr(row, "source_port", 0) or 0):
            previous.source_port = int(row.source_port)
        previous.last_seen_at = max(
            [value for value in (previous.last_seen_at, row.last_seen_at) if value],
            default=previous.last_seen_at,
        )
        row.is_online = False
        row.presence_state = "offline"
        row.presence_failures = max(2, int(getattr(row, "presence_failures", 0) or 0))
        row.disconnect_time = row.disconnect_time or now
        row.device_limit_blocked = False
    return result

def _xray_endpoint_fingerprint(protocol: str, ip_address: str | None, source_port: int | None) -> str:
    # A TCP source port identifies one stream, not one device.  Keep it out of
    # the persistent session identity even when old rows still contain it.
    ip = _normalize_ip(ip_address or "") or "unknown"
    return f"xray:{protocol}:{ip}"


def _pending_endpoint_key(user_id: int, protocol: str, ip_address: str | None) -> tuple[int, str, str]:
    return int(user_id), str(protocol), (_normalize_ip(ip_address or "") or "unknown")


def _pending_endpoint_confirmed(
    user_id: int,
    protocol: str,
    ip_address: str | None,
    *,
    traffic_total: int,
    activity_latest: datetime | None,
    activity_count: int,
    observed_at: float,
    require_access_event: bool = False,
) -> bool:
    """Promote a new Xray identity only after post-debounce real activity.

    A one-shot latency test can leave an established transport or a stale Xray
    online bit behind. Socket presence alone is therefore insufficient for a
    *new* visible session. The first observation establishes a baseline; later
    byte growth or a newer access-log event confirms actual continued use.
    """
    key = _pending_endpoint_key(user_id, protocol, ip_address)
    current_total = max(0, int(traffic_total or 0))
    current_count = max(0, int(activity_count or 0))
    current_latest = activity_latest.timestamp() if activity_latest else 0.0
    state = _XRAY_PENDING_ENDPOINTS.get(key)
    if state is None:
        _XRAY_PENDING_ENDPOINTS[key] = {
            "first_seen": float(observed_at),
            "traffic_total": current_total,
            "activity_latest": current_latest,
            "activity_count": current_count,
            "last_seen": float(observed_at),
        }
        return False

    raw_first_seen = state.get("first_seen")
    first_seen = float(observed_at if raw_first_seen is None else raw_first_seen)
    previous_total = max(0, int(state.get("traffic_total", 0) or 0))
    previous_latest = float(state.get("activity_latest", 0.0) or 0.0)
    previous_count = max(0, int(state.get("activity_count", 0) or 0))
    access_advanced = bool(
        current_latest > previous_latest
        or (current_latest == previous_latest and current_count > previous_count)
    )
    traffic_advanced = current_total > previous_total
    activity_advanced = access_advanced or traffic_advanced
    state.update({
        "traffic_total": current_total,
        "activity_latest": current_latest,
        "activity_count": current_count,
        "last_seen": float(observed_at),
    })
    # Do not promote activity that happened only during the initial latency
    # probe. It must still be advancing after the debounce window while the
    # exact transport is present. This is what separates a pooled ping socket
    # from a tunnel that is actually being used.
    # When the same public IP is already confirmed on the sibling Xray
    # protocol, byte counters alone are not protocol-safe evidence: some Xray
    # builds leak those counters across VMess/VLESS identities.  In that case
    # require a second, protocol-scoped accepted access event after debounce.
    # This prevents a real VMess tunnel from being published as VLESS (or the
    # reverse) and then being killed by the shared max-device limiter.
    confirmation_advanced = access_advanced if require_access_event else activity_advanced
    if confirmation_advanced and float(observed_at) - first_seen >= XRAY_ONLINE_CONFIRM_SECONDS:
        _XRAY_PENDING_ENDPOINTS.pop(key, None)
        return True
    return False


def _cleanup_pending_xray_endpoints(seen: set[tuple[int, str, str]], observed_at: float) -> None:
    cutoff = float(observed_at) - XRAY_PENDING_ENDPOINT_TTL_SECONDS
    for key, state in list(_XRAY_PENDING_ENDPOINTS.items()):
        if key not in seen or float(state.get("last_seen", 0.0) or 0.0) < cutoff:
            _XRAY_PENDING_ENDPOINTS.pop(key, None)


def _clear_pending_xray_endpoints(user_id: int, protocol: str | None = None) -> None:
    for key in list(_XRAY_PENDING_ENDPOINTS):
        if key[0] == int(user_id) and (protocol is None or key[1] == protocol):
            _XRAY_PENDING_ENDPOINTS.pop(key, None)


def _mark_xray_log_present(
    log: ConnectionLog,
    now: datetime,
    *,
    active: bool,
    identity_verified: bool = False,
    strong_protocol_evidence: bool = False,
    transport_ip_address: str | None = None,
    transport_source_port: int | None = None,
) -> None:
    log.is_online = True
    log.disconnect_time = None
    log.presence_failures = 0
    log.presence_state = "active" if active else "idle"
    log.last_seen_at = now
    if identity_verified:
        log.identity_verified = True
    if transport_ip_address:
        log.transport_ip_address = _normalize_ip(transport_ip_address) or transport_ip_address
    if transport_source_port:
        log.transport_source_port = int(transport_source_port)
    if strong_protocol_evidence:
        log.protocol_evidence_at = now
    if active:
        log.last_activity_at = now


def _xray_log_has_strong_protocol_evidence(log: ConnectionLog) -> bool:
    """Return whether a row was attributed by an exact protocol transport.

    ``identity_verified`` existed in older releases and may already be true on
    a phantom sibling row.  The evidence timestamp was introduced in 2.3.87;
    requiring both fields makes old ambiguous VMess/VLESS rows harmless until
    the exact listener/access-log pair verifies them again.
    """
    return bool(
        getattr(log, "identity_verified", False)
        and getattr(log, "protocol_evidence_at", None)
    )


def _xray_log_transport_endpoint(log: ConnectionLog) -> tuple[str, int] | None:
    """Return the exact kernel transport endpoint stored for one Xray row."""
    transport_ip = _normalize_ip(str(getattr(log, "transport_ip_address", "") or ""))
    transport_port = int(getattr(log, "transport_source_port", 0) or 0)
    if transport_ip and transport_port > 0:
        return transport_ip, transport_port

    # Direct-listener upgrade path for rows created before 2.3.87.  This is
    # safe only when both the public IP and exact source port were stored.
    row_ip = _normalize_ip(log.ip_address or "")
    row_port = int(getattr(log, "source_port", 0) or 0)
    if row_ip and row_port > 0:
        return row_ip, row_port
    return None


def _mark_xray_log_missing(log: ConnectionLog, now: datetime) -> bool:
    """Record one failed presence probe; close only on the second miss."""
    failures = int(getattr(log, "presence_failures", 0) or 0) + 1
    log.presence_failures = failures
    if failures >= XRAY_PRESENCE_FAILURE_LIMIT:
        log.presence_state = "offline"
        log.is_online = False
        log.disconnect_time = log.disconnect_time or now
        log.device_limit_blocked = False
        return True
    log.presence_state = "probing"
    return False


def fast_reconcile_xray_presence(db: Session) -> int:
    """Retire disconnected VMess/VLESS rows from exact kernel transports.

    This path deliberately does not query Xray statistics and never creates a
    session.  It only validates the exact protocol/listener endpoint already
    recorded by the full sampler.  Therefore it can run every two seconds even
    while accounting is busy, without the VMess/VLESS sibling-attribution race
    that previously forced it to share the heavy sampler lock. Two misses close
    a disconnected row in about four seconds.
    """
    now = datetime.utcnow()
    logs = (
        db.query(ConnectionLog)
        .filter(ConnectionLog.protocol.in_(PROTOCOLS), ConnectionLog.is_online == True)  # noqa: E712
        .order_by(ConnectionLog.protocol.asc(), ConnectionLog.user_id.asc(), ConnectionLog.id.asc())
        .all()
    )
    changed = 0
    live_peers: dict[int, dict[str, set[str]]] = {}

    by_protocol: dict[str, list[ConnectionLog]] = {protocol: [] for protocol in PROTOCOLS}
    for log in logs:
        if log.protocol in by_protocol:
            by_protocol[log.protocol].append(log)

    for protocol, protocol_logs in by_protocol.items():
        if not protocol_logs:
            continue
        try:
            listener_port = int(get_protocol_settings(db, protocol).get("port") or 0)
        except (TypeError, ValueError):
            listener_port = 0
        socket_supported, socket_endpoints = (
            _active_remote_endpoint_snapshot(listener_port) if listener_port > 0 else (False, set())
        )
        if not socket_supported:
            # An unavailable proc/ss probe is not evidence of disconnect. The
            # next two-second pass will retry rather than creating false drops.
            continue

        for log in protocol_logs:
            endpoint = _xray_log_transport_endpoint(log) if _xray_log_has_strong_protocol_evidence(log) else None
            present = bool(endpoint and endpoint in socket_endpoints)
            old = (bool(log.is_online), str(log.presence_state or ''), int(log.presence_failures or 0))
            if present:
                _mark_xray_log_present(
                    log, now, active=True, identity_verified=True,
                    strong_protocol_evidence=True,
                    transport_ip_address=endpoint[0], transport_source_port=endpoint[1],
                )
                public_ip = _normalize_ip(log.ip_address or "")
                if public_ip:
                    live_peers.setdefault(int(log.user_id), {}).setdefault(protocol, set()).add(public_ip)
            else:
                _mark_xray_log_missing(log, now)
            current = (bool(log.is_online), str(log.presence_state or ''), int(log.presence_failures or 0))
            if current != old:
                changed += 1

    # Release max-device slots/rules immediately after the second miss. The
    # dedicated lock serialises only admission state; accounting may continue.
    with _XRAY_MAX_DEVICE_LOCK:
        _reconcile_xray_max_devices(db, live_peers, now)
    return changed


def _sample_xray_traffic_impl(db: Session) -> int:
    """Synchronise Xray counters and live VMess/VLESS sessions.

    Presence is now resolved every scheduler tick from *current* Xray online
    state and the current kernel socket snapshot. Traffic deltas are still used
    for accounting, but never keep a disconnected user online by themselves
    when a reliable online signal is available.
    """
    updates = 0
    now = datetime.utcnow()
    observed_at = time.monotonic()
    pending_seen: set[tuple[int, str, str]] = set()
    _XRAY_LIVE_COUNTS.clear()
    _XRAY_LIVE_ENDPOINTS.clear()
    banned = {normalized for normalized in (_normalize_ip(row.ip_address) for row in db.query(BannedIP).all()) if normalized}
    # user_id -> protocol -> live source IPs. Max-device enforcement is applied
    # after both VMess and VLESS have been sampled so the limit is shared.
    live_peers: dict[int, dict[str, set[str]]] = {}
    # nftables counters are a reliable accounting fallback when the installed
    # Xray CLI exposes no per-user StatsService rows. They are read once per
    # sampling pass so this does not add one shell call per user.
    try:
        from app.services.rate_limiter import xray_nft_usage_snapshot
        nft_usage = xray_nft_usage_snapshot()
    except Exception:
        logger.exception("Failed to read Xray nft accounting counters")
        nft_usage = {}

    for protocol in PROTOCOLS:
        globally_enabled = _bool(db, f"{protocol}_enabled", False)
        if not globally_enabled:
            for log in db.query(ConnectionLog).filter(
                ConnectionLog.protocol == protocol,
                ConnectionLog.is_online == True,  # noqa: E712
            ).all():
                log.is_online = False
                log.disconnect_time = log.disconnect_time or now
            continue

        settings = get_protocol_settings(db, protocol)
        stats = _stats(protocol)
        # Keep the legacy IP snapshot call as the primary availability signal
        # (also used by diagnostics/tests), then enrich it with source ports.
        socket_supported, _socket_ips = _active_remote_ip_snapshot(int(settings["port"]))
        endpoint_supported, socket_endpoints = _active_remote_endpoint_snapshot(int(settings["port"]))
        if endpoint_supported and socket_endpoints:
            socket_supported = True
        elif not endpoint_supported:
            socket_endpoints = set()
        users = (
            db.query(VpnUser)
            .filter(getattr(VpnUser, f"enable_{protocol}") == True)  # noqa: E712
            .order_by(VpnUser.id)
            .all()
        )
        seen_online: set[int] = set()

        for user in users:
            stats_values = dict(stats.get(user.id) or {})
            nft_values = nft_usage.get((int(user.id), protocol))
            values = {
                "uplink": int(stats_values.get("uplink", 0) or 0),
                "downlink": int(stats_values.get("downlink", 0) or 0),
                "online": int(stats_values.get("online", 0) or 0),
                "online_supported": bool(stats_values.get("online_supported", False)),
                "traffic_supported": bool(stats_values.get("traffic_supported", False)),
                "traffic_source": str(stats_values.get("traffic_source", "none") or "none"),
            }
            counter = (
                db.query(XrayUsageCounter)
                .filter(XrayUsageCounter.user_id == user.id, XrayUsageCounter.protocol == protocol)
                .first()
            )
            counter_created = counter is None
            if not counter:
                counter = XrayUsageCounter(
                    user_id=user.id, protocol=protocol, last_uplink=0, last_downlink=0,
                    last_nft_uplink=0, last_nft_downlink=0,
                )
                db.add(counter)
            elif (
                str(getattr(counter, "usage_source", "") or "") == "nft"
                and int(getattr(counter, "last_nft_uplink", 0) or 0) == 0
                and int(getattr(counter, "last_nft_downlink", 0) or 0) == 0
                and (int(counter.last_uplink or 0) > 0 or int(counter.last_downlink or 0) > 0)
            ):
                # Upgrade path from 2.3.67: its generic baseline contained nft
                # counters. Seed the new dedicated columns from that value so
                # the update cannot count the whole existing counter twice.
                counter.last_nft_uplink = int(counter.last_uplink or 0)
                counter.last_nft_downlink = int(counter.last_downlink or 0)

            # Maintain independent baselines for Xray and nftables. A single
            # shared baseline silently lost traffic whenever StatsService became
            # available/unavailable between two four-second samples.
            xray_uplink = max(0, int(values.get("uplink", 0) or 0))
            xray_downlink = max(0, int(values.get("downlink", 0) or 0))
            nft_uplink = max(0, int((nft_values or {}).get("uplink", 0) or 0))
            nft_downlink = max(0, int((nft_values or {}).get("downlink", 0) or 0))

            delta_xray_up = xray_uplink - int(counter.last_uplink or 0) if xray_uplink >= int(counter.last_uplink or 0) else xray_uplink
            delta_xray_down = xray_downlink - int(counter.last_downlink or 0) if xray_downlink >= int(counter.last_downlink or 0) else xray_downlink
            delta_nft_up = nft_uplink - int(getattr(counter, "last_nft_uplink", 0) or 0) if nft_uplink >= int(getattr(counter, "last_nft_uplink", 0) or 0) else nft_uplink
            delta_nft_down = nft_downlink - int(getattr(counter, "last_nft_downlink", 0) or 0) if nft_downlink >= int(getattr(counter, "last_nft_downlink", 0) or 0) else nft_downlink

            counter.last_uplink = xray_uplink
            counter.last_downlink = xray_downlink
            counter.last_nft_uplink = nft_uplink
            counter.last_nft_downlink = nft_downlink

            # A freshly-created runtime row establishes a baseline rather than
            # charging all traffic accumulated since the Xray service started.
            if counter_created:
                delta = 0
                counter.usage_source = (
                    "xray" if values.get("traffic_source") == "user"
                    else "nft" if nft_values is not None
                    else "xray-outbound" if values.get("traffic_supported")
                    else "none"
                )
                uplink = nft_uplink if nft_values is not None and values.get("traffic_source") != "user" else xray_uplink
                downlink = nft_downlink if nft_values is not None and values.get("traffic_source") != "user" else xray_downlink
            # Canonical user stats are authoritative. Outbound-only stats on
            # Xray 26.x can exist but remain zero; prefer nft accounting there.
            elif values.get("traffic_source") == "user":
                delta = max(0, delta_xray_up) + max(0, delta_xray_down)
                counter.usage_source = "xray"
                uplink, downlink = xray_uplink, xray_downlink
            elif nft_values is not None:
                delta = max(0, delta_nft_up) + max(0, delta_nft_down)
                counter.usage_source = "nft"
                uplink, downlink = nft_uplink, nft_downlink
            elif values.get("traffic_supported"):
                delta = max(0, delta_xray_up) + max(0, delta_xray_down)
                counter.usage_source = "xray-outbound"
                uplink, downlink = xray_uplink, xray_downlink
            else:
                delta = 0
                uplink = downlink = 0
            if delta:
                user.used_bytes = int(user.used_bytes or 0) + delta
                counter.last_activity_at = now
                updates += 1
            counter.updated_at = now

            existing_logs = _dedupe_active_xray_logs(db, user.id, protocol, now)

            stats_count_supported = bool(values.get("online_supported", False))
            stats_online_count = max(0, int(values.get("online", 0) or 0))
            pre_activity_recent = bool(
                delta > 0 or (
                    counter.last_activity_at
                    and (now - counter.last_activity_at).total_seconds() <= max(4, XRAY_ACTIVITY_GRACE_SECONDS)
                )
            )
            # One statsquery call covers all identities. Only run the heavier
            # per-user IP API for identities that may currently be online or
            # need an existing row verified. This keeps the 4-second monitor
            # responsive even with many accounts.
            need_identity_probe = (
                not stats_count_supported
                or stats_online_count > 0
                or bool(existing_logs)
                or pre_activity_recent
            )
            if need_identity_probe:
                _api_supported, api_ips_raw = _online_ip_snapshot(protocol, user.id)
            else:
                _api_supported, api_ips_raw = True, []
            if stats_count_supported:
                direct_count_supported, direct_online_count = False, 0
            else:
                direct_count_supported, direct_online_count = _online_count_snapshot(protocol, user.id)

            def usable_peer(raw: str | None) -> str | None:
                normalized = _normalize_ip(raw or "")
                if not normalized:
                    return None
                try:
                    if ipaddress.ip_address(normalized).is_loopback:
                        return None
                except ValueError:
                    return None
                return normalized

            api_ips = sorted({value for value in (usable_peer(ip) for ip in api_ips_raw) if value})
            online_count = max(direct_online_count if direct_count_supported else 0, stats_online_count if stats_count_supported else 0)
            _XRAY_LIVE_COUNTS[(int(user.id), protocol)] = int(online_count)

            # A fresh row must have an exact endpoint from this protocol's own
            # access log and that endpoint must still exist on this protocol's
            # listener. For a reverse proxy the access log endpoint is normally
            # loopback; store that exact loopback IP+port separately from the
            # public client IP returned by the protocol-specific API.
            recent_access_rows = _recent_log_endpoints(
                protocol, user.id, max_lines=12000, max_age_seconds=20
            )
            direct_access: list[tuple[str, int, datetime]] = []
            proxy_access: list[tuple[str, int, datetime]] = []
            for raw_ip, raw_port, stamp in recent_access_rows:
                transport_ip = _normalize_ip(raw_ip or "")
                transport_port = int(raw_port or 0)
                if not transport_ip or transport_port <= 0:
                    continue
                if socket_supported and (transport_ip, transport_port) not in socket_endpoints:
                    continue
                try:
                    is_loopback_transport = ipaddress.ip_address(transport_ip).is_loopback
                except ValueError:
                    continue
                target = proxy_access if is_loopback_transport else direct_access
                target.append((transport_ip, transport_port, stamp))

            endpoint_map: dict[tuple[str, int], datetime] = {}
            transport_map: dict[tuple[str, int], tuple[str, int, bool]] = {}

            for public_ip, public_port, stamp in direct_access:
                key = (public_ip, int(public_port))
                previous = endpoint_map.get(key)
                if previous is None or stamp < previous:
                    endpoint_map[key] = stamp
                    transport_map[key] = (public_ip, int(public_port), True)

            # Map an exact loopback transport to the real public identity. The
            # API may supply the public IP, but it can never keep/create a row
            # without the exact access-log/socket pair below.
            if proxy_access:
                public_candidates = list(api_ips)
                if not public_candidates:
                    # API-less continuity: an already-strong row may retain its
                    # public identity only when its stored exact proxy transport
                    # is still one of the current access-log/socket endpoints.
                    proxy_keys = {(ip, port) for ip, port, _stamp in proxy_access}
                    public_candidates = sorted({
                        ip for log in existing_logs
                        if _xray_log_has_strong_protocol_evidence(log)
                        and _xray_log_transport_endpoint(log) in proxy_keys
                        and (ip := usable_peer(log.ip_address))
                    })
                if public_candidates:
                    ordered_proxy = sorted(proxy_access, key=lambda item: item[2])
                    for index, public_ip in enumerate(public_candidates):
                        transport_ip, transport_port, stamp = ordered_proxy[min(index, len(ordered_proxy) - 1)]
                        key = (public_ip, 0)
                        endpoint_map.setdefault(key, stamp)
                        transport_map[key] = (transport_ip, transport_port, True)

            # Preserve an established direct/proxy tunnel only through the exact
            # transport previously recorded for this exact protocol. A generic
            # loopback socket plus a stale online bit is no longer accepted.
            for log in existing_logs:
                if not _xray_log_has_strong_protocol_evidence(log):
                    continue
                public_ip = usable_peer(log.ip_address)
                transport_endpoint = _xray_log_transport_endpoint(log)
                if not public_ip or not transport_endpoint:
                    continue
                if not socket_supported or transport_endpoint not in socket_endpoints:
                    continue
                try:
                    transport_is_loopback = ipaddress.ip_address(transport_endpoint[0]).is_loopback
                except ValueError:
                    continue
                public_port = 0 if transport_is_loopback else int(getattr(log, "source_port", 0) or transport_endpoint[1])
                key = (public_ip, public_port)
                endpoint_map.setdefault(key, log.connect_time or now)
                transport_map.setdefault(key, (transport_endpoint[0], transport_endpoint[1], True))

            live_endpoint_rows = [
                (ip, port or None, endpoint_map[(ip, port)])
                for ip, port in sorted(endpoint_map, key=lambda value: endpoint_map[value])
            ]
            mapped_socket_ips = [ip for ip, _port, _stamp in live_endpoint_rows]
            _XRAY_LIVE_ENDPOINTS[(int(user.id), protocol)] = live_endpoint_rows

            # A live kernel socket is the authoritative transport signal. The
            # per-user Xray APIs identify who owns that socket.  When an older
            # build/proxy topology cannot return the IP, a positive online count
            # or fresh byte delta may map the single live identity without
            # letting stale counters keep a disconnected user online.

            # Only endpoints attributed to this exact protocol/user may create
            # or preserve a row. Raw online counters, traffic deltas, and an IP
            # returned by a sibling-prone API are diagnostics only.
            online = bool(live_endpoint_rows)
            ips = mapped_socket_ips

            if _forced_disconnect_suppressed(user.id, protocol, ips):
                online = False

            if online and _eligible(user, protocol, local_enabled=local_assignment_enabled(db)):
                normalized_ips = [ip for ip in (_normalize_ip(value or "") for value in ips) if ip]
                blocked_ips = [ip for ip in normalized_ips if ip in banned]
                for blocked_ip in blocked_ips:
                    disconnect_xray_session(db, user.username, protocol=protocol, ip_address=blocked_ip)
                allowed_ips = [ip for ip in normalized_ips if ip not in banned]
                if normalized_ips and not allowed_ips:
                    online = False

            if online and _eligible(user, protocol, local_enabled=local_assignment_enabled(db)):
                if live_endpoint_rows:
                    allowed_endpoints = [
                        (ip, port, stamp) for ip, port, stamp in live_endpoint_rows
                        if ip not in banned
                    ]
                else:
                    if not allowed_ips:
                        allowed_ips = [""]
                    allowed_endpoints = [(ip, None, now) for ip in dict.fromkeys(allowed_ips)]

                desired_fingerprints = {
                    _xray_endpoint_fingerprint(protocol, ip, source_port)
                    for ip, source_port, _stamp in allowed_endpoints
                }
                existing_by_fingerprint: dict[str, ConnectionLog] = {}
                for log in existing_logs:
                    fingerprint = str(getattr(log, "device_fingerprint", "") or "") or _xray_endpoint_fingerprint(
                        protocol, log.ip_address, getattr(log, "source_port", None)
                    )
                    log.device_fingerprint = fingerprint
                    if fingerprint not in desired_fingerprints:
                        _mark_xray_log_missing(log, now)
                    elif log.is_online:
                        existing_by_fingerprint.setdefault(fingerprint, log)
                        _XRAY_PENDING_ENDPOINTS.pop(
                            _pending_endpoint_key(user.id, protocol, log.ip_address), None
                        )

                # Read the access log a second time only while at least one new
                # identity is waiting for confirmation. Confirmed users retain
                # the old one-pass sampling cost.
                new_fingerprints = desired_fingerprints - set(existing_by_fingerprint)
                activity_latest, activity_count = (
                    _recent_log_activity_summary(protocol, user.id)
                    if new_fingerprints else (None, 0)
                )
                traffic_total = max(
                    max(0, int(uplink or 0)) + max(0, int(downlink or 0)),
                    max(0, int(xray_uplink or 0)) + max(0, int(xray_downlink or 0)),
                    max(0, int(nft_uplink or 0)) + max(0, int(nft_downlink or 0)),
                )
                confirmed_new: set[str] = set()
                representative_ip: dict[str, str | None] = {}
                for ip, source_port, _stamp in allowed_endpoints:
                    fingerprint = _xray_endpoint_fingerprint(protocol, ip, source_port)
                    representative_ip.setdefault(fingerprint, _normalize_ip(ip or "") or None)
                sibling_protocol = "vless" if protocol == "vmess" else "vmess"
                sibling_live_ips = {
                    ip
                    for sibling_log in db.query(ConnectionLog).filter(
                        ConnectionLog.user_id == int(user.id),
                        ConnectionLog.protocol == sibling_protocol,
                        ConnectionLog.is_online == True,  # noqa: E712
                    ).all()
                    if _xray_log_has_strong_protocol_evidence(sibling_log)
                    and (ip := _normalize_ip(sibling_log.ip_address or ""))
                }
                for fingerprint in new_fingerprints:
                    public_ip = representative_ip.get(fingerprint)
                    pending_key = _pending_endpoint_key(user.id, protocol, public_ip)
                    pending_seen.add(pending_key)
                    if _pending_endpoint_confirmed(
                        user.id,
                        protocol,
                        public_ip,
                        traffic_total=traffic_total,
                        activity_latest=activity_latest,
                        activity_count=activity_count,
                        observed_at=observed_at,
                        require_access_event=bool(public_ip and public_ip in sibling_live_ips),
                    ):
                        confirmed_new.add(fingerprint)

                for ip, source_port, connected_at in allowed_endpoints:
                    normalized = _normalize_ip(ip or "") or None
                    source_port = int(source_port or 0) or None
                    endpoint_key = (normalized or "", int(source_port or 0))
                    transport_info = transport_map.get(endpoint_key)
                    if not transport_info:
                        # Every admitted row must have an exact transport from
                        # this protocol's listener; API/count hints alone stop
                        # here and cannot become a sibling session.
                        continue
                    transport_ip, transport_port, strong_evidence = transport_info
                    fingerprint = _xray_endpoint_fingerprint(protocol, normalized, source_port)
                    log = existing_by_fingerprint.get(fingerprint)
                    if not log and source_port:
                        log = next((
                            candidate for candidate in existing_logs
                            if candidate.is_online
                            and (_normalize_ip(candidate.ip_address or "") or None) == normalized
                            and not int(getattr(candidate, "source_port", 0) or 0)
                        ), None)

                    verified_evidence = bool(strong_evidence and transport_ip and transport_port)

                    # Never create a VMess/VLESS row solely because a raw online
                    # statistic was positive. This was the source of phantom
                    # VLESS rows while only VMess was actually selected.
                    if not log and not verified_evidence:
                        continue
                    if log and not verified_evidence:
                        _mark_xray_log_missing(log, now)
                        continue
                    # A one-shot config/latency probe establishes only the
                    # candidate baseline. The same user/IP must later move bytes
                    # or emit another access event before becoming visible.
                    if not log and fingerprint not in confirmed_new:
                        continue

                    if not log:
                        log = ConnectionLog(
                            user_id=user.id,
                            protocol=protocol,
                            ip_address=normalized,
                            source_port=source_port,
                            interface=f"xray-{protocol}",
                            connect_time=connected_at or now,
                            is_online=True,
                            presence_state="active",
                            presence_failures=0,
                            last_seen_at=now,
                            last_activity_at=now if (delta > 0 or source_port) else None,
                            device_fingerprint=fingerprint,
                            identity_verified=True,
                            transport_ip_address=transport_ip,
                            transport_source_port=transport_port,
                            protocol_evidence_at=now,
                        )
                        db.add(log)
                        existing_logs.append(log)
                        existing_by_fingerprint[fingerprint] = log
                    else:
                        log.ip_address = normalized
                        log.source_port = source_port
                        log.device_fingerprint = fingerprint
                    _mark_xray_log_present(
                        log,
                        now,
                        active=True,
                        identity_verified=True,
                        strong_protocol_evidence=True,
                        transport_ip_address=transport_ip,
                        transport_source_port=transport_port,
                    )

                live_logs = [log for log in existing_logs if log.is_online]
                if live_logs:
                    # Pending latency probes must not consume max-device slots.
                    # Only sessions that passed the same confirmation gate used
                    # by the online UI participate in shared device enforcement.
                    confirmed_ips = {
                        ip for log in live_logs
                        if (ip := _normalize_ip(log.ip_address or ""))
                    }
                    if confirmed_ips:
                        live_peers.setdefault(int(user.id), {}).setdefault(protocol, set()).update(confirmed_ips)
                    seen_online.add(user.id)
                    ensure_first_connect(user)
                live_logs.sort(key=lambda item: (item.connect_time or now, item.id or 0))
                for index, log in enumerate(live_logs):
                    log.bytes_out = uplink if index == 0 else 0
                    log.bytes_in = downlink if index == 0 else 0

            else:
                for log in existing_logs:
                    _mark_xray_log_missing(log, now)

        # Users disabled for this protocol or removed from the enabled-user
        # query still receive the same two-probe offline decision. Do not touch
        # rows already processed above in this transaction.
        enabled_ids = {int(user.id) for user in users}
        for log in db.query(ConnectionLog).filter(
            ConnectionLog.protocol == protocol,
            ConnectionLog.is_online == True,  # noqa: E712
        ).all():
            if int(log.user_id) not in enabled_ids:
                _mark_xray_log_missing(log, now)

    _cleanup_pending_xray_endpoints(pending_seen, observed_at)
    with _XRAY_MAX_DEVICE_LOCK:
        _reconcile_xray_max_devices(db, live_peers, now)
    db.commit()
    return updates


def sample_xray_traffic(db: Session) -> int:
    """Serialise live sampling across the scheduler and HTTP endpoints."""
    with _XRAY_SAMPLE_LOCK:
        return _sample_xray_traffic_impl(db)


def _restart_without_user(db: Session, protocol: str, user_id: int) -> bool:
    if not _bool(db, f"{protocol}_enabled", False) or not (Path(XRAY_BINARY).is_file() or shutil.which("xray")):
        return False
    try:
        target = write_config(db, protocol, exclude_user_ids={user_id})
        valid, _ = validate_config(target)
        if not valid:
            return False
        _systemctl("restart", protocol)
        write_config(db, protocol)
        _systemctl("restart", protocol)
        return True
    except Exception:
        try:
            write_config(db, protocol)
            _systemctl("restart", protocol)
        except Exception:
            pass
        return False


def disconnect_xray_session(
    db: Session,
    username: str,
    protocol: str | None = None,
    ip_address: str | None = None,
) -> bool:
    user = db.query(VpnUser).filter(VpnUser.username == username).first()
    if not user:
        return False
    protocols = (protocol,) if protocol in PROTOCOLS else PROTOCOLS
    disconnected = False
    for item in protocols:
        _clear_pending_xray_endpoints(user.id, item)
        _remember_forced_disconnect(user.id, item, ip_address)
        counter = (
            db.query(XrayUsageCounter)
            .filter(XrayUsageCounter.user_id == user.id, XrayUsageCounter.protocol == item)
            .first()
        )
        if counter:
            counter.last_activity_at = None
        runtime_disconnected = False
        binary = shutil.which(XRAY_BINARY) or (XRAY_BINARY if Path(XRAY_BINARY).is_file() else None)
        candidate_ips: set[str] = set()
        normalized_requested = _normalize_ip(ip_address or "") if ip_address else None
        if normalized_requested:
            candidate_ips.add(normalized_requested)
        for active_log in db.query(ConnectionLog).filter(
            ConnectionLog.user_id == user.id,
            ConnectionLog.protocol == item,
            ConnectionLog.is_online == True,  # noqa: E712
        ).all():
            normalized = _normalize_ip(active_log.ip_address or "")
            if normalized:
                candidate_ips.add(normalized)
        api_supported, api_live_ips = _online_ip_snapshot(item, user.id)
        if api_supported:
            candidate_ips.update(ip for ip in (_normalize_ip(value) for value in api_live_ips) if ip)

        if candidate_ips and binary:
            # Xray's RoutingService can terminate connections from a source IP
            # by installing a short-lived source block. Remove the rule
            # immediately afterwards so this action remains a disconnect, not a
            # permanent ban (the panel's existing firewall chain owns bans).
            server = f"--server=127.0.0.1:{API_PORTS[item]}"
            successful_rules: list[str] = []
            for target_ip in sorted(candidate_ips):
                rule_tag = f"vpnpanel-disconnect-{uuid.uuid4().hex}"
                command = [
                    binary, "api", "sib", server,
                    "-outbound=blocked", f"-inbound={item}-in",
                    f"-ruletag={rule_tag}", target_ip,
                ]
                result = subprocess.run(command, capture_output=True, text=True, timeout=10, check=False)
                if result.returncode == 0:
                    successful_rules.append(rule_tag)
            if successful_rules:
                deadline = time.monotonic() + 2.2
                while time.monotonic() < deadline:
                    supported, live_ips = _online_ip_snapshot(item, user.id)
                    current = {ip for ip in (_normalize_ip(value) for value in live_ips) if ip}
                    if supported and not (current & candidate_ips):
                        runtime_disconnected = True
                        break
                    time.sleep(0.2)
                for rule_tag in successful_rules:
                    subprocess.run(
                        [binary, "api", "rmrules", server, rule_tag],
                        capture_output=True, text=True, timeout=10, check=False,
                    )
        if not runtime_disconnected:
            # Cross-version fallback: briefly restart only this protocol with
            # the selected identity absent, then restore the normal config.
            # This disconnects that user's sessions without touching other VPN daemons.
            runtime_disconnected = _restart_without_user(db, item, user.id)
        disconnected = disconnected or runtime_disconnected

        query = db.query(ConnectionLog).filter(
            ConnectionLog.user_id == user.id,
            ConnectionLog.protocol == item,
            ConnectionLog.is_online == True,  # noqa: E712
        )
        if ip_address:
            query = query.filter(ConnectionLog.ip_address == ip_address)
        for log in query.all():
            log.is_online = False
            log.disconnect_time = log.disconnect_time or datetime.utcnow()
            disconnected = True
    db.commit()
    return disconnected


def server_address(db: Session, protocol: str) -> str:
    specific = _get(db, f"{protocol}_server_address", "").strip()
    if specific:
        return specific
    vpn_domain = _get(db, "vpn_domain", "").strip()
    if vpn_domain and _get(db, "vpn_domain_status", "") == "active":
        return vpn_domain
    return get_settings().PUBLIC_SERVER_IP


def build_uri(db: Session, user: VpnUser, protocol: str) -> str | None:
    if protocol not in PROTOCOLS or not _eligible(user, protocol, local_enabled=local_assignment_enabled(db)) or not _bool(db, f"{protocol}_enabled", False):
        return None
    settings = get_protocol_settings(db, protocol)
    host = server_address(db, protocol)
    name = quote(f"{settings.get('remark') or protocol.upper()} - {user.username}", safe="")
    if protocol == "vmess":
        payload = {
            "v": "2",
            "ps": f"{settings.get('remark') or protocol.upper()} - {user.username}",
            "add": host,
            "port": str(settings["port"]),
            "id": user.xray_uuid,
            "aid": "0",
            "scy": "auto",
            "net": settings["transport"],
            "type": "none",
            "host": settings["tls_domain"] if settings["transport"] == "ws" else "",
            "path": settings["ws_path"] if settings["transport"] == "ws" else "",
            "tls": "tls" if settings["tls_enabled"] else "",
            "sni": settings["tls_domain"] if settings["tls_enabled"] else "",
        }
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        return "vmess://" + base64.b64encode(raw).decode("ascii")
    query = {
        "encryption": "none",
        "security": "tls" if settings["tls_enabled"] else "none",
        "type": settings["transport"],
    }
    if settings["transport"] == "ws":
        query["path"] = settings["ws_path"]
        if settings["tls_domain"]:
            query["host"] = settings["tls_domain"]
    if settings["tls_enabled"] and settings["tls_domain"]:
        query["sni"] = settings["tls_domain"]
    if settings.get("flow"):
        query["flow"] = settings["flow"]
    query_text = "&".join(f"{quote(k)}={quote(str(v), safe='/')}" for k, v in query.items())
    return f"vless://{user.xray_uuid}@{host}:{settings['port']}?{query_text}#{name}"
