"""Per-user upload/download rate limiting across all panel VPN protocols.

Download means traffic from the internet/server toward the VPN client. Upload
means traffic from the VPN client toward the internet/server.

Runtime enforcement paths:
- L2TP / PPTP / SSTP: tc on each dedicated ppp* session interface.
- OpenConnect: tc on each dedicated vpns* session interface.
- OpenVPN: tc filters on the shared tun interface, classified by tunnel IP.
- IKEv2/IPsec: nftables rules on each strongSwan-assigned virtual client IP.
- VMess / VLESS: Xray selects a per-user marked outbound; nftables uses the
  connection mark to police both internet-side upload and download traffic.

A value of zero means unlimited. All operations are best-effort and isolated in
an nftables table named ``vpn_panel_rate`` so they do not replace the firewall
rules managed by the rest of the panel.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import os
import re
import shutil
import subprocess
import tempfile
import zlib
from collections import defaultdict
from pathlib import Path
from typing import Optional

from app.services.server_targets import user_selected_for_local, local_assignment_enabled

logger = logging.getLogger("vpn-panel.rate-limit")

_IFACE_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,32}$")
_UNIQUE_PROTOCOLS = {"l2tp", "pptp", "sstp", "openconnect"}
_XRAY_PROTOCOLS = {"vmess", "vless"}
_NFT_TABLE = "vpn_panel_rate"
_MARK_PREFIX = 0x51000000
_MARK_MASK = 0xFF000000
_LAST_SHARED_SIGNATURE: str | None = None


def _run(args: list[str], *, check: bool = False, timeout: int = 8) -> subprocess.CompletedProcess:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    if check and result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "command failed").strip())
    return result


def _valid_interface(interface: Optional[str]) -> Optional[str]:
    value = (interface or "").strip()
    if not value or not _IFACE_RE.fullmatch(value):
        return None
    if _run(["ip", "link", "show", "dev", value]).returncode != 0:
        return None
    return value


def _mbit(value: int | None) -> int:
    try:
        return max(0, min(int(value or 0), 100000))
    except (TypeError, ValueError):
        return 0


def _burst_kb(rate_mbps: int) -> int:
    return max(64, min(4096, rate_mbps * 64))


def _delete_root(interface: str) -> None:
    _run(["tc", "qdisc", "del", "dev", interface, "root"])


def _delete_ingress(interface: str) -> None:
    _run(["tc", "qdisc", "del", "dev", interface, "ingress"])


def _apply_unique_interface(interface: str, download_mbps: int, upload_mbps: int) -> None:
    """Shape a dedicated per-session interface."""
    if download_mbps > 0:
        burst = _burst_kb(download_mbps)
        _run([
            "tc", "qdisc", "replace", "dev", interface, "root", "tbf",
            "rate", f"{download_mbps}mbit", "burst", f"{burst}kb", "latency", "400ms",
        ], check=True)
    else:
        _delete_root(interface)

    if upload_mbps > 0:
        burst = _burst_kb(upload_mbps)
        _run(["tc", "qdisc", "replace", "dev", interface, "handle", "ffff:", "ingress"], check=True)
        _run([
            "tc", "filter", "replace", "dev", interface, "parent", "ffff:",
            "protocol", "all", "pref", "10", "u32", "match", "u32", "0", "0",
            "police", "rate", f"{upload_mbps}mbit", "burst", f"{burst}kb",
            "drop", "flowid", ":1",
        ], check=True)
    else:
        _delete_ingress(interface)


def _openvpn_ids(user_id: int, tunnel_ip: str) -> tuple[int, int]:
    class_minor = 2000 + (int(user_id) % 60000)
    pref = 1000 + (zlib.crc32(tunnel_ip.encode("utf-8")) % 50000)
    return class_minor, pref


def _valid_ipv4(value: Optional[str]) -> Optional[str]:
    try:
        ip = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None
    return str(ip) if ip.version == 4 else None


def _ensure_openvpn_htb(interface: str) -> None:
    qdisc = _run(["tc", "qdisc", "show", "dev", interface]).stdout
    if "htb 1:" not in qdisc:
        _run(["tc", "qdisc", "replace", "dev", interface, "root", "handle", "1:", "htb", "default", "999"], check=True)
    _run([
        "tc", "class", "replace", "dev", interface, "parent", "1:",
        "classid", "1:999", "htb", "rate", "10gbit", "ceil", "10gbit",
    ], check=True)


def _ensure_shared_ingress(interface: str) -> None:
    qdisc = _run(["tc", "qdisc", "show", "dev", interface]).stdout
    if "ingress ffff:" not in qdisc:
        result = _run(["tc", "qdisc", "add", "dev", interface, "handle", "ffff:", "ingress"])
        if result.returncode != 0 and "File exists" not in (result.stderr or ""):
            raise RuntimeError((result.stderr or result.stdout or "failed to add ingress qdisc").strip())


def _apply_openvpn_shared(interface: str, user_id: int, tunnel_ip: str, download_mbps: int, upload_mbps: int) -> None:
    class_minor, pref = _openvpn_ids(user_id, tunnel_ip)

    if download_mbps > 0:
        _ensure_openvpn_htb(interface)
        burst = _burst_kb(download_mbps)
        _run([
            "tc", "class", "replace", "dev", interface, "parent", "1:",
            "classid", f"1:{class_minor}", "htb", "rate", f"{download_mbps}mbit",
            "ceil", f"{download_mbps}mbit", "burst", f"{burst}kb",
        ], check=True)
        _run([
            "tc", "filter", "replace", "dev", interface, "protocol", "ip",
            "parent", "1:", "pref", str(pref), "u32", "match", "ip", "dst",
            f"{tunnel_ip}/32", "flowid", f"1:{class_minor}",
        ], check=True)
    else:
        _run(["tc", "filter", "del", "dev", interface, "protocol", "ip", "parent", "1:", "pref", str(pref)])

    if upload_mbps > 0:
        burst = _burst_kb(upload_mbps)
        _ensure_shared_ingress(interface)
        _run([
            "tc", "filter", "replace", "dev", interface, "parent", "ffff:",
            "protocol", "ip", "pref", str(pref), "u32", "match", "ip", "src",
            f"{tunnel_ip}/32", "police", "rate", f"{upload_mbps}mbit",
            "burst", f"{burst}kb", "drop", "flowid", ":1",
        ], check=True)
    else:
        _run(["tc", "filter", "del", "dev", interface, "parent", "ffff:", "protocol", "ip", "pref", str(pref)])


def user_rate_mark(user_id: int, protocol: str | None = None) -> int:
    """Stable per-user/per-protocol fwmark for Xray internet-side sockets.

    VMess and VLESS need distinct marks so the panel can suspend only the
    selected protocol while leaving the other protocol and the transport
    connection itself untouched. The default keeps backward compatibility for
    callers that only need a stable user mark.
    """
    uid = max(1, int(user_id)) & 0x007FFFFF
    if str(protocol or '').lower() == 'vless':
        uid |= 0x00800000
    return _MARK_PREFIX | uid


def _nft_rate_kbytes(rate_mbps: int) -> int:
    # Mbps -> decimal kilobytes/second. nftables byte-rate limits are easier to
    # audit than a packet-rate approximation and aggregate all connections in
    # one rule for the same user.
    return max(1, int(rate_mbps) * 125)


def _nft_burst_kbytes(rate_mbps: int) -> int:
    # Keep the short TCP burst usable without allowing a multi-second speed-test
    # spike to hide the configured limit. Roughly 250 ms of traffic.
    return max(64, min(8192, int(rate_mbps) * 32))


def _nft_available() -> str | None:
    nft = shutil.which("nft") or ("/usr/sbin/nft" if os.path.exists("/usr/sbin/nft") else None)
    if nft:
        modprobe = shutil.which("modprobe") or "/usr/sbin/modprobe"
        if Path(modprobe).exists():
            for module in ("nf_conntrack", "nf_tables", "nft_limit"):
                _run([modprobe, module], timeout=8)
    return nft


def _remove_nft_table(nft: str) -> None:
    exists = _run([nft, "list", "table", "inet", _NFT_TABLE], timeout=10)
    if exists.returncode == 0:
        _run([nft, "delete", "table", "inet", _NFT_TABLE], timeout=10)


def _apply_nft_script(nft: str, script: str) -> None:
    fd, path = tempfile.mkstemp(prefix="vpn-panel-rate-", suffix=".nft")
    previous = _run([nft, "list", "table", "inet", _NFT_TABLE], timeout=10)
    previous_script = previous.stdout if previous.returncode == 0 else ""
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(script)

        # Validate against a throw-away table name. Checking the real table name
        # while the current ruleset is still active would incorrectly fail with
        # "File exists" on every reconciliation after the first one.
        check_path = path + ".check"
        check_script = script.replace(
            f"table inet {_NFT_TABLE}",
            f"table inet {_NFT_TABLE}_check",
            1,
        )
        Path(check_path).write_text(check_script, encoding="utf-8")
        try:
            checked = _run([nft, "-c", "-f", check_path], timeout=15)
        finally:
            try:
                os.unlink(check_path)
            except OSError:
                pass
        if checked.returncode != 0:
            raise RuntimeError((checked.stderr or checked.stdout or "nftables validation failed").strip())

        _remove_nft_table(nft)
        applied = _run([nft, "-f", path], timeout=15)
        if applied.returncode != 0:
            # Restore the previous isolated table if the kernel rejected the new
            # rules for a runtime reason after syntax validation.
            if previous_script.strip():
                restore_fd, restore_path = tempfile.mkstemp(prefix="vpn-panel-rate-restore-", suffix=".nft")
                try:
                    with os.fdopen(restore_fd, "w", encoding="utf-8") as restore_file:
                        restore_file.write(previous_script)
                    _run([nft, "-f", restore_path], timeout=15)
                finally:
                    try:
                        os.unlink(restore_path)
                    except OSError:
                        pass
            raise RuntimeError((applied.stderr or applied.stdout or "nftables apply failed").strip())
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def _valid_tunnel_ip(value: Optional[str]) -> Optional[str]:
    try:
        ip = ipaddress.ip_address((value or "").strip())
    except ValueError:
        return None
    return str(ip)


def _eligible_for_xray_mark(user, protocol: str, *, local_enabled: bool = True) -> bool:
    return bool(
        getattr(user, "is_active", False)
        and local_enabled
        and user_selected_for_local(user)
        and getattr(user, f"enable_{protocol}", False)
    )


def _shared_rule_model(db) -> tuple[list[dict], list[dict]]:
    # Local imports keep this module usable from migration/repair contexts.
    from app.models import ConnectionLog, VpnUser

    xray_users: list[dict] = []
    local_enabled = local_assignment_enabled(db)
    all_users = db.query(VpnUser).all()
    by_id = {int(u.id): u for u in all_users}
    # Every enabled Xray identity gets a dedicated marked outbound. This makes
    # speed limiting and the "connected but no internet" switch deterministic
    # even when a user previously had unlimited speed.
    for user in all_users:
        for protocol in ("vmess", "vless"):
            if not _eligible_for_xray_mark(user, protocol, local_enabled=local_enabled):
                continue
            xray_users.append({
                "id": int(user.id),
                "protocol": protocol,
                "mark": user_rate_mark(int(user.id), protocol),
                "download": _mbit(getattr(user, "download_limit_mbps", 0)),
                "upload": _mbit(getattr(user, "upload_limit_mbps", 0)),
                "blocked": bool(getattr(user, f"{protocol}_internet_blocked", False)),
            })

    ike_ips: dict[int, set[str]] = defaultdict(set)
    sessions = (
        db.query(ConnectionLog)
        .filter(ConnectionLog.protocol == "ikev2", ConnectionLog.is_online == True)  # noqa: E712
        .all()
    )
    for session in sessions:
        user = by_id.get(int(session.user_id))
        if not user or not getattr(user, "is_active", False):
            continue
        ip = _valid_tunnel_ip(getattr(session, "tunnel_ip", None))
        if ip:
            ike_ips[int(user.id)].add(ip)

    ike_users: list[dict] = []
    for user_id, ips in sorted(ike_ips.items()):
        user = by_id[user_id]
        download = _mbit(getattr(user, "download_limit_mbps", 0))
        upload = _mbit(getattr(user, "upload_limit_mbps", 0))
        if download <= 0 and upload <= 0:
            continue
        ike_users.append({"id": user_id, "ips": sorted(ips), "download": download, "upload": upload})
    return sorted(xray_users, key=lambda item: item["id"]), ike_users


def _render_nft_script(xray_users: list[dict], ike_users: list[dict]) -> str:
    lines = [
        f"table inet {_NFT_TABLE} {{",
        "  chain output {",
        "    type filter hook output priority mangle; policy accept;",
    ]
    for item in xray_users:
        mark = f"0x{item['mark']:08x}"
        # Xray sets SO_MARK on each per-user internet-side socket. Copy the
        # packet mark into conntrack on every outbound packet so reply packets
        # retain the same user identity across TCP and UDP/NAT.
        token = f'xray-{item["protocol"]}-user-{item["id"]}'
        lines.append(
            f'    meta mark {mark} ct mark set {mark} counter comment "{token}-track"'
        )
        if item.get("blocked"):
            lines.append(
                f'    meta mark {mark} counter drop comment "{token}-internet-block"'
            )
        elif item["upload"] > 0:
            lines.append(
                f'    meta mark {mark} counter limit rate over {_nft_rate_kbytes(item["upload"])} kbytes/second '
                f'burst {_nft_burst_kbytes(item["upload"])} kbytes drop comment "{token}-upload"'
            )
    lines += ["  }", "", "  chain prerouting {", "    type filter hook prerouting priority mangle; policy accept;"]
    for item in xray_users:
        mark = f"0x{item['mark']:08x}"
        # Restore the per-user connection mark onto reply packets before the
        # rate rule.  This is the download direction (internet -> Xray client).
        token = f'xray-{item["protocol"]}-user-{item["id"]}'
        lines.append(
            f'    ct mark {mark} meta mark set {mark} counter comment "{token}-restore"'
        )
        if item.get("blocked"):
            lines.append(
                f'    ct mark {mark} counter drop comment "{token}-internet-block-reply"'
            )
        elif item["download"] > 0:
            lines.append(
                f'    ct mark {mark} counter limit rate over {_nft_rate_kbytes(item["download"])} kbytes/second '
                f'burst {_nft_burst_kbytes(item["download"])} kbytes drop comment "{token}-download"'
            )
    lines += ["  }", "", "  chain forward {", "    type filter hook forward priority mangle; policy accept;"]
    for item in ike_users:
        ipv4 = [ip for ip in item["ips"] if ":" not in ip]
        ipv6 = [ip for ip in item["ips"] if ":" in ip]
        for family, ips in (("ip", ipv4), ("ip6", ipv6)):
            if not ips:
                continue
            values = ", ".join(ips)
            set_expr = ips[0] if len(ips) == 1 else f"{{ {values} }}"
            if item["upload"] > 0:
                lines.append(
                    f'    {family} saddr {set_expr} counter limit rate over {_nft_rate_kbytes(item["upload"])} kbytes/second '
                    f'burst {_nft_burst_kbytes(item["upload"])} kbytes drop comment "ikev2-user-{item["id"]}-upload"'
                )
            if item["download"] > 0:
                lines.append(
                    f'    {family} daddr {set_expr} counter limit rate over {_nft_rate_kbytes(item["download"])} kbytes/second '
                    f'burst {_nft_burst_kbytes(item["download"])} kbytes drop comment "ikev2-user-{item["id"]}-download"'
                )
    lines += ["  }", "}", ""]
    return "\n".join(lines)


def _verify_shared_rules(nft: str, xray_users: list[dict], ike_users: list[dict]) -> None:
    listed = _run([nft, "list", "table", "inet", _NFT_TABLE], timeout=10)
    if listed.returncode != 0:
        raise RuntimeError((listed.stderr or listed.stdout or "rate-limit nft table is missing").strip())
    body = listed.stdout or ""
    missing: list[str] = []
    for item in xray_users:
        token = f"xray-{item['protocol']}-user-{item['id']}"
        if f"{token}-track" not in body:
            missing.append(f"{token}-track")
        if f"{token}-restore" not in body:
            missing.append(f"{token}-restore")
        if item.get("blocked"):
            if f"{token}-internet-block" not in body:
                missing.append(f"{token}-internet-block")
            if f"{token}-internet-block-reply" not in body:
                missing.append(f"{token}-internet-block-reply")
        else:
            if item["upload"] > 0 and f"{token}-upload" not in body:
                missing.append(f"{token}-upload")
            if item["download"] > 0 and f"{token}-download" not in body:
                missing.append(f"{token}-download")
    for item in ike_users:
        if item["upload"] > 0 and f"ikev2-user-{item['id']}-upload" not in body:
            missing.append(f"ikev2-user-{item['id']}-upload")
        if item["download"] > 0 and f"ikev2-user-{item['id']}-download" not in body:
            missing.append(f"ikev2-user-{item['id']}-download")
    if missing:
        raise RuntimeError("rate-limit rules were not installed: " + ", ".join(missing))

def reconcile_shared_rate_limits(db, *, force: bool = False) -> bool:
    """Rebuild the isolated nftables rate table when desired state changes.

    This covers IKEv2 and Xray protocols. Dedicated-interface protocols keep
    using ``apply_session_limits`` so no existing tc behavior is replaced.
    """
    global _LAST_SHARED_SIGNATURE
    nft = _nft_available()
    if not nft:
        logger.warning("nft command is unavailable; IKEv2/Xray rate limits cannot be applied")
        return False

    xray_users, ike_users = _shared_rule_model(db)
    desired = {"xray": xray_users, "ikev2": ike_users}
    signature = hashlib.sha256(repr(desired).encode("utf-8")).hexdigest()
    if not force and signature == _LAST_SHARED_SIGNATURE:
        # Do not trust only the in-process signature: an external firewall
        # reload can remove our isolated table while the desired DB state stays
        # unchanged. Verify the live rules on every reconciliation and rebuild
        # immediately when they disappeared.
        if not xray_users and not ike_users:
            return True
        try:
            _verify_shared_rules(nft, xray_users, ike_users)
            return True
        except Exception:
            logger.warning("Live rate-limit table drift detected; rebuilding it")

    try:
        if not xray_users and not ike_users:
            _remove_nft_table(nft)
        else:
            _apply_nft_script(nft, _render_nft_script(xray_users, ike_users))
            _verify_shared_rules(nft, xray_users, ike_users)
        _LAST_SHARED_SIGNATURE = signature
        return True
    except Exception:
        logger.exception("Failed to reconcile shared IKEv2/Xray rate limits")
        return False




def xray_internet_block_installed(user_id: int, protocol: str, blocked: bool) -> bool:
    """Verify the live nftables state used by the panel internet switch."""
    if protocol not in _XRAY_PROTOCOLS:
        return False
    nft = _nft_available()
    if not nft:
        return False
    listed = _run([nft, "list", "table", "inet", _NFT_TABLE], timeout=10)
    if listed.returncode != 0:
        return not blocked
    token = f"xray-{protocol}-user-{int(user_id)}"
    body = listed.stdout or ""
    present = (
        f"{token}-internet-block" in body
        and f"{token}-internet-block-reply" in body
    )
    return present if blocked else not present

def xray_nft_usage_snapshot() -> dict[tuple[int, str], dict[str, int]]:
    """Read absolute per-user Xray byte counters from the isolated nft table.

    This is a fallback accounting source for Xray builds whose StatsService CLI
    is missing or returns no per-user counters.  The ``track`` rule counts
    client-to-internet bytes and ``restore`` counts internet-to-client bytes.
    Both JSON and text output are supported because nft versions differ across
    Ubuntu releases.
    """
    nft = _nft_available()
    if not nft:
        return {}
    result: dict[tuple[int, str], dict[str, int]] = {}
    token_re = re.compile(r"^xray-(vmess|vless)-user-(\d+)-(track|restore)$")

    def consume(comment: str, byte_count) -> None:
        match = token_re.match(str(comment or ""))
        if not match:
            return
        try:
            value = max(0, int(byte_count or 0))
        except (TypeError, ValueError):
            return
        protocol, raw_uid, direction = match.groups()
        bucket = result.setdefault((int(raw_uid), protocol), {"uplink": 0, "downlink": 0})
        field = "uplink" if direction == "track" else "downlink"
        # A duplicate/commented rule should never exist, but max() makes the
        # parser safe during an atomic table replacement.
        bucket[field] = max(int(bucket[field]), value)

    json_result = _run([nft, "-j", "list", "table", "inet", _NFT_TABLE], timeout=10)
    if json_result.returncode == 0:
        try:
            payload = __import__("json").loads(json_result.stdout or "{}")
        except Exception:
            payload = {}
        for item in payload.get("nftables", []) if isinstance(payload, dict) else []:
            rule = item.get("rule") if isinstance(item, dict) else None
            if not isinstance(rule, dict):
                continue
            comment = rule.get("comment")
            counter_bytes = None
            for expr in rule.get("expr", []) if isinstance(rule.get("expr"), list) else []:
                if not isinstance(expr, dict):
                    continue
                if not comment and isinstance(expr.get("comment"), str):
                    comment = expr.get("comment")
                counter = expr.get("counter")
                if isinstance(counter, dict) and "bytes" in counter:
                    counter_bytes = counter.get("bytes")
            if comment is not None and counter_bytes is not None:
                consume(str(comment), counter_bytes)
        if result:
            return result

    text_result = _run([nft, "list", "table", "inet", _NFT_TABLE], timeout=10)
    if text_result.returncode != 0:
        return result
    for line in (text_result.stdout or "").splitlines():
        comment = re.search(r'comment\s+"([^"]+)"', line)
        counter = re.search(r'counter\s+packets\s+\d+\s+bytes\s+(\d+)', line)
        if comment and counter:
            consume(comment.group(1), counter.group(1))
    return result

def apply_session_limits(user, session) -> bool:
    """Apply the user's current limits to one active session. Best effort."""
    protocol = str(getattr(session, "protocol", "") or "").lower()
    if protocol in {"ikev2", "vmess", "vless"}:
        # Shared protocols are reconciled as one isolated nftables ruleset by
        # the scheduler and immediately after user edits.
        return False

    interface = _valid_interface(getattr(session, "interface", None))
    if not interface:
        return False

    download = _mbit(getattr(user, "download_limit_mbps", 0))
    upload = _mbit(getattr(user, "upload_limit_mbps", 0))
    try:
        if protocol == "openvpn":
            tunnel_ip = _valid_ipv4(getattr(session, "tunnel_ip", None))
            if not tunnel_ip:
                logger.warning("OpenVPN rate limit skipped: missing tunnel IP for user=%s", getattr(user, "username", "?"))
                return False
            _apply_openvpn_shared(interface, int(user.id), tunnel_ip, download, upload)
            return True
        if protocol in _UNIQUE_PROTOCOLS:
            _apply_unique_interface(interface, download, upload)
            return True
        return False
    except Exception:
        logger.exception(
            "Failed to apply rate limits user=%s protocol=%s interface=%s",
            getattr(user, "username", "?"), protocol, interface,
        )
        return False


def remove_session_limits(user, session) -> None:
    """Remove only the rules associated with one disconnecting session."""
    protocol = str(getattr(session, "protocol", "") or "").lower()
    if protocol in {"ikev2", "vmess", "vless"}:
        return
    interface = _valid_interface(getattr(session, "interface", None))
    if not interface:
        return
    try:
        if protocol == "openvpn":
            tunnel_ip = _valid_ipv4(getattr(session, "tunnel_ip", None))
            if not tunnel_ip:
                return
            _, pref = _openvpn_ids(int(user.id), tunnel_ip)
            _run(["tc", "filter", "del", "dev", interface, "protocol", "ip", "parent", "1:", "pref", str(pref)])
            _run(["tc", "filter", "del", "dev", interface, "parent", "ffff:", "protocol", "ip", "pref", str(pref)])
        elif protocol in _UNIQUE_PROTOCOLS:
            _delete_root(interface)
            _delete_ingress(interface)
    except Exception:
        logger.exception("Failed to remove rate limit for %s/%s", getattr(user, "username", "?"), protocol)
