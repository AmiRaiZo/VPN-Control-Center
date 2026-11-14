from datetime import date, datetime
from contextlib import contextmanager
from pathlib import Path
import subprocess
import threading
from fastapi import APIRouter, Depends, HTTPException, Header
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import VpnUser, ConnectionLog, InternetBlockedIP
from app.services.server_targets import user_enabled_on_this_server
from app.schemas import InternalConnectEvent, InternalDisconnectEvent, InternalVerifyPasswordEvent
from app.config import get_settings
from app.services.telegram_notifier import log_event, log_connection_event
from app.services.rate_limiter import apply_session_limits, remove_session_limits
from app.services.user_lifecycle import ensure_first_connect
from app.services.cluster_admission import (
    build_cluster_session_key, release_cluster_session, reserve_cluster_session,
)

router = APIRouter(prefix="/api/internal", tags=["internal"])
settings = get_settings()

# All user-facing VPN transports share one concurrent-connection budget.
# ``ipsec`` is the transport card used by L2TP and therefore does not create a
# second user session of its own; the authenticated L2TP session is counted.
SHARED_USER_PROTOCOLS = {
    "pptp", "ipsec", "l2tp", "sstp", "openconnect", "openvpn",
    "ikev2", "vmess", "vless",
}
_PROTOCOL_ENABLE_FIELD = {
    "pptp": "enable_pptp",
    "l2tp": "enable_l2tp",
    "sstp": "enable_sstp",
    "openconnect": "enable_openconnect",
    "openvpn": "enable_openvpn",
    "ikev2": "enable_ikev2",
    "vmess": "enable_vmess",
    "vless": "enable_vless",
}

# FastAPI may execute hook requests in parallel.  The database row lock is the
# cross-process guard on MySQL; this small in-process lock also makes the rule
# deterministic on SQLite/tests and closes the tiny gap between two hook calls.
_ADMISSION_LOCKS_GUARD = threading.Lock()
_ADMISSION_LOCKS: dict[int, threading.Lock] = {}


@contextmanager
def _user_admission_lock(user_id: int):
    with _ADMISSION_LOCKS_GUARD:
        lock = _ADMISSION_LOCKS.setdefault(int(user_id), threading.Lock())
    lock.acquire()
    try:
        yield
    finally:
        lock.release()


def _assert_user_can_connect(db: Session, user: VpnUser, protocol: str) -> None:
    protocol = str(protocol or "").lower()
    field = _PROTOCOL_ENABLE_FIELD.get(protocol)
    if protocol not in SHARED_USER_PROTOCOLS or (field and not bool(getattr(user, field, False))):
        raise HTTPException(status_code=403, detail="protocol_disabled")
    if not user_enabled_on_this_server(db, user):
        raise HTTPException(status_code=403, detail="server_not_selected")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="denied")
    if user.expire_date and user.expire_date < date.today():
        raise HTTPException(status_code=403, detail="expired")
    if user.quota_bytes > 0 and int(user.used_bytes or 0) >= int(user.quota_bytes):
        raise HTTPException(status_code=403, detail="quota_exceeded")


def verify_internal_token(x_internal_token: str = Header(...)):
    if x_internal_token != settings.INTERNAL_API_TOKEN:
        raise HTTPException(status_code=401, detail="unauthorized")


XRAY_PROTOCOLS = {"vmess", "vless"}
# Xray presence is refreshed by an independent five-second scheduler.  A row
# not observed for more than two full ticks must not block a fresh authenticated
# connection forever if the scheduler/API was restarted mid-session.
FAST_XRAY_STALE_SECONDS = 12
SESSION_ROUTING_PROTOCOLS = {"pptp", "l2tp", "sstp", "openconnect", "openvpn"}


def _ensure_runtime_session_network(mode: str, payload, *, preserve_conntrack: bool = False) -> None:
    """Apply/remove a fast /32 route guard without making admission fail.

    Persistent pool routing is repaired by the systemd timer. This call closes
    the short window where a just-created ppp/tun interface exists before a
    provider/UFW reload or timer has restored forwarding/NAT.
    """
    protocol = str(getattr(payload, "protocol", "") or "").lower()
    interface = str(getattr(payload, "interface", "") or "").strip()
    tunnel_ip = str(getattr(payload, "tunnel_ip", "") or "").strip()
    if protocol not in SESSION_ROUTING_PROTOCOLS or not interface or not tunnel_ip:
        return
    helper = Path("/opt/vpn-panel/scripts/ensure_session_networking.sh")
    if not helper.is_file():
        return
    try:
        subprocess.Popen(
            [str(helper), "--up" if mode == "up" else "--down", protocol, interface, tunnel_ip, "handover" if preserve_conntrack else "fresh"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        # Authentication and the established tunnel must not be rejected merely
        # because a defensive route refresh raced with the periodic repair.
        return


def _schedule_replaced_ppp_retirement(previous: ConnectionLog | None, current: ConnectionLog) -> None:
    """Gracefully retire the old PPP only after its replacement is usable.

    X28-class embedded L2TP clients can open a replacement control tunnel while
    the previous PPP still carries traffic.  Killing the old pppd during
    admission creates a visible pause; leaving it forever leaks interfaces and
    routes.  A tiny root helper waits for the new pppd/interface, then TERM-kills
    only the exact previous PID.  The old ip-down hook is PID-scoped and cannot
    close the new database row.
    """
    if previous is None:
        return
    protocol = str(current.protocol or "").lower()
    old_pid = int(previous.pid or 0)
    new_pid = int(current.pid or 0)
    if protocol not in {"l2tp", "pptp"} or old_pid <= 1 or new_pid <= 1 or old_pid == new_pid:
        return
    helper = Path("/opt/vpn-panel/scripts/retire_ppp_handover.sh")
    if not helper.is_file():
        return
    try:
        subprocess.Popen(
            [str(helper), str(old_pid), str(new_pid), str(previous.interface or ""), str(current.interface or "")],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except OSError:
        return


def _fast_release_stale_rows(db: Session, user_id: int, now: datetime) -> int:
    """Perform only local/sub-millisecond stale cleanup during admission.

    Older releases synchronously queried PPP, OpenVPN, OpenConnect, IKEv2 and
    both Xray services here.  On a real server that routinely took the exact
    five/six seconds allowed by the protocol hook, so the hook timed out and
    rejected *every* otherwise-valid connection.  The scheduler already owns
    daemon reconciliation; the admission endpoint must stay fast.
    """
    closed = 0
    rows = db.query(ConnectionLog).filter(
        ConnectionLog.user_id == int(user_id),
        ConnectionLog.is_online == True,  # noqa: E712
    ).all()
    for row in rows:
        stale = False
        protocol = str(row.protocol or "").lower()
        if protocol in XRAY_PROTOCOLS:
            # Only a real sampler timestamp is authoritative. Legacy rows that
            # predate last_seen_at are left to the five-second Xray reconciler;
            # using connect_time alone could free a genuinely idle live tunnel.
            last_seen = row.last_seen_at
            if last_seen and (now - last_seen).total_seconds() > FAST_XRAY_STALE_SECONDS:
                stale = True
            elif str(row.presence_state or "") == "probing" and row.connect_time and (
                now - row.connect_time
            ).total_seconds() > FAST_XRAY_STALE_SECONDS:
                stale = True
        elif protocol in {"pptp", "l2tp"} and int(row.pid or 0) > 1:
            # A PPP session has one dedicated pppd process.  /proc lookup is
            # local and instant, unlike daemon management sockets. Existence
            # of pppd alone is not enough during teardown: after LCP reports a
            # dead serial link, the process remains briefly while IFF_UP is
            # already cleared. Release that row before central admission so an
            # immediate reconnect is not denied as an extra device.
            try:
                from pathlib import Path
                stale = not Path(f"/proc/{int(row.pid)}").exists()
                if not stale and row.interface:
                    from app.services.vpn_manager import _ppp_interface_is_live

                    stale = not _ppp_interface_is_live(row.interface)
            except (TypeError, ValueError):
                stale = False
        if stale:
            row.is_online = False
            row.presence_state = "offline"
            row.disconnect_time = row.disconnect_time or now
            closed += 1
    if closed:
        db.flush()
    return closed


def _normalize_public_ip(value: str | None) -> str | None:
    value = str(value or "").strip().lower()
    return value if value and value not in {"unknown", "-", "none"} else None


def _shared_active_connection_keys(db: Session, user_id: int) -> set[str]:
    """Return enforceable concurrent tunnel identities for one VPN account.

    ``max_devices`` is intentionally treated as the number of simultaneous VPN
    tunnels, not the number of distinct source IP addresses.  A phone/router
    that opens L2TP and OpenVPN at the same time therefore consumes two slots.

    Xray is the only exception at the raw-row level: one VMess/VLESS client can
    open many TCP streams.  Those stream rows are collapsed to one
    protocol+public-IP tunnel so browser/transport multiplexing does not create
    phantom slots.  Hook-based protocols already create exactly one row per
    admitted tunnel and are always counted separately.
    """
    rows = db.query(ConnectionLog).filter(
        ConnectionLog.user_id == int(user_id),
        ConnectionLog.is_online == True,  # noqa: E712
        ConnectionLog.device_limit_blocked == False,  # noqa: E712
    ).all()
    keys: set[str] = set()
    for row in rows:
        protocol = str(row.protocol or "").lower()
        public_ip = _normalize_public_ip(row.ip_address)
        if protocol in XRAY_PROTOCOLS and public_ip:
            keys.add(f"xray:{protocol}:ip:{public_ip}")
            continue
        # Unknown Xray peers and every hook-based tunnel stay session-scoped.
        keys.add(
            f"session:{int(row.id or 0)}:{protocol}:{row.interface or ''}:{row.pid or 0}"
        )
    return keys


def _shared_active_public_ips(db: Session, user_id: int) -> set[str]:
    """Return public IPs that already own an admitted tunnel for this user."""
    rows = db.query(ConnectionLog).filter(
        ConnectionLog.user_id == int(user_id),
        ConnectionLog.is_online == True,  # noqa: E712
        ConnectionLog.device_limit_blocked == False,  # noqa: E712
    ).all()
    return {
        public_ip
        for row in rows
        if (public_ip := _normalize_public_ip(row.ip_address))
    }


def _shared_active_device_keys(db: Session, user_id: int) -> set[str]:
    """Backward-compatible alias; keys now represent concurrent tunnels."""
    return _shared_active_connection_keys(db, user_id)


def _shared_active_session_count(db: Session, user_id: int) -> int:
    """Count admitted concurrent tunnels across every protocol."""
    return len(_shared_active_connection_keys(db, user_id))


def _retire_single_ppp_reconnect_at_limit(
    db: Session, user_id: int, payload: InternalConnectEvent, now: datetime
) -> ConnectionLog | None:
    """Replace one classic-PPP retry without consuming another slot.

    OpenWrt and several L2TP clients can establish a fresh PPP process while
    the previous control tunnel is still waiting for its timeout.  Both hooks
    then carry the same authenticated username, protocol and public endpoint,
    but have different pid/interface/tunnel-IP values.  Treating that short
    handover as another device rejects the usable replacement and creates a
    permanent reconnect loop.

    The exception is deliberately narrow and is used only after ``max_devices``
    is already full:
      * classic PPP only (L2TP/PPTP);
      * same protocol and same known public IP;
      * exactly one admitted matching row.

    A different public IP, a different protocol, or an ambiguous set of two
    matching live tunnels is never collapsed.  The old pppd is not terminated;
    its later ip-down event matches its own PID and therefore cannot close the
    newly admitted row.
    """
    protocol = str(payload.protocol or "").lower()
    public_ip = _normalize_public_ip(payload.ip_address)
    if protocol not in {"l2tp", "pptp"} or not public_ip:
        return None

    rows = db.query(ConnectionLog).filter(
        ConnectionLog.user_id == int(user_id),
        ConnectionLog.protocol == protocol,
        ConnectionLog.is_online == True,  # noqa: E712
        ConnectionLog.device_limit_blocked == False,  # noqa: E712
    ).order_by(ConnectionLog.connect_time.desc()).all()
    matching = [
        row for row in rows
        if _normalize_public_ip(row.ip_address) == public_ip
    ]
    if len(matching) != 1:
        return None

    previous = matching[0]
    # An exact duplicate hook for the same pppd was already handled by
    # _close_duplicate_attempt.  This path is only for a new PPP process that
    # is taking over the same authenticated endpoint.
    if payload.pid is not None and previous.pid == payload.pid:
        return None
    if payload.interface and previous.interface == payload.interface:
        return None
    if payload.tunnel_ip and previous.tunnel_ip == payload.tunnel_ip:
        return None

    previous.is_online = False
    previous.presence_state = "replaced"
    previous.disconnect_time = previous.disconnect_time or now
    db.flush()
    return previous


def _retire_cluster_replaced_session(
    db: Session,
    user_id: int,
    payload: InternalConnectEvent,
    replaced_session_key: str | None,
    now: datetime,
) -> ConnectionLog | None:
    """Retire only the exact old local row selected by the controller.

    The controller returns the old fleet key during a same-endpoint PPP
    handover. Matching that exact key prevents a late ip-down from closing the
    new tunnel and avoids collapsing two real sessions behind one NAT.
    """
    if not replaced_session_key:
        return None
    row = db.query(ConnectionLog).filter(
        ConnectionLog.user_id == int(user_id),
        ConnectionLog.is_online == True,  # noqa: E712
        ConnectionLog.cluster_session_key == str(replaced_session_key),
    ).first()
    if row is None:
        # Upgrade compatibility for an old row created before cluster keys were
        # stored. The narrow PPP matcher is still safe: same protocol, same
        # known public IP, and exactly one matching admitted row.
        return _retire_single_ppp_reconnect_at_limit(db, user_id, payload, now)
    row.is_online = False
    row.presence_state = "replaced"
    row.disconnect_time = row.disconnect_time or now
    db.flush()
    return row


def _close_duplicate_attempt(db: Session, user_id: int, payload: InternalConnectEvent, now: datetime) -> None:
    """Retire only provably stale/duplicate hook rows without killing live PPP.

    OpenWrt and some L2TP stacks can start a retry while the previous tunnel is
    still exchanging control packets.  Older releases treated every retry from
    the same public IP as a replacement and sent SIGTERM to the previous pppd.
    A second overlapping hook could then kill the newly usable tunnel, producing
    the exact "connected, no Internet" loop seen in the journal.

    A live, different pppd from the same public endpoint is left intact.
    ``max_devices`` is the only concurrent-session budget, so a second real
    tunnel from the same NAT address is allowed whenever the account still has
    a free slot. We retire a row only when it is the exact same hook identity or
    its recorded
    pppd no longer exists.  No admission request is allowed to terminate a live
    pppd process.
    """
    protocol = str(payload.protocol or "").lower()
    incoming_public_ip = _normalize_public_ip(payload.ip_address)
    rows = db.query(ConnectionLog).filter(
        ConnectionLog.user_id == int(user_id),
        ConnectionLog.protocol == protocol,
        ConnectionLog.is_online == True,  # noqa: E712
    ).all()

    changed = False
    for duplicate in rows:
        # OpenVPN server sessions all share the same ``dev`` (usually tun0),
        # so interface equality is not a session identity. Treating it as one
        # retired the first DB row without terminating its real tunnel and then
        # admitted a second connection despite max_devices=1. OpenVPN uses its
        # unique pool address; PPP-style transports may use pid/interface/IP.
        if protocol == "openvpn":
            exact_identity = bool(
                payload.tunnel_ip and duplicate.tunnel_ip == payload.tunnel_ip
            )
        else:
            exact_identity = bool(
                (payload.pid is not None and duplicate.pid == payload.pid)
                or (payload.interface and duplicate.interface == payload.interface)
                or (payload.tunnel_ip and duplicate.tunnel_ip == payload.tunnel_ip)
            )
        same_ppp_endpoint = bool(
            protocol in {"l2tp", "pptp"}
            and incoming_public_ip
            and _normalize_public_ip(duplicate.ip_address) == incoming_public_ip
        )
        if not exact_identity and not same_ppp_endpoint:
            continue

        stale = False
        if exact_identity:
            stale = True
        elif same_ppp_endpoint:
            old_pid = int(duplicate.pid or 0)
            current_pid = int(payload.pid or 0)
            if old_pid <= 1 or old_pid == current_pid:
                stale = True
            else:
                try:
                    comm = Path(f"/proc/{old_pid}/comm").read_text(
                        encoding="utf-8", errors="ignore"
                    ).strip()
                    stale = comm != "pppd"
                except OSError:
                    stale = True

        if not stale:
            # A genuinely live overlapping retry remains the admitted tunnel;
            # the newer attempt will be denied without killing the old one.
            continue

        duplicate.is_online = False
        duplicate.presence_state = "offline"
        duplicate.disconnect_time = duplicate.disconnect_time or now
        changed = True

    if changed:
        db.flush()


@router.post("/connect")
def connect_event(payload: InternalConnectEvent, db: Session = Depends(get_db), _=Depends(verify_internal_token)):
    """Atomically admit one new hook-based VPN session.

    The limit is global across PPTP, L2TP/IPsec, SSTP, OpenConnect, OpenVPN,
    IKEv2, VMess and VLESS. Each admitted tunnel consumes one slot regardless of
    whether it comes from the same or a different public IP. The only narrow
    exception is a classic-PPP reconnect handover from the same user, protocol
    and public endpoint while the old control tunnel is timing out. Other
    over-limit connections are rejected before becoming usable.
    """
    protocol = str(payload.protocol or "").lower()
    u = db.query(VpnUser).filter(VpnUser.username == payload.username).first()
    if not u:
        raise HTTPException(404, "user not found")

    # Never run daemon/API probes in the authentication hook.  They made the
    # request exceed the protocol's 5-6 second timeout and caused a total VPN
    # outage.  The background scheduler performs those probes every five
    # seconds; admission does only fast local cleanup below.
    with _user_admission_lock(int(u.id)):
        u = (
            db.query(VpnUser)
            .filter(VpnUser.id == u.id)
            .with_for_update()
            .first()
        )
        if not u:
            raise HTTPException(404, "user not found")
        _assert_user_can_connect(db, u, protocol)

        now = datetime.utcnow()
        # Never probe OpenVPN management sockets from the synchronous connect
        # hook. The fleet reservation layer already performs a same-server,
        # same-protocol, same-public-IP reconnect handover. A daemon scan here
        # added latency to every OpenVPN connection and multiplied status-2
        # traffic precisely while the client was completing its handshake.
        # Background presence reconciliation retires any remaining ghost row.
        _fast_release_stale_rows(db, u.id, now)
        _close_duplicate_attempt(db, u.id, payload, now)

        if payload.ip_address and db.query(InternetBlockedIP).filter(
            InternetBlockedIP.ip_address == payload.ip_address
        ).first():
            db.rollback()
            raise HTTPException(status_code=403, detail="public_ip_internet_blocked")

        # Reserve the account budget on the authoritative controller before the
        # local tunnel becomes usable. The controller counts this server, the
        # main server and every other node in one serialized decision.
        decision = reserve_cluster_session(
            db,
            user=u,
            protocol=protocol,
            public_ip=payload.ip_address,
            pid=payload.pid,
            interface=payload.interface,
            tunnel_ip=payload.tunnel_ip,
            source_port=payload.source_port,
            connect_time=now,
        )
        if not decision.allowed:
            db.rollback()
            raise HTTPException(
                status_code=403,
                detail=decision.reason or "max_devices_reached_all_protocols",
            )
        replaced_session = _retire_cluster_replaced_session(
            db, u.id, payload, decision.replaces_session_key, now
        )
        # A same-endpoint classic-PPP handover is one logical device session.
        # Keep its original start time so Online Users does not look like the
        # customer disconnected and reconnected every time OpenWrt renews the
        # underlying L2TP/PPTP process. A genuinely new connection has no
        # replacement row and therefore starts at ``now`` as usual.
        logical_connect_time = (
            replaced_session.connect_time
            if replaced_session is not None and replaced_session.connect_time is not None
            else now
        )

        ensure_first_connect(u, now)

        session = ConnectionLog(
            user_id=u.id,
            protocol=protocol,
            ip_address=payload.ip_address,
            interface=payload.interface,
            tunnel_ip=payload.tunnel_ip,
            source_port=payload.source_port,
            connect_time=logical_connect_time,
            is_online=True,
            presence_state="active",
            presence_failures=0,
            last_seen_at=now,
            last_activity_at=now,
            pid=payload.pid,
            platform=payload.platform,
            client_info=payload.client_info,
            cluster_session_key=decision.session_key,
        )
        db.add(session)
        db.commit()
        db.refresh(session)
        try:
            from app.services.node_manager import invalidate_local_snapshot_cache

            invalidate_local_snapshot_cache()
        except Exception:
            pass

    handover = replaced_session is not None
    _ensure_runtime_session_network("up", payload, preserve_conntrack=handover)
    apply_session_limits(u, session)
    _schedule_replaced_ppp_retirement(replaced_session, session)
    log_connection_event(
        "🔌 اتصال کاربر",
        f"یوزرنیم: {u.username} | پروتکل: {protocol} | آی‌پی: {payload.ip_address or '-'}"
        + (f" | دستگاه: {payload.platform}" if payload.platform else ""),
    )
    result = {"ok": True, "shared_limit": True}
    if handover:
        result.update({
            "handover": True,
            "replaced_pid": int(replaced_session.pid or 0),
        })
    return result


@router.post("/openvpn-auth")
def openvpn_auth(
    payload: InternalVerifyPasswordEvent, db: Session = Depends(get_db), _=Depends(verify_internal_token)
):
    """صدا زده می‌شود توسط openvpn_auth.sh (auth-user-pass-verify، برای همه‌ی
    کلاینت‌های OpenVPN، صرف‌نظر از cert_only/cert_password بودن کاربر - در
    حالت cert_only هم یوزر/پس همان کاربر نامرئی داخل فایلش هست، دقیقاً برای
    همین چک).

    دو شرط باید هر دو برقرار باشند:
      ۱) username == common_name سرتیفیکیتی که همین کلاینت با آن TLS
         handshake کرده (openvpn خودش common_name را از روی سرتیفیکیت پر
         می‌کند، نه چیزی که کاربر تایپ کرده) - این همان بندی است که تضمین
         می‌کند یک کاربر نتواند با کانفیگ/سرتیفیکیت کاربر دیگری، با یوزر/پس
         خودش یا حتی یوزر/پس درستِ آن کاربر دیگر وصل شود.
      ۲) رمز عبور با password ذخیره‌شده‌ی همان کاربر (همان فیلدی که برای
         L2TP/PPTP هم استفاده می‌شود) مطابقت داشته باشد.
    """
    if payload.username != payload.common_name:
        log_event("⚠️ تلاش اتصال OpenVPN مشکوک", f"یوزرنیم: {payload.username} | CN سرتیفیکیت: {payload.common_name} (عدم تطابق)")
        raise HTTPException(status_code=403, detail="username_cert_mismatch")

    u = db.query(VpnUser).filter(VpnUser.username == payload.username).first()
    if not u or not u.enable_openvpn or not u.is_active or not user_enabled_on_this_server(db, u):
        log_event("⚠️ تلاش اتصال ناموفق", f"یوزرنیم: {payload.username} | دلیل: غیرفعال/موجود نیست")
        raise HTTPException(status_code=403, detail="denied")

    if payload.password != u.password:
        log_event("⚠️ تلاش اتصال با پسورد اشتباه", f"یوزرنیم: {u.username}")
        raise HTTPException(status_code=403, detail="bad_password")

    return {"ok": True}


@router.post("/disconnect")
def disconnect_event(payload: InternalDisconnectEvent, db: Session = Depends(get_db), _=Depends(verify_internal_token)):
    u = db.query(VpnUser).filter(VpnUser.username == payload.username).first()
    if not u:
        raise HTTPException(404, "user not found")

    base_q = db.query(ConnectionLog).filter(
        ConnectionLog.user_id == u.id,
        ConnectionLog.protocol == payload.protocol,
    )
    online_q = base_q.filter(ConnectionLog.is_online == True)  # noqa: E712

    # قبلاً همیشه جدیدترین سشنِ آنلاینِ این کاربر/پروتکل را می‌بست، صرف‌نظر
    # از اینکه واقعاً همان سشنی است که الان قطع شده یا نه. اگر یک سشن قبلی
    # به‌دلیل قطع ناگهانی (کرش pppd، قطع شبکه) بدون اجرای ip-down باقی مانده
    # بود، این باعث می‌شد: ۱) هنگام اتصال بعدی، هم سشن قدیمی هم جدید با هم
    # آنلاین نشان داده شوند («۲ کاربر وصل شده»)، و ۲) با قطع سشنِ جدید،
    # دوباره همان (جدیدترین) رکورد بسته شود و سشن قدیمیِ یتیم برای همیشه
    # «آنلاین» بماند. راه‌حل درست: تطبیق دقیق روی pid (شناسه‌ی pppd همان
    # سشن، که ppp_ip_up.sh فرستاده) و در غیاب آن روی interface؛ فقط اگر
    # هیچ‌کدام موجود نبود (سشن‌های خیلی قدیمی) به جدیدترین برمی‌گردیم.
    session = None
    if payload.pid is not None:
        session = online_q.filter(ConnectionLog.pid == payload.pid).first()
    if session is None and payload.tunnel_ip:
        session = online_q.filter(ConnectionLog.tunnel_ip == payload.tunnel_ip).first()
    if session is None and payload.interface:
        session = online_q.filter(ConnectionLog.interface == payload.interface).first()

    # قطع اجباری از پنل، رکورد را همان لحظه آفلاین می‌کند تا UI منتظر اجرای
    # hook خارجی نماند. چند لحظه بعد ip-down/client-disconnect همان رویداد را
    # با interface/pid می‌فرستد؛ در آن حالت رکورد دیگر online نیست، اما باید
    # همان رکورد را دوباره پیدا کنیم تا فقط دلتای نهایی حجم اضافه شود، نه کل
    # حجم سشن برای بار دوم. جست‌وجوی زیر دقیقاً برای همین حالت است.
    if session is None and payload.pid is not None:
        session = (
            base_q.filter(ConnectionLog.pid == payload.pid)
            .order_by(ConnectionLog.connect_time.desc())
            .first()
        )
    if session is None and payload.tunnel_ip:
        session = (
            base_q.filter(ConnectionLog.tunnel_ip == payload.tunnel_ip)
            .order_by(ConnectionLog.connect_time.desc())
            .first()
        )
    if session is None and payload.interface:
        session = (
            base_q.filter(ConnectionLog.interface == payload.interface)
            .order_by(ConnectionLog.connect_time.desc())
            .first()
        )
    if session is None:
        session = online_q.order_by(ConnectionLog.connect_time.desc()).first()

    cluster_session_key = (
        str(getattr(session, "cluster_session_key", "") or "")
        if session is not None else build_cluster_session_key(
            payload.username,
            payload.protocol,
            pid=payload.pid,
            interface=payload.interface,
            tunnel_ip=payload.tunnel_ip,
            source_port=None,
        )
    )

    # از این به بعد used_bytes دیگر فقط اینجا (لحظه‌ی قطع) اضافه نمی‌شود -
    # sample_ppp_traffic (services/vpn_manager.py) هر MONITOR_INTERVAL_SECONDS
    # هم‌زمان که سشن آنلاین است این کار را می‌کند، وگرنه تا وقتی کاربر وصل
    # بود (حتی روزها) هم صفحه‌ی مصرف و هم چک quota_bytes حجم همان سشن را
    # نادیده می‌گرفتند. برای این‌که همان بایت‌ها اینجا دوباره اضافه نشوند
    # (double count)، به‌جای جمع‌کردن کل payload.bytes_in/out، فقط تفاضل
    # نسبت به آخرین مقداری که روی همین session.bytes_in/out ثبت شده (چه از
    # سمپل زنده، چه صفر اگر هیچ‌وقت سمپل نشده) اضافه می‌شود.
    if session:
        ensure_first_connect(u, session.connect_time or datetime.utcnow())
        remove_session_limits(u, session)
        prev_rx = session.bytes_in or 0
        prev_tx = session.bytes_out or 0
        delta_rx = payload.bytes_in - prev_rx if payload.bytes_in >= prev_rx else payload.bytes_in
        delta_tx = payload.bytes_out - prev_tx if payload.bytes_out >= prev_tx else payload.bytes_out
        session.is_online = False
        session.presence_state = "offline"
        session.disconnect_time = datetime.utcnow()
        session.bytes_in = payload.bytes_in
        session.bytes_out = payload.bytes_out
        u.used_bytes = (u.used_bytes or 0) + delta_rx + delta_tx
    else:
        # رسیدن رویداد قطع با بایت واقعی خودش اثبات می‌کند حساب حداقل یک اتصال
        # موفق داشته؛ حتی اگر رکورد قدیمی سشن پیش‌تر پاک/آفلاین شده باشد.
        if int(payload.bytes_in or 0) > 0 or int(payload.bytes_out or 0) > 0:
            ensure_first_connect(u)
        # هیچ رکورد آنلاینی برای بستن پیدا نشد (مثلاً reconcile_ppp_sessions
        # قبل از رسیدن این رویداد آن را آفلاین کرده بود) - محافظتی، رفتار
        # قبلی را برای اینکه حجمی گم نشود حفظ می‌کنیم.
        u.used_bytes = (u.used_bytes or 0) + payload.bytes_in + payload.bytes_out
    db.commit()
    try:
        from app.services.node_manager import invalidate_local_snapshot_cache

        invalidate_local_snapshot_cache()
    except Exception:
        pass
    try:
        release_cluster_session(db, session_key=cluster_session_key)
        db.commit()
    except Exception:
        db.rollback()
    _ensure_runtime_session_network("down", payload)
    log_connection_event(
        "🔌 قطع اتصال کاربر",
        f"یوزرنیم: {u.username} | پروتکل: {payload.protocol} | "
        f"دریافتی: {payload.bytes_in} بایت | ارسالی: {payload.bytes_out} بایت",
    )
    return {"ok": True}
