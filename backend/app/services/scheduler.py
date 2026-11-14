from datetime import date, datetime, timedelta
import logging
import threading
import time
from apscheduler.schedulers.background import BackgroundScheduler

from app.database import SessionLocal
from app.models import VpnUser, ConnectionLog, Setting
from app.services.vpn_manager import (
    sync_chap_secrets, kill_ppp_session, kill_sstp_session, kill_openvpn_session, kill_ikev2_session, kill_openconnect_session,
    reconcile_ppp_sessions, reconcile_openvpn_sessions, reconcile_protocol_services,
    reconcile_ikev2_sessions, sample_openvpn_traffic,
    sample_openconnect_traffic, reconcile_openconnect_sessions, reconcile_openvpn_extra_ports,
    runtime_auth_drift_reasons, repair_runtime_auth_drift, repair_vpn_ingress,
    apply_pending_xl2tpd_restart_if_idle,
)
from app.services.telegram_notifier import log_event, maybe_send_scheduled_backup
from app.services import license_manager, update_manager
from app.services.xray_manager import (
    sample_xray_traffic, fast_reconcile_xray_presence, disconnect_xray_session,
    sync_xray_users, ensure_xray_rate_configuration, XRAY_FAST_PRESENCE_INTERVAL_SECONDS,
)
from app.services.rate_limiter import reconcile_shared_rate_limits
from app.services.admin_license_manager import enforce_expirations
from app.services.node_manager import refresh_all_nodes, refresh_all_node_presence, sync_all_nodes
from app.config import get_settings

settings = get_settings()
logger = logging.getLogger("vpn-panel.scheduler")

# Once a minute, compare the panel-local clock with the configured daily
# backup hour. The setting can change without restarting the API.
TELEGRAM_BACKUP_CHECK_INTERVAL_SECONDS = 60
# Presence is retired every four seconds. Expensive byte/accounting probes stay
# on a separate fifteen-second pass so fast disconnect detection does not make
# the panel or a small node heavy.
LIVE_PRESENCE_INTERVAL_SECONDS = 4
ACCOUNTING_INTERVAL_SECONDS = 15

# One failed daemon probe must never stop the other eight protocols from being
# reconciled.  In 2.3.70 all probes shared one SQLAlchemy session and one
# uncaught exception (for example a temporarily unavailable OpenVPN management
# socket) aborted the pass before VMess/VLESS was reached.  That is why an Xray
# row could stay online for tens of seconds even though the scheduler itself was
# configured for four seconds.
_NON_XRAY_PASS_LOCK = threading.Lock()
_PPP_FAST_REFRESH_LOCK = threading.Lock()
_OPENVPN_FAST_REFRESH_LOCK = threading.Lock()
_XRAY_REFRESH_LOCK = threading.Lock()
_XRAY_FAST_REFRESH_LOCK = threading.Lock()
_LAST_XRAY_SAMPLE_MONOTONIC = 0.0

_OPENVPN_EXTRA_ALERT_SIGNATURE_KEY = "openvpn_extra_ports_alert_signature"
_OPENVPN_EXTRA_ALERT_LAST_SENT_KEY = "openvpn_extra_ports_alert_last_sent_at"
_OPENVPN_EXTRA_ALERT_REPEAT_SECONDS = 6 * 60 * 60


def _run_presence_probe(name, callback) -> bool:
    db = SessionLocal()
    try:
        callback(db)
        return True
    except Exception:
        try:
            db.rollback()
        except Exception:
            pass
        logger.exception("live-presence probe failed: %s", name)
        return False
    finally:
        db.close()


def _mark_xray_sample_complete() -> None:
    global _LAST_XRAY_SAMPLE_MONOTONIC
    _LAST_XRAY_SAMPLE_MONOTONIC = time.monotonic()


def xray_presence_age_seconds() -> float:
    if _LAST_XRAY_SAMPLE_MONOTONIC <= 0:
        return float("inf")
    return max(0.0, time.monotonic() - _LAST_XRAY_SAMPLE_MONOTONIC)


def refresh_xray_presence_if_stale(max_age_seconds: float = 5.5) -> bool:
    """HTTP safety net for the online-users page.

    Normally the background job refreshes Xray every four seconds.  If that
    heartbeat is stale (scheduler startup delay, a worker restart, or a failed
    pass), the next page poll performs one immediate Xray refresh instead of
    serving an old database row indefinitely.  The non-blocking lock avoids
    duplicate expensive API probes when the scheduler is already running.
    """
    if xray_presence_age_seconds() <= max_age_seconds:
        return False
    if not _XRAY_REFRESH_LOCK.acquire(blocking=False):
        return False
    try:
        ok = _run_presence_probe("xray-http-fast-fallback", fast_reconcile_xray_presence)
        return ok
    finally:
        _XRAY_REFRESH_LOCK.release()



def reconcile_xray_fast_job():
    """Retire dead VMess/VLESS transports independently in about four seconds.

    The fast reconciler now validates only exact kernel endpoints and never
    creates/attributes sessions, so it no longer waits behind slow accounting.
    Admission updates remain serialised inside xray_manager.
    """
    if not _XRAY_FAST_REFRESH_LOCK.acquire(blocking=False):
        return
    try:
        _run_presence_probe("xray-fast-presence", fast_reconcile_xray_presence)
    finally:
        _XRAY_FAST_REFRESH_LOCK.release()

def reconcile_xray_job():
    """Refresh VMess/VLESS accounting independently every fifteen seconds.

    This job deliberately does not share a lock or transaction with PPP,
    OpenVPN, OpenConnect, or IKEv2. Slow/unavailable daemons therefore cannot
    delay Xray offline detection.
    """
    if not _XRAY_REFRESH_LOCK.acquire(blocking=False):
        return
    try:
        _run_presence_probe("xray-rate-config", ensure_xray_rate_configuration)
        if _run_presence_probe("xray-presence", sample_xray_traffic):
            _mark_xray_sample_complete()
        _run_presence_probe("shared-rate-limits-after-xray", reconcile_shared_rate_limits)
    finally:
        _XRAY_REFRESH_LOCK.release()


def reconcile_ppp_fast_job():
    """Retire disconnected L2TP/PPTP rows on an isolated four-second clock.

    OpenVPN/OpenConnect management probes can occasionally wait on a daemon
    socket.  Keeping PPP behind those probes meant that a nominal four-second
    scheduler could still take much longer to notice an L2TP disconnect.  This
    dedicated job only samples/reconciles pppd and therefore cannot be delayed
    by another protocol.
    """
    if not _PPP_FAST_REFRESH_LOCK.acquire(blocking=False):
        return
    try:
        # reconcile_ppp_sessions records the last interface counters before it
        # closes stale rows, so one isolated transaction is enough here.
        _run_presence_probe("ppp-fast-presence", reconcile_ppp_sessions)
        # Daemon-level L2TP changes are deferred while any pppd call exists.
        # Check on the same two-second clock only after stale rows/processes are
        # reconciled; this never restarts xl2tpd during an active tunnel.
        apply_pending_xl2tpd_restart_if_idle()
    finally:
        _PPP_FAST_REFRESH_LOCK.release()



def reconcile_openvpn_fast_job():
    """Retire disappeared OpenVPN clients on an isolated two-second clock."""
    if not _OPENVPN_FAST_REFRESH_LOCK.acquire(blocking=False):
        return
    try:
        _run_presence_probe("openvpn-fast-presence", reconcile_openvpn_sessions)
    finally:
        _OPENVPN_FAST_REFRESH_LOCK.release()

def reconcile_sessions_job():
    """Run the remaining non-Xray presence/accounting probes.

    Every protocol probe has an isolated database transaction, so one failed
    daemon cannot cancel the rest of the pass. L2TP/PPTP have their own strict
    four-second job above; VMess/VLESS are handled by their dedicated jobs.
    """
    if not _NON_XRAY_PASS_LOCK.acquire(blocking=False):
        return
    try:
        _run_presence_probe("openvpn-traffic", sample_openvpn_traffic)
        _run_presence_probe("openconnect-traffic", sample_openconnect_traffic)
        _run_presence_probe("openconnect-presence", reconcile_openconnect_sessions)
        _run_presence_probe("ikev2-presence", reconcile_ikev2_sessions)
        _run_presence_probe("shared-rate-limits", reconcile_shared_rate_limits)
    finally:
        _NON_XRAY_PASS_LOCK.release()

    try:
        enforce_limits_job()
    except Exception:
        logger.exception("limit enforcement failed after live-presence pass")


def enforce_limits_job():
    """بررسی دوره‌ای: انقضای تاریخ، اتمام حجم و قطع اتصال کاربران غیرمجاز."""
    db = SessionLocal()
    try:
        changed = False
        users = db.query(VpnUser).filter(VpnUser.is_active == True).all()  # noqa: E712
        for u in users:
            expired = u.expire_date is not None and u.expire_date < date.today()
            over_quota = u.quota_bytes > 0 and u.used_bytes >= u.quota_bytes
            if expired or over_quota:
                u.is_active = False
                changed = True
                kill_ppp_session(db, u.username)
                kill_sstp_session(db, u.username)
                kill_openvpn_session(u.username)
                kill_ikev2_session(db, u.username)
                kill_openconnect_session(u.username)
                disconnect_xray_session(db, u.username)
                log_event(
                    "⏳ غیرفعال‌سازی خودکار یوزر",
                    f"یوزرنیم: {u.username} | دلیل: {'انقضای تاریخ' if expired else 'اتمام حجم'}",
                )
                # علامت‌گذاری سشن‌های باز به‌عنوان قطع‌شده
                open_sessions = (
                    db.query(ConnectionLog)
                    .filter(ConnectionLog.user_id == u.id, ConnectionLog.is_online == True)  # noqa: E712
                    .all()
                )
                for s in open_sessions:
                    s.is_online = False
                    s.disconnect_time = datetime.utcnow()
        if changed:
            db.commit()
            sync_chap_secrets(db)
            try:
                sync_xray_users(db, protocols=("vmess", "vless"), restart=True)
            except Exception:
                pass
    finally:
        db.close()


def runtime_auth_watchdog_job():
    """Repair deleted/stale protocol credential files without waiting for a
    user edit. The probe is read-only when stores are healthy, so it can run on
    both the controller and managed nodes without unnecessary service restarts.
    """
    db = SessionLocal()
    try:
        reasons = runtime_auth_drift_reasons(db)
        if not reasons:
            return
        repaired = repair_runtime_auth_drift(db, reasons)
        remaining = runtime_auth_drift_reasons(db)
        if remaining:
            logger.warning(
                "runtime auth drift remains after self-repair: reasons=%s repaired=%s remaining=%s",
                reasons, repaired, remaining,
            )
        else:
            logger.warning(
                "runtime auth drift self-repaired: reasons=%s repaired=%s",
                reasons, repaired,
            )
    except Exception:
        logger.exception("runtime auth watchdog failed")
    finally:
        db.close()


def vpn_ingress_watchdog_job():
    """Read/repair VPN listeners and host ingress at a deliberately slow
    cadence. Transport checks must never flap healthy tunnels; the 30-second
    credential/service watchdog is kept separate from firewall reconciliation.
    """
    try:
        ok, output = repair_vpn_ingress()
        if not ok:
            logger.warning("VPN ingress watchdog reported an incomplete state: %s", output[-2000:])
        elif "REPAIR " in output:
            logger.warning("VPN ingress watchdog repaired drift: %s", output[-2000:])
    except Exception:
        logger.exception("VPN ingress watchdog failed")


def reconcile_protocol_services_job():
    """هر PROTOCOL_WATCHDOG_INTERVAL_SECONDS یک‌بار: اگر سرویس یکی از
    پروتکل‌ها (بیشتر از همه SSTP/accel-ppp که سابقه‌ی کرش غیرمنتظره دارد)
    با وجود این‌که در تنظیمات پنل «فعال» علامت خورده، واقعاً خاموش/کرش‌کرده
    باشد، خودش را دوباره روشن می‌کند - رفع دقیق همان مشکل «SSTP بعد از چند
    دقیقه خاموش می‌شود و باید از پنل دوباره ذخیره شود»."""
    db = SessionLocal()
    try:
        reconcile_protocol_services(db)
    finally:
        db.close()


def _scheduler_setting(db, key: str) -> str:
    row = db.query(Setting).filter(Setting.key == key).first()
    return str(row.value or "") if row else ""


def _set_scheduler_setting(db, key: str, value: str) -> None:
    row = db.query(Setting).filter(Setting.key == key).first()
    if row:
        row.value = value
    else:
        db.add(Setting(key=key, value=value))


def reconcile_openvpn_extra_ports_job():
    """Repair active listeners without flooding Telegram or the host.

    A persistent bind/configuration problem used to emit the same alert on
    every watchdog tick and start another Telegram delivery thread. Besides
    spamming the owner, slow Telegram retries could consume the DB pool used by
    login. The durable signature below sends immediately when the broken set
    changes, then at most once every six hours until recovery.
    """
    db = SessionLocal()
    try:
        unresolved = sorted(set(reconcile_openvpn_extra_ports(db)))
        signature = ",".join(unresolved)
        previous = _scheduler_setting(db, _OPENVPN_EXTRA_ALERT_SIGNATURE_KEY)
        last_sent_raw = _scheduler_setting(db, _OPENVPN_EXTRA_ALERT_LAST_SENT_KEY)
        try:
            last_sent = datetime.fromisoformat(last_sent_raw) if last_sent_raw else None
        except ValueError:
            last_sent = None
        now = datetime.utcnow()

        if unresolved:
            elapsed = (now - last_sent).total_seconds() if last_sent else float("inf")
            if signature != previous or elapsed >= _OPENVPN_EXTRA_ALERT_REPEAT_SECONDS:
                log_event(
                    "⚠️ خودترمیم پورت اضافه‌ی OpenVPN ناموفق بود",
                    "وضعیت فعال پورت‌ها در پنل حفظ شد، اما لیسنرهای زیر هنوز روی سرور بالا نیستند: "
                    + ", ".join(unresolved),
                )
                _set_scheduler_setting(db, _OPENVPN_EXTRA_ALERT_LAST_SENT_KEY, now.isoformat())
            _set_scheduler_setting(db, _OPENVPN_EXTRA_ALERT_SIGNATURE_KEY, signature)
            db.commit()
            return

        if previous:
            log_event(
                "✅ پورت‌های اضافه‌ی OpenVPN ترمیم شدند",
                "تمام لیسنرهای فعال OpenVPN دوباره روی سرور در حال اجرا هستند.",
            )
            _set_scheduler_setting(db, _OPENVPN_EXTRA_ALERT_SIGNATURE_KEY, "")
            _set_scheduler_setting(db, _OPENVPN_EXTRA_ALERT_LAST_SENT_KEY, "")
            db.commit()
    except Exception:
        db.rollback()
        logger.exception("OpenVPN extra-port watchdog failed")
    finally:
        db.close()


def update_notification_job():
    """Refresh the Telegram update message and emit one success/failure log.

    The runner restarts the API during deployment; this scheduler job resumes
    from durable files and continues editing the exact same Telegram message.
    """
    db = SessionLocal()
    try:
        update_manager.process_update_notifications(db)
    except Exception:
        logger.exception("update notification watcher failed")
    finally:
        db.close()


def subadmin_license_check_job():
    db = SessionLocal()
    try:
        enforce_expirations(db)
    finally:
        db.close()


def license_check_job():
    """هر LICENSE_CHECK_INTERVAL_SECONDS یک‌بار: چک وضعیت لایسنس از سرور
    مرکزی و قفل/بازکردن خودکار سرویس‌های VPN بر همان اساس - نگاه کنید به
    license_manager.py."""
    db = SessionLocal()
    try:
        license_manager.refresh_license_status(db)
    finally:
        db.close()


def node_presence_job():
    refresh_all_node_presence()


def node_health_job():
    refresh_all_nodes()


def node_sync_job():
    sync_all_nodes()


def start_scheduler():
    scheduler = BackgroundScheduler(timezone="UTC")
    now = datetime.utcnow()

    def delayed(seconds: int):
        # Starting every daemon/SSH/license probe in the same millisecond caused
        # CPU/DB/socket bursts after API restarts.  Spread first runs across the
        # first minute; later runs retain their normal interval.
        return now + timedelta(seconds=seconds)

    scheduler.add_job(
        enforce_limits_job, "interval", seconds=60, id="enforce_limits_fallback",
        replace_existing=True, coalesce=True, max_instances=1, next_run_time=delayed(29),
    )
    scheduler.add_job(
        reconcile_xray_fast_job, "interval", seconds=max(4, XRAY_FAST_PRESENCE_INTERVAL_SECONDS),
        id="reconcile_xray_fast_presence", replace_existing=True, coalesce=True,
        max_instances=1, misfire_grace_time=3, next_run_time=delayed(4),
    )
    scheduler.add_job(
        reconcile_xray_job, "interval", seconds=15, id="reconcile_xray_sessions",
        replace_existing=True, coalesce=True, max_instances=1, misfire_grace_time=5,
        next_run_time=delayed(11),
    )
    scheduler.add_job(
        reconcile_ppp_fast_job, "interval", seconds=LIVE_PRESENCE_INTERVAL_SECONDS,
        id="reconcile_ppp_fast_presence", replace_existing=True, coalesce=True,
        max_instances=1, misfire_grace_time=3, next_run_time=delayed(2),
    )
    scheduler.add_job(
        reconcile_openvpn_fast_job, "interval", seconds=LIVE_PRESENCE_INTERVAL_SECONDS,
        id="reconcile_openvpn_fast_presence", replace_existing=True, coalesce=True,
        max_instances=1, misfire_grace_time=3, next_run_time=delayed(3),
    )
    scheduler.add_job(
        reconcile_sessions_job, "interval", seconds=ACCOUNTING_INTERVAL_SECONDS,
        id="reconcile_sessions", replace_existing=True, coalesce=True, max_instances=1,
        misfire_grace_time=5, next_run_time=delayed(9),
    )
    scheduler.add_job(
        vpn_ingress_watchdog_job, "interval",
        seconds=max(300, settings.PROTOCOL_WATCHDOG_INTERVAL_SECONDS),
        id="vpn_ingress_watchdog", replace_existing=True, coalesce=True,
        max_instances=1, next_run_time=delayed(90),
    )
    watchdog_seconds = max(60, settings.PROTOCOL_WATCHDOG_INTERVAL_SECONDS)
    scheduler.add_job(
        reconcile_protocol_services_job, "interval", seconds=watchdog_seconds,
        id="reconcile_protocol_services", replace_existing=True, coalesce=True,
        max_instances=1, next_run_time=delayed(21),
    )
    scheduler.add_job(
        runtime_auth_watchdog_job, "interval", seconds=watchdog_seconds,
        id="runtime_auth_watchdog", replace_existing=True, coalesce=True,
        max_instances=1, next_run_time=delayed(33),
    )
    scheduler.add_job(
        reconcile_openvpn_extra_ports_job, "interval", seconds=max(300, watchdog_seconds),
        id="reconcile_openvpn_extra_ports", replace_existing=True, coalesce=True,
        max_instances=1, next_run_time=delayed(45),
    )
    scheduler.add_job(
        subadmin_license_check_job, "interval", seconds=30, id="subadmin_license_check",
        replace_existing=True, coalesce=True, max_instances=1, next_run_time=delayed(17),
    )
    scheduler.add_job(
        update_notification_job, "interval", seconds=30, id="update_notifications",
        replace_existing=True, coalesce=True, max_instances=1, misfire_grace_time=5,
        next_run_time=delayed(23),
    )
    scheduler.add_job(
        maybe_send_scheduled_backup, "interval", seconds=TELEGRAM_BACKUP_CHECK_INTERVAL_SECONDS,
        id="telegram_scheduled_backup", replace_existing=True, coalesce=True,
        max_instances=1, next_run_time=delayed(37),
    )
    scheduler.add_job(
        node_presence_job, "interval", seconds=10, id="node_presence",
        replace_existing=True, coalesce=True, max_instances=1, misfire_grace_time=5,
        next_run_time=delayed(7),
    )
    scheduler.add_job(
        node_health_job, "interval", seconds=30, id="node_health",
        replace_existing=True, coalesce=True, max_instances=1, next_run_time=delayed(19),
    )
    scheduler.add_job(
        node_sync_job, "interval", seconds=120, id="node_sync",
        replace_existing=True, coalesce=True, max_instances=1, next_run_time=delayed(51),
    )
    scheduler.add_job(
        license_check_job, "interval", seconds=max(15, settings.LICENSE_CHECK_INTERVAL_SECONDS),
        id="license_check", replace_existing=True, coalesce=True, max_instances=1,
        next_run_time=delayed(13),
    )
    scheduler.start()
    return scheduler
