from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_telegram_log_delivery_is_bounded_and_single_worker():
    src = read("backend/app/services/telegram_notifier.py")
    assert "queue.Queue(maxsize=512)" in src
    assert "threading.Thread(target=_log_worker" in src
    assert "_LOG_SEND_TIMEOUT_SECONDS = 6" in src
    assert "_LOG_SEND_MAX_ATTEMPTS = 2" in src
    assert "_LOG_QUEUE.put_nowait(task)" in src
    assert "del db  # a request-bound Session must never cross" in src
    # The worker must close the SQLAlchemy session before doing network I/O.
    load_start = src.index("def _load_log_delivery")
    deliver_start = src.index("def _deliver_queued_log")
    load_block = src[load_start:deliver_start]
    assert "session.close()" in load_block
    assert "send_text(" not in load_block


def test_openvpn_listener_alerts_are_deduplicated_and_rate_limited():
    src = read("backend/app/services/scheduler.py")
    assert '_OPENVPN_EXTRA_ALERT_SIGNATURE_KEY = "openvpn_extra_ports_alert_signature"' in src
    assert '_OPENVPN_EXTRA_ALERT_LAST_SENT_KEY = "openvpn_extra_ports_alert_last_sent_at"' in src
    assert "_OPENVPN_EXTRA_ALERT_REPEAT_SECONDS = 6 * 60 * 60" in src
    assert "signature != previous or elapsed >= _OPENVPN_EXTRA_ALERT_REPEAT_SECONDS" in src
    assert "max(300, watchdog_seconds)" in src
    assert "✅ پورت‌های اضافه‌ی OpenVPN ترمیم شدند" in src


def test_impossible_legacy_extra_listeners_are_normalized():
    manager = read("backend/app/services/vpn_manager.py")
    settings = read("backend/app/routers/settings.py")
    assert 'if _db_setting(db, "local_services_mode", 1) == 0:' in manager
    assert 'if _db_setting(db, "openvpn_enabled", 1) == 0:' in manager
    assert "is_primary_duplicate" in manager
    assert "row.is_active = False" in manager
    assert "پورت اصلی OpenVPN" in settings


def test_login_has_a_hard_timeout_in_source_and_built_asset():
    source = read("frontend/src/pages/Login.jsx")
    assert "ECONNABORTED" in source
    assert "timeout: 15000" in source
    built = next((ROOT / "frontend/dist/assets").glob("r24000-Login-*.js")).read_text(encoding="utf-8")
    assert "ECONNABORTED" in built
    assert "timeout:15e3" in built


def test_release_identity_and_no_old_active_asset_namespace():
    assert read("VERSION").strip() == "2.4.0"
    assert 'version="2.4.0"' in read("backend/app/main.py")
    index = read("frontend/dist/index.html")
    assert "2.4.0" in index
    assert "index-v24000.js" in index
    active_files = [p.name for p in (ROOT / "frontend/dist/assets").iterdir() if p.is_file()]
    assert active_files
    assert all("23271" not in name for name in active_files)
