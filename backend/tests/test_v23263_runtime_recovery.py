from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_pptp_repair_is_runtime_owned_and_self_healing():
    setup = (ROOT / "install/setup_pptp.sh").read_text(encoding="utf-8")
    core = (ROOT / "install/setup_core_protocol.sh").read_text(encoding="utf-8")
    all_installer = (ROOT / "install/install_protocol.sh").read_text(encoding="utf-8")

    required_setup = (
        "normalize_pptp_runtime_config",
        "remoteip 192.168.43.10-192.168.43.250",
        "'listen', 'pidfile', 'logwtmp'",
        "pptpd-logwtmp",
        "clean_stale_pptpd_runtime",
        "TCP/1723 is occupied by",
        "ExecStartPre=/bin/rm -f /run/pptpd.pid",
        "KillMode=control-group",
        "RuntimeDirectory=pptpd",
        "start_and_verify_pptpd",
        "pptpd-last-error.log",
    )
    for fragment in required_setup:
        assert fragment in setup

    # Existing installations must be repaired too; the helper is not gated on
    # a missing binary/unit anymore.
    assert 'SKIP_APT_UPDATE=1 bash "$SCRIPT_DIR/setup_pptp.sh" --start' in core
    assert "Initial PPTP start failed; reinstalling the daemon" in core
    assert "did not pass readiness on the first run" in all_installer
    assert 'setup_pptp.sh" --force --install-only' in all_installer


def test_backup_export_uses_background_job_in_api_and_built_ui():
    route = (ROOT / "backend/app/routers/backup.py").read_text(encoding="utf-8")
    built = next((ROOT / "frontend/dist/assets").glob("r24000-Backup-*.js")).read_text(encoding="utf-8")

    assert '@router.post("/export/start")' in route
    assert '@router.get("/export/status/{job_id}")' in route
    assert '@router.get("/export/download/{job_id}")' in route
    assert "threading.Thread(" in route
    assert "include_cluster_nodes=include_settings" in route
    assert "/backup/export/start" in built
    assert "/backup/export/status/" in built
    assert "/backup/export/download/" in built
    assert "backup generation timeout" in built


def test_transient_license_outage_does_not_create_redirect_loop():
    manager = (ROOT / "backend/app/services/license_manager.py").read_text(encoding="utf-8")
    api = next((ROOT / "frontend/dist/assets").glob("r24000-api-*.js")).read_text(encoding="utf-8")

    assert 'KEY_UNREACHABLE_SINCE = "license_unreachable_since"' in manager
    assert 'current_locked_raw == "0"' in manager
    assert 'previously_valid_or_unlocked' in manager
    assert '"grace_mode": True' in manager
    assert "Any reachable response ends the continuous-outage window" in manager
    assert "/api/license/status" in api
    assert "window.location.replace(`/license-locked`)" in api


def test_release_identity_is_23263_and_active_asset_graph_is_unique():
    assert (ROOT / "VERSION").read_text(encoding="utf-8").strip() == "2.4.0"
    assert 'version="2.4.0"' in (ROOT / "backend/app/main.py").read_text(encoding="utf-8")
    html = (ROOT / "frontend/dist/index.html").read_text(encoding="utf-8")
    assert 'content="2.4.0"' in html
    assert '/assets/index-v24000.js' in html
    assert (ROOT / "frontend/dist/assets/index-v24000.js").is_file()
    assert next((ROOT / "frontend/dist/assets").glob("r24000-Backup-*.js")).is_file()
    assert next((ROOT / "frontend/dist/assets").glob("r24000-api-*.js")).is_file()
