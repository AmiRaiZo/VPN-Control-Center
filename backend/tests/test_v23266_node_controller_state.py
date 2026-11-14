from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_node_controller_route_is_allowed_through_node_role_guard():
    main = (ROOT / "backend/app/main.py").read_text(encoding="utf-8")
    assert '"/api/settings/node-controller"' in main
    assert "path.startswith(_NODE_ALLOWED_PREFIXES)" in main


def test_node_controller_state_reads_current_and_legacy_durable_sources():
    settings = (ROOT / "backend/app/routers/settings.py").read_text(encoding="utf-8")
    for path in (
        '/var/lib/vpn-panel/node-registration.env',
        '/opt/vpn-panel/panel.env',
        '/opt/vpn-panel/backend/.env',
        '/var/lib/vpn-panel/install-result.env',
    ):
        assert path in settings
    assert 'first_env("NODE_CONTROLLER_URL", "CONTROLLER_URL")' in settings
    assert 'first_env("NODE_CONTROLLER_TOKEN", "CONTROLLER_TOKEN")' in settings
    assert 'or os.uname().nodename.split(".", 1)[0]' in settings
    assert '"controller_token": controller_token' in settings
    assert '"token_configured": bool(controller_token)' in settings


def test_node_controller_api_still_requires_superadmin_and_hides_token_from_response():
    settings = (ROOT / "backend/app/routers/settings.py").read_text(encoding="utf-8")
    route = settings[settings.index('@router.get("/node-controller")'):settings.index('@router.post("/node-controller")')]
    assert 'Depends(require_superadmin)' in route
    assert 'state.pop("controller_token", None)' in route
