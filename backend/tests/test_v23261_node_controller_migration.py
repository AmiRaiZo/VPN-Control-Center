from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_node_controller_backend_is_register_first_and_transactional():
    text = (ROOT / "backend/app/routers/settings.py").read_text(encoding="utf-8")

    register_call = text.index(
        "_register_with_controller(payload.controller_url, payload.controller_token, payload.verify_controller_tls, registration_payload)"
    )
    persist_call = text.index("_persist_controller_migration(", register_call)
    assert register_call < persist_call

    assert '@router.get("/node-controller")' in text
    assert '@router.post("/node-controller")' in text
    assert 'effective_server_role(db) != "node"' in text
    assert 'require_superadmin' in text
    assert 'node_controller_token' in text
    assert '/var/lib/vpn-panel/node-registration.env' in text
    assert '/opt/vpn-panel/panel.env' in text
    assert '/opt/vpn-panel/backend/.env' in text
    assert '/var/lib/vpn-panel/install-result.env' in text
    assert 'os.replace(marker_tmp, marker)' in text
    assert text.index('os.replace(marker_tmp, marker)') < text.index('db.commit()', text.index('os.replace(marker_tmp, marker)'))


def test_old_controller_cleanup_has_two_secret_endpoint():
    nodes = (ROOT / "backend/app/routers/nodes.py").read_text(encoding="utf-8")
    schemas = (ROOT / "backend/app/schemas.py").read_text(encoding="utf-8")

    assert '@agent_router.post("/unregister")' in nodes
    assert '_agent_auth(db, x_node_token)' in nodes
    assert 'VpnNode.api_token == payload.api_token.strip()' in nodes
    assert 'def _remove_node_record' in nodes
    assert 'class NodeSelfUnregisterRequest' in schemas
    assert 'api_token: str = Field(..., min_length=16' in schemas


def test_node_settings_ui_contains_controller_migration_card():
    source = (ROOT / "frontend/src/pages/Settings.jsx").read_text(encoding="utf-8")
    api = (ROOT / "frontend/src/api.js").read_text(encoding="utf-8")
    html = (ROOT / "frontend/dist/index.html").read_text(encoding="utf-8")
    main = (ROOT / "frontend/dist/assets/index-v24000.js").read_text(encoding="utf-8")
    chunk_path = next((ROOT / "frontend/dist/assets").glob("r24000-Settings-*.js"))
    chunk = chunk_path.read_text(encoding="utf-8")

    assert "function NodeControllerCard()" in source
    assert "<NodeControllerCard />" in source
    assert "'/settings/node-controller'" in source
    assert "node-controller" in api
    assert '/assets/index-v24000.js' in html
    assert chunk_path.name in main
    assert 'تغییر سرور اصلی نود' in chunk
    assert '/settings/node-controller' in chunk
    assert './index-v24000.js' in chunk
    assert '`aria-checked`:' not in chunk
