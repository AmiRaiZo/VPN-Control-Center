from pathlib import Path

from app.services import node_manager


class FakeDB:
    def __init__(self):
        self.commits = 0

    def commit(self):
        self.commits += 1


def _patch_store(monkeypatch, values):
    def fake_get(_db, key, default=""):
        return values.get(key, default)

    def fake_set(_db, key, value):
        values[key] = value

    monkeypatch.setattr(node_manager, "_get", fake_get)
    monkeypatch.setattr(node_manager, "_set", fake_set)


def test_explicit_main_deployment_role_wins_over_stale_node_server_role(monkeypatch):
    values = {
        "deployment_role": "main",
        "server_role": "node",
        "node_temporary_main_mode": "1",
        "node_temporary_main_started_at": "stale",
    }
    _patch_store(monkeypatch, values)

    db = FakeDB()
    assert node_manager.is_node_installation(db) is False
    assert node_manager.effective_server_role(db) == "main"
    assert node_manager.panel_ui_server_role(db) == "main"


def test_startup_recovery_does_not_resurrect_deliberate_main_conversion(monkeypatch):
    values = {
        "deployment_role": "main",
        "server_role": "node",
        "node_panel_enabled": "1",
        "node_temporary_main_mode": "1",
        "node_temporary_main_started_at": "stale",
    }
    _patch_store(monkeypatch, values)

    db = FakeDB()
    assert node_manager.repair_orphaned_node_role(db) is True
    assert values["server_role"] == "main"
    assert values["node_temporary_main_mode"] == "0"
    assert values["node_temporary_main_started_at"] == ""
    assert db.commits == 1

    assert node_manager.ensure_deployment_identity(db) is True
    assert values["node_panel_enabled"] == "0"
    assert values["deployment_role"] == "main"
    assert values["server_role"] == "main"
    assert db.commits == 2


def test_reconfigure_script_updates_every_durable_role_source():
    root = Path(__file__).resolve().parents[2]
    script = (root / "install" / "reconfigure_deployment.sh").read_text(encoding="utf-8")

    required_fragments = (
        'BACKEND_ENV="$INSTALL_DIR/backend/.env"',
        'RESULT_ENV="/var/lib/vpn-panel/install-result.env"',
        '"$INSTALL_DIR/backend/venv/bin/python"',
        '"$INSTALL_DIR/backend/venv/bin/python3"',
        '"node_panel_enabled": node_panel_enabled',
        '"node_temporary_main_mode": "0"',
        'rm -f \\\n    /var/lib/vpn-panel/node-registration.env',
        'Verifying effective role after API restart',
    )
    for fragment in required_fragments:
        assert fragment in script
