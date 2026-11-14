from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def read(rel):
    return (ROOT / rel).read_text(encoding="utf-8")


def test_member_rule_model_and_migration_are_persistent():
    models = read("backend/app/models.py")
    migrations = read("backend/app/migrations.py")
    assert 'access_mode = Column(String(32)' in models
    assert 'class TelegramGroupMemberRule(Base):' in models
    assert '__tablename__ = "telegram_group_member_rules"' in models
    assert 'UniqueConstraint("group_id", "telegram_user_id"' in models
    assert "(\"telegram_admin_groups\", \"access_mode\", \"VARCHAR(32) NOT NULL DEFAULT 'all_members'\")" in migrations


def test_explicit_member_rule_precedence_and_group_modes():
    service = read("backend/app/services/telegram_groups.py")
    controller = read("backend/app/services/telegram_controller.py")
    assert 'VALID_ACCESS_MODES = {"all_members", "allowlist_only"}' in service
    block = service.split("def member_access_decision", 1)[1].split("def serialize_member_rule", 1)[0]
    assert 'rule.is_allowed' in block
    assert 'getattr(group, "access_mode", None)' in block
    assert 'allowlist_only' in block
    authorized = controller.split("def _authorized", 1)[1].split("def _is_control_chat", 1)[0]
    assert 'member_access_decision(db, group, user_id)' in authorized
    assert authorized.index('member_access_decision(db, group, user_id)') < authorized.index('_CURRENT_ADMIN_ID.set(int(owner.id))')


def test_legacy_member_access_api_is_not_registered_or_bundled():
    router = read("backend/app/routers/telegram_groups.py")
    html = read("frontend/dist/index.html")
    entry = read("frontend/dist/assets/index-v24000.js")
    widget_path = next((ROOT / "frontend/dist/assets").glob("r24000-TelegramBot-*.js"))
    widget = widget_path.read_text(encoding="utf-8")
    assert '@router.get("/{group_id}/members")' in router
    assert '@router.put("/{group_id}/members")' in router
    assert '@router.delete("/{group_id}/members/{telegram_user_id}")' in router
    assert "telegram_groups" not in read("backend/app/main.py")
    assert '/assets/index-v24000.js' in html
    assert widget_path.name in entry
    assert 'telegram-group-member-access-v24000' not in widget
    assert '/telegram-groups/' not in widget


def test_router_is_outermost_and_old_entry_cannot_remount_from_chunks():
    source = read("frontend/src/main.jsx")
    html = read("frontend/dist/index.html")
    entry = read("frontend/dist/assets/index-v24000.js")
    assert source.index("<BrowserRouter>") < source.index("<AppErrorBoundary>") < source.index("<UIProvider>")
    assert "window.__VP_PANEL_REACT_ROOT__" in source
    assert "Node.prototype" not in html
    assert "window.__VP_PANEL_REACT_ROOT__" in entry
    for path in (ROOT / "frontend/dist/assets").glob("*.js"):
        if path.name == "index-v23269.js":
            continue
        assert "index-v23269.js" not in path.read_text(encoding="utf-8"), path.name


def test_backup_and_release_identity_v24000():
    backup = read("backend/app/routers/backup.py")
    assert 'BACKUP_FORMAT_VERSION = 11' in backup
    assert '"telegram_group_member_rules"' in backup
    assert 'TelegramGroupMemberRule' in backup
    assert read("VERSION").strip() == "2.4.0"
    assert 'version="2.4.0"' in read("backend/app/main.py")
    assert 'content="2.4.0"' in read("frontend/dist/index.html")


def test_all_active_frontend_assets_are_release_namespaced_and_navigation_is_safe():
    assets = ROOT / "frontend/dist/assets"
    names = sorted(p.name for p in assets.iterdir() if p.is_file())
    assert "index-v24000.js" in names
    assert "index-v24000.css" in names
    assert all(not name.startswith(("r23261-", "r23263-", "r23269-", "r23270-")) for name in names)
    entry = read("frontend/dist/assets/index-v24000.js")
    assert "useNavigate() may be used only" in entry  # library diagnostic may remain internally
    assert "window.__VP_PANEL_REACT_ROOT__" in entry
    source_login = read("frontend/src/pages/Login.jsx")
    assert "usePanelNavigate" in source_login
    assert "useNavigate" not in source_login
