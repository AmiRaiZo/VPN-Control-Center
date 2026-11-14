from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODELS = (ROOT / "backend/app/models.py").read_text(encoding="utf-8")
ROUTER = (ROOT / "backend/app/routers/telegram_groups.py").read_text(encoding="utf-8")
SERVICE = (ROOT / "backend/app/services/telegram_groups.py").read_text(encoding="utf-8")
CONTROLLER = (ROOT / "backend/app/services/telegram_controller.py").read_text(encoding="utf-8")
MAIN = (ROOT / "backend/app/main.py").read_text(encoding="utf-8")
APP = (ROOT / "frontend/src/App.jsx").read_text(encoding="utf-8")
LAYOUT = (ROOT / "frontend/src/components/Layout.jsx").read_text(encoding="utf-8")
PAGE = (ROOT / "frontend/src/components/TelegramAdminGroups.jsx").read_text(encoding="utf-8")
DIST_HTML = (ROOT / "frontend/dist/index.html").read_text(encoding="utf-8")
DIST_ENTRY = (ROOT / "frontend/dist/assets/index-v24000.js").read_text(encoding="utf-8")
DIST_TG = next((ROOT / "frontend/dist/assets").glob("r24000-TelegramBot-*.js")).read_text(encoding="utf-8")
BACKUP = (ROOT / "backend/app/routers/backup.py").read_text(encoding="utf-8")


def test_group_tables_store_owner_but_never_permission_snapshots():
    assert 'class TelegramAdminGroup(Base):' in MODELS
    assert '__tablename__ = "telegram_admin_groups"' in MODELS
    assert 'admin_id = Column(Integer, ForeignKey("admins.id")' in MODELS
    assert 'chat_id = Column(BigInteger, nullable=False, index=True)' in MODELS
    assert 'class TelegramGroupLinkCode(Base):' in MODELS
    # Permissions remain authoritative on Admin and are not copied into a group.
    group_block = MODELS.split('class TelegramAdminGroup(Base):', 1)[1].split('class TelegramGroupLinkCode(Base):', 1)[0]
    assert 'permissions = Column' not in group_block
    assert 'server_targets = Column' not in group_block


def test_legacy_admin_group_api_is_not_exposed_without_legacy_polling_controller():
    assert 'router = APIRouter(prefix="/api/telegram-groups"' in ROUTER
    assert '@router.get("")' in ROUTER
    assert '@router.post("/link-code")' in ROUTER
    assert '@router.patch("/{group_id}")' in ROUTER
    assert '@router.post("/{group_id}/test")' in ROUTER
    assert '@router.delete("/{group_id}")' in ROUTER
    assert 'TelegramAdminGroup.admin_id == admin.id' in ROUTER
    assert 'admin_can_manage_group(admin, row)' in ROUTER
    assert 'admin.role != AdminRole.superadmin' in ROUTER
    assert 'app.include_router(telegram_groups.router)' not in MAIN


def test_one_time_link_is_panel_authorized_and_does_not_require_group_admin():
    assert 'LINK_CODE_TTL_MINUTES = 10' in SERVICE
    assert 'secrets.choice(_CODE_ALPHABET)' in SERVICE
    assert 'code_hash == hash_link_code(normalized)' in SERVICE
    assert 'TelegramGroupLinkCode.used_at.is_(None)' in SERVICE
    assert 'getattr(admin, "telegram_user_id", None)' not in SERVICE.split('def create_link_code', 1)[1].split('def resolve_link_code', 1)[0]
    assert 'if int(getattr(admin, "telegram_user_id", 0) or 0) != int(telegram_user_id or 0)' not in SERVICE
    assert 'def _handle_group_link_message' in CONTROLLER
    link_block = CONTROLLER.split('def _handle_group_link_message', 1)[1].split('def _handle_binding_message', 1)[0]
    assert '"getChatAdministrators"' not in link_block
    assert 'telegram_admin_ids' not in link_block
    assert 'link_row.used_at = utcnow()' in CONTROLLER


def test_every_group_member_runs_as_exact_owner_with_live_permissions():
    assert 'group = group_for_chat(db, chat.get("id"), active_only=False)' in CONTROLLER
    assert 'if int(group.admin_id) != linked_id' not in CONTROLLER
    assert '_CURRENT_ADMIN_ID.set(int(owner.id))' in CONTROLLER
    assert 'owner = db.query(Admin).filter(' in CONTROLLER
    assert 'A linked group is a shared workspace' in CONTROLLER
    assert 'Admin.id == int(requested_id)' in CONTROLLER
    assert 'Admin.is_active == True' in CONTROLLER
    assert 'Admin.telegram_bot_enabled == True' in CONTROLLER
    assert 'if is_expired(admin)' in CONTROLLER
    assert 'permissions = _permission_set(admin)' in CONTROLLER
    assert 'query = query.filter(VpnUser.owner_admin_id == admin.id)' in CONTROLLER
    assert 'admin_can_access_protocol(admin, key)' in CONTROLLER
    assert 'admin_can_access_target' in CONTROLLER


def test_legacy_group_control_page_is_replaced_by_notification_settings():
    assert 'path="telegram-bot"' in APP
    telegram_page = (ROOT / "frontend/src/pages/TelegramBot.jsx").read_text(encoding="utf-8")
    assert 'TelegramAdminGroups' not in telegram_page
    assert 'TelegramDeliverySettings' in telegram_page
    assert 'app.include_router(telegram_groups.router)' not in MAIN
    assert '/telegram-groups/' not in DIST_TG
    assert '/assets/index-v24000.js' in DIST_HTML
    assert 'TelegramBot-' in DIST_ENTRY
    assert 'telegram-group-member-access-v24000' not in DIST_TG
    assert '/telegram-groups/' not in DIST_TG



def test_group_connections_survive_full_backup_without_copying_link_codes():
    assert 'BACKUP_FORMAT_VERSION = 11' in BACKUP
    assert '"telegram_admin_groups": [' in BACKUP
    assert '"owner_admin_username": admin_username_by_id.get(row.admin_id)' in BACKUP
    assert 'for item in data.get("telegram_admin_groups", [])' in BACKUP
    assert 'TelegramGroupMemberRule' in BACKUP
    # One-time codes are deliberately not exported.
    data_block = BACKUP.split('data = {', 1)[1].split('data["counts"]', 1)[0]
    assert '"telegram_group_link_codes":' not in data_block


def test_release_identity_is_24000():
    assert (ROOT / "VERSION").read_text(encoding="utf-8").strip() == "2.4.0"
    assert 'version="2.4.0"' in MAIN
    assert 'content="2.4.0"' in DIST_HTML
    assert '/assets/index-v24000.js' in DIST_HTML
