from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTROLLER = (ROOT / "backend/app/services/telegram_controller.py").read_text(encoding="utf-8")
SERVICE = (ROOT / "backend/app/services/telegram_groups.py").read_text(encoding="utf-8")
PAGE = (ROOT / "frontend/src/components/TelegramAdminGroups.jsx").read_text(encoding="utf-8")


def test_linked_group_is_authorized_before_sender_panel_binding():
    block = CONTROLLER.split("def _authorized", 1)[1].split("def _is_control_chat", 1)[0]
    assert block.index('if chat_type in {"group", "supergroup"}') < block.index("linked = _linked_admin_for_telegram_id")
    assert "_CURRENT_ADMIN_ID.set(int(owner.id))" in block
    assert "group.admin_id" in block
    assert "Admin.telegram_bot_enabled == True" in block
    assert "if is_expired(owner)" in block


def test_group_link_needs_only_one_time_code_not_telegram_admin_role():
    link = CONTROLLER.split("def _handle_group_link_message", 1)[1].split("def _handle_binding_message", 1)[0]
    assert "getChatAdministrators" not in link
    assert "telegram_admin_ids" not in link
    assert "resolve_link_code(db, code)" in link
    assert "همه اعضای این گروه" in link
    assert "ادمین گروه" in link
    assert "telegram_user_id" not in SERVICE.split("def create_link_code", 1)[1].split("def group_for_chat", 1)[0]


def test_frontend_explains_shared_group_and_does_not_require_numeric_binding():
    assert "همه اعضا مجاز باشند" in PAGE
    assert "لازم نیست ادمین گروه باشند" in PAGE or "لازم نیست ادمین گروه باشند" in PAGE
    can_link = PAGE.split("const canLink", 1)[1].split("const myIds", 1)[0]
    assert "telegram_user_id" not in can_link


def test_release_identity_is_24000():
    assert (ROOT / "VERSION").read_text(encoding="utf-8").strip() == "2.4.0"
    assert 'version="2.4.0"' in (ROOT / "backend/app/main.py").read_text(encoding="utf-8")
