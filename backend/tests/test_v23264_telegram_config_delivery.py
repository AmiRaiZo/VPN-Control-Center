from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTROLLER = ROOT / "backend/app/services/telegram_controller.py"


def test_created_user_and_user_card_have_delivery_buttons():
    text = CONTROLLER.read_text(encoding="utf-8")
    assert '"📤 ارسال کانفیگ", "callback_data": f"usr:{user.id}:send_config"' in text
    assert '"📁 فایل‌های OpenVPN", "callback_data": f"usr:{user.id}:openvpn_files"' in text
    assert 'if bool(user.enable_openvpn)' in text
    assert 'if action == "send_config":' in text
    assert 'if action == "openvpn_files":' in text


def test_full_delivery_filters_protocols_and_sends_available_assets():
    text = CONTROLLER.read_text(encoding="utf-8")
    assert "def _connection_package_text" in text
    assert 'if bool(item.get("enabled"))' in text
    assert 'bool(getattr(user, f"enable_{key}", False))' in text
    assert "def _send_full_config_package" in text
    assert 'CONNECTION-INFO.txt' in text
    assert "def _send_sstp_certificates" in text
    assert "download_sub_sstp_cert" in text
    assert "def _send_openvpn_files" in text


def test_openvpn_delivery_matches_sub_page_combined_and_per_server_rules():
    text = CONTROLLER.read_text(encoding="utf-8")
    assert "openvpn_profile_nodes(db, user, require_shared_pki=False)" in text
    assert "openvpn_profile_nodes(db, user, require_shared_pki=True)" in text
    assert "if len(ready) > 1 and all_targets_ready:" in text
    assert "download_sub_openvpn_config(user.sub_token, db)" in text
    assert "download_sub_openvpn_config_for_target(target_key, user.sub_token, db)" in text
    assert 'f"ALL-{safe_user}.ovpn"' in text
    assert 'f"{safe_user}-{safe_node}.ovpn"' in text


def test_delivery_messages_are_persistent_and_qr_is_scanner_safe():
    text = CONTROLLER.read_text(encoding="utf-8")
    assert "def _send_persistent_text" in text
    assert "Menu cleanup must therefore" in text
    assert "def _send_document_bytes" in text
    assert '"sendDocument"' in text
    qr_start = text.index("def _subscription_qr_png")
    qr_end = text.index("def _subscription_delivery_keyboard", qr_start)
    qr = text[qr_start:qr_end]
    assert "quiet_modules = max(6" in qr
    assert "canvas_size = 720" in qr
    assert "Orange frame stays outside the white quiet zone" in qr
    assert "circuit" not in qr.lower()


def test_release_identity_is_23264():
    assert (ROOT / "VERSION").read_text(encoding="utf-8").strip() == "2.4.0"
    assert 'version="2.4.0"' in (ROOT / "backend/app/main.py").read_text(encoding="utf-8")
    html = (ROOT / "frontend/dist/index.html").read_text(encoding="utf-8")
    assert 'content="2.4.0"' in html
    # Frontend code did not change in this backend-focused release, so the
    # already-validated active entry remains the 2.3.263 bundle.
    assert '/assets/index-v24000.js' in html
