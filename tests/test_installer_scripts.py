from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_installer_pins_latest_release_and_installs_vpn_help():
    script = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert "releases/latest" in script
    assert "archive/refs/tags/${release_tag}.tar.gz" in script
    assert "jq rsync tar gzip" in script
    assert "/usr/local/bin/vpn-help" in script


def test_vpn_help_has_requested_maintenance_actions_and_safe_uninstall():
    script = (ROOT / "vpn-help.sh").read_text(encoding="utf-8")
    for label in (
        "تغییر شناسه Super Admin",
        "اضافه کردن ادمین زیرمجموعه",
        "تغییر توکن ربات تلگرام",
        "بررسی و نصب آخرین نسخه Release پنل",
        "حذف کامل برنامه و اطلاعات",
    ):
        assert label in script
    assert "releases/latest" in script
    assert '== "REMOVE"' in script


def test_admin_home_button_is_only_added_for_authorized_users():
    source = (ROOT / "src/vpn_manager/bot.py").read_text(encoding="utf-8")
    assert 'if admin:\n        rows.append([("🛡 پنل ادمین", "adm:home")])' in source
    assert '"admin:perm:"' in source


def test_admin_cli_supports_subordinate_admin_creation():
    source = (ROOT / "src/vpn_manager/admin_cli.py").read_text(encoding="utf-8")
    assert '"admin", "finance", "support"' in source
    assert '"source": "vpn-help"' in source

