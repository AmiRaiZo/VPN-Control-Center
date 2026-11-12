from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_installer_pins_latest_release_and_installs_vpn_help():
    script = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert "releases/latest" in script
    assert "archive/refs/tags/${release_tag}.tar.gz" in script
    assert "jq rsync tar gzip" in script
    assert "/usr/local/bin/vpn-help" in script
    assert 'PYTHON_BIN="${PYTHON_BIN:-python3}"' in script
    assert "python3 python3-venv python3-pip" in script
    assert "(3, 12) <= sys.version_info[:2] < (3, 15)" in script
    assert "python3.12" not in script
    assert '"${APP_DIR}/.venv/bin/python" -m pip install' in script


def test_installer_recreates_an_existing_venv_when_python_is_out_of_range():
    script = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert '"${APP_DIR}/.venv/bin/python" -c' in script
    assert 'rm -rf "${APP_DIR}/.venv"' in script


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
    assert script.count('chown "${SERVICE_USER}:${SERVICE_USER}" "${ENV_FILE}"') == 2
    assert script.count('chmod 0600 "${ENV_FILE}"') == 2


def test_admin_home_button_is_only_added_for_authorized_users():
    source = (ROOT / "src/vpn_manager/bot.py").read_text(encoding="utf-8")
    assert 'if admin:\n        rows.append([("🛡 پنل ادمین", "adm:home")])' in source
    assert '"admin:perm:"' in source


def test_admin_cli_supports_subordinate_admin_creation():
    source = (ROOT / "src/vpn_manager/admin_cli.py").read_text(encoding="utf-8")
    assert '"admin", "finance", "support"' in source
    assert '"source": "vpn-help"' in source

