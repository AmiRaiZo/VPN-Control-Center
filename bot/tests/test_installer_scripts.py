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
    assert all(candidate in script for candidate in ("python3.12", "python3.13", "python3.14"))
    assert '"${APP_DIR}/.venv/bin/python" -m pip install' in script


def test_installer_recreates_an_existing_venv_when_python_is_out_of_range():
    script = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert '"${APP_DIR}/.venv/bin/python" -c' in script
    assert 'rm -rf "${APP_DIR}/.venv"' in script


def test_installer_reads_visible_credentials_directly_from_tty_and_feeds_setup_via_stdin():
    script = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert "printf '%s' \"Bot token (visible input): \" >/dev/tty" in script
    assert "IFS= read -r bot_token </dev/tty" in script
    assert "printf '%s' \"Main admin Telegram numeric ID: \" >/dev/tty" in script
    assert "IFS= read -r admin_ids </dev/tty" in script
    assert "vpn_manager.setup_bot --stdin" in script
    assert "</dev/tty" not in script.split("vpn_manager.setup_bot --stdin")[0].split("runuser")[-1]
    assert "trap on_install_interrupt INT" in script
    assert "unset bot_token admin_ids" in script
    assert "read -r -s" not in script


def test_installer_refreshes_existing_partial_install_without_overwriting_state():
    script = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert 'if [[ ! -f "${APP_DIR}/pyproject.toml" ]]' not in script
    assert "archive/refs/tags/${release_tag}.tar.gz" in script
    updater = (ROOT / "update-local.sh").read_text(encoding="utf-8")
    assert "--exclude='.env'" in updater
    assert "--exclude='var/'" in updater
    assert "--exclude='backups/'" in updater
    assert "--exclude='.venv/'" in updater
    assert "--exclude='.release-tag'" in updater
    assert "vpn-manager-bot" in updater
    assert '"${STAGED_SOURCE}/" "${APP_DIR}/"' in script
    assert '"${release_tag}" > "${APP_DIR}/.release-tag"' in script


def test_vpn_help_has_requested_maintenance_actions_and_safe_uninstall():
    script = (ROOT / "vpn-help.sh").read_text(encoding="utf-8")
    for label in (
        "1) Change Super Admin Telegram ID",
        "2) Add a subordinate administrator",
        "3) Change Telegram bot token",
        "4) Check and install the latest panel Release",
        "5) Uninstall the application and all local data",
    ):
        assert label in script
    assert "releases/latest" in script
    assert '== "REMOVE"' in script
    assert "--set-admin-id" in script
    assert "--set-token" in script
    assert "The systemd service is not installed yet" in script
    assert "No success was reported" in script
    assert "New Telegram bot token (visible input): " in script
    assert "read -r -s" not in script
    assert all(ord(character) < 128 for character in script)


def test_all_ssh_shell_scripts_are_ascii_english():
    for path in ROOT.glob("*.sh"):
        assert path.read_text(encoding="utf-8").isascii(), f"Non-English text found in {path.name}"


def test_admin_home_button_is_only_added_for_authorized_users():
    source = (ROOT / "src/vpn_manager/bot.py").read_text(encoding="utf-8")
    assert 'if admin:\n        rows.append([("🛡 پنل ادمین", "adm:home")])' in source
    assert '"admin:perm:"' in source


def test_admin_cli_supports_subordinate_admin_creation():
    source = (ROOT / "src/vpn_manager/admin_cli.py").read_text(encoding="utf-8")
    assert '"admin", "finance", "support"' in source
    assert '"source": "vpn-help"' in source
