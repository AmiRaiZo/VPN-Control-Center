from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_profile_generator_keeps_only_friendly_name_comment():
    text = (ROOT / "backend/app/services/vpn_manager.py").read_text(encoding="utf-8")
    assert "# OVPN_ACCESS_SERVER_FRIENDLY_NAME={friendly_profile_name}" in text
    assert "# Keep the declared order" not in text
    assert "# OpenVPN advances" not in text
    assert "# Keep credentials/certificates" not in text


def test_combined_and_per_node_names_are_explicit():
    users = (ROOT / "backend/app/routers/users.py").read_text(encoding="utf-8")
    sub = (ROOT / "backend/app/routers/sub.py").read_text(encoding="utf-8")
    assert 'profile_name=f"ALL-{_safe_openvpn_filename(u.username)}"' in users
    assert 'profile_name=f"ALL-{_safe_download_name(u.username, \'user\')}"' in sub
    assert 'profile_name=f"{_safe_download_name(u.username)}-{filename_node}"' in sub


def test_fresh_install_has_online_dependency_fallback():
    install = (ROOT / "install/install.sh").read_text(encoding="utf-8")
    update = (ROOT / "install/update.sh").read_text(encoding="utf-8")
    assert "Compact full package detected; downloading Python dependencies" in install
    assert "Downloading required Python dependencies" in update
