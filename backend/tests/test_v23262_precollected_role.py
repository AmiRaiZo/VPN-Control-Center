from pathlib import Path


def test_precollected_role_is_not_overwritten_by_installed_panel_env():
    root = Path(__file__).resolve().parents[2]
    script = (root / "install" / "install.sh").read_text(encoding="utf-8")

    guard = 'if [ "$PRECOLLECTED_CHOICES" != "1" ]; then'
    old_role_assignment = '[ -n "$CURRENT_ROLE" ] && SERVER_ROLE="$CURRENT_ROLE"'
    old_local_assignment = '[ -n "$CURRENT_LOCAL" ] && INSTALL_LOCAL_SERVICES="$CURRENT_LOCAL"'
    preserve_message = 'Preserving pre-collected deployment choice over installed defaults'

    assert guard in script
    assert preserve_message in script
    guard_pos = script.index(guard)
    role_pos = script.index(old_role_assignment, guard_pos)
    local_pos = script.index(old_local_assignment, guard_pos)
    else_pos = script.index('else', guard_pos)
    assert guard_pos < role_pos < else_pos
    assert guard_pos < local_pos < else_pos
    assert 'invalid pre-collected SERVER_ROLE' in script
    assert 'invalid pre-collected INSTALL_LOCAL_SERVICES' in script


def test_release_identity_is_23263():
    root = Path(__file__).resolve().parents[2]
    assert (root / "VERSION").read_text(encoding="utf-8").strip() == "2.4.0"
    assert 'version="2.4.0"' in (root / "backend/app/main.py").read_text(encoding="utf-8")
    assert 'content="2.4.0"' in (root / "frontend/dist/index.html").read_text(encoding="utf-8")
