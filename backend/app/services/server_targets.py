from __future__ import annotations

import json
from typing import Iterable

from app.models import Admin, AdminRole, Setting, VpnNode, VpnUser

ALL_TARGET = "all"
LOCAL_TARGET = "local"
NODE_PREFIX = "node:"
LOCAL_ASSIGNMENT_SETTING = "local_user_assignment_enabled"


def _parse_raw(raw: str | None, *, empty_means_all: bool = True) -> set[str]:
    """Return normalized target tokens.

    Legacy NULL/empty VPN-user and admin rows mean ``all`` so upgrades never
    revoke existing access.  Explicit JSON [] is preserved as an empty admin
    scope when ``empty_means_all`` is False.
    """
    if raw is None or str(raw).strip() == "":
        return {ALL_TARGET} if empty_means_all else set()
    try:
        value = json.loads(raw)
    except Exception:
        value = [item.strip() for item in str(raw).split(",") if item.strip()]
    if not isinstance(value, list):
        return {ALL_TARGET} if empty_means_all else set()
    result = {str(item).strip().lower() for item in value if str(item).strip()}
    return result or ({ALL_TARGET} if empty_means_all else set())


def _setting_bool(db, key: str, default: bool = True) -> bool:
    row = db.query(Setting).filter(Setting.key == key).first()
    if not row or row.value is None:
        return default
    return str(row.value).strip().lower() in {"1", "true", "yes", "on"}


def local_assignment_enabled(db) -> bool:
    return _setting_bool(db, LOCAL_ASSIGNMENT_SETTING, True)


def set_local_assignment_enabled(db, enabled: bool) -> None:
    row = db.query(Setting).filter(Setting.key == LOCAL_ASSIGNMENT_SETTING).first()
    value = "1" if enabled else "0"
    if row:
        row.value = value
    else:
        db.add(Setting(key=LOCAL_ASSIGNMENT_SETTING, value=value))


def targets_for_user(user: VpnUser) -> set[str]:
    # Node-managed rows only exist on a node after the controller selected that
    # node. They must therefore always be accepted by that node's local daemons.
    if bool(getattr(user, "node_managed", False)):
        return {LOCAL_TARGET}
    return _parse_raw(getattr(user, "server_targets", None))


def _parse_admin_scope(raw: str | None) -> set[str]:
    """Legacy NULL/blank remains all; an explicit JSON [] remains empty."""
    if raw is None or str(raw).strip() == "":
        return {ALL_TARGET}
    return _parse_raw(raw, empty_means_all=False)


def targets_for_admin(admin: Admin | None) -> set[str]:
    if admin is None or getattr(admin, "role", None) == AdminRole.superadmin:
        return {ALL_TARGET}
    return _parse_admin_scope(getattr(admin, "server_targets", None))


def targets_for_admin_license(license_row) -> set[str]:
    return _parse_admin_scope(getattr(license_row, "server_targets", None))


def serialize_targets(values: Iterable[str] | None) -> str:
    normalized = {str(item).strip().lower() for item in (values or []) if str(item).strip()}
    if not normalized or ALL_TARGET in normalized:
        return json.dumps([ALL_TARGET], separators=(",", ":"))
    ordered = sorted(normalized, key=lambda item: (item != LOCAL_TARGET, item))
    return json.dumps(ordered, separators=(",", ":"))


def serialize_admin_targets(values: Iterable[str] | None) -> str:
    normalized = {str(item).strip().lower() for item in (values or []) if str(item).strip()}
    if ALL_TARGET in normalized:
        return json.dumps([ALL_TARGET], separators=(",", ":"))
    ordered = sorted(normalized, key=lambda item: (item != LOCAL_TARGET, item))
    return json.dumps(ordered, separators=(",", ":"))


def globally_assignable_tokens(db) -> list[str]:
    result: list[str] = []
    if local_assignment_enabled(db):
        result.append(LOCAL_TARGET)
    rows = (
        db.query(VpnNode)
        .filter(VpnNode.enabled == True, VpnNode.user_assignment_enabled == True)  # noqa: E712
        .order_by(VpnNode.id)
        .all()
    )
    result.extend(f"{NODE_PREFIX}{int(row.id)}" for row in rows)
    return result


def admin_can_access_target(admin: Admin | None, token: str) -> bool:
    allowed = targets_for_admin(admin)
    return ALL_TARGET in allowed or str(token).strip().lower() in allowed


def available_target_tokens(db, admin: Admin | None = None) -> list[str]:
    return [token for token in globally_assignable_tokens(db) if admin_can_access_target(admin, token)]


def user_selected_for_local(user: VpnUser) -> bool:
    targets = targets_for_user(user)
    return ALL_TARGET in targets or LOCAL_TARGET in targets


def user_enabled_on_this_server(db, user: VpnUser) -> bool:
    """Return whether local protocol daemons must accept this user.

    Controller-owned rows obey the controller's local-server assignment switch.
    A ``node_managed`` row, however, exists on a node only because the
    controller explicitly selected that node and pushed the row there.  Older
    code applied the controller-local switch a second time on the node; a stale
    ``local_user_assignment_enabled=0`` setting then made just that node reject
    otherwise-valid OpenVPN credentials with AUTH_FAILED.
    """
    if bool(getattr(user, "node_managed", False)):
        return True
    return bool(local_assignment_enabled(db) and user_selected_for_local(user))


def user_selected_for_node(user: VpnUser, node_id: int) -> bool:
    targets = targets_for_user(user)
    return ALL_TARGET in targets or f"{NODE_PREFIX}{int(node_id)}" in targets


def validate_admin_target_tokens(db, values: Iterable[str] | None) -> list[str]:
    normalized = {str(item).strip().lower() for item in (values or []) if str(item).strip()}
    if ALL_TARGET in normalized:
        return [ALL_TARGET]
    # Admin scope may include a temporarily hidden/offline node, but never a
    # deleted/nonexistent node. This lets a server be hidden from user creation
    # without losing the delegated admin's saved scope when re-enabled.
    allowed = {LOCAL_TARGET}
    allowed.update(f"{NODE_PREFIX}{int(row.id)}" for row in db.query(VpnNode).all())
    invalid = sorted(normalized - allowed)
    if invalid:
        raise ValueError("سرور انتخاب‌شده وجود ندارد: " + ", ".join(invalid))
    return sorted(normalized, key=lambda item: (item != LOCAL_TARGET, item))


def validate_target_tokens(db, values: Iterable[str] | None, admin: Admin | None = None) -> list[str]:
    normalized = {str(item).strip().lower() for item in (values or []) if str(item).strip()}
    available = available_target_tokens(db, admin)
    available_set = set(available)
    if not normalized:
        raise ValueError("حداقل یک سرور فعال و مجاز انتخاب کنید")
    if ALL_TARGET in normalized:
        # Keep the compact future-aware token only for admins whose server scope
        # is also future-aware. Explicitly scoped admins get today's concrete
        # intersection so a later node cannot be granted accidentally.
        if ALL_TARGET in targets_for_admin(admin):
            if not available:
                raise ValueError("هیچ سرور فعالی برای ساخت کاربر وجود ندارد")
            return [ALL_TARGET]
        if not available:
            raise ValueError("هیچ سرور مجازی برای این ادمین فعال نیست")
        return available
    invalid = sorted(normalized - available_set)
    if invalid:
        raise ValueError("سرور انتخاب‌شده فعال نیست یا این ادمین به آن دسترسی ندارد: " + ", ".join(invalid))
    return sorted(normalized, key=lambda item: (item != LOCAL_TARGET, item))


def endpoint_selected_for_user(user: VpnUser, endpoint: dict) -> bool:
    if bool(endpoint.get("local")):
        return user_selected_for_local(user)
    node_id = endpoint.get("id")
    try:
        return user_selected_for_node(user, int(node_id))
    except (TypeError, ValueError):
        return False
