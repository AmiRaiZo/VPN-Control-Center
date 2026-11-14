from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from aiogram.types import Chat, Message, User

from vpn_manager import bot as bot_module


@pytest.mark.parametrize(
    ("state_name", "expected"),
    [
        ("PanelAdd:name", "panels"),
        ("ManagedClientEdit:days", "panels"),
        ("PlanEdit:price", "plans"),
        ("AdminAdd:role", "admins"),
        ("WalletAdjust:description", "wallet"),
        ("WalletTopup:amount", None),
        (None, None),
    ],
)
def test_admin_fsm_area_maps_only_privileged_workflows(state_name, expected):
    assert bot_module._admin_fsm_area(state_name) == expected


def test_custom_admin_permissions_are_explicit_and_do_not_grant_owner_access():
    assert bot_module._can("custom:panels,orders", "panels")
    assert bot_module._can("custom:panels,orders", "orders")
    assert not bot_module._can("custom:panels,orders", "wallet")
    assert not bot_module._can("custom:panels,orders", "admins")
    assert not bot_module._can("custom:", "panels")


def test_default_roles_keep_their_existing_permission_matrix():
    assert bot_module._role_default_permissions("admin") == {
        "panels",
        "customers",
        "customer_write",
        "plans",
        "orders",
        "stats",
        "wallet",
    }
    assert bot_module._role_default_permissions("finance") == {
        "customers",
        "orders",
        "settings",
        "stats",
        "wallet",
    }
    assert bot_module._role_default_permissions("support") == {"customers", "stats"}


def test_only_owner_default_has_audit_access_but_custom_override_can_grant_it():
    assert bot_module._can("owner", "audit")
    assert not bot_module._can("admin", "audit")
    assert bot_module._can("custom:audit,stats", "audit")


def test_lifecycle_datetime_normalizes_naive_and_offset_aware_values():
    naive = datetime(2026, 11, 12, 10, 0)
    assert bot_module._utc_datetime(naive).tzinfo == UTC
    aware = datetime(2026, 11, 12, 13, 30, tzinfo=UTC)
    assert bot_module._utc_datetime(aware) == aware


@pytest.mark.asyncio
async def test_admin_fsm_message_is_blocked_and_cleared_after_permission_revocation(
    monkeypatch,
):
    state = SimpleNamespace(get_state=AsyncMock(return_value="PanelAdd:url"), clear=AsyncMock())
    event = Message(
        message_id=1,
        date=datetime.now(UTC),
        chat=Chat(id=123, type="private"),
        from_user=User(id=123, is_bot=False, first_name="Admin"),
        text="https://panel.example",
    )
    can = AsyncMock(return_value=False)
    monkeypatch.setattr(bot_module, "_message_can", can)
    handler = AsyncMock()

    result = await bot_module.AdminFSMAccessMiddleware()(handler, event, {"state": state})

    assert result is None
    can.assert_awaited_once_with(event, "panels")
    state.clear.assert_awaited_once()
    handler.assert_not_awaited()


@pytest.mark.asyncio
async def test_cancel_is_allowed_even_when_admin_permission_was_revoked(monkeypatch):
    state = SimpleNamespace(get_state=AsyncMock(return_value="PanelAdd:url"), clear=AsyncMock())
    event = Message(
        message_id=2,
        date=datetime.now(UTC),
        chat=Chat(id=123, type="private"),
        from_user=User(id=123, is_bot=False, first_name="Admin"),
        text="/cancel",
    )
    can = AsyncMock(return_value=False)
    monkeypatch.setattr(bot_module, "_message_can", can)
    handler = AsyncMock(return_value="cancelled")

    result = await bot_module.AdminFSMAccessMiddleware()(handler, event, {"state": state})

    assert result == "cancelled"
    can.assert_not_awaited()
    handler.assert_awaited_once()


@pytest.mark.asyncio
async def test_admin_fsm_rejects_non_text_input_without_running_handler(monkeypatch):
    state = SimpleNamespace(get_state=AsyncMock(return_value="PanelAdd:url"), clear=AsyncMock())
    event = Message(
        message_id=3,
        date=datetime.now(UTC),
        chat=Chat(id=123, type="private"),
        from_user=User(id=123, is_bot=False, first_name="Admin"),
    )
    answer = AsyncMock()
    monkeypatch.setattr(Message, "answer", answer)
    handler = AsyncMock()

    result = await bot_module.AdminFSMAccessMiddleware()(handler, event, {"state": state})

    assert result is None
    answer.assert_awaited_once()
    handler.assert_not_awaited()
    state.clear.assert_not_awaited()
