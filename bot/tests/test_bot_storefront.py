from datetime import UTC, datetime, timedelta
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from aiogram.exceptions import TelegramAPIError, TelegramBadRequest
from aiogram.methods import SendMessage
from aiogram.types import BufferedInputFile
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from vpn_manager import bot as bot_module
from vpn_manager.models import (
    AdminUser,
    AuditLog,
    Base,
    Customer,
    ManagedClient,
    Order,
    Panel,
    Subscription,
    VPNService,
)


@pytest.fixture
async def admin_session_factory(tmp_path, monkeypatch):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'bot-admins.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    monkeypatch.setattr(bot_module, "AsyncSessionFactory", factory)
    monkeypatch.setattr(bot_module, "_root_admins", lambda: frozenset({1001}))
    yield factory
    await engine.dispose()


def test_profile_routes_are_not_registered_for_removed_history_pages():
    handlers = bot_module.router.callback_query.handlers
    callbacks = [str(handler.callback) for handler in handlers]

    assert not any("shop_profile_orders" in callback for callback in callbacks)
    assert not any("shop_profile_active" in callback for callback in callbacks)


@pytest.mark.asyncio
async def test_purchase_animation_uses_bundled_gif_and_returns_sent_message():
    sent = SimpleNamespace(message_id=77, delete=AsyncMock())
    bot = SimpleNamespace(send_animation=AsyncMock(return_value=sent))

    result = await bot_module._send_progress_animation(bot, 12345, "در حال آماده‌سازی")

    assert result is sent
    bot.send_animation.assert_awaited_once()
    args, kwargs = bot.send_animation.await_args
    assert args[0] == 12345
    assert isinstance(args[1], BufferedInputFile)
    assert kwargs["caption"] == "در حال آماده‌سازی"
    assert args[1].filename == "vpn-purchase-progress.gif"


@pytest.mark.asyncio
async def test_purchase_animation_failure_returns_none_for_text_fallback():
    bot = SimpleNamespace(
        send_animation=AsyncMock(
            side_effect=TelegramAPIError(
                method=SendMessage(chat_id=12345, text="test"), message="animation unavailable"
            )
        )
    )

    assert await bot_module._send_progress_animation(bot, 12345, "در حال آماده‌سازی") is None


@pytest.mark.asyncio
async def test_state_prompt_replaces_the_previous_transient_prompt():
    sent = SimpleNamespace(message_id=92)
    bot = SimpleNamespace(delete_message=AsyncMock())
    state = SimpleNamespace(
        get_data=AsyncMock(return_value={"_prompt_message_id": 91}),
        update_data=AsyncMock(),
    )
    message = SimpleNamespace(
        bot=bot,
        chat=SimpleNamespace(id=123),
        answer=AsyncMock(return_value=sent),
    )

    result = await bot_module._state_prompt(message, state, "مرحله بعد")

    assert result is sent
    bot.delete_message.assert_awaited_once_with(123, 91)
    message.answer.assert_awaited_once_with("مرحله بعد")
    state.update_data.assert_awaited_once_with(_prompt_message_id=92)


@pytest.mark.asyncio
async def test_callback_error_handler_sends_recovery_menu_for_unhandled_failure():
    bot = SimpleNamespace(send_message=AsyncMock())
    callback = SimpleNamespace(
        bot=bot,
        data="plan:show:invalid-id",
        from_user=SimpleNamespace(id=51001),
        message=SimpleNamespace(chat=SimpleNamespace(id=51001)),
    )
    event = SimpleNamespace(
        update=SimpleNamespace(callback_query=callback),
        exception=ValueError("invalid UUID"),
    )

    assert await bot_module.callback_error_handler(event)

    bot.send_message.assert_awaited_once()
    args, kwargs = bot.send_message.await_args
    assert args[0] == 51001
    assert "دکمه قدیمی" in args[1]
    buttons = [button for row in kwargs["reply_markup"].inline_keyboard for button in row]
    assert len(buttons) == 1 and buttons[0].callback_data == "home"


@pytest.mark.asyncio
async def test_callback_error_handler_ignores_already_applied_message_edit():
    bot = SimpleNamespace(send_message=AsyncMock())
    callback = SimpleNamespace(
        bot=bot,
        data="home",
        from_user=SimpleNamespace(id=51001),
        message=SimpleNamespace(chat=SimpleNamespace(id=51001)),
    )
    event = SimpleNamespace(
        update=SimpleNamespace(callback_query=callback),
        exception=TelegramBadRequest(
            method=SendMessage(chat_id=51001, text="same"),
            message="message is not modified",
        ),
    )

    assert await bot_module.callback_error_handler(event)
    bot.send_message.assert_not_awaited()


@pytest.mark.asyncio
async def test_bulk_panel_api_cache_reuses_and_closes_one_session_per_panel(monkeypatch):
    panel = SimpleNamespace(id="panel-1")
    api = SimpleNamespace(close=AsyncMock())
    create_api = AsyncMock(return_value=api)
    monkeypatch.setattr(bot_module, "_panel_api", create_api)
    clients = {}

    first = await bot_module._cached_panel_api(panel, clients)
    second = await bot_module._cached_panel_api(panel, clients)

    assert first is second is api
    create_api.assert_awaited_once_with(panel)
    await bot_module._close_panel_apis(clients)
    api.close.assert_awaited_once()
    assert clients == {}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("handler", "callback_data", "state_data"),
    [
        (
            bot_module.core_install,
            "core:installyes:old-confirmation",
            {
                "core_panel_id": "00000000-0000-0000-0000-000000000001",
                "core_name": "xray",
                "core_install_token": "current-confirmation",
            },
        ),
        (
            bot_module.outbound_delete_confirmed,
            "outbound:deleteyes:old-confirmation",
            {
                "panel_id": "00000000-0000-0000-0000-000000000001",
                "tag": "current-outbound",
                "delete_confirmation_token": "current-confirmation",
            },
        ),
        (
            bot_module.admin_add_role,
            "adminrole:admin:old-confirmation",
            {"telegram_id": 70001, "admin_role_token": "current-confirmation"},
        ),
    ],
)
async def test_stale_fsm_confirmation_cannot_apply_to_a_new_operation(
    admin_session_factory, handler, callback_data, state_data
):
    state = SimpleNamespace(
        get_data=AsyncMock(return_value=state_data),
        clear=AsyncMock(),
    )
    callback = SimpleNamespace(
        answer=AsyncMock(),
        data=callback_data,
        from_user=SimpleNamespace(id=1001),
        message=SimpleNamespace(answer=AsyncMock()),
    )

    await handler(callback, state)

    callback.message.answer.assert_awaited_once()
    assert "قدیمی یا نامعتبر" in callback.message.answer.await_args.args[0]
    state.clear.assert_not_awaited()
    if handler is bot_module.admin_add_role:
        async with admin_session_factory() as session:
            assert (
                await session.scalar(select(AdminUser).where(AdminUser.telegram_id == 70001))
                is None
            )


@pytest.mark.asyncio
async def test_disabling_panel_updates_every_service_and_child_record(admin_session_factory):
    async with admin_session_factory() as session:
        panel = Panel(
            name="multi-service-panel",
            base_url="https://panel.example",
            base_path="",
            username="api",
            encrypted_password="encrypted",
            is_active=True,
        )
        session.add(panel)
        await session.flush()
        services = [
            VPNService(
                panel_id=panel.id,
                external_id=f"service-{index}",
                name=f"Service {index}",
                protocol="ssh",
                is_active=True,
            )
            for index in range(2)
        ]
        session.add_all(services)
        await session.flush()
        customers = [Customer(telegram_id=71000 + index, full_name="User") for index in range(2)]
        session.add_all(customers)
        await session.flush()
        session.add_all(
            [
                ManagedClient(
                    service_id=service.id,
                    external_identity=f"identity-{index}",
                    email=f"user-{index}@example.test",
                    is_enabled=True,
                    is_present=True,
                    encrypted_payload="encrypted",
                )
                for index, service in enumerate(services)
            ]
            + [
                Subscription(
                    customer_id=customers[index].id,
                    service_id=service.id,
                    status="active",
                )
                for index, service in enumerate(services)
            ]
        )
        await session.commit()
        panel_id = panel.id

    callback = SimpleNamespace(
        answer=AsyncMock(),
        data=f"panel:toggle:{panel_id}",
        from_user=SimpleNamespace(id=1001),
        message=SimpleNamespace(answer=AsyncMock()),
    )
    await bot_module.panel_toggle(callback)

    async with admin_session_factory() as session:
        panel = await session.get(Panel, panel_id)
        clients = (await session.scalars(select(ManagedClient))).all()
        subscriptions = (await session.scalars(select(Subscription))).all()
        services = (await session.scalars(select(VPNService))).all()
        assert not panel.is_active
        assert len(services) == 2 and all(not service.is_active for service in services)
        assert len(clients) == 2 and all(not client.is_present for client in clients)
        assert len(subscriptions) == 2 and all(sub.status == "cancelled" for sub in subscriptions)


@pytest.mark.asyncio
async def test_disabling_panel_without_services_does_not_raise(admin_session_factory):
    async with admin_session_factory() as session:
        panel = Panel(
            name="empty-panel",
            base_url="https://panel.example",
            base_path="",
            username="api",
            encrypted_password="encrypted",
            is_active=True,
        )
        session.add(panel)
        await session.commit()
        panel_id = panel.id

    callback = SimpleNamespace(
        answer=AsyncMock(),
        data=f"panel:toggle:{panel_id}",
        from_user=SimpleNamespace(id=1001),
        message=SimpleNamespace(answer=AsyncMock()),
    )
    await bot_module.panel_toggle(callback)

    async with admin_session_factory() as session:
        panel = await session.get(Panel, panel_id)
        assert not panel.is_active


@pytest.mark.asyncio
async def test_profile_is_compact_and_counts_paid_purchases_and_active_subscriptions(
    admin_session_factory,
):
    async with admin_session_factory() as session:
        customer = Customer(telegram_id=51001, username="own", full_name="Own User")
        panel = Panel(
            name="profile-panel",
            base_url="https://panel.example",
            base_path="",
            username="api",
            encrypted_password="encrypted",
            is_active=True,
        )
        session.add_all([customer, panel])
        await session.flush()
        service = VPNService(
            panel_id=panel.id,
            external_id="profile-service",
            name="Profile Service",
            protocol="ssh",
            is_active=True,
        )
        session.add(service)
        await session.flush()
        session.add_all(
            [
                Order(
                    customer_id=customer.id,
                    order_type="subscription",
                    amount=Decimal(120000),
                    currency="IRR",
                    status="fulfilled",
                ),
                Order(
                    customer_id=customer.id,
                    order_type="subscription",
                    amount=Decimal(120000),
                    currency="IRR",
                    status="fulfillment_failed",
                ),
                Order(
                    customer_id=customer.id,
                    order_type="subscription",
                    amount=Decimal(120000),
                    currency="IRR",
                    status="pending_payment",
                ),
                Order(
                    customer_id=customer.id,
                    order_type="wallet_topup",
                    amount=Decimal(120000),
                    currency="IRR",
                    status="fulfilled",
                ),
                Order(
                    customer_id=customer.id,
                    order_type="subscription",
                    amount=Decimal(120000),
                    currency="IRR",
                    status="refunded",
                ),
                Subscription(
                    customer_id=customer.id,
                    service_id=service.id,
                    status="active",
                    expires_at=datetime.now(UTC) + timedelta(days=3),
                ),
                Subscription(
                    customer_id=customer.id,
                    service_id=service.id,
                    external_client_id="no-expiry-profile-sub",
                    status="active",
                    expires_at=None,
                ),
                Subscription(
                    customer_id=customer.id,
                    service_id=service.id,
                    external_client_id="expired-profile-sub",
                    status="active",
                    expires_at=datetime.now(UTC) - timedelta(days=1),
                ),
            ]
        )
        await session.commit()

    callback = SimpleNamespace(
        answer=AsyncMock(),
        data="shop:profile",
        from_user=SimpleNamespace(id=51001, username="own", first_name="Own", last_name="User"),
        message=SimpleNamespace(edit_text=AsyncMock()),
    )
    await bot_module.shop_profile(callback)

    rendered = callback.message.edit_text.await_args.args[0]
    markup = callback.message.edit_text.await_args.kwargs["reply_markup"]
    buttons = [button for row in markup.inline_keyboard for button in row]
    assert "نام: Own User" in rendered
    assert "نام کاربری: @own" in rendered
    assert "آیدی عددی: 51001" in rendered
    assert "تعداد کل خریدها: 2" in rendered
    assert "خریدهای فعال: 2" in rendered
    assert "سوابق" not in rendered and "آخرین خریدها" not in rendered
    assert len(buttons) == 1 and buttons[0].callback_data == "home"
    assert all(button.copy_text is None for button in buttons)
    callback.answer.assert_awaited_once()


@pytest.mark.asyncio
async def test_profile_without_accessible_message_returns_private_chat_guidance():
    bot = SimpleNamespace(send_message=AsyncMock())
    callback = SimpleNamespace(
        answer=AsyncMock(),
        bot=bot,
        from_user=SimpleNamespace(id=51515),
        message=None,
    )

    await bot_module.shop_profile(callback)

    callback.answer.assert_awaited_once()
    bot.send_message.assert_awaited_once()
    assert bot.send_message.await_args.args[0] == 51515


@pytest.mark.asyncio
@pytest.mark.parametrize(("file_count", "expected_groups"), [(2, [2]), (11, [10, 1])])
async def test_config_delivery_groups_documents_in_telegram_album_chunks(
    file_count, expected_groups
):
    bot = SimpleNamespace(
        send_chat_action=AsyncMock(),
        send_media_group=AsyncMock(return_value=[]),
        send_document=AsyncMock(),
    )
    files = [
        {"filename": f"config-{index}.conf", "content": f"config-{index}".encode()}
        for index in range(file_count)
    ]

    assert await bot_module._send_subscription_files(bot, 12345, files)

    actual_groups = [len(call.kwargs["media"]) for call in bot.send_media_group.await_args_list]
    assert actual_groups == [size for size in expected_groups if size > 1]
    assert bot.send_document.await_count == expected_groups.count(1)


@pytest.mark.asyncio
async def test_config_delivery_falls_back_to_individual_documents_after_album_error():
    bot = SimpleNamespace(
        send_chat_action=AsyncMock(),
        send_media_group=AsyncMock(
            side_effect=TelegramAPIError(
                method=SendMessage(chat_id=12345, text="test"), message="album rejected"
            )
        ),
        send_document=AsyncMock(),
    )
    files = [
        {"filename": f"config-{index}.conf", "content": f"config-{index}".encode()}
        for index in range(2)
    ]

    assert await bot_module._send_subscription_files(bot, 12345, files)
    assert bot.send_media_group.await_count == 1
    assert bot.send_document.await_count == 2


@pytest.mark.asyncio
async def test_config_delivery_reports_failure_when_individual_file_cannot_be_sent():
    bot = SimpleNamespace(
        send_chat_action=AsyncMock(),
        send_document=AsyncMock(
            side_effect=TelegramAPIError(
                method=SendMessage(chat_id=12345, text="test"), message="upload failed"
            )
        ),
    )

    assert not await bot_module._send_subscription_files(
        bot, 12345, [{"filename": "broken.conf", "content": b"config"}]
    )


@pytest.mark.asyncio
async def test_shared_subscription_delivery_sends_then_cleans_up_animation():
    animation = SimpleNamespace(delete=AsyncMock())
    bot = SimpleNamespace(
        send_message=AsyncMock(),
        send_animation=AsyncMock(return_value=animation),
        send_chat_action=AsyncMock(),
        send_document=AsyncMock(),
    )

    delivered = await bot_module._send_subscription_delivery(
        bot,
        12345,
        (
            "اشتراک آماده است",
            "https://example.test/sub",
            [{"filename": "client.conf", "content": b"x"}],
        ),
    )

    assert delivered
    bot.send_message.assert_awaited_once()
    bot.send_animation.assert_awaited_once()
    bot.send_document.assert_awaited_once()
    animation.delete.assert_awaited_once()


@pytest.mark.asyncio
async def test_database_super_admin_is_owner_and_inactive_admin_is_denied(admin_session_factory):
    async with admin_session_factory() as session:
        session.add_all(
            [
                AdminUser(
                    telegram_id=2002,
                    role="owner",
                    is_active=True,
                    extra_data={"super_admin_source": "database"},
                ),
                AdminUser(telegram_id=3003, role="owner", is_active=False, extra_data={}),
            ]
        )
        await session.commit()
        assert await bot_module._admin_role(session, 2002) == "owner"
        assert await bot_module._admin_role(session, 3003) is None
        assert await bot_module._admin_role(session, 1001) == "owner"


@pytest.mark.asyncio
async def test_database_super_admin_survives_bootstrap_and_environment_owner_is_preserved(
    admin_session_factory,
):
    async with admin_session_factory() as session:
        session.add_all(
            [
                AdminUser(
                    telegram_id=2002,
                    role="owner",
                    is_active=True,
                    extra_data={"super_admin_source": "database"},
                ),
                AdminUser(telegram_id=1001, role="admin", is_active=False, extra_data={}),
                AdminUser(telegram_id=4004, role="owner", is_active=True, extra_data={}),
            ]
        )
        await session.commit()

    await bot_module.bootstrap_admins()

    async with admin_session_factory() as session:
        database_owner = await session.scalar(
            select(AdminUser).where(AdminUser.telegram_id == 2002)
        )
        environment_owner = await session.scalar(
            select(AdminUser).where(AdminUser.telegram_id == 1001)
        )
        legacy_owner = await session.scalar(select(AdminUser).where(AdminUser.telegram_id == 4004))
        assert database_owner.role == "owner" and database_owner.is_active
        assert environment_owner.role == "owner" and environment_owner.is_active
        assert legacy_owner.role == "admin" and not legacy_owner.is_active


@pytest.mark.asyncio
async def test_only_owner_can_promote_admin_and_promotion_is_audited(admin_session_factory):
    async with admin_session_factory() as session:
        target = AdminUser(telegram_id=60006, role="support", is_active=True, extra_data={})
        session.add(target)
        await session.commit()
        target_id = target.id

    callback = SimpleNamespace(
        answer=AsyncMock(),
        data=f"admin:promote-confirm:{target_id}",
        from_user=SimpleNamespace(id=1001),
        message=SimpleNamespace(edit_text=AsyncMock(), answer=AsyncMock()),
    )
    await bot_module.admin_promote_confirm(callback)

    async with admin_session_factory() as session:
        promoted = await session.get(AdminUser, target_id)
        audit = await session.scalar(
            select(AuditLog).where(AuditLog.action == "admin.super_admin_granted")
        )
        assert promoted.role == "owner" and promoted.is_active
        assert promoted.extra_data["super_admin_source"] == "database"
        assert audit is not None and audit.actor_telegram_id == 1001


@pytest.mark.asyncio
async def test_non_owner_cannot_promote_admin_even_with_forged_callback(admin_session_factory):
    async with admin_session_factory() as session:
        target = AdminUser(telegram_id=60007, role="support", is_active=True, extra_data={})
        actor = AdminUser(telegram_id=2002, role="admin", is_active=True, extra_data={})
        session.add_all([target, actor])
        await session.commit()
        target_id = target.id

    callback = SimpleNamespace(
        answer=AsyncMock(),
        data=f"admin:promote-confirm:{target_id}",
        from_user=SimpleNamespace(id=2002),
        message=SimpleNamespace(edit_text=AsyncMock(), answer=AsyncMock()),
    )
    await bot_module.admin_promote_confirm(callback)

    async with admin_session_factory() as session:
        promoted = await session.get(AdminUser, target_id)
        assert promoted.role == "support"
        callback.message.edit_text.assert_not_awaited()


@pytest.mark.asyncio
async def test_admin_deactivation_requires_a_second_confirmation_callback(admin_session_factory):
    async with admin_session_factory() as session:
        target = AdminUser(telegram_id=60008, role="support", is_active=True, extra_data={})
        session.add(target)
        await session.commit()
        target_id = target.id

    first_callback = SimpleNamespace(
        answer=AsyncMock(),
        data=f"admin:toggle:{target_id}",
        from_user=SimpleNamespace(id=1001),
        message=SimpleNamespace(edit_text=AsyncMock(), answer=AsyncMock()),
    )
    await bot_module.admin_toggle(first_callback)

    async with admin_session_factory() as session:
        target = await session.get(AdminUser, target_id)
        assert target.is_active
    assert f"admin:toggle-confirm:{target_id}" in str(
        first_callback.message.edit_text.await_args.kwargs["reply_markup"].model_dump()
    )

    confirm_callback = SimpleNamespace(
        answer=AsyncMock(),
        data=f"admin:toggle-confirm:{target_id}",
        from_user=SimpleNamespace(id=1001),
        message=SimpleNamespace(edit_text=AsyncMock(), answer=AsyncMock()),
    )
    await bot_module.admin_toggle_confirm(confirm_callback)

    async with admin_session_factory() as session:
        target = await session.get(AdminUser, target_id)
        audit = await session.scalar(
            select(AuditLog).where(AuditLog.action == "admin.status_changed")
        )
        assert not target.is_active
        assert audit is not None and audit.actor_telegram_id == 1001


@pytest.mark.asyncio
async def test_database_super_admin_demotion_is_audited_and_environment_owner_remains(
    admin_session_factory,
):
    async with admin_session_factory() as session:
        target = AdminUser(
            telegram_id=60009,
            role="owner",
            is_active=True,
            extra_data={"super_admin_source": "database"},
        )
        session.add(target)
        await session.commit()
        target_id = target.id

    callback = SimpleNamespace(
        answer=AsyncMock(),
        data=f"admin:demote-confirm:{target_id}",
        from_user=SimpleNamespace(id=1001),
        message=SimpleNamespace(edit_text=AsyncMock(), answer=AsyncMock()),
    )
    await bot_module.admin_demote_confirm(callback)

    async with admin_session_factory() as session:
        demoted = await session.get(AdminUser, target_id)
        audit = await session.scalar(
            select(AuditLog).where(AuditLog.action == "admin.super_admin_revoked")
        )
        assert demoted.role == "admin" and demoted.is_active
        assert "super_admin_source" not in demoted.extra_data
        assert audit is not None and audit.actor_telegram_id == 1001
        assert await bot_module._admin_role(session, 1001) == "owner"


@pytest.mark.asyncio
async def test_admin_list_is_paginated_with_eight_entries_per_page(admin_session_factory):
    async with admin_session_factory() as session:
        session.add_all(
            [
                AdminUser(telegram_id=70000 + index, role="support", is_active=True, extra_data={})
                for index in range(9)
            ]
        )
        await session.commit()

    first_callback = SimpleNamespace(
        answer=AsyncMock(),
        data="adm:admins",
        from_user=SimpleNamespace(id=1001),
        message=SimpleNamespace(edit_text=AsyncMock()),
    )
    await bot_module.admin_admins(first_callback)
    first_markup = first_callback.message.edit_text.await_args.kwargs["reply_markup"]
    first_buttons = [button for row in first_markup.inline_keyboard for button in row]
    assert sum(button.callback_data.startswith("admin:view:") for button in first_buttons) == 8
    assert any(button.callback_data == "adm:admins:1" for button in first_buttons)

    second_callback = SimpleNamespace(
        answer=AsyncMock(),
        data="adm:admins:1",
        from_user=SimpleNamespace(id=1001),
        message=SimpleNamespace(edit_text=AsyncMock()),
    )
    await bot_module.admin_admins(second_callback)
    second_markup = second_callback.message.edit_text.await_args.kwargs["reply_markup"]
    second_buttons = [button for row in second_markup.inline_keyboard for button in row]
    assert sum(button.callback_data.startswith("admin:view:") for button in second_buttons) == 1
    assert any(button.callback_data == "adm:admins:0" for button in second_buttons)
