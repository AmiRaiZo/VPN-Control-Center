from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from vpn_manager.bot import prepare_long_polling


@pytest.mark.asyncio
async def test_prepare_long_polling_removes_existing_webhook_without_dropping_updates():
    bot = SimpleNamespace(
        get_webhook_info=AsyncMock(return_value=SimpleNamespace(url="https://example.test/hook")),
        delete_webhook=AsyncMock(),
    )

    await prepare_long_polling(bot)

    bot.get_webhook_info.assert_awaited_once_with()
    bot.delete_webhook.assert_awaited_once_with(drop_pending_updates=False)


@pytest.mark.asyncio
async def test_prepare_long_polling_keeps_long_polling_when_no_webhook_exists():
    bot = SimpleNamespace(
        get_webhook_info=AsyncMock(return_value=SimpleNamespace(url="")),
        delete_webhook=AsyncMock(),
    )

    await prepare_long_polling(bot)

    bot.get_webhook_info.assert_awaited_once_with()
    bot.delete_webhook.assert_not_awaited()
