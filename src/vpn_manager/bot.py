from __future__ import annotations

import asyncio
import logging
import os

from aiogram import Bot, Dispatcher
from aiogram.filters import Command, CommandStart
from aiogram.types import BotCommand, Message

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("vpn_manager.bot")


def configured_admin_ids(raw_value: str) -> frozenset[int]:
    values = [item.strip() for item in raw_value.split(",") if item.strip()]
    if not values or any(not item.isdigit() or int(item) <= 0 for item in values):
        raise RuntimeError("ADMIN_TELEGRAM_IDS must contain positive numeric Telegram IDs")
    return frozenset(int(item) for item in values)


async def run_bot() -> None:
    token = os.getenv("BOT_TOKEN", "").strip()
    if not token:
        raise RuntimeError("BOT_TOKEN is not configured; run the installer first")
    admins = configured_admin_ids(os.getenv("ADMIN_TELEGRAM_IDS", ""))
    bot = Bot(token=token)
    dispatcher = Dispatcher()

    @dispatcher.message(CommandStart())
    async def start_handler(message: Message) -> None:
        if message.from_user is None or message.from_user.id not in admins:
            await message.answer("⛔ دسترسی شما به این ربات مجاز نیست.")
            return
        await message.answer(
            "✅ ربات مرکز کنترل VPN فعال است.\n"
            "شما به‌عنوان مدیر اصلی شناسایی شدید.\n\n"
            "نسخه فعلی زیرساخت اتصال ربات را فعال کرده است؛ ماژول‌های فروش، کیف پول و مدیریت سرویس هنوز در حال توسعه‌اند."
        )

    @dispatcher.message(Command("admin"))
    async def admin_handler(message: Message) -> None:
        if message.from_user is None or message.from_user.id not in admins:
            await message.answer("⛔ دسترسی غیرمجاز")
            return
        await message.answer("👑 مدیر اصلی تأیید شد.\nوضعیت ربات: آنلاین\nنسخه: 0.1.0")

    await bot.set_my_commands(
        [
            BotCommand(command="start", description="شروع و بررسی دسترسی"),
            BotCommand(command="admin", description="وضعیت مدیر و ربات"),
        ]
    )
    logger.info("Telegram bot polling started; configured admin count=%d", len(admins))
    try:
        await dispatcher.start_polling(bot, drop_pending_updates=False)
    finally:
        await bot.session.close()


def main() -> None:
    asyncio.run(run_bot())


if __name__ == "__main__":
    main()
