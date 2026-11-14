from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from aiogram import Bot, Dispatcher, F, Router
from aiogram.dispatcher.middlewares.base import BaseMiddleware
from aiogram.enums import ChatAction
from aiogram.exceptions import TelegramAPIError
from aiogram.filters import Command, CommandStart
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup
from aiogram.fsm.storage.memory import MemoryStorage
from aiogram.types import (
    BotCommand,
    BufferedInputFile,
    CallbackQuery,
    CopyTextButton,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    InputMediaDocument,
    Message,
)
from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import selectinload

from vpn_manager.commerce import (
    attach_payment_receipt,
    create_manual_order,
    get_or_create_customer,
    post_wallet_entry,
    wallet_balance,
)
from vpn_manager.database import AsyncSessionFactory, engine
from vpn_manager.models import (
    AdminUser,
    AuditLog,
    Customer,
    ManagedClient,
    Order,
    Panel,
    Payment,
    ProductPlan,
    StoreSetting,
    Subscription,
    VPNService,
    utc_now,
)
from vpn_manager.panels import PanelConfig, VpnUiClient
from vpn_manager.panels.errors import PanelError, PanelTwoFactorRequired
from vpn_manager.panels.protocols import IDENTITY_FIELDS, SUPPORTED_PANEL_PROTOCOLS
from vpn_manager.provisioning import fulfill_subscription_order
from vpn_manager.security.panel_credentials import decrypt_panel_password, encrypt_panel_password
from vpn_manager.security.totp import totp_code

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger("vpn_manager.bot")
router = Router()


class PanelAdd(StatesGroup):
    name = State()
    url = State()
    base_path = State()
    username = State()
    password = State()
    totp_seed = State()


class PanelEdit(StatesGroup):
    url = State()
    base_path = State()
    username = State()
    password = State()
    totp_seed = State()


class InboundAdd(StatesGroup):
    name = State()
    port = State()


class InboundRename(StatesGroup):
    name = State()


class InboundPortEdit(StatesGroup):
    port = State()


class PlanAdd(StatesGroup):
    name = State()
    days = State()
    traffic_gb = State()
    devices = State()
    price = State()


class PlanEdit(StatesGroup):
    name = State()
    days = State()
    traffic_gb = State()
    devices = State()
    price = State()


class AdminAdd(StatesGroup):
    telegram_id = State()
    role = State()


class CustomerSearch(StatesGroup):
    query = State()


class StoreSettings(StatesGroup):
    payment_instructions = State()


class WalletTopup(StatesGroup):
    amount = State()


class WalletAdjust(StatesGroup):
    amount = State()
    description = State()


class ManagedClientEdit(StatesGroup):
    traffic_gb = State()
    days = State()
    devices = State()


class OutboundAdd(StatesGroup):
    tag = State()
    remark = State()
    settings = State()


class OutboundDelete(StatesGroup):
    tag = State()


def configured_admin_ids(raw_value: str) -> frozenset[int]:
    values = [item.strip() for item in raw_value.split(",") if item.strip()]
    if not values or any(not item.isdigit() or int(item) <= 0 for item in values):
        raise RuntimeError("ADMIN_TELEGRAM_IDS must contain positive numeric Telegram IDs")
    return frozenset(int(item) for item in values)


def _root_admins() -> frozenset[int]:
    return configured_admin_ids(os.getenv("ADMIN_TELEGRAM_IDS", ""))


async def _admin_role(session, telegram_id: int) -> str | None:
    if telegram_id in _root_admins():
        return "owner"
    admin = await session.scalar(
        select(AdminUser).where(AdminUser.telegram_id == telegram_id, AdminUser.is_active.is_(True))
    )
    if not admin:
        return None
    if admin.role == "owner":
        return "owner"
    custom = (admin.extra_data or {}).get("permissions")
    if isinstance(custom, list):
        allowed = sorted({str(item) for item in custom if str(item) in _permission_areas()})
        return "custom:" + ",".join(allowed)
    return admin.role


def _permission_areas() -> set[str]:
    return {
        "panels",
        "customers",
        "customer_write",
        "plans",
        "orders",
        "settings",
        "stats",
        "wallet",
        "audit",
    }


def _can(role: str | None, area: str) -> bool:
    if role and role.startswith("custom:"):
        return area in role.partition(":")[2].split(",")
    permissions = {
        "owner": {
            "panels",
            "customers",
            "customer_write",
            "plans",
            "orders",
            "admins",
            "settings",
            "stats",
            "wallet",
            "audit",
        },
        "admin": {
            "panels",
            "customers",
            "customer_write",
            "plans",
            "orders",
            "stats",
            "wallet",
        },
        "finance": {"customers", "orders", "settings", "stats", "wallet"},
        "support": {"customers", "stats"},
    }
    return area in permissions.get(role or "", set())


async def _is_admin(telegram_id: int) -> bool:
    async with AsyncSessionFactory() as session:
        return await _admin_role(session, telegram_id) is not None


async def _message_can(message: Message, area: str) -> bool:
    if message.from_user is None:
        return False
    async with AsyncSessionFactory() as session:
        role = await _admin_role(session, message.from_user.id)
    if not _can(role, area):
        await message.answer("⛔ دسترسی این عملیات برای حساب شما فعال نیست.")
        return False
    return True


def _admin_fsm_area(state_name: str | None) -> str | None:
    if not state_name:
        return None
    group = state_name.split(":", 1)[0]
    return {
        "PanelAdd": "panels",
        "PanelEdit": "panels",
        "InboundAdd": "panels",
        "InboundRename": "panels",
        "InboundPortEdit": "panels",
        "ManagedClientEdit": "panels",
        "OutboundAdd": "panels",
        "OutboundDelete": "panels",
        "PlanAdd": "plans",
        "PlanEdit": "plans",
        "AdminAdd": "admins",
        "CustomerSearch": "customers",
        "StoreSettings": "settings",
        "WalletAdjust": "wallet",
    }.get(group)


class AdminFSMAccessMiddleware(BaseMiddleware):
    """Re-check role permissions on every message in an administrative FSM."""

    async def __call__(self, handler, event, data):
        if not isinstance(event, Message) or (event.text or "").startswith("/cancel"):
            return await handler(event, data)
        state = data.get("state")
        if state is None:
            return await handler(event, data)
        state_name = await state.get_state()
        if state_name is None:
            return await handler(event, data)
        stored = await state.get_data() if hasattr(state, "get_data") else {}
        previous_prompt_id = stored.get("_prompt_message_id")
        area = _admin_fsm_area(state_name)
        if area is not None:
            if event.text is None:
                await event.answer("برای این مرحله فقط پیام متنی ارسال کنید؛ یا /cancel بزنید.")
                return None
            if not await _message_can(event, area):
                await state.clear()
                await _delete_message_quietly(event)
                if previous_prompt_id:
                    try:
                        await event.bot.delete_message(event.chat.id, int(previous_prompt_id))
                    except (TelegramAPIError, RuntimeError, ValueError):
                        pass
                return None
        try:
            return await handler(event, data)
        finally:
            # User input in a form is transient. Remove it after processing so
            # passwords, panel details and routine form answers do not clutter chat.
            if event.text and not event.text.startswith("/cancel"):
                await _delete_message_quietly(event)
            if previous_prompt_id:
                try:
                    await event.bot.delete_message(event.chat.id, int(previous_prompt_id))
                except TelegramAPIError:
                    pass


router.message.outer_middleware(AdminFSMAccessMiddleware())


def _kb(rows: list[list[tuple[str, str]]]) -> InlineKeyboardMarkup:
    for row in rows:
        for _, callback_data in row:
            if not callback_data or len(callback_data.encode("utf-8")) > 64:
                raise ValueError("Telegram callback_data must contain 1 to 64 bytes")
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text=label, callback_data=data) for label, data in row]
            for row in rows
        ]
    )


def _home_keyboard(admin: bool) -> InlineKeyboardMarkup:
    rows = [
        [("🛍 خرید سرویس", "shop:plans"), ("📦 اشتراک‌های من", "shop:subs")],
        [("💳 کیف پول", "shop:wallet"), ("🧾 سفارش‌های من", "shop:orders")],
        [("👤 مشخصات من", "shop:profile")],
    ]
    if admin:
        rows.append([("🛡 پنل ادمین", "adm:home")])
    return _kb(rows)


async def _delete_message_quietly(message: Message) -> None:
    try:
        await message.delete()
    except (TelegramAPIError, RuntimeError):
        pass


async def _state_prompt(message: Message, state: FSMContext, text: str, **kwargs) -> Message:
    """Replace the previous transient form prompt and remember the new one."""
    stored = await state.get_data()
    previous_prompt_id = stored.get("_prompt_message_id")
    if previous_prompt_id:
        try:
            await message.bot.delete_message(message.chat.id, int(previous_prompt_id))
        except (TelegramAPIError, RuntimeError, ValueError):
            pass
    sent = await message.answer(text, **kwargs)
    await state.update_data(_prompt_message_id=sent.message_id)
    return sent


async def _edit_or_answer(message: Message, text: str, **kwargs) -> Message:
    """Prefer editing the current bot message; fall back to one new message."""
    try:
        return await message.edit_text(text, **kwargs)
    except TelegramAPIError:
        return await message.answer(text, **kwargs)


def _admin_keyboard(role: str) -> InlineKeyboardMarkup:
    rows: list[list[tuple[str, str]]] = []
    if _can(role, "panels"):
        rows.append([("🖥 پنل‌ها و اینباندها", "adm:panels")])
    if _can(role, "customers"):
        rows.append([("👥 کاربران", "adm:customers")])
    if _can(role, "plans"):
        rows.append([("📦 پلن‌ها و قیمت‌گذاری", "adm:plans")])
    if _can(role, "orders"):
        rows.append([("🧾 سفارش‌ها و پرداخت‌ها", "adm:orders")])
    if _can(role, "admins"):
        rows.append([("🛡 مدیران ربات", "adm:admins")])
    if _can(role, "settings"):
        rows.append([("⚙️ تنظیمات فروش", "adm:settings")])
    if _can(role, "stats"):
        rows.append([("📊 آمار فروش", "adm:stats")])
    if _can(role, "audit"):
        rows.append([("📜 گزارش فعالیت مدیران", "adm:audit")])
    rows.append([("🛍 بازگشت به فروشگاه", "home")])
    return _kb(rows)


async def _answer_admin(callback: CallbackQuery, area: str) -> str | None:
    if callback.from_user is None:
        await callback.answer("دسترسی غیرمجاز", show_alert=True)
        return None
    async with AsyncSessionFactory() as session:
        role = await _admin_role(session, callback.from_user.id)
    if not _can(role, area):
        await callback.answer("شما اجازه انجام این عملیات را ندارید.", show_alert=True)
        return None
    await callback.answer()
    return role


async def _setting(session, key: str, default: str = "") -> str:
    item = await session.get(StoreSetting, key)
    return item.value if item else default


async def _set_setting(session, key: str, value: str) -> None:
    item = await session.get(StoreSetting, key)
    if item is None:
        session.add(StoreSetting(key=key, value=value))
    else:
        item.value = value


async def _audit(
    session, actor_id: int, action: str, resource: str, resource_id=None, details=None
):
    session.add(
        AuditLog(
            actor_telegram_id=actor_id,
            action=action,
            resource_type=resource,
            resource_id=resource_id,
            details=details or {},
        )
    )


async def _panel_api(panel: Panel) -> VpnUiClient:
    from vpn_manager.security.panel_credentials import decrypt_panel_password

    api = VpnUiClient(
        PanelConfig(
            name=panel.name,
            base_url=panel.base_url,
            base_path=panel.base_path,
            username=panel.username,
            password=decrypt_panel_password(panel.encrypted_password),
        )
    )
    try:
        try:
            await api.login()
        except PanelTwoFactorRequired:
            seed_ciphertext = (panel.extra_data or {}).get("totp_secret_encrypted")
            if not seed_ciphertext:
                raise RuntimeError("برای این پنل 2FA فعال است اما Seed امن ثبت نشده است.")
            await api.login(two_factor_code=totp_code(decrypt_panel_password(seed_ciphertext)))
    except Exception:
        await api.close()
        raise
    return api


async def _sync_services(session, panel: Panel, inbound_rows: list[dict]) -> int:
    seen: set[str] = set()
    for inbound in inbound_rows:
        external_id = str(inbound.get("id", "")).strip()
        protocol = str(inbound.get("protocol", "unknown")).lower()
        if not external_id or protocol not in SUPPORTED_PANEL_PROTOCOLS:
            continue
        seen.add(external_id)
        service = await session.scalar(
            select(VPNService).where(
                VPNService.panel_id == panel.id, VPNService.external_id == external_id
            )
        )
        if service is None:
            service = VPNService(
                panel_id=panel.id,
                external_id=external_id,
                name=str(inbound.get("remark") or f"{protocol} #{external_id}")[:160],
                protocol=protocol,
                is_active=bool(inbound.get("enable", True)),
                extra_data={"port": inbound.get("port"), "listen": inbound.get("listen", "")},
            )
            session.add(service)
        else:
            service.name = str(inbound.get("remark") or service.name)[:160]
            service.protocol = protocol
            service.is_active = bool(inbound.get("enable", True))
            service.extra_data = {
                **(service.extra_data or {}),
                "port": inbound.get("port"),
                "listen": inbound.get("listen", ""),
            }
    for service in (
        await session.scalars(select(VPNService).where(VPNService.panel_id == panel.id))
    ).all():
        if service.external_id not in seen:
            service.is_active = False
            for plan in (
                await session.scalars(
                    select(ProductPlan).where(ProductPlan.service_id == service.id)
                )
            ).all():
                plan.is_active = False
    panel.status = "online"
    panel.last_checked_at = utc_now()
    panel.last_error = None
    await session.flush()
    return len(seen)


def _inbound_clients(inbound: dict) -> list[dict]:
    settings = inbound.get("settings") or {}
    if isinstance(settings, str):
        try:
            settings = json.loads(settings)
        except ValueError:
            return []
    clients = settings.get("clients", []) if isinstance(settings, dict) else []
    return (
        [client for client in clients if isinstance(client, dict)]
        if isinstance(clients, list)
        else []
    )


async def _sync_managed_clients(session, service: VPNService, inbound: dict) -> list[ManagedClient]:
    identity_key = IDENTITY_FIELDS.get(service.protocol)
    if not identity_key:
        return []
    seen: set[str] = set()
    for payload in _inbound_clients(inbound):
        identity = str(payload.get(identity_key, "")).strip()
        if not identity:
            continue
        seen.add(identity)
        email = str(payload.get("email") or payload.get("id") or identity)[:255]
        record = await session.scalar(
            select(ManagedClient).where(
                ManagedClient.service_id == service.id,
                ManagedClient.external_identity == identity,
            )
        )
        encrypted = encrypt_panel_password(json.dumps(payload, separators=(",", ":")))
        if record is None:
            record = ManagedClient(
                service_id=service.id,
                external_identity=identity,
                email=email,
                is_enabled=bool(payload.get("enable", False)),
                is_present=True,
                encrypted_payload=encrypted,
                extra_data={"protocol": service.protocol, "comment": payload.get("comment", "")},
            )
            session.add(record)
        else:
            record.email = email
            record.is_enabled = bool(payload.get("enable", False))
            record.is_present = True
            record.encrypted_payload = encrypted
            record.extra_data = {
                **(record.extra_data or {}),
                "protocol": service.protocol,
                "comment": payload.get("comment", ""),
            }
    existing = (
        await session.scalars(select(ManagedClient).where(ManagedClient.service_id == service.id))
    ).all()
    for record in existing:
        if record.external_identity not in seen:
            record.is_present = False
    await session.flush()
    return list(
        (
            await session.scalars(
                select(ManagedClient)
                .where(ManagedClient.service_id == service.id, ManagedClient.is_present.is_(True))
                .order_by(ManagedClient.email)
            )
        ).all()
    )


async def _panel_connect_and_sync(panel_id: uuid.UUID) -> int:
    async with AsyncSessionFactory() as session:
        panel = await session.get(Panel, panel_id)
        if panel is None:
            raise ValueError("پنل پیدا نشد.")
        api = await _panel_api(panel)
        try:
            rows = await api.list_inbounds()
        finally:
            await api.close()
        count = await _sync_services(session, panel, rows)
        await session.commit()
        return count


async def _notify_customer(bot: Bot, telegram_id: int, text: str) -> None:
    try:
        await bot.send_message(telegram_id, text)
    except TelegramAPIError as exc:
        logger.warning("Could not notify customer %s (%s)", telegram_id, type(exc).__name__)


def _utc_datetime(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


async def _subscription_lifecycle_tick(bot: Bot, *, now: datetime | None = None) -> dict[str, int]:
    """Send one-day reminders and retry expiry suspension for due subscriptions.

    The bot service is intentionally the single scheduler owner. Do not run multiple
    polling instances against the same database without adding a distributed lease.
    """
    current = _utc_datetime(now or utc_now())
    counts = {"reminded": 0, "expired": 0, "failed": 0}
    async with AsyncSessionFactory() as session:
        subscriptions = (
            await session.scalars(
                select(Subscription)
                .where(
                    Subscription.status.in_(["active", "suspension_failed"]),
                    Subscription.expires_at.is_not(None),
                )
                .order_by(Subscription.expires_at.asc())
                .limit(500)
            )
        ).all()
        for subscription in subscriptions:
            expiry = _utc_datetime(subscription.expires_at)
            extra = dict(subscription.extra_data or {})
            customer = await session.get(Customer, subscription.customer_id)
            if (
                subscription.status == "active"
                and current < expiry <= current + timedelta(hours=24)
                and not extra.get("pre_expiry_notified_at")
                and customer
                and customer.telegram_id
            ):
                try:
                    await bot.send_message(
                        customer.telegram_id,
                        f"⏳ یادآوری: اشتراک شما تا {expiry:%Y-%m-%d %H:%M UTC} اعتبار دارد. برای جلوگیری از قطعی، تمدید را از فروشگاه انجام دهید.",
                    )
                    extra["pre_expiry_notified_at"] = current.isoformat()
                    subscription.extra_data = extra
                    counts["reminded"] += 1
                    await session.commit()
                except TelegramAPIError as exc:
                    logger.warning(
                        "Could not send expiry reminder for %s (%s)",
                        subscription.id,
                        type(exc).__name__,
                    )
            if expiry > current:
                continue
            service = await session.get(VPNService, subscription.service_id)
            panel = await session.get(Panel, service.panel_id) if service else None
            api = None
            try:
                if service is None or panel is None or not subscription.external_client_id:
                    raise ValueError("اطلاعات سرویس/پنل/شناسه کلاینت برای تعلیق موجود نیست.")
                payload_ciphertext = extra.get("client_payload_encrypted")
                if not payload_ciphertext:
                    raise ValueError("payload رمزنگاری‌شده کلاینت پیدا نشد.")
                payload = json.loads(decrypt_panel_password(payload_ciphertext))
                payload["enable"] = False
                api = await _panel_api(panel)
                await api.update_client(
                    int(service.external_id), subscription.external_client_id, payload
                )
                subscription.status = "expired"
                subscription.extra_data = {
                    **extra,
                    "client_payload_encrypted": encrypt_panel_password(
                        json.dumps(payload, separators=(",", ":"))
                    ),
                    "expired_at": current.isoformat(),
                    "lifecycle_error": None,
                }
                await _audit(
                    session,
                    0,
                    "subscription.expired_and_disabled",
                    "subscription",
                    subscription.id,
                    {"service_id": str(subscription.service_id)},
                )
                counts["expired"] += 1
                await session.commit()
                if customer and customer.telegram_id:
                    await _notify_customer(
                        bot,
                        customer.telegram_id,
                        f"⌛ اشتراک {service.name} منقضی و در پنل غیرفعال شد. برای استفاده مجدد آن را تمدید کنید.",
                    )
            except Exception as exc:
                subscription.status = "suspension_failed"
                subscription.extra_data = {
                    **extra,
                    "lifecycle_error": type(exc).__name__,
                    "lifecycle_last_attempt_at": current.isoformat(),
                }
                await _audit(
                    session,
                    0,
                    "subscription.expiry_suspend_failed",
                    "subscription",
                    subscription.id,
                    {"error": type(exc).__name__},
                )
                counts["failed"] += 1
                await session.commit()
                logger.exception("Automatic expiry suspension failed for %s", subscription.id)
            finally:
                if api is not None:
                    await api.close()
    return counts


async def _subscription_lifecycle_worker(bot: Bot) -> None:
    while True:
        try:
            counts = await _subscription_lifecycle_tick(bot)
            if any(counts.values()):
                logger.info("Subscription lifecycle tick: %s", counts)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Subscription lifecycle worker iteration failed")
        await asyncio.sleep(300)


def _price(amount: Decimal, currency: str) -> str:
    amount_text = f"{amount:,.0f}" if amount == amount.to_integral_value() else f"{amount:,.2f}"
    return f"{amount_text} {currency}"


async def _store_subscription_delivery(
    session, subscription: Subscription
) -> tuple[str, str, list[dict[str, Any]]]:
    from vpn_manager.security.panel_credentials import decrypt_panel_password

    service = await session.get(VPNService, subscription.service_id)
    panel = await session.get(Panel, service.panel_id) if service else None
    payload = json.loads(
        decrypt_panel_password(subscription.extra_data["client_payload_encrypted"])
    )
    if panel is None or service is None:
        raise ValueError("اطلاعات پنل اشتراک در دسترس نیست.")
    base_path = panel.base_path.strip("/")
    root = panel.base_url.rstrip("/")
    if base_path:
        root += f"/{base_path}"
    subscription_url = f"{root}/sub/{payload['subId']}"
    lines = [
        "✅ سرویس شما با موفقیت آماده شد.",
        "━━━━━━━━━━━━━━━━━━",
        f"نام سرویس: {service.name}",
        f"پروتکل: {service.protocol}",
        f"شناسه: {payload.get('email', '-')}",
        f"اعتبار تا: {subscription.expires_at:%Y-%m-%d %H:%M UTC}",
        "━━━━━━━━━━━━━━━━━━",
        "برای وارد کردن تنظیمات، فایل‌های پیوست را در برنامهٔ VPN خود Import کنید.",
        "لینک اشتراک نیز از دکمهٔ کپی زیر قابل دریافت است.",
    ]
    if payload.get("id"):
        lines.append(f"نام کاربری/شناسه ورود: {payload['id']}")
    if payload.get("password"):
        lines.append(f"رمز عبور: {payload['password']}")
    if payload.get("auth"):
        lines.append(f"کلید احراز هویت: {payload['auth']}")
    if payload.get("secret"):
        lines.append(f"Secret: {payload['secret']}")
    files: list[dict[str, Any]] = []
    if service.protocol in {"openvpn", "wg-c", "awg", "gre", "ssh"}:
        api = None
        try:
            api = await _panel_api(panel)
            transport = "udp"
            if service.protocol == "openvpn":
                inbound = await api.get_inbound(int(service.external_id))
                settings = inbound.get("settings") or {}
                if isinstance(settings, str):
                    settings = json.loads(settings)
                if isinstance(settings, dict) and not settings.get("udpEnable", True):
                    transport = "tcp"
            files = await api.render_client_configs(
                int(service.external_id),
                service.protocol,
                str(payload.get("email", "")),
                transport=transport,
            )
        except (PanelError, ValueError, TypeError, KeyError) as exc:
            logger.warning(
                "Could not render %s config for subscription %s (%s)",
                service.protocol,
                subscription.id,
                type(exc).__name__,
            )
            lines.append("کانفیگ اختصاصی از API پنل دریافت نشد؛ مدیر باید آن را بررسی کند.")
        finally:
            if api is not None:
                await api.close()
    return "\n".join(lines), subscription_url, files


async def _send_subscription_files(bot: Bot, telegram_id: int, files: list[dict[str, Any]]) -> bool:
    """Send protocol-native config files as one tidy Telegram document album."""
    if not files:
        return True

    async def send_one(item: dict[str, Any]) -> bool:
        filename = (
            str(item.get("filename") or "vpn-config.txt").replace("\\", "_").replace("/", "_")
        )
        try:
            await bot.send_document(
                telegram_id,
                BufferedInputFile(item["content"], filename=filename),
                caption=f"📎 فایل تنظیمات: {filename}",
            )
            return True
        except TelegramAPIError as exc:
            logger.warning(
                "Could not send subscription config to customer %s (%s)",
                telegram_id,
                type(exc).__name__,
            )
            return False

    all_sent = True
    for offset in range(0, len(files), 10):
        group = files[offset : offset + 10]
        try:
            await bot.send_chat_action(telegram_id, ChatAction.UPLOAD_DOCUMENT)
        except TelegramAPIError:
            pass
        if len(group) == 1:
            all_sent = await send_one(group[0]) and all_sent
            continue
        media = [
            InputMediaDocument(
                media=BufferedInputFile(
                    item["content"],
                    filename=str(item.get("filename") or "vpn-config.txt")
                    .replace("\\", "_")
                    .replace("/", "_"),
                ),
                caption=f"📎 {str(item.get('filename') or 'vpn-config.txt')[:900]}",
            )
            for item in group
        ]
        try:
            await bot.send_media_group(telegram_id, media=media)
        except TelegramAPIError as exc:
            logger.warning(
                "Could not send grouped subscription configs to customer %s (%s); falling back to individual documents",
                telegram_id,
                type(exc).__name__,
            )
            for item in group:
                all_sent = await send_one(item) and all_sent
    return all_sent


def _subscription_delivery_keyboard(subscription_url: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="📋 کپی لینک اشتراک",
                    copy_text=CopyTextButton(text=subscription_url),
                )
            ],
            [InlineKeyboardButton(text="📦 مشاهده اشتراک‌های من", callback_data="shop:subs")],
        ]
    )


async def _send_subscription_delivery(
    bot: Bot,
    telegram_id: int,
    delivery: tuple[str, str, list[dict[str, Any]]],
    *,
    status_message: Message | None = None,
) -> bool:
    message, subscription_url, files = delivery
    reply_markup = _subscription_delivery_keyboard(subscription_url)
    try:
        if status_message is not None:
            await status_message.edit_text(message, reply_markup=reply_markup)
        else:
            await bot.send_message(telegram_id, message, reply_markup=reply_markup)
    except TelegramAPIError as exc:
        logger.warning(
            "Could not send subscription summary to customer %s (%s)",
            telegram_id,
            type(exc).__name__,
        )
        return False
    animation_message = (
        await _send_progress_animation(bot, telegram_id, "در حال ارسال فایل‌های کانفیگ شما…")
        if files
        else None
    )
    try:
        return await _send_subscription_files(bot, telegram_id, files)
    finally:
        if animation_message is not None:
            await _delete_message_quietly(animation_message)


async def _send_progress_animation(bot: Bot, chat_id: int, caption: str) -> Message | None:
    """Send the bundled lightweight purchase animation; callers retain a text fallback."""
    asset = Path(__file__).parent / "assets" / "purchase-progress.gif"
    try:
        payload = asset.read_bytes()
        return await bot.send_animation(
            chat_id,
            BufferedInputFile(payload, filename="vpn-purchase-progress.gif"),
            caption=caption,
        )
    except (OSError, TelegramAPIError) as exc:
        logger.info("Purchase animation unavailable for chat %s (%s)", chat_id, type(exc).__name__)
        return None


async def _approve_order(bot: Bot, order_id: uuid.UUID, actor_id: int) -> str:
    async with AsyncSessionFactory() as session:
        order = await session.scalar(
            select(Order).options(selectinload(Order.customer)).where(Order.id == order_id)
        )
        payment = await session.scalar(
            select(Payment).where(Payment.order_id == order_id, Payment.provider == "manual")
        )
        if order is None or payment is None:
            return "سفارش یا پرداخت پیدا نشد."
        if payment.status != "pending" or order.status != "pending_payment":
            return "این سفارش قبلاً بررسی شده است."
        if not (payment.extra_data or {}).get("receipt_file_id"):
            return "هنوز رسیدی برای این سفارش ثبت نشده است."
        claimed = await session.execute(
            update(Order)
            .where(Order.id == order_id, Order.status == "pending_payment")
            .values(status="paid")
        )
        if claimed.rowcount != 1:
            await session.rollback()
            return "این سفارش هم‌زمان توسط مدیر دیگری بررسی شده است."
        payment.status = "paid"
        payment.paid_at = utc_now()
        payment.extra_data = {**(payment.extra_data or {}), "reviewed_by": actor_id}
        await _audit(session, actor_id, "payment.approved", "order", order.id)

        if order.order_type == "wallet_topup":
            await post_wallet_entry(
                session,
                customer_id=order.customer_id,
                amount=Decimal(order.amount),
                entry_type="topup",
                idempotency_key=f"payment:{payment.id}",
                description="شارژ کیف پول با تأیید مدیر",
                reference=str(order.id),
            )
            order.status = "fulfilled"
            await session.commit()
            await _notify_customer(
                bot,
                order.customer.telegram_id,
                f"✅ پرداخت شما تأیید شد و کیف پول به مبلغ {_price(Decimal(order.amount), order.currency)} شارژ شد.",
            )
            return "پرداخت تأیید و کیف پول شارژ شد."

        await session.commit()

        try:
            subscription = await fulfill_subscription_order(session, order)
        except Exception as exc:
            logger.exception("Order fulfillment failed for %s", order.id)
            order.status = "fulfillment_failed"
            await session.commit()
            await _notify_customer(
                bot,
                order.customer.telegram_id,
                "پرداخت شما ثبت شده، اما ساخت سرویس در پنل با خطا مواجه شد. مدیر در حال پیگیری است؛ مبلغ را دوباره پرداخت نکنید.",
            )
            return f"پرداخت ثبت شد، ولی Provisioning شکست خورد: {type(exc).__name__}. سفارش را می‌توان Retry کرد."
        try:
            delivery = await _store_subscription_delivery(session, subscription)
            delivered = await _send_subscription_delivery(bot, order.customer.telegram_id, delivery)
            if not delivered:
                return "پرداخت تأیید و سرویس ساخته شد؛ ارسال پیام/فایل کامل نشد. کاربر می‌تواند از «اشتراک‌های من» دوباره کانفیگ را دریافت کند."
        except (ValueError, KeyError, TypeError) as exc:
            logger.exception("Subscription delivered but message rendering failed for %s", order.id)
            return f"سرویس روی پنل فعال شد، اما ساخت پیام تحویل خطا داشت: {type(exc).__name__}. از بخش اشتراک‌های من قابل بازیابی است."
        return "پرداخت تأیید و اشتراک روی پنل ساخته/تمدید شد."


async def _retry_order(bot: Bot, order_id: uuid.UUID, actor_id: int) -> str:
    async with AsyncSessionFactory() as session:
        order = await session.get(Order, order_id)
        if order is None or order.status not in {"paid", "processing", "fulfillment_failed"}:
            return "سفارش در وضعیت قابل Retry نیست."
        if order.order_type == "wallet_topup":
            payment = await session.scalar(
                select(Payment).where(Payment.order_id == order.id, Payment.provider == "manual")
            )
            if payment is None or payment.status != "paid":
                return "پرداخت شارژ کیف پول تأیید نشده و قابل بازیابی نیست."
            await post_wallet_entry(
                session,
                customer_id=order.customer_id,
                amount=Decimal(order.amount),
                entry_type="topup",
                idempotency_key=f"payment:{payment.id}",
                description="بازیابی شارژ کیف پول پس از وقفهٔ پردازش",
                reference=str(order.id),
            )
            order.status = "fulfilled"
            await _audit(session, actor_id, "wallet.topup_recovered", "order", order.id)
            customer = await session.get(Customer, order.customer_id)
            await session.commit()
            if customer and customer.telegram_id:
                await _notify_customer(
                    bot,
                    customer.telegram_id,
                    f"✅ شارژ کیف پول سفارش {str(order.id)[:8]} بازیابی شد.",
                )
            return "شارژ کیف پول با کنترل تکرار بازیابی و تکمیل شد."
        try:
            subscription = await fulfill_subscription_order(session, order)
        except Exception as exc:
            logger.exception("Retry failed for order %s", order_id)
            return f"Retry ناموفق بود: {type(exc).__name__}."
        customer = await session.get(Customer, order.customer_id)
        try:
            delivery = await _store_subscription_delivery(session, subscription)
            if customer and customer.telegram_id:
                delivered = await _send_subscription_delivery(bot, customer.telegram_id, delivery)
                if not delivered:
                    return "سرویس ساخته شد، اما ارسال کامل کانفیگ انجام نشد؛ کاربر از «اشتراک‌های من» دوباره دریافت کند."
        except (ValueError, KeyError, TypeError) as exc:
            logger.exception("Retry succeeded but delivery message failed for %s", order_id)
            return f"سرویس ساخته شد، اما ارسال مشخصات خطا داشت: {type(exc).__name__}."
        return "ساخت سرویس با موفقیت تکمیل شد."


@router.message(CommandStart())
async def start_handler(message: Message) -> None:
    if message.from_user is None:
        return
    async with AsyncSessionFactory() as session:
        customer = await get_or_create_customer(session, message.from_user)
        role = await _admin_role(session, message.from_user.id)
        await session.commit()
        if customer.status != "active":
            await message.answer("⛔ حساب کاربری شما غیرفعال شده است. با پشتیبانی تماس بگیرید.")
            return
    greeting = "به مرکز کنترل VPN خوش آمدید.\nاز منوی زیر استفاده کنید."
    if role:
        greeting = f"سلام مدیر گرامی. سطح دسترسی: {role}\nبه پنل مدیریت و فروش خوش آمدید."
    await message.answer(greeting, reply_markup=_home_keyboard(role is not None))


@router.message(Command("admin"))
async def admin_command(message: Message) -> None:
    if message.from_user is None:
        return
    async with AsyncSessionFactory() as session:
        role = await _admin_role(session, message.from_user.id)
    if not role:
        await message.answer("⛔ دسترسی غیرمجاز")
        return
    await message.answer("👑 مدیریت مرکز کنترل VPN", reply_markup=_admin_keyboard(role))


@router.message(Command("cancel"))
async def cancel_handler(message: Message, state: FSMContext) -> None:
    stored = await state.get_data()
    previous_prompt_id = stored.get("_prompt_message_id")
    await state.clear()
    if previous_prompt_id:
        try:
            await message.bot.delete_message(message.chat.id, int(previous_prompt_id))
        except (TelegramAPIError, RuntimeError, ValueError):
            pass
    await message.answer(
        "عملیات لغو شد.", reply_markup=_home_keyboard(await _is_admin(message.from_user.id))
    )


def _profile_keyboard(telegram_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="📋 کپی آیدی عددی",
                    copy_text=CopyTextButton(text=str(telegram_id)),
                )
            ],
            [
                InlineKeyboardButton(
                    text="🧾 سوابق تمام خریدها", callback_data="shop:profile:orders:0"
                )
            ],
            [InlineKeyboardButton(text="✅ سرویس‌های فعال", callback_data="shop:profile:active:0")],
            [InlineKeyboardButton(text="🔄 بروزرسانی مشخصات", callback_data="shop:profile")],
            [InlineKeyboardButton(text="↩️ منوی اصلی", callback_data="home")],
        ]
    )


def _order_status_label(status: str) -> str:
    return {
        "pending_payment": "در انتظار پرداخت",
        "paid": "پرداخت‌شده",
        "processing": "در حال آماده‌سازی",
        "fulfilled": "تکمیل‌شده",
        "rejected": "ردشده",
        "refunded": "مستردشده",
        "fulfillment_failed": "نیازمند پیگیری",
        "cancelled": "لغوشده",
    }.get(status, f"وضعیت نامشخص ({status})")


def _order_type_label(order_type: str) -> str:
    return {
        "subscription": "خرید سرویس",
        "wallet_topup": "شارژ کیف پول",
    }.get(order_type, f"سفارش دیگر ({order_type})")


@router.callback_query(F.data == "shop:profile")
async def shop_profile(callback: CallbackQuery) -> None:
    await callback.answer()
    if callback.from_user is None:
        return
    now = utc_now()
    async with AsyncSessionFactory() as session:
        customer = await get_or_create_customer(session, callback.from_user)
        if customer.status != "active":
            await callback.message.answer("حساب کاربری شما غیرفعال است.")
            return
        balance = await wallet_balance(session, customer.id)
        order_count = (
            await session.scalar(
                select(func.count(Order.id)).where(Order.customer_id == customer.id)
            )
            or 0
        )
        active_filter = (
            Subscription.customer_id == customer.id,
            Subscription.status == "active",
            or_(Subscription.expires_at.is_(None), Subscription.expires_at > now),
        )
        active_count = (
            await session.scalar(select(func.count(Subscription.id)).where(*active_filter)) or 0
        )
        recent_orders = (
            await session.scalars(
                select(Order)
                .where(Order.customer_id == customer.id)
                .order_by(Order.created_at.desc())
                .limit(3)
            )
        ).all()
        active_subscriptions = (
            await session.scalars(
                select(Subscription)
                .options(selectinload(Subscription.plan), selectinload(Subscription.service))
                .where(*active_filter)
                .order_by(Subscription.expires_at.asc().nulls_last())
                .limit(3)
            )
        ).all()
        await session.commit()

    username = f"@{callback.from_user.username}" if callback.from_user.username else "ثبت نشده"
    name = (
        " ".join(
            part for part in (callback.from_user.first_name, callback.from_user.last_name) if part
        )
        or "ثبت نشده"
    )
    lines = [
        "👤 مشخصات من",
        f"نام: {name}",
        f"نام کاربری: {username}",
        f"آیدی عددی: {callback.from_user.id}",
        f"موجودی کیف پول: {_price(balance, 'IRR')}",
        f"تعداد کل سفارش‌ها: {order_count}",
        f"سرویس‌های فعال: {active_count}",
    ]
    if recent_orders:
        lines.append("\n🧾 آخرین خریدها")
        lines.extend(
            f"• {_order_type_label(order.order_type)} | {_price(Decimal(order.amount), order.currency)} | {_order_status_label(order.status)}"
            for order in recent_orders
        )
    else:
        lines.append("\nهنوز خریدی در حساب شما ثبت نشده است.")
    if active_subscriptions:
        lines.append("\n✅ اشتراک‌های فعال")
        for subscription in active_subscriptions:
            plan_name = subscription.plan.name if subscription.plan else "اشتراک"
            service_name = subscription.service.name if subscription.service else "سرویس"
            expiry = (
                f"تا {subscription.expires_at:%Y-%m-%d %H:%M} UTC"
                if subscription.expires_at
                else "بدون تاریخ انقضا"
            )
            lines.append(f"• {plan_name} · {service_name} · {expiry}")
    await callback.message.edit_text(
        "\n".join(lines),
        reply_markup=_profile_keyboard(callback.from_user.id),
    )


@router.callback_query(F.data.startswith("shop:profile:orders:"))
async def shop_profile_orders(callback: CallbackQuery) -> None:
    await callback.answer()
    if callback.from_user is None:
        return
    try:
        page = max(0, int(callback.data.rsplit(":", 1)[1]))
    except ValueError:
        page = 0
    page_size = 5
    async with AsyncSessionFactory() as session:
        customer = await session.scalar(
            select(Customer).where(Customer.telegram_id == callback.from_user.id)
        )
        if customer is None:
            await callback.message.edit_text(
                "هنوز سابقه خریدی برای شما ثبت نشده است.",
                reply_markup=_kb([[("↩️ مشخصات من", "shop:profile")]]),
            )
            return
        total = (
            await session.scalar(
                select(func.count(Order.id)).where(Order.customer_id == customer.id)
            )
            or 0
        )
        page = min(page, max(0, (total - 1) // page_size)) if total else 0
        orders = (
            await session.scalars(
                select(Order)
                .where(Order.customer_id == customer.id)
                .order_by(Order.created_at.desc())
                .limit(page_size)
                .offset(page * page_size)
            )
        ).all()
    lines = [f"🧾 سوابق خرید شما · {total} سفارش"]
    for order in orders:
        lines.append(
            f"\n• {_order_type_label(order.order_type)}\n"
            f"مبلغ: {_price(Decimal(order.amount), order.currency)}\n"
            f"وضعیت: {_order_status_label(order.status)}\n"
            f"تاریخ: {order.created_at:%Y-%m-%d %H:%M} UTC\n"
            f"کد: {str(order.id)[:8]}"
        )
    rows = []
    if page > 0:
        rows.append([("⬅️ صفحه قبل", f"shop:profile:orders:{page - 1}")])
    if (page + 1) * page_size < total:
        rows.append([("صفحه بعد ➡️", f"shop:profile:orders:{page + 1}")])
    rows.extend([[("↩️ مشخصات من", "shop:profile")], [("↩️ منوی اصلی", "home")]])
    await callback.message.edit_text("\n".join(lines), reply_markup=_kb(rows))


@router.callback_query(F.data.startswith("shop:profile:active:"))
async def shop_profile_active(callback: CallbackQuery) -> None:
    await callback.answer()
    if callback.from_user is None:
        return
    try:
        page = max(0, int(callback.data.rsplit(":", 1)[1]))
    except ValueError:
        page = 0
    page_size = 5
    now = utc_now()
    async with AsyncSessionFactory() as session:
        customer = await session.scalar(
            select(Customer).where(Customer.telegram_id == callback.from_user.id)
        )
        if customer is None:
            subscriptions = []
            total = 0
        else:
            active_filter = (
                Subscription.customer_id == customer.id,
                Subscription.status == "active",
                or_(Subscription.expires_at.is_(None), Subscription.expires_at > now),
            )
            total = (
                await session.scalar(select(func.count(Subscription.id)).where(*active_filter)) or 0
            )
            page = min(page, max(0, (total - 1) // page_size)) if total else 0
            subscriptions = (
                await session.scalars(
                    select(Subscription)
                    .options(selectinload(Subscription.plan), selectinload(Subscription.service))
                    .where(*active_filter)
                    .order_by(Subscription.expires_at.asc().nulls_last())
                    .limit(page_size)
                    .offset(page * page_size)
                )
            ).all()
    lines = [f"✅ اشتراک‌های فعال من · {total}"]
    rows = []
    for subscription in subscriptions:
        service_name = subscription.service.name if subscription.service else "سرویس"
        plan_name = subscription.plan.name if subscription.plan else "اشتراک"
        expiry = (
            f"{subscription.expires_at:%Y-%m-%d %H:%M} UTC"
            if subscription.expires_at
            else "نامحدود"
        )
        lines.append(f"\n• {plan_name} — {service_name}\nاعتبار: {expiry}")
        rows.append([(f"📦 جزئیات {plan_name[:30]}", f"shop:sub:{subscription.id}")])
    if not subscriptions:
        lines.append("\nدر حال حاضر اشتراک فعالی ندارید.")
    nav = []
    if page > 0:
        nav.append(("⬅️ قبلی", f"shop:profile:active:{page - 1}"))
    if (page + 1) * page_size < total:
        nav.append(("بعدی ➡️", f"shop:profile:active:{page + 1}"))
    if nav:
        rows.append(nav)
    rows.extend([[("↩️ مشخصات من", "shop:profile")], [("↩️ منوی اصلی", "home")]])
    await callback.message.edit_text("\n".join(lines), reply_markup=_kb(rows))


@router.callback_query(F.data == "home")
async def home_callback(callback: CallbackQuery) -> None:
    if callback.from_user is None:
        return
    await callback.answer()
    await callback.message.edit_text(
        "منوی اصلی مرکز کنترل VPN",
        reply_markup=_home_keyboard(await _is_admin(callback.from_user.id)),
    )


@router.callback_query(F.data == "adm:home")
async def admin_home(callback: CallbackQuery) -> None:
    if callback.from_user is None:
        return
    async with AsyncSessionFactory() as session:
        role = await _admin_role(session, callback.from_user.id)
    if not role:
        await callback.answer("دسترسی غیرمجاز", show_alert=True)
        return
    await callback.answer()
    await callback.message.edit_text("👑 مدیریت مرکز کنترل VPN", reply_markup=_admin_keyboard(role))


@router.callback_query(F.data == "adm:panels")
async def admin_panels(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    async with AsyncSessionFactory() as session:
        panels = (await session.scalars(select(Panel).order_by(Panel.created_at.desc()))).all()
    rows = [[("➕ افزودن پنل vpn-ui", "panel:add")]]
    for panel in panels:
        status = "🟢" if panel.status == "online" and panel.is_active else "🔴"
        rows.append([(f"{status} {panel.name}", f"panel:show:{panel.id}")])
    rows.append([("↩️ بازگشت", "adm:home")])
    await callback.message.edit_text("🖥 مدیریت پنل‌ها", reply_markup=_kb(rows))


@router.callback_query(F.data == "panel:add")
async def panel_add_start(callback: CallbackQuery, state: FSMContext) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    await state.clear()
    await state.set_state(PanelAdd.name)
    await _state_prompt(callback.message, state, "نام نمایشی پنل را بفرستید:")


@router.message(PanelAdd.name)
async def panel_add_name(message: Message, state: FSMContext) -> None:
    await state.update_data(name=message.text.strip()[:120])
    await state.set_state(PanelAdd.url)
    await _state_prompt(message, state, "آدرس کامل پنل را با https:// بفرستید:")


@router.message(PanelAdd.url)
async def panel_add_url(message: Message, state: FSMContext) -> None:
    await state.update_data(base_url=message.text.strip().rstrip("/"))
    await state.set_state(PanelAdd.base_path)
    await _state_prompt(message, state, "Base Path پنل را بفرستید؛ اگر ندارد فقط - ارسال کنید:")


@router.message(PanelAdd.base_path)
async def panel_add_path(message: Message, state: FSMContext) -> None:
    value = message.text.strip()
    await state.update_data(base_path="" if value == "-" else value.strip("/"))
    await state.set_state(PanelAdd.username)
    await _state_prompt(message, state, "نام کاربری مدیر پنل:")


@router.message(PanelAdd.username)
async def panel_add_username(message: Message, state: FSMContext) -> None:
    await state.update_data(username=message.text.strip())
    await state.set_state(PanelAdd.password)
    await _state_prompt(
        message,
        state,
        "رمز عبور پنل را بفرستید. پیام پس از دریافت حذف می‌شود؛ آن را در گروه ارسال نکنید:",
    )


async def _finish_panel_add(
    message: Message, state: FSMContext, totp_seed: str | None = None
) -> None:
    if not await _message_can(message, "panels"):
        await state.clear()
        return
    data = await state.get_data()
    try:
        config = PanelConfig(
            name=data["name"],
            base_url=data["base_url"],
            base_path=data.get("base_path", ""),
            username=data["username"],
            password=data["password"],
        )
        api = VpnUiClient(config)
        try:
            if totp_seed:
                await api.login(two_factor_code=totp_code(totp_seed))
            else:
                await api.login()
            inbound_rows = await api.list_inbounds()
        finally:
            await api.close()
        extra_data = {}
        if totp_seed:
            extra_data["totp_secret_encrypted"] = encrypt_panel_password(totp_seed)
        async with AsyncSessionFactory() as session:
            duplicate = await session.scalar(select(Panel).where(Panel.name == data["name"]))
            if duplicate:
                raise ValueError("پنلی با این نام قبلاً ثبت شده است.")
            panel = Panel(
                name=data["name"],
                base_url=config.base_url,
                base_path=config.base_path,
                username=config.username,
                encrypted_password=encrypt_panel_password(data["password"]),
                is_active=True,
                status="online",
                last_checked_at=utc_now(),
                extra_data=extra_data,
            )
            session.add(panel)
            await session.flush()
            count = await _sync_services(session, panel, inbound_rows)
            await _audit(session, message.from_user.id, "panel.created", "panel", panel.id)
            await session.commit()
        await state.clear()
        await message.answer(
            f"✅ پنل با موفقیت متصل شد. {count} اینباند همگام‌سازی شد.",
            reply_markup=_home_keyboard(True),
        )
    except PanelTwoFactorRequired:
        await state.set_state(PanelAdd.totp_seed)
        await _state_prompt(
            message,
            state,
            "این پنل 2FA دارد. برای اتصال خودکار دائمی، Seed/Base32 اپلیکیشن Authenticator را بفرستید (کد ۶ رقمی یک‌بارمصرف نفرستید). پیام حذف خواهد شد. اگر Seed را ندارید /cancel کنید و 2FA را برای حساب API غیرفعال کنید.",
        )
    except Exception as exc:
        logger.exception("Panel add failed (%s)", type(exc).__name__)
        await state.clear()
        await message.answer(f"❌ اتصال پنل انجام نشد: {str(exc)[:250]}")


@router.message(PanelAdd.password)
async def panel_add_password(message: Message, state: FSMContext) -> None:
    password = message.text or ""
    try:
        await message.delete()
    except TelegramAPIError as exc:
        logger.debug("Could not delete credential message (%s)", type(exc).__name__)
    if not password:
        await _state_prompt(message, state, "رمز عبور خالی است. دوباره ارسال کنید:")
        return
    await state.update_data(password=password)
    await _finish_panel_add(message, state)


@router.message(PanelAdd.totp_seed)
async def panel_add_totp(message: Message, state: FSMContext) -> None:
    seed = (message.text or "").strip()
    try:
        await message.delete()
    except TelegramAPIError as exc:
        logger.debug("Could not delete TOTP seed message (%s)", type(exc).__name__)
    try:
        totp_code(seed)
    except ValueError:
        await _state_prompt(message, state, "Seed معتبر Base32 نیست. دوباره ارسال کنید یا /cancel:")
        return
    await _finish_panel_add(message, state, seed)


@router.callback_query(F.data.startswith("panel:edit:"))
async def panel_edit_start(callback: CallbackQuery, state: FSMContext) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    panel_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    async with AsyncSessionFactory() as session:
        panel = await session.get(Panel, panel_id)
    if panel is None:
        await callback.message.answer("پنل پیدا نشد.")
        return
    await state.clear()
    await state.update_data(panel_id=str(panel.id))
    await state.set_state(PanelEdit.url)
    await _state_prompt(
        callback.message,
        state,
        f"آدرس جدید پنل را وارد کنید یا - برای حفظ مقدار فعلی:\n{panel.base_url}",
    )


@router.message(PanelEdit.url)
async def panel_edit_url(message: Message, state: FSMContext) -> None:
    value = (message.text or "").strip()
    if value != "-" and not value.startswith("https://"):
        await _state_prompt(message, state, "آدرس باید با https:// شروع شود یا - بفرستید:")
        return
    await state.update_data(base_url=value)
    await state.set_state(PanelEdit.base_path)
    await _state_prompt(
        message, state, "Base Path جدید یا - برای حفظ مقدار فعلی (برای خالی‌کردن، فقط / بفرستید):"
    )


@router.message(PanelEdit.base_path)
async def panel_edit_base_path(message: Message, state: FSMContext) -> None:
    value = (message.text or "").strip()
    await state.update_data(base_path=value)
    await state.set_state(PanelEdit.username)
    await _state_prompt(message, state, "نام کاربری جدید یا - برای حفظ مقدار فعلی:")


@router.message(PanelEdit.username)
async def panel_edit_username(message: Message, state: FSMContext) -> None:
    value = (message.text or "").strip()
    await state.update_data(username=value)
    await state.set_state(PanelEdit.password)
    await _state_prompt(message, state, "رمز عبور جدید یا - برای حفظ رمز فعلی (پیام حذف می‌شود):")


async def _finish_panel_edit(
    message: Message, state: FSMContext, new_totp_seed: str | None = None
) -> None:
    if not await _message_can(message, "panels"):
        await state.clear()
        return
    data = await state.get_data()
    try:
        async with AsyncSessionFactory() as session:
            panel = await session.get(Panel, uuid.UUID(data["panel_id"]))
            if panel is None:
                raise ValueError("پنل پیدا نشد.")
            from vpn_manager.security.panel_credentials import decrypt_panel_password

            password = data["password"]
            if password == "-":
                password = decrypt_panel_password(panel.encrypted_password)
            base_url = panel.base_url if data["base_url"] == "-" else data["base_url"].rstrip("/")
            if data["base_path"] == "-":
                base_path = panel.base_path
            elif data["base_path"] == "/":
                base_path = ""
            else:
                base_path = data["base_path"].strip("/")
            username = panel.username if data["username"] == "-" else data["username"]
            seed_cipher = (panel.extra_data or {}).get("totp_secret_encrypted")
            seed = new_totp_seed or (decrypt_panel_password(seed_cipher) if seed_cipher else None)
            config = PanelConfig(
                name=panel.name,
                base_url=base_url,
                base_path=base_path,
                username=username,
                password=password,
            )
            api = VpnUiClient(config)
            try:
                try:
                    await api.login()
                except PanelTwoFactorRequired:
                    if not seed:
                        raise
                    await api.login(two_factor_code=totp_code(seed))
                inbounds = await api.list_inbounds()
            finally:
                await api.close()
            panel.base_url = base_url
            panel.base_path = base_path
            panel.username = username
            panel.encrypted_password = encrypt_panel_password(password)
            panel.extra_data = dict(panel.extra_data or {})
            if new_totp_seed:
                panel.extra_data["totp_secret_encrypted"] = encrypt_panel_password(new_totp_seed)
            panel.status = "online"
            panel.last_checked_at = utc_now()
            panel.last_error = None
            count = await _sync_services(session, panel, inbounds)
            await _audit(
                session, message.from_user.id, "panel.connection_updated", "panel", panel.id
            )
            await session.commit()
        await state.clear()
        await message.answer(f"✅ اتصال پنل بروزرسانی و تست شد؛ {count} اینباند Sync شد.")
    except PanelTwoFactorRequired:
        await state.set_state(PanelEdit.totp_seed)
        await _state_prompt(
            message,
            state,
            "پنل 2FA می‌خواهد و Seed قبلی موجود نیست. Seed/Base32 اپلیکیشن Authenticator را بفرستید؛ پیام حذف می‌شود:",
        )
    except Exception as exc:
        logger.exception("Panel connection edit failed")
        await state.clear()
        await message.answer(f"❌ بروزرسانی اتصال ناموفق بود: {str(exc)[:250]}")


@router.message(PanelEdit.password)
async def panel_edit_password(message: Message, state: FSMContext) -> None:
    value = message.text or ""
    try:
        await message.delete()
    except TelegramAPIError as exc:
        logger.debug("Could not delete updated panel password message (%s)", type(exc).__name__)
    if not value:
        await _state_prompt(message, state, "رمز خالی است؛ رمز جدید یا - را ارسال کنید:")
        return
    await state.update_data(password=value)
    await _finish_panel_edit(message, state)


@router.message(PanelEdit.totp_seed)
async def panel_edit_totp(message: Message, state: FSMContext) -> None:
    seed = (message.text or "").strip()
    try:
        await message.delete()
    except TelegramAPIError as exc:
        logger.debug("Could not delete updated TOTP seed message (%s)", type(exc).__name__)
    try:
        totp_code(seed)
    except ValueError:
        await _state_prompt(message, state, "Seed معتبر Base32 نیست؛ دوباره ارسال کنید:")
        return
    await _finish_panel_edit(message, state, seed)


@router.callback_query(F.data.startswith("panel:show:"))
async def panel_show(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    panel_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    async with AsyncSessionFactory() as session:
        panel = await session.get(Panel, panel_id)
        services = (
            await session.scalars(select(VPNService).where(VPNService.panel_id == panel_id))
        ).all()
    if panel is None:
        await callback.message.answer("پنل پیدا نشد.")
        return
    rows = [
        [
            ("🔄 همگام‌سازی اینباندها", f"panel:sync:{panel_id}"),
            ("📡 فهرست اینباندها", f"panel:inbounds:{panel_id}"),
        ],
        [("🧩 هسته‌ها و Core Setup", f"panel:cores:{panel_id}")],
        [("🌐 تونل‌های خروجی Xray", f"panel:outbounds:{panel_id}")],
        [("✏️ ویرایش اتصال پنل", f"panel:edit:{panel_id}")],
        [("⏸ فعال/غیرفعال‌کردن پنل", f"panel:toggle:{panel_id}")],
        [("↩️ بازگشت", "adm:panels")],
    ]
    await callback.message.edit_text(
        f"🖥 {panel.name}\nوضعیت: {panel.status}\nآدرس: {panel.base_url}\nتعداد سرویس‌های همگام‌شده: {len(services)}",
        reply_markup=_kb(rows),
    )


@router.callback_query(F.data.startswith("panel:cores:"))
async def panel_cores(callback: CallbackQuery, state: FSMContext) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    panel_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    await state.clear()
    await state.update_data(core_panel_id=str(panel_id))
    try:
        async with AsyncSessionFactory() as session:
            panel = await session.get(Panel, panel_id)
            if panel is None or not panel.is_active:
                raise ValueError("پنل فعال پیدا نشد.")
            api = await _panel_api(panel)
            try:
                status = await api.core_status()
                catalog = await api.core_catalog()
            finally:
                await api.close()
        rows = []
        for core in catalog:
            if core.get("builtin") or core.get("installed"):
                continue
            name = str(core.get("name", ""))
            if name:
                rows.append([(f"➕ نصب {name}", f"core:install:{name}")])
        rows.append([("↩️ بازگشت", f"panel:show:{panel_id}")])
        status_text = json.dumps(status, ensure_ascii=False, default=str)[:1800]
        await callback.message.edit_text(
            f"🧩 وضعیت Coreها\n\n{status_text}\n\nبرای نصب Core جدید، روی نام آن بزنید. نصب Core ممکن است بسته‌ها/ماژول‌های سیستم‌عامل را تغییر دهد؛ ریبوت خودکار انجام نمی‌شود.",
            reply_markup=_kb(rows),
        )
    except Exception as exc:
        logger.exception("Core status request failed")
        await callback.message.answer(f"❌ دریافت وضعیت Core ناموفق بود: {str(exc)[:200]}")


@router.callback_query(F.data.startswith("core:install:"))
async def core_install_confirm(callback: CallbackQuery, state: FSMContext) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    data = await state.get_data()
    if not data.get("core_panel_id"):
        await callback.message.answer("پنل انتخابی منقضی شده است؛ دوباره صفحه Coreها را باز کنید.")
        return
    core_name = callback.data.rsplit(":", 1)[1]
    await state.update_data(core_name=core_name)
    await callback.message.answer(
        f"⚠️ نصب Core «{core_name}» روی سرور پنل شروع می‌شود و ممکن است پکیج‌ها/ماژول‌های سیستم را تغییر دهد. ادامه می‌دهید؟",
        reply_markup=_kb(
            [
                [
                    ("بله، نصب کن", "core:installyes"),
                    ("لغو", f"panel:cores:{data['core_panel_id']}"),
                ]
            ]
        ),
    )


@router.callback_query(F.data == "core:installyes")
async def core_install(callback: CallbackQuery, state: FSMContext) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    data = await state.get_data()
    if not data.get("core_panel_id") or not data.get("core_name"):
        await callback.message.answer("درخواست نصب منقضی شده است؛ دوباره Core را انتخاب کنید.")
        await state.clear()
        return
    panel_id = uuid.UUID(data["core_panel_id"])
    core_name = data["core_name"]
    progress = await callback.message.answer(
        f"⏳ نصب Core «{core_name}» شروع شد؛ در حال دریافت وضعیت از پنل…"
    )
    try:
        async with AsyncSessionFactory() as session:
            panel = await session.get(Panel, panel_id)
            if panel is None or not panel.is_active:
                raise ValueError("پنل فعال پیدا نشد.")
            api = await _panel_api(panel)
            try:
                await api.provision_cores([core_name])
                deadline = asyncio.get_running_loop().time() + 600
                final_status = {}
                last_edit = 0.0
                while asyncio.get_running_loop().time() < deadline:
                    final_status = await api.provision_status()
                    running = bool(final_status.get("running"))
                    done = bool(final_status.get("done"))
                    now = asyncio.get_running_loop().time()
                    if now - last_edit >= 5:
                        steps = final_status.get("steps", [])
                        last_step = steps[-1] if isinstance(steps, list) and steps else {}
                        await progress.edit_text(
                            f"⏳ نصب Core «{core_name}»\nدر حال اجرا: {running}\nآخرین مرحله: {str(last_step.get('name') or last_step.get('msg') or 'در حال بررسی')[:180]}"
                        )
                        last_edit = now
                    if done and not running:
                        break
                    await asyncio.sleep(1)
                else:
                    raise TimeoutError("Core provisioning exceeded 10 minutes")
                await progress.edit_text(
                    f"{'✅' if not final_status.get('error') else '⚠️'} نتیجه نصب Core «{core_name}»\n{json.dumps(final_status, ensure_ascii=False, default=str)[:3000]}\n\nاگر rebootRequired=true باشد، ریبوت را فقط در زمان مناسب و با هماهنگی انجام دهید؛ ربات سرور را خودکار ریبوت نمی‌کند."
                )
            finally:
                await api.close()
        await state.clear()
    except Exception as exc:
        logger.exception("Core provisioning failed")
        await state.clear()
        await progress.edit_text(f"❌ نصب Core ناموفق بود: {str(exc)[:300]}")


@router.callback_query(F.data.startswith("panel:outbounds:"))
async def panel_outbounds(callback: CallbackQuery, state: FSMContext) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    await state.clear()
    panel_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    try:
        async with AsyncSessionFactory() as session:
            panel = await session.get(Panel, panel_id)
            if panel is None or not panel.is_active:
                raise ValueError("پنل فعال پیدا نشد.")
            api = await _panel_api(panel)
            try:
                outbounds = await api.vpn_outbound_list()
                statuses = {}
                for outbound in outbounds:
                    tag = str(outbound.get("tag", ""))
                    if tag:
                        try:
                            statuses[tag] = await api.vpn_outbound_status(tag)
                        except PanelError as exc:
                            statuses[tag] = {"detail": str(exc)}
            finally:
                await api.close()
        lines = ["🌐 تونل‌های خروجی VPN در Xray"]
        if not outbounds:
            lines.append("هیچ تونل خروجی VPN ثبت نشده است.")
        for item in outbounds[:25]:
            tag = str(item.get("tag", "-"))
            status = statuses.get(tag, {})
            state = "🟢 بالا" if status.get("running", status.get("up", False)) else "🔴 قطع/نامشخص"
            lines.append(f"• {tag} · {item.get('kind', '-')} · {state}\n  {item.get('remark', '')}")
        await callback.message.edit_text(
            "\n".join(lines),
            reply_markup=_kb(
                [
                    [("➕ افزودن تونل خروجی", f"outbound:add:{panel_id}")],
                    [("🗑 حذف تونل خروجی", f"outbound:delete:{panel_id}")],
                    [("🔄 بروزرسانی", f"panel:outbounds:{panel_id}")],
                    [("↩️ بازگشت", f"panel:show:{panel_id}")],
                ]
            ),
        )
    except Exception as exc:
        logger.exception("VPN outbound listing failed")
        await callback.message.answer(f"❌ دریافت تونل‌های خروجی ناموفق بود: {str(exc)[:200]}")


@router.callback_query(F.data.startswith("outbound:add:"))
async def outbound_add_start(callback: CallbackQuery, state: FSMContext) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    panel_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    try:
        async with AsyncSessionFactory() as session:
            panel = await session.get(Panel, panel_id)
            if panel is None or not panel.is_active:
                raise ValueError("پنل فعال پیدا نشد.")
            api = await _panel_api(panel)
            try:
                kinds = await api.vpn_outbound_kinds()
            finally:
                await api.close()
        available = [item for item in kinds if item.get("available")]
        if not available:
            await callback.message.answer(
                "هیچ نوع تونل خروجی قابل استفاده‌ای روی این پنل موجود نیست."
            )
            return
        await state.clear()
        await state.update_data(
            panel_id=str(panel_id), available_kinds=[item.get("kind") for item in available]
        )
        await state.set_state(OutboundAdd.tag)
        await _state_prompt(
            callback.message, state, "یک Tag یکتا برای تونل انتخاب کنید (فقط حروف، عدد، - و _):"
        )
    except Exception as exc:
        logger.exception("Could not load VPN outbound kinds")
        await callback.message.answer(f"❌ دریافت انواع تونل ناموفق بود: {str(exc)[:200]}")


@router.message(OutboundAdd.tag)
async def outbound_add_tag(message: Message, state: FSMContext) -> None:
    tag = (message.text or "").strip()
    if not tag or len(tag) > 48 or not all(ch.isalnum() or ch in "-_" for ch in tag):
        await _state_prompt(
            message, state, "Tag نامعتبر است. فقط حروف، عدد، خط تیره و زیرخط مجاز است:"
        )
        return
    data = await state.get_data()
    await state.update_data(tag=tag)
    rows = [[(str(kind), f"outkind:{kind}")] for kind in data.get("available_kinds", []) if kind]
    await _state_prompt(message, state, "نوع تونل خروجی را انتخاب کنید:", reply_markup=_kb(rows))


@router.callback_query(F.data.startswith("outkind:"))
async def outbound_add_kind(callback: CallbackQuery, state: FSMContext) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    kind = callback.data.split(":", 1)[1]
    data = await state.get_data()
    if kind not in data.get("available_kinds", []):
        await callback.message.answer("این نوع تونل در دسترس نیست.")
        return
    await state.update_data(kind=kind)
    await state.set_state(OutboundAdd.remark)
    await _state_prompt(
        callback.message, state, "توضیح نمایشی تونل (در صورت نداشتن، - ارسال کنید):"
    )


@router.message(OutboundAdd.remark)
async def outbound_add_remark(message: Message, state: FSMContext) -> None:
    remark = (message.text or "").strip()
    await state.update_data(remark="" if remark == "-" else remark[:160])
    await state.set_state(OutboundAdd.settings)
    await _state_prompt(
        message,
        state,
        "Settings را به‌صورت JSON معتبر بفرستید. ساختار دقیق به نوع تونل بستگی دارد؛ این داده مستقیم به درایور vpn-ui ارسال می‌شود. پیام حاوی Secret پس از دریافت حذف خواهد شد.",
    )


@router.message(OutboundAdd.settings)
async def outbound_add_settings(message: Message, state: FSMContext) -> None:
    if not await _message_can(message, "panels"):
        await state.clear()
        return
    raw = message.text or ""
    try:
        await message.delete()
    except TelegramAPIError as exc:
        logger.debug("Could not delete outbound secret message (%s)", type(exc).__name__)
    try:
        settings = json.loads(raw)
        if not isinstance(settings, dict):
            raise TypeError("Settings must be a JSON object")
        data = await state.get_data()
        panel_id = uuid.UUID(data["panel_id"])
        async with AsyncSessionFactory() as session:
            panel = await session.get(Panel, panel_id)
            if panel is None or not panel.is_active:
                raise ValueError("پنل فعال پیدا نشد.")
            api = await _panel_api(panel)
            try:
                result = await api.vpn_outbound_save(
                    tag=data["tag"],
                    kind=data["kind"],
                    settings=settings,
                    remark=data.get("remark", ""),
                )
            finally:
                await api.close()
            await _audit(
                session,
                message.from_user.id,
                "vpn_outbound.created",
                "panel",
                panel.id,
                {"tag": data["tag"], "kind": data["kind"]},
            )
            await session.commit()
        await state.clear()
        await message.answer(
            f"✅ تونل خروجی ذخیره شد.\nTag: {data['tag']}\nInterface: {result.get('iface', 'ثبت شد')}"
        )
    except (json.JSONDecodeError, ValueError, TypeError, PanelError, RuntimeError) as exc:
        await state.clear()
        await message.answer(f"❌ ذخیره تونل انجام نشد: {str(exc)[:300]}")


@router.callback_query(F.data.startswith("outbound:delete:"))
async def outbound_delete_start(callback: CallbackQuery, state: FSMContext) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    panel_id = callback.data.rsplit(":", 1)[1]
    await state.clear()
    await state.update_data(panel_id=panel_id)
    await state.set_state(OutboundDelete.tag)
    await _state_prompt(callback.message, state, "Tag دقیق تونلی که باید حذف شود را وارد کنید:")


@router.message(OutboundDelete.tag)
async def outbound_delete_tag(message: Message, state: FSMContext) -> None:
    if not await _message_can(message, "panels"):
        await state.clear()
        return
    tag = (message.text or "").strip()
    data = await state.get_data()
    try:
        async with AsyncSessionFactory() as session:
            panel = await session.get(Panel, uuid.UUID(data["panel_id"]))
            if panel is None:
                raise ValueError("پنل پیدا نشد.")
            api = await _panel_api(panel)
            try:
                outbounds = await api.vpn_outbound_list()
            finally:
                await api.close()
        if not any(str(item.get("tag")) == tag for item in outbounds):
            await _state_prompt(
                message, state, "تونلی با این Tag پیدا نشد. دوباره وارد کنید یا /cancel:"
            )
            return
        await state.update_data(tag=tag)
        await _state_prompt(
            message,
            state,
            f"⚠️ تونل خروجی «{tag}» حذف شود؟",
            reply_markup=_kb(
                [
                    [
                        ("بله، حذف شود", "outbound:deleteyes"),
                        ("لغو", f"panel:outbounds:{data['panel_id']}"),
                    ]
                ]
            ),
        )
    except Exception as exc:
        logger.exception("VPN outbound delete lookup failed")
        await state.clear()
        await message.answer(f"❌ بررسی تونل ناموفق بود: {str(exc)[:200]}")


@router.callback_query(F.data == "outbound:deleteyes")
async def outbound_delete_confirmed(callback: CallbackQuery, state: FSMContext) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    data = await state.get_data()
    try:
        async with AsyncSessionFactory() as session:
            panel = await session.get(Panel, uuid.UUID(data["panel_id"]))
            if panel is None:
                raise ValueError("پنل پیدا نشد.")
            api = await _panel_api(panel)
            try:
                await api.vpn_outbound_delete(data["tag"])
            finally:
                await api.close()
            await _audit(
                session,
                callback.from_user.id,
                "vpn_outbound.deleted",
                "panel",
                panel.id,
                {"tag": data["tag"]},
            )
            await session.commit()
        await state.clear()
        await callback.message.answer(f"تونل خروجی «{data['tag']}» حذف شد.")
    except Exception as exc:
        logger.exception("VPN outbound delete failed")
        await state.clear()
        await callback.message.answer(f"❌ حذف تونل ناموفق بود: {str(exc)[:200]}")


@router.callback_query(F.data.startswith("panel:toggle:"))
async def panel_toggle(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    panel_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    async with AsyncSessionFactory() as session:
        panel = await session.get(Panel, panel_id)
        if panel is None:
            await callback.message.answer("پنل پیدا نشد.")
            return
        panel.is_active = not panel.is_active
        if not panel.is_active:
            for service in (
                await session.scalars(select(VPNService).where(VPNService.panel_id == panel.id))
            ).all():
                service.is_active = False
                for plan in (
                    await session.scalars(
                        select(ProductPlan).where(ProductPlan.service_id == service.id)
                    )
                ).all():
                    plan.is_active = False
            for managed in (
                await session.scalars(
                    select(ManagedClient).where(ManagedClient.service_id == service.id)
                )
            ).all():
                managed.is_present = False
            for subscription in (
                await session.scalars(
                    select(Subscription).where(Subscription.service_id == service.id)
                )
            ).all():
                subscription.status = "cancelled"
        await _audit(
            session,
            callback.from_user.id,
            "panel.toggled",
            "panel",
            panel.id,
            {"active": panel.is_active},
        )
        await session.commit()
    await callback.message.answer("وضعیت پنل ذخیره شد. برای مشاهده جزئیات دوباره پنل را باز کنید.")


@router.callback_query(F.data.startswith("panel:sync:"))
async def panel_sync(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    panel_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    try:
        count = await _panel_connect_and_sync(panel_id)
        await callback.message.answer(f"✅ همگام‌سازی انجام شد؛ {count} اینباند معتبر شناسایی شد.")
    except Exception as exc:
        logger.exception("Panel sync failed")
        await callback.message.answer(f"❌ همگام‌سازی ناموفق: {str(exc)[:250]}")


@router.callback_query(F.data.startswith("panel:inbounds:"))
async def panel_inbounds(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    panel_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    async with AsyncSessionFactory() as session:
        services = (
            await session.scalars(
                select(VPNService).where(VPNService.panel_id == panel_id).order_by(VPNService.name)
            )
        ).all()
    rows = [[("➕ ساخت اینباند جدید", f"inbound:add:{panel_id}")]]
    for service in services:
        state = "🟢" if service.is_active else "🔴"
        rows.append(
            [
                (
                    f"{state} {service.name} · {service.protocol} · #{service.external_id}",
                    f"inbound:show:{service.id}",
                )
            ]
        )
    rows.append([("↩️ بازگشت", f"panel:show:{panel_id}")])
    await callback.message.edit_text("📡 اینباندهای پنل", reply_markup=_kb(rows))


@router.callback_query(F.data.startswith("inbound:add:"))
async def inbound_add_start(callback: CallbackQuery, state: FSMContext) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    panel_id = callback.data.rsplit(":", 1)[1]
    supported = [
        "l2tp",
        "pptp",
        "openconnect",
        "openvpn",
        "sstp",
        "ikev2",
        "wg-c",
        "awg",
        "gre",
        "mtproto",
        "ssh",
        "anytls",
        "tuic",
        "naive",
    ]
    rows = [[(protocol, f"inaddproto:{panel_id}:{protocol}")] for protocol in supported]
    rows.append([("↩️ بازگشت", f"panel:inbounds:{panel_id}")])
    await callback.message.edit_text(
        "پروتکل را انتخاب کنید. توجه: OpenConnect و پروتکل‌های TLS ممکن است بعد از ساخت به گواهی و Stream Settings نیاز داشته باشند.",
        reply_markup=_kb(rows),
    )


@router.callback_query(F.data.startswith("inaddproto:"))
async def inbound_add_protocol(callback: CallbackQuery, state: FSMContext) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    _, panel_id, protocol = callback.data.split(":", 2)
    await state.clear()
    await state.update_data(panel_id=panel_id, protocol=protocol)
    await state.set_state(InboundAdd.name)
    await _state_prompt(callback.message, state, "نام اینباند:")


@router.message(InboundAdd.name)
async def inbound_add_name(message: Message, state: FSMContext) -> None:
    await state.update_data(name=(message.text or "").strip()[:160])
    await state.set_state(InboundAdd.port)
    data = await state.get_data()
    if data["protocol"] == "gre":
        await _state_prompt(message, state, "GRE پورت ندارد؛ برای ادامه فقط - ارسال کنید:")
    else:
        await _state_prompt(message, state, "شماره پورت (1 تا 65535):")


@router.message(InboundAdd.port)
async def inbound_add_port(message: Message, state: FSMContext) -> None:
    if not await _message_can(message, "panels"):
        await state.clear()
        return
    data = await state.get_data()
    try:
        if data["protocol"] == "gre" and (message.text or "").strip() == "-":
            port = None
        else:
            port = int((message.text or "").strip())
            if not 1 <= port <= 65535:
                raise ValueError
        panel_id = uuid.UUID(data["panel_id"])
        async with AsyncSessionFactory() as session:
            panel = await session.get(Panel, panel_id)
            if panel is None or not panel.is_active:
                raise ValueError("پنل فعال پیدا نشد.")
            api = await _panel_api(panel)
            try:
                settings: dict = {"clients": []}
                if data["protocol"] == "openvpn":
                    settings.update(await api.generate_inbound_certificate("openvpn"))
                elif data["protocol"] in {"openconnect", "sstp"}:
                    cert = await api.generate_inbound_certificate(data["protocol"])
                    settings.update(
                        {
                            "tlsUseFile": False,
                            "certificate": cert["certificate"],
                            "key": cert["key"],
                        }
                    )
                elif data["protocol"] == "ikev2":
                    cert = await api.generate_inbound_certificate("ikev2")
                    settings.update(
                        {
                            "authMode": "eap-mschapv2",
                            "tlsUseFile": False,
                            "certificate": cert["certificate"],
                            "key": cert["key"],
                            "caCert": cert["caCert"],
                        }
                    )
                await api.create_inbound(
                    remark=data["name"],
                    protocol=data["protocol"],
                    port=port,
                    enable=True,
                    settings=settings,
                )
                rows = await api.list_inbounds()
            finally:
                await api.close()
            await _sync_services(session, panel, rows)
            await _audit(
                session,
                message.from_user.id,
                "inbound.created",
                "panel",
                panel.id,
                {"protocol": data["protocol"], "port": port},
            )
            await session.commit()
        await state.clear()
        await message.answer("✅ درخواست ساخت اینباند موفق بود و فهرست پنل به‌روزرسانی شد.")
    except Exception as exc:
        logger.exception("Inbound create failed")
        await state.clear()
        await message.answer(f"❌ ساخت اینباند ناموفق بود: {str(exc)[:250]}")


@router.callback_query(F.data.startswith("inbound:show:"))
async def inbound_show(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    service_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    async with AsyncSessionFactory() as session:
        service = await session.get(VPNService, service_id)
        plans = (
            await session.scalars(select(ProductPlan).where(ProductPlan.service_id == service_id))
        ).all()
    if service is None:
        await callback.message.answer("سرویس پیدا نشد.")
        return
    panel_id = service.panel_id
    rows = [
        [
            ("🔁 تغییر وضعیت", f"inbound:toggle:{service.id}"),
            ("✏️ تغییر نام", f"inbound:rename:{service.id}"),
        ],
        *([[("🔌 تغییر پورت", f"inbound:port:{service.id}")]] if service.protocol != "gre" else []),
        [("👥 مدیریت کاربران اینباند", f"inbound:clients:{service.id}")],
        [("🗑 حذف اینباند", f"inbound:delete:{service.id}")],
        [("↩️ بازگشت", f"panel:inbounds:{panel_id}")],
    ]
    await callback.message.edit_text(
        f"{service.name}\nپروتکل: {service.protocol}\nشناسه پنل: {service.external_id}\nوضعیت فروش: {'فعال' if service.is_active else 'غیرفعال'}\nپلن‌ها: {len(plans)}",
        reply_markup=_kb(rows),
    )


@router.callback_query(F.data.startswith("inbound:clients:"))
async def inbound_clients(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    service_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    try:
        async with AsyncSessionFactory() as session:
            service = await session.get(VPNService, service_id)
            panel = await session.get(Panel, service.panel_id) if service else None
            if service is None or panel is None:
                raise ValueError("اینباند پیدا نشد.")
            api = await _panel_api(panel)
            try:
                inbound = await api.get_inbound(int(service.external_id))
            finally:
                await api.close()
            clients = await _sync_managed_clients(session, service, inbound)
            await session.commit()
        rows = [
            [
                (
                    f"{'🟢' if item.is_enabled else '🔴'} {item.email} · {item.external_identity[:14]}",
                    f"mclient:show:{item.id}",
                )
            ]
            for item in clients[:40]
        ]
        rows.append([("↩️ بازگشت", f"inbound:show:{service_id}")])
        await callback.message.edit_text(
            f"👥 کاربران اینباند {service.name}\nتعداد: {len(clients)}",
            reply_markup=_kb(rows),
        )
    except Exception as exc:
        logger.exception("Could not load inbound clients")
        await callback.message.answer(f"❌ دریافت کاربران ناموفق بود: {str(exc)[:200]}")


@router.callback_query(F.data.startswith("mclient:show:"))
async def managed_client_show(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    record_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    async with AsyncSessionFactory() as session:
        record = await session.get(ManagedClient, record_id)
        service = await session.get(VPNService, record.service_id) if record else None
        panel = await session.get(Panel, service.panel_id) if service else None
        if record is None or service is None or panel is None or not record.is_present:
            await callback.message.answer("کاربر پنل پیدا نشد یا حذف شده است.")
            return
        payload = json.loads(decrypt_panel_password(record.encrypted_payload))
        usage = None
        try:
            api = await _panel_api(panel)
            try:
                usage = await api.client_traffic(record.email)
            finally:
                await api.close()
        except PanelError as exc:
            logger.info(
                "Traffic lookup unavailable for client %s (%s)", record.id, type(exc).__name__
            )
    up = int((usage or {}).get("up", 0) or 0)
    down = int((usage or {}).get("down", 0) or 0)
    quota = int(payload.get("totalGB", 0) or 0)
    expiry_ms = int(payload.get("expiryTime", 0) or 0)
    expiry_text = (
        datetime.fromtimestamp(expiry_ms / 1000, UTC).strftime("%Y-%m-%d %H:%M UTC")
        if expiry_ms
        else "نامحدود"
    )
    lines = [
        f"👤 {record.email}",
        f"پروتکل: {service.protocol}",
        f"هویت API: {record.external_identity}",
        f"وضعیت: {'فعال' if record.is_enabled else 'غیرفعال'}",
        f"مصرف ثبت‌شده: {(up + down) / 1024**3:.3f} GB",
        f"سقف حجم: {quota / 1024**3:.3f} GB" if quota else "سقف حجم: نامحدود",
        f"انقضا: {expiry_text}",
        f"IP هم‌زمان مجاز (limitIp): {payload.get('limitIp', 0) or 'نامحدود'}",
    ]
    await callback.message.edit_text(
        "\n".join(lines),
        reply_markup=_kb(
            [
                [
                    ("🔁 فعال/غیرفعال", f"mclient:toggle:{record.id}"),
                    ("✏️ ویرایش محدودیت‌ها", f"mclient:edit:{record.id}"),
                ],
                [("🗑 حذف کاربر از اینباند", f"mclient:delete:{record.id}")],
                [("↩️ بازگشت", f"inbound:clients:{service.id}")],
            ]
        ),
    )


@router.callback_query(F.data.startswith("mclient:toggle:"))
async def managed_client_toggle(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    record_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    try:
        async with AsyncSessionFactory() as session:
            record = await session.get(ManagedClient, record_id)
            service = await session.get(VPNService, record.service_id) if record else None
            panel = await session.get(Panel, service.panel_id) if service else None
            if record is None or service is None or panel is None or not record.is_present:
                raise ValueError("کاربر پنل پیدا نشد.")
            payload = json.loads(decrypt_panel_password(record.encrypted_payload))
            enabled = not bool(payload.get("enable", record.is_enabled))
            payload["enable"] = enabled
            api = await _panel_api(panel)
            try:
                await api.update_client(int(service.external_id), record.external_identity, payload)
            finally:
                await api.close()
            record.is_enabled = enabled
            record.encrypted_payload = encrypt_panel_password(
                json.dumps(payload, separators=(",", ":"))
            )
            await _audit(
                session,
                callback.from_user.id,
                "panel_client.toggled",
                "managed_client",
                record.id,
                {"enabled": enabled},
            )
            await session.commit()
        await callback.message.answer("وضعیت کاربر در پنل تغییر کرد.")
    except Exception as exc:
        logger.exception("Managed client toggle failed")
        await callback.message.answer(f"❌ تغییر وضعیت کاربر ناموفق بود: {str(exc)[:200]}")


@router.callback_query(F.data.startswith("mclient:delete:"))
async def managed_client_delete_confirm(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    record_id = callback.data.rsplit(":", 1)[1]
    await callback.message.answer(
        "⚠️ این عملیات حساب را از اینباند انتخاب‌شده حذف می‌کند. مطمئن هستید؟",
        reply_markup=_kb(
            [
                [
                    ("بله، حذف کن", f"mclient:deleteyes:{record_id}"),
                    ("لغو", f"mclient:show:{record_id}"),
                ]
            ]
        ),
    )


@router.callback_query(F.data.startswith("mclient:deleteyes:"))
async def managed_client_delete(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    record_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    try:
        async with AsyncSessionFactory() as session:
            record = await session.get(ManagedClient, record_id)
            service = await session.get(VPNService, record.service_id) if record else None
            panel = await session.get(Panel, service.panel_id) if service else None
            if record is None or service is None or panel is None or not record.is_present:
                raise ValueError("کاربر پنل پیدا نشد.")
            api = await _panel_api(panel)
            try:
                await api.delete_client(int(service.external_id), record.external_identity)
            finally:
                await api.close()
            record.is_present = False
            for subscription in (
                await session.scalars(
                    select(Subscription).where(
                        Subscription.service_id == service.id,
                        Subscription.external_client_id == record.external_identity,
                    )
                )
            ).all():
                subscription.status = "cancelled"
            await _audit(
                session, callback.from_user.id, "panel_client.deleted", "managed_client", record.id
            )
            await session.commit()
        await callback.message.answer("کاربر از اینباند حذف شد.")
    except Exception as exc:
        logger.exception("Managed client delete failed")
        await callback.message.answer(f"❌ حذف کاربر ناموفق بود: {str(exc)[:200]}")


@router.callback_query(F.data.startswith("mclient:edit:"))
async def managed_client_edit_start(callback: CallbackQuery, state: FSMContext) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    record_id = callback.data.rsplit(":", 1)[1]
    await state.clear()
    await state.update_data(record_id=record_id)
    await state.set_state(ManagedClientEdit.traffic_gb)
    await _state_prompt(callback.message, state, "سقف حجم جدید به GB (0 = نامحدود):")


@router.message(ManagedClientEdit.traffic_gb)
async def managed_client_edit_traffic(message: Message, state: FSMContext) -> None:
    try:
        traffic_gb = Decimal((message.text or "").strip().replace(",", "."))
        if traffic_gb < 0 or traffic_gb > Decimal(100000):
            raise ValueError
    except (InvalidOperation, ValueError):
        await _state_prompt(message, state, "عدد معتبر صفر یا بیشتر وارد کنید:")
        return
    await state.update_data(traffic_limit_bytes=int(traffic_gb * Decimal(1024**3)))
    await state.set_state(ManagedClientEdit.days)
    await _state_prompt(message, state, "اعتبار باقی‌مانده به روز (0 = بدون انقضا):")


@router.message(ManagedClientEdit.days)
async def managed_client_edit_days(message: Message, state: FSMContext) -> None:
    try:
        days = int((message.text or "").strip())
        if not 0 <= days <= 3650:
            raise ValueError
    except ValueError:
        await _state_prompt(message, state, "عدد بین 0 تا 3650 وارد کنید:")
        return
    await state.update_data(days=days)
    await state.set_state(ManagedClientEdit.devices)
    await _state_prompt(message, state, "حداکثر IP/اتصال هم‌زمان (limitIp؛ 0 = نامحدود):")


@router.message(ManagedClientEdit.devices)
async def managed_client_edit_finish(message: Message, state: FSMContext) -> None:
    if not await _message_can(message, "panels"):
        await state.clear()
        return
    try:
        devices = int((message.text or "").strip())
        if not 0 <= devices <= 64:
            raise ValueError
        data = await state.get_data()
        async with AsyncSessionFactory() as session:
            record = await session.get(ManagedClient, uuid.UUID(data["record_id"]))
            service = await session.get(VPNService, record.service_id) if record else None
            panel = await session.get(Panel, service.panel_id) if service else None
            if record is None or service is None or panel is None or not record.is_present:
                raise ValueError("کاربر پنل پیدا نشد.")
            payload = json.loads(decrypt_panel_password(record.encrypted_payload))
            payload["totalGB"] = data["traffic_limit_bytes"]
            payload["expiryTime"] = (
                int((datetime.now(UTC) + timedelta(days=data["days"])).timestamp() * 1000)
                if data["days"]
                else 0
            )
            payload["limitIp"] = devices
            api = await _panel_api(panel)
            try:
                await api.update_client(int(service.external_id), record.external_identity, payload)
            finally:
                await api.close()
            record.encrypted_payload = encrypt_panel_password(
                json.dumps(payload, separators=(",", ":"))
            )
            record.is_enabled = bool(payload.get("enable", True))
            for subscription in (
                await session.scalars(
                    select(Subscription).where(
                        Subscription.service_id == service.id,
                        Subscription.external_client_id == record.external_identity,
                    )
                )
            ).all():
                subscription.traffic_limit_bytes = data["traffic_limit_bytes"]
                subscription.expires_at = (
                    datetime.fromtimestamp(payload["expiryTime"] / 1000, UTC)
                    if payload["expiryTime"]
                    else None
                )
            await _audit(
                session, message.from_user.id, "panel_client.updated", "managed_client", record.id
            )
            await session.commit()
        await message.answer("✅ محدودیت‌های کاربر در پنل به‌روزرسانی شد.")
    except (PanelError, ValueError, RuntimeError) as exc:
        await message.answer(f"❌ ویرایش کاربر ناموفق بود: {str(exc)[:200]}")
    finally:
        await state.clear()


@router.callback_query(F.data.startswith("inbound:toggle:"))
async def inbound_toggle(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    service_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    try:
        async with AsyncSessionFactory() as session:
            service = await session.get(VPNService, service_id)
            panel = await session.get(Panel, service.panel_id) if service else None
            if service is None or panel is None:
                raise ValueError("سرویس یا پنل پیدا نشد.")
            api = await _panel_api(panel)
            try:
                inbound = await api.get_inbound(int(service.external_id))
                enabled = not bool(inbound.get("enable", True))
                await api.update_inbound(int(service.external_id), enable=enabled)
            finally:
                await api.close()
            service.is_active = enabled
            if not enabled:
                for plan in (
                    await session.scalars(
                        select(ProductPlan).where(ProductPlan.service_id == service.id)
                    )
                ).all():
                    plan.is_active = False
            await _audit(
                session,
                callback.from_user.id,
                "inbound.toggled",
                "service",
                service.id,
                {"enabled": enabled},
            )
            await session.commit()
        await callback.message.answer(
            "وضعیت اینباند تغییر کرد. برای مشاهده جزئیات دوباره آن را باز کنید."
        )
    except Exception as exc:
        logger.exception("Inbound toggle failed")
        await callback.message.answer(f"❌ تغییر وضعیت ناموفق: {str(exc)[:200]}")


@router.callback_query(F.data.startswith("inbound:rename:"))
async def inbound_rename_start(callback: CallbackQuery, state: FSMContext) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    service_id = callback.data.rsplit(":", 1)[1]
    await state.clear()
    await state.update_data(service_id=service_id)
    await state.set_state(InboundRename.name)
    await _state_prompt(callback.message, state, "نام جدید اینباند را بفرستید:")


@router.message(InboundRename.name)
async def inbound_rename_finish(message: Message, state: FSMContext) -> None:
    if not await _message_can(message, "panels"):
        await state.clear()
        return
    data = await state.get_data()
    name = (message.text or "").strip()[:160]
    try:
        async with AsyncSessionFactory() as session:
            service = await session.get(VPNService, uuid.UUID(data["service_id"]))
            panel = await session.get(Panel, service.panel_id) if service else None
            if service is None or panel is None or not name:
                raise ValueError("نام یا سرویس معتبر نیست.")
            api = await _panel_api(panel)
            try:
                await api.update_inbound(int(service.external_id), remark=name)
            finally:
                await api.close()
            service.name = name
            await _audit(session, message.from_user.id, "inbound.renamed", "service", service.id)
            await session.commit()
        await message.answer("✅ نام اینباند تغییر کرد.")
    except (PanelError, ValueError, RuntimeError) as exc:
        await message.answer(f"❌ تغییر نام انجام نشد: {str(exc)[:200]}")
    finally:
        await state.clear()


@router.callback_query(F.data.startswith("inbound:port:"))
async def inbound_port_start(callback: CallbackQuery, state: FSMContext) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    service_id = callback.data.rsplit(":", 1)[1]
    await state.clear()
    await state.update_data(service_id=service_id)
    await state.set_state(InboundPortEdit.port)
    await _state_prompt(callback.message, state, "پورت جدید اینباند را وارد کنید (1 تا 65535):")


@router.message(InboundPortEdit.port)
async def inbound_port_finish(message: Message, state: FSMContext) -> None:
    if not await _message_can(message, "panels"):
        await state.clear()
        return
    try:
        port = int((message.text or "").strip())
        if not 1 <= port <= 65535:
            raise ValueError
        data = await state.get_data()
        async with AsyncSessionFactory() as session:
            service = await session.get(VPNService, uuid.UUID(data["service_id"]))
            panel = await session.get(Panel, service.panel_id) if service else None
            if service is None or panel is None or service.protocol == "gre":
                raise ValueError("اینباند معتبر نیست.")
            api = await _panel_api(panel)
            try:
                await api.update_inbound(int(service.external_id), port=port)
            finally:
                await api.close()
            service.extra_data = {**(service.extra_data or {}), "port": port}
            await _audit(
                session,
                message.from_user.id,
                "inbound.port_changed",
                "service",
                service.id,
                {"port": port},
            )
            await session.commit()
        await message.answer("✅ پورت اینباند تغییر کرد.")
    except (PanelError, ValueError, RuntimeError) as exc:
        await message.answer(f"❌ تغییر پورت ناموفق بود: {str(exc)[:200]}")
    finally:
        await state.clear()


@router.callback_query(F.data.startswith("inbound:delete:"))
async def inbound_delete_confirm(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    service_id = callback.data.rsplit(":", 1)[1]
    await callback.message.answer(
        "⚠️ حذف اینباند روی سرور پنل اثر واقعی دارد. مطمئن هستید؟",
        reply_markup=_kb(
            [
                [
                    ("بله، حذف شود", f"inbound:deleteyes:{service_id}"),
                    ("لغو", f"inbound:show:{service_id}"),
                ]
            ]
        ),
    )


@router.callback_query(F.data.startswith("inbound:deleteyes:"))
async def inbound_delete(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "panels"):
        return
    service_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    try:
        async with AsyncSessionFactory() as session:
            service = await session.get(VPNService, service_id)
            panel = await session.get(Panel, service.panel_id) if service else None
            if service is None or panel is None:
                raise ValueError("اینباند پیدا نشد.")
            api = await _panel_api(panel)
            try:
                await api.delete_inbound(int(service.external_id))
            finally:
                await api.close()
            service.is_active = False
            for plan in (
                await session.scalars(
                    select(ProductPlan).where(ProductPlan.service_id == service.id)
                )
            ).all():
                plan.is_active = False
            subscriptions = (
                await session.scalars(
                    select(Subscription).where(
                        Subscription.service_id == service.id,
                        Subscription.status.notin_(["cancelled", "expired"]),
                    )
                )
            ).all()
            for subscription in subscriptions:
                subscription.status = "cancelled"
            managed_clients = (
                await session.scalars(
                    select(ManagedClient).where(ManagedClient.service_id == service.id)
                )
            ).all()
            for managed in managed_clients:
                managed.is_present = False
                managed.is_enabled = False
            await _audit(
                session,
                callback.from_user.id,
                "inbound.deleted",
                "service",
                service.id,
                {
                    "cancelled_subscriptions": len(subscriptions),
                    "marked_clients_absent": len(managed_clients),
                },
            )
            await session.commit()
        await callback.message.answer(
            f"اینباند حذف و از فروش خارج شد؛ {len(subscriptions)} اشتراک لغو و {len(managed_clients)} رکورد کلاینت از حالت حاضر خارج شد."
        )
    except Exception as exc:
        logger.exception("Inbound delete failed")
        await callback.message.answer(f"❌ حذف ناموفق: {str(exc)[:200]}")


@router.callback_query(F.data == "adm:customers")
async def admin_customers(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "customers"):
        return
    async with AsyncSessionFactory() as session:
        customers = (
            await session.scalars(select(Customer).order_by(Customer.created_at.desc()).limit(20))
        ).all()
    rows = [[("🔎 جستجوی کاربر با ID یا Username", "cust:search")]]
    for customer in customers:
        label = f"{'⛔' if customer.status != 'active' else '👤'} {customer.full_name or customer.username or customer.telegram_id} · {customer.telegram_id}"
        rows.append([(label[:60], f"cust:show:{customer.id}")])
    rows.append([("↩️ بازگشت", "adm:home")])
    await callback.message.edit_text("👥 آخرین کاربران ثبت‌شده", reply_markup=_kb(rows))


@router.callback_query(F.data == "cust:search")
async def customer_search_start(callback: CallbackQuery, state: FSMContext) -> None:
    if not await _answer_admin(callback, "customers"):
        return
    await state.clear()
    await state.set_state(CustomerSearch.query)
    await _state_prompt(callback.message, state, "Telegram ID یا Username کاربر را وارد کنید:")


@router.message(CustomerSearch.query)
async def customer_search_finish(message: Message, state: FSMContext) -> None:
    if not await _message_can(message, "customers"):
        await state.clear()
        return
    query = (message.text or "").strip().lstrip("@")
    if len(query) < 2:
        await _state_prompt(message, state, "حداقل دو نویسه وارد کنید:")
        return
    async with AsyncSessionFactory() as session:
        statement = select(Customer).order_by(Customer.created_at.desc()).limit(20)
        if query.isdigit():
            statement = statement.where(Customer.telegram_id == int(query))
        else:
            statement = statement.where(
                func.lower(Customer.username).contains(query.lower())
                | func.lower(Customer.full_name).contains(query.lower())
            )
        customers = (await session.scalars(statement)).all()
    await state.clear()
    rows = [
        [
            (
                f"{'⛔' if customer.status != 'active' else '👤'} {customer.full_name or customer.username or customer.telegram_id} · {customer.telegram_id}"[
                    :60
                ],
                f"cust:show:{customer.id}",
            )
        ]
        for customer in customers
    ]
    rows.append([("↩️ بازگشت", "adm:customers")])
    await message.answer(
        f"نتیجه جستجو: {len(customers)} کاربر",
        reply_markup=_kb(rows),
    )


@router.callback_query(F.data.startswith("cust:show:"))
async def customer_show(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "customers"):
        return
    customer_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    async with AsyncSessionFactory() as session:
        customer = await session.get(Customer, customer_id)
        balance = await wallet_balance(session, customer_id)
        subs = (
            await session.scalars(
                select(Subscription).where(Subscription.customer_id == customer_id)
            )
        ).all()
        role = await _admin_role(session, callback.from_user.id)
    if customer is None:
        await callback.message.answer("کاربر پیدا نشد.")
        return
    rows = []
    if _can(role, "customer_write"):
        rows.append([("⛔ مسدود/فعال‌سازی", f"cust:toggle:{customer.id}")])
    if _can(role, "wallet"):
        rows.append([("💰 اصلاح موجودی کیف پول", f"cust:walletadjust:{customer.id}")])
    if (
        _can(role, "customer_write")
        and customer.status == "active"
        and any(sub.status in {"suspended", "suspension_failed"} for sub in subs)
    ):
        rows.append([("▶️ بازیابی اشتراک‌های تعلیق‌شده/نامشخص", f"cust:restore:{customer.id}")])
    rows.append([("↩️ بازگشت", "adm:customers")])
    await callback.message.edit_text(
        f"👤 {customer.full_name or '-'}\nTelegram ID: {customer.telegram_id}\nUsername: @{customer.username or '-'}\nوضعیت: {customer.status}\nکیف پول: {_price(balance, 'IRR')}\nتعداد اشتراک: {len(subs)}",
        reply_markup=_kb(rows),
    )


@router.callback_query(F.data.startswith("cust:toggle:"))
async def customer_toggle(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "customer_write"):
        return
    customer_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    async with AsyncSessionFactory() as session:
        customer = await session.get(Customer, customer_id)
        if customer is None:
            await callback.message.answer("کاربر پیدا نشد.")
            return
        customer.status = "blocked" if customer.status == "active" else "active"
        disabled_count = 0
        failed_count = 0
        if customer.status == "blocked":
            subscriptions = (
                await session.scalars(
                    select(Subscription).where(
                        Subscription.customer_id == customer.id,
                        Subscription.status.notin_(["cancelled", "expired"]),
                    )
                )
            ).all()
            for subscription in subscriptions:
                encrypted_payload = (subscription.extra_data or {}).get("client_payload_encrypted")
                service = await session.get(VPNService, subscription.service_id)
                panel = await session.get(Panel, service.panel_id) if service else None
                if not encrypted_payload or not service or not panel:
                    subscription.status = "suspension_failed"
                    failed_count += 1
                    continue
                api = None
                try:
                    payload = json.loads(decrypt_panel_password(encrypted_payload))
                    payload["enable"] = False
                    api = await _panel_api(panel)
                    await api.update_client(
                        int(service.external_id), subscription.external_client_id, payload
                    )
                    subscription.extra_data = {
                        **subscription.extra_data,
                        "client_payload_encrypted": encrypt_panel_password(
                            json.dumps(payload, separators=(",", ":"))
                        ),
                    }
                    managed = await session.scalar(
                        select(ManagedClient).where(
                            ManagedClient.service_id == service.id,
                            ManagedClient.external_identity == subscription.external_client_id,
                        )
                    )
                    if managed:
                        managed.is_enabled = False
                        managed.encrypted_payload = subscription.extra_data[
                            "client_payload_encrypted"
                        ]
                    subscription.status = "suspended"
                    disabled_count += 1
                except (PanelError, ValueError, RuntimeError, TypeError) as exc:
                    logger.warning(
                        "Could not suspend subscription %s (%s)",
                        subscription.id,
                        type(exc).__name__,
                    )
                    subscription.status = "suspension_failed"
                    failed_count += 1
                finally:
                    if api is not None:
                        await api.close()
        await _audit(
            session,
            callback.from_user.id,
            "customer.status_changed",
            "customer",
            customer.id,
            {"status": customer.status},
        )
        await session.commit()
    if customer.status == "blocked":
        await callback.message.answer(
            f"حساب مسدود شد. سرویس‌های غیرفعال‌شده: {disabled_count}؛ نیازمند بررسی دستی: {failed_count}."
        )
    else:
        await callback.message.answer(
            "حساب فعال شد. اشتراک‌های قبلاً تعلیق‌شده به‌صورت خودکار فعال نمی‌شوند؛ برای جلوگیری از فعال‌سازی ناخواسته باید جداگانه بررسی شوند."
        )


@router.callback_query(F.data.startswith("cust:restore:"))
async def customer_restore_subscriptions(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "customer_write"):
        return
    customer_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    restored = 0
    skipped = 0
    async with AsyncSessionFactory() as session:
        customer = await session.get(Customer, customer_id)
        if customer is None or customer.status != "active":
            await callback.message.answer("ابتدا باید حساب مشتری فعال باشد.")
            return
        subscriptions = (
            await session.scalars(
                select(Subscription).where(
                    Subscription.customer_id == customer.id,
                    Subscription.status.in_(["suspended", "suspension_failed"]),
                )
            )
        ).all()
        for subscription in subscriptions:
            expiry = subscription.expires_at
            if expiry and expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=UTC)
            if expiry and expiry <= datetime.now(UTC):
                subscription.status = "expired"
                skipped += 1
                continue
            service = await session.get(VPNService, subscription.service_id)
            panel = await session.get(Panel, service.panel_id) if service else None
            encrypted = (subscription.extra_data or {}).get("client_payload_encrypted")
            if (
                not service
                or not service.is_active
                or not panel
                or not panel.is_active
                or not encrypted
            ):
                skipped += 1
                continue
            api = None
            try:
                payload = json.loads(decrypt_panel_password(encrypted))
                payload["enable"] = True
                api = await _panel_api(panel)
                await api.update_client(
                    int(service.external_id), subscription.external_client_id, payload
                )
                subscription.extra_data = {
                    **subscription.extra_data,
                    "client_payload_encrypted": encrypt_panel_password(
                        json.dumps(payload, separators=(",", ":"))
                    ),
                }
                subscription.status = "active"
                managed = await session.scalar(
                    select(ManagedClient).where(
                        ManagedClient.service_id == service.id,
                        ManagedClient.external_identity == subscription.external_client_id,
                    )
                )
                if managed:
                    managed.is_enabled = True
                    managed.encrypted_payload = subscription.extra_data["client_payload_encrypted"]
                restored += 1
            except (PanelError, ValueError, RuntimeError, TypeError) as exc:
                logger.warning(
                    "Could not restore subscription %s (%s)",
                    subscription.id,
                    type(exc).__name__,
                )
                skipped += 1
            finally:
                if api is not None:
                    await api.close()
        await _audit(
            session,
            callback.from_user.id,
            "customer.subscriptions_restored",
            "customer",
            customer.id,
            {"restored": restored, "skipped": skipped},
        )
        await session.commit()
    await callback.message.answer(
        f"فعال‌سازی مجدد تمام شد. موفق: {restored}؛ نیازمند بررسی/منقضی: {skipped}."
    )


@router.callback_query(F.data.startswith("cust:walletadjust:"))
async def customer_wallet_adjust_start(callback: CallbackQuery, state: FSMContext) -> None:
    if not await _answer_admin(callback, "wallet"):
        return
    customer_id = callback.data.rsplit(":", 1)[1]
    await state.clear()
    await state.update_data(customer_id=customer_id)
    await state.set_state(WalletAdjust.amount)
    await _state_prompt(
        callback.message,
        state,
        "مبلغ اصلاح موجودی را با علامت وارد کنید؛ مثال +500000 برای افزایش یا -200000 برای کسر (ریال):",
    )


@router.message(WalletAdjust.amount)
async def customer_wallet_adjust_amount(message: Message, state: FSMContext) -> None:
    if not await _message_can(message, "wallet"):
        await state.clear()
        return
    try:
        amount = Decimal((message.text or "").strip().replace(",", ""))
        if amount == 0 or abs(amount) > Decimal(1000000000000):
            raise ValueError
    except (InvalidOperation, ValueError):
        await _state_prompt(
            message, state, "مبلغ غیرصفر و معتبر وارد کنید؛ افزایش با + و کسر با -:"
        )
        return
    await state.update_data(amount=str(amount))
    await state.set_state(WalletAdjust.description)
    await _state_prompt(message, state, "علت اصلاح موجودی را وارد کنید (در دفتر مالی ثبت می‌شود):")


@router.message(WalletAdjust.description)
async def customer_wallet_adjust_finish(message: Message, state: FSMContext) -> None:
    if not await _message_can(message, "wallet"):
        await state.clear()
        return
    data = await state.get_data()
    description = (message.text or "").strip()
    if len(description) < 3:
        await _state_prompt(message, state, "توضیح حداقل باید 3 نویسه باشد:")
        return
    amount = Decimal(data["amount"])
    try:
        async with AsyncSessionFactory() as session:
            customer = await session.get(Customer, uuid.UUID(data["customer_id"]))
            if customer is None:
                raise ValueError("کاربر پیدا نشد.")
            await post_wallet_entry(
                session,
                customer_id=customer.id,
                amount=amount,
                entry_type="admin_credit" if amount > 0 else "admin_debit",
                idempotency_key=f"admin-adjust:{message.from_user.id}:{uuid.uuid4().hex}",
                description=description,
                reference=f"admin:{message.from_user.id}",
            )
            await _audit(
                session,
                message.from_user.id,
                "wallet.admin_adjustment",
                "customer",
                customer.id,
                {"amount": str(amount), "description": description},
            )
            await session.commit()
            telegram_id = customer.telegram_id
            balance = await wallet_balance(session, customer.id)
        await state.clear()
        await message.answer(
            f"✅ دفتر کیف پول اصلاح شد.\nتغییر: {_price(abs(amount), 'IRR')} {'افزایش' if amount > 0 else 'کسر'}\nموجودی جدید: {_price(balance, 'IRR')}"
        )
        if telegram_id:
            await _notify_customer(
                message.bot,
                telegram_id,
                f"مبلغ {_price(abs(amount), 'IRR')} توسط مدیریت از کیف پول شما {'افزوده' if amount > 0 else 'کسر'} شد.",
            )
    except ValueError as exc:
        await message.answer(f"❌ اصلاح موجودی انجام نشد: {str(exc)[:180]}")
        await state.clear()


@router.callback_query(F.data == "adm:plans")
async def admin_plans(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "plans"):
        return
    async with AsyncSessionFactory() as session:
        plans = (
            await session.scalars(select(ProductPlan).order_by(ProductPlan.created_at.desc()))
        ).all()
    rows = [[("➕ ساخت پلن جدید", "plan:add")]]
    for plan in plans:
        rows.append(
            [
                (
                    f"{'🟢' if plan.is_active else '🔴'} {plan.name} · {_price(Decimal(plan.price), plan.currency)}",
                    f"plan:show:{plan.id}",
                )
            ]
        )
    rows.append([("↩️ بازگشت", "adm:home")])
    await callback.message.edit_text(
        "📦 پلن‌های فروش (برای مدیریت/ویرایش روی پلن بزنید)", reply_markup=_kb(rows)
    )


@router.callback_query(F.data.startswith("plan:show:"))
async def plan_show(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "plans"):
        return
    plan_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    async with AsyncSessionFactory() as session:
        plan = await session.get(ProductPlan, plan_id)
        service = await session.get(VPNService, plan.service_id) if plan else None
    if plan is None:
        await callback.message.answer("پلن پیدا نشد.")
        return
    device_note = (
        "\nتوجه: تعداد slot/config در این پروتکل از userLimit اینباند می‌آید، نه limitIp پلن."
        if service and service.protocol in {"wg-c", "awg", "gre"}
        else ""
    )
    await callback.message.edit_text(
        f"📦 {plan.name}\nسرویس: {service.name if service else '-'}\nمدت: {plan.duration_days} روز\nحجم: {plan.traffic_limit_bytes / 1024**3:.2f} GB\nحداکثر IP هم‌زمان (limitIp): {plan.device_limit or 'نامحدود'}\nقیمت: {_price(Decimal(plan.price), plan.currency)}\nوضعیت: {'فعال' if plan.is_active else 'غیرفعال'}{device_note}",
        reply_markup=_kb(
            [
                [("✏️ ویرایش پلن", f"plan:edit:{plan.id}")],
                [("🔁 فعال/غیرفعال", f"plan:toggle:{plan.id}")],
                [("↩️ بازگشت", "adm:plans")],
            ]
        ),
    )


@router.callback_query(F.data.startswith("plan:edit:"))
async def plan_edit_start(callback: CallbackQuery, state: FSMContext) -> None:
    if not await _answer_admin(callback, "plans"):
        return
    plan_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    async with AsyncSessionFactory() as session:
        plan = await session.get(ProductPlan, plan_id)
    if plan is None:
        await callback.message.answer("پلن پیدا نشد.")
        return
    await state.clear()
    await state.update_data(plan_id=str(plan.id))
    await state.set_state(PlanEdit.name)
    await _state_prompt(callback.message, state, f"نام جدید پلن (فعلی: {plan.name}):")


@router.message(PlanEdit.name)
async def plan_edit_name(message: Message, state: FSMContext) -> None:
    name = (message.text or "").strip()
    if not name:
        await _state_prompt(message, state, "نام نمی‌تواند خالی باشد:")
        return
    await state.update_data(name=name[:120])
    await state.set_state(PlanEdit.days)
    await _state_prompt(message, state, "مدت جدید به روز (1 تا 3650):")


@router.message(PlanEdit.days)
async def plan_edit_days(message: Message, state: FSMContext) -> None:
    try:
        days = int((message.text or "").strip())
        if not 1 <= days <= 3650:
            raise ValueError
    except ValueError:
        await _state_prompt(message, state, "عدد بین 1 تا 3650 وارد کنید:")
        return
    await state.update_data(days=days)
    await state.set_state(PlanEdit.traffic_gb)
    await _state_prompt(message, state, "حجم جدید به GB (0 = نامحدود):")


@router.message(PlanEdit.traffic_gb)
async def plan_edit_traffic(message: Message, state: FSMContext) -> None:
    try:
        gb = Decimal((message.text or "").strip().replace(",", "."))
        if gb < 0 or gb > Decimal(100000):
            raise ValueError
    except (InvalidOperation, ValueError):
        await _state_prompt(message, state, "حجم معتبر وارد کنید:")
        return
    await state.update_data(traffic_limit_bytes=int(gb * Decimal(1024**3)))
    await state.set_state(PlanEdit.devices)
    await _state_prompt(message, state, "حداکثر IP/اتصال هم‌زمان (limitIp؛ 0 = نامحدود):")


@router.message(PlanEdit.devices)
async def plan_edit_devices(message: Message, state: FSMContext) -> None:
    try:
        devices = int((message.text or "").strip())
        if not 0 <= devices <= 64:
            raise ValueError
    except ValueError:
        await _state_prompt(message, state, "عدد بین 0 تا 64 وارد کنید:")
        return
    await state.update_data(devices=devices)
    await state.set_state(PlanEdit.price)
    await _state_prompt(message, state, "قیمت جدید به ریال:")


@router.message(PlanEdit.price)
async def plan_edit_price(message: Message, state: FSMContext) -> None:
    if not await _message_can(message, "plans"):
        await state.clear()
        return
    data = await state.get_data()
    try:
        price = Decimal((message.text or "").strip().replace(",", ""))
        if price <= 0 or price > Decimal(999999999999999):
            raise ValueError
        async with AsyncSessionFactory() as session:
            plan = await session.get(ProductPlan, uuid.UUID(data["plan_id"]))
            if plan is None:
                raise ValueError("پلن پیدا نشد.")
            plan.name = data["name"]
            plan.duration_days = data["days"]
            plan.traffic_limit_bytes = data["traffic_limit_bytes"]
            plan.device_limit = data["devices"]
            plan.price = price
            await _audit(session, message.from_user.id, "plan.updated", "plan", plan.id)
            await session.commit()
        await message.answer("✅ پلن به‌روزرسانی شد.")
    except (InvalidOperation, ValueError) as exc:
        await _state_prompt(
            message, state, f"مقادیر معتبر نیست: {str(exc)[:150]}\nدوباره قیمت را وارد کنید:"
        )
        return
    await state.clear()


@router.callback_query(F.data == "plan:add")
async def plan_add_start(callback: CallbackQuery, state: FSMContext) -> None:
    if not await _answer_admin(callback, "plans"):
        return
    async with AsyncSessionFactory() as session:
        services = (
            await session.scalars(select(VPNService).where(VPNService.is_active.is_(True)))
        ).all()
    rows = [
        [(f"{service.name} · {service.protocol}", f"plan:service:{service.id}")]
        for service in services
    ]
    rows.append([("↩️ بازگشت", "adm:plans")])
    if not services:
        await callback.message.answer("ابتدا یک پنل را اضافه و اینباندهای فعال آن را Sync کنید.")
        return
    await callback.message.edit_text("پلن روی کدام سرویس ساخته شود؟", reply_markup=_kb(rows))


@router.callback_query(F.data.startswith("plan:service:"))
async def plan_add_service(callback: CallbackQuery, state: FSMContext) -> None:
    if not await _answer_admin(callback, "plans"):
        return
    await state.clear()
    await state.update_data(service_id=callback.data.rsplit(":", 1)[1])
    await state.set_state(PlanAdd.name)
    await _state_prompt(callback.message, state, "نام پلن:")


@router.message(PlanAdd.name)
async def plan_add_name(message: Message, state: FSMContext) -> None:
    await state.update_data(name=(message.text or "").strip()[:120])
    await state.set_state(PlanAdd.days)
    await _state_prompt(message, state, "مدت اعتبار به روز (عدد صحیح مثبت):")


@router.message(PlanAdd.days)
async def plan_add_days(message: Message, state: FSMContext) -> None:
    try:
        days = int((message.text or "").strip())
        if days <= 0 or days > 3650:
            raise ValueError
    except ValueError:
        await _state_prompt(message, state, "عدد معتبر بین 1 تا 3650 وارد کنید:")
        return
    await state.update_data(days=days)
    await state.set_state(PlanAdd.traffic_gb)
    await _state_prompt(message, state, "حجم به GB (برای نامحدود عدد 0):")


@router.message(PlanAdd.traffic_gb)
async def plan_add_traffic(message: Message, state: FSMContext) -> None:
    try:
        gb = Decimal((message.text or "").strip().replace(",", "."))
        if gb < 0 or gb > Decimal(100000):
            raise ValueError
    except (InvalidOperation, ValueError):
        await _state_prompt(message, state, "حجم نامعتبر است؛ یک عدد صفر یا بیشتر وارد کنید:")
        return
    bytes_limit = int(gb * Decimal(1024**3))
    await state.update_data(traffic_limit_bytes=bytes_limit)
    await state.set_state(PlanAdd.devices)
    await _state_prompt(message, state, "حداکثر IP/اتصال هم‌زمان (limitIp؛ 0 یعنی نامحدود):")


@router.message(PlanAdd.devices)
async def plan_add_devices(message: Message, state: FSMContext) -> None:
    try:
        devices = int((message.text or "").strip())
        if not 0 <= devices <= 64:
            raise ValueError
    except ValueError:
        await _state_prompt(message, state, "عدد بین 0 تا 64 وارد کنید:")
        return
    await state.update_data(devices=devices)
    await state.set_state(PlanAdd.price)
    await _state_prompt(message, state, "قیمت به ریال (عدد صحیح):")


@router.message(PlanAdd.price)
async def plan_add_price(message: Message, state: FSMContext) -> None:
    if not await _message_can(message, "plans"):
        await state.clear()
        return
    data = await state.get_data()
    try:
        price = Decimal((message.text or "").strip().replace(",", ""))
        if price <= 0 or price > Decimal(999999999999999):
            raise ValueError
        async with AsyncSessionFactory() as session:
            service = await session.get(VPNService, uuid.UUID(data["service_id"]))
            if service is None or not service.is_active:
                raise ValueError("سرویس انتخاب‌شده غیرفعال شده است.")
            plan = ProductPlan(
                service_id=service.id,
                name=data["name"],
                duration_days=data["days"],
                traffic_limit_bytes=data["traffic_limit_bytes"],
                device_limit=data["devices"],
                price=price,
                currency="IRR",
                is_active=True,
            )
            session.add(plan)
            await _audit(session, message.from_user.id, "plan.created", "plan", plan.id)
            await session.commit()
        await message.answer("✅ پلن ساخته شد و در فروشگاه نمایش داده می‌شود.")
    except (InvalidOperation, ValueError) as exc:
        await _state_prompt(
            message, state, f"قیمت/سرویس معتبر نیست: {str(exc)[:160]}\nدوباره قیمت را وارد کنید:"
        )
        return
    finally:
        if not message.text:
            await state.clear()
    await state.clear()


@router.callback_query(F.data.startswith("plan:toggle:"))
async def plan_toggle(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "plans"):
        return
    plan_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    async with AsyncSessionFactory() as session:
        plan = await session.get(ProductPlan, plan_id)
        if plan is None:
            await callback.message.answer("پلن پیدا نشد.")
            return
        service = await session.get(VPNService, plan.service_id)
        plan.is_active = not plan.is_active and bool(service and service.is_active)
        await _audit(
            session,
            callback.from_user.id,
            "plan.toggled",
            "plan",
            plan.id,
            {"active": plan.is_active},
        )
        await session.commit()
    await callback.message.answer("وضعیت پلن ذخیره شد.")


@router.callback_query(F.data == "adm:orders")
async def admin_orders(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "orders"):
        return
    async with AsyncSessionFactory() as session:
        orders = (
            await session.scalars(
                select(Order)
                .where(
                    Order.status.in_(
                        ["pending_payment", "fulfillment_failed", "paid", "processing"]
                    )
                )
                .order_by(Order.created_at.desc())
                .limit(20)
            )
        ).all()
    rows = []
    for order in orders:
        rows.append(
            [
                (
                    f"{order.status} · {_price(Decimal(order.amount), order.currency)} · {str(order.id)[:8]}",
                    f"order:view:{order.id}",
                )
            ]
        )
    rows.append([("↩️ بازگشت", "adm:home")])
    await callback.message.edit_text("🧾 سفارش‌های نیازمند بررسی / تکمیل", reply_markup=_kb(rows))


@router.callback_query(F.data.startswith("order:view:"))
async def order_view(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "orders"):
        return
    order_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    async with AsyncSessionFactory() as session:
        order = await session.get(Order, order_id)
        payment = await session.scalar(
            select(Payment).where(Payment.order_id == order_id, Payment.provider == "manual")
        )
        customer = await session.get(Customer, order.customer_id) if order else None
        plan = await session.get(ProductPlan, order.plan_id) if order and order.plan_id else None
    if order is None:
        await callback.message.answer("سفارش پیدا نشد.")
        return
    receipt_id = (payment.extra_data or {}).get("receipt_file_id") if payment else None
    rows = []
    if order.status == "pending_payment" and payment and receipt_id:
        rows.append([("✅ تأیید پرداخت و اجرای سرویس", f"order:approve:{order.id}")])
        rows.append([("❌ رد پرداخت", f"order:reject:{order.id}")])
    if order.status in {"paid", "processing", "fulfillment_failed"}:
        rows.append([("🔁 بازیابی / تلاش مجدد ساخت سرویس", f"order:retry:{order.id}")])
    rows.append([("↩️ بازگشت", "adm:orders")])
    details = (
        f"سفارش: {order.id}\nنوع: {order.order_type}\nوضعیت: {order.status}\n"
        f"مبلغ: {_price(Decimal(order.amount), order.currency)}\n"
        f"مشتری: {customer.full_name if customer else '-'} ({customer.telegram_id if customer else '-'})\n"
        f"پلن: {plan.name if plan else '-'}\n"
        f"وضعیت پرداخت: {payment.status if payment else 'wallet'}\n"
        f"رسید: {'دریافت شده' if receipt_id else 'ثبت نشده'}"
    )
    await callback.message.edit_text(details, reply_markup=_kb(rows))
    if receipt_id:
        await callback.message.answer_photo(receipt_id, caption=f"رسید سفارش {str(order.id)[:8]}")


@router.callback_query(F.data.startswith("order:approve:"))
async def order_approve(callback: CallbackQuery, bot: Bot) -> None:
    if not await _answer_admin(callback, "orders"):
        return
    order_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    result = await _approve_order(bot, order_id, callback.from_user.id)
    await callback.message.edit_text(
        result,
        reply_markup=_kb([[("↩️ بازگشت به سفارش‌ها", "adm:orders")]]),
    )


@router.callback_query(F.data.startswith("order:reject:"))
async def order_reject(callback: CallbackQuery, bot: Bot) -> None:
    if not await _answer_admin(callback, "orders"):
        return
    order_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    async with AsyncSessionFactory() as session:
        order = await session.get(Order, order_id)
        payment = await session.scalar(
            select(Payment).where(Payment.order_id == order_id, Payment.provider == "manual")
        )
        if (
            order is None
            or payment is None
            or payment.status != "pending"
            or order.status != "pending_payment"
        ):
            await callback.message.answer("این پرداخت در وضعیت قابل رد نیست.")
            return
        claimed_order = await session.execute(
            update(Order)
            .where(Order.id == order_id, Order.status == "pending_payment")
            .values(status="rejected")
        )
        claimed_payment = await session.execute(
            update(Payment)
            .where(
                Payment.order_id == order_id,
                Payment.provider == "manual",
                Payment.status == "pending",
            )
            .values(status="rejected")
        )
        if claimed_order.rowcount != 1 or claimed_payment.rowcount != 1:
            await session.rollback()
            await callback.message.answer("این سفارش هم‌زمان توسط مدیر دیگری بررسی شده است.")
            return
        await _audit(session, callback.from_user.id, "payment.rejected", "order", order.id)
        customer = await session.get(Customer, order.customer_id)
        await session.commit()
    if customer and customer.telegram_id:
        await _notify_customer(
            bot,
            customer.telegram_id,
            f"❌ پرداخت سفارش {str(order_id)[:8]} رد شد. برای پیگیری با پشتیبانی تماس بگیرید.",
        )
    await callback.message.edit_text(
        "پرداخت رد شد.", reply_markup=_kb([[("↩️ بازگشت به سفارش‌ها", "adm:orders")]])
    )


@router.callback_query(F.data.startswith("order:retry:"))
async def order_retry(callback: CallbackQuery, bot: Bot) -> None:
    if not await _answer_admin(callback, "orders"):
        return
    order_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    result = await _retry_order(bot, order_id, callback.from_user.id)
    await callback.message.edit_text(
        result,
        reply_markup=_kb([[("↩️ بازگشت به سفارش‌ها", "adm:orders")]]),
    )


@router.callback_query(F.data.startswith("adm:admins"))
async def admin_admins(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "admins"):
        return
    try:
        page = max(0, int(callback.data.rsplit(":", 1)[1])) if callback.data != "adm:admins" else 0
    except ValueError:
        page = 0
    await _admin_admins_view(callback, page)


async def _admin_admins_view(callback: CallbackQuery, page: int = 0) -> None:
    page_size = 8
    async with AsyncSessionFactory() as session:
        total = await session.scalar(select(func.count(AdminUser.id))) or 0
        page = min(page, max(0, (total - 1) // page_size)) if total else 0
        admins = (
            await session.scalars(
                select(AdminUser)
                .order_by(AdminUser.telegram_id)
                .limit(page_size)
                .offset(page * page_size)
            )
        ).all()
    rows = [[("➕ افزودن مدیر", "admin:add")]]
    for admin in admins:
        root = admin.telegram_id in _root_admins()
        state_icon = (
            "🔐" if root else "👑" if admin.role == "owner" else "🟢" if admin.is_active else "🔴"
        )
        rows.append(
            [
                (
                    f"{state_icon} {admin.telegram_id} · {_admin_role_label(admin)}",
                    f"admin:view:{admin.id}",
                )
            ]
        )
    navigation = []
    if page > 0:
        navigation.append(("⬅️ قبلی", f"adm:admins:{page - 1}"))
    if (page + 1) * page_size < total:
        navigation.append(("بعدی ➡️", f"adm:admins:{page + 1}"))
    if navigation:
        rows.append(navigation)
    rows.append([("↩️ بازگشت", "adm:home")])
    await callback.message.edit_text(
        f"🛡 مدیریت مدیران · {total} حساب · صفحه {page + 1}/{max(1, (total + page_size - 1) // page_size)}\nبرای دیدن جزئیات، تغییر مجوزها یا ارتقا به سوپرادمین، حساب موردنظر را انتخاب کنید.\n🔐 مالک اصلی محیطی · 👑 سوپرادمین دائمی",
        reply_markup=_kb(rows),
    )


def _admin_role_label(admin: AdminUser) -> str:
    if admin.role == "owner":
        return "مالک اصلی" if admin.telegram_id in _root_admins() else "سوپرادمین"
    permissions = (admin.extra_data or {}).get("permissions")
    if isinstance(permissions, list):
        return f"اختصاصی · {len(set(permissions) & _permission_areas())} مجوز"
    return {"admin": "مدیر عملیات", "finance": "مدیر مالی", "support": "پشتیبانی"}.get(
        admin.role, admin.role
    )


@router.callback_query(F.data.startswith("admin:view:"))
async def admin_view(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "admins"):
        return
    admin_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    await admin_view_render(callback, admin_id)


async def admin_view_render(callback: CallbackQuery, admin_id: uuid.UUID) -> None:
    async with AsyncSessionFactory() as session:
        admin = await session.get(AdminUser, admin_id)
        if admin is None:
            await callback.message.answer("مدیر پیدا نشد.")
            return
        permissions = (admin.extra_data or {}).get("permissions")
        allowed = set(permissions) if isinstance(permissions, list) else None
        is_environment_owner = admin.telegram_id in _root_admins()
        is_database_owner = admin.role == "owner" and not is_environment_owner
        rows = []
        labels = {
            "panels": "پنل‌ها و سرویس‌ها",
            "customers": "مشاهده کاربران",
            "customer_write": "تغییر وضعیت کاربران",
            "plans": "پلن‌ها",
            "orders": "سفارش و پرداخت",
            "settings": "تنظیمات فروش",
            "stats": "آمار",
            "wallet": "کیف پول",
            "audit": "گزارش فعالیت مدیران",
        }
        if is_environment_owner:
            rows.append([("🔐 مالک اصلی؛ دسترسی از تنظیمات امن سرور می‌آید", "adm:admins")])
        elif is_database_owner:
            rows.append([("⬇️ تنزل به مدیر عملیات", f"admin:demote:{admin.id}")])
        elif allowed is None:
            rows.append([("استفاده از دسترسی پیش‌فرض نقش", f"admin:permreset:{admin.id}")])
            rows.append([("ساخت دسترسی اختصاصی از نقش فعلی", f"admin:permscustom:{admin.id}")])
            rows.append([("⭐ ارتقا به سوپرادمین کامل", f"admin:promote:{admin.id}")])
        else:
            for area, label in labels.items():
                rows.append(
                    [
                        (
                            f"{'✅' if area in allowed else '⬜'} {label}",
                            f"admin:perm:{admin.id}:{area}",
                        )
                    ]
                )
            rows.append([("بازگشت به دسترسی پیش‌فرض نقش", f"admin:permreset:{admin.id}")])
            rows.append([("⭐ ارتقا به سوپرادمین کامل", f"admin:promote:{admin.id}")])
        if not is_environment_owner and not is_database_owner:
            rows.append([("🔴/🟢 تغییر وضعیت مدیر", f"admin:toggle:{admin.id}")])
        rows.append([("↩️ بازگشت به مدیران", "adm:admins")])
        role_title = _admin_role_label(admin)
        await callback.message.edit_text(
            f"👤 مدیر: {admin.telegram_id}\nسطح دسترسی: {role_title}\nوضعیت: {'فعال' if admin.is_active else 'غیرفعال'}\n"
            f"مجوزها: {'تمام دسترسی‌ها' if admin.role == 'owner' else 'اختصاصی' if allowed is not None else 'پیش‌فرض نقش'}",
            reply_markup=_kb(rows),
        )


@router.callback_query(F.data.startswith("admin:promote:"))
async def admin_promote_confirm_start(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "admins"):
        return
    admin_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    async with AsyncSessionFactory() as session:
        admin = await session.get(AdminUser, admin_id)
        if admin is None or admin.telegram_id in _root_admins() or admin.role == "owner":
            await callback.message.answer("این حساب قابل ارتقا نیست یا از قبل سوپرادمین است.")
            return
        telegram_id = admin.telegram_id
    await callback.message.edit_text(
        f"⚠️ ارتقای کاربر {telegram_id} به سوپرادمین کامل\n\nاین کار تمام دسترسی‌ها، از جمله مدیریت مدیران و کیف پول را به او می‌دهد. این دسترسی پس از راه‌اندازی مجدد ربات هم باقی می‌ماند.\n\nآیا ادامه می‌دهید؟",
        reply_markup=_kb(
            [
                [("✅ بله، سوپرادمین شود", f"admin:promote-confirm:{admin_id}")],
                [("لغو", f"admin:view:{admin_id}")],
            ]
        ),
    )


@router.callback_query(F.data.startswith("admin:promote-confirm:"))
async def admin_promote_confirm(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "admins"):
        return
    admin_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    async with AsyncSessionFactory() as session:
        admin = await session.get(AdminUser, admin_id)
        if admin is None or admin.telegram_id in _root_admins() or admin.role == "owner":
            await callback.message.answer("این حساب دیگر قابل ارتقا نیست.")
            return
        admin.role = "owner"
        admin.is_active = True
        admin.extra_data = {
            key: value
            for key, value in (admin.extra_data or {}).items()
            if key not in {"permissions", "super_admin_source"}
        }
        admin.extra_data["super_admin_source"] = "database"
        await _audit(
            session,
            callback.from_user.id,
            "admin.super_admin_granted",
            "admin",
            admin.id,
            {"telegram_id": admin.telegram_id, "source": "database"},
        )
        await session.commit()
    await admin_view_render(callback, admin_id)


@router.callback_query(F.data.startswith("admin:demote:"))
async def admin_demote_confirm_start(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "admins"):
        return
    admin_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    async with AsyncSessionFactory() as session:
        admin = await session.get(AdminUser, admin_id)
        if (
            admin is None
            or admin.telegram_id in _root_admins()
            or admin.role != "owner"
            or admin.telegram_id == callback.from_user.id
        ):
            await callback.message.answer(
                "این سوپرادمین قابل تنزل نیست. برای جلوگیری از قفل‌شدن دسترسی، تنزل خودتان از این مسیر مجاز نیست."
            )
            return
        telegram_id = admin.telegram_id
    await callback.message.edit_text(
        f"⚠️ تنزل سوپرادمین {telegram_id} به مدیر عملیات\n\nدسترسی کامل او حذف می‌شود و فقط مجوزهای پایه مدیر عملیات را خواهد داشت.\n\nتأیید می‌کنید؟",
        reply_markup=_kb(
            [
                [("✅ تأیید تنزل دسترسی", f"admin:demote-confirm:{admin_id}")],
                [("لغو", f"admin:view:{admin_id}")],
            ]
        ),
    )


@router.callback_query(F.data.startswith("admin:demote-confirm:"))
async def admin_demote_confirm(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "admins"):
        return
    admin_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    async with AsyncSessionFactory() as session:
        admin = await session.get(AdminUser, admin_id)
        if (
            admin is None
            or admin.telegram_id in _root_admins()
            or admin.role != "owner"
            or admin.telegram_id == callback.from_user.id
        ):
            await callback.message.answer("این عملیات مجاز نیست یا حساب دیگر سوپرادمین نیست.")
            return
        database_owners = set(
            (
                await session.scalars(
                    select(AdminUser.telegram_id).where(
                        AdminUser.role == "owner", AdminUser.is_active.is_(True)
                    )
                )
            ).all()
        )
        remaining = set(_root_admins()) | (database_owners - {admin.telegram_id})
        if not remaining:
            await callback.message.answer("تنزل آخرین سوپرادمین مجاز نیست.")
            return
        target_id = admin.telegram_id
        admin.role = "admin"
        admin.is_active = True
        admin.extra_data = {
            key: value
            for key, value in (admin.extra_data or {}).items()
            if key not in {"permissions", "super_admin_source"}
        }
        await _audit(
            session,
            callback.from_user.id,
            "admin.super_admin_revoked",
            "admin",
            admin.id,
            {"telegram_id": target_id},
        )
        await session.commit()
    await admin_view_render(callback, admin_id)


@router.callback_query(F.data.startswith("admin:permscustom:"))
async def admin_permissions_custom(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "admins"):
        return
    admin_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    async with AsyncSessionFactory() as session:
        admin = await session.get(AdminUser, admin_id)
        if admin is None or admin.telegram_id in _root_admins() or admin.role == "owner":
            await callback.message.answer("مدیر معتبر نیست.")
            return
        current = _role_default_permissions(admin.role)
        admin.extra_data = {**(admin.extra_data or {}), "permissions": sorted(current)}
        await _audit(
            session, callback.from_user.id, "admin.permissions_customized", "admin", admin.id
        )
        await session.commit()
    await admin_view_render(callback, admin_id)


def _role_default_permissions(role: str) -> set[str]:
    defaults = {
        "admin": {"panels", "customers", "customer_write", "plans", "orders", "stats", "wallet"},
        "finance": {"customers", "orders", "settings", "stats", "wallet"},
        "support": {"customers", "stats"},
    }
    return set(defaults.get(role, set()))


@router.callback_query(F.data.startswith("admin:permreset:"))
async def admin_permissions_reset(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "admins"):
        return
    admin_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    async with AsyncSessionFactory() as session:
        admin = await session.get(AdminUser, admin_id)
        if admin is None or admin.telegram_id in _root_admins() or admin.role == "owner":
            await callback.message.answer("مدیر معتبر نیست.")
            return
        admin.extra_data = {k: v for k, v in (admin.extra_data or {}).items() if k != "permissions"}
        await _audit(session, callback.from_user.id, "admin.permissions_reset", "admin", admin.id)
        await session.commit()
    await admin_view_render(callback, admin_id)


@router.callback_query(F.data.startswith("admin:perm:"))
async def admin_permission_toggle(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "admins"):
        return
    _, _, raw_id, area = callback.data.split(":", 3)
    if area not in _permission_areas():
        await callback.message.answer("مجوز نامعتبر است.")
        return
    admin_id = uuid.UUID(raw_id)
    async with AsyncSessionFactory() as session:
        admin = await session.get(AdminUser, admin_id)
        if admin is None or admin.telegram_id in _root_admins() or admin.role == "owner":
            await callback.message.answer("مدیر معتبر نیست.")
            return
        permissions = (admin.extra_data or {}).get("permissions")
        if not isinstance(permissions, list):
            permissions = sorted(_role_default_permissions(admin.role))
        allowed = set(permissions)
        if area in allowed:
            allowed.remove(area)
        else:
            allowed.add(area)
        admin.extra_data = {**(admin.extra_data or {}), "permissions": sorted(allowed)}
        await _audit(
            session,
            callback.from_user.id,
            "admin.permission_toggled",
            "admin",
            admin.id,
            {"area": area, "enabled": area in allowed},
        )
        await session.commit()
    await admin_view_render(callback, admin_id)


@router.callback_query(F.data == "admin:add")
async def admin_add_start(callback: CallbackQuery, state: FSMContext) -> None:
    if not await _answer_admin(callback, "admins"):
        return
    await state.clear()
    await state.set_state(AdminAdd.telegram_id)
    await _state_prompt(callback.message, state, "Telegram numeric ID مدیر جدید را بفرستید:")


@router.message(AdminAdd.telegram_id)
async def admin_add_id(message: Message, state: FSMContext) -> None:
    if not await _message_can(message, "admins"):
        await state.clear()
        return
    value = (message.text or "").strip()
    if not value.isdigit() or int(value) <= 0 or int(value) in _root_admins():
        await _state_prompt(
            message,
            state,
            "شناسه باید عدد مثبت باشد و نباید مالک اصلی باشد. دوباره بفرستید:",
        )
        return
    await state.update_data(telegram_id=int(value))
    await state.set_state(AdminAdd.role)
    await _state_prompt(
        message,
        state,
        "نقش مدیر را انتخاب کنید:",
        reply_markup=_kb(
            [
                [("مدیر عملیات", "adminrole:admin"), ("مالی", "adminrole:finance")],
                [("پشتیبانی", "adminrole:support")],
            ]
        ),
    )


@router.callback_query(F.data.startswith("adminrole:"))
async def admin_add_role(callback: CallbackQuery, state: FSMContext) -> None:
    if not await _answer_admin(callback, "admins"):
        return
    role = callback.data.split(":", 1)[1]
    if role not in {"admin", "finance", "support"}:
        await callback.message.answer("نقش نامعتبر است.")
        return
    data = await state.get_data()
    async with AsyncSessionFactory() as session:
        admin = await session.scalar(
            select(AdminUser).where(AdminUser.telegram_id == data["telegram_id"])
        )
        if admin is None:
            session.add(
                AdminUser(
                    telegram_id=data["telegram_id"],
                    role=role,
                    is_active=True,
                    added_by=callback.from_user.id,
                )
            )
        else:
            if admin.role == "owner":
                await callback.message.answer(
                    "این حساب سوپرادمین است. برای تنزل آن از دکمهٔ اختصاصی تنزل در صفحهٔ مدیر استفاده کنید."
                )
                await state.clear()
                return
            admin.role = role
            admin.is_active = True
            admin.extra_data = {
                key: value
                for key, value in (admin.extra_data or {}).items()
                if key != "permissions"
            }
        await _audit(
            session,
            callback.from_user.id,
            "admin.granted",
            "admin",
            details={"telegram_id": data["telegram_id"], "role": role},
        )
        await session.commit()
    await state.clear()
    await _admin_admins_view(callback)


@router.callback_query(F.data.startswith("admin:toggle:"))
async def admin_toggle(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "admins"):
        return
    admin_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    async with AsyncSessionFactory() as session:
        admin = await session.get(AdminUser, admin_id)
        if admin is None or admin.telegram_id in _root_admins() or admin.role == "owner":
            await callback.message.answer("این مدیر قابل غیرفعال‌سازی نیست.")
            return
        action = "فعال‌سازی" if not admin.is_active else "غیرفعال‌سازی"
        target_active = not admin.is_active
        telegram_id = admin.telegram_id
    await callback.message.edit_text(
        f"⚠️ {action} مدیر {telegram_id}\n\nبا این کار دسترسی مدیریتی این حساب {'برقرار' if target_active else 'قطع'} می‌شود.\nآیا تأیید می‌کنید؟",
        reply_markup=_kb(
            [
                [(f"✅ تأیید {action}", f"admin:toggle-confirm:{admin_id}")],
                [("لغو", f"admin:view:{admin_id}")],
            ]
        ),
    )


@router.callback_query(F.data.startswith("admin:toggle-confirm:"))
async def admin_toggle_confirm(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "admins"):
        return
    admin_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    async with AsyncSessionFactory() as session:
        admin = await session.get(AdminUser, admin_id)
        if admin is None or admin.telegram_id in _root_admins() or admin.role == "owner":
            await callback.message.answer("این مدیر قابل تغییر وضعیت نیست.")
            return
        admin.is_active = not admin.is_active
        await _audit(
            session,
            callback.from_user.id,
            "admin.status_changed",
            "admin",
            admin.id,
            {"active": admin.is_active},
        )
        await session.commit()
    await admin_view_render(callback, admin_id)


@router.callback_query(F.data == "adm:settings")
async def admin_settings(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "settings"):
        return
    async with AsyncSessionFactory() as session:
        instructions = await _setting(session, "payment_instructions", "تنظیم نشده")
    await callback.message.edit_text(
        f"⚙️ تنظیمات فروش\n\nاطلاعات پرداخت فعلی:\n{instructions}",
        reply_markup=_kb(
            [
                [("✏️ تنظیم/ویرایش اطلاعات پرداخت", "settings:payment")],
                [("↩️ بازگشت", "adm:home")],
            ]
        ),
    )


@router.callback_query(F.data == "settings:payment")
async def settings_payment_start(callback: CallbackQuery, state: FSMContext) -> None:
    if not await _answer_admin(callback, "settings"):
        return
    await state.clear()
    await state.set_state(StoreSettings.payment_instructions)
    await _state_prompt(
        callback.message,
        state,
        "متن کامل روش پرداخت را ارسال کنید (شماره کارت/شبا، نام صاحب حساب و توضیحات):",
    )


@router.message(StoreSettings.payment_instructions)
async def settings_payment_save(message: Message, state: FSMContext) -> None:
    if not await _message_can(message, "settings"):
        await state.clear()
        return
    text = (message.text or "").strip()
    if len(text) < 8:
        await _state_prompt(message, state, "متن خیلی کوتاه است؛ دوباره ارسال کنید:")
        return
    async with AsyncSessionFactory() as session:
        await _set_setting(session, "payment_instructions", text[:3000])
        await _audit(
            session, message.from_user.id, "store.payment_instructions_changed", "store_setting"
        )
        await session.commit()
    await state.clear()
    await message.answer("✅ اطلاعات پرداخت ذخیره شد.")


@router.callback_query(F.data == "adm:stats")
async def admin_stats(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "stats"):
        return
    async with AsyncSessionFactory() as session:
        customers = await session.scalar(select(func.count(Customer.id))) or 0
        active_subs = (
            await session.scalar(
                select(func.count(Subscription.id)).where(Subscription.status == "active")
            )
            or 0
        )
        orders = await session.scalar(select(func.count(Order.id))) or 0
        revenue = (
            await session.scalar(
                select(func.coalesce(func.sum(Payment.amount), 0)).where(Payment.status == "paid")
            )
            or 0
        )
        pending = (
            await session.scalar(
                select(func.count(Order.id)).where(Order.status == "pending_payment")
            )
            or 0
        )
    await callback.message.edit_text(
        f"📊 آمار فروش\nکاربران: {customers}\nاشتراک‌های فعال: {active_subs}\nکل سفارش‌ها: {orders}\nپرداخت‌های در انتظار: {pending}\nمجموع پرداخت تأییدشده: {_price(Decimal(revenue), 'IRR')}",
        reply_markup=_kb([[("↩️ بازگشت", "adm:home")]]),
    )


@router.callback_query(F.data == "adm:audit")
async def admin_audit(callback: CallbackQuery) -> None:
    if not await _answer_admin(callback, "audit"):
        return
    async with AsyncSessionFactory() as session:
        events = (
            await session.scalars(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(20))
        ).all()
    if not events:
        body = "هنوز رویدادی ثبت نشده است."
    else:
        lines = []
        for event in events:
            stamp = event.created_at.strftime("%Y-%m-%d %H:%M") if event.created_at else "-"
            details = json.dumps(event.details or {}, ensure_ascii=False, default=str)
            lines.append(
                f"{stamp} · {event.action}\nمدیر: {event.actor_telegram_id or '-'} · منبع: {event.resource_type}\nجزئیات: {details[:220]}"
            )
        body = "\n\n".join(lines)
    await callback.message.edit_text(
        f"📜 آخرین فعالیت‌های ثبت‌شده (حداکثر ۲۰ مورد)\n\n{body}",
        reply_markup=_kb([[("↩️ بازگشت", "adm:home")]]),
    )


@router.callback_query(F.data == "shop:plans")
async def shop_plans(callback: CallbackQuery) -> None:
    await callback.answer()
    async with AsyncSessionFactory() as session:
        plans = (
            await session.scalars(
                select(ProductPlan)
                .where(ProductPlan.is_active.is_(True))
                .order_by(ProductPlan.price)
            )
        ).all()
    rows = []
    for plan in plans:
        rows.append(
            [
                (
                    f"📦 {plan.name[:32]} · {_price(Decimal(plan.price), plan.currency)}",
                    f"shop:plan:{plan.id}",
                )
            ]
        )
    rows.append([("↩️ منوی اصلی", "home")])
    body = (
        "🛍 پلن‌های فعال فروشگاه\n\nبرای مشاهده جزئیات و انتخاب روش پرداخت، یک پلن را انتخاب کنید."
        if plans
        else "🛍 در حال حاضر پلن فعالی برای فروش وجود ندارد. لطفاً بعداً دوباره بررسی کنید."
    )
    await callback.message.edit_text(body, reply_markup=_kb(rows))


@router.callback_query(F.data.startswith("shop:plan:"))
async def shop_plan(callback: CallbackQuery) -> None:
    await callback.answer()
    plan_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    async with AsyncSessionFactory() as session:
        plan = await session.get(ProductPlan, plan_id)
        service = await session.get(VPNService, plan.service_id) if plan else None
    if plan is None or service is None or not plan.is_active or not service.is_active:
        await callback.message.answer("این پلن در حال حاضر در دسترس نیست.")
        return
    traffic = (
        "نامحدود"
        if not plan.traffic_limit_bytes
        else f"{plan.traffic_limit_bytes / 1024**3:.2f} GB"
    )
    device_note = (
        "\nتوجه: تعداد slot/config در این پروتکل از userLimit اینباند می‌آید، نه limitIp پلن."
        if service.protocol in {"wg-c", "awg", "gre"}
        else ""
    )
    description = f"\nتوضیحات: {plan.description[:400]}" if plan.description else ""
    await callback.message.edit_text(
        f"📦 جزئیات پلن: {plan.name}\n\n🌐 سرویس: {service.name}\n🔐 پروتکل: {service.protocol.upper()}\n⏳ مدت اعتبار: {plan.duration_days} روز\n📊 حجم: {traffic}\n📱 حداکثر IP هم‌زمان: {plan.device_limit or 'نامحدود'}\n💰 قیمت نهایی: {_price(Decimal(plan.price), plan.currency)}{description}{device_note}\n\nروش پرداخت را انتخاب کنید:",
        reply_markup=_kb(
            [
                [("💳 پرداخت کارت‌به‌کارت", f"shop:buy:{plan.id}")],
                [("👛 پرداخت از کیف پول", f"shop:walletbuy:{plan.id}")],
                [("↩️ بازگشت به پلن‌ها", "shop:plans")],
            ]
        ),
    )


async def _start_manual_payment(
    message: Message,
    *,
    plan: ProductPlan | None,
    customer: Customer,
    order_type: str,
    subscription_id=None,
    renewal: bool = False,
) -> None:
    async with AsyncSessionFactory() as session:
        instructions = await _setting(session, "payment_instructions", "")
        if not instructions:
            await message.answer("روش پرداخت هنوز توسط مدیر تنظیم نشده است. لطفاً بعداً تلاش کنید.")
            return
        order, _ = await create_manual_order(
            session,
            customer=customer,
            amount=Decimal(plan.price) if plan else Decimal(0),
            currency=plan.currency if plan else "IRR",
            order_type=order_type,
            description=f"خرید پلن {plan.name}" if plan else "شارژ کیف پول",
            plan_id=plan.id if plan else None,
            subscription_id=subscription_id,
        )
        if renewal:
            order.extra_data = {**(order.extra_data or {}), "renewal": True}
        await session.commit()
    await message.answer(
        f"🧾 سفارش شما ثبت شد.\n\nمبلغ: {_price(Decimal(order.amount), order.currency)}\n\n{instructions}\n\nپس از واریز، تصویر رسید را به‌صورت عکس ارسال کنید و کد کامل سفارش را در Caption قرار دهید. تا زمان تأیید مدیر، سرویس فعال نمی‌شود.",
        reply_markup=InlineKeyboardMarkup(
            inline_keyboard=[
                [
                    InlineKeyboardButton(
                        text="📋 کپی کد سفارش",
                        copy_text=CopyTextButton(text=str(order.id)),
                    )
                ],
                [InlineKeyboardButton(text="👤 مشخصات من", callback_data="shop:profile")],
            ]
        ),
    )


@router.callback_query(F.data.startswith("shop:buy:"))
async def shop_buy(callback: CallbackQuery) -> None:
    await callback.answer()
    if callback.from_user is None:
        return
    plan_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    async with AsyncSessionFactory() as session:
        customer = await get_or_create_customer(session, callback.from_user)
        plan = await session.get(ProductPlan, plan_id)
        await session.commit()
    if customer.status != "active" or plan is None or not plan.is_active:
        await callback.message.answer("امکان ثبت سفارش وجود ندارد.")
        return
    await _start_manual_payment(
        callback.message, plan=plan, customer=customer, order_type="subscription"
    )


@router.callback_query(F.data.startswith("shop:walletbuy:"))
async def shop_wallet_buy(callback: CallbackQuery, bot: Bot) -> None:
    await callback.answer()
    if callback.from_user is None:
        return
    plan_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    status_message = await callback.message.answer("⏳ در حال بررسی موجودی و ثبت خرید شما...")
    try:
        async with AsyncSessionFactory() as session:
            customer = await get_or_create_customer(session, callback.from_user)
            if customer.status != "active":
                raise ValueError("حساب کاربری شما غیرفعال است.")
            plan = await session.get(ProductPlan, plan_id)
            if plan is None or not plan.is_active:
                raise ValueError("پلن فعال نیست.")
            order = Order(
                customer_id=customer.id,
                plan_id=plan.id,
                order_type="subscription",
                amount=plan.price,
                currency=plan.currency,
                status="processing",
                description=f"خرید کیف پول: {plan.name}",
            )
            session.add(order)
            await session.flush()
            await post_wallet_entry(
                session,
                customer_id=customer.id,
                amount=-Decimal(plan.price),
                entry_type="purchase",
                idempotency_key=f"order:{order.id}:debit",
                description=f"خرید {plan.name}",
                reference=str(order.id),
            )
            await session.commit()
            await _edit_or_answer(
                status_message, "⚙️ پرداخت ثبت شد؛ در حال ساخت سرویس و آماده‌سازی کانفیگ..."
            )
            try:
                await bot.send_chat_action(callback.from_user.id, ChatAction.TYPING)
            except TelegramAPIError:
                pass
            try:
                subscription = await fulfill_subscription_order(session, order)
            except Exception:
                await post_wallet_entry(
                    session,
                    customer_id=customer.id,
                    amount=Decimal(plan.price),
                    entry_type="refund",
                    idempotency_key=f"order:{order.id}:refund",
                    description="بازگشت وجه به‌دلیل خطای ساخت سرویس",
                    reference=str(order.id),
                )
                order.status = "refunded"
                await session.commit()
                raise
            try:
                delivery = await _store_subscription_delivery(session, subscription)
                delivered = await _send_subscription_delivery(
                    bot,
                    callback.from_user.id,
                    delivery,
                    status_message=status_message,
                )
                if not delivered:
                    await _edit_or_answer(
                        status_message,
                        "✅ سرویس ساخته شد، اما ارسال همه فایل‌ها کامل نشد. از بخش «اشتراک‌های من» دوباره کانفیگ را دریافت کنید.",
                        reply_markup=_kb([[("📦 اشتراک‌های من", "shop:subs")]]),
                    )
            except (ValueError, KeyError, TypeError) as exc:
                logger.exception("Wallet purchase provisioned but delivery message failed")
                await _edit_or_answer(
                    status_message,
                    f"✅ سرویس فعال شد، اما ساخت پیام تحویل خطا داشت ({type(exc).__name__}). از بخش اشتراک‌های من آن را دریافت کنید.",
                    reply_markup=_kb([[("📦 اشتراک‌های من", "shop:subs")]]),
                )
    except ValueError as exc:
        await _edit_or_answer(status_message, f"❌ خرید انجام نشد: {exc!s}")
    except Exception as exc:
        logger.exception("Wallet purchase failed")
        await _edit_or_answer(
            status_message,
            f"❌ خرید کامل نشد ({type(exc).__name__}). موجودی کیف پول را در «مشخصات من» بررسی کنید؛ در صورت کسر وجه و عدم فعال‌شدن سرویس، با پشتیبانی تماس بگیرید.",
            reply_markup=_kb([[("👤 مشخصات من", "shop:profile")]]),
        )


@router.callback_query(F.data == "shop:wallet")
async def shop_wallet(callback: CallbackQuery) -> None:
    await callback.answer()
    async with AsyncSessionFactory() as session:
        customer = await get_or_create_customer(session, callback.from_user)
        balance = await wallet_balance(session, customer.id)
        await session.commit()
    await callback.message.edit_text(
        f"👛 موجودی کیف پول: {_price(balance, 'IRR')}\nبرای افزایش موجودی، درخواست شارژ ثبت کنید.",
        reply_markup=_kb(
            [
                [("➕ شارژ کیف پول", "shop:topup")],
                [("↩️ منوی اصلی", "home")],
            ]
        ),
    )


@router.callback_query(F.data == "shop:topup")
async def shop_topup_start(callback: CallbackQuery, state: FSMContext) -> None:
    await callback.answer()
    await state.clear()
    await state.set_state(WalletTopup.amount)
    await _state_prompt(callback.message, state, "مبلغ شارژ به ریال را وارد کنید (حداقل 10,000):")


@router.message(WalletTopup.amount)
async def shop_topup_amount(message: Message, state: FSMContext) -> None:
    try:
        amount = Decimal((message.text or "").strip().replace(",", ""))
        if amount < 10000 or amount > Decimal(1000000000000):
            raise ValueError
    except (InvalidOperation, ValueError):
        await _state_prompt(message, state, "مبلغ معتبر وارد کنید؛ حداقل 10,000 ریال:")
        return
    async with AsyncSessionFactory() as session:
        customer = await get_or_create_customer(session, message.from_user)
        if customer.status != "active":
            await message.answer("حساب شما غیرفعال است؛ امکان شارژ کیف پول وجود ندارد.")
            await state.clear()
            return
        await session.commit()
    # Wallet top-ups use a plan-less order with an explicit amount.
    async with AsyncSessionFactory() as session:
        instructions = await _setting(session, "payment_instructions", "")
        if not instructions:
            await message.answer("روش پرداخت هنوز توسط مدیر تنظیم نشده است.")
            await state.clear()
            return
        order, _ = await create_manual_order(
            session,
            customer=customer,
            amount=amount,
            currency="IRR",
            order_type="wallet_topup",
            description="شارژ کیف پول",
        )
        await session.commit()
    await state.clear()
    await message.answer(
        f"درخواست شارژ ثبت شد.\nمبلغ: {_price(amount, 'IRR')}\n\n{instructions}\n\nرسید را به‌صورت عکس ارسال کنید و کد کامل سفارش را در Caption قرار دهید.",
        reply_markup=InlineKeyboardMarkup(
            inline_keyboard=[
                [
                    InlineKeyboardButton(
                        text="📋 کپی کد سفارش",
                        copy_text=CopyTextButton(text=str(order.id)),
                    )
                ],
                [InlineKeyboardButton(text="👤 مشخصات من", callback_data="shop:profile")],
            ]
        ),
    )


@router.message(F.photo)
async def payment_receipt_photo(message: Message, bot: Bot) -> None:
    if message.from_user is None:
        return
    caption = (message.caption or "").strip()
    try:
        order_id = uuid.UUID(caption)
    except ValueError:
        await message.answer("برای ثبت رسید، کد کامل سفارش را در Caption عکس قرار دهید.")
        return
    async with AsyncSessionFactory() as session:
        customer = await get_or_create_customer(session, message.from_user)
        if customer.status != "active":
            await message.answer("حساب شما غیرفعال است و امکان ثبت رسید ندارد.")
            return
        order = await session.get(Order, order_id)
        if order is None or order.customer_id != customer.id or order.status != "pending_payment":
            await message.answer("سفارش معتبر و در انتظار پرداختی برای شما پیدا نشد.")
            return
        try:
            await attach_payment_receipt(
                session,
                order_id,
                file_id=message.photo[-1].file_id,
                caption=caption,
            )
        except ValueError as exc:
            await message.answer(str(exc))
            return
        await session.commit()
        order_amount = order.amount
        currency = order.currency
    await message.answer(
        "✅ رسید دریافت شد و برای بررسی به مدیران ارسال شد. پس از تأیید، سرویس فعال می‌شود."
    )
    admin_ids = set(_root_admins())
    async with AsyncSessionFactory() as session:
        admin_ids.update(
            (
                await session.scalars(
                    select(AdminUser.telegram_id).where(AdminUser.is_active.is_(True))
                )
            ).all()
        )
    for admin_id in admin_ids:
        try:
            await bot.send_photo(
                admin_id,
                message.photo[-1].file_id,
                caption=f"رسید جدید\nسفارش: {order_id}\nمبلغ: {_price(Decimal(order_amount), currency)}\nمشتری: {message.from_user.id}",
                reply_markup=_kb([[("بررسی سفارش", f"order:view:{order_id}")]]),
            )
        except TelegramAPIError as exc:
            logger.warning(
                "Could not forward receipt to admin %s (%s)", admin_id, type(exc).__name__
            )


@router.callback_query(F.data == "shop:subs")
async def shop_subscriptions(callback: CallbackQuery) -> None:
    await callback.answer()
    async with AsyncSessionFactory() as session:
        customer = await get_or_create_customer(session, callback.from_user)
        subscriptions = (
            await session.scalars(
                select(Subscription)
                .where(Subscription.customer_id == customer.id)
                .order_by(Subscription.created_at.desc())
                .limit(15)
            )
        ).all()
        await session.commit()
    if not subscriptions:
        await callback.message.edit_text(
            "هنوز اشتراک فعالی ندارید.",
            reply_markup=_kb([[("🛍 خرید سرویس", "shop:plans")], [("↩️ منوی اصلی", "home")]]),
        )
        return
    rows = []
    for sub in subscriptions:
        label = f"{sub.status} · تا {sub.expires_at:%Y-%m-%d}" if sub.expires_at else sub.status
        rows.append([(f"اشتراک {str(sub.id)[:8]} · {label}", f"shop:sub:{sub.id}")])
    rows.append([("↩️ منوی اصلی", "home")])
    await callback.message.edit_text("📦 اشتراک‌های شما:", reply_markup=_kb(rows))


@router.callback_query(F.data.startswith("shop:sub:"))
async def shop_subscription_detail(callback: CallbackQuery) -> None:
    await callback.answer()
    subscription_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    async with AsyncSessionFactory() as session:
        customer = await get_or_create_customer(session, callback.from_user)
        if customer.status != "active":
            await callback.message.answer("حساب کاربری شما غیرفعال است.")
            return
        subscription = await session.get(Subscription, subscription_id)
        if subscription is None or subscription.customer_id != customer.id:
            await callback.message.answer("اشتراک پیدا نشد.")
            return
        plan = (
            await session.get(ProductPlan, subscription.plan_id) if subscription.plan_id else None
        )
        service = await session.get(VPNService, subscription.service_id)
        delivery = await _store_subscription_delivery(session, subscription)
        payload_text = delivery[0]
    rows = []
    if plan and subscription.status == "active":
        rows.append([("🔄 تمدید اشتراک", f"shop:renew:{subscription.id}")])
    rows.append([("↩️ بازگشت", "shop:subs")])
    await callback.message.edit_text(
        f"اشتراک: {subscription.id}\nسرویس: {service.name if service else '-'}\nوضعیت: {subscription.status}\nاعتبار: {subscription.expires_at}\n\n{payload_text}",
        reply_markup=_subscription_delivery_keyboard(delivery[1]),
    )
    files_sent = await _send_subscription_files(callback.bot, callback.from_user.id, delivery[2])
    if not files_sent:
        await callback.message.answer(
            "⚠️ پیام مشخصات نمایش داده شد، اما ارسال بعضی فایل‌های کانفیگ ناموفق بود. لطفاً دوباره تلاش کنید یا با پشتیبانی تماس بگیرید."
        )


@router.callback_query(F.data.startswith("shop:renew:"))
async def shop_renew(callback: CallbackQuery) -> None:
    await callback.answer()
    subscription_id = uuid.UUID(callback.data.rsplit(":", 1)[1])
    async with AsyncSessionFactory() as session:
        customer = await get_or_create_customer(session, callback.from_user)
        if customer.status != "active":
            await callback.message.answer("حساب کاربری شما غیرفعال است.")
            return
        subscription = await session.get(Subscription, subscription_id)
        if (
            subscription is None
            or subscription.customer_id != customer.id
            or not subscription.plan_id
        ):
            await callback.message.answer("اشتراک برای تمدید معتبر نیست.")
            return
        plan = await session.get(ProductPlan, subscription.plan_id)
        if plan is None or not plan.is_active:
            await callback.message.answer(
                "پلن فعلی غیرفعال است؛ برای تمدید با پشتیبانی تماس بگیرید."
            )
            return
        await session.commit()
    await _start_manual_payment(
        callback.message,
        plan=plan,
        customer=customer,
        order_type="subscription",
        subscription_id=subscription.id,
        renewal=True,
    )


@router.callback_query(F.data == "shop:orders")
async def shop_orders(callback: CallbackQuery) -> None:
    await callback.answer()
    async with AsyncSessionFactory() as session:
        customer = await get_or_create_customer(session, callback.from_user)
        orders = (
            await session.scalars(
                select(Order)
                .where(Order.customer_id == customer.id)
                .order_by(Order.created_at.desc())
                .limit(10)
            )
        ).all()
        await session.commit()
    if not orders:
        await callback.message.edit_text(
            "سفارشی ثبت نشده است.", reply_markup=_kb([[("↩️ منوی اصلی", "home")]])
        )
        return
    lines = [
        f"{str(order.id)[:8]} · {order.status} · {_price(Decimal(order.amount), order.currency)}"
        for order in orders
    ]
    await callback.message.edit_text(
        "🧾 سفارش‌های اخیر شما:\n" + "\n".join(lines), reply_markup=_kb([[("↩️ منوی اصلی", "home")]])
    )


async def bootstrap_admins() -> None:
    ids = _root_admins()
    async with AsyncSessionFactory() as session:
        previous_owners = (
            await session.scalars(select(AdminUser).where(AdminUser.role == "owner"))
        ).all()
        for previous in previous_owners:
            source = (previous.extra_data or {}).get("super_admin_source")
            if previous.telegram_id not in ids and source != "database":
                previous.role = "admin"
                previous.is_active = False
                previous.extra_data = {
                    key: value
                    for key, value in (previous.extra_data or {}).items()
                    if key not in {"permissions", "super_admin_source"}
                }
                await _audit(
                    session,
                    min(ids),
                    "admin.super_admin_revoked",
                    "admin",
                    previous.id,
                    {"telegram_id": previous.telegram_id},
                )
        for telegram_id in ids:
            admin = await session.scalar(
                select(AdminUser).where(AdminUser.telegram_id == telegram_id)
            )
            if admin is None:
                session.add(
                    AdminUser(
                        telegram_id=telegram_id,
                        role="owner",
                        is_active=True,
                        extra_data={"super_admin_source": "environment"},
                    )
                )
            else:
                admin.role = "owner"
                admin.is_active = True
                admin.extra_data = {
                    key: value
                    for key, value in (admin.extra_data or {}).items()
                    if key != "permissions"
                }
                admin.extra_data["super_admin_source"] = "environment"
        await session.commit()


async def prepare_long_polling(bot: Bot) -> None:
    """Remove an old Telegram webhook before this process starts long polling."""
    webhook = await bot.get_webhook_info()
    if webhook.url:
        logger.warning(
            "A Telegram webhook is configured; removing it because this service uses long polling."
        )
        await bot.delete_webhook(drop_pending_updates=False)
        logger.info("Telegram webhook removed; pending updates were preserved.")


async def run_bot() -> None:
    token = os.getenv("BOT_TOKEN", "").strip()
    if not token:
        raise RuntimeError("BOT_TOKEN is not configured; run the installer first")
    _root_admins()  # Fail fast if the allowlist is missing or malformed.
    await bootstrap_admins()
    bot = Bot(token=token)
    await prepare_long_polling(bot)
    identity = await bot.get_me()
    dispatcher = Dispatcher(storage=MemoryStorage())
    dispatcher.include_router(router)
    await bot.set_my_commands(
        [
            BotCommand(command="start", description="شروع فروشگاه و بررسی دسترسی"),
            BotCommand(command="admin", description="ورود به مدیریت"),
            BotCommand(command="cancel", description="لغو عملیات جاری"),
        ]
    )
    logger.info(
        "VPN Control Center bot authenticated as @%s (id=%d); configured owner count=%d",
        identity.username,
        identity.id,
        len(_root_admins()),
    )
    lifecycle_task = asyncio.create_task(
        _subscription_lifecycle_worker(bot), name="subscription-lifecycle"
    )
    try:
        await dispatcher.start_polling(bot, drop_pending_updates=False)
    finally:
        lifecycle_task.cancel()
        try:
            await lifecycle_task
        except asyncio.CancelledError:
            pass
        await bot.session.close()
        await engine.dispose()


def main() -> None:
    asyncio.run(run_bot())


if __name__ == "__main__":
    main()
