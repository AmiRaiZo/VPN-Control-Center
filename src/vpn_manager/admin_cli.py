"""Small local maintenance CLI for adding a subordinate Telegram administrator."""

from __future__ import annotations

import argparse
import asyncio

from sqlalchemy import select

from vpn_manager.config import get_settings
from vpn_manager.database import AsyncSessionFactory, engine
from vpn_manager.models import AdminUser, AuditLog
from vpn_manager.setup_bot import normalize_admin_ids


async def add_admin(telegram_id: int, role: str) -> None:
    if telegram_id <= 0 or role not in {"admin", "finance", "support"}:
        raise ValueError("Invalid Telegram ID or role")
    async with AsyncSessionFactory() as session:
        settings_ids = normalize_admin_ids(get_settings().admin_telegram_ids)
        roots = {int(value) for value in settings_ids.split(",")}
        if telegram_id in roots:
            raise ValueError("The Super Admin cannot be added as a subordinate admin")
        admin = await session.scalar(select(AdminUser).where(AdminUser.telegram_id == telegram_id))
        action = "admin.created"
        if admin is None:
            admin = AdminUser(
                telegram_id=telegram_id,
                role=role,
                is_active=True,
                added_by=int(settings_ids.split(",", 1)[0]),
                extra_data={},
            )
            session.add(admin)
        else:
            action = "admin.role_changed"
            admin.role = role
            admin.is_active = True
            admin.added_by = int(settings_ids.split(",", 1)[0])
            admin.extra_data = {
                key: value
                for key, value in (admin.extra_data or {}).items()
                if key != "permissions"
            }
        session.add(
            AuditLog(
                actor_telegram_id=int(settings_ids.split(",", 1)[0]),
                action=action,
                resource_type="admin",
                details={"telegram_id": telegram_id, "role": role, "source": "vpn-help"},
            )
        )
        await session.commit()


async def _run(args: argparse.Namespace) -> None:
    try:
        await add_admin(args.telegram_id, args.role)
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="VPN Control Center admin maintenance")
    sub = parser.add_subparsers(dest="command", required=True)
    add = sub.add_parser("add-admin")
    add.add_argument("--telegram-id", type=int, required=True)
    add.add_argument("--role", choices=["admin", "finance", "support"], required=True)
    args = parser.parse_args()
    asyncio.run(_run(args))
    print(f"Admin {args.telegram_id} saved with role {args.role}.")


if __name__ == "__main__":
    main()

