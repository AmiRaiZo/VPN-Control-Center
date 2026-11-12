"""Transactional customer, order, wallet and manual-payment primitives."""

from __future__ import annotations

from decimal import Decimal
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vpn_manager.models import (
    Customer,
    Order,
    Payment,
    WalletAccount,
    WalletLedger,
    utc_now,
)


async def get_or_create_customer(session: AsyncSession, telegram_user: Any) -> Customer:
    customer = await session.scalar(
        select(Customer).where(Customer.telegram_id == telegram_user.id)
    )
    if customer is None:
        customer = Customer(
            telegram_id=telegram_user.id,
            username=getattr(telegram_user, "username", None),
            full_name=" ".join(
                part
                for part in (
                    getattr(telegram_user, "first_name", None),
                    getattr(telegram_user, "last_name", None),
                )
                if part
            )[:200],
        )
        session.add(customer)
        await session.flush()
    else:
        customer.username = getattr(telegram_user, "username", None)
        customer.full_name = " ".join(
            part
            for part in (
                getattr(telegram_user, "first_name", None),
                getattr(telegram_user, "last_name", None),
            )
            if part
        )[:200]
    wallet = await session.scalar(
        select(WalletAccount).where(WalletAccount.customer_id == customer.id)
    )
    if wallet is None:
        session.add(WalletAccount(customer_id=customer.id, currency="IRR", balance=Decimal(0)))
        await session.flush()
    return customer


async def wallet_balance(session: AsyncSession, customer_id: UUID) -> Decimal:
    wallet = await session.scalar(
        select(WalletAccount).where(WalletAccount.customer_id == customer_id)
    )
    return wallet.balance if wallet else Decimal(0)


async def post_wallet_entry(
    session: AsyncSession,
    *,
    customer_id: UUID,
    amount: Decimal,
    entry_type: str,
    idempotency_key: str,
    description: str,
    reference: str | None = None,
) -> WalletLedger:
    """Post one immutable ledger entry; repeating the key never posts twice."""
    if amount == 0:
        raise ValueError("Wallet ledger amount cannot be zero")
    existing = await session.scalar(
        select(WalletLedger).where(WalletLedger.idempotency_key == idempotency_key)
    )
    if existing is not None:
        existing_wallet = await session.get(WalletAccount, existing.wallet_id)
        if (
            existing_wallet is None
            or existing_wallet.customer_id != customer_id
            or Decimal(existing.amount) != amount
            or existing.entry_type != entry_type
        ):
            raise ValueError("Idempotency key was already used for a different wallet operation")
        return existing
    wallet = await session.scalar(
        select(WalletAccount).where(WalletAccount.customer_id == customer_id).with_for_update()
    )
    if wallet is None:
        wallet = WalletAccount(customer_id=customer_id, currency="IRR", balance=Decimal(0))
        session.add(wallet)
        await session.flush()
    new_balance = Decimal(wallet.balance) + amount
    if new_balance < 0:
        raise ValueError("موجودی کیف پول کافی نیست.")
    wallet.balance = new_balance
    entry = WalletLedger(
        wallet_id=wallet.id,
        amount=amount,
        balance_after=new_balance,
        currency=wallet.currency,
        entry_type=entry_type,
        idempotency_key=idempotency_key,
        reference=reference,
        description=description[:500],
    )
    session.add(entry)
    await session.flush()
    return entry


async def create_manual_order(
    session: AsyncSession,
    *,
    customer: Customer,
    amount: Decimal,
    currency: str,
    order_type: str,
    description: str,
    plan_id: UUID | None = None,
    subscription_id: UUID | None = None,
) -> tuple[Order, Payment]:
    if amount <= 0:
        raise ValueError("Order amount must be greater than zero")
    order = Order(
        customer_id=customer.id,
        plan_id=plan_id,
        subscription_id=subscription_id,
        order_type=order_type,
        amount=amount,
        currency=currency.upper(),
        status="pending_payment",
        description=description[:500],
    )
    session.add(order)
    await session.flush()
    payment = Payment(
        order_id=order.id,
        provider="manual",
        external_id=f"manual:{order.id}",
        amount=amount,
        currency=currency.upper(),
        status="pending",
        extra_data={"receipt_file_id": None, "receipt_caption": None},
    )
    session.add(payment)
    await session.flush()
    return order, payment


async def attach_payment_receipt(
    session: AsyncSession, order_id: UUID, *, file_id: str | None, caption: str | None
) -> Payment:
    payment = await session.scalar(
        select(Payment).where(Payment.order_id == order_id, Payment.provider == "manual")
    )
    if payment is None or payment.status != "pending":
        raise ValueError("این سفارش در انتظار رسید پرداخت نیست.")
    payment.extra_data = {
        **(payment.extra_data or {}),
        "receipt_file_id": file_id,
        "receipt_caption": (caption or "")[:500],
        "receipt_submitted_at": utc_now().isoformat(),
    }
    await session.flush()
    return payment

