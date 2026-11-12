from decimal import Decimal
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from vpn_manager.commerce import (
    attach_payment_receipt,
    create_manual_order,
    get_or_create_customer,
    post_wallet_entry,
    wallet_balance,
)
from vpn_manager.models import Base, Order, Payment


@pytest.fixture
async def session_factory(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'commerce.db'}")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest.mark.asyncio
async def test_wallet_ledger_is_idempotent_and_prevents_negative_balance(session_factory):
    async with session_factory() as session:
        customer = await get_or_create_customer(
            session, SimpleNamespace(id=1234, username="buyer", first_name="Test", last_name="User")
        )
        await post_wallet_entry(
            session,
            customer_id=customer.id,
            amount=Decimal(100000),
            entry_type="topup",
            idempotency_key="payment:one",
            description="test topup",
        )
        first = await post_wallet_entry(
            session,
            customer_id=customer.id,
            amount=Decimal(100000),
            entry_type="topup",
            idempotency_key="payment:one",
            description="duplicate callback",
        )
        assert await wallet_balance(session, customer.id) == Decimal(100000)
        await post_wallet_entry(
            session,
            customer_id=customer.id,
            amount=Decimal(-25000),
            entry_type="purchase",
            idempotency_key="order:one:debit",
            description="test purchase",
        )
        assert await wallet_balance(session, customer.id) == Decimal(75000)
        with pytest.raises(ValueError, match="کافی نیست"):
            await post_wallet_entry(
                session,
                customer_id=customer.id,
                amount=Decimal(-90000),
                entry_type="purchase",
                idempotency_key="order:two:debit",
                description="too expensive",
            )
        with pytest.raises(ValueError, match="Idempotency key"):
            await post_wallet_entry(
                session,
                customer_id=customer.id,
                amount=Decimal(200000),
                entry_type="topup",
                idempotency_key="payment:one",
                description="mismatched replay",
            )
        await session.commit()
        assert first.id is not None


@pytest.mark.asyncio
async def test_manual_order_receipt_is_bound_to_pending_payment(session_factory):
    async with session_factory() as session:
        customer = await get_or_create_customer(
            session, SimpleNamespace(id=4321, username="buyer2", first_name="A", last_name="B")
        )
        order, payment = await create_manual_order(
            session,
            customer=customer,
            amount=Decimal(250000),
            currency="IRR",
            order_type="wallet_topup",
            description="wallet topup",
        )
        await attach_payment_receipt(
            session, order.id, file_id="telegram-file-id", caption=str(order.id)
        )
        await session.commit()
        refreshed_order = await session.get(Order, order.id)
        refreshed_payment = await session.get(Payment, payment.id)
        assert refreshed_order.status == "pending_payment"
        assert refreshed_payment.status == "pending"
        assert refreshed_payment.extra_data["receipt_file_id"] == "telegram-file-id"
        with pytest.raises(ValueError, match="در انتظار رسید"):
            await attach_payment_receipt(session, uuid4(), file_id="x", caption="x")

