"""SQLAlchemy 2 persistence models for the control plane."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from decimal import Decimal
from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utc_now() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Shared declarative metadata."""


class UUIDPrimaryKey:
    id: Mapped[uuid.UUID] = mapped_column(Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4)


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=utc_now,
        onupdate=utc_now,
        server_default=func.now(),
        nullable=False,
    )


class AdminUser(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "admin_users"

    telegram_id: Mapped[int] = mapped_column(BigInteger, unique=True, nullable=False)
    role: Mapped[str] = mapped_column(String(24), default="admin", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    added_by: Mapped[int | None] = mapped_column(BigInteger)
    extra_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)


class StoreSetting(Base):
    __tablename__ = "store_settings"

    key: Mapped[str] = mapped_column(String(80), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class Panel(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "panels"

    name: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    base_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    base_path: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    encrypted_password: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="unknown", nullable=False)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_error: Mapped[str | None] = mapped_column(Text)
    version: Mapped[str | None] = mapped_column(String(80))
    extra_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    services: Mapped[list[VPNService]] = relationship(back_populates="panel")


class Customer(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "customers"

    telegram_id: Mapped[int | None] = mapped_column(BigInteger, unique=True)
    username: Mapped[str | None] = mapped_column(String(64), index=True)
    full_name: Mapped[str | None] = mapped_column(String(200))
    phone: Mapped[str | None] = mapped_column(String(32), unique=True)
    status: Mapped[str] = mapped_column(String(24), default="active", nullable=False)
    extra_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    wallet: Mapped[WalletAccount | None] = relationship(back_populates="customer", uselist=False)
    subscriptions: Mapped[list[Subscription]] = relationship(back_populates="customer")
    orders: Mapped[list[Order]] = relationship(back_populates="customer")


class VPNService(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "vpn_services"
    __table_args__ = (
        UniqueConstraint("panel_id", "external_id", name="uq_vpn_services_panel_external"),
    )

    panel_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("panels.id", ondelete="RESTRICT"), index=True
    )
    external_id: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    protocol: Mapped[str] = mapped_column(String(40), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    extra_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    panel: Mapped[Panel] = relationship(back_populates="services")
    subscriptions: Mapped[list[Subscription]] = relationship(back_populates="service")
    plans: Mapped[list[ProductPlan]] = relationship(back_populates="service")


class ProductPlan(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "product_plans"
    __table_args__ = (
        CheckConstraint("duration_days > 0", name="ck_product_plans_duration_positive"),
        CheckConstraint("traffic_limit_bytes >= 0", name="ck_product_plans_traffic_nonnegative"),
        CheckConstraint("device_limit >= 0", name="ck_product_plans_devices_nonnegative"),
        CheckConstraint("price >= 0", name="ck_product_plans_price_nonnegative"),
        Index("ix_product_plans_active", "is_active"),
    )

    service_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("vpn_services.id", ondelete="RESTRICT"), index=True
    )
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(String(500))
    duration_days: Mapped[int] = mapped_column(nullable=False)
    traffic_limit_bytes: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    device_limit: Mapped[int] = mapped_column(default=1, nullable=False)
    price: Mapped[Decimal] = mapped_column(Numeric(20, 4), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), default="IRR", nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    extra_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    service: Mapped[VPNService] = relationship(back_populates="plans")


class ManagedClient(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "managed_clients"
    __table_args__ = (
        UniqueConstraint(
            "service_id", "external_identity", name="uq_managed_clients_service_identity"
        ),
        Index("ix_managed_clients_email", "email"),
        Index("ix_managed_clients_present", "is_present"),
    )

    service_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("vpn_services.id", ondelete="RESTRICT"), index=True
    )
    external_identity: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_present: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    encrypted_payload: Mapped[str] = mapped_column(Text, nullable=False)
    extra_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    service: Mapped[VPNService] = relationship()


class Subscription(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "subscriptions"
    __table_args__ = (
        CheckConstraint(
            "traffic_limit_bytes IS NULL OR traffic_limit_bytes >= 0",
            name="ck_subscriptions_traffic_nonnegative",
        ),
        UniqueConstraint(
            "service_id", "external_client_id", name="uq_subscriptions_service_external_client"
        ),
        Index("ix_subscriptions_customer_status", "customer_id", "status"),
        Index("ix_subscriptions_expires_at", "expires_at"),
    )

    customer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("customers.id", ondelete="RESTRICT"))
    plan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("product_plans.id", ondelete="RESTRICT")
    )
    service_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("vpn_services.id", ondelete="RESTRICT")
    )
    external_client_id: Mapped[str | None] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(24), default="pending", nullable=False)
    starts_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    traffic_limit_bytes: Mapped[int | None] = mapped_column(BigInteger)
    extra_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    customer: Mapped[Customer] = relationship(back_populates="subscriptions")
    service: Mapped[VPNService] = relationship(back_populates="subscriptions")
    plan: Mapped[ProductPlan | None] = relationship()
    traffic_snapshots: Mapped[list[TrafficSnapshot]] = relationship(back_populates="subscription")


class WalletAccount(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "wallet_accounts"
    __table_args__ = (
        CheckConstraint("balance >= 0", name="ck_wallet_accounts_balance_nonnegative"),
    )

    customer_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("customers.id", ondelete="RESTRICT"), unique=True
    )
    currency: Mapped[str] = mapped_column(String(3), default="IRR", nullable=False)
    balance: Mapped[Decimal] = mapped_column(Numeric(20, 4), default=Decimal(0), nullable=False)

    customer: Mapped[Customer] = relationship(back_populates="wallet")
    ledger_entries: Mapped[list[WalletLedger]] = relationship(back_populates="wallet")


class WalletLedger(UUIDPrimaryKey, Base):
    __tablename__ = "wallet_ledger"
    __table_args__ = (
        CheckConstraint("amount <> 0", name="ck_wallet_ledger_amount_nonzero"),
        Index("ix_wallet_ledger_wallet_created", "wallet_id", "created_at"),
    )

    wallet_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("wallet_accounts.id", ondelete="RESTRICT")
    )
    amount: Mapped[Decimal] = mapped_column(Numeric(20, 4), nullable=False)
    balance_after: Mapped[Decimal] = mapped_column(Numeric(20, 4), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    entry_type: Mapped[str] = mapped_column(String(32), nullable=False)
    reference: Mapped[str | None] = mapped_column(String(160))
    idempotency_key: Mapped[str | None] = mapped_column(String(160), unique=True)
    description: Mapped[str | None] = mapped_column(String(500))
    extra_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    wallet: Mapped[WalletAccount] = relationship(back_populates="ledger_entries")


class Order(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "orders"
    __table_args__ = (
        CheckConstraint("amount >= 0", name="ck_orders_amount_nonnegative"),
        Index("ix_orders_customer_created", "customer_id", "created_at"),
    )

    customer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("customers.id", ondelete="RESTRICT"))
    plan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("product_plans.id", ondelete="RESTRICT")
    )
    subscription_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("subscriptions.id", ondelete="SET NULL")
    )
    order_type: Mapped[str] = mapped_column(String(24), default="subscription", nullable=False)
    amount: Mapped[Decimal] = mapped_column(Numeric(20, 4), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="pending", nullable=False)
    description: Mapped[str | None] = mapped_column(String(500))
    extra_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    customer: Mapped[Customer] = relationship(back_populates="orders")
    payments: Mapped[list[Payment]] = relationship(back_populates="order")
    plan: Mapped[ProductPlan | None] = relationship()


class Payment(UUIDPrimaryKey, TimestampMixin, Base):
    __tablename__ = "payments"
    __table_args__ = (
        CheckConstraint("amount > 0", name="ck_payments_amount_positive"),
        UniqueConstraint("provider", "external_id", name="uq_payments_provider_external"),
        Index("ix_payments_status_created", "status", "created_at"),
    )

    order_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("orders.id", ondelete="RESTRICT"))
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    external_id: Mapped[str | None] = mapped_column(String(200))
    amount: Mapped[Decimal] = mapped_column(Numeric(20, 4), nullable=False)
    currency: Mapped[str] = mapped_column(String(3), nullable=False)
    status: Mapped[str] = mapped_column(String(24), default="pending", nullable=False)
    paid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    extra_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    order: Mapped[Order] = relationship(back_populates="payments")


class TrafficSnapshot(UUIDPrimaryKey, Base):
    __tablename__ = "traffic_snapshots"
    __table_args__ = (
        CheckConstraint(
            "upload_bytes >= 0 AND download_bytes >= 0",
            name="ck_traffic_snapshots_bytes_nonnegative",
        ),
        UniqueConstraint(
            "subscription_id", "captured_at", name="uq_traffic_snapshots_subscription_time"
        ),
        Index("ix_traffic_snapshots_subscription_time", "subscription_id", "captured_at"),
    )

    subscription_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("subscriptions.id", ondelete="RESTRICT")
    )
    upload_bytes: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    download_bytes: Mapped[int] = mapped_column(BigInteger, default=0, nullable=False)
    captured_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    extra_data: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    subscription: Mapped[Subscription] = relationship(back_populates="traffic_snapshots")


class AuditLog(UUIDPrimaryKey, Base):
    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_resource", "resource_type", "resource_id"),
        Index("ix_audit_logs_created_at", "created_at"),
    )

    actor_customer_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("customers.id", ondelete="SET NULL")
    )
    actor_telegram_id: Mapped[int | None] = mapped_column(BigInteger, index=True)
    panel_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("panels.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(80), nullable=False)
    resource_id: Mapped[uuid.UUID | None] = mapped_column(Uuid(as_uuid=True))
    ip_address: Mapped[str | None] = mapped_column(String(45))
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

