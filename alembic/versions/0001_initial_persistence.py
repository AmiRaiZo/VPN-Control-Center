"""Initial control-plane persistence schema.

Revision ID: 0001_initial
Revises:
Create Date: 2026-11-12
"""

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None

UUID = sa.Uuid(as_uuid=True)
JSON = sa.JSON().with_variant(postgresql.JSONB(), "postgresql")
MONEY = sa.Numeric(20, 4)
TS = sa.DateTime(timezone=True)


def _timestamps() -> list[sa.Column]:
    return [
        sa.Column("created_at", TS, server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", TS, server_default=sa.func.now(), nullable=False),
    ]


def upgrade() -> None:
    op.create_table(
        "panels",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("name", sa.String(120), nullable=False, unique=True),
        sa.Column("base_url", sa.String(2048), nullable=False),
        sa.Column("base_path", sa.String(255), nullable=False),
        sa.Column("username", sa.String(255), nullable=False),
        sa.Column("encrypted_password", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("last_checked_at", TS),
        sa.Column("last_error", sa.Text()),
        sa.Column("version", sa.String(80)),
        sa.Column("extra_data", JSON, nullable=False),
        *_timestamps(),
    )
    op.create_table(
        "customers",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("telegram_id", sa.BigInteger(), unique=True),
        sa.Column("username", sa.String(64)),
        sa.Column("full_name", sa.String(200)),
        sa.Column("phone", sa.String(32), unique=True),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("extra_data", JSON, nullable=False),
        *_timestamps(),
    )
    op.create_index("ix_customers_username", "customers", ["username"])
    op.create_table(
        "vpn_services",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("panel_id", UUID, nullable=False),
        sa.Column("external_id", sa.String(128), nullable=False),
        sa.Column("name", sa.String(160), nullable=False),
        sa.Column("protocol", sa.String(40), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("extra_data", JSON, nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["panel_id"], ["panels.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("panel_id", "external_id", name="uq_vpn_services_panel_external"),
    )
    op.create_index("ix_vpn_services_panel_id", "vpn_services", ["panel_id"])
    op.create_table(
        "subscriptions",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("customer_id", UUID, nullable=False),
        sa.Column("service_id", UUID, nullable=False),
        sa.Column("external_client_id", sa.String(255)),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("starts_at", TS),
        sa.Column("expires_at", TS),
        sa.Column("traffic_limit_bytes", sa.BigInteger()),
        sa.Column("extra_data", JSON, nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["customer_id"], ["customers.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["service_id"], ["vpn_services.id"], ondelete="RESTRICT"),
        sa.CheckConstraint(
            "traffic_limit_bytes IS NULL OR traffic_limit_bytes >= 0",
            name="ck_subscriptions_traffic_nonnegative",
        ),
        sa.UniqueConstraint(
            "service_id", "external_client_id", name="uq_subscriptions_service_external_client"
        ),
    )
    op.create_index("ix_subscriptions_customer_status", "subscriptions", ["customer_id", "status"])
    op.create_index("ix_subscriptions_expires_at", "subscriptions", ["expires_at"])
    op.create_index("ix_subscriptions_external_client_id", "subscriptions", ["external_client_id"])
    op.create_table(
        "wallet_accounts",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("customer_id", UUID, nullable=False, unique=True),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("balance", MONEY, nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["customer_id"], ["customers.id"], ondelete="RESTRICT"),
        sa.CheckConstraint("balance >= 0", name="ck_wallet_accounts_balance_nonnegative"),
    )
    op.create_table(
        "orders",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("customer_id", UUID, nullable=False),
        sa.Column("subscription_id", UUID),
        sa.Column("amount", MONEY, nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("description", sa.String(500)),
        sa.Column("extra_data", JSON, nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["customer_id"], ["customers.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["subscription_id"], ["subscriptions.id"], ondelete="SET NULL"),
        sa.CheckConstraint("amount >= 0", name="ck_orders_amount_nonnegative"),
    )
    op.create_index("ix_orders_customer_created", "orders", ["customer_id", "created_at"])
    op.create_table(
        "wallet_ledger",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("wallet_id", UUID, nullable=False),
        sa.Column("amount", MONEY, nullable=False),
        sa.Column("balance_after", MONEY, nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("entry_type", sa.String(32), nullable=False),
        sa.Column("reference", sa.String(160)),
        sa.Column("idempotency_key", sa.String(160), unique=True),
        sa.Column("description", sa.String(500)),
        sa.Column("extra_data", JSON, nullable=False),
        sa.Column("created_at", TS, server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["wallet_id"], ["wallet_accounts.id"], ondelete="RESTRICT"),
        sa.CheckConstraint("amount <> 0", name="ck_wallet_ledger_amount_nonzero"),
    )
    op.create_index("ix_wallet_ledger_wallet_created", "wallet_ledger", ["wallet_id", "created_at"])
    op.create_table(
        "payments",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("order_id", UUID, nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("external_id", sa.String(200)),
        sa.Column("amount", MONEY, nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("paid_at", TS),
        sa.Column("extra_data", JSON, nullable=False),
        *_timestamps(),
        sa.ForeignKeyConstraint(["order_id"], ["orders.id"], ondelete="RESTRICT"),
        sa.CheckConstraint("amount > 0", name="ck_payments_amount_positive"),
        sa.UniqueConstraint("provider", "external_id", name="uq_payments_provider_external"),
    )
    op.create_index("ix_payments_status_created", "payments", ["status", "created_at"])
    op.create_table(
        "traffic_snapshots",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("subscription_id", UUID, nullable=False),
        sa.Column("upload_bytes", sa.BigInteger(), nullable=False),
        sa.Column("download_bytes", sa.BigInteger(), nullable=False),
        sa.Column("captured_at", TS, nullable=False),
        sa.Column("extra_data", JSON, nullable=False),
        sa.ForeignKeyConstraint(["subscription_id"], ["subscriptions.id"], ondelete="RESTRICT"),
        sa.CheckConstraint(
            "upload_bytes >= 0 AND download_bytes >= 0",
            name="ck_traffic_snapshots_bytes_nonnegative",
        ),
        sa.UniqueConstraint(
            "subscription_id", "captured_at", name="uq_traffic_snapshots_subscription_time"
        ),
    )
    op.create_index(
        "ix_traffic_snapshots_subscription_time",
        "traffic_snapshots",
        ["subscription_id", "captured_at"],
    )
    op.create_table(
        "audit_logs",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("actor_customer_id", UUID),
        sa.Column("panel_id", UUID),
        sa.Column("action", sa.String(120), nullable=False),
        sa.Column("resource_type", sa.String(80), nullable=False),
        sa.Column("resource_id", UUID),
        sa.Column("ip_address", sa.String(45)),
        sa.Column("details", JSON, nullable=False),
        sa.Column("created_at", TS, server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["actor_customer_id"], ["customers.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["panel_id"], ["panels.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_audit_logs_resource", "audit_logs", ["resource_type", "resource_id"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_index("ix_traffic_snapshots_subscription_time", table_name="traffic_snapshots")
    op.drop_table("traffic_snapshots")
    op.drop_index("ix_payments_status_created", table_name="payments")
    op.drop_table("payments")
    op.drop_index("ix_wallet_ledger_wallet_created", table_name="wallet_ledger")
    op.drop_table("wallet_ledger")
    op.drop_index("ix_orders_customer_created", table_name="orders")
    op.drop_table("orders")
    op.drop_table("wallet_accounts")
    op.drop_index("ix_subscriptions_external_client_id", table_name="subscriptions")
    op.drop_index("ix_subscriptions_expires_at", table_name="subscriptions")
    op.drop_index("ix_subscriptions_customer_status", table_name="subscriptions")
    op.drop_table("subscriptions")
    op.drop_index("ix_vpn_services_panel_id", table_name="vpn_services")
    op.drop_table("vpn_services")
    op.drop_index("ix_customers_username", table_name="customers")
    op.drop_table("customers")
    op.drop_table("panels")

