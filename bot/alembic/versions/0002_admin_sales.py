"""Telegram administration and VPN storefront.

Revision ID: 0002_admin_sales
Revises: 0001_initial
"""

import sqlalchemy as sa

from alembic import op

revision = "0002_admin_sales"
down_revision = "0001_initial"
branch_labels = None
depends_on = None

UUID = sa.Uuid(as_uuid=True)
TS = sa.DateTime(timezone=True)
MONEY = sa.Numeric(20, 4)


def upgrade() -> None:
    op.create_table(
        "admin_users",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("telegram_id", sa.BigInteger(), nullable=False, unique=True),
        sa.Column("role", sa.String(24), nullable=False, server_default="admin"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("added_by", sa.BigInteger()),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", TS, nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "store_settings",
        sa.Column("key", sa.String(80), primary_key=True),
        sa.Column("value", sa.Text(), nullable=False),
        sa.Column("updated_at", TS, nullable=False, server_default=sa.func.now()),
    )
    op.create_table(
        "product_plans",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("service_id", UUID, nullable=False),
        sa.Column("name", sa.String(120), nullable=False),
        sa.Column("description", sa.String(500)),
        sa.Column("duration_days", sa.Integer(), nullable=False),
        sa.Column("traffic_limit_bytes", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("device_limit", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("price", MONEY, nullable=False),
        sa.Column("currency", sa.String(3), nullable=False, server_default="IRR"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("extra_data", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", TS, nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["service_id"], ["vpn_services.id"], ondelete="RESTRICT"),
        sa.CheckConstraint("duration_days > 0", name="ck_product_plans_duration_positive"),
        sa.CheckConstraint("traffic_limit_bytes >= 0", name="ck_product_plans_traffic_nonnegative"),
        sa.CheckConstraint("device_limit >= 0", name="ck_product_plans_devices_nonnegative"),
        sa.CheckConstraint("price >= 0", name="ck_product_plans_price_nonnegative"),
    )
    op.create_index("ix_product_plans_service_id", "product_plans", ["service_id"])
    op.create_index("ix_product_plans_active", "product_plans", ["is_active"])
    op.create_table(
        "managed_clients",
        sa.Column("id", UUID, primary_key=True),
        sa.Column("service_id", UUID, nullable=False),
        sa.Column("external_identity", sa.String(255), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("is_enabled", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("is_present", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("encrypted_payload", sa.Text(), nullable=False),
        sa.Column("extra_data", sa.JSON(), nullable=False, server_default="{}"),
        sa.Column("created_at", TS, nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", TS, nullable=False, server_default=sa.func.now()),
        sa.ForeignKeyConstraint(["service_id"], ["vpn_services.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint(
            "service_id", "external_identity", name="uq_managed_clients_service_identity"
        ),
    )
    op.create_index("ix_managed_clients_service_id", "managed_clients", ["service_id"])
    op.create_index("ix_managed_clients_email", "managed_clients", ["email"])
    op.create_index("ix_managed_clients_present", "managed_clients", ["is_present"])
    with op.batch_alter_table("orders") as batch:
        batch.add_column(sa.Column("plan_id", UUID, nullable=True))
        batch.add_column(
            sa.Column("order_type", sa.String(24), nullable=False, server_default="subscription")
        )
        batch.create_foreign_key(
            "fk_orders_plan_id_product_plans",
            "product_plans",
            ["plan_id"],
            ["id"],
            ondelete="RESTRICT",
        )
    with op.batch_alter_table("subscriptions") as batch:
        batch.add_column(sa.Column("plan_id", UUID, nullable=True))
        batch.create_foreign_key(
            "fk_subscriptions_plan_id_product_plans",
            "product_plans",
            ["plan_id"],
            ["id"],
            ondelete="RESTRICT",
        )
    op.add_column("audit_logs", sa.Column("actor_telegram_id", sa.BigInteger(), nullable=True))
    op.create_index("ix_audit_logs_actor_telegram_id", "audit_logs", ["actor_telegram_id"])


def downgrade() -> None:
    op.drop_index("ix_audit_logs_actor_telegram_id", table_name="audit_logs")
    op.drop_column("audit_logs", "actor_telegram_id")
    with op.batch_alter_table("subscriptions") as batch:
        batch.drop_constraint("fk_subscriptions_plan_id_product_plans", type_="foreignkey")
        batch.drop_column("plan_id")
    with op.batch_alter_table("orders") as batch:
        batch.drop_constraint("fk_orders_plan_id_product_plans", type_="foreignkey")
        batch.drop_column("order_type")
        batch.drop_column("plan_id")
    op.drop_index("ix_managed_clients_present", table_name="managed_clients")
    op.drop_index("ix_managed_clients_email", table_name="managed_clients")
    op.drop_index("ix_managed_clients_service_id", table_name="managed_clients")
    op.drop_table("managed_clients")
    op.drop_index("ix_product_plans_active", table_name="product_plans")
    op.drop_index("ix_product_plans_service_id", table_name="product_plans")
    op.drop_table("product_plans")
    op.drop_table("store_settings")
    op.drop_table("admin_users")
