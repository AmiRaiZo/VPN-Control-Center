"""Per-admin permission overrides.

Revision ID: 0003_admin_permissions
Revises: 0002_admin_sales
"""

import sqlalchemy as sa

from alembic import op

revision = "0003_admin_permissions"
down_revision = "0002_admin_sales"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "admin_users",
        sa.Column("extra_data", sa.JSON(), nullable=False, server_default="{}"),
    )


def downgrade() -> None:
    op.drop_column("admin_users", "extra_data")

