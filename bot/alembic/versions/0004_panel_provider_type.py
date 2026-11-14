"""Identify the API provider for each managed panel.

Revision ID: 0004_panel_provider_type
Revises: 0003_admin_permissions
"""

import sqlalchemy as sa

from alembic import op

revision = "0004_panel_provider_type"
down_revision = "0003_admin_permissions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "panels",
        sa.Column("provider_type", sa.String(length=24), nullable=False, server_default="vpn_ui"),
    )


def downgrade() -> None:
    op.drop_column("panels", "provider_type")
