"""Add stable OIDC subject for Authentik login.

Revision ID: nlv000000001
Revises: f7c3e9a1d5b4
"""
from alembic import op
import sqlalchemy as sa

revision = "nlv000000001"
down_revision = "f7c3e9a1d5b4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("t_d_user", sa.Column("oidc_sub", sa.String(255), nullable=True))
    op.create_index("ix_t_d_user_oidc_sub", "t_d_user", ["oidc_sub"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_t_d_user_oidc_sub", table_name="t_d_user")
    op.drop_column("t_d_user", "oidc_sub")
