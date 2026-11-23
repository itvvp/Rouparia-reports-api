"""users e refresh_sessions

Revision ID: 0001
Revises:
"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.mssql import DATETIME2

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

NOW = sa.text("SYSUTCDATETIME()")


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("name", sa.Unicode(255), nullable=False),
        sa.Column("email", sa.String(255, collation="Latin1_General_CI_AS"), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(10), nullable=False, server_default="user"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.text("1")),
        sa.Column("failed_logins", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column("locked_until", DATETIME2, nullable=True),
        sa.Column("created_at", DATETIME2, nullable=False, server_default=NOW),
        sa.Column("updated_at", DATETIME2, nullable=False, server_default=NOW),
        sa.CheckConstraint("role IN ('user', 'admin', 'superuser')", name="ck_users_role"),
    )
    op.create_index("ux_users_email", "users", ["email"], unique=True)

    op.create_table(
        "refresh_sessions",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", DATETIME2, nullable=False),
        sa.Column("revoked_at", DATETIME2, nullable=True),
        sa.Column("created_at", DATETIME2, nullable=False, server_default=NOW),
    )
    op.create_index("ux_refresh_sessions_token_hash", "refresh_sessions", ["token_hash"], unique=True)
    op.create_index("ix_refresh_sessions_user_id", "refresh_sessions", ["user_id"])


def downgrade() -> None:
    op.drop_table("refresh_sessions")
    op.drop_table("users")
