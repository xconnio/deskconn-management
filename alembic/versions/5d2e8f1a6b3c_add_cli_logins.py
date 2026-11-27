"""add cli logins

Revision ID: 5d2e8f1a6b3c
Revises: 8b1e4d2c9a70
Create Date: 2026-11-26 12:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision: str = "5d2e8f1a6b3c"
down_revision: Union[str, Sequence[str], None] = "8b1e4d2c9a70"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


cli_login_status = postgresql.ENUM(
    "pending", "approved", "denied", name="cli_login_status", schema="deskconn", create_type=False
)


def upgrade() -> None:
    cli_login_status.create(op.get_bind(), checkfirst=True)
    op.create_table(
        "cli_logins",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("device_code_hash", sa.Text(), nullable=False),
        sa.Column("user_code", sa.Text(), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column("hostname", sa.Text(), nullable=False),
        sa.Column("purpose", sa.Text(), server_default="login", nullable=False),
        sa.Column("status", cli_login_status, nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("session_id", sa.BigInteger(), nullable=False),
        sa.Column("user_id", sa.UUID(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["deskconn.users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("device_code_hash"),
        sa.UniqueConstraint("user_code"),
        schema="deskconn",
    )
    op.create_index(op.f("ix_deskconn_cli_logins_user_id"), "cli_logins", ["user_id"], unique=False, schema="deskconn")


def downgrade() -> None:
    op.drop_index(op.f("ix_deskconn_cli_logins_user_id"), table_name="cli_logins", schema="deskconn")
    op.drop_table("cli_logins", schema="deskconn")
    cli_login_status.drop(op.get_bind(), checkfirst=True)
