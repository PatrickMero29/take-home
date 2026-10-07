"""SP-owned opaque storage; no IDP tables exist in an SP database."""

import sqlalchemy as sa
from alembic import op

revision = "sp_architecture_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "browser_sessions",
        sa.Column("token_digest", sa.String(64), primary_key=True),
        sa.Column("encrypted_payload", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
    )
    op.create_table(
        "authorization_transactions",
        sa.Column("state_digest", sa.String(64), primary_key=True),
        sa.Column("browser_digest", sa.String(64), nullable=False),
        sa.Column("encrypted_payload", sa.LargeBinary(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("authorization_transactions")
    op.drop_table("browser_sessions")
