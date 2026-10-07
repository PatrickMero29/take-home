"""Durable browser-bound, one-use credential login continuations."""

import sqlalchemy as sa
from alembic import op

revision = "idp_browser_login_05"
down_revision = "idp_foundations_04"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "login_challenges",
        sa.Column("challenge_digest", sa.String(64), primary_key=True),
        sa.Column(
            "browser_digest",
            sa.String(64),
            sa.ForeignKey("browser_sessions.token_digest", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("encrypted_payload", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.CheckConstraint("expires_at > created_at", name="login_positive_lifetime"),
    )
    op.create_index("login_challenge_expiry", "login_challenges", ["expires_at"])


def downgrade() -> None:
    op.drop_table("login_challenges")
