"""Browser-bound lifecycle intent and irreversible browser-session invalidation."""

import sqlalchemy as sa
from alembic import op

revision = "sp_lifecycle_05"
down_revision = "sp_browser_login_04"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "browser_actions",
        sa.Column("challenge_digest", sa.String(64), primary_key=True),
        sa.Column(
            "browser_digest",
            sa.String(64),
            sa.ForeignKey("browser_sessions.token_digest", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("purpose", sa.String(32), nullable=False),
        sa.Column("encrypted_payload", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.CheckConstraint("expires_at > created_at", name="action_positive_lifetime"),
    )
    op.create_index("browser_action_expiry", "browser_actions", ["expires_at"])
    op.execute("""
        CREATE FUNCTION browser_lifetime_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.token_digest IS DISTINCT FROM OLD.token_digest
                OR NEW.created_at IS DISTINCT FROM OLD.created_at
                OR NEW.encrypted_payload IS DISTINCT FROM OLD.encrypted_payload
                OR NEW.expires_at > OLD.expires_at THEN
                RAISE EXCEPTION 'Browser session identity and expiry cannot be extended';
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute(
        "CREATE TRIGGER guard_browser_lifetime BEFORE UPDATE ON browser_sessions "
        "FOR EACH ROW EXECUTE FUNCTION browser_lifetime_guard()"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER guard_browser_lifetime ON browser_sessions")
    op.execute("DROP FUNCTION browser_lifetime_guard()")
    op.drop_table("browser_actions")
