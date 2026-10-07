"""Browser-bound lifecycle intent and durable code-replay retention."""

import sqlalchemy as sa
from alembic import op

revision = "idp_lifecycle_06"
down_revision = "idp_browser_login_05"
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
    # Consumed proofs must remain available while a derived grant can authorize.
    # Existing immutable-update guards already preserve the original code facts.
    op.execute("""
        CREATE FUNCTION retain_consumed_code() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF OLD.consumed_at IS NOT NULL THEN
                RAISE EXCEPTION 'Consumed authorization proof is retained for replay containment';
            END IF;
            RETURN OLD;
        END $$
    """)
    op.execute(
        "CREATE TRIGGER retain_consumed_authorization_code BEFORE DELETE ON authorization_codes "
        "FOR EACH ROW EXECUTE FUNCTION retain_consumed_code()"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER retain_consumed_authorization_code ON authorization_codes")
    op.execute("DROP FUNCTION retain_consumed_code()")
    op.drop_table("browser_actions")
