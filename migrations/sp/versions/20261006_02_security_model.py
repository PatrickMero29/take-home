"""SP-local authenticated evidence and encrypted credential custody."""

import sqlalchemy as sa
from alembic import op

revision = "sp_security_model_02"
down_revision = "sp_architecture_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sp_authentication_sessions",
        sa.Column(
            "token_digest",
            sa.String(64),
            sa.ForeignKey("browser_sessions.token_digest", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("encrypted_evidence", sa.LargeBinary(), nullable=False),
        sa.Column("encrypted_access_token", sa.LargeBinary(), nullable=False),
        sa.Column("encrypted_refresh_token", sa.LargeBinary(), nullable=False),
        sa.Column("grant_id", sa.String(255), nullable=False),
        sa.Column("session_id", sa.String(255), nullable=False),
        sa.Column("client_id", sa.String(255), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.Column("last_seen_at", sa.BigInteger(), nullable=False),
        sa.Column("idle_expires_at", sa.BigInteger(), nullable=False),
        sa.Column("revoked_at", sa.BigInteger(), nullable=True),
        sa.CheckConstraint("expires_at > created_at", name="sp_positive_lifetime"),
        sa.CheckConstraint("idle_expires_at <= expires_at", name="sp_idle_absolute_ceiling"),
        sa.CheckConstraint(
            "last_seen_at >= created_at AND idle_expires_at > last_seen_at",
            name="sp_activity_lifetime",
        ),
    )
    op.execute("""
        CREATE FUNCTION sp_session_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF (to_jsonb(NEW) - ARRAY['last_seen_at', 'idle_expires_at', 'revoked_at',
                                     'encrypted_access_token', 'encrypted_refresh_token'])
                IS DISTINCT FROM
                (to_jsonb(OLD) - ARRAY['last_seen_at', 'idle_expires_at', 'revoked_at',
                                     'encrypted_access_token', 'encrypted_refresh_token']) THEN
                RAISE EXCEPTION 'SP authentication evidence and absolute lifetime are immutable';
            END IF;
            IF OLD.revoked_at IS NOT NULL AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
                RAISE EXCEPTION 'Local revocation is irreversible';
            END IF;
            IF NEW.last_seen_at < OLD.last_seen_at THEN
                RAISE EXCEPTION 'SP activity cannot move backwards';
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute(
        "CREATE TRIGGER guard_sp_session BEFORE UPDATE ON sp_authentication_sessions "
        "FOR EACH ROW EXECUTE FUNCTION sp_session_guard()"
    )


def downgrade() -> None:
    op.drop_table("sp_authentication_sessions")
    op.execute("DROP FUNCTION sp_session_guard()")
