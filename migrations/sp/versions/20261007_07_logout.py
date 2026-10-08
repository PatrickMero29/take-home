"""Session-specific back-channel termination and transactional replay receipts."""

import sqlalchemy as sa
from alembic import op

revision = "sp_logout_07"
down_revision = "sp_refresh_06"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sp_logout_sessions",
        sa.Column("issuer", sa.Text(), primary_key=True),
        sa.Column("session_id", sa.String(255), primary_key=True),
        sa.Column("received_at", sa.BigInteger(), nullable=False),
    )
    op.create_table(
        "sp_logout_receipts",
        sa.Column("issuer", sa.Text(), primary_key=True),
        sa.Column("token_id", sa.String(255), primary_key=True),
        sa.Column("token_digest", sa.String(64), nullable=False),
        sa.Column("session_id", sa.String(255), nullable=False),
        sa.Column("issued_at", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.Column("received_at", sa.BigInteger(), nullable=False),
        sa.CheckConstraint("expires_at > issued_at", name="logout_receipt_positive_lifetime"),
    )
    op.create_index(
        "sp_session_logout_match", "sp_authentication_sessions", ["session_id", "client_id"]
    )
    op.execute("""
        CREATE FUNCTION immutable_sp_logout() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'Logout termination and replay receipts are immutable';
        END $$
    """)
    for table in ("sp_logout_sessions", "sp_logout_receipts"):
        op.execute(
            f"CREATE TRIGGER immutable_{table} BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION immutable_sp_logout()"
        )


def downgrade() -> None:
    op.drop_index("sp_session_logout_match", table_name="sp_authentication_sessions")
    op.drop_table("sp_logout_receipts")
    op.drop_table("sp_logout_sessions")
    op.execute("DROP FUNCTION immutable_sp_logout()")
