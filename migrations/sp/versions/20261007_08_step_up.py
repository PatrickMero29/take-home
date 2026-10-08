"""Durable evidence of an assurance/recency-enforced sensitive operation."""

import sqlalchemy as sa
from alembic import op

revision = "sp_step_up_08"
down_revision = "sp_logout_07"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "sensitive_operations",
        sa.Column("operation_id", sa.String(36), primary_key=True),
        sa.Column(
            "token_digest",
            sa.String(64),
            sa.ForeignKey("sp_authentication_sessions.token_digest"),
            nullable=False,
        ),
        sa.Column("encrypted_evidence", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
    )
    op.execute("""
        CREATE FUNCTION immutable_sensitive_operation() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'Sensitive operation evidence is immutable';
        END $$
    """)
    op.execute(
        "CREATE TRIGGER immutable_sensitive_operations BEFORE UPDATE OR DELETE "
        "ON sensitive_operations "
        "FOR EACH ROW EXECUTE FUNCTION immutable_sensitive_operation()"
    )


def downgrade() -> None:
    op.drop_table("sensitive_operations")
    op.execute("DROP FUNCTION immutable_sensitive_operation()")
