"""Immutable runtime encryption-key binding for each independently owned SP database."""

import sqlalchemy as sa
from alembic import op

revision = "sp_foundations_03"
down_revision = "sp_security_model_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "runtime_key_binding",
        sa.Column("binding_id", sa.Integer(), primary_key=True),
        sa.Column("service_id", sa.String(16), nullable=False),
        sa.Column("encrypted_check", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.CheckConstraint("binding_id=1", name="runtime_binding_singleton"),
    )
    op.execute("""
        CREATE FUNCTION runtime_binding_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'Runtime encryption binding is immutable';
        END $$
    """)
    op.execute(
        "CREATE TRIGGER guard_runtime_binding BEFORE UPDATE OR DELETE ON runtime_key_binding "
        "FOR EACH ROW EXECUTE FUNCTION runtime_binding_guard()"
    )


def downgrade() -> None:
    op.drop_table("runtime_key_binding")
    op.execute("DROP FUNCTION runtime_binding_guard()")
