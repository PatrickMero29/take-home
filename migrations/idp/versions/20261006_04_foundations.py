"""Seeded user credentials and immutable runtime encryption-key custody."""

import sqlalchemy as sa
from alembic import op

revision = "idp_foundations_04"
down_revision = "idp_protocol_lineage_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("subject", sa.String(255), primary_key=True),
        sa.Column("username", sa.String(32), nullable=False, unique=True),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.CheckConstraint("username ~ '^[a-z][a-z0-9_-]{0,31}$'", name="user_username_profile"),
        sa.CheckConstraint("created_at > 0", name="user_creation_positive"),
    )
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
    op.execute("""
        CREATE FUNCTION user_identity_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.subject IS DISTINCT FROM OLD.subject
                OR NEW.username IS DISTINCT FROM OLD.username
                OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION 'Stable user identity is immutable';
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute(
        "CREATE TRIGGER guard_user_identity BEFORE UPDATE ON users "
        "FOR EACH ROW EXECUTE FUNCTION user_identity_guard()"
    )


def downgrade() -> None:
    op.drop_table("runtime_key_binding")
    op.execute("DROP FUNCTION runtime_binding_guard()")
    op.drop_table("users")
    op.execute("DROP FUNCTION user_identity_guard()")
