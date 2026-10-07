"""Durable client recovery barriers and complete atomic signer-containment audit."""

import sqlalchemy as sa
from alembic import op

revision = "idp_compromise_control_09"
down_revision = "idp_signing_rotation_08"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("clients", sa.Column("compromised_key_id", sa.String(128), nullable=True))
    op.create_check_constraint(
        "client_compromise_requires_replacement",
        "clients",
        "NOT enabled OR compromised_key_id IS NULL OR key_id <> compromised_key_id",
    )
    op.execute("""
        CREATE FUNCTION client_compromise_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.compromised_key_id IS DISTINCT FROM OLD.compromised_key_id AND (
                NEW.compromised_key_id IS NULL OR NEW.compromised_key_id <> OLD.key_id
                OR NEW.key_id <> OLD.key_id OR NEW.enabled
            ) THEN
                RAISE EXCEPTION 'Compromise history cannot be cleared or bypassed';
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute(
        "CREATE TRIGGER guard_client_compromise BEFORE UPDATE ON clients "
        "FOR EACH ROW EXECUTE FUNCTION client_compromise_guard()"
    )
    op.add_column("signing_audit", sa.Column("replacement_key_id", sa.String(255), nullable=True))


def downgrade() -> None:
    op.drop_column("signing_audit", "replacement_key_id")
    op.execute("DROP TRIGGER guard_client_compromise ON clients")
    op.execute("DROP FUNCTION client_compromise_guard()")
    op.drop_constraint("client_compromise_requires_replacement", "clients", type_="check")
    op.drop_column("clients", "compromised_key_id")
