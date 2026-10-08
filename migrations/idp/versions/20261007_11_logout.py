"""Leased, fenced, recoverable logout delivery and original A/B logout metadata."""

import sqlalchemy as sa
from alembic import op

revision = "idp_logout_11"
down_revision = "idp_refresh_10"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for column in (
        sa.Column("lease_id", sa.String(36), nullable=True),
        sa.Column("lease_expires_at", sa.BigInteger(), nullable=True),
        sa.Column("token_id", sa.String(255), nullable=True),
        sa.Column("token_expires_at", sa.BigInteger(), nullable=True),
        sa.Column("signing_key_id", sa.String(255), nullable=True),
        sa.Column("completed_at", sa.BigInteger(), nullable=True),
        sa.Column("last_error", sa.String(32), nullable=True),
    ):
        op.add_column("logout_outbox", column)
    op.create_foreign_key(
        "logout_delivery_signer", "logout_outbox", "signing_trust", ["signing_key_id"], ["key_id"]
    )
    op.create_check_constraint(
        "logout_delivery_state",
        "logout_outbox",
        "status IN ('pending','delivered','failed','skipped') AND attempts >= 0 "
        "AND (lease_id IS NULL) = (lease_expires_at IS NULL)",
    )
    op.create_index("logout_due_deliveries", "logout_outbox", ["status", "next_attempt_at"])
    # Enable only the original, uncustomized A/B profile. Registry triggers bump
    # versions, invalidating old pending codes without resetting established trust.
    op.execute("""
        UPDATE clients SET
            backchannel_logout_uri = regexp_replace(redirect_uris->>0,
                '/auth/callback$', '/backchannel-logout'),
            post_logout_redirect_uris = json_build_array(regexp_replace(redirect_uris->>0,
                '/auth/callback$', '/'))
        WHERE client_id IN ('sp-a','sp-b') AND backchannel_logout_uri IS NULL
            AND post_logout_redirect_uris::jsonb = '[]'::jsonb
            AND json_array_length(redirect_uris) = 1
            AND redirect_uris->>0 ~ ('^https://' || client_id ||
                '\\.localhost(:[0-9]+)?/auth/callback$')
    """)
    op.execute("""
        UPDATE logout_outbox AS delivery SET destination = client.backchannel_logout_uri
        FROM clients AS client WHERE delivery.client_id = client.client_id
            AND delivery.destination IS NULL AND delivery.status = 'pending'
    """)
    op.execute("""
        UPDATE logout_outbox SET status = 'skipped', last_error = 'no_destination'
        WHERE destination IS NULL AND status = 'pending'
    """)
    op.execute("""
        UPDATE logout_outbox SET status = 'failed', last_error = 'unbound_intent'
        WHERE status = 'pending' AND (issuer IS NULL OR session_id IS NULL OR client_id IS NULL)
    """)
    op.execute("""
        CREATE FUNCTION logout_delivery_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.delivery_id IS DISTINCT FROM OLD.delivery_id
                OR NEW.issuer IS DISTINCT FROM OLD.issuer
                OR NEW.session_id IS DISTINCT FROM OLD.session_id
                OR NEW.client_id IS DISTINCT FROM OLD.client_id
                OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION 'Logout delivery identity is immutable';
            END IF;
            IF OLD.status = 'delivered' AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
                RAISE EXCEPTION 'Acknowledged logout delivery is terminal';
            END IF;
            IF NEW.attempts < OLD.attempts AND NOT
                (OLD.status IN ('failed','skipped') AND NEW.status = 'pending') THEN
                RAISE EXCEPTION 'Logout attempts reset only on explicit recovery';
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute(
        "CREATE TRIGGER guard_logout_delivery BEFORE UPDATE ON logout_outbox "
        "FOR EACH ROW EXECUTE FUNCTION logout_delivery_guard()"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER guard_logout_delivery ON logout_outbox")
    op.execute("DROP FUNCTION logout_delivery_guard()")
    op.drop_index("logout_due_deliveries", table_name="logout_outbox")
    op.drop_constraint("logout_delivery_state", "logout_outbox", type_="check")
    op.drop_constraint("logout_delivery_signer", "logout_outbox", type_="foreignkey")
    for name in (
        "last_error",
        "completed_at",
        "signing_key_id",
        "token_expires_at",
        "token_id",
        "lease_expires_at",
        "lease_id",
    ):
        op.drop_column("logout_outbox", name)
