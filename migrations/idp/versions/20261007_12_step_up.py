"""Encrypted TOTP, immutable accepted counters, and durable authentication throttling."""

import sqlalchemy as sa
from alembic import op

revision = "idp_step_up_12"
down_revision = "idp_logout_11"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "totp_credentials",
        sa.Column("subject", sa.String(255), sa.ForeignKey("users.subject"), primary_key=True),
        sa.Column("encrypted_secret", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("last_accepted_counter", sa.BigInteger(), nullable=False, server_default="-1"),
        sa.CheckConstraint("last_accepted_counter >= -1", name="totp_counter_floor"),
    )
    op.create_table(
        "totp_consumptions",
        sa.Column(
            "subject", sa.String(255), sa.ForeignKey("totp_credentials.subject"), primary_key=True
        ),
        sa.Column("counter", sa.BigInteger(), primary_key=True),
        sa.Column(
            "event_id",
            sa.String(255),
            sa.ForeignKey("authentication_events.event_id"),
            nullable=False,
            unique=True,
        ),
        sa.Column("accepted_at", sa.BigInteger(), nullable=False),
        sa.CheckConstraint("counter >= 0 AND accepted_at > 0", name="totp_consumption_times"),
    )
    op.create_table(
        "authentication_limits",
        sa.Column("bucket_digest", sa.String(64), primary_key=True),
        sa.Column("window_started_at", sa.BigInteger(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.CheckConstraint("attempts >= 0", name="authentication_attempts_nonnegative"),
    )
    op.execute("""
        CREATE FUNCTION totp_credential_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF (to_jsonb(NEW) - 'last_accepted_counter') IS DISTINCT FROM
                (to_jsonb(OLD) - 'last_accepted_counter') THEN
                RAISE EXCEPTION 'TOTP credential identity and custody are immutable';
            END IF;
            IF NEW.last_accepted_counter < OLD.last_accepted_counter THEN
                RAISE EXCEPTION 'TOTP replay protection is irreversible';
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute(
        "CREATE TRIGGER guard_totp_credential BEFORE UPDATE ON totp_credentials "
        "FOR EACH ROW EXECUTE FUNCTION totp_credential_guard()"
    )
    op.execute(
        "CREATE TRIGGER immutable_totp_consumptions BEFORE UPDATE OR DELETE ON totp_consumptions "
        "FOR EACH ROW EXECUTE FUNCTION immutable_security_fact()"
    )
    op.execute("""
        CREATE FUNCTION totp_event_binding() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM authentication_events AS event
                JOIN idp_security_sessions AS parent USING (session_id)
                WHERE event.event_id = NEW.event_id AND parent.subject = NEW.subject
                AND event.assurance = 'urn:take-home:acr:password-totp'
                AND event.methods::jsonb = '["pwd","otp"]'::jsonb) THEN
                RAISE EXCEPTION 'TOTP consumption must bind its subject and stronger event';
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute(
        "CREATE CONSTRAINT TRIGGER require_totp_event_binding AFTER INSERT ON totp_consumptions "
        "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION totp_event_binding()"
    )


def downgrade() -> None:
    op.drop_table("authentication_limits")
    op.drop_table("totp_consumptions")
    op.execute("DROP FUNCTION totp_event_binding()")
    op.drop_table("totp_credentials")
    op.execute("DROP FUNCTION totp_credential_guard()")
