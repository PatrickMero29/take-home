"""Durable issuer private material, publication marker, and generic signed-artifact retention."""

import sqlalchemy as sa
from alembic import op

revision = "idp_signing_rotation_08"
down_revision = "idp_operator_control_07"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("signing_trust", sa.Column("published_at", sa.BigInteger(), nullable=True))
    op.create_table(
        "signing_key_material",
        sa.Column(
            "key_id", sa.String(255), sa.ForeignKey("signing_trust.key_id"), primary_key=True
        ),
        sa.Column("encrypted_private_key", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
    )
    op.create_table(
        "signed_artifacts",
        sa.Column("artifact_id", sa.String(255), primary_key=True),
        sa.Column("key_id", sa.String(255), sa.ForeignKey("signing_trust.key_id"), nullable=False),
        sa.Column("purpose", sa.String(32), nullable=False),
        sa.Column("client_id", sa.String(255), sa.ForeignKey("clients.client_id"), nullable=False),
        sa.Column("issued_at", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.CheckConstraint("expires_at > issued_at", name="signed_artifact_positive_lifetime"),
        sa.CheckConstraint(
            "purpose IN ('id_token','logout_token')", name="signed_artifact_purpose"
        ),
    )
    op.execute("""
        INSERT INTO signed_artifacts(artifact_id,key_id,purpose,client_id,issued_at,expires_at)
        SELECT e.token_id,e.signing_key_id,'id_token',g.client_id,e.issued_at,e.expires_at
        FROM authentication_evidence e JOIN federation_grants g ON g.grant_id=e.grant_id
    """)
    op.create_table(
        "signing_audit",
        sa.Column("event_id", sa.String(255), primary_key=True),
        sa.Column(
            "operator_id", sa.String(255), sa.ForeignKey("operators.operator_id"), nullable=False
        ),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("key_id", sa.String(255), sa.ForeignKey("signing_trust.key_id"), nullable=False),
        sa.Column("previous_active_key_id", sa.String(255), nullable=True),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
    )
    for table in ("signing_key_material", "signed_artifacts", "signing_audit"):
        op.execute(
            f"CREATE TRIGGER immutable_{table} BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION immutable_security_fact()"
        )
    op.execute("""
        CREATE OR REPLACE FUNCTION signing_trust_guard()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF (to_jsonb(NEW) - ARRAY['state','verification_deadline','published_at'])
                IS DISTINCT FROM
                (to_jsonb(OLD) - ARRAY['state','verification_deadline','published_at']) THEN
                RAISE EXCEPTION 'Signing key identity is immutable';
            END IF;
            IF NEW.verification_deadline < OLD.verification_deadline THEN
                RAISE EXCEPTION 'Verification retention cannot shrink';
            END IF;
            IF OLD.published_at IS NOT NULL AND NEW.published_at IS DISTINCT FROM OLD.published_at
                OR NEW.published_at < NEW.created_at THEN
                RAISE EXCEPTION 'Signing key publication is irreversible';
            END IF;
            IF OLD.state = 'revoked' AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
                RAISE EXCEPTION 'Key revocation is irreversible';
            END IF;
            IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
                (OLD.state = 'prepared' AND NEW.state IN ('active','revoked')) OR
                (OLD.state = 'active' AND NEW.state IN ('draining','revoked')) OR
                (OLD.state = 'draining' AND NEW.state IN ('retired','revoked')) OR
                (OLD.state = 'retired' AND NEW.state = 'revoked')
            ) THEN
                RAISE EXCEPTION 'Invalid signing trust transition';
            END IF;
            RETURN NEW;
        END $$
    """)
    # Only the existing fully privileged seeded operator gains the new explicit
    # capability. Customized read-only/disabled accounts are preserved.
    op.execute("""
        UPDATE operators SET permissions='["clients:read","clients:write","keys:read","keys:write"]'
        WHERE username='operator' AND enabled
          AND permissions::jsonb='["clients:read","clients:write"]'::jsonb
    """)


def downgrade() -> None:
    # Keep the guard valid while removing its publication column. The current
    # expression's JSON subtraction is intentionally tolerant of an absent key.
    op.drop_table("signing_audit")
    op.drop_table("signed_artifacts")
    op.drop_table("signing_key_material")
    op.execute("""
        CREATE OR REPLACE FUNCTION signing_trust_guard()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF (to_jsonb(NEW) - ARRAY['state','verification_deadline'])
                IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['state','verification_deadline']) THEN
                RAISE EXCEPTION 'Signing key identity is immutable';
            END IF;
            IF NEW.verification_deadline < OLD.verification_deadline THEN
                RAISE EXCEPTION 'Verification retention cannot shrink';
            END IF;
            IF OLD.state='revoked' AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
                RAISE EXCEPTION 'Key revocation is irreversible';
            END IF;
            IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
                (OLD.state='prepared' AND NEW.state IN ('active','revoked')) OR
                (OLD.state='active' AND NEW.state IN ('draining','revoked')) OR
                (OLD.state='draining' AND NEW.state IN ('retired','revoked')) OR
                (OLD.state='retired' AND NEW.state='revoked')
            ) THEN
                RAISE EXCEPTION 'Invalid signing trust transition';
            END IF;
            RETURN NEW;
        END $$
    """)
    op.drop_column("signing_trust", "published_at")
