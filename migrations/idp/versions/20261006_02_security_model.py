"""Normalized authentication lineage, trust states, token families, and bound logout intents."""

import sqlalchemy as sa
from alembic import op

revision = "idp_security_model_02"
down_revision = "idp_architecture_01"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("clients", sa.Column("backchannel_logout_uri", sa.Text(), nullable=True))
    op.create_table(
        "security_gate",
        sa.Column("gate_id", sa.Integer(), primary_key=True),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.CheckConstraint("gate_id=1", name="security_gate_singleton"),
        sa.CheckConstraint("revision >= 0", name="security_revision_nonnegative"),
    )
    op.execute("INSERT INTO security_gate(gate_id, revision) VALUES (1, 0)")
    op.create_table(
        "signing_trust",
        sa.Column("key_id", sa.String(255), primary_key=True),
        sa.Column("public_key_pem", sa.Text(), nullable=False),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("verification_deadline", sa.BigInteger(), nullable=False),
        sa.CheckConstraint(
            "state IN ('prepared','active','draining','retired','revoked')",
            name="signing_trust_state",
        ),
        sa.CheckConstraint("verification_deadline >= 0", name="signing_deadline_nonnegative"),
    )
    op.create_index(
        "one_active_signer",
        "signing_trust",
        ["state"],
        unique=True,
        postgresql_where=sa.text("state='active'"),
    )
    op.create_table(
        "idp_security_sessions",
        sa.Column("session_id", sa.String(255), primary_key=True),
        sa.Column("issuer", sa.Text(), nullable=False),
        sa.Column("subject", sa.String(255), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.Column("revoked_at", sa.BigInteger(), nullable=True),
        sa.Column("revocation_reason", sa.String(32), nullable=True),
        sa.CheckConstraint("expires_at > created_at", name="idp_session_positive_lifetime"),
        sa.CheckConstraint(
            "(revoked_at IS NULL) = (revocation_reason IS NULL)",
            name="idp_session_revocation_pair",
        ),
    )
    op.create_table(
        "authentication_events",
        sa.Column("event_id", sa.String(255), primary_key=True),
        sa.Column(
            "session_id",
            sa.String(255),
            sa.ForeignKey("idp_security_sessions.session_id"),
            nullable=False,
        ),
        sa.Column("authenticated_at", sa.BigInteger(), nullable=False),
        sa.Column("assurance", sa.String(255), nullable=False),
        sa.Column("methods", sa.JSON(), nullable=False),
        sa.UniqueConstraint("event_id", "session_id", name="event_session_binding"),
    )
    op.create_table(
        "federation_grants",
        sa.Column("grant_id", sa.String(255), primary_key=True),
        sa.Column("client_id", sa.String(255), sa.ForeignKey("clients.client_id"), nullable=False),
        sa.Column(
            "session_id",
            sa.String(255),
            sa.ForeignKey("idp_security_sessions.session_id"),
            nullable=False,
        ),
        sa.Column("event_id", sa.String(255), nullable=False),
        sa.Column(
            "root_signing_key_id",
            sa.String(255),
            sa.ForeignKey("signing_trust.key_id"),
            nullable=False,
        ),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.Column("revoked_at", sa.BigInteger(), nullable=True),
        sa.Column("revocation_reason", sa.String(32), nullable=True),
        sa.ForeignKeyConstraint(
            ["event_id", "session_id"],
            ["authentication_events.event_id", "authentication_events.session_id"],
            name="grant_event_session_binding",
        ),
        sa.CheckConstraint("expires_at > created_at", name="grant_positive_lifetime"),
        sa.CheckConstraint(
            "(revoked_at IS NULL) = (revocation_reason IS NULL)", name="grant_revocation_pair"
        ),
        sa.UniqueConstraint("grant_id", "root_signing_key_id", name="grant_signing_binding"),
    )
    op.create_table(
        "authentication_evidence",
        sa.Column("token_id", sa.String(255), primary_key=True),
        sa.Column(
            "grant_id",
            sa.String(255),
            sa.ForeignKey("federation_grants.grant_id"),
            unique=True,
            nullable=False,
        ),
        sa.Column("token_digest", sa.String(64), nullable=False, unique=True),
        sa.Column(
            "signing_key_id", sa.String(255), sa.ForeignKey("signing_trust.key_id"), nullable=False
        ),
        sa.Column("issued_at", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.CheckConstraint("expires_at > issued_at", name="evidence_positive_lifetime"),
        sa.ForeignKeyConstraint(
            ["grant_id", "signing_key_id"],
            ["federation_grants.grant_id", "federation_grants.root_signing_key_id"],
            name="evidence_grant_signing_binding",
        ),
    )
    op.create_table(
        "refresh_families",
        sa.Column("family_id", sa.String(255), primary_key=True),
        sa.Column(
            "grant_id",
            sa.String(255),
            sa.ForeignKey("federation_grants.grant_id"),
            unique=True,
            nullable=False,
        ),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("revoked_at", sa.BigInteger(), nullable=True),
        sa.CheckConstraint("expires_at > created_at", name="family_positive_lifetime"),
        sa.CheckConstraint("generation >= 0", name="family_generation_nonnegative"),
        sa.UniqueConstraint("family_id", "grant_id", name="family_grant_binding"),
    )
    op.create_table(
        "refresh_credentials",
        sa.Column("token_digest", sa.String(64), primary_key=True),
        sa.Column(
            "family_id", sa.String(255), sa.ForeignKey("refresh_families.family_id"), nullable=False
        ),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("issued_at", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.Column("consumed_at", sa.BigInteger(), nullable=True),
        sa.UniqueConstraint("family_id", "generation", name="refresh_family_generation"),
        sa.CheckConstraint("generation >= 0", name="refresh_generation_nonnegative"),
        sa.CheckConstraint("expires_at > issued_at", name="refresh_positive_lifetime"),
    )
    op.create_table(
        "access_credentials",
        sa.Column("token_digest", sa.String(64), primary_key=True),
        sa.Column(
            "grant_id", sa.String(255), sa.ForeignKey("federation_grants.grant_id"), nullable=False
        ),
        sa.Column(
            "family_id", sa.String(255), sa.ForeignKey("refresh_families.family_id"), nullable=False
        ),
        sa.Column("issued_at", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.CheckConstraint("expires_at > issued_at", name="access_positive_lifetime"),
        sa.ForeignKeyConstraint(
            ["family_id", "grant_id"],
            ["refresh_families.family_id", "refresh_families.grant_id"],
            name="access_family_grant_binding",
        ),
    )
    op.alter_column("logout_outbox", "destination", existing_type=sa.Text(), nullable=True)
    op.add_column("logout_outbox", sa.Column("issuer", sa.Text(), nullable=True))
    op.add_column("logout_outbox", sa.Column("session_id", sa.String(255), nullable=True))
    op.add_column("logout_outbox", sa.Column("client_id", sa.String(255), nullable=True))
    op.create_foreign_key(
        "logout_session_lineage",
        "logout_outbox",
        "idp_security_sessions",
        ["session_id"],
        ["session_id"],
    )
    op.create_foreign_key(
        "logout_client_recipient", "logout_outbox", "clients", ["client_id"], ["client_id"]
    )
    op.create_unique_constraint(
        "one_logout_intent_per_recipient", "logout_outbox", ["session_id", "client_id"]
    )
    op.execute("""
        CREATE FUNCTION immutable_security_fact() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'Authentication facts and issuance evidence are immutable';
        END $$
    """)
    for table in ("authentication_events", "authentication_evidence", "access_credentials"):
        op.execute(
            f"CREATE TRIGGER immutable_{table} BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION immutable_security_fact()"
        )
    op.execute("""
        CREATE FUNCTION security_lifecycle_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF (to_jsonb(NEW) - string_to_array(TG_ARGV[0], ','))
                IS DISTINCT FROM (to_jsonb(OLD) - string_to_array(TG_ARGV[0], ',')) THEN
                RAISE EXCEPTION 'Security lineage and absolute lifetime are immutable';
            END IF;
            IF OLD.revoked_at IS NOT NULL AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
                RAISE EXCEPTION 'Revocation is irreversible';
            END IF;
            RETURN NEW;
        END $$
    """)
    for table, mutable in (
        ("idp_security_sessions", "revoked_at,revocation_reason"),
        ("federation_grants", "revoked_at,revocation_reason"),
        ("refresh_families", "generation,revoked_at"),
    ):
        op.execute(
            f"CREATE TRIGGER guard_{table} BEFORE UPDATE ON {table} FOR EACH ROW "
            f"EXECUTE FUNCTION security_lifecycle_guard('{mutable}')"
        )
    op.execute("""
        CREATE FUNCTION signing_trust_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF (to_jsonb(NEW) - ARRAY['state', 'verification_deadline'])
                IS DISTINCT FROM (to_jsonb(OLD) - ARRAY['state', 'verification_deadline']) THEN
                RAISE EXCEPTION 'Signing key identity is immutable';
            END IF;
            IF NEW.verification_deadline < OLD.verification_deadline THEN
                RAISE EXCEPTION 'Verification retention cannot shrink';
            END IF;
            IF OLD.state = 'revoked' AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
                RAISE EXCEPTION 'Key revocation is irreversible';
            END IF;
            IF NEW.state IS DISTINCT FROM OLD.state AND NOT (
                (OLD.state = 'prepared' AND NEW.state IN ('active', 'revoked')) OR
                (OLD.state = 'active' AND NEW.state IN ('draining', 'revoked')) OR
                (OLD.state = 'draining' AND NEW.state IN ('retired', 'revoked')) OR
                (OLD.state = 'retired' AND NEW.state = 'revoked')
            ) THEN
                RAISE EXCEPTION 'Invalid signing trust transition';
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute(
        "CREATE TRIGGER guard_signing_trust BEFORE UPDATE ON signing_trust "
        "FOR EACH ROW EXECUTE FUNCTION signing_trust_guard()"
    )
    op.execute("""
        CREATE FUNCTION refresh_consumption_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF (to_jsonb(NEW) - 'consumed_at') IS DISTINCT FROM (to_jsonb(OLD) - 'consumed_at') THEN
                RAISE EXCEPTION 'Refresh credential identity and lifetime are immutable';
            END IF;
            IF OLD.consumed_at IS NOT NULL AND NEW.consumed_at IS DISTINCT FROM OLD.consumed_at THEN
                RAISE EXCEPTION 'Refresh consumption is irreversible';
            END IF;
            IF NEW.consumed_at < NEW.issued_at THEN
                RAISE EXCEPTION 'Refresh consumption cannot precede issuance';
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute(
        "CREATE TRIGGER guard_refresh_consumption BEFORE UPDATE ON refresh_credentials "
        "FOR EACH ROW EXECUTE FUNCTION refresh_consumption_guard()"
    )


def downgrade() -> None:
    op.drop_constraint("one_logout_intent_per_recipient", "logout_outbox", type_="unique")
    op.drop_constraint("logout_session_lineage", "logout_outbox", type_="foreignkey")
    op.drop_constraint("logout_client_recipient", "logout_outbox", type_="foreignkey")
    op.execute("DELETE FROM logout_outbox WHERE destination IS NULL")
    op.alter_column("logout_outbox", "destination", existing_type=sa.Text(), nullable=False)
    for column in ("client_id", "session_id", "issuer"):
        op.drop_column("logout_outbox", column)
    for table in (
        "access_credentials",
        "refresh_credentials",
        "refresh_families",
        "authentication_evidence",
        "federation_grants",
        "authentication_events",
        "idp_security_sessions",
        "signing_trust",
        "security_gate",
    ):
        op.drop_table(table)
    op.execute("DROP FUNCTION immutable_security_fact()")
    op.execute("DROP FUNCTION security_lifecycle_guard()")
    op.execute("DROP FUNCTION signing_trust_guard()")
    op.execute("DROP FUNCTION refresh_consumption_guard()")
    op.drop_column("clients", "backchannel_logout_uri")
