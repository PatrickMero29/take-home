"""Separate operator authority, live versioned registration, and auditable credentials."""

import sqlalchemy as sa
from alembic import op

revision = "idp_operator_control_07"
down_revision = "idp_lifecycle_06"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for name, default in (
        ("allowed_grants", "'[\"authorization_code\"]'"),
        ("allowed_scopes", "'[\"openid\"]'"),
        ("post_logout_redirect_uris", "'[]'"),
    ):
        op.add_column(
            "clients", sa.Column(name, sa.JSON(), nullable=False, server_default=sa.text(default))
        )
    op.add_column(
        "clients",
        sa.Column(
            "token_endpoint_auth_method",
            sa.String(32),
            nullable=False,
            server_default="private_key_jwt",
        ),
    )
    op.add_column(
        "clients",
        sa.Column(
            "token_endpoint_auth_signing_alg", sa.String(16), nullable=False, server_default="RS256"
        ),
    )
    op.add_column(
        "clients",
        sa.Column("registration_version", sa.BigInteger(), nullable=False, server_default="1"),
    )
    op.add_column(
        "authorization_codes",
        sa.Column("client_version", sa.BigInteger(), nullable=True, server_default="1"),
    )
    # ALTER's constant default covers existing immutable proofs without issuing
    # an UPDATE that would violate the pre-existing protocol-code guard.
    op.execute("""
        CREATE FUNCTION client_registration_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.client_id IS DISTINCT FROM OLD.client_id THEN
                RAISE EXCEPTION 'Client identity is immutable';
            END IF;
            IF (to_jsonb(NEW) - 'registration_version') IS DISTINCT FROM
                (to_jsonb(OLD) - 'registration_version') THEN
                NEW.registration_version := OLD.registration_version + 1;
            ELSIF NEW.registration_version IS DISTINCT FROM OLD.registration_version THEN
                RAISE EXCEPTION 'Registration version changes require metadata changes';
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute(
        "CREATE TRIGGER guard_client_registration BEFORE UPDATE ON clients "
        "FOR EACH ROW EXECUTE FUNCTION client_registration_guard()"
    )
    op.create_table(
        "operators",
        sa.Column("operator_id", sa.String(255), primary_key=True),
        sa.Column("username", sa.String(32), nullable=False, unique=True),
        sa.Column("password_hash", sa.Text(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("permissions", sa.JSON(), nullable=False),
        sa.Column("credential_version", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.CheckConstraint("credential_version > 0", name="operator_positive_version"),
    )
    op.execute("""
        CREATE FUNCTION operator_identity_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.operator_id IS DISTINCT FROM OLD.operator_id
                OR NEW.username IS DISTINCT FROM OLD.username
                OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
                RAISE EXCEPTION 'Operator identity is immutable';
            END IF;
            IF NEW.password_hash IS DISTINCT FROM OLD.password_hash
                OR NEW.enabled IS DISTINCT FROM OLD.enabled
                OR to_jsonb(NEW.permissions) IS DISTINCT FROM to_jsonb(OLD.permissions) THEN
                NEW.credential_version := OLD.credential_version + 1;
            ELSIF NEW.credential_version IS DISTINCT FROM OLD.credential_version THEN
                RAISE EXCEPTION 'Operator credential version cannot be reset';
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute(
        "CREATE TRIGGER guard_operator_identity BEFORE UPDATE ON operators "
        "FOR EACH ROW EXECUTE FUNCTION operator_identity_guard()"
    )
    op.create_table(
        "operator_sessions",
        sa.Column(
            "token_digest",
            sa.String(64),
            sa.ForeignKey("browser_sessions.token_digest", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "operator_id", sa.String(255), sa.ForeignKey("operators.operator_id"), nullable=False
        ),
        sa.Column("credential_version", sa.BigInteger(), nullable=False),
        sa.Column("channel", sa.String(16), nullable=False),
        sa.CheckConstraint("channel IN ('browser','api')", name="operator_session_channel"),
    )
    op.create_table(
        "client_key_history",
        sa.Column("key_id", sa.String(128), primary_key=True),
        sa.Column("client_id", sa.String(255), sa.ForeignKey("clients.client_id"), nullable=False),
        sa.Column("public_key_pem", sa.Text(), nullable=False, unique=True),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
    )
    op.execute(
        "INSERT INTO client_key_history(key_id, client_id, public_key_pem, created_at) "
        "SELECT key_id, client_id, public_key_pem, EXTRACT(EPOCH FROM now())::bigint FROM clients"
    )
    op.create_table(
        "operator_audit",
        sa.Column("event_id", sa.String(255), primary_key=True),
        sa.Column(
            "operator_id", sa.String(255), sa.ForeignKey("operators.operator_id"), nullable=False
        ),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("client_id", sa.String(255), sa.ForeignKey("clients.client_id"), nullable=False),
        sa.Column("registration_version", sa.BigInteger(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
    )
    for table in ("operator_audit", "client_key_history"):
        op.execute(
            f"CREATE TRIGGER immutable_{table} BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION immutable_security_fact()"
        )


def downgrade() -> None:
    op.drop_table("operator_audit")
    op.drop_table("client_key_history")
    op.drop_table("operator_sessions")
    op.drop_table("operators")
    op.execute("DROP FUNCTION operator_identity_guard()")
    op.execute("DROP TRIGGER guard_client_registration ON clients")
    op.execute("DROP FUNCTION client_registration_guard()")
    op.drop_column("authorization_codes", "client_version")
    for name in (
        "registration_version",
        "token_endpoint_auth_signing_alg",
        "token_endpoint_auth_method",
        "post_logout_redirect_uris",
        "allowed_scopes",
        "allowed_grants",
    ):
        op.drop_column("clients", name)
