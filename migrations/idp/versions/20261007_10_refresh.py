"""Immutable rotating refresh ancestry, signed renewal evidence, and enabled default profiles."""

import sqlalchemy as sa
from alembic import op

revision = "idp_refresh_10"
down_revision = "idp_compromise_control_09"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "refresh_credentials", sa.Column("predecessor_digest", sa.String(64), nullable=True)
    )
    op.create_foreign_key(
        "refresh_predecessor",
        "refresh_credentials",
        "refresh_credentials",
        ["predecessor_digest"],
        ["token_digest"],
    )
    op.create_unique_constraint(
        "one_refresh_successor", "refresh_credentials", ["predecessor_digest"]
    )
    op.execute("""
        CREATE FUNCTION refresh_ancestry_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NEW.generation=0 AND NEW.predecessor_digest IS NOT NULL OR
               NEW.generation>0 AND NOT EXISTS (
                   SELECT 1 FROM refresh_credentials p WHERE p.token_digest=NEW.predecessor_digest
                   AND p.family_id=NEW.family_id AND p.generation+1=NEW.generation
                   AND p.consumed_at IS NOT NULL
               ) THEN
                RAISE EXCEPTION 'Refresh issuance requires a consumed bound predecessor';
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute(
        "CREATE TRIGGER guard_refresh_ancestry BEFORE INSERT ON refresh_credentials "
        "FOR EACH ROW EXECUTE FUNCTION refresh_ancestry_guard()"
    )
    op.create_table(
        "refresh_issuances",
        sa.Column("token_id", sa.String(255), primary_key=True),
        sa.Column("token_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("family_id", sa.String(255), nullable=False),
        sa.Column("grant_id", sa.String(255), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column(
            "predecessor_digest",
            sa.String(64),
            sa.ForeignKey("refresh_credentials.token_digest"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "successor_digest",
            sa.String(64),
            sa.ForeignKey("refresh_credentials.token_digest"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "access_digest",
            sa.String(64),
            sa.ForeignKey("access_credentials.token_digest"),
            nullable=False,
            unique=True,
        ),
        sa.Column(
            "signing_key_id", sa.String(255), sa.ForeignKey("signing_trust.key_id"), nullable=False
        ),
        sa.Column("issued_at", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
        sa.ForeignKeyConstraint(
            ["family_id", "grant_id"], ["refresh_families.family_id", "refresh_families.grant_id"]
        ),
        sa.UniqueConstraint("family_id", "generation", name="one_signed_refresh_generation"),
        sa.CheckConstraint(
            "generation > 0 AND expires_at > issued_at", name="refresh_evidence_lifetime"
        ),
    )
    op.execute(
        "CREATE TRIGGER immutable_refresh_issuances BEFORE UPDATE OR DELETE ON refresh_issuances "
        "FOR EACH ROW EXECUTE FUNCTION immutable_security_fact()"
    )
    op.execute("""
        CREATE FUNCTION complete_refresh_issuance() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM refresh_credentials p JOIN refresh_credentials n
                ON n.predecessor_digest=p.token_digest
                JOIN access_credentials a ON a.family_id=n.family_id
                JOIN signed_artifacts s ON s.artifact_id=NEW.token_id
                WHERE p.token_digest=NEW.predecessor_digest AND p.consumed_at IS NOT NULL
                AND n.token_digest=NEW.successor_digest AND n.family_id=NEW.family_id
                AND n.generation=NEW.generation AND a.token_digest=NEW.access_digest
                AND a.grant_id=NEW.grant_id AND s.key_id=NEW.signing_key_id
                AND s.purpose='id_token' AND s.issued_at=NEW.issued_at
                AND s.expires_at=NEW.expires_at
            ) THEN
                RAISE EXCEPTION 'Refresh publication requires committed rotation and evidence';
            END IF;
            RETURN NULL;
        END $$
    """)
    op.execute(
        "CREATE CONSTRAINT TRIGGER complete_refresh_issuance AFTER INSERT ON refresh_issuances "
        "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION complete_refresh_issuance()"
    )
    # Upgrade the original A/B code-only default once; preserve state, destinations,
    # customized capability sets, and registered non-default clients.
    op.execute("""
        UPDATE clients SET allowed_grants='["authorization_code","refresh_token"]'
        WHERE client_id IN ('sp-a','sp-b')
          AND allowed_grants::jsonb='["authorization_code"]'::jsonb
          AND allowed_scopes::jsonb='["openid"]'::jsonb
    """)


def downgrade() -> None:
    op.drop_table("refresh_issuances")
    op.execute("DROP FUNCTION complete_refresh_issuance()")
    op.execute("DROP TRIGGER guard_refresh_ancestry ON refresh_credentials")
    op.execute("DROP FUNCTION refresh_ancestry_guard()")
    op.drop_constraint("one_refresh_successor", "refresh_credentials", type_="unique")
    op.drop_constraint("refresh_predecessor", "refresh_credentials", type_="foreignkey")
    op.drop_column("refresh_credentials", "predecessor_digest")
