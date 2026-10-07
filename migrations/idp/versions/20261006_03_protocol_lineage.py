"""Bind protocol codes and committed token issuance to canonical security lineage."""

import sqlalchemy as sa
from alembic import op

revision = "idp_protocol_lineage_03"
down_revision = "idp_security_model_02"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Existing unbound prototype records remain history, never redeemable authority.
    op.add_column("authorization_codes", sa.Column("event_id", sa.String(255), nullable=True))
    op.create_foreign_key(
        "code_event_session_binding",
        "authorization_codes",
        "authentication_events",
        ["event_id", "sid"],
        ["event_id", "session_id"],
    )
    op.add_column("token_issuances", sa.Column("grant_id", sa.String(255), nullable=True))
    op.create_foreign_key(
        "protocol_grant_binding",
        "token_issuances",
        "federation_grants",
        ["grant_id"],
        ["grant_id"],
    )
    op.create_unique_constraint("one_protocol_issuance_per_grant", "token_issuances", ["grant_id"])
    op.execute("""
        CREATE FUNCTION protocol_code_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_OP = 'INSERT' THEN
                IF NEW.event_id IS NULL OR NOT EXISTS (
                    SELECT 1 FROM authentication_events e JOIN idp_security_sessions s
                    ON s.session_id=e.session_id
                    WHERE e.event_id=NEW.event_id AND e.session_id=NEW.sid AND s.subject=NEW.sub
                    AND e.authenticated_at=NEW.auth_time AND e.assurance=NEW.acr
                    AND e.methods::jsonb=NEW.amr::jsonb
                    AND NEW.expires_at > NEW.created_at AND NEW.expires_at <= s.expires_at
                    AND s.revoked_at IS NULL
                ) THEN
                    RAISE EXCEPTION 'A code requires matching persisted authentication lineage';
                END IF;
            ELSE
                IF (to_jsonb(NEW) - 'consumed_at')
                    IS DISTINCT FROM (to_jsonb(OLD) - 'consumed_at') THEN
                    RAISE EXCEPTION 'Code recipient, proof, lineage and lifetime are immutable';
                END IF;
                IF OLD.consumed_at IS NOT NULL AND NEW.consumed_at IS DISTINCT FROM OLD.consumed_at
                THEN
                    RAISE EXCEPTION 'Code consumption is irreversible';
                END IF;
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute(
        "CREATE TRIGGER guard_protocol_code BEFORE INSERT OR UPDATE ON authorization_codes "
        "FOR EACH ROW EXECUTE FUNCTION protocol_code_guard()"
    )
    op.execute("""
        CREATE FUNCTION complete_protocol_issuance() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM token_issuances i
                JOIN authorization_codes c ON c.code_digest=i.code_digest
                JOIN federation_grants g ON g.grant_id=i.grant_id
                JOIN authentication_evidence e ON e.grant_id=g.grant_id AND e.token_id=i.issuance_id
                JOIN access_credentials a ON a.grant_id=g.grant_id
                WHERE i.issuance_id=NEW.issuance_id AND c.consumed_at IS NOT NULL
                AND c.event_id=g.event_id AND c.sid=g.session_id AND c.client_id=g.client_id
                AND i.client_id=g.client_id AND i.sid=g.session_id AND i.sub=c.sub
                AND i.id_token_digest=e.token_digest AND i.signing_key_id=e.signing_key_id
                AND a.token_digest=i.access_token_digest
            ) THEN
                RAISE EXCEPTION 'Protocol issuance must commit with its consumed code and grant';
            END IF;
            RETURN NULL;
        END $$
    """)
    op.execute(
        "CREATE CONSTRAINT TRIGGER complete_protocol_issuance "
        "AFTER INSERT OR UPDATE ON token_issuances DEFERRABLE INITIALLY DEFERRED "
        "FOR EACH ROW EXECUTE FUNCTION complete_protocol_issuance()"
    )
    op.execute("""
        CREATE FUNCTION protocol_issuance_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF OLD.grant_id IS NOT NULL AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
                RAISE EXCEPTION 'Committed protocol issuance is immutable';
            END IF;
            RETURN NEW;
        END $$
    """)
    op.execute(
        "CREATE TRIGGER guard_protocol_issuance BEFORE UPDATE ON token_issuances "
        "FOR EACH ROW EXECUTE FUNCTION protocol_issuance_guard()"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER guard_protocol_issuance ON token_issuances")
    op.execute("DROP TRIGGER complete_protocol_issuance ON token_issuances")
    op.execute("DROP TRIGGER guard_protocol_code ON authorization_codes")
    op.execute("DROP FUNCTION protocol_issuance_guard()")
    op.execute("DROP FUNCTION complete_protocol_issuance()")
    op.execute("DROP FUNCTION protocol_code_guard()")
    op.drop_constraint("one_protocol_issuance_per_grant", "token_issuances", type_="unique")
    op.drop_constraint("protocol_grant_binding", "token_issuances", type_="foreignkey")
    op.drop_column("token_issuances", "grant_id")
    op.drop_constraint("code_event_session_binding", "authorization_codes", type_="foreignkey")
    op.drop_column("authorization_codes", "event_id")
