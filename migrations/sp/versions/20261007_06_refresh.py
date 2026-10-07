"""Durable single-flight renewal, encrypted credential context, and ambiguous-failure barrier."""

import sqlalchemy as sa
from alembic import op

revision = "sp_refresh_06"
down_revision = "sp_lifecycle_05"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for column in (
        sa.Column("access_expires_at", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("refresh_generation", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("refresh_state", sa.String(16), nullable=False, server_default="ready"),
        sa.Column("refresh_attempt_id", sa.String(64), nullable=True),
        sa.Column("refresh_started_at", sa.BigInteger(), nullable=True),
    ):
        op.add_column("sp_authentication_sessions", column)
    op.create_check_constraint(
        "sp_refresh_state",
        "sp_authentication_sessions",
        "refresh_state IN ('ready','pending','blocked') AND refresh_generation >= 0",
    )
    op.execute("""
        CREATE OR REPLACE FUNCTION sp_session_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF (to_jsonb(NEW) - ARRAY['last_seen_at','idle_expires_at','revoked_at',
                'encrypted_access_token','encrypted_refresh_token','access_expires_at',
                'refresh_generation','refresh_state','refresh_attempt_id','refresh_started_at'])
                IS DISTINCT FROM
                (to_jsonb(OLD) - ARRAY['last_seen_at','idle_expires_at','revoked_at',
                'encrypted_access_token','encrypted_refresh_token','access_expires_at',
                'refresh_generation','refresh_state','refresh_attempt_id','refresh_started_at'])
                THEN
                RAISE EXCEPTION 'SP authentication evidence and absolute lifetime are immutable';
            END IF;
            IF OLD.revoked_at IS NOT NULL AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
                RAISE EXCEPTION 'Local revocation is irreversible';
            END IF;
            IF NEW.last_seen_at < OLD.last_seen_at
                OR NEW.refresh_generation < OLD.refresh_generation
                OR OLD.refresh_state='blocked' AND NEW.refresh_state<>'blocked' THEN
                RAISE EXCEPTION 'SP activity, rotation and ambiguity cannot be reset';
            END IF;
            RETURN NEW;
        END $$
    """)


def downgrade() -> None:
    op.drop_constraint("sp_refresh_state", "sp_authentication_sessions", type_="check")
    op.execute("""
        CREATE OR REPLACE FUNCTION sp_session_guard() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
            IF (to_jsonb(NEW) - ARRAY['last_seen_at','idle_expires_at','revoked_at',
                                      'encrypted_access_token','encrypted_refresh_token'])
                IS DISTINCT FROM
                (to_jsonb(OLD) - ARRAY['last_seen_at','idle_expires_at','revoked_at',
                                      'encrypted_access_token','encrypted_refresh_token']) THEN
                RAISE EXCEPTION 'SP authentication evidence and absolute lifetime are immutable';
            END IF;
            IF OLD.revoked_at IS NOT NULL AND to_jsonb(NEW) IS DISTINCT FROM to_jsonb(OLD) THEN
                RAISE EXCEPTION 'Local revocation is irreversible';
            END IF;
            IF NEW.last_seen_at < OLD.last_seen_at THEN
                RAISE EXCEPTION 'SP activity cannot move backwards';
            END IF;
            RETURN NEW;
        END $$
    """)
    for name in (
        "refresh_started_at",
        "refresh_attempt_id",
        "refresh_state",
        "refresh_generation",
        "access_expires_at",
    ):
        op.drop_column("sp_authentication_sessions", name)
