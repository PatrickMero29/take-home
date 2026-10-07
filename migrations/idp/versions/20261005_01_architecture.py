"""IDP protocol tables and generic session/logout delivery infrastructure."""

import sqlalchemy as sa
from alembic import op

revision = "idp_architecture_01"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "clients",
        sa.Column("client_id", sa.String(255), primary_key=True),
        sa.Column("redirect_uris", sa.JSON(), nullable=False),
        sa.Column("public_key_pem", sa.Text(), nullable=False),
        sa.Column("key_id", sa.String(255), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
    )
    op.create_table(
        "authorization_codes",
        sa.Column("code_digest", sa.String(64), primary_key=True),
        sa.Column("client_id", sa.String(255), sa.ForeignKey("clients.client_id"), nullable=False),
        sa.Column("redirect_uri", sa.Text(), nullable=False),
        sa.Column("scope", sa.String(64), nullable=False),
        sa.Column("nonce", sa.String(256), nullable=False),
        sa.Column("code_challenge", sa.String(128), nullable=False),
        sa.Column("created_at", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.Integer(), nullable=False),
        sa.Column("consumed_at", sa.Integer(), nullable=True),
        sa.Column("sub", sa.String(255), nullable=False),
        sa.Column("sid", sa.String(255), nullable=False),
        sa.Column("auth_time", sa.Integer(), nullable=False),
        sa.Column("acr", sa.String(255), nullable=False),
        sa.Column("amr", sa.JSON(), nullable=False),
    )
    op.create_table(
        "client_assertion_replays",
        sa.Column(
            "client_id", sa.String(255), sa.ForeignKey("clients.client_id"), primary_key=True
        ),
        sa.Column("jti", sa.String(256), primary_key=True),
        sa.Column("expires_at", sa.Integer(), nullable=False),
    )
    op.create_table(
        "token_issuances",
        sa.Column("issuance_id", sa.String(255), primary_key=True),
        sa.Column(
            "code_digest",
            sa.String(64),
            sa.ForeignKey("authorization_codes.code_digest"),
            nullable=False,
            unique=True,
        ),
        sa.Column("client_id", sa.String(255), sa.ForeignKey("clients.client_id"), nullable=False),
        sa.Column("access_token_digest", sa.String(64), nullable=False, unique=True),
        sa.Column("id_token_digest", sa.String(64), nullable=True),
        sa.Column("signing_key_id", sa.String(255), nullable=False),
        sa.Column("sub", sa.String(255), nullable=False),
        sa.Column("sid", sa.String(255), nullable=False),
        sa.Column("created_at", sa.Integer(), nullable=False),
    )
    op.create_table(
        "browser_sessions",
        sa.Column("token_digest", sa.String(64), primary_key=True),
        sa.Column("encrypted_payload", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("expires_at", sa.BigInteger(), nullable=False),
    )
    op.create_table(
        "logout_outbox",
        sa.Column("delivery_id", sa.String(36), primary_key=True),
        sa.Column("destination", sa.Text(), nullable=False),
        sa.Column("encrypted_payload", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.BigInteger(), nullable=False),
        sa.Column("next_attempt_at", sa.BigInteger(), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
    )


def downgrade() -> None:
    for table in (
        "logout_outbox",
        "browser_sessions",
        "token_issuances",
        "client_assertion_replays",
        "authorization_codes",
        "clients",
    ):
        op.drop_table(table)
