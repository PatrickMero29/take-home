"""Code-flow sessions can exist without a protocol-issued refresh credential."""

import sqlalchemy as sa
from alembic import op

revision = "sp_browser_login_04"
down_revision = "sp_foundations_03"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("sp_authentication_sessions", "encrypted_refresh_token", nullable=True)


def downgrade() -> None:
    # Preserve code-only sessions without inventing a credential or deleting user state.
    if (
        op.get_bind()
        .execute(
            sa.text(
                "SELECT 1 FROM sp_authentication_sessions "
                "WHERE encrypted_refresh_token IS NULL LIMIT 1"
            )
        )
        .first()
        is not None
    ):
        raise RuntimeError("Code-only sessions require the browser-login schema")
    op.alter_column("sp_authentication_sessions", "encrypted_refresh_token", nullable=False)
