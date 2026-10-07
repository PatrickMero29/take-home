"""Phase 4 migration preserves both pending and consumed immutable Phase 3 proofs."""

import asyncio
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from pydantic import SecretStr
from sqlalchemy import select
from sqlalchemy.engine import Connection

from federated_identity.common.persistence.migrations import migrate
from federated_identity.common.settings.policy import verifier_digest
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.repositories.signing import SignedArtifactRow
from federated_identity.idp.repositories.tables import AuthorizationCodeRow
from federated_identity.idp.schemas.signing import SignedArtifactPurpose
from federated_identity.sp.protocol.oidc import InvalidAuthorizationResponse
from tests.helpers import ProtocolLab, callback_code

pytestmark = pytest.mark.integration


async def test_operator_upgrade_preserves_pending_and_consumed_code_lineage(
    lab: ProtocolLab,
) -> None:
    consumed = lab.rp().begin()
    consumed_callback = await lab.authorize(consumed)
    issued = await lab.rp().exchange_verified(consumed, consumed_callback)
    pending = lab.rp().begin()
    pending_callback = await lab.authorize(pending)
    root = await asyncio.to_thread(lambda: Path(__file__).resolve().parents[2])
    configuration = Config()
    configuration.set_main_option("script_location", str(root / "migrations" / "idp"))
    configuration.set_main_option("path_separator", "os")

    def downgrade(connection: Connection) -> None:
        configuration.attributes["connection"] = connection
        command.downgrade(configuration, "idp_lifecycle_06")

    async with lab.database.engine.begin() as connection:
        await connection.run_sync(downgrade)
    await migrate(lab.database, ServiceId.IDP)
    async with lab.database.sessions() as session:
        rows = list(await session.scalars(select(AuthorizationCodeRow)))
        assert len(rows) == 2 and all(row.client_version == 1 for row in rows)
        old = await session.get(
            AuthorizationCodeRow, verifier_digest(callback_code(consumed_callback))
        )
        assert old is not None and old.consumed_at == lab.clock.now()
        signed = await session.get(SignedArtifactRow, issued.claims.jti)
        assert signed is not None
        assert signed.key_id == issued.evidence.signing_key_id
        assert signed.purpose == SignedArtifactPurpose.ID_TOKEN.value
        assert signed.client_id == "sp-a"
        assert (signed.issued_at, signed.expires_at) == (issued.claims.iat, issued.claims.exp)
    status = await lab.security.check_access(
        SecretStr(issued.response.access_token), authenticated_client="sp-a"
    )
    assert status.active and status.context == issued.context
    # Phase 7's default capability upgrade increments registry policy. Immutable
    # pending proof survives, but its old approval cannot bypass the new version.
    with pytest.raises(InvalidAuthorizationResponse):
        await lab.rp().exchange_verified(pending, pending_callback)
    fresh = lab.rp().begin()
    valid = await lab.rp().exchange_verified(fresh, await lab.authorize(fresh))
    assert valid.claims.sub == lab.principal.sub
