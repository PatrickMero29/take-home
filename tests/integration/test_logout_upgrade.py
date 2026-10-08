"""Phase 7 upgrade preserves lineage/custody and adopts only original logout metadata."""

import asyncio

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select, text
from sqlalchemy.engine import Connection

from federated_identity.common.persistence.migrations import migrate, migration_configuration
from federated_identity.common.settings.policy import verifier_digest
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.repositories.outbox import LogoutOutboxRow
from federated_identity.idp.repositories.security_tables import IdpSessionRow
from federated_identity.idp.repositories.tables import ClientRow
from federated_identity.sp.repositories.security_tables import SpAuthenticationRow
from tests.security_helpers import SecurityLab

pytestmark = pytest.mark.integration


async def test_logout_upgrade_preserves_pending_revocation_custody_and_custom_registration(
    security_lab: SecurityLab,
) -> None:
    lab = security_lab
    parent, authentication = await lab.idp.open_session(lab.authentication())
    issued = await lab.issue(authentication)
    other = await lab.issue(authentication, client_id="sp-b")
    cookies = {
        ServiceId.SP_A: await lab.sps["sp-a"].establish(issued.proof.evidence, issued.credentials),
        ServiceId.SP_B: await lab.sps["sp-b"].establish(other.proof.evidence, other.credentials),
    }
    custody = {}
    for service, cookie in cookies.items():
        async with lab.databases[service].sessions() as session:
            row = await session.get(SpAuthenticationRow, verifier_digest(cookie.get_secret_value()))
            assert row is not None
            custody[service] = (row.encrypted_evidence, row.encrypted_refresh_token, row.expires_at)
    await lab.idp.end_session(parent.session_id)
    for service, database in lab.databases.items():
        configuration = await asyncio.to_thread(migration_configuration, service)

        def downgrade(
            connection: Connection,
            configuration: Config = configuration,
            service: ServiceId = service,
        ) -> None:
            configuration.attributes["connection"] = connection
            command.downgrade(
                configuration, "idp_refresh_10" if service == ServiceId.IDP else "sp_refresh_06"
            )

        async with database.engine.begin() as connection:
            await connection.run_sync(downgrade)
    async with lab.idp.repository.transaction() as work:
        a, b = await work.get(ClientRow, "sp-a"), await work.get(ClientRow, "sp-b")
        assert a is not None and b is not None
        a.redirect_uris = ["https://sp-a.localhost:8444/auth/callback"]
        a.backchannel_logout_uri, a.post_logout_redirect_uris = None, []
        b.redirect_uris = ["https://sp-b.localhost:8445/auth/callback"]
        b.backchannel_logout_uri = "https://sp-b.localhost:8445/custom-logout"
        b.post_logout_redirect_uris = ["https://sp-b.localhost:8445/custom-return"]
    # A Phase 7 bound intent has no destination/signature lease yet.
    async with lab.database.engine.begin() as connection:
        await connection.execute(
            text(
                "UPDATE logout_outbox SET destination=NULL, status='pending' WHERE client_id='sp-a'"
            )
        )
    for service, database in lab.databases.items():
        await migrate(database, service)
        await migrate(database, service)
    async with lab.database.sessions() as session:
        a, b = await session.get(ClientRow, "sp-a"), await session.get(ClientRow, "sp-b")
        assert a is not None and b is not None
        assert a.backchannel_logout_uri == "https://sp-a.localhost:8444/backchannel-logout"
        assert a.post_logout_redirect_uris == ["https://sp-a.localhost:8444/"]
        assert b.backchannel_logout_uri == "https://sp-b.localhost:8445/custom-logout"
        assert b.post_logout_redirect_uris == ["https://sp-b.localhost:8445/custom-return"]
        intents = list(await session.scalars(select(LogoutOutboxRow)))
        assert len(intents) == 2
        recovered = next(row for row in intents if row.client_id == "sp-a")
        assert recovered.status == "pending" and recovered.destination == a.backchannel_logout_uri
        assert recovered.session_id == parent.session_id and recovered.lease_id is None
        assert (
            lab.ciphers[ServiceId.IDP].decrypt(
                recovered.encrypted_payload, purpose="logout-delivery"
            )["sid"]
            == parent.session_id
        )
        persisted = await session.get(IdpSessionRow, parent.session_id)
        assert persisted is not None and persisted.revoked_at == lab.clock.now()
    for service, cookie in cookies.items():
        async with lab.databases[service].sessions() as session:
            row = await session.get(SpAuthenticationRow, verifier_digest(cookie.get_secret_value()))
            assert row is not None
            assert (row.encrypted_evidence, row.encrypted_refresh_token, row.expires_at) == custody[
                service
            ]
    assert not (
        await lab.idp.check_access(issued.credentials.access_token, authenticated_client="sp-a")
    ).active
