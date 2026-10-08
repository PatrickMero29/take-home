"""The Phase 8 upgrade preserves existing session/grant and encrypted credential custody."""

import asyncio

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import text
from sqlalchemy.engine import Connection

from federated_identity.common.persistence.migrations import migrate, migration_configuration
from federated_identity.common.security.model import AuthenticationRequirement
from federated_identity.common.settings.runtime import ServiceId
from tests.security_helpers import SecurityLab

pytestmark = pytest.mark.integration


async def test_step_up_upgrade_preserves_existing_password_authority(
    security_lab: SecurityLab,
) -> None:
    lab = security_lab
    issued = await lab.issue()
    cookie = await lab.sps["sp-a"].establish(issued.proof.evidence, issued.credentials)
    before = await lab.sps["sp-a"].repository.load(cookie)
    for service, database in lab.databases.items():
        configuration = await asyncio.to_thread(migration_configuration, service)
        target = "idp_logout_11" if service == ServiceId.IDP else "sp_logout_07"

        def downgrade(
            connection: Connection, target: str = target, configuration: Config = configuration
        ) -> None:
            configuration.attributes["connection"] = connection
            command.downgrade(configuration, target)

        async with database.engine.begin() as connection:
            await connection.run_sync(downgrade)
        await migrate(database, service)
        await migrate(database, service)
        async with database.sessions() as session:
            head = await session.scalar(text("SELECT version_num FROM alembic_version"))
            assert head == ("idp_step_up_12" if service == ServiceId.IDP else "sp_step_up_08")
    assert await lab.sps["sp-a"].repository.load(cookie) == before
    assert (
        await lab.sps["sp-a"].authorize(cookie, AuthenticationRequirement())
    ).authentication == issued.credentials.context.authentication
