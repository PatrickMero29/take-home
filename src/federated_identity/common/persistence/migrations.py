"""Programmatic Alembic migrations using the same verified asyncpg connection boundary."""

import asyncio
from importlib import resources
from pathlib import Path

from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy.engine import Connection

from federated_identity.common.persistence.database import AsyncDatabase
from federated_identity.common.settings.runtime import ServiceId


def migration_configuration(service: ServiceId) -> Config:
    history = "idp" if service == ServiceId.IDP else "sp"
    packaged = resources.files("federated_identity").joinpath("migrations", history)
    if packaged.is_dir():
        directory = Path(str(packaged))
    else:
        directory = Path(__file__).resolve().parents[4] / "migrations" / history
    if not directory.is_dir():
        raise RuntimeError("Deployment requires its packaged migration directory")
    configuration = Config()
    configuration.set_main_option("script_location", str(directory))
    configuration.set_main_option("path_separator", "os")
    return configuration


async def migration_head(service: ServiceId) -> str:
    def head() -> str:
        value = ScriptDirectory.from_config(migration_configuration(service)).get_current_head()
        if value is None:
            raise RuntimeError("A runtime requires a single current migration head")
        return value

    return await asyncio.to_thread(head)


async def migrate(database: AsyncDatabase, service: ServiceId) -> None:
    configuration = await asyncio.to_thread(migration_configuration, service)

    def apply(connection: Connection) -> None:
        configuration.attributes["connection"] = connection
        command.upgrade(configuration, "head")

    async with database.engine.begin() as connection:
        await connection.run_sync(apply)
