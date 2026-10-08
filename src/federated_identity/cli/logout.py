"""Owner-side queue inspection/recovery without exporting signed delivery payloads."""

import asyncio

from federated_identity.common.security.secrets import load_runtime_secrets
from federated_identity.common.settings.policy import SystemClock
from federated_identity.common.settings.runtime import RuntimeSettings, ServiceId
from federated_identity.idp.repositories.database import Database
from federated_identity.idp.repositories.outbox import PostgresLogoutOutbox


async def logout_queue(
    settings: RuntimeSettings, *, retry_id: str | None = None
) -> list[dict[str, object]]:
    if settings.service_id != ServiceId.IDP:
        raise ValueError("Logout delivery recovery belongs to the IDP owner")
    assets = await asyncio.to_thread(load_runtime_secrets, settings)
    database = await asyncio.to_thread(Database, assets.database_url, ca_file=assets.ca_certificate)
    try:
        outbox = PostgresLogoutOutbox(database, assets.envelope, SystemClock())
        if retry_id is not None:
            await outbox.retry(retry_id)
        return [row.model_dump(mode="json") for row in await outbox.inspect()]
    finally:
        await database.dispose()
