import asyncio
import dataclasses
import uuid
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretBytes

from federated_identity.cli.bootstrap import bootstrap_assets
from federated_identity.common.persistence.foundations import (
    RuntimeBindingRow,
    RuntimeFoundationError,
    enroll_encryption_binding,
)
from federated_identity.common.persistence.sessions import PostgresSessionBackend
from federated_identity.common.security.secrets import (
    EncryptionBinding,
    EnvelopeCipher,
    load_runtime_secrets,
)
from federated_identity.common.settings.runtime import ServiceId
from tests.security_helpers import SecurityLab
from tests.unit.test_architecture import settings

pytestmark = pytest.mark.integration


async def test_initial_key_enrollment_verifies_existing_encrypted_data(
    security_lab: SecurityLab, tmp_path: Path
) -> None:
    await asyncio.to_thread(bootstrap_assets, tmp_path)
    assets = await asyncio.to_thread(load_runtime_secrets, settings(tmp_path, ServiceId.SP_A))
    database = security_lab.databases[ServiceId.SP_A]
    sessions = PostgresSessionBackend(database, assets.envelope, security_lab.clock)
    cookie = await sessions.create({"kind": "persisted-before-key-binding"}, ttl=300)
    wrong = dataclasses.replace(
        assets,
        envelope=EnvelopeCipher.from_key(SecretBytes(Fernet.generate_key())),
        binding=EncryptionBinding(service_id=ServiceId.SP_A, key_id=str(uuid.uuid4())),
    )
    with pytest.raises(RuntimeFoundationError, match="restore the original"):
        await enroll_encryption_binding(database, wrong, ServiceId.SP_A)
    async with database.sessions() as session:
        assert await session.get(RuntimeBindingRow, 1) is None
    await enroll_encryption_binding(database, assets, ServiceId.SP_A)
    stored = await sessions.lookup(cookie)
    assert stored is not None and stored.payload["kind"] == "persisted-before-key-binding"
