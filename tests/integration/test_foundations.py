import asyncio
import dataclasses
import secrets
import uuid
from collections.abc import AsyncIterator
from http import HTTPStatus

import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from pydantic import SecretBytes, SecretStr
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from federated_identity.cli.architecture_probe import ArchitectureStack, architecture_stack
from federated_identity.cli.bootstrap import bootstrap_assets
from federated_identity.cli.databases import initialize_databases
from federated_identity.cli.service import build_application
from federated_identity.common.persistence.foundations import (
    RuntimeFoundationError,
    RuntimeReadiness,
    enroll_encryption_binding,
)
from federated_identity.common.persistence.migrations import migration_head
from federated_identity.common.security.model import AuthenticationMethod
from federated_identity.common.security.passwords import Argon2Passwords, hash_password
from federated_identity.common.security.secrets import (
    EncryptionBinding,
    EnvelopeCipher,
    load_runtime_secrets,
)
from federated_identity.common.settings.policy import SystemClock
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.repositories.database import Database
from federated_identity.idp.repositories.users import UserRepository, UserRow
from federated_identity.idp.services.authentication import PasswordAuthenticator
from federated_identity.idp.services.provisioning import load_seeded_users
from federated_identity.sp.repositories.database import SpDatabase
from tests.integration.test_architecture import assets_for, service_settings

pytestmark = [pytest.mark.integration, pytest.mark.asyncio(loop_scope="module")]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def foundations_stack() -> AsyncIterator[ArchitectureStack]:
    async with architecture_stack() as stack:
        yield stack


async def test_seeded_users_survive_bootstrap_and_restart_without_resetting_account_state(
    foundations_stack: ArchitectureStack,
) -> None:
    stack = foundations_stack
    settings = service_settings(stack, ServiceId.IDP)
    assets = await assets_for(stack, ServiceId.IDP)
    seed = await asyncio.to_thread(load_seeded_users, settings.secrets_directory, assets.envelope)
    database = await asyncio.to_thread(Database, assets.database_url, ca_file=assets.ca_certificate)
    original = {user.subject: user for user in seed.users}
    try:
        users = UserRepository(database, SystemClock())
        verifier = PasswordAuthenticator(
            users, await Argon2Passwords.create(), issuer=stack.issuer, clock=SystemClock()
        )
        for user in seed.users:
            stored = await users.credential(user.username)
            assert stored is not None and stored.password_hash == user.password_hash
            proof = await verifier.authenticate(user.username, user.password)
            assert proof is not None and proof.subject.subject == user.subject
            assert proof.methods == (AuthenticationMethod.PASSWORD,)
        assert await verifier.authenticate("unknown-user", seed.users[0].password) is None
        assert await verifier.authenticate("alice", SecretStr(secrets.token_urlsafe(32))) is None
        changed = await asyncio.to_thread(hash_password, SecretStr(secrets.token_urlsafe(32)))
        async with database.sessions() as session:
            row = await session.get(UserRow, seed.users[0].subject)
            assert row is not None
            row.enabled = False
            row.password_hash = changed.get_secret_value()
            await session.commit()
        await asyncio.to_thread(bootstrap_assets, stack.root)
        await initialize_databases(stack.root, host="127.0.0.1", port=stack.postgres_port)
        await stack.stop(ServiceId.IDP)
        await stack.start(ServiceId.IDP)
        stored = await users.credential(seed.users[0].username)
        assert stored is not None and not stored.enabled and stored.password_hash == changed
        assert await verifier.authenticate(stored.username, seed.users[0].password) is None
        assert (
            await asyncio.to_thread(load_seeded_users, settings.secrets_directory, assets.envelope)
            == seed
        )
        async with database.engine.begin() as connection:
            with pytest.raises(DBAPIError, match="immutable"):
                await connection.execute(
                    text("UPDATE users SET subject='new-subject' WHERE username='alice'")
                )
    finally:
        async with database.sessions() as session:
            for subject, user in original.items():
                row = await session.get(UserRow, subject)
                assert row is not None
                row.enabled = user.enabled
                row.password_hash = user.password_hash.get_secret_value()
            await session.commit()
        await database.dispose()


async def test_public_runtime_output_does_not_expose_generated_credentials(
    foundations_stack: ArchitectureStack,
) -> None:
    stack = foundations_stack
    assets = await assets_for(stack, ServiceId.IDP)
    seed = await asyncio.to_thread(load_seeded_users, stack.root / "idp", assets.envelope)
    forbidden = [user.password.get_secret_value() for user in seed.users]
    forbidden.extend(user.password_hash.get_secret_value() for user in seed.users)
    forbidden.append(assets.database_url.get_secret_value())
    forbidden.append(assets.tls_password.get_secret_value())
    async with stack.client() as client:
        for service in (ServiceId.IDP, ServiceId.SP_A, ServiceId.SP_B):
            for path in ("/", "/architecture", "/health/ready"):
                response = await client.get(f"{stack.origin(service)}{path}")
                assert response.is_success
                for value in forbidden:
                    assert value not in response.text and value not in repr(response.headers)
                assert "PRIVATE KEY" not in response.text


async def test_readiness_requires_migrations_and_database_key_binding(
    foundations_stack: ArchitectureStack,
) -> None:
    stack = foundations_stack
    assets = await assets_for(stack, ServiceId.SP_A)
    database = await asyncio.to_thread(
        SpDatabase, assets.database_url, ca_file=assets.ca_certificate
    )
    head = await migration_head(ServiceId.SP_A)
    try:
        checks = RuntimeReadiness(database, assets, ServiceId.SP_A, head)
        await checks.validate()
        async with database.engine.begin() as connection:
            await connection.execute(text("UPDATE alembic_version SET version_num='outdated'"))
        async with stack.client() as client:
            response = await client.get(f"{stack.origin(ServiceId.SP_A)}/health/ready")
            assert response.status_code == HTTPStatus.SERVICE_UNAVAILABLE
        with pytest.raises(RuntimeFoundationError, match="migration head"):
            await checks.validate()
        async with database.engine.begin() as connection:
            await connection.execute(
                text("UPDATE alembic_version SET version_num=:version"), {"version": head}
            )
        wrong = dataclasses.replace(
            assets, envelope=EnvelopeCipher.from_key(SecretBytes(Fernet.generate_key()))
        )
        with pytest.raises(RuntimeFoundationError, match="persisted database binding"):
            await RuntimeReadiness(database, wrong, ServiceId.SP_A, head).validate()
        with pytest.raises(DBAPIError, match="immutable"):
            async with database.engine.begin() as connection:
                await connection.execute(text("DELETE FROM runtime_key_binding"))
    finally:
        async with database.engine.begin() as connection:
            await connection.execute(
                text("UPDATE alembic_version SET version_num=:version"), {"version": head}
            )
        await database.dispose()


async def test_valid_replacement_key_and_local_check_cannot_reenroll_existing_database(
    foundations_stack: ArchitectureStack,
) -> None:
    stack = foundations_stack
    service = ServiceId.SP_A
    settings = service_settings(stack, service)
    assets = await assets_for(stack, service)
    paths = [settings.secrets_directory / name for name in ("encryption.key", "encryption.check")]
    originals = [await asyncio.to_thread(path.read_bytes) for path in paths]
    replacement_key = Fernet.generate_key()
    cipher = EnvelopeCipher.from_key(SecretBytes(replacement_key))
    binding = EncryptionBinding(service_id=service, key_id=str(uuid.uuid4()))
    await stack.stop(service)
    try:
        await asyncio.to_thread(paths[0].write_bytes, replacement_key)
        await asyncio.to_thread(
            paths[1].write_bytes,
            cipher.encrypt(binding.model_dump(mode="json"), purpose="runtime-key-check"),
        )
        replaced = await asyncio.to_thread(load_runtime_secrets, settings)
        database = await asyncio.to_thread(
            SpDatabase, replaced.database_url, ca_file=replaced.ca_certificate
        )
        try:
            with pytest.raises(RuntimeFoundationError):
                await enroll_encryption_binding(database, replaced, service)
            with pytest.raises(RuntimeFoundationError):
                await build_application(settings, replaced)
        finally:
            await database.dispose()
        with pytest.raises(RuntimeError, match="exited during startup"):
            await stack.start(service)
    finally:
        await stack.stop(service)
        for path, value in zip(paths, originals, strict=True):
            await asyncio.to_thread(path.write_bytes, value)
        await stack.start(service)
    assert (await assets_for(stack, service)).binding == assets.binding


async def test_password_proof_cannot_race_account_disabling(
    foundations_stack: ArchitectureStack,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    stack = foundations_stack
    assets = await assets_for(stack, ServiceId.IDP)
    seed = await asyncio.to_thread(load_seeded_users, stack.root / "idp", assets.envelope)
    user = seed.users[0]
    database = await asyncio.to_thread(Database, assets.database_url, ca_file=assets.ca_certificate)
    entered = asyncio.Event()
    release = asyncio.Event()
    original = Argon2Passwords.verify

    async def delayed(
        self: Argon2Passwords, password: SecretStr, encoded: SecretStr | None
    ) -> bool:
        matched = await original(self, password, encoded)
        entered.set()
        await release.wait()
        return matched

    monkeypatch.setattr(Argon2Passwords, "verify", delayed)
    verifier = PasswordAuthenticator(
        UserRepository(database, SystemClock()),
        await Argon2Passwords.create(),
        issuer=stack.issuer,
        clock=SystemClock(),
    )
    attempt = asyncio.create_task(verifier.authenticate(user.username, user.password))
    try:
        await asyncio.wait_for(entered.wait(), timeout=2)
        async with database.sessions() as session:
            row = await session.get(UserRow, user.subject)
            assert row is not None
            row.enabled = False
            await session.commit()
        release.set()
        assert await attempt is None
    finally:
        release.set()
        await attempt
        async with database.sessions() as session:
            row = await session.get(UserRow, user.subject)
            assert row is not None
            row.enabled = True
            await session.commit()
        await database.dispose()
