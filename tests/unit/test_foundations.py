import asyncio
import json
import logging
import secrets
import threading
from collections.abc import AsyncIterator
from http import HTTPStatus
from pathlib import Path

import httpx2 as httpx
import pytest
from argon2 import PasswordHasher
from cryptography.fernet import Fernet
from pydantic import SecretStr
from starlette.types import Receive, Scope, Send

from federated_identity.cli.bootstrap import bootstrap_assets
from federated_identity.cli.main import seed_credentials
from federated_identity.cli.operator import operator_credentials
from federated_identity.common.observability.boundaries import RuntimeBoundaries
from federated_identity.common.observability.logging import JsonFormatter
from federated_identity.common.security.passwords import (
    Argon2Passwords,
    approved_hash,
    hash_password,
)
from federated_identity.common.security.secrets import RuntimeSecretsError, load_runtime_secrets
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.services.provisioning import load_seeded_operator, load_seeded_users
from tests.unit.test_architecture import settings


def test_private_seeded_credentials_are_generated_once_and_never_public_config(
    tmp_path: Path,
) -> None:
    bootstrap_assets(tmp_path)
    assets = load_runtime_secrets(settings(tmp_path))
    material = load_seeded_users(tmp_path / "idp", assets.envelope)
    assert {user.username for user in material.users} == {"alice", "bob"}
    ciphertext = (tmp_path / "idp" / "seed-users.enc").read_bytes()
    for user in material.users:
        assert approved_hash(user.password_hash)
        assert user.password.get_secret_value().encode() not in ciphertext
        assert user.password_hash.get_secret_value().encode() not in ciphertext
        revealed = seed_credentials(settings(tmp_path), user.username)
        assert revealed["password"] == user.password.get_secret_value()
    bootstrap_assets(tmp_path)
    assert (tmp_path / "idp" / "seed-users.enc").read_bytes() == ciphertext
    assert load_seeded_users(tmp_path / "idp", assets.envelope) == material
    with pytest.raises(ValueError, match="only"):
        seed_credentials(settings(tmp_path, ServiceId.SP_A), "alice")


@pytest.mark.parametrize(
    "name",
    [
        "encryption.key",
        "encryption.check",
        "database.password",
        "seed-users.enc",
        "seed-operator.enc",
        "seed-totp.enc",
    ],
)
def test_bootstrap_never_replaces_missing_material_in_an_existing_bundle(
    tmp_path: Path, name: str
) -> None:
    bootstrap_assets(tmp_path)
    path = tmp_path / "idp" / name
    path.unlink()
    with pytest.raises(RuntimeError, match="recovery"):
        bootstrap_assets(tmp_path)
    assert not path.exists()


def test_operator_provisioning_is_distinct_private_and_preserved(tmp_path: Path) -> None:
    bootstrap_assets(tmp_path)
    assets = load_runtime_secrets(settings(tmp_path))
    operator = load_seeded_operator(tmp_path / "idp", assets.envelope)
    users = load_seeded_users(tmp_path / "idp", assets.envelope)
    assert operator.username not in {user.username for user in users.users}
    assert operator.password not in {user.password for user in users.users}
    path = tmp_path / "idp" / "seed-operator.enc"
    encrypted = path.read_bytes()
    assert operator.password.get_secret_value().encode() not in encrypted
    assert operator.password_hash.get_secret_value().encode() not in encrypted
    assert path.stat().st_mode & 0o077 == 0
    bootstrap_assets(tmp_path)
    assert path.read_bytes() == encrypted
    assert (
        operator_credentials(settings(tmp_path))["password"] == operator.password.get_secret_value()
    )
    with pytest.raises(ValueError, match="only"):
        operator_credentials(settings(tmp_path, ServiceId.SP_A))


def test_existing_secret_bundle_gains_operator_material_once_without_resetting_users(
    tmp_path: Path,
) -> None:
    bootstrap_assets(tmp_path)
    idp = tmp_path / "idp"
    original_users = (idp / "seed-users.enc").read_bytes()
    (idp / "seed-operator.enc").unlink()
    (idp / "bundle.complete").write_bytes(b"runtime-secret-bundle-v1")
    bootstrap_assets(tmp_path)
    assert (idp / "seed-users.enc").read_bytes() == original_users
    assert (idp / "bundle.complete").read_bytes() == b"runtime-secret-bundle-v3"
    assert (idp / "seed-operator.enc").is_file()
    material = (idp / "seed-operator.enc").read_bytes()
    bootstrap_assets(tmp_path)
    assert (idp / "seed-operator.enc").read_bytes() == material


def test_a_different_valid_encryption_key_fails_at_startup(tmp_path: Path) -> None:
    bootstrap_assets(tmp_path)
    (tmp_path / "sp-a" / "encryption.key").write_bytes(Fernet.generate_key())
    with pytest.raises(RuntimeSecretsError, match="persisted secret binding"):
        load_runtime_secrets(settings(tmp_path, ServiceId.SP_A))


def test_secret_bundle_cannot_be_used_by_another_service(tmp_path: Path) -> None:
    bootstrap_assets(tmp_path)
    wrong = settings(tmp_path, ServiceId.SP_B).model_copy(
        update={"secrets_directory": tmp_path / "sp-a"}
    )
    with pytest.raises(RuntimeSecretsError, match="different application"):
        load_runtime_secrets(wrong)


def test_log_formatter_does_not_interpolate_credentials_or_dependency_exceptions() -> None:
    secret = secrets.token_urlsafe(32)
    record = logging.LogRecord(
        "sqlalchemy.engine",
        logging.ERROR,
        __file__,
        1,
        "database password=%s Bearer credential",
        (secret,),
        None,
    )
    record.secret = secret
    rendered = JsonFormatter().format(record)
    assert secret not in rendered and "password" not in rendered
    assert json.loads(rendered)["event"] == "dependency_event"
    application = logging.LogRecord(
        "federated_identity.cli.service",
        logging.ERROR,
        __file__,
        1,
        "startup_failed",
        (),
        None,
    )
    application.service = "idp"
    assert json.loads(JsonFormatter().format(application))["service"] == "idp"


async def test_argon2_authentication_work_is_vetted_and_unknown_credentials_never_match() -> None:
    password = SecretStr(secrets.token_urlsafe(32))
    encoded = await asyncio.to_thread(hash_password, password)
    passwords = await Argon2Passwords.create()
    assert await passwords.verify(password, encoded)
    assert not await passwords.verify(SecretStr(secrets.token_urlsafe(32)), encoded)
    assert not await passwords.verify(password, None)
    assert not await passwords.verify(SecretStr("x" * 1025), encoded)


async def test_cancelling_password_verification_keeps_worker_capacity_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    passwords = await Argon2Passwords.create()
    passwords.slots = asyncio.Semaphore(1)
    entered = threading.Event()
    release = threading.Event()
    original = PasswordHasher.verify

    def delayed(self: PasswordHasher, encoded: str, password: str) -> bool:
        entered.set()
        release.wait(timeout=5)
        return original(self, encoded, password)

    monkeypatch.setattr(PasswordHasher, "verify", delayed)
    task = asyncio.create_task(passwords.verify(SecretStr("wrong"), None))
    try:
        assert await asyncio.to_thread(entered.wait, 2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert passwords.slots.locked()
    finally:
        release.set()
    async with asyncio.timeout(2):
        await passwords.slots.acquire()
        passwords.slots.release()


async def consume(scope: Scope, receive: Receive, send: Send) -> None:
    while True:
        message = await receive()
        if not message.get("more_body", False):
            break
    await send({"type": "http.response.start", "status": HTTPStatus.OK, "headers": []})
    await send({"type": "http.response.body", "body": b"ok"})


async def test_runtime_rejects_declared_and_streamed_oversize_requests() -> None:
    app = RuntimeBoundaries(consume, timeout_seconds=1, max_body_bytes=8, max_inflight=1)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://idp.localhost"
    ) as client:
        declared = await client.post("/", content=b"x" * 9)
        assert declared.status_code == HTTPStatus.REQUEST_ENTITY_TOO_LARGE

        async def chunks() -> AsyncIterator[bytes]:
            yield b"12345"
            yield b"67890"

        streamed = await client.post("/", content=chunks())
        assert streamed.status_code == HTTPStatus.REQUEST_ENTITY_TOO_LARGE
        assert (await client.post("/", content=b"123")).status_code == HTTPStatus.OK


async def test_request_deadlines_and_capacity_do_not_block_the_event_loop() -> None:
    entered = asyncio.Event()
    release = asyncio.Event()

    async def waiting(scope: Scope, receive: Receive, send: Send) -> None:
        entered.set()
        await release.wait()

    app = RuntimeBoundaries(waiting, timeout_seconds=0.15, max_body_bytes=16, max_inflight=1)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://idp.localhost"
    ) as client:
        first = asyncio.create_task(client.get("/"))
        await asyncio.wait_for(entered.wait(), timeout=1)
        overloaded = await client.get("/")
        assert overloaded.status_code == HTTPStatus.SERVICE_UNAVAILABLE
        assert (await first).status_code == HTTPStatus.GATEWAY_TIMEOUT
        release.set()
