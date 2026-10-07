"""Vetted Argon2id hashing with bounded CPU work outside the event loop."""

import asyncio
import secrets
from dataclasses import dataclass, field

from argon2 import PasswordHasher, extract_parameters
from argon2.exceptions import InvalidHashError, VerificationError
from argon2.low_level import Type
from pydantic import SecretStr

MAX_PASSWORD_BYTES = 1024


def password_hasher() -> PasswordHasher:
    return PasswordHasher(
        time_cost=3, memory_cost=65536, parallelism=1, hash_len=32, salt_len=16, type=Type.ID
    )


def approved_hash(encoded: SecretStr) -> bool:
    try:
        parameters = extract_parameters(encoded.get_secret_value())
    except (InvalidHashError, ValueError):
        return False
    return (
        parameters.type == Type.ID
        and parameters.version == 19
        and 19456 <= parameters.memory_cost <= 65536
        and 2 <= parameters.time_cost <= 4
        and 1 <= parameters.parallelism <= 4
        and 16 <= parameters.salt_len <= 32
        and 16 <= parameters.hash_len <= 64
    )


def hash_password(password: SecretStr) -> SecretStr:
    value = password.get_secret_value()
    if not 1 <= len(value.encode("utf-8")) <= MAX_PASSWORD_BYTES:
        raise ValueError("A password must have a bounded, nonempty encoded length")
    return SecretStr(password_hasher().hash(value))


@dataclass
class Argon2Passwords:
    hasher: PasswordHasher = field(repr=False)
    dummy_hash: SecretStr = field(repr=False)
    slots: asyncio.Semaphore = field(repr=False)

    @classmethod
    async def create(cls) -> "Argon2Passwords":
        dummy = await asyncio.to_thread(hash_password, SecretStr(secrets.token_urlsafe(32)))
        return cls(password_hasher(), dummy, asyncio.Semaphore(2))

    async def verify(self, password: SecretStr, encoded: SecretStr | None) -> bool:
        if not 1 <= len(password.get_secret_value().encode("utf-8")) <= MAX_PASSWORD_BYTES:
            return False
        selected = encoded if encoded is not None else self.dummy_hash
        if not approved_hash(selected):
            raise ValueError("Stored credentials require a supported, bounded Argon2id hash")

        def verify() -> bool:
            try:
                return self.hasher.verify(selected.get_secret_value(), password.get_secret_value())
            except VerificationError:
                return False

        await self.slots.acquire()
        worker = asyncio.create_task(asyncio.to_thread(verify))

        def finished(task: asyncio.Task[bool]) -> None:
            self.slots.release()
            if not task.cancelled():
                task.exception()  # Retrieve a detached worker error after caller cancellation.

        worker.add_done_callback(finished)
        matched = await asyncio.shield(worker)
        return matched and encoded is not None
