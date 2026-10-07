"""Database failures and credential races cannot publish uncommitted browser authentication."""

import asyncio
import secrets
from collections.abc import Mapping

import pytest
import pytest_asyncio
from pydantic import JsonValue, SecretStr
from sqlalchemy import event, select, text
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from federated_identity.common.persistence.sessions import BrowserSessionRow, PostgresSessionBackend
from federated_identity.common.security.passwords import Argon2Passwords, hash_password
from federated_identity.common.security.secrets import EnvelopeCipher
from federated_identity.common.security.totp import TotpEngine
from federated_identity.common.settings.runtime import RuntimeSettings, ServiceId
from federated_identity.idp.repositories.browser import IdpBrowserRepository, LoginChallengeRow
from federated_identity.idp.repositories.mfa import TotpRepository
from federated_identity.idp.repositories.security_tables import (
    AuthenticationEventRow,
    IdpSessionRow,
)
from federated_identity.idp.repositories.users import UserRepository, UserRow
from federated_identity.idp.schemas.browser import (
    CompletedLogin,
    IdpBrowserIdentity,
    LoginContinuation,
)
from federated_identity.idp.schemas.users import SeededUser
from federated_identity.idp.services.authentication import PasswordAuthenticator, VerifiedPassword
from federated_identity.idp.services.browser import (
    IdpBrowserService,
    InvalidLoginForm,
    RejectedCredentials,
)
from federated_identity.idp.services.mfa import TotpAuthenticator
from tests.security_helpers import SecurityLab

pytestmark = pytest.mark.integration


@pytest_asyncio.fixture
async def credential_browser(security_lab: SecurityLab) -> tuple[IdpBrowserService, SeededUser]:
    lab = security_lab
    password = SecretStr(secrets.token_urlsafe(32))
    user = SeededUser(
        subject="user:credential-model",
        username="alice",
        password_hash=await asyncio.to_thread(hash_password, password),
        password=password,
    )
    users = UserRepository(lab.database, lab.clock)
    await users.seed([user])
    cipher = lab.ciphers[ServiceId.IDP]
    service = IdpBrowserService(
        RuntimeSettings(
            service_id=ServiceId.IDP, public_url=lab.issuer, issuer=lab.issuer, listen_port=443
        ),
        IdpBrowserRepository(lab.database, cipher, lab.clock),
        PostgresSessionBackend(lab.database, cipher, lab.clock),
        lab.idp,
        PasswordAuthenticator(
            users, await Argon2Passwords.create(), issuer=lab.issuer, clock=lab.clock
        ),
        TotpAuthenticator(TotpRepository(lab.database, cipher, lab.clock), TotpEngine()),
    )
    return service, user


@pytest.mark.parametrize("failure", ["encryption", "commit"])
async def test_failed_binding_cannot_publish_cookie_or_orphan_authentication(
    security_lab: SecurityLab,
    credential_browser: tuple[IdpBrowserService, SeededUser],
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    lab = security_lab
    service, user = credential_browser
    binding = await service.binding(None)
    challenge = await service.challenge(binding, LoginContinuation())
    original = EnvelopeCipher.encrypt
    bind = IdpBrowserRepository.bind_in

    def fail_encryption(
        self: EnvelopeCipher, payload: Mapping[str, JsonValue], *, purpose: str
    ) -> bytes:
        if purpose == "browser-session" and payload.get("kind") == "idp-authenticated":
            raise RuntimeError("Injected binding failure")
        return original(self, payload, purpose=purpose)

    def reject_commit(session: Session) -> None:
        if session.info.get("browser_test_failure"):
            raise RuntimeError("Injected binding failure")

    # A typed storage hook marks only the credential-binding transaction; the
    # independently committed one-use form reservation remains durable.
    async def mark_binding(
        self: IdpBrowserRepository,
        session: AsyncSession,
        identity: IdpBrowserIdentity,
        previous: BrowserSessionRow,
        *,
        ttl: int,
    ) -> SecretStr:
        cookie = await bind(self, session, identity, previous, ttl=ttl)
        session.info["browser_test_failure"] = True
        return cookie

    event.listen(Session, "before_commit", reject_commit)
    try:
        with monkeypatch.context() as patch:
            if failure == "encryption":
                patch.setattr(EnvelopeCipher, "encrypt", fail_encryption)
            else:
                patch.setattr(IdpBrowserRepository, "bind_in", mark_binding)
            with pytest.raises(RuntimeError, match="Injected binding failure"):
                await service.submit(challenge, binding.token, user.username, user.password)
    finally:
        event.remove(Session, "before_commit", reject_commit)
    async with lab.database.sessions() as session:
        assert not list(await session.scalars(select(IdpSessionRow)))
        assert not list(await session.scalars(select(AuthenticationEventRow)))
        assert not list(await session.scalars(select(LoginChallengeRow)))
        assert len(list(await session.scalars(select(BrowserSessionRow)))) == 1
    assert await service.identity(binding.token) is None
    with pytest.raises(InvalidLoginForm):
        await service.submit(challenge, binding.token, user.username, user.password)
    fresh = await service.challenge(binding, LoginContinuation())
    completed = await service.submit(fresh, binding.token, user.username, user.password)
    assert isinstance(completed, CompletedLogin)
    assert (
        completed.cookie != binding.token and await service.identity(completed.cookie) is not None
    )


async def test_browser_cookie_publication_waits_for_the_authentication_commit(
    security_lab: SecurityLab,
    credential_browser: tuple[IdpBrowserService, SeededUser],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lab = security_lab
    service, user = credential_browser
    binding = await service.binding(None)
    challenge = await service.challenge(binding, LoginContinuation())
    entered = asyncio.Event()
    original = IdpBrowserRepository.bind_in

    async def mark_binding(
        self: IdpBrowserRepository,
        session: AsyncSession,
        identity: IdpBrowserIdentity,
        previous: BrowserSessionRow,
        *,
        ttl: int,
    ) -> SecretStr:
        cookie = await original(self, session, identity, previous, ttl=ttl)
        session.info["browser_test_pause"] = True
        return cookie

    def pause(session: Session) -> None:
        if session.info.get("browser_test_pause"):
            entered.set()
            session.execute(text("SELECT pg_advisory_xact_lock(984207)"))

    monkeypatch.setattr(IdpBrowserRepository, "bind_in", mark_binding)
    event.listen(Session, "before_commit", pause)
    try:
        async with lab.database.engine.connect() as blocker:
            await blocker.execute(text("SELECT pg_advisory_lock(984207)"))
            publication = asyncio.create_task(
                service.submit(challenge, binding.token, user.username, user.password)
            )
            try:
                await asyncio.wait_for(entered.wait(), timeout=3)
                assert not publication.done()
                async with lab.database.sessions() as session:
                    assert not list(await session.scalars(select(AuthenticationEventRow)))
                    assert len(list(await session.scalars(select(BrowserSessionRow)))) == 1
            finally:
                await blocker.execute(text("SELECT pg_advisory_unlock(984207)"))
                result = await asyncio.wait_for(publication, timeout=3)
        assert isinstance(result, CompletedLogin)
        assert await service.identity(result.cookie) == result.identity
    finally:
        event.remove(Session, "before_commit", pause)


@pytest.mark.parametrize("change", ["disabled", "password"])
async def test_credential_change_between_verification_and_binding_cannot_create_a_session(
    security_lab: SecurityLab,
    credential_browser: tuple[IdpBrowserService, SeededUser],
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    lab = security_lab
    service, user = credential_browser
    binding = await service.binding(None)
    challenge = await service.challenge(binding, LoginContinuation())
    entered, release = asyncio.Event(), asyncio.Event()
    original = PasswordAuthenticator.verify_credentials

    async def delayed(
        self: PasswordAuthenticator, username: str, password: SecretStr
    ) -> VerifiedPassword | None:
        proof = await original(self, username, password)
        entered.set()
        await release.wait()
        return proof

    monkeypatch.setattr(PasswordAuthenticator, "verify_credentials", delayed)
    attempt = asyncio.create_task(
        service.submit(challenge, binding.token, user.username, user.password)
    )
    try:
        await asyncio.wait_for(entered.wait(), timeout=3)
        replacement = await asyncio.to_thread(hash_password, SecretStr(secrets.token_urlsafe(32)))
        async with lab.database.sessions() as session:
            row = await session.get(UserRow, user.subject)
            assert row is not None
            if change == "disabled":
                row.enabled = False
            else:
                row.password_hash = replacement.get_secret_value()
            await session.commit()
    finally:
        release.set()
        result = await asyncio.wait_for(attempt, timeout=3)
    assert isinstance(result, RejectedCredentials)
    assert await service.identity(binding.token) is None
    async with lab.database.sessions() as session:
        assert not list(await session.scalars(select(AuthenticationEventRow)))
