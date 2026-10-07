"""One-use browser-bound credential forms and encrypted IDP session/event references."""

import json
import secrets

from pydantic import SecretStr
from sqlalchemy import BigInteger, CheckConstraint, ForeignKey, LargeBinary, String, delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from federated_identity.common.persistence.database import AsyncDatabase
from federated_identity.common.persistence.sessions import BrowserSessionRow
from federated_identity.common.security.model import AuthenticationMethod
from federated_identity.common.security.secrets import EnvelopeCipher
from federated_identity.common.settings.policy import Clock, verifier_digest
from federated_identity.idp.repositories.security import event_snapshot, session_snapshot
from federated_identity.idp.repositories.security_tables import (
    AuthenticationEventRow,
    IdpSessionRow,
)
from federated_identity.idp.repositories.users import UserRow
from federated_identity.idp.schemas.browser import IdpBrowserIdentity, LoginContinuation


class LoginBase(DeclarativeBase):
    pass


class LoginChallengeRow(LoginBase):
    __tablename__ = "login_challenges"
    __table_args__ = (CheckConstraint("expires_at > created_at", name="login_positive_lifetime"),)

    challenge_digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    browser_digest: Mapped[str] = mapped_column(
        ForeignKey(BrowserSessionRow.__table__.c.token_digest, ondelete="CASCADE"), nullable=False
    )
    encrypted_payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


class IdpBrowserRepository:
    def __init__(self, database: AsyncDatabase, cipher: EnvelopeCipher, clock: Clock) -> None:
        self.database = database
        self.cipher = cipher
        self.clock = clock

    async def challenge(
        self, browser: SecretStr, continuation: LoginContinuation, *, ttl: int
    ) -> SecretStr:
        if ttl <= 0:
            raise ValueError("A positive login form lifetime is required")
        challenge = SecretStr(secrets.token_urlsafe(32))
        now = self.clock.now()
        async with self.database.sessions() as session:
            session.add(
                LoginChallengeRow(
                    challenge_digest=verifier_digest(challenge.get_secret_value()),
                    browser_digest=verifier_digest(browser.get_secret_value()),
                    encrypted_payload=self.cipher.encrypt(
                        continuation.model_dump(mode="json"), purpose="idp-login"
                    ),
                    created_at=now,
                    expires_at=now + ttl,
                )
            )
            await session.commit()
        return challenge

    async def consume(self, challenge: SecretStr, browser: SecretStr) -> LoginContinuation | None:
        statement = (
            delete(LoginChallengeRow)
            .where(
                LoginChallengeRow.challenge_digest == verifier_digest(challenge.get_secret_value()),
                LoginChallengeRow.browser_digest == verifier_digest(browser.get_secret_value()),
                LoginChallengeRow.expires_at > self.clock.now(),
            )
            .returning(LoginChallengeRow.encrypted_payload)
        )
        async with self.database.sessions() as session:
            encrypted = (await session.execute(statement)).scalar_one_or_none()
            if encrypted is None:
                return None
            continuation = LoginContinuation.model_validate_json(
                json.dumps(self.cipher.decrypt(encrypted, purpose="idp-login"))
            )
            await session.commit()
        return continuation

    async def identity(self, cookie: SecretStr) -> IdpBrowserIdentity | None:
        async with self.database.sessions() as session:
            browser = await session.get(
                BrowserSessionRow, verifier_digest(cookie.get_secret_value())
            )
            return await self.identity_in(session, browser) if browser is not None else None

    async def identity_in(
        self, session: AsyncSession, browser: BrowserSessionRow
    ) -> IdpBrowserIdentity | None:
        if browser.expires_at <= self.clock.now():
            return None
        payload = self.cipher.decrypt(browser.encrypted_payload, purpose="browser-session")
        if payload.get("kind") != "idp-authenticated":
            return None
        sid, event_id = payload.get("sid"), payload.get("event_id")
        if not isinstance(sid, str) or not isinstance(event_id, str):
            raise ValueError("IDP browser sessions require persisted authentication references")
        statement = (
            select(IdpSessionRow, AuthenticationEventRow, UserRow)
            .join(
                AuthenticationEventRow,
                AuthenticationEventRow.session_id == IdpSessionRow.session_id,
            )
            .join(UserRow, UserRow.subject == IdpSessionRow.subject)
            .where(
                IdpSessionRow.session_id == sid,
                AuthenticationEventRow.event_id == event_id,
                IdpSessionRow.revoked_at.is_(None),
                IdpSessionRow.expires_at > self.clock.now(),
                UserRow.enabled.is_(True),
            )
        )
        result = (await session.execute(statement)).one_or_none()
        if result is None:
            return None
        parent, event, user = result
        if min(browser.expires_at, parent.expires_at) <= self.clock.now():
            return None
        authentication = event_snapshot(event, parent)
        if AuthenticationMethod.PASSWORD not in authentication.methods:
            return None
        return IdpBrowserIdentity(
            session=session_snapshot(parent), authentication=authentication, username=user.username
        )

    async def bind_in(
        self,
        session: AsyncSession,
        identity: IdpBrowserIdentity,
        previous: BrowserSessionRow,
        *,
        ttl: int,
    ) -> SecretStr:
        cookie = SecretStr(secrets.token_urlsafe(32))
        now = self.clock.now()
        session.add(
            BrowserSessionRow(
                token_digest=verifier_digest(cookie.get_secret_value()),
                encrypted_payload=self.cipher.encrypt(
                    {
                        "kind": "idp-authenticated",
                        "sid": identity.session.session_id,
                        "event_id": identity.authentication.event_id,
                    },
                    purpose="browser-session",
                ),
                created_at=now,
                expires_at=now + ttl,
            )
        )
        await session.delete(previous)
        await session.flush()
        return cookie
