"""Expiring one-use CSRF intents, consumed in the caller's lifecycle transaction."""

import json
import secrets

from pydantic import SecretStr
from sqlalchemy import BigInteger, CheckConstraint, ForeignKey, LargeBinary, String, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from federated_identity.common.persistence.database import AsyncDatabase
from federated_identity.common.persistence.sessions import BrowserSessionRow
from federated_identity.common.security.actions import BrowserAction, BrowserActionPurpose
from federated_identity.common.security.model import Denial, SecurityDenied
from federated_identity.common.security.secrets import EnvelopeCipher
from federated_identity.common.settings.policy import Clock, verifier_digest


class ActionBase(DeclarativeBase):
    pass


class BrowserActionRow(ActionBase):
    __tablename__ = "browser_actions"
    __table_args__ = (CheckConstraint("expires_at > created_at", name="action_positive_lifetime"),)

    challenge_digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    browser_digest: Mapped[str] = mapped_column(
        ForeignKey(BrowserSessionRow.__table__.c.token_digest, ondelete="CASCADE"), nullable=False
    )
    purpose: Mapped[str] = mapped_column(String(32), nullable=False)
    encrypted_payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    created_at: Mapped[int] = mapped_column(BigInteger, nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


class PostgresBrowserActions:
    def __init__(self, database: AsyncDatabase, cipher: EnvelopeCipher, clock: Clock) -> None:
        self.database = database
        self.cipher = cipher
        self.clock = clock

    async def issue(
        self, browser: SecretStr, action: BrowserAction, *, expires_at: int
    ) -> SecretStr:
        async with self.database.sessions() as session:
            async with session.begin():
                challenge = await self.issue_in(session, browser, action, expires_at=expires_at)
        return challenge

    async def issue_in(
        self, session: AsyncSession, browser: SecretStr, action: BrowserAction, *, expires_at: int
    ) -> SecretStr:
        challenge = SecretStr(secrets.token_urlsafe(32))
        row = await session.get(
            BrowserSessionRow,
            verifier_digest(browser.get_secret_value()),
            with_for_update=True,
        )
        now = self.clock.now()
        expires = min(expires_at, row.expires_at) if row is not None else now
        if expires <= now:
            raise SecurityDenied(Denial.EXPIRED)
        session.add(
            BrowserActionRow(
                challenge_digest=verifier_digest(challenge.get_secret_value()),
                browser_digest=verifier_digest(browser.get_secret_value()),
                purpose=action.purpose.value,
                encrypted_payload=self.cipher.encrypt(
                    action.model_dump(mode="json"), purpose="browser-action"
                ),
                created_at=now,
                expires_at=expires,
            )
        )
        return challenge

    async def consume_in(
        self,
        session: AsyncSession,
        challenge: SecretStr,
        browser: SecretStr,
        purpose: BrowserActionPurpose,
    ) -> BrowserAction:
        statement = (
            delete(BrowserActionRow)
            .where(
                BrowserActionRow.challenge_digest == verifier_digest(challenge.get_secret_value()),
                BrowserActionRow.browser_digest == verifier_digest(browser.get_secret_value()),
                BrowserActionRow.purpose == purpose.value,
                BrowserActionRow.expires_at > self.clock.now(),
            )
            .returning(BrowserActionRow.encrypted_payload)
        )
        encrypted = (await session.execute(statement)).scalar_one_or_none()
        if encrypted is None:
            raise SecurityDenied(Denial.BINDING)
        action = BrowserAction.model_validate_json(
            json.dumps(self.cipher.decrypt(encrypted, purpose="browser-action"))
        )
        if action.purpose != purpose:
            raise SecurityDenied(Denial.PURPOSE)
        return action
