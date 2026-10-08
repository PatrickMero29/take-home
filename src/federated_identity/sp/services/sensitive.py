"""Fresh stronger assurance is enforced at both page access and operation commit."""

import uuid

from pydantic import SecretStr

from federated_identity.common.persistence.sessions import BrowserSessionRow
from federated_identity.common.security.actions import BrowserAction, BrowserActionPurpose
from federated_identity.common.security.model import (
    Assurance,
    AuthenticationRequirement,
    Denial,
    SecurityDenied,
    SpSessionEvidence,
)
from federated_identity.common.security.policies import require_assurance
from federated_identity.common.settings.policy import verifier_digest
from federated_identity.sp.repositories.sensitive import SensitiveOperationRow
from federated_identity.sp.services.browser import SpBrowserService


class SpSensitiveService:
    def __init__(self, browser: SpBrowserService) -> None:
        self.browser = browser
        self.security = browser.security

    @property
    def requirement(self) -> AuthenticationRequirement:
        return AuthenticationRequirement(
            minimum=Assurance.PASSWORD_TOTP,
            max_age_seconds=self.browser.settings.sensitive_max_age_seconds,
        )

    async def authorize(self, cookie: SecretStr) -> SpSessionEvidence:
        return await self.security.authorize(cookie, self.requirement)

    async def challenge(self, cookie: SecretStr, local: SpSessionEvidence) -> SecretStr:
        return await self.browser.actions.issue(
            cookie,
            BrowserAction(purpose=BrowserActionPurpose.SP_SENSITIVE, target=local.grant_id),
            expires_at=min(
                local.expires_at,
                self.security.clock.now() + self.browser.settings.browser_action_ttl_seconds,
            ),
        )

    async def act(self, cookie: SecretStr, challenge: SecretStr) -> str:
        authorized = await self.authorize(cookie)  # No local lock spans online authority.
        digest = verifier_digest(cookie.get_secret_value())
        async with self.security.repository.database.sessions() as session:
            async with session.begin():
                browser = await session.get(BrowserSessionRow, digest, with_for_update=True)
                loaded = await self.security.repository.load_in(session, cookie)
                now = self.security.clock.now()
                if (
                    browser is None
                    or loaded is None
                    or loaded[0].revoked_at is not None
                    or min(browser.expires_at, loaded[0].expires_at, loaded[0].idle_expires_at)
                    <= now
                    or loaded[0].authentication != authorized.authentication
                    or loaded[0].grant_id != authorized.grant_id
                ):
                    raise SecurityDenied(Denial.REVOKED)
                require_assurance(loaded[0].authentication, self.requirement, now=now)
                action = await self.browser.actions.consume_in(
                    session, challenge, cookie, BrowserActionPurpose.SP_SENSITIVE
                )
                if action.target != loaded[0].grant_id:
                    raise SecurityDenied(Denial.BINDING)
                identifier = str(uuid.uuid4())
                session.add(
                    SensitiveOperationRow(
                        operation_id=identifier,
                        token_digest=digest,
                        created_at=now,
                        encrypted_evidence=self.security.repository.cipher.encrypt(
                            {
                                "subject": authorized.subject,
                                "grant_id": authorized.grant_id,
                                "authentication": authorized.authentication.model_dump(mode="json"),
                                "authorized_at": now,
                            },
                            purpose="sensitive-operation",
                        ),
                    )
                )
        return identifier
