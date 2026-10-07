"""Separate credential-backed operator sessions; no federation artifact grants authority."""

import secrets
from dataclasses import dataclass
from http import HTTPStatus

from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

from federated_identity.common.persistence.actions import PostgresBrowserActions
from federated_identity.common.persistence.sessions import BrowserSessionRow, SessionBackend
from federated_identity.common.security.actions import BrowserAction, BrowserActionPurpose
from federated_identity.common.security.model import Denial, SecurityDenied
from federated_identity.common.security.passwords import Argon2Passwords
from federated_identity.common.settings.policy import verifier_digest
from federated_identity.common.settings.runtime import RuntimeSettings
from federated_identity.idp.repositories.operator import (
    OperatorRepository,
    OperatorRow,
    OperatorSessionRow,
    operator_credential,
)
from federated_identity.idp.schemas.operator import (
    OperatorAuthorization,
    OperatorChannel,
    OperatorPermission,
    OperatorPrincipal,
)
from federated_identity.idp.services.security_model import IdpSecurityModel


class OperatorError(ValueError):
    def __init__(self, description: str, status: HTTPStatus) -> None:
        super().__init__(description)
        self.description = description
        self.status = status


@dataclass(frozen=True)
class OperatorSession:
    token: SecretStr
    ttl: int


class OperatorService:
    def __init__(
        self,
        settings: RuntimeSettings,
        repository: OperatorRepository,
        sessions: SessionBackend,
        passwords: Argon2Passwords,
        security: IdpSecurityModel,
    ) -> None:
        self.settings = settings
        self.repository = repository
        self.sessions = sessions
        self.passwords = passwords
        self.security = security
        self.actions = PostgresBrowserActions(
            repository.database, repository.cipher, repository.clock
        )

    async def login_form(self, cookie: SecretStr | None) -> tuple[SecretStr, SecretStr]:
        existing = await self.sessions.lookup(cookie) if cookie is not None else None
        if existing is None or existing.payload.get("kind") != "operator-anonymous":
            cookie = await self.sessions.create(
                {"kind": "operator-anonymous"}, ttl=self.settings.browser_action_ttl_seconds
            )
        if cookie is None:
            raise RuntimeError("Operator form requires its generated browser binding")
        challenge = await self.actions.issue(
            cookie,
            BrowserAction(purpose=BrowserActionPurpose.OPERATOR_LOGIN, target="operator"),
            expires_at=self.repository.clock.now() + self.settings.browser_action_ttl_seconds,
        )
        return cookie, challenge

    async def login(
        self,
        username: str,
        password: SecretStr,
        *,
        channel: OperatorChannel,
        browser: SecretStr | None = None,
        challenge: SecretStr | None = None,
    ) -> OperatorSession:
        if channel == OperatorChannel.BROWSER:
            if browser is None or challenge is None:
                raise OperatorError("An operator login form is required", HTTPStatus.FORBIDDEN)
            async with self.repository.database.sessions() as session:
                async with session.begin():
                    try:
                        await self.actions.consume_in(
                            session, challenge, browser, BrowserActionPurpose.OPERATOR_LOGIN
                        )
                    except SecurityDenied:
                        raise OperatorError(
                            "The operator form is invalid or expired", HTTPStatus.FORBIDDEN
                        ) from None
        elif browser is not None or challenge is not None:
            raise OperatorError("API login cannot reuse a browser form", HTTPStatus.BAD_REQUEST)
        credential = await self.repository.credential(username)
        matched = await self.passwords.verify(
            password, credential.password_hash if credential is not None else None
        )
        if not matched or credential is None or not credential.enabled:
            raise OperatorError("Invalid operator credentials", HTTPStatus.UNAUTHORIZED)
        token = SecretStr(secrets.token_urlsafe(32))
        async with self.security.repository.transaction() as work:
            current = await work.session.get(
                OperatorRow, credential.operator_id, with_for_update=True
            )
            if current is None or operator_credential(current) != credential:
                raise OperatorError("Invalid operator credentials", HTTPStatus.UNAUTHORIZED)
            previous = None
            if browser is not None:
                previous = await work.session.get(
                    BrowserSessionRow,
                    verifier_digest(browser.get_secret_value()),
                    with_for_update=True,
                )
                if previous is None or previous.expires_at <= self.repository.clock.now():
                    raise OperatorError(
                        "The initiating operator browser is no longer active", HTTPStatus.FORBIDDEN
                    )
                payload = self.repository.cipher.decrypt(
                    previous.encrypted_payload, purpose="browser-session"
                )
                if payload.get("kind") != "operator-anonymous":
                    raise OperatorError(
                        "An operator browser binding is required", HTTPStatus.FORBIDDEN
                    )
            now = self.repository.clock.now()
            ttl = self.settings.operator_session_ttl_seconds
            digest = verifier_digest(token.get_secret_value())
            work.session.add(
                BrowserSessionRow(
                    token_digest=digest,
                    created_at=now,
                    expires_at=now + ttl,
                    encrypted_payload=self.repository.cipher.encrypt(
                        {
                            "kind": f"operator-{channel.value}",
                            "operator_id": credential.operator_id,
                            "credential_version": credential.credential_version,
                        },
                        purpose="browser-session",
                    ),
                )
            )
            await work.flush()
            work.session.add(
                OperatorSessionRow(
                    token_digest=digest,
                    operator_id=credential.operator_id,
                    credential_version=credential.credential_version,
                    channel=channel.value,
                )
            )
            if previous is not None:
                await work.session.delete(previous)
        return OperatorSession(token, ttl)

    async def principal(
        self, authorization: OperatorAuthorization, permission: OperatorPermission | None = None
    ) -> OperatorPrincipal:
        async with self.repository.database.sessions() as session:
            return await self.authorize_in(session, authorization, permission)

    async def authorize_in(
        self,
        session: AsyncSession,
        authorization: OperatorAuthorization,
        permission: OperatorPermission | None = None,
    ) -> OperatorPrincipal:
        try:
            return await self.repository.authorize_in(
                session, authorization.token, authorization.channel, permission
            )
        except SecurityDenied as error:
            if error.reason == Denial.RECIPIENT:
                raise OperatorError(
                    "Operator permission is required", HTTPStatus.FORBIDDEN
                ) from None
            raise OperatorError(
                "Operator authentication is required", HTTPStatus.UNAUTHORIZED
            ) from None

    async def action(
        self, authorization: OperatorAuthorization, purpose: BrowserActionPurpose, target: str
    ) -> SecretStr:
        if authorization.channel != OperatorChannel.BROWSER:
            raise OperatorError(
                "Browser intentions require an operator browser session", HTTPStatus.FORBIDDEN
            )
        permission: OperatorPermission | None
        if purpose in {
            BrowserActionPurpose.SIGNING_PREPARE,
            BrowserActionPurpose.SIGNING_ACTIVATE,
            BrowserActionPurpose.SIGNING_RETIRE,
            BrowserActionPurpose.SIGNING_CONTAIN,
        }:
            permission = OperatorPermission.KEYS_WRITE
        else:
            permission = (
                OperatorPermission.CLIENTS_WRITE
                if purpose != BrowserActionPurpose.OPERATOR_LOGOUT
                else None
            )
        principal = await self.principal(authorization, permission)
        return await self.actions.issue(
            authorization.token,
            BrowserAction(purpose=purpose, target=target),
            expires_at=min(
                principal.expires_at,
                self.repository.clock.now() + self.settings.browser_action_ttl_seconds,
            ),
        )

    async def consume_in(
        self,
        session: AsyncSession,
        authorization: OperatorAuthorization,
        purpose: BrowserActionPurpose,
        target: str,
    ) -> None:
        if authorization.channel == OperatorChannel.API:
            if authorization.challenge is not None:
                raise OperatorError(
                    "API authority cannot use browser intentions", HTTPStatus.FORBIDDEN
                )
            return
        if authorization.challenge is None:
            raise OperatorError("An operator browser intention is required", HTTPStatus.FORBIDDEN)
        try:
            action = await self.actions.consume_in(
                session, authorization.challenge, authorization.token, purpose
            )
            if action.target != target:
                raise SecurityDenied(Denial.BINDING)
        except SecurityDenied:
            raise OperatorError(
                "The operator intention is invalid or expired", HTTPStatus.FORBIDDEN
            ) from None

    async def logout(self, authorization: OperatorAuthorization) -> None:
        async with self.security.repository.transaction() as work:
            await self.authorize_in(work.session, authorization)
            await self.consume_in(
                work.session, authorization, BrowserActionPurpose.OPERATOR_LOGOUT, "operator"
            )
            browser = await work.session.get(
                BrowserSessionRow,
                verifier_digest(authorization.token.get_secret_value()),
                with_for_update=True,
            )
            if browser is not None:
                await work.session.delete(browser)
