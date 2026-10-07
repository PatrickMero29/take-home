"""Password verification, immutable authentication history, and opaque browser binding."""

from dataclasses import dataclass

from pydantic import SecretStr

from federated_identity.common.persistence.actions import PostgresBrowserActions
from federated_identity.common.persistence.sessions import BrowserSessionRow, SessionBackend
from federated_identity.common.security.actions import BrowserAction, BrowserActionPurpose
from federated_identity.common.security.browser import BrowserBinding, browser_binding
from federated_identity.common.security.model import (
    AuthenticationMethod,
    Denial,
    FederationGrant,
    RevocationReason,
    SecurityDenied,
)
from federated_identity.common.settings.policy import verifier_digest
from federated_identity.common.settings.runtime import RuntimeSettings
from federated_identity.idp.repositories.browser import IdpBrowserRepository
from federated_identity.idp.repositories.security import grant_snapshot
from federated_identity.idp.repositories.security_tables import FederationGrantRow
from federated_identity.idp.repositories.throttling import (
    AuthenticationLimiter,
    AuthenticationThrottled,
)
from federated_identity.idp.repositories.users import UserRow
from federated_identity.idp.schemas.browser import (
    CompletedLogin,
    IdpBrowserIdentity,
    LoginContinuation,
)
from federated_identity.idp.services.authentication import PasswordAuthenticator
from federated_identity.idp.services.mfa import TotpAuthenticator
from federated_identity.idp.services.security_model import IdpSecurityModel


class InvalidLoginForm(ValueError):
    pass


@dataclass(frozen=True)
class RejectedCredentials:
    continuation: LoginContinuation


class IdpBrowserService:
    def __init__(
        self,
        settings: RuntimeSettings,
        repository: IdpBrowserRepository,
        sessions: SessionBackend,
        security: IdpSecurityModel,
        authentication: PasswordAuthenticator,
        mfa: TotpAuthenticator,
    ) -> None:
        self.settings = settings
        self.repository = repository
        self.sessions = sessions
        self.security = security
        self.authentication = authentication
        self.mfa = mfa
        self.limiter = AuthenticationLimiter(repository.database, repository.clock, settings)
        self.actions = PostgresBrowserActions(
            repository.database, repository.cipher, repository.clock
        )
        if repository.database is not security.repository.database:
            raise ValueError(
                "IDP browser binding and authentication must share a transaction store"
            )

    async def binding(self, cookie: SecretStr | None) -> BrowserBinding:
        return await browser_binding(
            cookie, settings=self.settings, sessions=self.sessions, clock=self.repository.clock
        )

    async def identity(self, cookie: SecretStr | None) -> IdpBrowserIdentity | None:
        if cookie is None:
            return None
        identity = await self.repository.identity(cookie)
        if identity is not None and identity.session.subject.issuer != self.settings.issuer:
            return None
        return identity

    async def challenge(
        self, binding: BrowserBinding, continuation: LoginContinuation
    ) -> SecretStr:
        now = self.repository.clock.now()
        deadline = continuation.expires_at or now + self.settings.login_transaction_ttl_seconds
        ttl = min(binding.ttl, self.settings.login_transaction_ttl_seconds, deadline - now)
        if ttl <= 0:
            raise InvalidLoginForm("The original credential continuation has expired")
        return await self.repository.challenge(
            binding.token,
            continuation.model_copy(update={"expires_at": deadline}),
            ttl=ttl,
        )

    async def grants(self, cookie: SecretStr) -> list[FederationGrant]:
        async with self.security.repository.transaction() as work:
            browser = await work.session.get(
                BrowserSessionRow, verifier_digest(cookie.get_secret_value())
            )
            identity = (
                await self.repository.identity_in(work.session, browser)
                if browser is not None
                else None
            )
            if identity is None or identity.session.subject.issuer != self.settings.issuer:
                raise SecurityDenied(Denial.MISSING)
            return [
                grant_snapshot(row)
                for row in await work.grants_for_session(identity.session.session_id)
            ]

    async def action_challenge(self, cookie: SecretStr, action: BrowserAction) -> SecretStr:
        identity = await self.identity(cookie)
        if identity is None:
            raise SecurityDenied(Denial.MISSING)
        if action.purpose == BrowserActionPurpose.IDP_LOGOUT:
            if action.target != identity.session.session_id:
                raise SecurityDenied(Denial.BINDING)
        elif action.purpose == BrowserActionPurpose.IDP_REVOKE:
            if not any(grant.grant_id == action.target for grant in await self.grants(cookie)):
                raise SecurityDenied(Denial.BINDING)
        else:
            raise SecurityDenied(Denial.PURPOSE)
        return await self.actions.issue(
            cookie,
            action,
            expires_at=min(
                identity.session.expires_at,
                self.repository.clock.now() + self.settings.browser_action_ttl_seconds,
            ),
        )

    async def act(
        self, cookie: SecretStr, challenge: SecretStr, purpose: BrowserActionPurpose
    ) -> str | None:
        ended_session: str | None = None
        async with self.security.repository.transaction() as work:
            browser = await work.session.get(
                BrowserSessionRow, verifier_digest(cookie.get_secret_value()), with_for_update=True
            )
            identity = (
                await self.repository.identity_in(work.session, browser)
                if browser is not None
                else None
            )
            if identity is None or identity.session.subject.issuer != self.settings.issuer:
                raise SecurityDenied(Denial.MISSING)
            action = await self.actions.consume_in(work.session, challenge, cookie, purpose)
            if purpose == BrowserActionPurpose.IDP_LOGOUT:
                if action.target != identity.session.session_id:
                    raise SecurityDenied(Denial.BINDING)
                await self.security.end_session_in(work, action.target)
                ended_session = action.target
                if browser is not None:
                    await work.session.delete(browser)
            elif purpose == BrowserActionPurpose.IDP_REVOKE:
                grant = await work.get(FederationGrantRow, action.target)
                if grant is None or grant.session_id != identity.session.session_id:
                    raise SecurityDenied(Denial.BINDING)
                await self.security.revoke_grant_in(
                    work,
                    grant.grant_id,
                    authenticated_client=grant.client_id,
                    reason=RevocationReason.USER_REVOCATION,
                )
            else:
                raise SecurityDenied(Denial.PURPOSE)
        return ended_session

    async def submit(
        self,
        challenge: SecretStr,
        browser: SecretStr,
        username: str,
        password: SecretStr,
        otp: SecretStr | None = None,
        *,
        source: str = "local",
    ) -> CompletedLogin | RejectedCredentials:
        continuation = await self.repository.consume(challenge, browser)
        if continuation is None:
            raise InvalidLoginForm("The login form has expired or does not belong to this browser")
        if (
            continuation.requires_totp
            and continuation.attempts >= self.settings.mfa_form_max_attempts
        ):
            raise AuthenticationThrottled(self.settings.authentication_window_seconds)
        await self.limiter.reserve(username, browser, source)
        rejected = RejectedCredentials(
            continuation.model_copy(update={"attempts": min(20, continuation.attempts + 1)})
        )
        # No database lock is held during the bounded, off-thread Argon2id work.
        proof = await self.authentication.verify_credentials(username, password)
        if proof is None:
            return rejected
        async with self.security.repository.transaction() as work:
            previous = await work.session.get(
                BrowserSessionRow,
                verifier_digest(browser.get_secret_value()),
                with_for_update=True,
            )
            if previous is None or previous.expires_at <= self.repository.clock.now():
                raise InvalidLoginForm("The initiating browser session is no longer active")
            if (
                continuation.expires_at is not None
                and continuation.expires_at <= self.repository.clock.now()
            ):
                raise InvalidLoginForm("The credential continuation expired during verification")
            user = await work.session.get(UserRow, proof.credential.subject, with_for_update=True)
            if (
                user is None
                or not user.enabled
                or user.username != proof.credential.username
                or user.password_hash != proof.credential.password_hash.get_secret_value()
            ):
                return rejected
            current = await self.repository.identity_in(work.session, previous)
            if (
                continuation.expected_subject is not None
                and (
                    current is None
                    or proof.credential.subject != continuation.expected_subject
                    or current.session.subject.subject != continuation.expected_subject
                )
            ) or (current is not None and current.session.subject != proof.authentication.subject):
                return rejected
            authentication = proof.authentication
            totp = None
            if continuation.requires_totp:
                if otp is None:
                    return rejected
                totp = await self.mfa.match_in(work.session, user.subject, otp)
                if totp is None:
                    return rejected
                authentication = authentication.model_copy(
                    update={
                        "methods": (AuthenticationMethod.PASSWORD, AuthenticationMethod.OTP),
                        "authenticated_at": self.repository.clock.now(),
                    }
                )
            elif otp is not None:
                return rejected
            if current is None:
                parent, event = await self.security.open_session_in(work, authentication)
            else:
                parent = current.session
                event = await self.security.reauthenticate_in(
                    work, parent.session_id, authentication
                )
            if totp is not None:
                if otp is None:
                    raise RuntimeError("A matched factor requires its submitted code")
                self.mfa.consume_in(work.session, totp, event.event_id, otp)
            identity = IdpBrowserIdentity(
                session=parent, authentication=event, username=proof.credential.username
            )
            ttl = min(
                self.settings.session_ttl_seconds,
                parent.expires_at - self.repository.clock.now(),
            )
            if ttl <= 0:
                raise InvalidLoginForm("The authentication session has expired")
            cookie = await self.repository.bind_in(work.session, identity, previous, ttl=ttl)
            result = CompletedLogin(
                cookie=cookie, identity=identity, continuation=continuation, ttl=ttl
            )
        # The browser identifier, event and session are committed before publication.
        return result
