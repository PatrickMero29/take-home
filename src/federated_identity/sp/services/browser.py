"""Browser-bound authorization orchestration with persisted one-use transactions."""

from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlencode

from pydantic import SecretStr

from federated_identity.common.persistence.actions import PostgresBrowserActions
from federated_identity.common.persistence.sessions import BrowserSessionRow, SessionBackend
from federated_identity.common.security.actions import BrowserAction, BrowserActionPurpose
from federated_identity.common.security.browser import BrowserBinding, browser_binding
from federated_identity.common.security.contracts import GrantRevoker
from federated_identity.common.security.model import (
    Assurance,
    AuthenticationRequirement,
    Denial,
    SecurityDenied,
    SpSessionEvidence,
)
from federated_identity.common.settings.policy import verifier_digest
from federated_identity.common.settings.runtime import RuntimeSettings
from federated_identity.sp.protocol.oidc import InvalidAuthorizationResponse, OidcClient
from federated_identity.sp.repositories.security_tables import SpAuthenticationRow
from federated_identity.sp.repositories.transactions import PostgresAuthorizationTransactions
from federated_identity.sp.services.security_model import SpSecurityModel


@dataclass(frozen=True)
class StartedLogin:
    authorization_url: str = field(repr=False)
    binding: BrowserBinding


@dataclass(frozen=True)
class EstablishedLogin:
    cookie: SecretStr
    ttl: int


class SpBrowserService:
    def __init__(
        self,
        settings: RuntimeSettings,
        sessions: SessionBackend,
        oidc: OidcClient,
        transactions: PostgresAuthorizationTransactions,
        security: SpSecurityModel,
        revoker: GrantRevoker,
    ) -> None:
        self.settings = settings
        self.sessions = sessions
        self.oidc = oidc
        self.transactions = transactions
        self.security = security
        self.revoker = revoker
        self.actions = PostgresBrowserActions(
            security.repository.database, security.repository.cipher, security.clock
        )

    async def binding(self, cookie: SecretStr | None) -> BrowserBinding:
        if cookie is not None:
            loaded = await self.security.repository.load(cookie)
            if loaded is not None and (
                loaded[0].revoked_at is not None
                or min(loaded[0].expires_at, loaded[0].idle_expires_at) <= self.oidc.clock.now()
            ):
                cookie = None
        return await browser_binding(
            cookie, settings=self.settings, sessions=self.sessions, clock=self.oidc.clock
        )

    async def begin(
        self,
        cookie: SecretStr | None,
        *,
        prompt: Literal["login"] | None = None,
        max_age: int | None = None,
        acr_values: Assurance | None = None,
        expected_subject: str | None = None,
    ) -> StartedLogin:
        binding = await self.binding(cookie)
        transaction = self.oidc.begin(
            prompt=prompt, max_age=max_age, acr_values=acr_values, expected_subject=expected_subject
        )
        await self.transactions.save(
            transaction,
            binding.token,
            ttl=min(binding.ttl, self.settings.login_transaction_ttl_seconds),
        )
        return StartedLogin(transaction.authorization_url, binding)

    async def complete(self, state: str, browser: SecretStr, callback_url: str) -> EstablishedLogin:
        if await self.sessions.lookup(browser) is None:
            raise InvalidAuthorizationResponse("The initiating browser session is not active")
        transaction = await self.transactions.consume(state, browser)
        if transaction is None:
            raise InvalidAuthorizationResponse("No active transaction belongs to this browser")
        login = await self.oidc.exchange_verified(transaction, callback_url)
        cookie = await self.security.establish_login(login, previous_cookie=browser)
        now = self.oidc.clock.now()
        ttl = min(
            self.settings.lifecycle.sp_session_seconds,
            login.context.session_expires_at - now,
            login.context.grant.expires_at - now,
            login.context.family.expires_at - now,
        )
        return EstablishedLogin(cookie, ttl)

    async def authorize(self, cookie: SecretStr) -> SpSessionEvidence:
        return await self.security.authorize(cookie, AuthenticationRequirement())

    async def action_challenge(self, cookie: SecretStr, purpose: BrowserActionPurpose) -> SecretStr:
        if purpose not in {
            BrowserActionPurpose.SP_LOGOUT,
            BrowserActionPurpose.SP_GLOBAL_LOGOUT,
            BrowserActionPurpose.SP_REVOKE,
            BrowserActionPurpose.SP_REAUTHENTICATE,
            BrowserActionPurpose.SP_STEP_UP,
        }:
            raise SecurityDenied(Denial.PURPOSE)
        loaded = await self.security.repository.load(cookie)
        if loaded is None or loaded[0].revoked_at is not None:
            raise SecurityDenied(Denial.MISSING)
        local = loaded[0]
        if local.issuer != self.settings.issuer or local.client_id != self.settings.client_id:
            raise SecurityDenied(Denial.BINDING)
        return await self.actions.issue(
            cookie,
            BrowserAction(purpose=purpose, target=local.grant_id),
            expires_at=min(
                local.expires_at,
                self.oidc.clock.now() + self.settings.browser_action_ttl_seconds,
            ),
        )

    async def reauthenticate(
        self, cookie: SecretStr, challenge: SecretStr, *, force: bool, max_age: int
    ) -> StartedLogin:
        local = await self.consume_authentication_intent(
            cookie, challenge, BrowserActionPurpose.SP_REAUTHENTICATE
        )
        return await self.begin(
            cookie,
            prompt="login" if force else None,
            max_age=0 if force else max_age,
            expected_subject=local.subject,
        )

    async def step_up(self, cookie: SecretStr, challenge: SecretStr) -> StartedLogin:
        local = await self.consume_authentication_intent(
            cookie, challenge, BrowserActionPurpose.SP_STEP_UP
        )
        return await self.begin(
            cookie,
            prompt="login",
            max_age=0,
            acr_values=Assurance.PASSWORD_TOTP,
            expected_subject=local.subject,
        )

    async def consume_authentication_intent(
        self, cookie: SecretStr, challenge: SecretStr, purpose: BrowserActionPurpose
    ) -> SpSessionEvidence:
        async with self.security.repository.database.sessions() as session:
            async with session.begin():
                browser = await session.get(
                    BrowserSessionRow,
                    verifier_digest(cookie.get_secret_value()),
                    with_for_update=True,
                )
                loaded = await self.security.repository.load_in(session, cookie)
                if (
                    browser is None
                    or loaded is None
                    or loaded[0].revoked_at is not None
                    or min(browser.expires_at, loaded[0].expires_at, loaded[0].idle_expires_at)
                    <= self.oidc.clock.now()
                ):
                    raise SecurityDenied(Denial.REVOKED)
                action = await self.actions.consume_in(session, challenge, cookie, purpose)
                if action.target != loaded[0].grant_id:
                    raise SecurityDenied(Denial.BINDING)
                if (
                    loaded[0].issuer != self.settings.issuer
                    or loaded[0].client_id != self.settings.client_id
                ):
                    raise SecurityDenied(Denial.BINDING)
                result = loaded[0]
        return result

    async def global_logout(self, cookie: SecretStr, challenge: SecretStr) -> str:
        async with self.security.repository.database.sessions() as session:
            async with session.begin():
                digest = verifier_digest(cookie.get_secret_value())
                browser = await session.get(BrowserSessionRow, digest, with_for_update=True)
                row = await session.get(SpAuthenticationRow, digest, with_for_update=True)
                loaded = await self.security.repository.load_in(session, cookie)
                if (
                    browser is None
                    or row is None
                    or loaded is None
                    or row.revoked_at is not None
                    or min(browser.expires_at, row.expires_at, row.idle_expires_at)
                    <= self.oidc.clock.now()
                    or loaded[0].issuer != self.settings.issuer
                    or loaded[0].client_id != self.settings.client_id
                ):
                    raise SecurityDenied(Denial.MISSING)
                action = await self.actions.consume_in(
                    session, challenge, cookie, BrowserActionPurpose.SP_GLOBAL_LOGOUT
                )
                if action.target != row.grant_id:
                    raise SecurityDenied(Denial.BINDING)
                evidence = self.security.repository.cipher.decrypt(
                    row.encrypted_evidence, purpose="sp-authentication"
                )
                parameters = {
                    "client_id": self.settings.client_id,
                    "post_logout_redirect_uri": f"{self.settings.public_url}/",
                }
                hint = evidence.get("id_token")
                if isinstance(hint, str):
                    parameters["id_token_hint"] = hint
        # The OP still authenticates and confirms its current browser. Cancellation
        # there leaves this SP signed in; completed logout arrives by the back-channel.
        return f"{self.settings.issuer}/end-session?{urlencode(parameters)}"

    async def act(
        self, cookie: SecretStr, challenge: SecretStr, purpose: BrowserActionPurpose
    ) -> None:
        if purpose not in {BrowserActionPurpose.SP_LOGOUT, BrowserActionPurpose.SP_REVOKE}:
            raise SecurityDenied(Denial.PURPOSE)
        async with self.security.repository.database.sessions() as session:
            async with session.begin():
                browser = await session.get(
                    BrowserSessionRow,
                    verifier_digest(cookie.get_secret_value()),
                    with_for_update=True,
                )
                if browser is None or browser.expires_at <= self.oidc.clock.now():
                    raise SecurityDenied(Denial.EXPIRED)
                loaded = await self.security.repository.load_in(session, cookie)
                if loaded is None or loaded[0].revoked_at is not None:
                    raise SecurityDenied(Denial.MISSING)
                if (
                    loaded[0].issuer != self.settings.issuer
                    or loaded[0].client_id != self.settings.client_id
                ):
                    raise SecurityDenied(Denial.BINDING)
                action = await self.actions.consume_in(session, challenge, cookie, purpose)
                if action.target != loaded[0].grant_id:
                    raise SecurityDenied(Denial.BINDING)
                if purpose == BrowserActionPurpose.SP_LOGOUT:
                    await self.security.repository.revoke_in(
                        session, cookie, now=self.oidc.clock.now()
                    )
        if purpose == BrowserActionPurpose.SP_REVOKE:
            # Commit the one-use intent, release local locks, then authenticate
            # the owning SP to the IDP. Outages preserve the local session.
            await self.revoker.revoke(loaded[1])
            await self.security.logout_local(cookie)
