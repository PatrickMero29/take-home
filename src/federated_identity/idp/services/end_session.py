"""RP-Initiated Logout with historical hints, current-browser matching, and explicit intent."""

import asyncio
from dataclasses import dataclass
from urllib.parse import urlencode

from joserfc import jwt
from joserfc.errors import JoseError
from joserfc.jwk import RSAKey
from pydantic import Field, SecretStr, ValidationError

from federated_identity.common.persistence.sessions import BrowserSessionRow
from federated_identity.common.security.actions import (
    BrowserAction,
    BrowserActionPurpose,
    LogoutReturn,
)
from federated_identity.common.security.artifacts import BaseIdTokenClaims, JwtHeader
from federated_identity.common.security.model import Denial, KeyState, SecurityDenied
from federated_identity.common.security.oidc import InvalidIdToken, login_header
from federated_identity.common.settings.policy import (
    SIGNING_ALGORITHM,
    FrozenModel,
    Identifier,
    verifier_digest,
)
from federated_identity.idp.repositories.security import SecurityUnitOfWork
from federated_identity.idp.repositories.security_tables import (
    AuthenticationEvidenceRow,
    IdpSessionRow,
    RefreshIssuanceRow,
    SigningTrustRow,
)
from federated_identity.idp.repositories.tables import ClientRow
from federated_identity.idp.schemas.clients import ClientUri
from federated_identity.idp.services.browser import IdpBrowserService


class InvalidLogoutRequest(ValueError):
    pass


class EndSessionParameters(FrozenModel):
    id_token_hint: SecretStr | None = None
    client_id: Identifier | None = None
    post_logout_redirect_uri: ClientUri | None = None
    state: str | None = Field(default=None, min_length=1, max_length=256)
    # These optional advisory parameters cannot select an account or a session.
    logout_hint: str | None = Field(default=None, max_length=255)
    ui_locales: str | None = Field(default=None, max_length=256)


def logout_return_uri(context: LogoutReturn | None) -> str | None:
    if context is None or context.post_logout_redirect_uri is None:
        return None
    location = context.post_logout_redirect_uri
    if context.state is not None:
        location = f"{location}?{urlencode({'state': context.state})}"
    return location


@dataclass(frozen=True)
class LogoutPrompt:
    challenge: SecretStr | None
    return_uri: str | None = None


@dataclass(frozen=True)
class CompletedLogout:
    session_id: str
    return_uri: str | None


class RpInitiatedLogout:
    def __init__(self, browser: IdpBrowserService) -> None:
        self.browser = browser
        self.security = browser.security

    async def hint_in(self, work: SecurityUnitOfWork, token: str) -> BaseIdTokenClaims:
        try:
            header = login_header(token, max_bytes=self.security.protocol.max_jwt_bytes)
            trust = await work.get(SigningTrustRow, header.kid)
            if trust is None or trust.state == KeyState.REVOKED.value:
                raise ValueError("Unknown or revoked historical signer")

            def verify() -> BaseIdTokenClaims:
                key = RSAKey.import_key(trust.public_key_pem)
                decoded = jwt.decode(token, key, algorithms=[SIGNING_ALGORITHM])
                if JwtHeader.model_validate(decoded.header) != header:
                    raise ValueError("Invalid ID-token purpose")
                claims = BaseIdTokenClaims.model_validate(decoded.claims)
                # Expired hints are permitted only by the historical-context path.
                # All other registered temporal checks remain in effect.
                jwt.JWTClaimsRegistry(
                    now=self.security.clock.now(), leeway=self.security.protocol.clock_skew_seconds
                ).validate({name: value for name, value in decoded.claims.items() if name != "exp"})
                return claims

            claims = await asyncio.to_thread(verify)
            record: AuthenticationEvidenceRow | RefreshIssuanceRow | None = await work.get(
                AuthenticationEvidenceRow, claims.jti
            )
            if record is None:
                record = await work.get(RefreshIssuanceRow, claims.jti)
            lineage = await work.lineage(record.grant_id) if record else None
            if (
                record is None
                or lineage is None
                or record.token_digest != verifier_digest(token)
                or record.signing_key_id != header.kid
                or record.issued_at != claims.iat
                or record.expires_at != claims.exp
                or claims.iss != self.security.issuer
                or claims.aud != lineage.client.client_id
                or claims.sub != lineage.session.subject
                or claims.sid != lineage.session.session_id
                or (claims.azp is not None and claims.azp != claims.aud)
                or not 0 < claims.exp - claims.iat <= self.security.protocol.id_token_ttl_seconds
            ):
                raise ValueError("The hint must identify exact committed ID-token issuance")
            recent_until = max(lineage.session.expires_at, lineage.session.revoked_at or 0)
            if (
                self.security.clock.now()
                >= recent_until + self.browser.settings.browser_action_ttl_seconds
            ):
                raise ValueError("The hinted session is no longer current or recent")
            return claims
        except (JoseError, ValidationError, ValueError, TypeError, InvalidIdToken) as error:
            raise InvalidLogoutRequest("Invalid ID-token logout hint") from error

    async def begin(
        self, cookie: SecretStr | None, parameters: EndSessionParameters
    ) -> LogoutPrompt:
        async with self.security.repository.transaction() as work:
            claims = (
                await self.hint_in(work, parameters.id_token_hint.get_secret_value())
                if parameters.id_token_hint is not None
                else None
            )
            client_id = parameters.client_id or (claims.aud if claims else None)
            if claims is not None and client_id != claims.aud:
                raise InvalidLogoutRequest("The requesting client does not match the hint")
            client = await work.get(ClientRow, client_id) if client_id else None
            if client_id is not None and (client is None or not client.enabled):
                raise InvalidLogoutRequest("The requesting client is not registered and enabled")
            destination = parameters.post_logout_redirect_uri
            if destination is not None and (
                client is None or destination not in client.post_logout_redirect_uris
            ):
                raise InvalidLogoutRequest(
                    "The post-logout redirect must match registered metadata"
                )
            browser = (
                await work.session.get(
                    BrowserSessionRow,
                    verifier_digest(cookie.get_secret_value()),
                    with_for_update=True,
                )
                if cookie is not None
                else None
            )
            identity = (
                await self.browser.repository.identity_in(work.session, browser)
                if browser is not None
                else None
            )
            if (
                claims is not None
                and identity is not None
                and (
                    identity.session.session_id != claims.sid
                    or identity.session.subject.subject != claims.sub
                )
            ):
                raise SecurityDenied(Denial.BINDING)
            context = (
                LogoutReturn(
                    client_id=client.client_id,
                    registration_version=client.registration_version,
                    post_logout_redirect_uri=destination,
                    state=parameters.state,
                )
                if client is not None
                else None
            )
            if identity is None:
                if claims is not None:
                    parent = await work.get(IdpSessionRow, claims.sid)
                    if (
                        parent is not None
                        and parent.revoked_at is None
                        and parent.expires_at > self.security.clock.now()
                    ):
                        # A hint is never a replacement for the OP's browser authentication.
                        raise SecurityDenied(Denial.BINDING)
                    return LogoutPrompt(None, logout_return_uri(context))
                return LogoutPrompt(None)
            if cookie is None or identity.session.subject.issuer != self.security.issuer:
                raise SecurityDenied(Denial.BINDING)
            if (
                claims is None
                and client is not None
                and not any(
                    grant.client_id == client.client_id
                    for grant in await work.grants_for_session(identity.session.session_id)
                )
            ):
                raise InvalidLogoutRequest("The client has no bound logout context in this browser")
            challenge = await self.browser.actions.issue_in(
                work.session,
                cookie,
                BrowserAction(
                    purpose=BrowserActionPurpose.RP_LOGOUT,
                    target=identity.session.session_id,
                    logout_return=context,
                ),
                expires_at=min(
                    identity.session.expires_at,
                    self.security.clock.now() + self.browser.settings.browser_action_ttl_seconds,
                ),
            )
        return LogoutPrompt(challenge)

    async def confirm(self, cookie: SecretStr, challenge: SecretStr) -> CompletedLogout:
        async with self.security.repository.transaction() as work:
            browser = await work.session.get(
                BrowserSessionRow, verifier_digest(cookie.get_secret_value()), with_for_update=True
            )
            identity = (
                await self.browser.repository.identity_in(work.session, browser)
                if browser is not None
                else None
            )
            if identity is None or browser is None:
                raise SecurityDenied(Denial.MISSING)
            action = await self.browser.actions.consume_in(
                work.session, challenge, cookie, BrowserActionPurpose.RP_LOGOUT
            )
            if (
                action.target != identity.session.session_id
                or identity.session.subject.issuer != self.security.issuer
            ):
                raise SecurityDenied(Denial.BINDING)
            context = action.logout_return
            if context is not None:
                client = await work.get(ClientRow, context.client_id)
                if (
                    client is None
                    or not client.enabled
                    or client.registration_version != context.registration_version
                    or (
                        context.post_logout_redirect_uri is not None
                        and context.post_logout_redirect_uri not in client.post_logout_redirect_uris
                    )
                ):
                    raise SecurityDenied(Denial.BINDING)
            await self.security.end_session_in(work, action.target)
            await work.session.delete(browser)
            result = CompletedLogout(action.target, logout_return_uri(context))
        return result
