"""Verified issuer notification to durable, session-specific local termination."""

from pydantic import SecretStr

from federated_identity.common.security.contracts import LogoutTokenChecker
from federated_identity.common.security.logout import (
    InvalidLogoutToken,
    logout_header,
    validate_logout_token,
)
from federated_identity.sp.protocol.oidc import OidcClient
from federated_identity.sp.repositories.security import SpSecurityRepository


class SpLogoutService:
    def __init__(
        self, oidc: OidcClient, repository: SpSecurityRepository, checker: LogoutTokenChecker
    ) -> None:
        self.oidc = oidc
        self.repository = repository
        self.checker = checker

    async def receive(self, token: str) -> None:
        header = logout_header(token, max_bytes=self.oidc.settings.policy.max_jwt_bytes)
        keys = await self.oidc.jwks.for_key(header.kid)
        verified = validate_logout_token(
            token, settings=self.oidc.settings, keys=keys, clock=self.oidc.clock
        )
        if not await self.checker.check_logout(SecretStr(token)):
            raise InvalidLogoutToken("Logout evidence is unissued or no longer trusted")
        await self.repository.accept_logout(
            verified,
            client_id=self.oidc.settings.client_id,
            clock=self.oidc.clock,
            skew=self.oidc.settings.policy.clock_skew_seconds,
        )
