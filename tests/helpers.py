"""Typed test fixtures; forged artifacts are signed only with vetted JOSE libraries."""

import secrets
import ssl
from dataclasses import dataclass, field
from http import HTTPStatus
from urllib.parse import parse_qs, urlsplit

import httpx2 as httpx
from fastapi import FastAPI
from joserfc import jwt

from federated_identity.common.keys import SigningKey
from federated_identity.common.policy import Clock, IdpSettings
from federated_identity.idp.repositories.database import Database
from federated_identity.idp.repositories.security import SecurityRepository
from federated_identity.idp.schemas.models import AuthenticatedPrincipal
from federated_identity.idp.services.oidc import OidcService
from federated_identity.idp.services.security_model import IdpSecurityModel
from federated_identity.sp.protocol.oidc import AuthorizationTransaction, OidcClient, RpSettings

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


@dataclass
class MutableClock:
    value: int

    def now(self) -> int:
        return self.value


@dataclass(frozen=True)
class KeyFixtures:
    issuer: SigningKey
    client_a: SigningKey
    client_b: SigningKey


@dataclass
class ProtocolLab:
    settings: IdpSettings
    database: Database
    service: OidcService
    security: IdpSecurityModel
    app: FastAPI
    clock: MutableClock
    keys: KeyFixtures
    principal: AuthenticatedPrincipal
    browser: httpx.AsyncClient
    proof_headers: dict[str, str] = field(repr=False)
    tls_context: ssl.SSLContext

    def security_for(self, database: Database, *, issuer: str | None = None) -> IdpSecurityModel:
        return IdpSecurityModel(
            SecurityRepository(database),
            issuer=issuer or self.settings.issuer,
            clock=self.clock,
            lifecycle=self.security.lifecycle,
            protocol=self.settings.policy,
            cipher=self.security.cipher,
        )

    def rp(self, client_id: str = "sp-a") -> OidcClient:
        key = self.keys.client_a if client_id == "sp-a" else self.keys.client_b
        return OidcClient(
            self.rp_settings(client_id),
            key,
            self.clock,
            tls_context=self.tls_context,
            transport=httpx.ASGITransport(app=self.app),
        )

    def rp_settings(self, client_id: str = "sp-a") -> RpSettings:
        return RpSettings(
            issuer=self.settings.issuer,
            client_id=client_id,
            redirect_uri=f"https://{client_id}.localhost/callback",
            policy=self.settings.policy,
        )

    async def authorize(self, transaction: AuthorizationTransaction) -> str:
        response = await self.browser.get(transaction.authorization_url, headers=self.proof_headers)
        assert response.status_code == HTTPStatus.FOUND, response.text
        callback = response.headers["location"]
        assert "code" in parse_qs(urlsplit(callback).query), callback
        return callback

    def assertion(
        self,
        client_id: str = "sp-a",
        *,
        claims_update: dict[str, object] | None = None,
        header_update: dict[str, object] | None = None,
        remove_claim: str | None = None,
        signing_key: SigningKey | None = None,
        endpoint: str | None = None,
    ) -> str:
        key = signing_key or (self.keys.client_a if client_id == "sp-a" else self.keys.client_b)
        now = self.clock.now()
        claims: dict[str, object] = {
            "iss": client_id,
            "sub": client_id,
            "aud": endpoint or self.settings.token_endpoint,
            "iat": now,
            "exp": now + self.settings.policy.assertion_ttl_seconds,
            "jti": secrets.token_urlsafe(24),
        }
        if claims_update:
            claims.update(claims_update)
        if remove_claim:
            del claims[remove_claim]
        header: dict[str, object] = {"alg": "RS256", "typ": "JWT", "kid": key.kid}
        if header_update:
            header.update(header_update)
        return jwt.encode(header, claims, key.key, algorithms=["RS256"])

    def token_parameters(
        self,
        transaction: AuthorizationTransaction,
        callback: str,
        *,
        assertion: str | None = None,
        client_id: str | None = None,
    ) -> dict[str, str]:
        recipient = client_id or transaction.client_id
        return {
            "grant_type": "authorization_code",
            "client_id": recipient,
            "code": callback_code(callback),
            "redirect_uri": transaction.redirect_uri,
            "code_verifier": transaction.verifier,
            "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": assertion or self.assertion(recipient),
        }


def callback_code(callback: str) -> str:
    return parse_qs(urlsplit(callback).query)["code"][0]


def require_code_error(callback: str, expected: str) -> None:
    fields = parse_qs(urlsplit(callback).query)
    assert fields["error"] == [expected]
    assert "code" not in fields


def verify_assertion_claims(assertion: str, key: SigningKey, clock: Clock) -> dict[str, object]:
    # Used to inspect a generated test credential without bypassing its signature.
    decoded = jwt.decode(assertion, key.key, algorithms=["RS256"])
    jwt.JWTClaimsRegistry(now=clock.now()).validate(decoded.claims)
    return dict(decoded.claims)
