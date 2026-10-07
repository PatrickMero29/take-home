"""Model-only trusted test events and library-signed evidence, using real storage."""

import secrets
from collections.abc import Callable
from dataclasses import dataclass

from authlib.oidc.core.grants.util import generate_id_token
from pydantic import SecretStr

from federated_identity.common.persistence.database import AsyncDatabase
from federated_identity.common.security.contracts import GrantStatus, GrantUnavailable
from federated_identity.common.security.keys import SigningKey
from federated_identity.common.security.model import (
    AuthenticationEvent,
    AuthenticationMethod,
    IssuedCredentials,
    LifecyclePolicy,
    LoginEvidence,
    SubjectIdentity,
    TrustedAuthentication,
)
from federated_identity.common.security.secrets import EnvelopeCipher
from federated_identity.common.settings.policy import ProtocolPolicy
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.repositories.database import Database
from federated_identity.idp.repositories.security import SecurityRepository
from federated_identity.idp.schemas.models import TokenResponse
from federated_identity.idp.services.security_model import IdpSecurityModel
from federated_identity.sp.protocol.oidc import RpSettings, verified_login_evidence
from federated_identity.sp.services.security_model import SpSecurityModel
from tests.helpers import KeyFixtures, MutableClock


class AuthoritativeChecker:
    """A dependency boundary double; authorization itself uses the actual IDP database."""

    def __init__(self, model: IdpSecurityModel, client_id: str) -> None:
        self.model = model
        self.client_id = client_id
        self.available = True
        self.calls = 0

    async def check(self, token: SecretStr) -> GrantStatus:
        self.calls += 1
        if not self.available:
            raise GrantUnavailable("Injected dependency outage")
        return await self.model.check_access(token, authenticated_client=self.client_id)


@dataclass(frozen=True)
class ModelProof:
    response: TokenResponse
    evidence: LoginEvidence
    nonce: str


@dataclass(frozen=True)
class ModelGrant:
    proof: ModelProof
    credentials: IssuedCredentials


@dataclass
class SecurityLab:
    databases: dict[ServiceId, AsyncDatabase]
    ciphers: dict[ServiceId, EnvelopeCipher]
    keys: KeyFixtures
    clock: MutableClock
    lifecycle: LifecyclePolicy
    protocol: ProtocolPolicy
    idp: IdpSecurityModel
    sps: dict[str, SpSecurityModel]
    checkers: dict[str, AuthoritativeChecker]
    issuer: str = "https://idp.localhost"

    @property
    def database(self) -> AsyncDatabase:
        return self.databases[ServiceId.IDP]

    def model(self, database: AsyncDatabase) -> IdpSecurityModel:
        return IdpSecurityModel(
            SecurityRepository(database),
            issuer=self.issuer,
            clock=self.clock,
            lifecycle=self.lifecycle,
            protocol=self.protocol,
            cipher=self.ciphers[ServiceId.IDP],
        )

    def authentication(
        self,
        *,
        subject: str = "user:model-fixture",
        methods: tuple[AuthenticationMethod, ...] = (AuthenticationMethod.PASSWORD,),
        authenticated_at: int | None = None,
    ) -> TrustedAuthentication:
        return TrustedAuthentication(
            subject=SubjectIdentity(issuer=self.issuer, subject=subject),
            authenticated_at=self.clock.now() if authenticated_at is None else authenticated_at,
            methods=methods,
        )

    def proof(
        self,
        event: AuthenticationEvent,
        *,
        client_id: str = "sp-a",
        signer: SigningKey | None = None,
    ) -> ModelProof:
        selected = signer or self.keys.issuer
        nonce = secrets.token_urlsafe(32)
        access = secrets.token_urlsafe(32)
        mint: Callable[..., str] = generate_id_token
        # The vetted encoder supports explicit user-info claims. Inject the test
        # clock there instead of changing global wall time or implementing JOSE.
        token = mint(
            token={"access_token": access},
            user_info={
                "sub": event.subject.subject,
                "sid": event.session_id,
                "jti": secrets.token_urlsafe(24),
                "iat": self.clock.now(),
                "exp": self.clock.now() + self.protocol.id_token_ttl_seconds,
            },
            key=selected.key,
            iss=self.issuer,
            aud=client_id,
            alg="RS256",
            nonce=nonce,
            auth_time=event.authenticated_at,
            acr=event.assurance.value,
            amr=[method.value for method in event.methods],
            kid=selected.kid,
        )
        response = TokenResponse(
            token_type="Bearer",
            access_token=access,
            id_token=token,
            expires_in=self.protocol.access_token_ttl_seconds,
            scope="openid",
        )
        evidence = verified_login_evidence(
            response,
            settings=self.rp_settings(client_id),
            nonce=nonce,
            keys=selected.public_jwks(),
            clock=self.clock,
            event_id=event.event_id,
        )
        return ModelProof(response, evidence, nonce)

    def rp_settings(self, client_id: str = "sp-a") -> RpSettings:
        return RpSettings(
            issuer=self.issuer,
            client_id=client_id,
            redirect_uri=f"https://{client_id}.localhost/callback",
            policy=self.protocol,
        )

    async def issue(
        self,
        event: AuthenticationEvent | None = None,
        *,
        client_id: str = "sp-a",
        signer: SigningKey | None = None,
    ) -> ModelGrant:
        if event is None:
            _, event = await self.idp.open_session(self.authentication())
        proof = self.proof(event, client_id=client_id, signer=signer)
        credentials = await self.idp.issue_grant(
            proof.evidence, access_token=SecretStr(proof.response.access_token)
        )
        return ModelGrant(proof, credentials)


async def create_model_databases(
    admin: AsyncDatabase,
    suffix: str,
    *,
    services: tuple[ServiceId, ...] = (ServiceId.IDP, ServiceId.SP_A, ServiceId.SP_B),
) -> dict[ServiceId, AsyncDatabase]:
    """Names are generated by the harness, never supplied by an application caller."""
    databases: dict[ServiceId, AsyncDatabase] = {}
    async with admin.engine.connect() as connection:
        connection = await connection.execution_options(isolation_level="AUTOCOMMIT")
        for service in services:
            name = f"security_{service.value.replace('-', '_')}_{suffix}"
            await connection.exec_driver_sql(f'CREATE DATABASE "{name}"')
            url = SecretStr(
                admin.engine.url.set(database=name).render_as_string(hide_password=False)
            )
            databases[service] = Database(url)
    return databases
