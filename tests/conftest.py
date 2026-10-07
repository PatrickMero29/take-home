"""All integration checks use an actual disposable PostgreSQL process."""

import asyncio
import secrets
import ssl
import time
from collections.abc import AsyncIterator

import httpx2 as httpx
import pytest
import pytest_asyncio
from cryptography.fernet import Fernet
from pydantic import SecretBytes, SecretStr

from federated_identity.cli.architecture_probe import ArchitectureStack, architecture_stack
from federated_identity.cli.probe_runtime import FixturePrincipalProvider, temporary_postgres
from federated_identity.common.keys import SigningKey
from federated_identity.common.persistence.database import AsyncDatabase
from federated_identity.common.persistence.migrations import migrate
from federated_identity.common.policy import IdpSettings
from federated_identity.common.security.model import (
    AuthenticationMethod,
    LifecyclePolicy,
    SubjectIdentity,
    TrustedAuthentication,
)
from federated_identity.common.security.secrets import EnvelopeCipher
from federated_identity.common.settings.policy import ProtocolPolicy
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.api.app import create_app
from federated_identity.idp.repositories.database import Database
from federated_identity.idp.repositories.security import SecurityRepository
from federated_identity.idp.schemas.models import AuthenticatedPrincipal, ClientRegistration
from federated_identity.idp.services.oidc import OidcService
from federated_identity.idp.services.security_model import IdpSecurityModel
from federated_identity.sp.repositories.security import SpSecurityRepository
from federated_identity.sp.services.security_model import SpSecurityModel
from tests.helpers import KeyFixtures, MutableClock, ProtocolLab
from tests.security_helpers import AuthoritativeChecker, SecurityLab, create_model_databases


@pytest.fixture(scope="session")
def key_fixtures() -> KeyFixtures:
    return KeyFixtures(SigningKey.generate(), SigningKey.generate(), SigningKey.generate())


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def postgres_url() -> AsyncIterator[SecretStr]:
    async with temporary_postgres() as url:
        yield url


@pytest_asyncio.fixture
async def deployed_stack() -> AsyncIterator[ArchitectureStack]:
    async with architecture_stack() as stack:
        yield stack


@pytest_asyncio.fixture
async def lab(postgres_url: SecretStr, key_fixtures: KeyFixtures) -> AsyncIterator[ProtocolLab]:
    admin = AsyncDatabase(postgres_url)
    databases = await create_model_databases(admin, secrets.token_hex(8), services=(ServiceId.IDP,))
    database = databases[ServiceId.IDP]
    assert isinstance(database, Database)
    url = SecretStr(database.engine.url.render_as_string(hide_password=False))
    try:
        await database.initialize(
            [
                ClientRegistration(
                    client_id="sp-a",
                    redirect_uris=(
                        "https://sp-a.localhost/callback",
                        "https://sp-a.localhost/alternate",
                    ),
                    public_key_pem=key_fixtures.client_a.public_pem(),
                    key_id=key_fixtures.client_a.kid,
                ),
                ClientRegistration(
                    client_id="sp-b",
                    redirect_uris=("https://sp-b.localhost/callback",),
                    public_key_pem=key_fixtures.client_b.public_pem(),
                    key_id=key_fixtures.client_b.kid,
                ),
            ]
        )
        settings = IdpSettings(issuer="https://idp.localhost", database_url=url)
        clock = MutableClock(int(time.time()))
        security = IdpSecurityModel(
            SecurityRepository(database),
            issuer=settings.issuer,
            clock=clock,
            lifecycle=LifecyclePolicy(),
            protocol=settings.policy,
            cipher=EnvelopeCipher.from_key(SecretBytes(Fernet.generate_key())),
        )
        await security.register_runtime_signer(key_fixtures.issuer)
        _, event = await security.open_session(
            TrustedAuthentication(
                subject=SubjectIdentity(
                    issuer=settings.issuer, subject=f"user:{secrets.token_urlsafe(16)}"
                ),
                # Code expiry depends on issuance, independently of this older event.
                authenticated_at=clock.now() - 1800,
                methods=(AuthenticationMethod.FIXTURE,),
            )
        )
        principal = AuthenticatedPrincipal.from_event(event)
        proof = SecretStr(secrets.token_urlsafe(32))
        service = OidcService(settings, database, key_fixtures.issuer, clock, security=security)
        app = create_app(service, principal_provider=FixturePrincipalProvider(proof, principal))
        tls_context = await asyncio.to_thread(ssl.create_default_context)
        async with httpx.AsyncClient(
            base_url=settings.issuer,
            transport=httpx.ASGITransport(app=app),
            follow_redirects=False,
            trust_env=False,
            timeout=5,
        ) as browser:
            yield ProtocolLab(
                settings=settings,
                database=database,
                service=service,
                security=security,
                app=app,
                clock=clock,
                keys=key_fixtures,
                principal=principal,
                browser=browser,
                proof_headers={"Authorization": f"Bearer {proof.get_secret_value()}"},
                tls_context=tls_context,
            )
    finally:
        await database.dispose()
        try:
            async with admin.engine.connect() as connection:
                connection = await connection.execution_options(isolation_level="AUTOCOMMIT")
                await connection.exec_driver_sql(f'DROP DATABASE "{database.engine.url.database}"')
        finally:
            await admin.dispose()


@pytest_asyncio.fixture
async def security_lab(
    postgres_url: SecretStr, key_fixtures: KeyFixtures
) -> AsyncIterator[SecurityLab]:
    admin = AsyncDatabase(postgres_url)
    databases = await create_model_databases(admin, secrets.token_hex(8))
    try:
        for service, database in databases.items():
            await migrate(database, service)
        idp_database = databases[ServiceId.IDP]
        assert isinstance(idp_database, Database)
        await idp_database.seed_clients(
            [
                ClientRegistration(
                    client_id="sp-a",
                    redirect_uris=("https://sp-a.localhost/callback",),
                    public_key_pem=key_fixtures.client_a.public_pem(),
                    key_id=key_fixtures.client_a.kid,
                    backchannel_logout_uri="https://sp-a.localhost/backchannel-logout",
                ),
                ClientRegistration(
                    client_id="sp-b",
                    redirect_uris=("https://sp-b.localhost/callback",),
                    public_key_pem=key_fixtures.client_b.public_pem(),
                    key_id=key_fixtures.client_b.kid,
                ),
            ]
        )
        ciphers = {
            service: EnvelopeCipher.from_key(SecretBytes(Fernet.generate_key()))
            for service in databases
        }
        clock = MutableClock(int(time.time()))
        lifecycle = LifecyclePolicy()
        protocol = ProtocolPolicy()
        model = IdpSecurityModel(
            SecurityRepository(idp_database),
            issuer="https://idp.localhost",
            clock=clock,
            lifecycle=lifecycle,
            protocol=protocol,
            cipher=ciphers[ServiceId.IDP],
        )
        await model.register_runtime_signer(key_fixtures.issuer)
        checkers = {
            service.value: AuthoritativeChecker(model, service.value)
            for service in (ServiceId.SP_A, ServiceId.SP_B)
        }
        sps = {
            service.value: SpSecurityModel(
                SpSecurityRepository(databases[service], ciphers[service]),
                checkers[service.value],
                issuer="https://idp.localhost",
                client_id=service.value,
                clock=clock,
                lifecycle=lifecycle,
            )
            for service in (ServiceId.SP_A, ServiceId.SP_B)
        }
        yield SecurityLab(
            databases, ciphers, key_fixtures, clock, lifecycle, protocol, model, sps, checkers
        )
    finally:
        for database in databases.values():
            await database.dispose()
        try:
            async with admin.engine.connect() as connection:
                connection = await connection.execution_options(isolation_level="AUTOCOMMIT")
                for database in databases.values():
                    await connection.exec_driver_sql(
                        f'DROP DATABASE "{database.engine.url.database}"'
                    )
        finally:
            await admin.dispose()
