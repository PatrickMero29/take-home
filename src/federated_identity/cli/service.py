"""Independent process entry point, with all file/key work completed before serving requests."""

import asyncio
import logging
import ssl

import httpx2 as httpx
import uvicorn
from fastapi import FastAPI

from federated_identity.common.observability.logging import configure_logging
from federated_identity.common.persistence.database import AsyncDatabase
from federated_identity.common.persistence.foundations import (
    RuntimeFoundationError,
    RuntimeReadiness,
)
from federated_identity.common.persistence.migrations import migration_head
from federated_identity.common.persistence.sessions import PostgresSessionBackend
from federated_identity.common.security.passwords import Argon2Passwords
from federated_identity.common.security.secrets import (
    RuntimeSecrets,
    RuntimeSecretsError,
    load_runtime_secrets,
)
from federated_identity.common.security.totp import TotpEngine
from federated_identity.common.settings.policy import Clock, IdpSettings, SystemClock
from federated_identity.common.settings.runtime import RuntimeSettings, ServiceId
from federated_identity.idp.api.app import PrincipalProvider
from federated_identity.idp.api.runtime import create_idp_application
from federated_identity.idp.repositories.browser import IdpBrowserRepository
from federated_identity.idp.repositories.database import Database
from federated_identity.idp.repositories.mfa import TotpRepository
from federated_identity.idp.repositories.operator import OperatorRepository
from federated_identity.idp.repositories.outbox import PostgresLogoutOutbox
from federated_identity.idp.repositories.security import SecurityRepository
from federated_identity.idp.repositories.users import UserRepository
from federated_identity.idp.schemas.components import IdpComponents
from federated_identity.idp.services.authentication import PasswordAuthenticator
from federated_identity.idp.services.browser import IdpBrowserService
from federated_identity.idp.services.clients import ClientAdministration
from federated_identity.idp.services.end_session import RpInitiatedLogout
from federated_identity.idp.services.logout import HttpsLogoutTransport, LogoutDispatcher
from federated_identity.idp.services.mfa import TotpAuthenticator
from federated_identity.idp.services.oidc import OidcService
from federated_identity.idp.services.operator import OperatorService
from federated_identity.idp.services.security_model import IdpSecurityModel
from federated_identity.idp.services.signing import SigningKeyAdministration, SigningKeyService
from federated_identity.sp.api.app import create_sp_application
from federated_identity.sp.protocol.oidc import OidcClient, RpSettings
from federated_identity.sp.repositories.database import SpDatabase
from federated_identity.sp.repositories.security import SpSecurityRepository
from federated_identity.sp.repositories.transactions import PostgresAuthorizationTransactions
from federated_identity.sp.schemas.components import SpComponents
from federated_identity.sp.services.browser import SpBrowserService
from federated_identity.sp.services.logout import SpLogoutService
from federated_identity.sp.services.renewal import SpRenewalService
from federated_identity.sp.services.revocation import AuthenticatedGrantChecker
from federated_identity.sp.services.security_model import SpSecurityModel
from federated_identity.sp.services.sensitive import SpSensitiveService


async def build_application(
    settings: RuntimeSettings,
    assets: RuntimeSecrets,
    *,
    principal_provider: PrincipalProvider | None = None,
    backchannel_transport: httpx.AsyncBaseTransport | None = None,
    clock: Clock | None = None,
) -> FastAPI:
    clock = clock if clock is not None else SystemClock()
    database_class = Database if settings.service_id == ServiceId.IDP else SpDatabase
    database = await asyncio.to_thread(
        database_class, assets.database_url, ca_file=assets.ca_certificate
    )
    try:
        readiness = RuntimeReadiness(
            database, assets, settings.service_id, await migration_head(settings.service_id)
        )
        await readiness.validate()
        return await compose_application(
            settings,
            assets,
            database,
            readiness,
            clock,
            principal_provider=principal_provider,
            backchannel_transport=backchannel_transport,
        )
    except BaseException:
        await database.dispose()
        raise


async def compose_application(
    settings: RuntimeSettings,
    assets: RuntimeSecrets,
    database: AsyncDatabase,
    readiness: RuntimeReadiness,
    clock: Clock,
    *,
    principal_provider: PrincipalProvider | None = None,
    backchannel_transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    sessions = PostgresSessionBackend(database, assets.envelope, clock)
    tls = await asyncio.to_thread(ssl.create_default_context, cafile=str(assets.ca_certificate))
    if settings.service_id == ServiceId.IDP:
        if not isinstance(database, Database):
            raise RuntimeError("The IDP requires its protocol database adapter")
        security = IdpSecurityModel(
            SecurityRepository(database),
            issuer=settings.issuer,
            clock=clock,
            lifecycle=settings.lifecycle,
            protocol=settings.policy,
            cipher=assets.envelope,
        )
        signing = SigningKeyService(security, assets.signer)
        await signing.initialize()
        users = UserRepository(database, clock)
        authentication = PasswordAuthenticator(
            users, await Argon2Passwords.create(), issuer=settings.issuer, clock=clock
        )
        operators = OperatorService(
            settings,
            OperatorRepository(database, assets.envelope, clock),
            sessions,
            authentication.passwords,
            security,
        )
        service = OidcService(
            IdpSettings(
                issuer=settings.issuer, database_url=assets.database_url, policy=settings.policy
            ),
            database,
            assets.signer,
            clock,
            security=security,
            keys=signing,
        )
        browser = IdpBrowserService(
            settings,
            IdpBrowserRepository(database, assets.envelope, clock),
            sessions,
            security,
            authentication,
            TotpAuthenticator(TotpRepository(database, assets.envelope, clock), TotpEngine()),
        )
        outbox = PostgresLogoutOutbox(database, assets.envelope, clock)
        logout_transport = HttpsLogoutTransport(
            tls, timeout=settings.logout_delivery_timeout_seconds, transport=backchannel_transport
        )
        return create_idp_application(
            IdpComponents(
                settings=settings,
                oidc=service,
                sessions=sessions,
                logout_outbox=outbox,
                logout_transport=logout_transport,
                logout=RpInitiatedLogout(browser),
                logout_dispatcher=LogoutDispatcher(
                    settings, outbox, security, signing, logout_transport
                ),
                step_up=TotpEngine(),
                security=security,
                users=users,
                authentication=authentication,
                browser=browser,
                operators=operators,
                clients=ClientAdministration(operators, assets.signer.public_pem()),
                signing=SigningKeyAdministration(operators, signing),
                readiness=readiness,
            ),
            principal_provider=principal_provider,
        )
    if not isinstance(database, SpDatabase):
        raise RuntimeError("An SP requires its own database adapter")
    grants = AuthenticatedGrantChecker(
        settings, assets.signer, tls, clock, transport=backchannel_transport
    )
    security_sp = SpSecurityModel(
        SpSecurityRepository(database, assets.envelope),
        grants,
        issuer=settings.issuer,
        client_id=settings.service_id.value,
        clock=clock,
        lifecycle=settings.lifecycle,
    )
    oidc = OidcClient(
        RpSettings(
            issuer=settings.issuer,
            client_id=settings.service_id.value,
            redirect_uri=settings.redirect_uri,
            policy=settings.policy,
            request_timeout_seconds=settings.request_timeout_seconds,
            jwks_cache_ttl_seconds=settings.jwks_cache_ttl_seconds,
            jwks_refresh_cooldown_seconds=settings.jwks_refresh_cooldown_seconds,
        ),
        assets.signer,
        clock,
        tls_context=tls,
        grant_checker=grants,
        transport=backchannel_transport,
    )
    transactions = PostgresAuthorizationTransactions(database, assets.envelope, clock)
    security_sp.renewer = SpRenewalService(security_sp.repository, oidc)
    browser_sp = SpBrowserService(settings, sessions, oidc, transactions, security_sp, grants)
    components = SpComponents(
        settings=settings,
        secrets=assets,
        database=database,
        sessions=sessions,
        oidc=oidc,
        grants=grants,
        transactions=transactions,
        step_up=TotpEngine(),
        security=security_sp,
        browser=browser_sp,
        logout=SpLogoutService(oidc, security_sp.repository, grants),
        sensitive=SpSensitiveService(browser_sp),
        readiness=readiness,
    )
    return create_sp_application(components)


async def serve(
    settings: RuntimeSettings,
    *,
    principal_provider: PrincipalProvider | None = None,
    backchannel_transport: httpx.AsyncBaseTransport | None = None,
    clock: Clock | None = None,
) -> None:
    configure_logging()
    try:
        assets = await asyncio.to_thread(load_runtime_secrets, settings)
        app = await build_application(
            settings,
            assets,
            principal_provider=principal_provider,
            backchannel_transport=backchannel_transport,
            clock=clock,
        )
    except (RuntimeSecretsError, RuntimeFoundationError) as error:
        logging.getLogger(__name__).exception(
            "startup_failed", extra={"service": settings.service_id.value}
        )
        raise SystemExit(str(error)) from None
    except Exception:
        logging.getLogger(__name__).exception(
            "startup_failed", extra={"service": settings.service_id.value}
        )
        raise SystemExit(
            "Runtime startup failed; verify persisted secret custody and initialization"
        ) from None
    configuration = uvicorn.Config(
        app,
        host=settings.listen_host,
        port=settings.listen_port,
        ssl_certfile=str(assets.certificate),
        ssl_keyfile=str(assets.private_key),
        ssl_keyfile_password=assets.tls_password.get_secret_value(),
        proxy_headers=False,
        access_log=False,
        ws="none",
        server_header=False,
        timeout_keep_alive=settings.keep_alive_seconds,
        timeout_graceful_shutdown=settings.graceful_shutdown_seconds,
    )
    logging.getLogger(__name__).info(
        "runtime_started", extra={"service": settings.service_id.value}
    )
    await uvicorn.Server(configuration).serve()
