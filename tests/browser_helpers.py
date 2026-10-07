"""Real HTTPS/browser-flow helpers; credentials stay in the isolated owner-side harness."""

import asyncio
from http import HTTPStatus

import httpx2 as httpx
from authlib.oauth2.rfc7523 import private_key_jwt_sign

from federated_identity.cli.architecture_probe import ArchitectureStack, LoopbackTransport
from federated_identity.cli.login_probe import require_status, submit_password
from federated_identity.cli.phase0 import process_settings
from federated_identity.common.persistence.database import AsyncDatabase
from federated_identity.common.security.secrets import RuntimeSecrets, load_runtime_secrets
from federated_identity.common.settings.policy import SystemClock
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.repositories.database import Database
from federated_identity.idp.schemas.users import SeededUser
from federated_identity.sp.protocol.oidc import OidcClient, RpSettings
from federated_identity.sp.repositories.database import SpDatabase


async def runtime_assets(stack: ArchitectureStack, service: ServiceId) -> RuntimeSecrets:
    return await asyncio.to_thread(load_runtime_secrets, process_settings(stack, service))


async def runtime_database(stack: ArchitectureStack, service: ServiceId) -> AsyncDatabase:
    assets = await runtime_assets(stack, service)
    database = Database if service == ServiceId.IDP else SpDatabase
    return await asyncio.to_thread(database, assets.database_url, ca_file=assets.ca_certificate)


async def login_at_idp(
    stack: ArchitectureStack, browser: httpx.AsyncClient, user: SeededUser
) -> None:
    form = await browser.get(f"{stack.issuer}/login")
    require_status(form, HTTPStatus.OK)
    require_status(await submit_password(browser, stack.issuer, form, user), HTTPStatus.SEE_OTHER)


async def start_sp_login(
    stack: ArchitectureStack, browser: httpx.AsyncClient, service: ServiceId = ServiceId.SP_A
) -> str:
    response = await browser.get(f"{stack.origin(service)}/auth/login")
    require_status(response, HTTPStatus.SEE_OTHER)
    return str(response.headers["location"])


async def sso_callback(
    stack: ArchitectureStack, browser: httpx.AsyncClient, service: ServiceId = ServiceId.SP_A
) -> str:
    response = await browser.get(await start_sp_login(stack, browser, service))
    require_status(response, HTTPStatus.FOUND)
    return str(response.headers["location"])


async def complete_sso(
    stack: ArchitectureStack, browser: httpx.AsyncClient, service: ServiceId = ServiceId.SP_A
) -> httpx.Response:
    require_status(
        await browser.get(await sso_callback(stack, browser, service)), HTTPStatus.SEE_OTHER
    )
    account = await browser.get(f"{stack.origin(service)}/account")
    require_status(account, HTTPStatus.OK)
    return account


async def runtime_rp(stack: ArchitectureStack, service: ServiceId = ServiceId.SP_A) -> OidcClient:
    assets = await runtime_assets(stack, service)
    settings = process_settings(stack, service)
    return OidcClient(
        RpSettings(
            issuer=stack.issuer,
            client_id=service.value,
            redirect_uri=settings.redirect_uri,
            policy=settings.policy,
        ),
        assets.signer,
        SystemClock(),
        tls_context=stack.tls,
        transport=LoopbackTransport(stack.tls),
    )


async def assertion(
    stack: ArchitectureStack, service: ServiceId = ServiceId.SP_A, *, endpoint: str = "/token"
) -> str:
    assets = await runtime_assets(stack, service)
    now = SystemClock().now()
    result: str = private_key_jwt_sign(
        assets.signer.key,
        client_id=service.value,
        token_endpoint=f"{stack.issuer}{endpoint}",
        claims={"iat": now, "exp": now + 60},
        header={"kid": assets.signer.kid},
        alg="RS256",
    )
    return result
