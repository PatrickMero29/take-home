import asyncio
import secrets
from collections.abc import Callable

import asyncpg
import pytest
from authlib.oauth2.rfc7523 import private_key_jwt_sign
from cryptography.fernet import InvalidToken
from pydantic import SecretStr

from federated_identity.cli.architecture_probe import ArchitectureStack, LoopbackTransport
from federated_identity.cli.bootstrap import bootstrap_assets
from federated_identity.cli.databases import initialize_databases
from federated_identity.cli.phase0 import prove_on_stack
from federated_identity.common.persistence.sessions import BrowserSessionRow
from federated_identity.common.security.secrets import RuntimeSecrets, load_runtime_secrets
from federated_identity.common.settings.policy import SystemClock, verifier_digest
from federated_identity.common.settings.runtime import RuntimeSettings, ServiceId
from federated_identity.idp.repositories.outbox import LogoutOutboxRow, PostgresLogoutOutbox
from federated_identity.sp.protocol.oidc import OidcClient, RpSettings
from federated_identity.sp.repositories.database import SpDatabase
from federated_identity.sp.repositories.transactions import PostgresAuthorizationTransactions
from federated_identity.sp.services.revocation import AuthenticatedGrantChecker

pytestmark = pytest.mark.integration


def service_settings(stack: ArchitectureStack, service: ServiceId) -> RuntimeSettings:
    return RuntimeSettings(
        service_id=service,
        public_url=stack.origin(service),
        issuer=stack.issuer,
        listen_port=stack.ports[service],
        secrets_directory=stack.root / service.value,
        database_host="127.0.0.1",
        database_port=stack.postgres_port,
    )


async def assets_for(stack: ArchitectureStack, service: ServiceId) -> RuntimeSecrets:
    return await asyncio.to_thread(load_runtime_secrets, service_settings(stack, service))


async def test_independent_processes_tls_and_database_access_boundaries(
    deployed_stack: ArchitectureStack,
) -> None:
    stack = deployed_stack
    assert len({process.pid for process in stack.processes.values()}) == 3
    async with stack.client() as client:
        for service in (ServiceId.IDP, ServiceId.SP_A, ServiceId.SP_B):
            response = await client.get(f"{stack.origin(service)}/health/ready")
            assert response.json()["service"] == service.value
            assert response.is_success
            configuration = (await client.get(f"{stack.origin(service)}/architecture")).json()
            assert configuration["issuer"] == stack.issuer

    assets = await assets_for(stack, ServiceId.SP_A)
    password = await asyncio.to_thread(
        (stack.root / "sp-a" / "database.password").read_text, encoding="ascii"
    )
    connection = await asyncpg.connect(
        host="127.0.0.1",
        port=stack.postgres_port,
        user=ServiceId.SP_A.role,
        database=ServiceId.SP_A.database,
        password=password,
        ssl=stack.tls,
    )
    try:
        privileged = await connection.fetchrow(
            "SELECT rolsuper, rolcreatedb, rolcreaterole FROM pg_roles WHERE rolname=current_user"
        )
        assert privileged is not None and not any(privileged)
        with pytest.raises(asyncpg.UndefinedTableError):
            await connection.execute("SELECT * FROM clients")
    finally:
        await connection.close()
    with pytest.raises(asyncpg.InsufficientPrivilegeError):
        await asyncpg.connect(
            host="127.0.0.1",
            port=stack.postgres_port,
            user=ServiceId.SP_A.role,
            database=ServiceId.IDP.database,
            password=password,
            ssl=stack.tls,
        )
    database = await asyncio.to_thread(
        SpDatabase, assets.database_url, ca_file=assets.ca_certificate
    )
    try:
        assert await database.ready()
    finally:
        await database.dispose()


async def test_opaque_cookies_storage_encryption_and_restart(
    deployed_stack: ArchitectureStack,
) -> None:
    stack = deployed_stack
    async with stack.client() as client:
        response = await client.get(f"{stack.origin(ServiceId.SP_A)}/")
        cookie_name = service_settings(stack, ServiceId.SP_A).cookie_name
        token = client.cookies.get(cookie_name)
        assert token is not None and len(token) >= 32
        header = response.headers["set-cookie"].lower()
        assert "secure" in header and "httponly" in header and "samesite=lax" in header
        assert "domain=" not in header
        assets = await assets_for(stack, ServiceId.SP_A)
        database = await asyncio.to_thread(
            SpDatabase, assets.database_url, ca_file=assets.ca_certificate
        )
        try:
            async with database.sessions() as session:
                row = await session.get(BrowserSessionRow, verifier_digest(token))
                assert row is not None
                assert b"anonymous" not in row.encrypted_payload
                original_created_at = row.created_at
            await stack.stop(ServiceId.SP_A)
            await stack.start(ServiceId.SP_A)
            restarted = await client.get(f"{stack.origin(ServiceId.SP_A)}/")
            assert "set-cookie" not in restarted.headers
            assert client.cookies.get(cookie_name) == token
            async with database.sessions() as session:
                row = await session.get(BrowserSessionRow, verifier_digest(token))
                assert row is not None and row.created_at == original_created_at
        finally:
            await database.dispose()


async def test_bootstrap_and_migrations_preserve_existing_keys_and_passwords(
    deployed_stack: ArchitectureStack,
) -> None:
    stack = deployed_stack
    before = {
        str(path.relative_to(stack.root)): await asyncio.to_thread(path.read_bytes)
        for service in ("authority", "postgres", *ServiceId)
        for path in (stack.root / service).iterdir()
        if path.is_file() and path.name != "bootstrap.lock"
    }
    await asyncio.to_thread(bootstrap_assets, stack.root)
    await initialize_databases(stack.root, host="127.0.0.1", port=stack.postgres_port)
    for name, expected in before.items():
        assert await asyncio.to_thread((stack.root / name).read_bytes) == expected
    async with stack.client() as client:
        before_jwks = (await client.get(f"{stack.issuer}/jwks.json")).json()
        await stack.stop(ServiceId.IDP)
        await stack.start(ServiceId.IDP)
        assert (await client.get(f"{stack.issuer}/jwks.json")).json() == before_jwks


async def test_one_use_browser_bound_transaction_and_client_key_isolation(
    deployed_stack: ArchitectureStack,
) -> None:
    stack = deployed_stack
    settings = service_settings(stack, ServiceId.SP_A)
    assets = await assets_for(stack, ServiceId.SP_A)
    other = await assets_for(stack, ServiceId.SP_B)
    database = await asyncio.to_thread(
        SpDatabase, assets.database_url, ca_file=assets.ca_certificate
    )
    clock = SystemClock()
    transaction = OidcClient(
        RpSettings(
            issuer=stack.issuer,
            client_id="sp-a",
            redirect_uri=settings.redirect_uri,
            policy=settings.policy,
        ),
        assets.signer,
        clock,
        tls_context=stack.tls,
    ).begin()
    browser = SecretStr(secrets.token_urlsafe(32))
    store = PostgresAuthorizationTransactions(database, assets.envelope, clock)
    try:
        await store.save(transaction, browser)
        assert await store.consume(transaction.state, SecretStr(secrets.token_urlsafe(32))) is None
        consumed = await store.consume(transaction.state, browser)
        assert consumed == transaction
        assert await store.consume(transaction.state, browser) is None
        ciphertext = assets.envelope.encrypt({"kind": "anonymous"}, purpose="browser-session")
        with pytest.raises(InvalidToken):
            other.envelope.decrypt(ciphertext, purpose="browser-session")
    finally:
        await database.dispose()


async def test_durable_outbox_rejects_unbound_legacy_payloads_after_restart(
    deployed_stack: ArchitectureStack,
) -> None:
    stack = deployed_stack
    assets = await assets_for(stack, ServiceId.IDP)
    database = await asyncio.to_thread(
        SpDatabase, assets.database_url, ca_file=assets.ca_certificate
    )
    try:
        outbox = PostgresLogoutOutbox(database, assets.envelope, SystemClock())
        delivery_id = await outbox.enqueue(
            f"{stack.origin(ServiceId.SP_A)}/backchannel-logout",
            {"stage": "architecture-contract", "payload": "future signed notification"},
        )
        async with database.sessions() as session:
            row = await session.get(LogoutOutboxRow, delivery_id)
            assert row is not None and b"future signed notification" not in row.encrypted_payload
            assert (
                assets.envelope.decrypt(row.encrypted_payload, purpose="logout-delivery")["stage"]
                == "architecture-contract"
            )
        await stack.stop(ServiceId.IDP)
        await stack.start(ServiceId.IDP)
        async with asyncio.timeout(5):
            while True:
                async with database.sessions() as session:
                    row = await session.get(LogoutOutboxRow, delivery_id)
                    assert row is not None
                    if row.status == "failed":
                        assert row.last_error == "unbound_intent"
                        break
                await asyncio.sleep(0.05)
        assert await outbox.pending_count() == 0
    finally:
        await database.dispose()


async def test_persisted_private_key_jwt_registration_authenticates_over_tls(
    deployed_stack: ArchitectureStack,
) -> None:
    stack = deployed_stack
    settings = service_settings(stack, ServiceId.SP_A)
    assets = await assets_for(stack, ServiceId.SP_A)
    now = SystemClock().now()
    sign: Callable[..., str] = private_key_jwt_sign
    assertion = sign(
        assets.signer.key,
        client_id="sp-a",
        token_endpoint=f"{stack.issuer}/token",
        claims={"iat": now, "exp": now + settings.policy.assertion_ttl_seconds},
        header={"kid": assets.signer.kid},
        alg="RS256",
    )
    async with stack.client() as client:
        response = await client.post(
            f"{stack.issuer}/token",
            data={
                "grant_type": "authorization_code",
                "code": secrets.token_urlsafe(32),
                "redirect_uri": f"{stack.origin(ServiceId.SP_A)}/auth/callback",
                "code_verifier": secrets.token_urlsafe(48),
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": assertion,
            },
        )
    # Reaching invalid_grant proves the assertion was accepted; no authenticated
    # user event or grant is fabricated to exercise the architecture boundary.
    assert response.json()["error"] == "invalid_grant"


async def test_authenticated_authorization_service_returns_inactive_for_unknown_tokens(
    deployed_stack: ArchitectureStack,
) -> None:
    stack = deployed_stack
    settings = service_settings(stack, ServiceId.SP_A)
    assets = await assets_for(stack, ServiceId.SP_A)
    checker = AuthenticatedGrantChecker(
        settings,
        assets.signer,
        stack.tls,
        SystemClock(),
        transport=LoopbackTransport(stack.tls),
    )
    status = await checker.check(SecretStr(secrets.token_urlsafe(32)))
    assert not status.active and status.context is None


async def test_phase0_protocol_on_deployed_processes_and_service_roles(
    deployed_stack: ArchitectureStack,
) -> None:
    report = await prove_on_stack(deployed_stack)
    assert report["independent_processes"] == 3
    assert report["recipient_specific_grants"]
    assert report["authoritative_introspection"]
    assert report["browser_bound_transactions"]
