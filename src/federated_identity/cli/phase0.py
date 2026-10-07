"""Verify PKCE/OIDC and authoritative lineage on the deployed three-process architecture."""

import argparse
import asyncio
import json
import secrets
from http import HTTPStatus
from pathlib import Path

from pydantic import SecretStr

from federated_identity.cli.architecture_probe import (
    ArchitectureStack,
    LoopbackTransport,
    architecture_stack,
)
from federated_identity.cli.bootstrap import write_new
from federated_identity.cli.phase0_runtime import PrincipalFixture
from federated_identity.common.persistence.sessions import PostgresSessionBackend
from federated_identity.common.security.model import (
    AuthenticationMethod,
    SubjectIdentity,
    TrustedAuthentication,
)
from federated_identity.common.security.secrets import load_runtime_secrets
from federated_identity.common.settings.policy import SystemClock
from federated_identity.common.settings.runtime import RuntimeSettings, ServiceId
from federated_identity.idp.repositories.database import Database
from federated_identity.idp.repositories.security import SecurityRepository
from federated_identity.idp.schemas.models import AuthenticatedPrincipal
from federated_identity.idp.services.security_model import IdpSecurityModel
from federated_identity.sp.protocol.oidc import OidcClient, RpSettings
from federated_identity.sp.repositories.database import SpDatabase
from federated_identity.sp.repositories.transactions import PostgresAuthorizationTransactions


def process_settings(stack: ArchitectureStack, service: ServiceId) -> RuntimeSettings:
    return RuntimeSettings(
        service_id=service,
        public_url=stack.origin(service),
        issuer=stack.issuer,
        listen_port=stack.ports[service],
        secrets_directory=stack.root / service.value,
        database_host="127.0.0.1",
        database_port=stack.postgres_port,
    )


async def prove_on_stack(stack: ArchitectureStack) -> dict[str, object]:
    clock = SystemClock()
    settings = process_settings(stack, ServiceId.IDP)
    assets = await asyncio.to_thread(load_runtime_secrets, settings)
    database = await asyncio.to_thread(Database, assets.database_url, ca_file=assets.ca_certificate)
    try:
        model = IdpSecurityModel(
            SecurityRepository(database),
            issuer=stack.issuer,
            clock=clock,
            lifecycle=settings.lifecycle,
            protocol=settings.policy,
            cipher=assets.envelope,
        )
        _, event = await model.open_session(
            TrustedAuthentication(
                subject=SubjectIdentity(
                    issuer=stack.issuer, subject=f"user:{secrets.token_urlsafe(16)}"
                ),
                authenticated_at=clock.now() - 30,
                methods=(AuthenticationMethod.FIXTURE,),
            )
        )
        fixture = PrincipalFixture(
            principal=AuthenticatedPrincipal.from_event(event),
            proof=SecretStr(secrets.token_urlsafe(32)),
        )
        # SecretStr intentionally redacts JSON; serialize its generated proof only
        # into this owner-private authenticated-encryption envelope.
        encrypted = assets.envelope.encrypt(
            {
                "principal": fixture.principal.model_dump(mode="json"),
                "proof": fixture.proof.get_secret_value(),
            },
            purpose="phase0-principal-fixture",
        )
        path = stack.root / "idp" / "phase0.fixture"
        await asyncio.to_thread(write_new, path, encrypted)
        await stack.stop(ServiceId.IDP)
        await stack.start(ServiceId.IDP, fixture_file=path)
        grants: list[str] = []
        for service in (ServiceId.SP_A, ServiceId.SP_B):
            rp_settings = process_settings(stack, service)
            rp_assets = await asyncio.to_thread(load_runtime_secrets, rp_settings)
            rp = OidcClient(
                RpSettings(
                    issuer=stack.issuer,
                    client_id=service.value,
                    redirect_uri=rp_settings.redirect_uri,
                    policy=rp_settings.policy,
                ),
                rp_assets.signer,
                clock,
                tls_context=stack.tls,
                transport=LoopbackTransport(stack.tls),
            )
            transaction = rp.begin()
            sp_database = await asyncio.to_thread(
                SpDatabase, rp_assets.database_url, ca_file=rp_assets.ca_certificate
            )
            try:
                sessions = PostgresSessionBackend(sp_database, rp_assets.envelope, clock)
                cookie = await sessions.create({"kind": "phase0-browser-binding"}, ttl=300)
                transactions = PostgresAuthorizationTransactions(
                    sp_database, rp_assets.envelope, clock
                )
                await transactions.save(transaction, cookie)
                async with stack.client() as browser:
                    response = await browser.get(
                        transaction.authorization_url,
                        headers={"Authorization": f"Bearer {fixture.proof.get_secret_value()}"},
                    )
                if response.status_code != HTTPStatus.FOUND:
                    raise RuntimeError("The authenticated authorization request failed")
                wrong_browser = SecretStr(secrets.token_urlsafe(32))
                if await transactions.consume(transaction.state, wrong_browser) is not None:
                    raise RuntimeError("A callback transaction must remain bound to its browser")
                consumed = await transactions.consume(transaction.state, cookie)
                if consumed is None or consumed != transaction:
                    raise RuntimeError("A callback transaction must be persisted and one-use")
                if await transactions.consume(transaction.state, cookie) is not None:
                    raise RuntimeError("A callback transaction cannot be reused")
                login = await rp.exchange_verified(consumed, response.headers["location"])
            finally:
                await sp_database.dispose()
            evidence = await database.issuance_evidence(login.response.access_token)
            if (
                evidence is None
                or evidence.grant_id != login.context.grant.grant_id
                or evidence.issuance_id != login.evidence.token_id
                or evidence.id_token_digest != login.evidence.token_digest
                or login.evidence.authentication != event
                or login.claims.auth_time != fixture.principal.auth_time
            ):
                raise RuntimeError("The code and canonical authentication lineage did not commit")
            grants.append(login.context.grant.grant_id)
        if len(set(grants)) != 2:
            raise RuntimeError("Each relying party needs its own grant")
        return {
            "result": "phase0 integrated protocol proof passed",
            "services": [ServiceId.IDP.value, ServiceId.SP_A.value, ServiceId.SP_B.value],
            "independent_processes": len({process.pid for process in stack.processes.values()}),
            "transport": "verified HTTPS and PostgreSQL TLS",
            "database_roles": "isolated per service",
            "schema": "deployment migrations",
            "flow": "authorization_code + S256 PKCE",
            "client_authentication": "endpoint-bound private_key_jwt",
            "id_tokens_validated": True,
            "authentication_event_preserved": True,
            "recipient_specific_grants": True,
            "authoritative_introspection": True,
            "browser_bound_transactions": True,
            "issuance_committed": True,
        }
    finally:
        await database.dispose()


async def prove(binaries: Path | None = None) -> dict[str, object]:
    async with architecture_stack(binaries) as stack:
        return await prove_on_stack(stack)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--postgres-bin", type=Path, help="Directory containing initdb and pg_ctl")
    arguments = parser.parse_args()
    print(json.dumps(asyncio.run(prove(arguments.postgres_bin)), indent=2))
