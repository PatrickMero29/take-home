import asyncio
from http import HTTPStatus

import httpx2 as httpx
import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from federated_identity.idp.api.app import create_app
from federated_identity.idp.protocol.authlib_adapter import OpenIdProfile
from federated_identity.idp.repositories.database import Database, ProtocolRepository
from federated_identity.idp.repositories.security_tables import (
    AccessCredentialRow,
    AuthenticationEvidenceRow,
    FederationGrantRow,
    RefreshFamilyRow,
)
from federated_identity.idp.repositories.tables import AuthorizationCodeRow
from federated_identity.idp.schemas.models import ClientRegistration
from federated_identity.idp.services.oidc import OidcService
from tests.helpers import ProtocolLab, callback_code

pytestmark = pytest.mark.integration


async def test_pg_sleep_in_a_sync_shaped_hook_does_not_block_health(
    lab: ProtocolLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    entered = asyncio.Event()
    finished = asyncio.Event()
    original = ProtocolRepository.get_client

    def delayed(self: ProtocolRepository, client_id: str) -> ClientRegistration | None:
        entered.set()
        # An actual PostgreSQL wait, through the exact provider run_sync path.
        self.session.execute(text("SELECT pg_sleep(:delay)"), {"delay": 0.5})
        finished.set()
        return original(self, client_id)

    monkeypatch.setattr(ProtocolRepository, "get_client", delayed)
    exchange = asyncio.create_task(
        lab.browser.post("/token", data=lab.token_parameters(transaction, callback))
    )
    try:
        await asyncio.wait_for(entered.wait(), timeout=2)
        health = await asyncio.wait_for(lab.browser.get("/health"), timeout=0.25)
        assert health.status_code == HTTPStatus.OK
        assert not finished.is_set(), "The event loop waited for the database before serving health"
        assert (await exchange).status_code == HTTPStatus.OK
    finally:
        await exchange


async def test_http_success_waits_for_database_commit(lab: ProtocolLab) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    entered = asyncio.Event()
    release = asyncio.Event()

    class PausedCommitSession(AsyncSession):
        async def commit(self) -> None:
            entered.set()
            await release.wait()
            await super().commit()

    database = Database(lab.settings.database_url, session_class=PausedCommitSession)
    service = OidcService(
        lab.settings, database, lab.keys.issuer, lab.clock, security=lab.security_for(database)
    )
    app = create_app(service)
    try:
        async with httpx.AsyncClient(
            base_url=lab.settings.issuer, transport=httpx.ASGITransport(app=app)
        ) as client:
            exchange = asyncio.create_task(
                client.post("/token", data=lab.token_parameters(transaction, callback))
            )
            try:
                await asyncio.wait_for(entered.wait(), timeout=2)
                assert not exchange.done()
                assert await lab.database.issuance_count(callback_code(callback)) == 0
                async with lab.database.sessions() as session:
                    for model in (
                        FederationGrantRow,
                        AuthenticationEvidenceRow,
                        AccessCredentialRow,
                    ):
                        assert not list(await session.scalars(select(model)))
                release.set()
                response = await asyncio.wait_for(exchange, timeout=2)
            finally:
                release.set()
                await exchange
        assert response.status_code == HTTPStatus.OK
        assert await lab.database.issuance_count(callback_code(callback)) == 1
        async with lab.database.sessions() as session:
            for model in (FederationGrantRow, AuthenticationEvidenceRow, AccessCredentialRow):
                assert len(list(await session.scalars(select(model)))) == 1
    finally:
        await database.dispose()


async def test_commit_failure_cannot_publish_or_consume(lab: ProtocolLab) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    assertion = lab.assertion()

    class FailedCommitSession(AsyncSession):
        async def commit(self) -> None:
            raise RuntimeError("Injected commit failure")

    database = Database(lab.settings.database_url, session_class=FailedCommitSession)
    service = OidcService(
        lab.settings, database, lab.keys.issuer, lab.clock, security=lab.security_for(database)
    )
    app = create_app(service)
    try:
        async with httpx.AsyncClient(
            base_url=lab.settings.issuer, transport=httpx.ASGITransport(app=app)
        ) as client:
            with pytest.raises(RuntimeError, match="Injected commit failure"):
                await client.post(
                    "/token", data=lab.token_parameters(transaction, callback, assertion=assertion)
                )
    finally:
        await database.dispose()
    assert await lab.database.issuance_count(callback_code(callback)) == 0
    async with lab.database.sessions() as session:
        for model in (
            FederationGrantRow,
            AuthenticationEvidenceRow,
            AccessCredentialRow,
            RefreshFamilyRow,
        ):
            assert not list(await session.scalars(select(model)))
    # The same assertion is retryable because the entire transaction rolled back.
    response = await lab.browser.post(
        "/token", data=lab.token_parameters(transaction, callback, assertion=assertion)
    )
    assert response.status_code == HTTPStatus.OK


async def test_signing_failure_rolls_back_issuance_consumption_and_replay(
    lab: ProtocolLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    assertion = lab.assertion()

    def fail_signing(self: OpenIdProfile, client: object) -> None:
        raise RuntimeError("Injected signer failure")

    with monkeypatch.context() as patch:
        patch.setattr(OpenIdProfile, "resolve_client_private_key", fail_signing)
        with pytest.raises(RuntimeError, match="Injected signer failure"):
            await lab.browser.post(
                "/token", data=lab.token_parameters(transaction, callback, assertion=assertion)
            )
    assert await lab.database.issuance_count(callback_code(callback)) == 0
    async with lab.database.sessions() as session:
        statement = select(AuthorizationCodeRow).where(
            AuthorizationCodeRow.client_id == transaction.client_id
        )
        row = (await session.execute(statement)).scalar_one()
        assert row.consumed_at is None
    response = await lab.browser.post(
        "/token", data=lab.token_parameters(transaction, callback, assertion=assertion)
    )
    assert response.status_code == HTTPStatus.OK
