"""One real HTTPS/Chromium deployment exercises local/global logout and durable recovery."""

import asyncio
import json
from collections.abc import AsyncIterator
from http import HTTPStatus
from pathlib import Path

import pytest
import pytest_asyncio
from playwright.async_api import BrowserContext, Page, expect
from sqlalchemy import select

from federated_identity.cli.architecture_probe import ArchitectureStack, architecture_stack
from federated_identity.cli.bootstrap import write_new
from federated_identity.cli.login_probe import seeded_user
from federated_identity.common.persistence.database import AsyncDatabase
from federated_identity.common.security.secrets import RuntimeSecrets
from federated_identity.common.settings.policy import SystemClock
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.repositories.outbox import LogoutOutboxRow
from federated_identity.sp.repositories.logout import LogoutSessionRow
from tests.browser_helpers import runtime_assets, runtime_database
from tests.e2e.test_refresh import advance_clock

pytestmark = pytest.mark.integration


@pytest_asyncio.fixture
async def deployed_stack(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> AsyncIterator[ArchitectureStack]:
    clock = tmp_path / "process-clock"
    await asyncio.to_thread(write_new, clock, str(SystemClock().now()).encode("ascii"))
    monkeypatch.setenv("FID_VERIFICATION_CLOCK", str(clock))
    async with architecture_stack() as stack:
        yield stack


async def row_for(database: AsyncDatabase, sid: str, client: str) -> LogoutOutboxRow:
    async with database.sessions() as session:
        return (
            await session.scalars(
                select(LogoutOutboxRow).where(
                    LogoutOutboxRow.session_id == sid, LogoutOutboxRow.client_id == client
                )
            )
        ).one()


async def wait_delivery(
    database: AsyncDatabase, sid: str, client: str, status: str
) -> LogoutOutboxRow:
    async with asyncio.timeout(10):
        while True:
            row = await row_for(database, sid, client)
            if row.status == status and row.lease_id is None:
                return row
            await asyncio.sleep(0.05)


async def account(page: Page, origin: str) -> dict[str, object]:
    response = await page.goto(f"{origin}/account")
    assert response is not None and response.status == HTTPStatus.OK
    result: dict[str, object] = json.loads(await page.locator("body").inner_text())
    return result


def delivery_token(assets: RuntimeSecrets, row: LogoutOutboxRow) -> str:
    value = assets.envelope.decrypt(row.encrypted_payload, purpose="logout-delivery")["token"]
    assert isinstance(value, str)
    return value


async def test_real_local_global_logout_sp_outage_expired_retry_and_dispatcher_restart(
    deployed_stack: ArchitectureStack,
    trusted_browser_context: BrowserContext,
) -> None:
    stack, context = deployed_stack, trusted_browser_context
    alice = await seeded_user(stack)
    a, b = await context.new_page(), await context.new_page()
    idp_db = await runtime_database(stack, ServiceId.IDP)
    assets = await runtime_assets(stack, ServiceId.IDP)
    try:
        for page, service in ((a, ServiceId.SP_A), (b, ServiceId.SP_B)):
            await page.goto(stack.origin(service))
            await page.get_by_role("link", name="Sign in", exact=True).click()
            if service == ServiceId.SP_A:
                await page.get_by_label("Username", exact=True).fill(alice.username)
                await page.get_by_label("Password", exact=True).fill(
                    alice.password.get_secret_value()
                )
                await page.get_by_role("button", name="Sign in", exact=True).click()
            await page.wait_for_url(f"{stack.origin(service)}/")
            await expect(page.get_by_test_id("subject")).to_have_text(alice.subject)
        sid = str((await account(a, stack.origin(ServiceId.SP_A)))["sid"])
        await a.goto(stack.origin(ServiceId.SP_A))
        await a.get_by_role("link", name="Sign out locally", exact=True).click()
        await a.get_by_role("button", name="Sign out locally", exact=True).click()
        await a.wait_for_url(f"{stack.origin(ServiceId.SP_A)}/")
        assert (await account(b, stack.origin(ServiceId.SP_B)))["sid"] == sid
        await a.get_by_role("link", name="Sign in", exact=True).click()
        await a.wait_for_url(f"{stack.origin(ServiceId.SP_A)}/")
        await expect(a.get_by_test_id("subject")).to_have_text(alice.subject)
        captured = {entry["name"]: entry["value"] for entry in await context.cookies()}
        await stack.stop(ServiceId.SP_B)
        await a.get_by_role("link", name="Sign out everywhere", exact=True).click()
        await a.get_by_role("button", name="Continue to global sign out", exact=True).click()
        await expect(
            a.get_by_role("button", name="Sign out everywhere", exact=True)
        ).to_be_visible()
        async with stack.client() as client:
            active = await client.get(
                f"{stack.issuer}/account",
                headers={"Cookie": f"__Host-fid-idp={captured['__Host-fid-idp']}"},
            )
            assert active.status_code == HTTPStatus.OK
        await a.get_by_role("button", name="Sign out everywhere", exact=True).click()
        await a.wait_for_url(f"{stack.origin(ServiceId.SP_A)}/")
        await expect(a.get_by_role("link", name="Sign in", exact=True)).to_be_visible()
        await wait_delivery(idp_db, sid, "sp-a", "delivered")
        offline = await wait_delivery(idp_db, sid, "sp-b", "pending")
        old_jti = offline.token_id
        assert old_jti is not None and offline.attempts == 1
        assert not any(entry["name"] == "__Host-fid-idp" for entry in await context.cookies())
        # Establish a distinct session while the old B notification is pending.
        await a.get_by_role("link", name="Sign in", exact=True).click()
        await expect(a.get_by_label("Password", exact=True)).to_be_visible()
        await a.get_by_label("Username", exact=True).fill(alice.username)
        await a.get_by_label("Password", exact=True).fill(alice.password.get_secret_value())
        await a.get_by_role("button", name="Sign in", exact=True).click()
        await a.wait_for_url(f"{stack.origin(ServiceId.SP_A)}/")
        fresh_sid = str((await account(a, stack.origin(ServiceId.SP_A)))["sid"])
        assert fresh_sid != sid
        await stack.stop(ServiceId.IDP)
        await stack.start(ServiceId.SP_B)
        async with stack.client() as client:
            unavailable = await client.get(
                f"{stack.origin(ServiceId.SP_B)}/account",
                headers={"Cookie": f"__Host-fid-sp-b={captured['__Host-fid-sp-b']}"},
            )
            assert unavailable.status_code == HTTPStatus.SERVICE_UNAVAILABLE
        await stack.start(ServiceId.IDP)
        async with stack.client() as client:
            rejected = await client.get(
                f"{stack.origin(ServiceId.SP_B)}/account",
                headers={"Cookie": f"__Host-fid-sp-b={captured['__Host-fid-sp-b']}"},
            )
            assert rejected.status_code == HTTPStatus.UNAUTHORIZED
        await advance_clock(301)
        recovered = await wait_delivery(idp_db, sid, "sp-b", "delivered")
        assert recovered.token_id != old_jti and recovered.attempts == 2
        assert (await account(a, stack.origin(ServiceId.SP_A)))["sid"] == fresh_sid
        await b.goto(stack.origin(ServiceId.SP_B))
        await b.get_by_role("link", name="Sign in", exact=True).click()
        await b.wait_for_url(f"{stack.origin(ServiceId.SP_B)}/")
        assert (await account(b, stack.origin(ServiceId.SP_B)))["sid"] == fresh_sid
        await stack.stop(ServiceId.SP_B)
        await stack.start(ServiceId.SP_B)
        async with stack.client() as client:
            duplicate = await client.post(
                f"{stack.origin(ServiceId.SP_B)}/backchannel-logout",
                data={"logout_token": delivery_token(assets, recovered)},
            )
            assert duplicate.status_code == HTTPStatus.OK
            wrong_recipient = await client.post(
                f"{stack.origin(ServiceId.SP_A)}/backchannel-logout",
                data={"logout_token": delivery_token(assets, recovered)},
            )
            assert wrong_recipient.status_code == HTTPStatus.BAD_REQUEST
        assert (await account(b, stack.origin(ServiceId.SP_B)))["sid"] == fresh_sid
        b_db = await runtime_database(stack, ServiceId.SP_B)
        try:
            async with b_db.sessions() as session:
                assert await session.get(LogoutSessionRow, (stack.issuer, sid)) is not None
        finally:
            await b_db.dispose()
        await stack.stop(ServiceId.IDP)
        await stack.start(ServiceId.IDP)
        await stack.stop(ServiceId.SP_A)
        await stack.start(ServiceId.SP_A)
        for page, service in ((a, ServiceId.SP_A), (b, ServiceId.SP_B)):
            assert (await account(page, stack.origin(service)))["sid"] == fresh_sid
        async with stack.client() as client:
            for service in (ServiceId.IDP, ServiceId.SP_A, ServiceId.SP_B):
                name = f"__Host-fid-{service.value}"
                replay = await client.get(
                    f"{stack.origin(service)}/account",
                    headers={"Cookie": f"{name}={captured[name]}"},
                )
                assert replay.status_code == HTTPStatus.UNAUTHORIZED
    finally:
        await idp_db.dispose()
