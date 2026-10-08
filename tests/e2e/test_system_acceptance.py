"""One fresh real-process deployment combines the submission's selected security properties."""

import asyncio
import json
import os
from collections.abc import AsyncIterator
from http import HTTPStatus
from pathlib import Path

import pytest
import pytest_asyncio
from playwright.async_api import BrowserContext, Page, expect
from pydantic import SecretStr
from sqlalchemy import select, text

from federated_identity.cli.architecture_probe import ArchitectureStack, architecture_stack
from federated_identity.cli.architecture_runtime import LocalServiceTransport
from federated_identity.cli.bootstrap import bootstrap_assets, write_new
from federated_identity.cli.databases import initialize_databases
from federated_identity.cli.login_probe import seeded_user
from federated_identity.cli.operator import OperatorClient, client_metadata
from federated_identity.cli.phase0 import process_settings
from federated_identity.cli.probe_runtime import command, postgres_bin
from federated_identity.common.persistence.database import AsyncDatabase
from federated_identity.common.persistence.migrations import migration_head
from federated_identity.common.security.model import KeyState
from federated_identity.common.settings.policy import SystemClock, verifier_digest
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.repositories.security_tables import RefreshFamilyRow
from federated_identity.idp.schemas.clients import ClientCreate
from federated_identity.idp.services.provisioning import load_seeded_operator
from federated_identity.sp.protocol.oidc import OidcClient, RpSettings
from federated_identity.sp.repositories.security import SpSecurityRepository
from federated_identity.sp.repositories.security_tables import SpAuthenticationRow
from federated_identity.sp.services.renewal import RefreshAttempt, SpRenewalService
from federated_identity.sp.services.revocation import AuthenticatedGrantChecker
from tests.browser_helpers import runtime_assets, runtime_database
from tests.e2e.test_logout import delivery_token, wait_delivery
from tests.e2e.test_refresh import advance_clock
from tests.e2e.test_step_up import current_code, enrolled_authenticator
from tests.helpers import MutableClock

pytestmark = pytest.mark.integration
APPLICATIONS = (ServiceId.SP_A, ServiceId.SP_B, ServiceId.SP_C)


@pytest_asyncio.fixture
async def deployed_stack(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> AsyncIterator[ArchitectureStack]:
    path = tmp_path / "system-clock"
    await asyncio.to_thread(write_new, path, str(SystemClock().now()).encode("ascii"))
    monkeypatch.setenv("FID_VERIFICATION_CLOCK", str(path))
    async with architecture_stack() as stack:
        yield stack


async def process_time() -> int:
    return int(await asyncio.to_thread(Path(os.environ["FID_VERIFICATION_CLOCK"]).read_bytes))


async def account(page: Page, origin: str) -> dict[str, object]:
    result = await page.goto(f"{origin}/account")
    assert result is not None and result.status == HTTPStatus.OK
    value: dict[str, object] = json.loads(await page.locator("body").inner_text())
    return value


async def postgres_stop(stack: ArchitectureStack) -> None:
    await command(
        str(postgres_bin() / "pg_ctl"),
        "-D",
        str(stack.root / "pgdata"),
        "-w",
        "-t",
        "10",
        "-m",
        "fast",
        "stop",
    )


async def postgres_start(stack: ArchitectureStack) -> None:
    await command(
        str(postgres_bin() / "pg_ctl"),
        "-D",
        str(stack.root / "pgdata"),
        "-l",
        str(stack.root / "postgres.log"),
        "-w",
        "-t",
        "10",
        "-o",
        stack.postgres_options,
        "start",
    )


async def assert_captured_status(
    stack: ArchitectureStack,
    captured: dict[str, SecretStr],
    services: tuple[ServiceId, ...],
    status: HTTPStatus,
) -> None:
    async with stack.client() as client:
        for service in services:
            name = f"__Host-fid-{service.value}"
            result = await client.get(
                f"{stack.origin(service)}/account",
                headers={"Cookie": f"{name}={captured[name].get_secret_value()}"},
            )
            assert result.status_code == status


async def refresh_claim(
    stack: ArchitectureStack, database: AsyncDatabase, cookie: SecretStr
) -> tuple[SpRenewalService, RefreshAttempt]:
    settings = process_settings(stack, ServiceId.SP_B)
    assets = await runtime_assets(stack, ServiceId.SP_B)
    clock = MutableClock(await process_time())
    transport = LocalServiceTransport(stack.tls)
    checker = AuthenticatedGrantChecker(
        settings, assets.signer, stack.tls, clock, transport=transport
    )
    oidc = OidcClient(
        RpSettings(
            issuer=stack.issuer,
            client_id="sp-b",
            redirect_uri=settings.redirect_uri,
            policy=settings.policy,
        ),
        assets.signer,
        clock,
        tls_context=stack.tls,
        transport=transport,
        grant_checker=checker,
    )
    service = SpRenewalService(SpSecurityRepository(database, assets.envelope), oidc)
    claim = await service.claim(cookie)
    assert isinstance(claim, RefreshAttempt)
    return service, claim


async def test_selected_features_compose_with_application_database_and_pending_work_restarts(
    deployed_stack: ArchitectureStack,
    trusted_browser_context: BrowserContext,
) -> None:
    stack, context = deployed_stack, trusted_browser_context
    user = await seeded_user(stack)
    otp = await enrolled_authenticator(stack)
    idp_assets = await runtime_assets(stack, ServiceId.IDP)
    operator = await asyncio.to_thread(
        load_seeded_operator, stack.root / "idp", idp_assets.envelope
    )
    admin = OperatorClient(stack.issuer, stack.tls, transport=LocalServiceTransport(stack.tls))
    databases = {service: await runtime_database(stack, service) for service in ServiceId}
    pages = {service: await context.new_page() for service in APPLICATIONS}
    try:
        # Fresh state, current migration heads, and idempotent reinitialization.
        for service, database in databases.items():
            async with database.sessions() as session:
                assert await session.scalar(
                    text("SELECT version_num FROM alembic_version")
                ) == await migration_head(service)
        original_keys = {
            service: (await runtime_assets(stack, service)).signer.kid for service in ServiceId
        }
        await asyncio.to_thread(bootstrap_assets, stack.root, public_ports=stack.ports)
        await initialize_databases(stack.root, host="127.0.0.1", port=stack.postgres_port)
        assert original_keys == {
            service: (await runtime_assets(stack, service)).signer.kid for service in ServiceId
        }
        for service in (ServiceId.SP_A, ServiceId.SP_B):
            page = pages[service]
            await page.goto(stack.origin(service))
            await page.get_by_role("link", name="Sign in", exact=True).click()
            if service == ServiceId.SP_A:
                await page.get_by_label("Username", exact=True).fill(user.username)
                await page.get_by_label("Password", exact=True).fill(
                    user.password.get_secret_value()
                )
                await page.get_by_role("button", name="Sign in", exact=True).click()
            await page.wait_for_url(f"{stack.origin(service)}/")
            await expect(page.get_by_test_id("subject")).to_have_text(user.subject)
        sid = str((await account(pages[ServiceId.SP_A], stack.origin(ServiceId.SP_A)))["sid"])
        initial_auth = (await account(pages[ServiceId.SP_B], stack.origin(ServiceId.SP_B)))[
            "auth_time"
        ]
        await admin.login(operator.username, operator.password)
        await stack.start(ServiceId.SP_C)
        c = pages[ServiceId.SP_C]
        await c.goto(stack.origin(ServiceId.SP_C))
        await c.get_by_role("link", name="Sign in", exact=True).click()
        await expect(c.get_by_text("invalid_client", exact=False)).to_be_visible()
        idp_pid = stack.processes[ServiceId.IDP].pid
        metadata = await asyncio.to_thread(client_metadata, process_settings(stack, ServiceId.SP_C))
        await admin.register(
            ClientCreate.model_validate_json(
                metadata.model_dump_json(exclude={"registration_version", "compromised_key_id"})
            )
        )
        assert stack.processes[ServiceId.IDP].pid == idp_pid
        await c.goto(stack.origin(ServiceId.SP_C))
        await c.get_by_role("link", name="Sign in", exact=True).click()
        await c.wait_for_url(f"{stack.origin(ServiceId.SP_C)}/")
        assert (await account(c, stack.origin(ServiceId.SP_C)))["sid"] == sid
        active = next(key for key in await admin.signing_keys() if key.state == KeyState.ACTIVE)
        replacement = await admin.prepare_key()
        await admin.activate_key(replacement.key_id, active.key_id)
        for service, page in pages.items():
            assert (await account(page, stack.origin(service)))["sid"] == sid
        captured = {entry["name"]: SecretStr(entry["value"]) for entry in await context.cookies()}

        # A valid IDP rotation commits while B's durable local claim is abandoned.
        await advance_clock(301)
        old_b = captured["__Host-fid-sp-b"]
        renewer, claim = await refresh_claim(stack, databases[ServiceId.SP_B], old_b)
        renewed = await renewer.oidc.refresh_verified(
            claim.token, authentication=claim.local.authentication, nonce=claim.nonce
        )
        assert renewed.context.family.generation == 1
        await stack.stop(ServiceId.SP_B)
        await postgres_stop(stack)
        try:
            await assert_captured_status(
                stack,
                captured,
                (ServiceId.IDP, ServiceId.SP_A, ServiceId.SP_C),
                HTTPStatus.SERVICE_UNAVAILABLE,
            )
        finally:
            await postgres_start(stack)
        await stack.start(ServiceId.SP_B)
        await advance_clock(renewer.lease_seconds + 1)
        await assert_captured_status(
            stack, captured, (ServiceId.SP_B,), HTTPStatus.SERVICE_UNAVAILABLE
        )
        async with databases[ServiceId.SP_B].sessions() as session:
            local = await session.get(
                SpAuthenticationRow, verifier_digest(old_b.get_secret_value())
            )
            assert (
                local is not None
                and local.refresh_state == "blocked"
                and local.refresh_generation == 0
            )
        async with databases[ServiceId.IDP].sessions() as session:
            family = await session.get(RefreshFamilyRow, renewed.context.family.family_id)
            assert family is not None and family.generation == 1 and family.revoked_at is None
        b = pages[ServiceId.SP_B]
        await b.goto(stack.origin(ServiceId.SP_B))
        await b.get_by_role("link", name="Start a fresh sign-in", exact=True).click()
        await b.wait_for_url(f"{stack.origin(ServiceId.SP_B)}/")
        assert (await account(b, stack.origin(ServiceId.SP_B)))["auth_time"] == initial_auth
        assert (
            next(
                entry["value"]
                for entry in await context.cookies()
                if entry["name"] == "__Host-fid-sp-b"
            )
            != old_b.get_secret_value()
        )
        for service in (ServiceId.SP_A, ServiceId.SP_C):
            assert (await account(pages[service], stack.origin(service)))[
                "auth_time"
            ] == initial_auth
            async with databases[service].sessions() as session:
                rows = list(
                    await session.scalars(
                        select(SpAuthenticationRow).where(
                            SpAuthenticationRow.session_id == sid,
                            SpAuthenticationRow.revoked_at.is_(None),
                        )
                    )
                )
                assert len(rows) == 1 and rows[0].refresh_generation == 1
        old_key = next(key for key in await admin.signing_keys() if key.key_id == active.key_id)
        await admin.retire_key(old_key.key_id, old_key.verification_deadline)

        # Fresh real step-up rotates A, while established B/C retain password proof.
        a = pages[ServiceId.SP_A]
        await a.goto(f"{stack.origin(ServiceId.SP_A)}/auth/step-up")
        await a.get_by_role("button", name="Verify password and TOTP", exact=True).click()
        await a.get_by_label("Username", exact=True).fill(user.username)
        await a.get_by_label("Password", exact=True).fill(user.password.get_secret_value())
        await a.get_by_label("Authenticator code", exact=True).fill(await current_code(otp))
        await a.get_by_role("button", name="Sign in", exact=True).click()
        await a.wait_for_url(f"{stack.origin(ServiceId.SP_A)}/")
        strong = await account(a, stack.origin(ServiceId.SP_A))
        assert strong["acr"] == "urn:take-home:acr:password-totp"
        await a.goto(f"{stack.origin(ServiceId.SP_A)}/sensitive")
        await a.get_by_role("button", name="Approve sensitive operation", exact=True).click()
        await expect(a.get_by_test_id("approval")).to_be_visible()
        for service in (ServiceId.SP_B, ServiceId.SP_C):
            assert (await account(pages[service], stack.origin(service)))[
                "acr"
            ] == "urn:take-home:acr:password"
        for service in (ServiceId.SP_A, ServiceId.IDP, ServiceId.SP_C):
            await stack.stop(service)
            await stack.start(service)
            for app, page in pages.items():
                assert (await account(page, stack.origin(app)))["sid"] == sid
        assert (await admin.inspect("sp-c"))[0].client_id == "sp-c"
        assert (
            next(key for key in await admin.signing_keys() if key.state == KeyState.ACTIVE).key_id
            == replacement.key_id
        )
        await advance_clock(301)
        assert (await account(a, stack.origin(ServiceId.SP_A)))["auth_time"] == strong["auth_time"]
        response = await a.goto(f"{stack.origin(ServiceId.SP_A)}/sensitive")
        assert response is not None and response.status == HTTPStatus.FORBIDDEN
        # Renew B/C while the parent is still active. This isolates immediate
        # authoritative revocation from expired-token/uncertain-renewal recovery.
        for service in (ServiceId.SP_B, ServiceId.SP_C):
            assert (await account(pages[service], stack.origin(service)))[
                "auth_time"
            ] == initial_auth

        # Logout includes the newly onboarded, unavailable recipient and recovers.
        final_cookies = {
            entry["name"]: SecretStr(entry["value"]) for entry in await context.cookies()
        }
        await stack.stop(ServiceId.SP_C)
        await a.goto(f"{stack.origin(ServiceId.SP_A)}/auth/logout/global")
        await a.get_by_role("button", name="Continue to global sign out", exact=True).click()
        await a.get_by_role("button", name="Sign out everywhere", exact=True).click()
        await a.wait_for_url(f"{stack.origin(ServiceId.SP_A)}/")
        for app in (ServiceId.SP_A, ServiceId.SP_B):
            await wait_delivery(databases[ServiceId.IDP], sid, app.value, "delivered")
        pending = await wait_delivery(databases[ServiceId.IDP], sid, "sp-c", "pending")
        assert pending.attempts == 1
        await stack.stop(ServiceId.IDP)
        await stack.start(ServiceId.SP_C)
        await stack.start(ServiceId.IDP)
        await assert_captured_status(
            stack, final_cookies, (ServiceId.SP_C,), HTTPStatus.UNAUTHORIZED
        )
        await advance_clock(2)
        recovered = await wait_delivery(databases[ServiceId.IDP], sid, "sp-c", "delivered")
        assert recovered.attempts == 2
        await assert_captured_status(
            stack, final_cookies, (ServiceId.IDP, *APPLICATIONS), HTTPStatus.UNAUTHORIZED
        )
        await postgres_stop(stack)
        await postgres_start(stack)
        await stack.stop(ServiceId.SP_C)
        await stack.start(ServiceId.SP_C)
        await assert_captured_status(
            stack, final_cookies, (ServiceId.IDP, *APPLICATIONS), HTTPStatus.UNAUTHORIZED
        )
        async with stack.client() as client:
            duplicate = await client.post(
                f"{stack.origin(ServiceId.SP_C)}/backchannel-logout",
                data={"logout_token": delivery_token(idp_assets, recovered)},
            )
            assert duplicate.status_code == HTTPStatus.OK
        await admin.logout()
    finally:
        for database in databases.values():
            await database.dispose()
