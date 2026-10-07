"""Real operator browser controls onboard a fourth HTTPS process without restarting the IDP."""

import asyncio
from http import HTTPStatus

import pytest
from playwright.async_api import BrowserContext, expect

from federated_identity.cli.architecture_probe import ArchitectureStack
from federated_identity.cli.login_probe import seeded_user
from federated_identity.cli.operator import client_metadata
from federated_identity.cli.phase0 import process_settings
from federated_identity.common.security.secrets import load_runtime_secrets
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.services.provisioning import load_seeded_operator

pytestmark = pytest.mark.integration


async def test_live_operator_registration_and_sp_c_login_over_verified_https(
    deployed_stack: ArchitectureStack, trusted_browser_context: BrowserContext
) -> None:
    stack = deployed_stack
    context = trusted_browser_context
    await stack.start(ServiceId.SP_C)
    alice = await seeded_user(stack)
    settings = process_settings(stack, ServiceId.IDP)
    assets = await asyncio.to_thread(load_runtime_secrets, settings)
    operator = await asyncio.to_thread(
        load_seeded_operator, settings.secrets_directory, assets.envelope
    )
    metadata = await asyncio.to_thread(client_metadata, process_settings(stack, ServiceId.SP_C))
    page = await context.new_page()
    await page.goto(stack.origin(ServiceId.SP_A))
    await page.get_by_role("link", name="Sign in", exact=True).click()
    await page.get_by_label("Username", exact=True).fill(alice.username)
    await page.get_by_label("Password", exact=True).fill(alice.password.get_secret_value())
    await page.get_by_role("button", name="Sign in", exact=True).click()
    await page.wait_for_url(f"{stack.origin(ServiceId.SP_A)}/")
    await expect(page.get_by_test_id("subject")).to_have_text(alice.subject)
    b = await context.new_page()
    await b.goto(stack.origin(ServiceId.SP_B))
    await b.get_by_role("link", name="Sign in", exact=True).click()
    await b.wait_for_url(f"{stack.origin(ServiceId.SP_B)}/")
    await expect(b.get_by_test_id("subject")).to_have_text(alice.subject)
    c = await context.new_page()
    await c.goto(stack.origin(ServiceId.SP_C))
    await c.get_by_role("link", name="Sign in", exact=True).click()
    assert await c.locator("input[name=password]").count() == 0
    assert await c.get_by_text("invalid_client", exact=False).count() >= 1
    original_pid = stack.processes[ServiceId.IDP].pid
    admin = await context.new_page()
    await admin.goto(f"{stack.issuer}/admin")
    await expect(admin.get_by_role("heading", name="Operator sign in", exact=True)).to_be_visible()
    await admin.get_by_label("Operator username").fill(operator.username)
    await admin.get_by_label("Operator password").fill(operator.password.get_secret_value())
    await admin.get_by_role("button", name="Operator sign in", exact=True).click()
    await admin.wait_for_url(f"{stack.issuer}/admin")
    await admin.get_by_role("link", name="Register a client", exact=True).click()
    await admin.get_by_label("Client metadata JSON").fill(metadata.model_dump_json(indent=2))
    await admin.get_by_role("button", name="Register client", exact=True).click()
    await admin.wait_for_url(f"{stack.issuer}/admin/clients/sp-c")
    assert stack.processes[ServiceId.IDP].pid == original_pid
    await c.goto(stack.origin(ServiceId.SP_C))
    await c.get_by_role("link", name="Sign in", exact=True).click()
    await c.wait_for_url(f"{stack.origin(ServiceId.SP_C)}/")
    await expect(c.get_by_test_id("subject")).to_have_text(alice.subject)
    for application in (page, b):
        await application.reload()
        await expect(application.get_by_test_id("subject")).to_have_text(alice.subject)
    await admin.get_by_role("button", name="Disable client", exact=True).click()
    await admin.wait_for_url(f"{stack.issuer}/admin/clients/sp-c")
    denied = await c.goto(f"{stack.origin(ServiceId.SP_C)}/account")
    assert denied is not None and denied.status == HTTPStatus.SERVICE_UNAVAILABLE
    await admin.get_by_role("button", name="Enable client", exact=True).click()
    await admin.wait_for_url(f"{stack.issuer}/admin/clients/sp-c")
    denied = await c.goto(f"{stack.origin(ServiceId.SP_C)}/account")
    assert denied is not None and denied.status == HTTPStatus.UNAUTHORIZED
    await stack.stop(ServiceId.IDP)
    await stack.start(ServiceId.IDP)
    await admin.reload()
    await expect(admin.get_by_role("heading", name="sp-c", exact=True)).to_be_visible()
    await c.goto(stack.origin(ServiceId.SP_C))
    await c.get_by_role("link", name="Sign in", exact=True).click()
    await c.wait_for_url(f"{stack.origin(ServiceId.SP_C)}/")
    await expect(c.get_by_test_id("subject")).to_have_text(alice.subject)
    cookies = await context.cookies(stack.issuer)
    assert {cookie["name"] for cookie in cookies} == {"__Host-fid-idp", "__Host-fid-operator"}
    assert all(
        cookie["secure"] and cookie["httpOnly"] and cookie["path"] == "/" for cookie in cookies
    )
