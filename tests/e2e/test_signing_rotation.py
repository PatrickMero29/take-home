"""Real TLS/browser rotation recovers both prewarmed SPs without restarting them."""

import asyncio

import pytest
from playwright.async_api import BrowserContext, expect

from federated_identity.cli.architecture_probe import ArchitectureStack
from federated_identity.cli.login_probe import seeded_user
from federated_identity.cli.phase0 import process_settings
from federated_identity.common.security.secrets import load_runtime_secrets
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.services.provisioning import load_seeded_operator

pytestmark = pytest.mark.integration


async def test_live_rotation_preserves_sessions_refreshes_sp_trust_and_survives_idp_restart(
    deployed_stack: ArchitectureStack, trusted_browser_context: BrowserContext
) -> None:
    stack = deployed_stack
    context = trusted_browser_context
    alice = await seeded_user(stack)
    assets = await asyncio.to_thread(load_runtime_secrets, process_settings(stack, ServiceId.IDP))
    operator = await asyncio.to_thread(load_seeded_operator, stack.root / "idp", assets.envelope)
    pages = {}
    for service in (ServiceId.SP_A, ServiceId.SP_B):
        page = await context.new_page()
        pages[service] = page
        await page.goto(stack.origin(service))
        await page.get_by_role("link", name="Sign in", exact=True).click()
        if service == ServiceId.SP_A:
            await page.get_by_label("Username", exact=True).fill(alice.username)
            await page.get_by_label("Password", exact=True).fill(alice.password.get_secret_value())
            await page.get_by_role("button", name="Sign in", exact=True).click()
        await page.wait_for_url(f"{stack.origin(service)}/")
        await expect(page.get_by_test_id("subject")).to_have_text(alice.subject)
    cookies = {cookie["name"]: cookie["value"] for cookie in await context.cookies()}
    pids = {
        service: stack.processes[service].pid
        for service in (ServiceId.IDP, ServiceId.SP_A, ServiceId.SP_B)
    }
    async with stack.client() as client:
        old_jwks = (await client.get(f"{stack.issuer}/jwks.json")).json()
        assert len(old_jwks["keys"]) == 1
        old_kid = old_jwks["keys"][0]["kid"]
    admin = await context.new_page()
    await admin.goto(f"{stack.issuer}/admin/login")
    await admin.get_by_label("Operator username").fill(operator.username)
    await admin.get_by_label("Operator password").fill(operator.password.get_secret_value())
    await admin.get_by_role("button", name="Operator sign in", exact=True).click()
    await admin.wait_for_url(f"{stack.issuer}/admin")
    await admin.get_by_role("link", name="Manage signing keys", exact=True).click()
    await admin.get_by_role("button", name="Prepare signing key", exact=True).click()
    await admin.wait_for_url(f"{stack.issuer}/admin/signing-keys")
    sections = await admin.locator("section[data-key-id]").all()
    assert len(sections) == 2
    prepared = None
    for section in sections:
        if "State: prepared" in await section.inner_text():
            prepared = section
            break
    assert prepared is not None
    new_kid = await prepared.get_attribute("data-key-id")
    assert new_kid is not None and new_kid != old_kid
    assert await admin.get_by_role("button", name="Activate signing key", exact=True).count() == 0
    async with admin.expect_popup() as popup_info:
        await admin.get_by_role("link", name="Publish public JWKS", exact=True).click()
    popup = await popup_info.value
    await popup.wait_for_load_state()
    assert new_kid in await popup.locator("body").inner_text()
    await popup.close()
    await admin.get_by_role("link", name="Reload key state", exact=True).click()
    await admin.get_by_role("button", name="Activate signing key", exact=True).click()
    await admin.wait_for_url(f"{stack.issuer}/admin/signing-keys")
    async with stack.client() as client:
        public = (await client.get(f"{stack.issuer}/jwks.json")).json()
        assert {key["kid"] for key in public["keys"]} == {old_kid, new_kid}
    for service, page in pages.items():
        await page.reload()
        await expect(page.get_by_test_id("subject")).to_have_text(alice.subject)
        assert (await context.cookies(stack.origin(service)))[0]["value"] == cookies[
            f"__Host-fid-{service.value}"
        ]
        # The actual SP instance still holds its first-key JWKS cache.
        await page.goto(f"{stack.origin(service)}/auth/login")
        await page.wait_for_url(f"{stack.origin(service)}/")
        await expect(page.get_by_test_id("subject")).to_have_text(alice.subject)
        assert stack.processes[service].pid == pids[service]
    assert stack.processes[ServiceId.IDP].pid == pids[ServiceId.IDP]
    await stack.stop(ServiceId.IDP)
    await stack.start(ServiceId.IDP)
    await admin.reload()
    active = admin.locator(f"section[data-key-id='{new_kid}']")
    draining = admin.locator(f"section[data-key-id='{old_kid}']")
    await expect(active).to_contain_text("State: active")
    await expect(draining).to_contain_text("State: draining")
    for service, page in pages.items():
        await page.goto(f"{stack.origin(service)}/auth/login")
        await page.wait_for_url(f"{stack.origin(service)}/")
        await expect(page.get_by_test_id("subject")).to_have_text(alice.subject)
        assert stack.processes[service].pid == pids[service]
