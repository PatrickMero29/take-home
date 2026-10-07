"""One real HTTPS/Chromium scenario exercises the user-facing lifecycle controls."""

from http import HTTPStatus

import pytest
from playwright.async_api import BrowserContext, expect

from federated_identity.cli.architecture_probe import ArchitectureStack
from federated_identity.cli.login_probe import seeded_user
from federated_identity.common.settings.runtime import ServiceId

pytestmark = pytest.mark.integration


async def test_browser_local_logout_grant_revocation_and_idp_session_termination(
    deployed_stack: ArchitectureStack, trusted_browser_context: BrowserContext
) -> None:
    stack = deployed_stack
    context = trusted_browser_context
    user = await seeded_user(stack)
    page = await context.new_page()
    await page.goto(stack.origin(ServiceId.SP_A))
    await page.get_by_role("link", name="Sign in", exact=True).click()
    await page.get_by_label("Username").fill(user.username)
    await page.get_by_label("Password").fill(user.password.get_secret_value())
    await page.get_by_role("button", name="Sign in", exact=True).click()
    await page.wait_for_url(f"{stack.origin(ServiceId.SP_A)}/")
    await expect(page.get_by_test_id("subject")).to_have_text(user.subject)
    old_a = (await context.cookies(stack.origin(ServiceId.SP_A)))[0]["value"]
    other = await context.new_page()
    await other.goto(stack.origin(ServiceId.SP_B))
    await other.get_by_role("link", name="Sign in", exact=True).click()
    await other.wait_for_url(f"{stack.origin(ServiceId.SP_B)}/")
    await expect(other.get_by_test_id("subject")).to_have_text(user.subject)
    await page.get_by_role("link", name="Sign out locally", exact=True).click()
    await page.get_by_role("button", name="Sign out locally", exact=True).click()
    await page.wait_for_url(f"{stack.origin(ServiceId.SP_A)}/")
    await expect(page.get_by_text("Not signed in.", exact=True)).to_be_visible()
    await other.reload()
    await expect(other.get_by_test_id("subject")).to_have_text(user.subject)
    await page.get_by_role("link", name="Sign in", exact=True).click()
    await page.wait_for_url(f"{stack.origin(ServiceId.SP_A)}/")
    await expect(page.get_by_test_id("subject")).to_have_text(user.subject)
    assert (await context.cookies(stack.origin(ServiceId.SP_A)))[0]["value"] != old_a
    await page.get_by_role("link", name="Revoke application access", exact=True).click()
    await page.get_by_role("button", name="Revoke application access", exact=True).click()
    await page.wait_for_url(f"{stack.origin(ServiceId.SP_A)}/")
    await expect(page.get_by_text("Not signed in.", exact=True)).to_be_visible()
    await other.reload()
    await expect(other.get_by_test_id("subject")).to_have_text(user.subject)
    b_cookie = (await context.cookies(stack.origin(ServiceId.SP_B)))[0]["value"]
    await page.goto(stack.issuer)
    await page.get_by_role("link", name="End IDP session", exact=True).click()
    await page.get_by_role("button", name="End IDP session", exact=True).click()
    await page.wait_for_url(f"{stack.issuer}/")
    await expect(page.get_by_text("Not signed in.", exact=True)).to_be_visible()
    await stack.stop(ServiceId.SP_B)
    await stack.start(ServiceId.SP_B)
    response = await other.goto(f"{stack.origin(ServiceId.SP_B)}/account")
    assert response is not None and response.status == HTTPStatus.UNAUTHORIZED
    assert (await context.cookies(stack.origin(ServiceId.SP_B)))[0]["value"] == b_cookie
