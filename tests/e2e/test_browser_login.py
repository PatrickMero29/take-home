from urllib.parse import urlsplit

import pytest
from playwright.async_api import BrowserContext, Response, expect

from federated_identity.cli.architecture_probe import ArchitectureStack
from federated_identity.cli.login_probe import seeded_user
from federated_identity.common.settings.runtime import ServiceId

pytestmark = pytest.mark.integration


async def test_browser_password_sso_and_authenticated_cookie_isolation(
    deployed_stack: ArchitectureStack, trusted_browser_context: BrowserContext
) -> None:
    stack = deployed_stack
    context = trusted_browser_context
    user = await seeded_user(stack)
    page = await context.new_page()
    await page.goto(stack.origin(ServiceId.SP_A))
    old_a = (await context.cookies(stack.origin(ServiceId.SP_A)))[0]["value"]
    await page.get_by_role("link", name="Sign in", exact=True).click()
    await expect(page.get_by_role("heading", name="Sign in", exact=True)).to_be_visible()
    await page.get_by_label("Username").fill(user.username)
    await page.get_by_label("Password").fill(user.password.get_secret_value())
    await page.get_by_role("button", name="Sign in", exact=True).click()
    await page.wait_for_url(f"{stack.origin(ServiceId.SP_A)}/")
    await expect(page.get_by_test_id("subject")).to_have_text(user.subject)
    assert await page.locator("h1").inner_text() == "sp-a"
    a_cookie = (await context.cookies(stack.origin(ServiceId.SP_A)))[0]
    assert a_cookie["value"] != old_a
    assert await page.evaluate("document.cookie") == ""
    authorization_statuses: list[int] = []

    def observe(response: Response) -> None:
        url = urlsplit(response.url)
        if url.hostname == ServiceId.IDP.hostname and url.path == "/authorize":
            authorization_statuses.append(response.status)

    page.on("response", observe)
    await page.goto(stack.origin(ServiceId.SP_B))
    await expect(page.get_by_text("Not signed in.", exact=True)).to_be_visible()
    await page.get_by_role("link", name="Sign in", exact=True).click()
    await page.wait_for_url(f"{stack.origin(ServiceId.SP_B)}/")
    await expect(page.get_by_test_id("subject")).to_have_text(user.subject)
    assert authorization_statuses == [302]
    assert await page.locator("input[type=password]").count() == 0
    cookies = await context.cookies()
    assert len(cookies) == 3 and len({cookie["value"] for cookie in cookies}) == 3
    for cookie in cookies:
        assert cookie["name"] == f"__Host-fid-{cookie['domain'].removesuffix('.localhost')}"
        assert cookie["secure"] and cookie["httpOnly"]
        assert cookie["path"] == "/" and cookie["sameSite"] == "Lax"
        assert not cookie["domain"].startswith(".")
    visible_to_b = await context.cookies(stack.origin(ServiceId.SP_B))
    assert len(visible_to_b) == 1 and visible_to_b[0]["name"] == "__Host-fid-sp-b"
    assert await page.evaluate("document.cookie") == ""
    before_b = visible_to_b[0]["value"]
    await stack.stop(ServiceId.SP_B)
    await stack.start(ServiceId.SP_B)
    await page.goto(stack.origin(ServiceId.SP_B))
    await expect(page.get_by_test_id("subject")).to_have_text(user.subject)
    assert (await context.cookies(stack.origin(ServiceId.SP_B)))[0]["value"] == before_b
    assert context.browser is not None
    transplanted = await context.browser.new_context(ignore_https_errors=False)
    try:
        await transplanted.add_cookies(
            [
                {
                    "name": "__Host-fid-sp-b",
                    "value": a_cookie["value"],
                    "url": f"{stack.origin(ServiceId.SP_B)}/",
                    "secure": True,
                    "httpOnly": True,
                    "sameSite": "Lax",
                }
            ]
        )
        hostile_page = await transplanted.new_page()
        response = await hostile_page.goto(f"{stack.origin(ServiceId.SP_B)}/account")
        assert response is not None and response.status == 401
    finally:
        await transplanted.close()
