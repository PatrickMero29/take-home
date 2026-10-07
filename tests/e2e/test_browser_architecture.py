import pytest
from playwright.async_api import BrowserContext

from federated_identity.cli.architecture_probe import ArchitectureStack
from federated_identity.common.settings.runtime import ServiceId

pytestmark = pytest.mark.integration


async def test_browser_trust_and_host_scoped_cookies(
    deployed_stack: ArchitectureStack, trusted_browser_context: BrowserContext
) -> None:
    context = trusted_browser_context
    page = await context.new_page()
    for service in (ServiceId.IDP, ServiceId.SP_A, ServiceId.SP_B):
        response = await page.goto(deployed_stack.origin(service))
        assert response is not None and response.ok
        assert await page.locator("h1").inner_text() == service.value
    cookies = await context.cookies()
    assert len(cookies) == 3
    for cookie in cookies:
        assert cookie["secure"] and cookie["httpOnly"]
        assert cookie["path"] == "/" and cookie["sameSite"] == "Lax"
        assert cookie["domain"] in {service.hostname for service in ServiceId}
        assert cookie["name"].startswith("__Host-fid-")
    visible_to_b = await context.cookies(deployed_stack.origin(ServiceId.SP_B))
    assert len(visible_to_b) == 1
    assert visible_to_b[0]["name"] == "__Host-fid-sp-b"
    before_a = (await context.cookies(deployed_stack.origin(ServiceId.SP_A)))[0]["value"]
    await deployed_stack.stop(ServiceId.SP_A)
    await deployed_stack.start(ServiceId.SP_A)
    await page.goto(deployed_stack.origin(ServiceId.SP_A))
    after_a = (await context.cookies(deployed_stack.origin(ServiceId.SP_A)))[0]["value"]
    assert after_a == before_a
