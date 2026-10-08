"""Actual trusted Chromium proves password/TOTP, RP isolation, recency and replay restart."""

import asyncio
import json
import os
import sys
from collections.abc import AsyncIterator
from http import HTTPStatus
from pathlib import Path

import pyotp
import pytest
import pytest_asyncio
from playwright.async_api import BrowserContext, Page, expect

from federated_identity.cli.architecture_probe import ArchitectureStack, architecture_stack
from federated_identity.cli.bootstrap import write_new
from federated_identity.cli.login_probe import seeded_user
from federated_identity.common.settings.policy import SystemClock
from federated_identity.common.settings.runtime import ServiceId
from tests.e2e.test_refresh import advance_clock

pytestmark = pytest.mark.integration


@pytest_asyncio.fixture
async def deployed_stack(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> AsyncIterator[ArchitectureStack]:
    path = tmp_path / "process-clock"
    await asyncio.to_thread(write_new, path, str(SystemClock().now()).encode("ascii"))
    monkeypatch.setenv("FID_VERIFICATION_CLOCK", str(path))
    async with architecture_stack() as stack:
        yield stack


async def enrolled_authenticator(stack: ArchitectureStack) -> pyotp.TOTP:
    environment = {
        **os.environ,
        "FID_SERVICE_ID": "idp",
        "FID_PUBLIC_URL": stack.issuer,
        "FID_ISSUER": stack.issuer,
        "FID_LISTEN_PORT": str(stack.ports[ServiceId.IDP]),
        "FID_SECRETS_DIRECTORY": str(stack.root / "idp"),
        "FID_DATABASE_HOST": "127.0.0.1",
        "FID_DATABASE_PORT": str(stack.postgres_port),
    }
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "federated_identity.cli.main",
        "totp-provisioning",
        "--username",
        "alice",
        env=environment,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    body, _ = await asyncio.wait_for(process.communicate(), timeout=30)
    assert process.returncode == 0
    result = pyotp.parse_uri(json.loads(body)["provisioning_uri"])
    assert isinstance(result, pyotp.TOTP)
    return result


async def current_code(otp: pyotp.TOTP) -> str:
    now = int(await asyncio.to_thread(Path(os.environ["FID_VERIFICATION_CLOCK"]).read_bytes))
    return otp.at(now)


async def account(page: Page, origin: str) -> dict[str, object]:
    response = await page.goto(f"{origin}/account")
    assert response is not None and response.status == HTTPStatus.OK
    result: dict[str, object] = json.loads(await page.locator("body").inner_text())
    return result


async def test_real_step_up_sensitive_access_stale_refresh_and_persisted_replay(
    deployed_stack: ArchitectureStack,
    trusted_browser_context: BrowserContext,
) -> None:
    stack, context = deployed_stack, trusted_browser_context
    user = await seeded_user(stack)
    otp = await enrolled_authenticator(stack)
    a, b = await context.new_page(), await context.new_page()
    for page, service in ((a, ServiceId.SP_A), (b, ServiceId.SP_B)):
        await page.goto(stack.origin(service))
        await page.get_by_role("link", name="Sign in", exact=True).click()
        if service == ServiceId.SP_A:
            await page.get_by_label("Username", exact=True).fill(user.username)
            await page.get_by_label("Password", exact=True).fill(user.password.get_secret_value())
            await page.get_by_role("button", name="Sign in", exact=True).click()
        await page.wait_for_url(f"{stack.origin(service)}/")
    captured = {entry["name"]: entry["value"] for entry in await context.cookies()}
    baseline_b = await account(b, stack.origin(ServiceId.SP_B))
    response = await a.goto(f"{stack.origin(ServiceId.SP_A)}/sensitive")
    assert response is not None and response.status == HTTPStatus.FORBIDDEN
    await a.get_by_role("link", name="Step up authentication", exact=True).click()
    await a.get_by_role("button", name="Verify password and TOTP", exact=True).click()
    await expect(a.get_by_label("Authenticator code", exact=True)).to_be_visible()
    code = await current_code(otp)
    await a.get_by_label("Username", exact=True).fill(user.username)
    await a.get_by_label("Password", exact=True).fill(user.password.get_secret_value())
    await a.get_by_label("Authenticator code", exact=True).fill(
        "000000" if code != "000000" else "000001"
    )
    await a.get_by_role("button", name="Sign in", exact=True).click()
    await expect(a.get_by_role("alert")).to_have_text("Invalid credentials or authentication code.")
    await a.get_by_label("Username", exact=True).fill(user.username)
    await a.get_by_label("Password", exact=True).fill(user.password.get_secret_value())
    await a.get_by_label("Authenticator code", exact=True).fill(code)
    await a.get_by_role("button", name="Sign in", exact=True).click()
    await a.wait_for_url(f"{stack.origin(ServiceId.SP_A)}/")
    upgraded = await account(a, stack.origin(ServiceId.SP_A))
    assert upgraded["acr"] == "urn:take-home:acr:password-totp" and upgraded["amr"] == [
        "pwd",
        "otp",
    ]
    after = {entry["name"]: entry["value"] for entry in await context.cookies()}
    assert after["__Host-fid-sp-a"] != captured["__Host-fid-sp-a"]
    assert after["__Host-fid-sp-b"] == captured["__Host-fid-sp-b"]
    assert (await account(b, stack.origin(ServiceId.SP_B)))["acr"] == baseline_b["acr"]
    await a.goto(f"{stack.origin(ServiceId.SP_A)}/sensitive")
    await a.get_by_role("button", name="Approve sensitive operation", exact=True).click()
    await expect(a.get_by_test_id("approval")).to_contain_text("Sensitive operation approved")
    response = await b.goto(f"{stack.origin(ServiceId.SP_B)}/sensitive")
    assert response is not None and response.status == HTTPStatus.FORBIDDEN
    await stack.stop(ServiceId.IDP)
    await stack.start(ServiceId.IDP)
    await a.goto(f"{stack.origin(ServiceId.SP_A)}/auth/step-up")
    await a.get_by_role("button", name="Verify password and TOTP", exact=True).click()
    await a.get_by_label("Username", exact=True).fill(user.username)
    await a.get_by_label("Password", exact=True).fill(user.password.get_secret_value())
    await a.get_by_label("Authenticator code", exact=True).fill(code)
    await a.get_by_role("button", name="Sign in", exact=True).click()
    await expect(a.get_by_role("alert")).to_have_text("Invalid credentials or authentication code.")
    await advance_clock(301)
    renewed = await account(a, stack.origin(ServiceId.SP_A))
    assert renewed["auth_time"] == upgraded["auth_time"] and renewed["acr"] == upgraded["acr"]
    response = await a.goto(f"{stack.origin(ServiceId.SP_A)}/sensitive")
    assert response is not None and response.status == HTTPStatus.FORBIDDEN
    await a.get_by_role("link", name="Step up authentication", exact=True).click()
    await a.get_by_role("button", name="Verify password and TOTP", exact=True).click()
    await a.get_by_label("Username", exact=True).fill(user.username)
    await a.get_by_label("Password", exact=True).fill(user.password.get_secret_value())
    await a.get_by_label("Authenticator code", exact=True).fill(await current_code(otp))
    await a.get_by_role("button", name="Sign in", exact=True).click()
    await a.wait_for_url(f"{stack.origin(ServiceId.SP_A)}/")
    assert (await account(a, stack.origin(ServiceId.SP_A)))["auth_time"] != upgraded["auth_time"]
    await stack.stop(ServiceId.SP_A)
    await stack.start(ServiceId.SP_A)
    response = await a.goto(f"{stack.origin(ServiceId.SP_A)}/sensitive")
    assert response is not None and response.status == HTTPStatus.OK
    async with stack.client() as client:
        replay = await client.get(
            f"{stack.origin(ServiceId.SP_A)}/account",
            headers={"Cookie": f"__Host-fid-sp-a={captured['__Host-fid-sp-a']}"},
        )
        assert replay.status_code == HTTPStatus.UNAUTHORIZED
