"""Actual browser TLS refresh and re-authentication use shared injected process time."""

import asyncio
import json
import os
from collections.abc import AsyncIterator
from http import HTTPStatus
from pathlib import Path

import pytest
import pytest_asyncio
from playwright.async_api import BrowserContext, expect

from federated_identity.cli.architecture_probe import ArchitectureStack, architecture_stack
from federated_identity.cli.bootstrap import write_new
from federated_identity.cli.login_probe import seeded_user
from federated_identity.common.settings.policy import SystemClock
from federated_identity.common.settings.runtime import ServiceId

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


async def advance_clock(seconds: int) -> None:
    path = Path(os.environ["FID_VERIFICATION_CLOCK"])

    def advance() -> None:
        value = int(path.read_bytes()) + seconds
        staging = path.with_suffix(".next")
        write_new(staging, str(value).encode("ascii"))
        os.replace(staging, path)

    await asyncio.to_thread(advance)
    # Let the probe clocks observe the atomic publication, not a token lifetime.
    await asyncio.sleep(0.05)


async def test_real_refresh_preserves_history_and_reauthentication_rotates_only_its_sp(
    deployed_stack: ArchitectureStack, trusted_browser_context: BrowserContext
) -> None:
    stack = deployed_stack
    context = trusted_browser_context
    alice = await seeded_user(stack)
    pages = {}
    original_auth = {}
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
        await page.goto(f"{stack.origin(service)}/account")
        original_auth[service] = json.loads(await page.locator("body").inner_text())["auth_time"]
    cookies = {entry["name"]: entry["value"] for entry in await context.cookies()}
    pids = {service: process.pid for service, process in stack.processes.items()}
    await advance_clock(301)
    for service, page in pages.items():
        await page.goto(f"{stack.origin(service)}/account")
        body = json.loads(await page.locator("body").inner_text())
        assert body["auth_time"] == original_auth[service] and body["subject"] == alice.subject
        assert stack.processes[service].pid == pids[service]
    after = {entry["name"]: entry["value"] for entry in await context.cookies()}
    assert after == cookies
    await advance_clock(61)
    a = pages[ServiceId.SP_A]
    await a.goto(f"{stack.origin(ServiceId.SP_A)}/auth/reauthenticate")
    await a.get_by_label("Authentication policy").select_option("force")
    await a.get_by_role("button", name="Re-authenticate", exact=True).click()
    await expect(a.get_by_label("Password", exact=True)).to_be_visible()
    await a.get_by_label("Username", exact=True).fill(alice.username)
    await a.get_by_label("Password", exact=True).fill("not-the-password")
    await a.get_by_role("button", name="Sign in", exact=True).click()
    await expect(a.get_by_role("alert")).to_have_text("Invalid username or password.")
    await a.get_by_label("Username", exact=True).fill(alice.username)
    await a.get_by_label("Password", exact=True).fill(alice.password.get_secret_value())
    await a.get_by_role("button", name="Sign in", exact=True).click()
    await a.wait_for_url(f"{stack.origin(ServiceId.SP_A)}/")
    await expect(a.get_by_test_id("subject")).to_have_text(alice.subject)
    await a.goto(f"{stack.origin(ServiceId.SP_A)}/account")
    after_a = json.loads(await a.locator("body").inner_text())
    assert after_a["auth_time"] > original_auth[ServiceId.SP_A]
    b = pages[ServiceId.SP_B]
    await b.goto(f"{stack.origin(ServiceId.SP_B)}/account")
    after_b = json.loads(await b.locator("body").inner_text())
    assert after_b["auth_time"] == original_auth[ServiceId.SP_B]
    changed = {entry["name"]: entry["value"] for entry in await context.cookies()}
    assert changed["__Host-fid-sp-a"] != cookies["__Host-fid-sp-a"]
    assert changed["__Host-fid-sp-b"] == cookies["__Host-fid-sp-b"]
    async with stack.client() as client:
        replay = await client.get(
            f"{stack.origin(ServiceId.SP_A)}/account",
            headers={"Cookie": f"__Host-fid-sp-a={cookies['__Host-fid-sp-a']}"},
        )
        assert replay.status_code == HTTPStatus.UNAUTHORIZED
    await stack.stop(ServiceId.SP_A)
    await stack.start(ServiceId.SP_A)
    await stack.stop(ServiceId.IDP)
    await stack.start(ServiceId.IDP)
    await advance_clock(301)
    for service, page in pages.items():
        response = await page.goto(f"{stack.origin(service)}/account")
        assert response is not None and response.status == HTTPStatus.OK
        assert json.loads(await page.locator("body").inner_text())["subject"] == alice.subject
