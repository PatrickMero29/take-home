"""Real TLS/Chromium contains and recovers an SP, then an issuer key, in one deployment."""

import asyncio
import os
import sys
from http import HTTPStatus

import pytest
from authlib.oauth2.rfc7523 import private_key_jwt_sign
from playwright.async_api import BrowserContext, expect

from federated_identity.cli.architecture_probe import ArchitectureStack
from federated_identity.cli.login_probe import seeded_user
from federated_identity.cli.phase0 import process_settings
from federated_identity.common.security.keys import SigningKey
from federated_identity.common.security.secrets import load_runtime_secrets
from federated_identity.common.settings.policy import SystemClock
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.schemas.clients import ClientCredentialReplacement, ClientRegistration
from federated_identity.idp.services.provisioning import load_seeded_operator

pytestmark = pytest.mark.integration


async def old_client_rejected(stack: ArchitectureStack, signer: SigningKey) -> None:
    async with stack.client() as client:
        for endpoint in ("/token", "/introspect", "/revoke"):
            now = SystemClock().now()
            assertion: str = private_key_jwt_sign(
                signer.key,
                client_id="sp-a",
                token_endpoint=f"{stack.issuer}{endpoint}",
                alg="RS256",
                claims={"iat": now, "exp": now + 60},
                header={"kid": signer.kid},
            )
            data = {
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": assertion,
            }
            if endpoint == "/token":
                data.update(
                    {
                        "grant_type": "authorization_code",
                        "code": "x" * 32,
                        "redirect_uri": f"{stack.origin(ServiceId.SP_A)}/auth/callback",
                        "code_verifier": "x" * 64,
                    }
                )
            else:
                data["token"] = "x" * 32
            response = await client.post(f"{stack.issuer}{endpoint}", data=data)
            assert response.status_code in {HTTPStatus.BAD_REQUEST, HTTPStatus.UNAUTHORIZED}
            assert response.json()["error"] == "invalid_client"


async def test_browser_compromise_containment_and_owner_recovery_survive_real_process_restart(
    deployed_stack: ArchitectureStack, trusted_browser_context: BrowserContext
) -> None:
    stack = deployed_stack
    context = trusted_browser_context
    alice = await seeded_user(stack)
    idp_assets = await asyncio.to_thread(
        load_runtime_secrets, process_settings(stack, ServiceId.IDP)
    )
    sp_assets = await asyncio.to_thread(
        load_runtime_secrets, process_settings(stack, ServiceId.SP_A)
    )
    operator = await asyncio.to_thread(
        load_seeded_operator, stack.root / "idp", idp_assets.envelope
    )
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
    old_cookies = {cookie["name"]: cookie["value"] for cookie in await context.cookies()}
    original_pids = {service: process.pid for service, process in stack.processes.items()}
    admin = await context.new_page()
    await admin.goto(f"{stack.issuer}/admin/login")
    await admin.get_by_label("Operator username").fill(operator.username)
    await admin.get_by_label("Operator password").fill(operator.password.get_secret_value())
    await admin.get_by_role("button", name="Operator sign in", exact=True).click()
    await admin.wait_for_url(f"{stack.issuer}/admin")
    await admin.goto(f"{stack.issuer}/admin/clients/sp-a")
    await admin.get_by_role("button", name="Contain compromised client", exact=True).click()
    await admin.wait_for_url(f"{stack.issuer}/admin/clients/sp-a")
    contained = ClientRegistration.model_validate_json(await admin.locator("pre").inner_text())
    assert not contained.enabled and contained.compromised_key_id == sp_assets.signer.kid
    await old_client_rejected(stack, sp_assets.signer)
    denied = await pages[ServiceId.SP_A].goto(f"{stack.origin(ServiceId.SP_A)}/account")
    assert denied is not None and denied.status == HTTPStatus.SERVICE_UNAVAILABLE
    await pages[ServiceId.SP_B].reload()
    await expect(pages[ServiceId.SP_B].get_by_test_id("subject")).to_have_text(alice.subject)
    await admin.get_by_role("button", name="Enable client", exact=True).click()
    await expect(
        admin.get_by_text("Replace compromised credentials before enabling", exact=False)
    ).to_be_visible()
    await admin.goto(f"{stack.issuer}/admin/clients/sp-a")

    # Exercise the actual owner CLI; stdout is only public replacement metadata.
    environment = {
        **os.environ,
        "FID_SERVICE_ID": "sp-a",
        "FID_PUBLIC_URL": stack.origin(ServiceId.SP_A),
        "FID_ISSUER": stack.issuer,
        "FID_SECRETS_DIRECTORY": str(stack.root / "sp-a"),
        "FID_LISTEN_PORT": str(stack.ports[ServiceId.SP_A]),
        "FID_DATABASE_HOST": "127.0.0.1",
        "FID_DATABASE_PORT": str(stack.postgres_port),
    }
    process = await asyncio.create_subprocess_exec(
        sys.executable,
        "-m",
        "federated_identity.cli.main",
        "client-key-replace",
        "--expected-key-id",
        contained.key_id,
        "--expected-version",
        str(contained.registration_version),
        env=environment,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    output, _ = await asyncio.wait_for(process.communicate(), timeout=30)
    assert process.returncode == 0 and b"PRIVATE KEY" not in output
    replacement = ClientCredentialReplacement.model_validate_json(output)
    await admin.get_by_label("Replace client credentials JSON").fill(replacement.model_dump_json())
    await admin.get_by_role("button", name="Replace client credentials", exact=True).click()
    await admin.wait_for_url(f"{stack.issuer}/admin/clients/sp-a")
    replaced = ClientRegistration.model_validate_json(await admin.locator("pre").inner_text())
    assert not replaced.enabled and replaced.key_id == replacement.key_id
    await stack.stop(ServiceId.SP_A)
    await stack.start(ServiceId.SP_A)
    await admin.get_by_role("button", name="Enable client", exact=True).click()
    await admin.wait_for_url(f"{stack.issuer}/admin/clients/sp-a")
    await old_client_rejected(stack, sp_assets.signer)
    denied = await pages[ServiceId.SP_A].goto(f"{stack.origin(ServiceId.SP_A)}/account")
    assert denied is not None and denied.status == HTTPStatus.UNAUTHORIZED
    await pages[ServiceId.SP_A].goto(f"{stack.origin(ServiceId.SP_A)}/auth/login")
    await pages[ServiceId.SP_A].wait_for_url(f"{stack.origin(ServiceId.SP_A)}/")
    await expect(pages[ServiceId.SP_A].get_by_test_id("subject")).to_have_text(alice.subject)
    assert stack.processes[ServiceId.SP_B].pid == original_pids[ServiceId.SP_B]
    assert stack.processes[ServiceId.IDP].pid == original_pids[ServiceId.IDP]

    # Both actual SPs still have the original issuer key in their prewarmed caches.
    await admin.goto(f"{stack.issuer}/admin/signing-keys")
    await admin.get_by_role("button", name="Prepare signing key", exact=True).click()
    await admin.wait_for_url(f"{stack.issuer}/admin/signing-keys")
    prepared = admin.locator("section[data-key-id]").filter(has_text="State: prepared")
    new_kid = await prepared.get_attribute("data-key-id")
    assert new_kid is not None
    async with admin.expect_popup() as popup_info:
        await admin.get_by_role("link", name="Publish public JWKS", exact=True).click()
    popup = await popup_info.value
    await popup.wait_for_load_state()
    await popup.close()
    await admin.get_by_role("link", name="Reload key state", exact=True).click()
    old_key = admin.locator(f"section[data-key-id='{idp_assets.signer.kid}']")
    await old_key.get_by_label("Replacement signing key").select_option(new_kid)
    await old_key.get_by_role("button", name="Contain compromised signing key", exact=True).click()
    await admin.wait_for_url(f"{stack.issuer}/admin/signing-keys")
    await expect(old_key).to_contain_text("State: revoked")
    await expect(admin.locator(f"section[data-key-id='{new_kid}']")).to_contain_text(
        "State: active"
    )
    for service, page in pages.items():
        denied = await page.goto(f"{stack.origin(service)}/account")
        assert denied is not None and denied.status == HTTPStatus.UNAUTHORIZED
        await page.goto(f"{stack.origin(service)}/auth/login")
        await page.wait_for_url(f"{stack.origin(service)}/")
        await expect(page.get_by_test_id("subject")).to_have_text(alice.subject)
    async with stack.client() as client:
        keys = (await client.get(f"{stack.issuer}/jwks.json")).json()["keys"]
        assert {key["kid"] for key in keys} == {new_kid}
    await stack.stop(ServiceId.IDP)
    await stack.start(ServiceId.IDP)
    await admin.reload()
    await expect(old_key).to_contain_text("State: revoked")
    await expect(admin.locator(f"section[data-key-id='{new_kid}']")).to_contain_text(
        "State: active"
    )
    async with stack.client() as client:
        for service, page in pages.items():
            await page.reload()
            await expect(page.get_by_test_id("subject")).to_have_text(alice.subject)
            cookie_name = f"__Host-fid-{service.value}"
            replay = await client.get(
                f"{stack.origin(service)}/account",
                headers={"Cookie": f"{cookie_name}={old_cookies[cookie_name]}"},
            )
            assert replay.status_code == HTTPStatus.UNAUTHORIZED
