"""Real Chromium trusts only this deployment's CA in an isolated temporary NSS profile."""

import asyncio
import os
import shutil
from collections.abc import AsyncIterator
from pathlib import Path

import pytest_asyncio
from playwright.async_api import BrowserContext, async_playwright

from federated_identity.cli.architecture_probe import ArchitectureStack
from federated_identity.cli.probe_runtime import command


@pytest_asyncio.fixture
async def trusted_browser_context(
    deployed_stack: ArchitectureStack, tmp_path: Path
) -> AsyncIterator[BrowserContext]:
    certutil = os.environ.get("FID_CERTUTIL") or shutil.which("certutil")
    if certutil is None:
        raise RuntimeError("Browser verification requires certutil (libnss3-tools)")
    home = tmp_path / "browser-home"
    nss = home / ".pki" / "nssdb"
    await asyncio.to_thread(nss.mkdir, parents=True, mode=0o700)
    await command(certutil, "-N", "--empty-password", "-d", f"sql:{nss}")
    await command(
        certutil,
        "-A",
        "-n",
        "Isolated federation test CA",
        "-t",
        "C,,",
        "-i",
        str(deployed_stack.root / "authority" / "ca.crt"),
        "-d",
        f"sql:{nss}",
    )
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(
            channel="chromium", headless=True, env={**os.environ, "HOME": str(home)}
        )
        try:
            context = await browser.new_context(ignore_https_errors=False)
            try:
                yield context
            finally:
                await context.close()
        finally:
            await browser.close()
