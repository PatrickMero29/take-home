"""Persisted infrastructure/factory reconstruction cannot restore ended or consumed authority."""

from collections.abc import AsyncIterator
from http import HTTPStatus

import pytest
import pytest_asyncio
from pydantic import SecretStr

from federated_identity.cli.probe_runtime import command, postgres_bin
from federated_identity.common.security.model import LifecyclePolicy
from federated_identity.common.settings.runtime import ServiceId
from tests.integration.test_refresh import issue, refresh_parameters
from tests.lifecycle_helpers import LifecycleLab, lifecycle_lab, next_scenario

pytestmark = [pytest.mark.integration, pytest.mark.asyncio(loop_scope="module")]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def acceptance_runtime() -> AsyncIterator[LifecycleLab]:
    async with lifecycle_lab() as lab:
        yield lab


@pytest_asyncio.fixture(loop_scope="module")
async def accepted(acceptance_runtime: LifecycleLab) -> LifecycleLab:
    next_scenario(acceptance_runtime)
    return acceptance_runtime


async def restart_infrastructure(lab: LifecycleLab) -> None:
    executable = str(postgres_bin() / "pg_ctl")
    await command(
        executable, "-D", str(lab.stack.root / "pgdata"), "-w", "-t", "10", "-m", "fast", "stop"
    )
    await command(
        executable,
        "-D",
        str(lab.stack.root / "pgdata"),
        "-l",
        str(lab.stack.root / "postgres.log"),
        "-w",
        "-t",
        "10",
        "-o",
        lab.stack.postgres_options,
        "start",
    )
    for service in (ServiceId.IDP, ServiceId.SP_A, ServiceId.SP_B):
        await lab.restart(service)


async def test_expired_revoked_and_active_sessions_keep_their_state_across_all_restarts(
    accepted: LifecycleLab,
) -> None:
    lab = accepted
    async with lab.client() as expired, lab.client() as revoked, lab.client() as active:
        lab.sp().security.lifecycle = LifecyclePolicy(sp_session_seconds=120, sp_idle_seconds=30)
        await lab.login(expired)
        await lab.sign_in(expired)
        expired_cookie = SecretStr(str(expired.cookies.get("__Host-fid-sp-a")))
        lab.sp().security.lifecycle = LifecyclePolicy()
        lab.clock.value += 60
        for browser in (revoked, active):
            await lab.login(browser)
            await lab.sign_in(browser)
            await lab.sign_in(browser, ServiceId.SP_B)
        revoked_sid = (await lab.account(revoked)).json()["sid"]
        active_sid = (await lab.account(active)).json()["sid"]
        await lab.idp().security.end_session(revoked_sid)
        await lab.idp().logout_dispatcher.dispatch_once(session_id=revoked_sid)
        await restart_infrastructure(lab)
        assert (await lab.account(expired)).status_code == HTTPStatus.UNAUTHORIZED
        forced = await active.get(
            f"{lab.stack.origin(ServiceId.SP_A)}/account",
            headers={"Cookie": f"__Host-fid-sp-a={expired_cookie.get_secret_value()}"},
        )
        assert forced.status_code == HTTPStatus.UNAUTHORIZED
        for service in (ServiceId.IDP, ServiceId.SP_A, ServiceId.SP_B):
            assert (await lab.account(revoked, service)).status_code == HTTPStatus.UNAUTHORIZED
            assert (await lab.account(active, service)).json()["sid"] == active_sid


async def test_consumed_code_and_refresh_replay_proofs_survive_infrastructure_restart(
    accepted: LifecycleLab,
) -> None:
    lab = accepted
    async with lab.client() as browser:
        await lab.login(browser)
        transaction = lab.sp().oidc.begin()
        callback = (await browser.get(transaction.authorization_url)).headers["location"]
        login = await lab.sp().oidc.exchange_verified(transaction, callback)
        original = await issue(lab, browser)
        assert original.response.refresh_token is not None
        successor = await browser.post(
            f"{lab.stack.issuer}/token",
            data=refresh_parameters(lab, original.response.refresh_token),
        )
        assert successor.status_code == HTTPStatus.OK
        refreshed_access = SecretStr(successor.json()["access_token"])
        await restart_infrastructure(lab)
        replay = await browser.post(
            f"{lab.stack.issuer}/token", data=lab.token_parameters(transaction, callback)
        )
        assert replay.json()["error"] == "invalid_grant"
        assert not (await lab.sp().grants.check(SecretStr(login.response.access_token))).active
        refresh_replay = await browser.post(
            f"{lab.stack.issuer}/token",
            data=refresh_parameters(lab, original.response.refresh_token),
        )
        assert refresh_replay.json()["error"] == "invalid_grant"
        assert not (await lab.sp().grants.check(refreshed_access)).active
        assert (await lab.account(browser, ServiceId.IDP)).status_code == HTTPStatus.OK
