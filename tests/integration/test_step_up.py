"""Real factor proof, replay, throttling and RP enforcement share TLS PostgreSQL and a clock."""

import asyncio
from collections.abc import AsyncIterator
from dataclasses import dataclass
from http import HTTPStatus
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx2 as httpx
import pyotp
import pytest
import pytest_asyncio
from pydantic import SecretStr
from sqlalchemy import event, func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from federated_identity.cli.bootstrap import bootstrap_assets
from federated_identity.cli.databases import initialize_databases
from federated_identity.cli.login_probe import credential_challenge
from federated_identity.cli.phase0 import process_settings
from federated_identity.cli.totp import totp_provisioning
from federated_identity.common.security.model import Assurance, SpSessionEvidence
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.repositories.mfa import TotpConsumptionRow, TotpCredentialRow
from federated_identity.idp.repositories.security_tables import AuthenticationEventRow
from federated_identity.idp.repositories.throttling import AuthenticationThrottled
from federated_identity.idp.schemas.users import SeededUser
from federated_identity.idp.services.authentication import PasswordAuthenticator, VerifiedPassword
from federated_identity.idp.services.mfa import TotpAuthenticator
from federated_identity.idp.services.provisioning import load_seeded_totps, load_seeded_users
from federated_identity.sp.repositories.sensitive import SensitiveOperationRow
from federated_identity.sp.services.sensitive import SpSensitiveService
from tests.lifecycle_helpers import LifecycleLab, action_challenge, lifecycle_lab, next_scenario

pytestmark = [pytest.mark.integration, pytest.mark.asyncio(loop_scope="module")]


@dataclass
class StepLab:
    life: LifecycleLab
    secrets: dict[str, SecretStr]
    users: dict[str, SeededUser]

    def code(self, *, offset: int = 0, username: str = "alice") -> str:
        user = self.users[username]
        return pyotp.TOTP(self.secrets[user.subject].get_secret_value()).at(
            self.life.clock.now() + offset
        )


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def step_runtime() -> AsyncIterator[StepLab]:
    async with lifecycle_lab() as lab:
        values = await asyncio.to_thread(
            load_seeded_totps, lab.stack.root / "idp", lab.assets[ServiceId.IDP].envelope
        )
        users = await asyncio.to_thread(
            load_seeded_users, lab.stack.root / "idp", lab.assets[ServiceId.IDP].envelope
        )
        yield StepLab(
            lab,
            {value.subject: value.secret for value in values.credentials},
            {user.username: user for user in users.users},
        )


@pytest_asyncio.fixture(loop_scope="module")
async def step(step_runtime: StepLab) -> StepLab:
    next_scenario(step_runtime.life)
    return step_runtime


def cookie(browser: httpx.AsyncClient, service: ServiceId = ServiceId.SP_A) -> SecretStr:
    value = browser.cookies.get(f"__Host-fid-{service.value}")
    assert isinstance(value, str)
    return SecretStr(value)


async def begin(
    step: StepLab, browser: httpx.AsyncClient, service: ServiceId = ServiceId.SP_A
) -> httpx.Response:
    lab = step.life
    form = await browser.get(f"{lab.stack.origin(service)}/auth/step-up")
    start = await lab.post_action(browser, service, "/auth/step-up", action_challenge(form))
    assert start.status_code == HTTPStatus.SEE_OTHER
    parameters = parse_qs(urlsplit(start.headers["location"]).query)
    assert parameters["acr_values"] == [Assurance.PASSWORD_TOTP.value]
    assert parameters["prompt"] == ["login"] and parameters["max_age"] == ["0"]
    response = await browser.get(start.headers["location"])
    assert response.status_code == HTTPStatus.OK and "name='otp'" in response.text
    return response


async def submit(
    step: StepLab,
    browser: httpx.AsyncClient,
    form: httpx.Response,
    *,
    code: str | None = None,
    username: str = "alice",
    password: str | None = None,
) -> httpx.Response:
    user = step.users[username]
    return await browser.post(
        f"{step.life.stack.issuer}/login",
        headers={"Origin": step.life.stack.issuer},
        data={
            "csrf": action_challenge(form),
            "username": username,
            "password": password if password is not None else user.password.get_secret_value(),
            "otp": code if code is not None else step.code(username=username),
        },
    )


async def elevate(
    step: StepLab, browser: httpx.AsyncClient, service: ServiceId = ServiceId.SP_A
) -> None:
    result = await submit(step, browser, await begin(step, browser, service))
    assert result.status_code == HTTPStatus.FOUND
    finished = await browser.get(result.headers["location"])
    assert finished.status_code == HTTPStatus.SEE_OTHER


async def operations(lab: LifecycleLab, service: ServiceId = ServiceId.SP_A) -> int:
    async with lab.sp(service).database.sessions() as session:
        return int(
            await session.scalar(select(func.count()).select_from(SensitiveOperationRow)) or 0
        )


async def consumptions(step: StepLab) -> list[TotpConsumptionRow]:
    async with step.life.idp().oidc.database.sessions() as session:
        return list(
            await session.scalars(
                select(TotpConsumptionRow).where(
                    TotpConsumptionRow.subject == step.life.user.subject,
                    TotpConsumptionRow.accepted_at >= step.life.clock.now() - 1000,
                )
            )
        )


async def test_real_step_up_rotates_only_selected_sp_and_enables_a_committed_sensitive_operation(
    step: StepLab,
) -> None:
    lab = step.life
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        await lab.sign_in(browser, ServiceId.SP_B)
        old_a, old_b, old_idp = (
            cookie(browser),
            cookie(browser, ServiceId.SP_B),
            cookie(browser, ServiceId.IDP),
        )
        baseline_b = (await lab.account(browser, ServiceId.SP_B)).json()
        base_count = await operations(lab)
        assert (
            await browser.get(f"{lab.stack.origin(ServiceId.SP_A)}/sensitive")
        ).status_code == HTTPStatus.FORBIDDEN
        lab.clock.value += 10
        await elevate(step, browser)
        assert cookie(browser) != old_a and cookie(browser, ServiceId.IDP) != old_idp
        assert cookie(browser, ServiceId.SP_B) == old_b
        after = (await lab.account(browser)).json()
        assert after["acr"] == Assurance.PASSWORD_TOTP.value and after["amr"] == ["pwd", "otp"]
        assert after["auth_time"] == lab.clock.now()
        assert (await lab.account(browser, ServiceId.SP_B)).json() == baseline_b
        assert (
            await browser.get(f"{lab.stack.origin(ServiceId.SP_B)}/sensitive")
        ).status_code == HTTPStatus.FORBIDDEN
        form = await browser.get(f"{lab.stack.origin(ServiceId.SP_A)}/sensitive")
        challenge = action_challenge(form)
        result = await lab.post_action(browser, ServiceId.SP_A, "/sensitive", challenge)
        assert result.status_code == HTTPStatus.OK and "Sensitive operation approved" in result.text
        assert await operations(lab) == base_count + 1
        assert (
            await lab.post_action(browser, ServiceId.SP_A, "/sensitive", challenge)
        ).status_code == HTTPStatus.FORBIDDEN
        replay = await browser.get(
            f"{lab.stack.origin(ServiceId.SP_A)}/account",
            headers={"Cookie": f"__Host-fid-sp-a={old_a.get_secret_value()}"},
        )
        assert replay.status_code == HTTPStatus.UNAUTHORIZED
        rows = await consumptions(step)
        assert len(rows) == 1 and rows[0].counter == lab.clock.now() // 30
        async with lab.idp().oidc.database.sessions() as session:
            event_row = await session.get(AuthenticationEventRow, rows[0].event_id)
            assert event_row is not None and event_row.assurance == Assurance.PASSWORD_TOTP.value


@pytest.mark.parametrize(
    "attack", ["wrong", "expired", "future", "wrong_password", "account_substitution", "missing"]
)
async def test_invalid_factor_or_password_cannot_create_stronger_evidence_or_consume_a_step(
    step: StepLab, attack: str
) -> None:
    lab = step.life
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        old = cookie(browser)
        form = await begin(step, browser)
        if attack == "missing":
            response = await browser.post(
                f"{lab.stack.issuer}/login",
                headers={"Origin": lab.stack.issuer},
                data={
                    "csrf": action_challenge(form),
                    "username": "alice",
                    "password": lab.user.password.get_secret_value(),
                },
            )
        else:
            code = step.code(offset=-90 if attack == "expired" else 90 if attack == "future" else 0)
            if attack == "wrong":
                code = "000000" if code != "000000" else "000001"
            response = await submit(
                step,
                browser,
                form,
                code=code,
                password="incorrect" if attack == "wrong_password" else None,
                username="bob" if attack == "account_substitution" else "alice",
            )
        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert not await consumptions(step)
        assert (
            cookie(browser) == old
            and (await lab.account(browser)).json()["acr"] == Assurance.PASSWORD.value
        )
        assert (
            await browser.get(f"{lab.stack.origin(ServiceId.SP_A)}/sensitive")
        ).status_code == HTTPStatus.FORBIDDEN


async def test_otp_replay_survives_idp_restart_and_unused_later_steps_work(step: StepLab) -> None:
    lab = step.life
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        original_code = step.code()
        await elevate(step, browser)
        await lab.restart(ServiceId.IDP)
        form = await begin(step, browser)
        response = await submit(step, browser, form, code=original_code)
        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert len(await consumptions(step)) == 1
        lab.clock.value += 60
        await elevate(step, browser)
        assert len(await consumptions(step)) == 2
        with pytest.raises(DBAPIError, match="irreversible"):
            async with lab.idp().oidc.database.engine.begin() as connection:
                await connection.execute(
                    text(
                        "UPDATE totp_credentials SET last_accepted_counter=-1 "
                        "WHERE subject=:subject"
                    ),
                    {"subject": lab.user.subject},
                )


async def test_concurrent_same_factor_has_one_committed_stronger_event(step: StepLab) -> None:
    lab = step.life
    async with lab.client() as a, lab.client() as b:
        await lab.login(a)
        await lab.login(b)
        await lab.sign_in(a)
        await lab.sign_in(b)
        forms = await asyncio.gather(begin(step, a), begin(step, b))
        code = step.code()
        results = await asyncio.gather(
            submit(step, a, forms[0], code=code), submit(step, b, forms[1], code=code)
        )
        assert sorted(value.status_code for value in results) == [302, 401]
        assert len(await consumptions(step)) == 1


async def test_refresh_preserves_mfa_history_and_stale_sensitive_access_requires_new_proof(
    step: StepLab,
) -> None:
    lab = step.life
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        await elevate(step, browser)
        before = (await lab.account(browser)).json()
        form = await browser.get(f"{lab.stack.origin(ServiceId.SP_A)}/sensitive")
        challenge = action_challenge(form)
        lab.clock.value += 301
        after = await lab.account(browser)
        assert after.status_code == HTTPStatus.OK
        for name in ("subject", "sid", "auth_time", "acr", "amr"):
            assert after.json()[name] == before[name]
        assert (
            await browser.get(f"{lab.stack.origin(ServiceId.SP_A)}/sensitive")
        ).status_code == HTTPStatus.FORBIDDEN
        assert (
            await lab.post_action(browser, ServiceId.SP_A, "/sensitive", challenge)
        ).status_code == HTTPStatus.FORBIDDEN
        await elevate(step, browser)
        assert (await lab.account(browser)).json()["auth_time"] > before["auth_time"]
        assert (
            await browser.get(f"{lab.stack.origin(ServiceId.SP_A)}/sensitive")
        ).status_code == HTTPStatus.OK


async def test_rp_rejects_downgraded_assurance_request_before_rotating_its_cookie(
    step: StepLab,
) -> None:
    lab = step.life
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        old = cookie(browser)
        form = await browser.get(f"{lab.stack.origin(ServiceId.SP_A)}/auth/step-up")
        start = await lab.post_action(
            browser, ServiceId.SP_A, "/auth/step-up", action_challenge(form)
        )
        values = {
            name: value[0]
            for name, value in parse_qs(urlsplit(start.headers["location"]).query).items()
        }
        values.pop("acr_values")
        values.pop("prompt")
        values.pop("max_age")
        callback = (await browser.get(f"{lab.stack.issuer}/authorize?{urlencode(values)}")).headers[
            "location"
        ]
        response = await browser.get(callback)
        assert (
            response.status_code == HTTPStatus.BAD_REQUEST and "set-cookie" not in response.headers
        )
        assert (
            cookie(browser) == old
            and (await lab.account(browser)).json()["acr"] == Assurance.PASSWORD.value
        )


@pytest.mark.parametrize("attack", ["missing", "origin", "other_browser", "purpose", "expired"])
async def test_step_up_intent_remains_cookie_origin_purpose_and_time_bound(
    step: StepLab, attack: str
) -> None:
    lab = step.life
    async with lab.client() as browser, lab.client() as other:
        await lab.login(browser)
        await lab.sign_in(browser)
        form = await browser.get(f"{lab.stack.origin(ServiceId.SP_A)}/auth/step-up")
        data = {"csrf": action_challenge(form)}
        headers = {
            "Origin": lab.stack.origin(ServiceId.SP_A),
            "Content-Type": "application/x-www-form-urlencoded",
        }
        target, path = browser, "/auth/step-up"
        if attack == "missing":
            data = {}
        elif attack == "origin":
            headers["Origin"] = lab.stack.issuer
        elif attack == "other_browser":
            await lab.login(other)
            await lab.sign_in(other)
            target = other
        elif attack == "purpose":
            path = "/auth/reauthenticate"
            data.update(mode="force", max_age="0")
        else:
            lab.clock.value += 300
        response = await target.post(
            f"{lab.stack.origin(ServiceId.SP_A)}{path}", headers=headers, data=data
        )
        assert response.status_code == HTTPStatus.FORBIDDEN
        assert not await consumptions(step)


async def test_attempt_limits_survive_new_forms_other_browsers_and_restart(step: StepLab) -> None:
    lab = step.life
    async with lab.client() as browser, lab.client() as other:
        await lab.login(browser)
        await lab.sign_in(browser)
        # Password login used one account attempt; four incorrect OTP attempts use the rest.
        for _ in range(4):
            form = await begin(step, browser)
            response = await submit(step, browser, form, code="nototp")
            assert response.status_code == HTTPStatus.UNAUTHORIZED
        await lab.restart(ServiceId.IDP)
        form = await begin(step, browser)
        response = await submit(step, browser, form)
        assert (
            response.status_code == HTTPStatus.TOO_MANY_REQUESTS
            and int(response.headers["retry-after"]) > 0
        )
        form = await other.get(f"{lab.stack.issuer}/login")
        response = await other.post(
            f"{lab.stack.issuer}/login",
            headers={"Origin": lab.stack.issuer},
            data={
                "csrf": action_challenge(form),
                "username": "alice",
                "password": lab.user.password.get_secret_value(),
            },
        )
        assert response.status_code == HTTPStatus.TOO_MANY_REQUESTS
        assert not await consumptions(step)
        lab.clock.value += 60
        await elevate(step, browser)


async def test_source_budget_bounds_username_spraying_and_browser_budget_is_independent(
    step: StepLab,
) -> None:
    lab = step.life
    limiter = lab.idp().browser.limiter
    one, two = SecretStr("a" * 43), SecretStr("b" * 43)
    for index in range(limiter.settings.authentication_source_attempts):
        await limiter.reserve(f"unknown{index}", SecretStr(f"{index:043d}"), "source-limit-test")
    with pytest.raises(AuthenticationThrottled):
        await limiter.reserve("another", two, "source-limit-test")
    for index in range(limiter.settings.authentication_browser_attempts):
        await limiter.reserve(f"browser{index}", one, f"source-{index}")
    with pytest.raises(AuthenticationThrottled):
        await limiter.reserve("freshname", one, "freshsource")


async def test_mfa_commit_failure_rolls_back_consumption_event_and_cookie(
    step: StepLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab = step.life
    original = TotpAuthenticator.consume_in

    def mark(
        self: TotpAuthenticator,
        session: AsyncSession,
        proof: tuple[TotpCredentialRow, int],
        event_id: str,
        code: SecretStr,
    ) -> None:
        original(self, session, proof, event_id, code)
        session.info["fail_mfa_commit"] = True

    def fail(session: Session) -> None:
        if session.info.get("fail_mfa_commit"):
            raise RuntimeError("Injected MFA commit failure")

    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        form = await begin(step, browser)
        before = cookie(browser, ServiceId.IDP)
        event.listen(Session, "before_commit", fail)
        try:
            with monkeypatch.context() as patch:
                patch.setattr(TotpAuthenticator, "consume_in", mark)
                with pytest.raises(RuntimeError, match="Injected MFA"):
                    await submit(step, browser, form)
        finally:
            event.remove(Session, "before_commit", fail)
        assert cookie(browser, ServiceId.IDP) == before and not await consumptions(step)
        assert (await lab.account(browser)).json()["acr"] == Assurance.PASSWORD.value
        await elevate(step, browser)
        assert len(await consumptions(step)) == 1


async def test_logout_while_password_proof_is_pending_cannot_consume_otp_or_create_an_event(
    step: StepLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab = step.life
    entered, release = asyncio.Event(), asyncio.Event()
    original = PasswordAuthenticator.verify_credentials

    async def pause(
        self: PasswordAuthenticator, username: str, password: SecretStr
    ) -> VerifiedPassword | None:
        proof = await original(self, username, password)
        entered.set()
        await release.wait()
        return proof

    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        sid = (await lab.account(browser)).json()["sid"]
        form = await begin(step, browser)
        monkeypatch.setattr(PasswordAuthenticator, "verify_credentials", pause)
        pending = asyncio.create_task(submit(step, browser, form))
        try:
            await asyncio.wait_for(entered.wait(), timeout=3)
            await lab.idp().security.end_session(sid)
        finally:
            release.set()
        assert (await asyncio.wait_for(pending, timeout=3)).status_code == HTTPStatus.UNAUTHORIZED
        assert not await consumptions(step)


async def test_enrolled_custody_owner_uri_and_consumed_history_survive_bootstrap(
    step: StepLab,
) -> None:
    lab = step.life
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        await elevate(step, browser)
        async with lab.idp().oidc.database.sessions() as session:
            row = await session.get(TotpCredentialRow, lab.user.subject)
            assert row is not None
            counter, encrypted = row.last_accepted_counter, row.encrypted_secret
            assert step.secrets[lab.user.subject].get_secret_value().encode() not in encrypted
        disclosed = await totp_provisioning(process_settings(lab.stack, ServiceId.IDP), "alice")
        parsed = pyotp.parse_uri(disclosed["provisioning_uri"])
        assert parsed.secret == step.secrets[lab.user.subject].get_secret_value()
        with pytest.raises(ValueError, match="only"):
            await totp_provisioning(process_settings(lab.stack, ServiceId.SP_A), "alice")
        await asyncio.to_thread(bootstrap_assets, lab.stack.root)
        await initialize_databases(lab.stack.root, host="127.0.0.1", port=lab.stack.postgres_port)
        await lab.restart(ServiceId.IDP)
        async with lab.idp().oidc.database.sessions() as session:
            row = await session.get(TotpCredentialRow, lab.user.subject)
            assert (
                row is not None
                and row.last_accepted_counter == counter
                and row.encrypted_secret == encrypted
            )
        for path in ("/", "/account", "/architecture", "/.well-known/openid-configuration"):
            response = await browser.get(f"{lab.stack.issuer}{path}")
            assert step.secrets[lab.user.subject].get_secret_value() not in response.text


async def test_future_drift_acceptance_cannot_replay_an_unused_earlier_step(step: StepLab) -> None:
    lab = step.life
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        form = await begin(step, browser)
        future = await submit(step, browser, form, code=step.code(offset=30))
        assert future.status_code == HTTPStatus.FOUND
        assert (await browser.get(future.headers["location"])).status_code == HTTPStatus.SEE_OTHER
        rejected = await submit(step, browser, await begin(step, browser), code=step.code())
        assert rejected.status_code == HTTPStatus.UNAUTHORIZED
        assert len(await consumptions(step)) == 1


async def test_factor_form_attempt_budget_is_bound_to_the_original_continuation(
    step: StepLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lab = step.life
    limiter = lab.idp().browser.limiter
    monkeypatch.setattr(
        limiter,
        "settings",
        limiter.settings.model_copy(update={"authentication_account_attempts": 20}),
    )
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        form = await begin(step, browser)
        for index in range(5):
            csrf = credential_challenge(form.text).get_secret_value()
            form = await browser.post(
                f"{lab.stack.issuer}/login",
                headers={"Origin": lab.stack.issuer},
                data={
                    "csrf": csrf,
                    "username": "alice",
                    "password": lab.user.password.get_secret_value(),
                    "otp": "nototp",
                },
            )
            assert form.status_code == (
                HTTPStatus.TOO_MANY_REQUESTS if index == 4 else HTTPStatus.UNAUTHORIZED
            )
        assert "name='otp'" not in form.text and not await consumptions(step)


async def test_sensitive_commit_failure_preserves_the_one_use_intent(step: StepLab) -> None:
    lab = step.life

    def fail(session: Session) -> None:
        if any(isinstance(row, SensitiveOperationRow) for row in session.new):
            raise RuntimeError("Injected sensitive operation commit failure")

    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        await elevate(step, browser)
        form = await browser.get(f"{lab.stack.origin(ServiceId.SP_A)}/sensitive")
        challenge = action_challenge(form)
        before = await operations(lab)
        event.listen(Session, "before_commit", fail)
        try:
            with pytest.raises(RuntimeError, match="Injected sensitive"):
                await lab.post_action(browser, ServiceId.SP_A, "/sensitive", challenge)
        finally:
            event.remove(Session, "before_commit", fail)
        assert await operations(lab) == before
        assert (
            await lab.post_action(browser, ServiceId.SP_A, "/sensitive", challenge)
        ).status_code == HTTPStatus.OK
        assert await operations(lab) == before + 1


async def test_sensitive_operation_rechecks_recency_after_its_online_authorization(
    step: StepLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lab = step.life
    entered, release = asyncio.Event(), asyncio.Event()
    original = SpSensitiveService.authorize

    async def pause(self: SpSensitiveService, token: SecretStr) -> SpSessionEvidence:
        local = await original(self, token)
        entered.set()
        await release.wait()
        return local

    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        await elevate(step, browser)
        form = await browser.get(f"{lab.stack.origin(ServiceId.SP_A)}/sensitive")
        challenge = action_challenge(form)
        before = await operations(lab)
        monkeypatch.setattr(SpSensitiveService, "authorize", pause)
        pending = asyncio.create_task(
            lab.post_action(browser, ServiceId.SP_A, "/sensitive", challenge)
        )
        try:
            await asyncio.wait_for(entered.wait(), timeout=3)
            lab.clock.value += lab.sp().settings.sensitive_max_age_seconds + 1
        finally:
            release.set()
        assert (await asyncio.wait_for(pending, timeout=3)).status_code == HTTPStatus.FORBIDDEN
        assert await operations(lab) == before


async def test_otp_expiring_during_event_creation_rolls_back_the_new_event(
    step: StepLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lab = step.life
    original = TotpAuthenticator.consume_in

    def expire(
        self: TotpAuthenticator,
        session: AsyncSession,
        proof: tuple[TotpCredentialRow, int],
        event_id: str,
        code: SecretStr,
    ) -> None:
        lab.clock.value += 90
        original(self, session, proof, event_id, code)

    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        form = await begin(step, browser)
        old = cookie(browser, ServiceId.IDP)
        monkeypatch.setattr(TotpAuthenticator, "consume_in", expire)
        response = await submit(step, browser, form)
        assert response.status_code == HTTPStatus.FORBIDDEN
        assert not await consumptions(step) and cookie(browser, ServiceId.IDP) == old


async def test_unmet_noninteractive_and_unsupported_assurance_never_issue_a_code(
    step: StepLab,
) -> None:
    lab = step.life
    async with lab.client() as browser:
        await lab.login(browser)
        transaction = lab.sp().oidc.begin(acr_values=Assurance.PASSWORD_TOTP)
        values = {
            name: value[0]
            for name, value in parse_qs(urlsplit(transaction.authorization_url).query).items()
        }
        values["prompt"] = "none"
        response = await browser.get(f"{lab.stack.issuer}/authorize?{urlencode(values)}")
        assert (
            "error=login_required" in response.headers["location"]
            and "code=" not in response.headers["location"]
        )
        values["acr_values"] = "urn:attacker:acr:administrator"
        rejected = await browser.get(f"{lab.stack.issuer}/authorize?{urlencode(values)}")
        assert (
            "error=invalid_request" in rejected.headers["location"]
            and "code=" not in rejected.headers["location"]
        )
