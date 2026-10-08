"""Phase 8 wire, durability and race checks share one TLS PostgreSQL runtime and clock."""

import asyncio
import json
import secrets
from collections.abc import AsyncIterator
from http import HTTPStatus
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx2 as httpx
import pytest
import pytest_asyncio
from joserfc import jwt
from pydantic import SecretStr
from sqlalchemy import event, func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from federated_identity.common.persistence.sessions import BrowserSessionRow
from federated_identity.common.security.contracts import GrantStatus, LogoutDelivery
from federated_identity.common.security.logout import (
    LOGOUT_EVENT,
    LogoutClaims,
    sign_logout_token,
    validate_logout_token,
)
from federated_identity.common.security.model import KeyState, SecurityDenied
from federated_identity.common.security.oidc import VerifiedRefresh
from federated_identity.common.settings.policy import verifier_digest
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.repositories.outbox import LogoutOutboxRow
from federated_identity.idp.repositories.security import SecurityUnitOfWork
from federated_identity.idp.repositories.security_tables import IdpSessionRow, SigningTrustRow
from federated_identity.idp.repositories.signing import SignedArtifactRow
from federated_identity.idp.repositories.tables import ClientRow
from federated_identity.idp.schemas.signing import SignedArtifactPurpose
from federated_identity.idp.services.security_model import IdpSecurityModel
from federated_identity.sp.repositories.logout import LogoutReceiptRow, LogoutSessionRow
from federated_identity.sp.repositories.security import SpSecurityRepository
from federated_identity.sp.repositories.security_tables import SpAuthenticationRow
from federated_identity.sp.services.renewal import RefreshAttempt, SpRenewalService
from tests.integration.test_signing_rotation import operator
from tests.lifecycle_helpers import LifecycleLab, action_challenge, lifecycle_lab, next_scenario

pytestmark = [pytest.mark.integration, pytest.mark.asyncio(loop_scope="module")]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def logout_runtime() -> AsyncIterator[LifecycleLab]:
    async with lifecycle_lab() as lab:
        yield lab


@pytest_asyncio.fixture(loop_scope="module")
async def logout_lab(logout_runtime: LifecycleLab) -> LifecycleLab:
    next_scenario(logout_runtime)
    return logout_runtime


def cookie(browser: httpx.AsyncClient, service: ServiceId = ServiceId.SP_A) -> SecretStr:
    value = browser.cookies.get(f"__Host-fid-{service.value}")
    assert isinstance(value, str)
    return SecretStr(value)


async def start_global(lab: LifecycleLab, browser: httpx.AsyncClient) -> httpx.Response:
    form = await browser.get(f"{lab.stack.origin(ServiceId.SP_A)}/auth/logout/global")
    result = await lab.post_action(
        browser, ServiceId.SP_A, "/auth/logout/global", action_challenge(form)
    )
    assert result.status_code == HTTPStatus.SEE_OTHER
    return result


async def deliveries(lab: LifecycleLab, sid: str) -> list[LogoutOutboxRow]:
    async with lab.idp().oidc.database.sessions() as session:
        return list(
            await session.scalars(
                select(LogoutOutboxRow)
                .where(LogoutOutboxRow.session_id == sid)
                .order_by(LogoutOutboxRow.client_id)
            )
        )


def stored_token(lab: LifecycleLab, row: LogoutOutboxRow) -> str:
    payload = lab.assets[ServiceId.IDP].envelope.decrypt(
        row.encrypted_payload, purpose="logout-delivery"
    )
    token = payload.get("token")
    assert isinstance(token, str)
    return token


async def mint_logout(
    lab: LifecycleLab, sid: str, *, client: str = "sp-a", committed: bool = False
) -> str:
    if committed:
        await lab.idp().security.end_session(sid)
        row = next(row for row in await deliveries(lab, sid) if row.client_id == client)
        claim = await lab.idp().logout_dispatcher.claim(row.delivery_id)
        assert claim is not None
        return claim.delivery.token.get_secret_value()
    async with lab.idp().security.repository.transaction() as work:
        signer = await lab.idp().oidc.keys.active_in(work)
    return sign_logout_token(
        LogoutClaims(
            iss=lab.stack.issuer,
            aud=client,
            sid=sid,
            sub=lab.user.subject,
            iat=lab.clock.now(),
            exp=lab.clock.now() + 300,
            jti=secrets.token_urlsafe(24),
            events={LOGOUT_EVENT: {}},
        ),
        signer,
    )


async def receipt_count(lab: LifecycleLab, sid: str, service: ServiceId = ServiceId.SP_A) -> int:
    async with lab.sp(service).database.sessions() as session:
        return int(
            await session.scalar(
                select(func.count())
                .select_from(LogoutReceiptRow)
                .where(LogoutReceiptRow.session_id == sid)
            )
            or 0
        )


async def test_global_logout_matches_sid_ends_both_sps_and_preserves_another_browser(
    logout_lab: LifecycleLab,
) -> None:
    lab = logout_lab
    async with lab.client() as browser, lab.client() as other:
        await lab.login(browser)
        await lab.sign_in(browser)
        await lab.sign_in(browser, ServiceId.SP_B)
        await lab.login(other)
        await lab.sign_in(other)
        sid = (await lab.account(browser)).json()["sid"]
        other_sid = (await lab.account(other)).json()["sid"]
        assert sid != other_sid
        captured = {
            service: cookie(browser, service)
            for service in (ServiceId.IDP, ServiceId.SP_A, ServiceId.SP_B)
        }
        start = await start_global(lab, browser)
        form = await browser.get(start.headers["location"])
        for service in (ServiceId.IDP, ServiceId.SP_A, ServiceId.SP_B):
            assert (await lab.account(browser, service)).status_code == HTTPStatus.OK
        assert not await deliveries(lab, sid)
        completed = await lab.post_action(
            browser, ServiceId.IDP, "/end-session/confirm", action_challenge(form)
        )
        assert completed.status_code == HTTPStatus.SEE_OTHER
        assert completed.headers["location"] == f"{lab.stack.origin(ServiceId.SP_A)}/"
        assert browser.cookies.get("__Host-fid-idp") is None
        for service in (ServiceId.IDP, ServiceId.SP_A, ServiceId.SP_B):
            response = await browser.get(
                f"{lab.stack.origin(service)}/account",
                headers={
                    "Cookie": f"__Host-fid-{service.value}={captured[service].get_secret_value()}"
                },
            )
            assert response.status_code == HTTPStatus.UNAUTHORIZED
        rows = await deliveries(lab, sid)
        assert len(rows) == 2 and all(
            row.status == "delivered" and row.attempts == 1 for row in rows
        )
        for service in (ServiceId.SP_A, ServiceId.SP_B):
            assert await receipt_count(lab, sid, service) == 1
            async with lab.sp(service).database.sessions() as session:
                local = await session.get(
                    SpAuthenticationRow, verifier_digest(captured[service].get_secret_value())
                )
                binding = await session.get(
                    BrowserSessionRow, verifier_digest(captured[service].get_secret_value())
                )
                assert local is not None and local.revoked_at == lab.clock.now()
                assert binding is not None and binding.expires_at <= lab.clock.now()
        async with lab.idp().oidc.database.sessions() as session:
            for row in rows:
                artifact = await session.get(SignedArtifactRow, row.token_id)
                assert (
                    artifact is not None
                    and artifact.purpose == SignedArtifactPurpose.LOGOUT_TOKEN.value
                )
                assert (
                    artifact.client_id == row.client_id
                    and artifact.expires_at == row.token_expires_at
                )
                assert stored_token(lab, row).encode() not in row.encrypted_payload
        assert (await lab.account(other)).status_code == HTTPStatus.OK
        assert (await lab.account(other, ServiceId.IDP)).status_code == HTTPStatus.OK
        await browser.get(completed.headers["location"])
        assert cookie(browser).get_secret_value() != captured[ServiceId.SP_A].get_secret_value()


@pytest.mark.parametrize("method", ["GET", "POST"])
async def test_no_hint_requests_confirm_current_browser_and_echo_state_after_exact_redirect(
    logout_lab: LifecycleLab,
    method: str,
) -> None:
    lab = logout_lab
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        parameters = {
            "client_id": "sp-a",
            "post_logout_redirect_uri": f"{lab.stack.origin(ServiceId.SP_A)}/",
            "state": "opaque state & https://attacker.example/",
            "ui_locales": "en fr",
        }
        if method == "GET":
            form = await browser.get(f"{lab.stack.issuer}/end-session", params=parameters)
        else:
            form = await browser.post(f"{lab.stack.issuer}/end-session", data=parameters)
        assert form.status_code == HTTPStatus.OK
        assert (await lab.account(browser)).status_code == HTTPStatus.OK
        result = await lab.post_action(
            browser, ServiceId.IDP, "/end-session/confirm", action_challenge(form)
        )
        location = urlsplit(result.headers["location"])
        assert (
            f"{location.scheme}://{location.netloc}{location.path}"
            == parameters["post_logout_redirect_uri"]
        )
        assert parse_qs(location.query) == {"state": [parameters["state"]]}


@pytest.mark.parametrize("service", [ServiceId.SP_A, ServiceId.IDP])
@pytest.mark.parametrize(
    "attack", ["missing", "foreign_origin", "other_browser", "expired", "wrong_purpose"]
)
async def test_global_logout_intent_is_browser_origin_purpose_and_expiry_bound(
    logout_lab: LifecycleLab,
    service: ServiceId,
    attack: str,
) -> None:
    lab = logout_lab
    async with lab.client() as browser, lab.client() as other:
        await lab.login(browser)
        await lab.sign_in(browser)
        if service == ServiceId.IDP:
            start = await start_global(lab, browser)
            form = await browser.get(start.headers["location"])
            path = "/end-session/confirm"
        else:
            form = await browser.get(f"{lab.stack.origin(service)}/auth/logout/global")
            path = "/auth/logout/global"
        data = {"csrf": action_challenge(form)}
        headers = {
            "Origin": lab.stack.origin(service),
            "Content-Type": "application/x-www-form-urlencoded",
        }
        target = browser
        if attack == "missing":
            data = {}
        elif attack == "foreign_origin":
            headers["Origin"] = "https://attacker.example"
        elif attack == "other_browser":
            await lab.login(other)
            await lab.sign_in(other)
            target = other
        elif attack == "expired":
            lab.clock.value += 300
        else:
            path = "/logout" if service == ServiceId.IDP else "/auth/logout"
        rejected = await target.post(
            f"{lab.stack.origin(service)}{path}", headers=headers, data=data
        )
        assert rejected.status_code == HTTPStatus.FORBIDDEN and "set-cookie" not in rejected.headers
        assert (await lab.account(browser, ServiceId.IDP)).status_code == HTTPStatus.OK
        assert (await lab.account(browser)).status_code == HTTPStatus.OK


@pytest.mark.parametrize(
    "attack",
    [
        "foreign_redirect",
        "redirect_suffix",
        "http_redirect",
        "relative_redirect",
        "client_mismatch",
        "unregistered_client",
        "forged_hint",
        "unissued_hint",
        "logout_as_hint",
        "duplicate",
    ],
)
async def test_initial_logout_rejects_untrusted_hints_and_redirects_without_side_effects(
    logout_lab: LifecycleLab,
    attack: str,
) -> None:
    lab = logout_lab
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        start = await start_global(lab, browser)
        parameters = {
            name: values[0]
            for name, values in parse_qs(urlsplit(start.headers["location"]).query).items()
        }
        if attack == "foreign_redirect":
            parameters["post_logout_redirect_uri"] = "https://attacker.example/"
        elif attack == "redirect_suffix":
            parameters["post_logout_redirect_uri"] += "auth/callback"
        elif attack == "http_redirect":
            parameters["post_logout_redirect_uri"] = parameters["post_logout_redirect_uri"].replace(
                "https:", "http:"
            )
        elif attack == "relative_redirect":
            parameters["post_logout_redirect_uri"] = "//attacker.example/"
        elif attack in {"client_mismatch", "unregistered_client"}:
            parameters["client_id"] = "sp-b" if attack == "client_mismatch" else "unknown-sp"
        elif attack in {"forged_hint", "unissued_hint"}:
            async with lab.idp().security.repository.transaction() as work:
                signer = await lab.idp().oidc.keys.active_in(work)
            original = jwt.decode(parameters["id_token_hint"], signer.key, algorithms=["RS256"])
            claims = dict(original.claims)
            claims["jti"] = secrets.token_urlsafe(24)
            key = lab.assets[ServiceId.SP_A].signer if attack == "forged_hint" else signer
            parameters["id_token_hint"] = jwt.encode(
                original.header, claims, key.key, algorithms=["RS256"]
            )
        elif attack == "logout_as_hint":
            parameters["id_token_hint"] = await mint_logout(
                lab, (await lab.account(browser)).json()["sid"]
            )
        url = f"{lab.stack.issuer}/end-session?{urlencode(parameters)}"
        if attack == "duplicate":
            url += "&client_id=sp-a"
        response = await browser.get(url)
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert "location" not in response.headers and "set-cookie" not in response.headers
        assert (await lab.account(browser)).status_code == HTTPStatus.OK
        assert (await lab.account(browser, ServiceId.IDP)).status_code == HTTPStatus.OK


async def test_hint_browser_binding_login_rejection_and_idempotent_completed_logout(
    logout_lab: LifecycleLab,
) -> None:
    lab = logout_lab
    async with lab.client() as owner, lab.client() as other, lab.client() as anonymous:
        await lab.login(owner)
        await lab.sign_in(owner)
        await lab.login(other)
        start = await start_global(lab, owner)
        location = start.headers["location"]
        for target in (other, anonymous):
            response = await target.get(location)
            assert (
                response.status_code == HTTPStatus.FORBIDDEN
                and "set-cookie" not in response.headers
            )
        hint = parse_qs(urlsplit(location).query)["id_token_hint"][0]
        for path in ("/account", "/admin/api/clients"):
            response = await anonymous.get(
                f"{lab.stack.issuer}{path}", headers={"Authorization": f"Bearer {hint}"}
            )
            assert response.status_code == HTTPStatus.UNAUTHORIZED
        form = await owner.get(location)
        completed = await lab.post_action(
            owner, ServiceId.IDP, "/end-session/confirm", action_challenge(form)
        )
        assert completed.status_code == HTTPStatus.SEE_OTHER
        repeated = await owner.get(location)
        assert repeated.status_code == HTTPStatus.SEE_OTHER
        assert repeated.headers["location"] == completed.headers["location"]
        await lab.login(owner)
        assert (await owner.get(location)).status_code == HTTPStatus.FORBIDDEN
        assert (await lab.account(owner, ServiceId.IDP)).status_code == HTTPStatus.OK
        assert (await lab.account(other, ServiceId.IDP)).status_code == HTTPStatus.OK


async def test_expired_hint_under_retired_routine_signer_still_requires_matching_confirmation(
    logout_lab: LifecycleLab,
) -> None:
    lab = logout_lab
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        start = await start_global(lab, browser)
        old_key = await lab.sp().security.repository.load(cookie(browser))
        assert old_key is not None
        admin = await operator(lab)
        replacement = await admin.prepare_key()
        await admin.activate_key(replacement.key_id, old_key[0].signing_key_id)
        lab.clock.value += 305
        await lab.idp().security.retire_trust(old_key[0].signing_key_id)
        form = await browser.get(start.headers["location"])
        assert form.status_code == HTTPStatus.OK
        assert (await lab.account(browser, ServiceId.IDP)).status_code == HTTPStatus.OK
        assert (
            await lab.post_action(
                browser, ServiceId.IDP, "/end-session/confirm", action_challenge(form)
            )
        ).status_code == HTTPStatus.SEE_OTHER
        assert (await lab.account(browser)).status_code == HTTPStatus.UNAUTHORIZED
        await admin.logout()


@pytest.mark.parametrize(
    "attack", ["wrong_audience", "expired", "forged", "id_token", "subject_mismatch"]
)
async def test_invalid_backchannel_never_reserves_replay_or_terminates_a_session(
    logout_lab: LifecycleLab,
    attack: str,
) -> None:
    lab = logout_lab
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        sid = (await lab.account(browser)).json()["sid"]
        valid = await mint_logout(lab, sid, committed=True)
        async with lab.idp().security.repository.transaction() as work:
            signer = await lab.idp().oidc.keys.active_in(work)
        original = jwt.decode(valid, signer.key, algorithms=["RS256"])
        claims = dict(original.claims)
        if attack == "wrong_audience":
            claims["aud"] = "sp-b"
        elif attack == "expired":
            claims.update(iat=lab.clock.now() - 300, exp=lab.clock.now() - 5)
        elif attack == "subject_mismatch":
            claims["sub"] = "user:other"
        invalid = jwt.encode(
            original.header,
            claims,
            (lab.assets[ServiceId.SP_A].signer.key if attack == "forged" else signer.key),
            algorithms=["RS256"],
        )
        if attack == "id_token":
            start = await start_global(lab, browser)
            invalid = parse_qs(urlsplit(start.headers["location"]).query)["id_token_hint"][0]
        endpoint = f"{lab.stack.origin(ServiceId.SP_A)}/backchannel-logout"
        rejected = await browser.post(endpoint, data={"logout_token": invalid})
        assert (
            rejected.status_code == HTTPStatus.BAD_REQUEST
            and rejected.headers["cache-control"] == "no-store"
        )
        assert await receipt_count(lab, sid) == 0
        local = await lab.sp().security.repository.load(cookie(browser))
        assert local is not None and local[0].revoked_at is None
        accepted = await browser.post(
            endpoint, data={"logout_token": valid, "ignored_extension": "value"}
        )
        assert accepted.status_code == HTTPStatus.OK and not accepted.content
        assert await receipt_count(lab, sid) == 1
        assert (await lab.account(browser)).status_code == HTTPStatus.UNAUTHORIZED


async def test_backchannel_replay_is_atomic_and_cannot_change_the_same_jti_context(
    logout_lab: LifecycleLab,
) -> None:
    lab = logout_lab
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        sid = (await lab.account(browser)).json()["sid"]
        token = await mint_logout(lab, sid, committed=True)
        endpoint = f"{lab.stack.origin(ServiceId.SP_A)}/backchannel-logout"
        results = await asyncio.gather(
            *(browser.post(endpoint, data={"logout_token": token}) for _ in range(8))
        )
        assert all(result.status_code == HTTPStatus.OK for result in results)
        assert await receipt_count(lab, sid) == 1
        async with lab.idp().security.repository.transaction() as work:
            signer = await lab.idp().oidc.keys.active_in(work)
        decoded = jwt.decode(token, signer.key, algorithms=["RS256"])
        altered = jwt.encode(
            decoded.header,
            {**decoded.claims, "sid": "different-session"},
            signer.key,
            algorithms=["RS256"],
        )
        assert (
            await browser.post(endpoint, data={"logout_token": altered})
        ).status_code == HTTPStatus.BAD_REQUEST
        await lab.restart(ServiceId.SP_A)
        assert (
            await browser.post(endpoint, data={"logout_token": token})
        ).status_code == HTTPStatus.OK
        assert await receipt_count(lab, sid) == 1
        with pytest.raises(DBAPIError, match="immutable"):
            async with lab.sp().database.engine.begin() as connection:
                await connection.execute(
                    text("DELETE FROM sp_logout_receipts WHERE session_id=:sid"), {"sid": sid}
                )


async def test_unavailable_sp_denies_old_cookie_before_retry_and_restart_recovers_delivery(
    logout_lab: LifecycleLab,
) -> None:
    lab = logout_lab
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        await lab.sign_in(browser, ServiceId.SP_B)
        sid = (await lab.account(browser)).json()["sid"]
        old_b = cookie(browser, ServiceId.SP_B)
        lab.transport.unavailable.add(ServiceId.SP_B.hostname)
        start = await start_global(lab, browser)
        form = await browser.get(start.headers["location"])
        result = await lab.post_action(
            browser, ServiceId.IDP, "/end-session/confirm", action_challenge(form)
        )
        assert result.status_code == HTTPStatus.SEE_OTHER
        rows = await deliveries(lab, sid)
        a, b = rows
        assert a.status == "delivered" and b.status == "pending" and b.attempts == 1
        first_token = stored_token(lab, b)
        async with lab.sp(ServiceId.SP_B).database.sessions() as session:
            local = await session.get(
                SpAuthenticationRow, verifier_digest(old_b.get_secret_value())
            )
            assert local is not None and local.revoked_at is None
        lab.transport.unavailable.clear()
        assert (await lab.account(browser, ServiceId.SP_B)).status_code == HTTPStatus.UNAUTHORIZED
        await lab.login(browser)
        await lab.sign_in(browser)
        new_a = cookie(browser)
        assert (await lab.account(browser)).json()["sid"] != sid
        await lab.restart(ServiceId.IDP)
        lab.clock.value = b.next_attempt_at
        assert await lab.idp().logout_dispatcher.dispatch_once(session_id=sid) == 1
        recovered = (await deliveries(lab, sid))[1]
        assert recovered.status == "delivered" and recovered.attempts == 2
        assert stored_token(lab, recovered) == first_token
        assert (
            cookie(browser) == new_a and (await lab.account(browser)).status_code == HTTPStatus.OK
        )
        duplicate = await browser.post(
            f"{lab.stack.origin(ServiceId.SP_A)}/backchannel-logout",
            data={"logout_token": stored_token(lab, a)},
        )
        assert (
            duplicate.status_code == HTTPStatus.OK
            and (await lab.account(browser)).status_code == HTTPStatus.OK
        )
        assert await receipt_count(lab, sid, ServiceId.SP_B) == 1


async def test_lost_ack_restart_and_stale_worker_are_fenced_while_exact_retry_is_idempotent(
    logout_lab: LifecycleLab,
) -> None:
    lab = logout_lab
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        sid = (await lab.account(browser)).json()["sid"]
        await lab.idp().security.end_session(sid)
        row = (await deliveries(lab, sid))[0]
        first = await lab.idp().logout_dispatcher.claim(row.delivery_id)
        assert first is not None
        assert await lab.idp().logout_transport.deliver(first.delivery)
        await lab.login(browser)
        await lab.sign_in(browser)
        new_sid = (await lab.account(browser)).json()["sid"]
        await lab.restart(ServiceId.IDP)
        dispatcher = lab.idp().logout_dispatcher
        assert await dispatcher.dispatch_once(session_id=sid) == 0
        lab.clock.value += int(dispatcher.settings.logout_delivery_timeout_seconds) + 5
        second = await dispatcher.claim(row.delivery_id)
        assert second is not None and second.lease_id != first.lease_id
        assert second.delivery.token == first.delivery.token
        await dispatcher.finish(first, delivered=True, retryable=False, error=None)
        pending = (await deliveries(lab, sid))[0]
        assert pending.status == "pending" and pending.lease_id == second.lease_id
        assert await dispatcher.transport.deliver(second.delivery)
        await dispatcher.finish(second, delivered=True, retryable=False, error=None)
        assert (await deliveries(lab, sid))[0].status == "delivered"
        assert await receipt_count(lab, sid) == 1
        assert (await lab.account(browser)).json()["sid"] == new_sid != sid
        with pytest.raises(ValueError, match="failed or skipped"):
            await lab.idp().logout_outbox.retry(row.delivery_id)
        with pytest.raises(DBAPIError, match="terminal"):
            async with lab.idp().oidc.database.engine.begin() as connection:
                await connection.execute(
                    text("UPDATE logout_outbox SET status='pending' WHERE delivery_id=:id"),
                    {"id": row.delivery_id},
                )


@pytest.mark.parametrize("failure", ["unavailable", "rejected", "cancelled"])
async def test_delivery_budget_permanent_rejection_and_cancellation_preserve_owner_recovery(
    logout_lab: LifecycleLab,
    failure: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lab = logout_lab
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        sid = (await lab.account(browser)).json()["sid"]
        await lab.idp().security.end_session(sid)
        row = (await deliveries(lab, sid))[0]
        dispatcher = lab.idp().logout_dispatcher
        original = dispatcher.transport
        entered, release = asyncio.Event(), asyncio.Event()

        class FailingTransport:
            async def deliver(self, delivery: LogoutDelivery) -> bool:
                entered.set()
                if failure == "cancelled":
                    await release.wait()
                request = httpx.Request("POST", delivery.destination)
                response = httpx.Response(503 if failure == "unavailable" else 400, request=request)
                response.raise_for_status()
                return False

        monkeypatch.setattr(
            dispatcher,
            "settings",
            dispatcher.settings.model_copy(update={"logout_max_attempts": 2}),
        )
        monkeypatch.setattr(dispatcher, "transport", FailingTransport())
        if failure == "cancelled":
            pending = asyncio.create_task(dispatcher.deliver_one(row.delivery_id))
            await asyncio.wait_for(entered.wait(), timeout=3)
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await pending
            state = (await deliveries(lab, sid))[0]
            assert state.status == "pending" and state.lease_expires_at is not None
            lab.clock.value = state.lease_expires_at
            monkeypatch.setattr(dispatcher, "transport", original)
            assert await dispatcher.dispatch_once(session_id=sid) == 1
        else:
            assert await dispatcher.dispatch_once(session_id=sid) == 1
            state = (await deliveries(lab, sid))[0]
            if failure == "unavailable":
                assert state.status == "pending" and state.next_attempt_at == lab.clock.now() + 2
                assert await dispatcher.dispatch_once(session_id=sid) == 0
                lab.clock.value = state.next_attempt_at
                assert await dispatcher.dispatch_once(session_id=sid) == 1
                state = (await deliveries(lab, sid))[0]
            assert state.status == "failed"
            assert state.attempts == (2 if failure == "unavailable" else 1)
            assert (await lab.account(browser)).status_code == HTTPStatus.UNAUTHORIZED
            assert await dispatcher.dispatch_once(session_id=sid) == 0
            await lab.idp().logout_outbox.retry(row.delivery_id)
            monkeypatch.setattr(dispatcher, "transport", original)
            assert await dispatcher.dispatch_once(session_id=sid) == 1
        assert (await deliveries(lab, sid))[0].status == "delivered"
        summary = json.dumps(
            [entry.model_dump() for entry in await lab.idp().logout_outbox.inspect()]
        )
        assert stored_token(lab, (await deliveries(lab, sid))[0]) not in summary


async def test_delivery_rejects_obsolete_destination_and_recovery_adopts_live_metadata(
    logout_lab: LifecycleLab,
) -> None:
    lab = logout_lab
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        sid = (await lab.account(browser)).json()["sid"]
        await lab.idp().security.end_session(sid)
        row = (await deliveries(lab, sid))[0]
        async with lab.idp().security.repository.transaction() as work:
            client = await work.get(ClientRow, "sp-a")
            assert client is not None
            client.backchannel_logout_uri = (
                f"{lab.stack.origin(ServiceId.SP_A)}/new-backchannel-logout"
            )
        assert await lab.idp().logout_dispatcher.dispatch_once(session_id=sid) == 0
        state = (await deliveries(lab, sid))[0]
        assert (
            state.status == "failed"
            and state.last_error == "destination_changed"
            and state.attempts == 0
        )
        await lab.idp().logout_outbox.retry(row.delivery_id)
        assert (await deliveries(lab, sid))[0].destination != row.destination
        await lab.idp().logout_dispatcher.dispatch_once(session_id=sid)
        assert (await deliveries(lab, sid))[0].last_error == "recipient_rejected"
        async with lab.idp().security.repository.transaction() as work:
            client = await work.get(ClientRow, "sp-a")
            assert client is not None
            client.backchannel_logout_uri = row.destination
        await lab.idp().logout_outbox.retry(row.delivery_id)
        await lab.idp().logout_dispatcher.dispatch_once(session_id=sid)
        assert (await deliveries(lab, sid))[0].status == "delivered"


async def test_logout_signing_retention_and_expired_retry_use_live_rotated_trust(
    logout_lab: LifecycleLab,
) -> None:
    lab = logout_lab
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        await lab.sign_in(browser, ServiceId.SP_B)
        sid = (await lab.account(browser)).json()["sid"]
        lab.clock.value += 20
        await lab.idp().security.end_session(sid)
        a, b = await deliveries(lab, sid)
        first_a = await lab.idp().logout_dispatcher.claim(a.delivery_id)
        first_b = await lab.idp().logout_dispatcher.claim(b.delivery_id)
        assert first_a is not None and first_b is not None
        a, b = await deliveries(lab, sid)
        old_key = a.signing_key_id
        assert old_key is not None and a.token_expires_at is not None
        admin = await operator(lab)
        replacement = await admin.prepare_key()
        await admin.activate_key(replacement.key_id, old_key)
        lab.clock.value = a.token_expires_at - 1
        with pytest.raises(SecurityDenied):
            await lab.idp().security.retire_trust(old_key)
        assert await lab.idp().logout_transport.deliver(first_a.delivery)
        await lab.idp().logout_dispatcher.finish(
            first_a, delivered=True, retryable=False, error=None
        )
        lab.clock.value = a.token_expires_at + 5
        await lab.idp().security.retire_trust(old_key)
        second_b = await lab.idp().logout_dispatcher.claim(b.delivery_id)
        assert second_b is not None and second_b.delivery.token != first_b.delivery.token
        renewed = (await deliveries(lab, sid))[1]
        assert renewed.signing_key_id == replacement.key_id and renewed.token_id != b.token_id
        assert await lab.idp().logout_transport.deliver(second_b.delivery)
        await lab.idp().logout_dispatcher.finish(
            second_b, delivered=True, retryable=False, error=None
        )
        async with lab.idp().oidc.database.sessions() as session:
            key = await session.get(SigningTrustRow, replacement.key_id)
            assert key is not None and key.verification_deadline >= (renewed.token_expires_at or 0)
            old = await session.get(SigningTrustRow, old_key)
            assert old is not None and old.state == KeyState.RETIRED.value
        await admin.logout()


async def test_backchannel_commit_failure_preserves_receipt_session_and_pending_callback(
    logout_lab: LifecycleLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lab = logout_lab
    original = SpSecurityRepository.revoke_digest_in

    async def mark(
        self: SpSecurityRepository, session: AsyncSession, digest: str, *, now: int
    ) -> None:
        await original(self, session, digest, now=now)
        session.info["fail_backchannel_commit"] = True

    def fail(session: Session) -> None:
        if session.info.get("fail_backchannel_commit"):
            raise RuntimeError("Injected back-channel commit failure")

    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        sid = (await lab.account(browser)).json()["sid"]
        start = await browser.get(f"{lab.stack.origin(ServiceId.SP_A)}/auth/login")
        callback = (await browser.get(start.headers["location"])).headers["location"]
        token = await mint_logout(lab, sid, committed=True)
        endpoint = f"{lab.stack.origin(ServiceId.SP_A)}/backchannel-logout"
        event.listen(Session, "before_commit", fail)
        try:
            with monkeypatch.context() as patch:
                patch.setattr(SpSecurityRepository, "revoke_digest_in", mark)
                with pytest.raises(RuntimeError, match="Injected back-channel"):
                    await browser.post(endpoint, data={"logout_token": token})
        finally:
            event.remove(Session, "before_commit", fail)
        assert await receipt_count(lab, sid) == 0
        local = await lab.sp().security.repository.load(cookie(browser))
        assert local is not None and local[0].revoked_at is None
        async with lab.sp().database.sessions() as session:
            assert await session.get(LogoutSessionRow, (lab.stack.issuer, sid)) is None
        assert (
            await browser.post(endpoint, data={"logout_token": token})
        ).status_code == HTTPStatus.OK
        assert (await browser.get(callback)).status_code == HTTPStatus.BAD_REQUEST


async def test_logout_confirmation_commit_failure_preserves_all_authority_and_the_intent(
    logout_lab: LifecycleLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lab = logout_lab
    original = IdpSecurityModel.end_session_in

    async def mark(self: IdpSecurityModel, work: SecurityUnitOfWork, session_id: str) -> None:
        await original(self, work, session_id)
        work.session.info["fail_global_commit"] = True

    def fail(session: Session) -> None:
        if session.info.get("fail_global_commit"):
            raise RuntimeError("Injected global commit failure")

    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        sid = (await lab.account(browser)).json()["sid"]
        start = await start_global(lab, browser)
        form = await browser.get(start.headers["location"])
        challenge = action_challenge(form)
        captured = cookie(browser, ServiceId.IDP)
        event.listen(Session, "before_commit", fail)
        try:
            with monkeypatch.context() as patch:
                patch.setattr(IdpSecurityModel, "end_session_in", mark)
                with pytest.raises(RuntimeError, match="Injected global"):
                    await lab.post_action(browser, ServiceId.IDP, "/end-session/confirm", challenge)
        finally:
            event.remove(Session, "before_commit", fail)
        assert not await deliveries(lab, sid)
        assert cookie(browser, ServiceId.IDP) == captured
        assert (await lab.account(browser)).status_code == HTTPStatus.OK
        assert (
            await lab.post_action(browser, ServiceId.IDP, "/end-session/confirm", challenge)
        ).status_code == HTTPStatus.SEE_OTHER


async def test_notification_before_callback_installation_fences_a_previously_authorized_response(
    logout_lab: LifecycleLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lab = logout_lab
    entered, release = asyncio.Event(), asyncio.Event()
    original = lab.sp().security.checker

    class PausedChecker:
        async def check(self, token: SecretStr) -> GrantStatus:
            result = await original.check(token)
            entered.set()
            await release.wait()
            return result

    async with lab.client() as browser:
        await lab.login(browser)
        sid = (await lab.account(browser, ServiceId.IDP)).json()["sid"]
        start = await browser.get(f"{lab.stack.origin(ServiceId.SP_A)}/auth/login")
        callback = (await browser.get(start.headers["location"])).headers["location"]
        monkeypatch.setattr(lab.sp().security, "checker", PausedChecker())
        pending = asyncio.create_task(browser.get(callback))
        try:
            await asyncio.wait_for(entered.wait(), timeout=3)
            await lab.idp().security.end_session(sid)
            assert await lab.idp().logout_dispatcher.dispatch_once(session_id=sid) == 1
        finally:
            release.set()
        result = await asyncio.wait_for(pending, timeout=3)
        assert result.status_code == HTTPStatus.BAD_REQUEST and "set-cookie" not in result.headers
        async with lab.sp().database.sessions() as session:
            assert await session.get(LogoutSessionRow, (lab.stack.issuer, sid)) is not None
            assert not list(
                await session.scalars(
                    select(SpAuthenticationRow).where(SpAuthenticationRow.session_id == sid)
                )
            )


async def test_notification_racing_verified_refresh_prevents_installation_without_network_locks(
    logout_lab: LifecycleLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lab = logout_lab
    entered, release = asyncio.Event(), asyncio.Event()
    original = SpRenewalService.finish

    async def pause(
        self: SpRenewalService, attempt: RefreshAttempt, refreshed: VerifiedRefresh
    ) -> SecretStr:
        entered.set()
        await release.wait()
        return await original(self, attempt, refreshed)

    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        sid = (await lab.account(browser)).json()["sid"]
        captured = cookie(browser)
        monkeypatch.setattr(SpRenewalService, "finish", pause)
        lab.clock.value += 301
        pending = asyncio.create_task(lab.account(browser))
        try:
            await asyncio.wait_for(entered.wait(), timeout=3)
            await lab.idp().security.end_session(sid)
            await asyncio.wait_for(
                lab.idp().logout_dispatcher.dispatch_once(session_id=sid), timeout=3
            )
        finally:
            release.set()
        assert (await asyncio.wait_for(pending, timeout=3)).status_code == HTTPStatus.UNAUTHORIZED
        async with lab.sp().database.sessions() as session:
            row = await session.get(
                SpAuthenticationRow, verifier_digest(captured.get_secret_value())
            )
            assert row is not None and row.revoked_at is not None and row.refresh_generation == 0
        async with lab.idp().oidc.database.sessions() as session:
            parent = await session.get(IdpSessionRow, sid)
            assert parent is not None and parent.revoked_at is not None


async def test_concurrent_confirmation_consumes_one_intent_and_enqueues_one_delivery(
    logout_lab: LifecycleLab,
) -> None:
    lab = logout_lab
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        sid = (await lab.account(browser)).json()["sid"]
        start = await start_global(lab, browser)
        form = await browser.get(start.headers["location"])
        challenge = action_challenge(form)
        original_cookie = cookie(browser, ServiceId.IDP)
        results = await asyncio.gather(
            *(
                browser.post(
                    f"{lab.stack.issuer}/end-session/confirm",
                    headers={
                        "Origin": lab.stack.issuer,
                        "Cookie": f"__Host-fid-idp={original_cookie.get_secret_value()}",
                    },
                    data={"csrf": challenge},
                )
                for _ in range(4)
            )
        )
        assert sorted(result.status_code for result in results) == [303, 403, 403, 403]
        assert len(await deliveries(lab, sid)) == 1 and await receipt_count(lab, sid) == 1


async def test_signed_delivery_commit_failure_cannot_publish_a_lease_jwt_or_retention(
    logout_lab: LifecycleLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    lab = logout_lab
    original = IdpSecurityModel.record_signed_artifact_in
    calls = 0

    async def mark(
        self: IdpSecurityModel,
        work: SecurityUnitOfWork,
        *,
        artifact_id: str,
        key_id: str,
        purpose: SignedArtifactPurpose,
        client_id: str,
        issued_at: int,
        expires_at: int,
    ) -> None:
        await original(
            self,
            work,
            artifact_id=artifact_id,
            key_id=key_id,
            purpose=purpose,
            client_id=client_id,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        work.session.info["fail_signed_delivery"] = True

    def fail(session: Session) -> None:
        if session.info.get("fail_signed_delivery"):
            raise RuntimeError("Injected signed delivery commit failure")

    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        sid = (await lab.account(browser)).json()["sid"]
        lab.clock.value += 20
        await lab.idp().security.end_session(sid)
        row = (await deliveries(lab, sid))[0]
        dispatcher = lab.idp().logout_dispatcher
        delegate = dispatcher.transport

        class RecordingTransport:
            async def deliver(self, delivery: LogoutDelivery) -> bool:
                nonlocal calls
                calls += 1
                return await delegate.deliver(delivery)

        monkeypatch.setattr(dispatcher, "transport", RecordingTransport())
        async with lab.idp().oidc.database.sessions() as session:
            signer = (
                await session.scalars(
                    select(SigningTrustRow).where(SigningTrustRow.state == "active")
                )
            ).one()
            deadline = signer.verification_deadline
        event.listen(Session, "before_commit", fail)
        try:
            with monkeypatch.context() as patch:
                patch.setattr(IdpSecurityModel, "record_signed_artifact_in", mark)
                with pytest.raises(RuntimeError, match="Injected signed delivery"):
                    await dispatcher.deliver_one(row.delivery_id)
        finally:
            event.remove(Session, "before_commit", fail)
        state = (await deliveries(lab, sid))[0]
        assert (
            state.attempts == 0 and state.lease_id is None and state.token_id is None and calls == 0
        )
        async with lab.idp().oidc.database.sessions() as session:
            key = await session.get(SigningTrustRow, signer.key_id)
            assert key is not None and key.verification_deadline == deadline
        assert await dispatcher.deliver_one(row.delivery_id) and calls == 1


async def test_logout_authority_is_owner_endpoint_and_issuance_bound_despite_cached_keys(
    logout_lab: LifecycleLab,
) -> None:
    lab = logout_lab
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        await lab.sign_in(browser, ServiceId.SP_B)
        sid = (await lab.account(browser)).json()["sid"]
        unissued = await mint_logout(lab, sid)
        endpoint = f"{lab.stack.origin(ServiceId.SP_A)}/backchannel-logout"
        assert (
            await browser.post(endpoint, data={"logout_token": unissued})
        ).status_code == HTTPStatus.BAD_REQUEST
        assert (await lab.account(browser)).status_code == HTTPStatus.OK
        token = await mint_logout(lab, sid, committed=True)
        assert await lab.sp().logout.checker.check_logout(SecretStr(token))
        assert not await lab.sp(ServiceId.SP_B).logout.checker.check_logout(SecretStr(token))
        fields = {
            "token": token,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": lab.assertion(ServiceId.SP_A, "/introspect"),
        }
        rejected = await browser.post(f"{lab.stack.issuer}/logout/introspect", data=fields)
        assert rejected.json()["error"] == "invalid_client"
        fields["client_assertion"] = lab.assertion(ServiceId.SP_A, "/logout/introspect")
        assert (
            await browser.post(f"{lab.stack.issuer}/logout/introspect", data=fields)
        ).json() == {"active": True}
        assert (await browser.post(f"{lab.stack.issuer}/logout/introspect", data=fields)).json()[
            "error"
        ] == "invalid_client"
        cached = await lab.sp().oidc.jwks.get()
        validated = validate_logout_token(
            token, settings=lab.sp().oidc.settings, keys=cached, clock=lab.clock
        )
        admin = await operator(lab)
        replacement = await admin.prepare_key()
        await admin.activate_key(replacement.key_id, validated.header.kid)
        await lab.idp().security.revoke_signer(validated.header.kid)
        # Cryptographic verification with prewarmed trust still succeeds, but the
        # separate authenticated issuance check rejects revoked signing authority.
        validate_logout_token(token, settings=lab.sp().oidc.settings, keys=cached, clock=lab.clock)
        assert (
            await browser.post(endpoint, data={"logout_token": token})
        ).status_code == HTTPStatus.BAD_REQUEST
        assert await receipt_count(lab, sid) == 0
        local = await lab.sp().security.repository.load(cookie(browser))
        assert local is not None and local[0].revoked_at is None
        await admin.logout()
