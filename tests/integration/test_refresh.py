"""Wire refresh and browser renewal share factories, actual TLS PostgreSQL, and injected time."""

import asyncio
from collections.abc import AsyncIterator
from http import HTTPStatus

import httpx2 as httpx
import pytest
import pytest_asyncio
from pydantic import SecretStr
from sqlalchemy import event, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from federated_identity.cli.login_probe import submit_password
from federated_identity.common.security.artifacts import RefreshTokenResponse
from federated_identity.common.security.model import (
    IssuedCredentials,
    LoginEvidence,
    SecurityDenied,
)
from federated_identity.common.security.oidc import VerifiedLogin, validate_refresh_token
from federated_identity.common.settings.policy import verifier_digest
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.repositories.security import SecurityUnitOfWork
from federated_identity.idp.repositories.security_tables import (
    RefreshCredentialRow,
    RefreshIssuanceRow,
)
from federated_identity.idp.repositories.users import UserRow
from federated_identity.idp.services.provisioning import load_seeded_users
from federated_identity.sp.repositories.security_tables import SpAuthenticationRow
from federated_identity.sp.services.renewal import RefreshAttempt, SpRenewalService
from tests.integration.test_containment import operator, recover_client
from tests.lifecycle_helpers import LifecycleLab, action_challenge, lifecycle_lab, next_scenario

pytestmark = [pytest.mark.integration, pytest.mark.asyncio(loop_scope="module")]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def refresh_runtime() -> AsyncIterator[LifecycleLab]:
    async with lifecycle_lab() as lab:
        yield lab


@pytest_asyncio.fixture(loop_scope="module")
async def renewal(refresh_runtime: LifecycleLab) -> LifecycleLab:
    next_scenario(refresh_runtime)
    return refresh_runtime


async def test_protocol_refresh_rotates_and_preserves_exact_authentication_history(
    renewal: LifecycleLab,
) -> None:
    lab = renewal
    async with lab.client() as browser:
        await lab.login(browser)
        transaction = lab.sp().oidc.begin()
        callback = (await browser.get(transaction.authorization_url)).headers["location"]
        original = await lab.sp().oidc.exchange_verified(transaction, callback)
        assert original.response.refresh_token is not None
        lab.clock.value += 301
        response = await browser.post(
            f"{lab.stack.issuer}/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": original.response.refresh_token,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": lab.assertion(ServiceId.SP_A, "/token"),
            },
        )
        assert response.status_code == HTTPStatus.OK
        rotated = RefreshTokenResponse.model_validate(response.json())
        assert rotated.refresh_token != original.response.refresh_token
        verified = validate_refresh_token(
            rotated,
            settings=lab.sp().oidc.settings,
            authentication=original.context.authentication,
            nonce=original.claims.nonce,
            keys=await lab.idp().oidc.keys.public_jwks(),
            clock=lab.clock,
        )
        status = await lab.idp().security.check_access(
            SecretStr(rotated.access_token), authenticated_client="sp-a"
        )
        assert status.active and status.context is not None
        assert status.context.authentication == original.context.authentication
        assert status.credential_evidence == verified.evidence(
            original.context.authentication.event_id
        )
        assert status.context.family.generation == 1
        async with lab.idp().oidc.database.sessions() as session:
            signed = await session.get(RefreshIssuanceRow, verified.claims.jti)
            assert signed is not None and signed.grant_id == original.context.grant.grant_id
            credentials = list(
                await session.scalars(
                    select(RefreshCredentialRow)
                    .where(RefreshCredentialRow.family_id == original.context.family.family_id)
                    .order_by(RefreshCredentialRow.generation)
                )
            )
            assert len(credentials) == 2 and credentials[0].consumed_at == lab.clock.now()
            assert credentials[1].predecessor_digest == credentials[0].token_digest


async def test_expired_access_is_renewed_without_password_or_cookie_rotation(
    renewal: LifecycleLab,
) -> None:
    lab = renewal
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        cookies = {cookie.name: cookie.value for cookie in browser.cookies.jar}
        before = (await lab.account(browser)).json()
        lab.clock.value += 301
        after = await lab.account(browser)
        assert after.status_code == HTTPStatus.OK
        assert after.json()["subject"] == before["subject"]
        assert after.json()["auth_time"] == before["auth_time"]
        assert {cookie.name: cookie.value for cookie in browser.cookies.jar} == cookies


async def issue(lab: LifecycleLab, browser: httpx.AsyncClient) -> VerifiedLogin:
    transaction = lab.sp().oidc.begin()
    callback = (await browser.get(transaction.authorization_url)).headers["location"]
    return await lab.sp().oidc.exchange_verified(transaction, callback)


def refresh_parameters(
    lab: LifecycleLab, token: str, service: ServiceId = ServiceId.SP_A
) -> dict[str, str]:
    return {
        "grant_type": "refresh_token",
        "refresh_token": token,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion": lab.assertion(service, "/token"),
    }


def cookie(browser: httpx.AsyncClient) -> SecretStr:
    value = next(item.value for item in browser.cookies.jar if item.name == "__Host-fid-sp-a")
    assert isinstance(value, str)
    return SecretStr(value)


async def test_wrong_client_reuse_never_changes_the_owners_family(renewal: LifecycleLab) -> None:
    lab = renewal
    async with lab.client() as browser:
        await lab.login(browser)
        original = await issue(lab, browser)
        assert original.response.refresh_token is not None
        rotated = await browser.post(
            f"{lab.stack.issuer}/token",
            data=refresh_parameters(lab, original.response.refresh_token),
        )
        assert rotated.status_code == HTTPStatus.OK
        for token in (original.response.refresh_token, rotated.json()["refresh_token"]):
            response = await browser.post(
                f"{lab.stack.issuer}/token", data=refresh_parameters(lab, token, ServiceId.SP_B)
            )
            assert response.json()["error"] == "invalid_grant"
        status = await lab.idp().security.check_access(
            SecretStr(rotated.json()["access_token"]), authenticated_client="sp-a"
        )
        assert status.active and status.context is not None
        assert status.context.family.generation == 1


async def test_authenticated_refresh_reuse_commits_family_revocation_before_error(
    renewal: LifecycleLab,
) -> None:
    lab = renewal
    async with lab.client() as browser:
        await lab.login(browser)
        original = await issue(lab, browser)
        assert original.response.refresh_token is not None
        rotated = await browser.post(
            f"{lab.stack.issuer}/token",
            data=refresh_parameters(lab, original.response.refresh_token),
        )
        assert rotated.status_code == HTTPStatus.OK
        replay = await browser.post(
            f"{lab.stack.issuer}/token",
            data=refresh_parameters(lab, original.response.refresh_token),
        )
        assert replay.json()["error"] == "invalid_grant"
        assert not (
            await lab.idp().security.check_access(
                SecretStr(rotated.json()["access_token"]), authenticated_client="sp-a"
            )
        ).active
        await lab.restart(ServiceId.IDP)
        again = await browser.post(
            f"{lab.stack.issuer}/token",
            data=refresh_parameters(lab, rotated.json()["refresh_token"]),
        )
        assert again.json()["error"] == "invalid_grant"


async def test_two_sp_instances_coordinate_concurrent_renewal_in_the_database(
    renewal: LifecycleLab,
) -> None:
    lab = renewal
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        original_cookie = cookie(browser)
        lab.clock.value += 301
        first = lab.sp().security.renewer
        assert isinstance(first, SpRenewalService)
        second = SpRenewalService(lab.sp().security.repository, lab.sp().oidc)
        access = await asyncio.gather(
            *(service.ensure_access(original_cookie) for service in [first, second] * 6)
        )
        assert len({token.get_secret_value() for token in access}) == 1
        async with lab.sp().database.sessions() as session:
            row = await session.get(
                SpAuthenticationRow, verifier_digest(original_cookie.get_secret_value())
            )
            assert row is not None and row.refresh_generation == 1 and row.refresh_state == "ready"
            encrypted = row.encrypted_refresh_token
            assert encrypted is not None and b"token" not in encrypted
        await lab.restart(ServiceId.SP_A)
        assert (await lab.account(browser)).status_code == HTTPStatus.OK


@pytest.mark.parametrize("failure", ["lost_response", "cancel", "sp_commit"])
async def test_ambiguous_refresh_never_resends_and_recovers_with_fresh_authorization(
    renewal: LifecycleLab, failure: str
) -> None:
    lab = renewal
    entered, release = asyncio.Event(), asyncio.Event()
    calls = 0
    delegate = lab.transport

    class Ambiguous(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            nonlocal calls
            is_refresh = (
                request.url.path == "/token" and b"grant_type=refresh_token" in request.content
            )
            response = await delegate.handle_async_request(request)
            if is_refresh:
                calls += 1
                assert response.status_code == HTTPStatus.OK
                entered.set()
                if failure == "lost_response":
                    raise httpx.ReadError("Injected lost refresh response")
                if failure == "cancel":
                    await release.wait()
            return response

    def fail(session: Session) -> None:
        if any(
            isinstance(row, SpAuthenticationRow)
            and row.refresh_state == "ready"
            and row.refresh_generation > 0
            for row in session.dirty
        ):
            raise RuntimeError("Injected SP refresh installation failure")

    original_transport = lab.sp().oidc.transport
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        original_cookie = cookie(browser)
        lab.clock.value += 301
        lab.sp().oidc.transport = Ambiguous()
        if failure == "sp_commit":
            event.listen(Session, "before_commit", fail)
        try:
            pending = asyncio.create_task(lab.account(browser))
            if failure == "cancel":
                await entered.wait()
                pending.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await pending
            else:
                assert (await pending).status_code == HTTPStatus.SERVICE_UNAVAILABLE
        finally:
            if failure == "sp_commit":
                event.remove(Session, "before_commit", fail)
            lab.sp().oidc.transport = original_transport
        assert calls == 1
        await lab.restart(ServiceId.SP_A)
        assert (await lab.account(browser)).status_code == HTTPStatus.SERVICE_UNAVAILABLE
        assert calls == 1
        async with lab.sp().database.sessions() as session:
            row = await session.get(
                SpAuthenticationRow, verifier_digest(original_cookie.get_secret_value())
            )
            assert row is not None and row.refresh_state == "blocked"
        await lab.sign_in(browser)
        assert cookie(browser) != original_cookie


async def test_abandoned_refresh_lease_survives_restart_and_blocks_without_waiting(
    renewal: LifecycleLab,
) -> None:
    lab = renewal
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        lab.clock.value += 301
        service = lab.sp().security.renewer
        assert isinstance(service, SpRenewalService)
        attempt = await service.claim(cookie(browser))
        assert isinstance(attempt, RefreshAttempt)
        await lab.restart(ServiceId.SP_A)
        lab.clock.value += service.lease_seconds
        assert (await lab.account(browser)).status_code == HTTPStatus.SERVICE_UNAVAILABLE
        await lab.sign_in(browser)


async def test_local_logout_wins_over_a_completed_remote_refresh(renewal: LifecycleLab) -> None:
    lab = renewal
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        original_cookie = cookie(browser)
        lab.clock.value += 301
        service = lab.sp().security.renewer
        assert isinstance(service, SpRenewalService)
        claim = await service.claim(original_cookie)
        assert isinstance(claim, RefreshAttempt)
        response = await lab.sp().oidc.refresh_verified(
            claim.token, authentication=claim.local.authentication, nonce=claim.nonce
        )
        await lab.sp().security.logout_local(original_cookie)
        with pytest.raises(SecurityDenied):
            await service.finish(claim, response)
        assert (await lab.account(browser)).status_code == HTTPStatus.UNAUTHORIZED


@pytest.mark.parametrize("kind", ["logout", "client", "key"])
async def test_refresh_racing_authoritative_containment_cannot_revive_authority(
    renewal: LifecycleLab, kind: str
) -> None:
    lab = renewal
    admin = await operator(lab)
    async with lab.client() as browser:
        await lab.login(browser)
        original = await issue(lab, browser)
        assert original.response.refresh_token is not None
        prepared = await admin.prepare_key()
        client = (await admin.inspect("sp-a"))[0]

        async def contain() -> None:
            if kind == "logout":
                await lab.idp().security.end_session(original.context.authentication.session_id)
            elif kind == "client":
                await admin.contain_client("sp-a", client.registration_version)
            else:
                await admin.contain_key(
                    original.evidence.signing_key_id,
                    prepared.key_id,
                    original.evidence.signing_key_id,
                )

        response, _ = await asyncio.gather(
            browser.post(
                f"{lab.stack.issuer}/token",
                data=refresh_parameters(lab, original.response.refresh_token),
            ),
            contain(),
        )
        if response.is_success:
            assert not (
                await lab.idp().security.check_access(
                    SecretStr(response.json()["access_token"]), authenticated_client="sp-a"
                )
            ).active
        else:
            assert response.json()["error"] in {"invalid_client", "invalid_grant"}
        if kind == "client":
            await recover_client(lab, admin)
    await admin.logout()


async def test_refresh_signer_rotation_retention_and_non_root_compromise_are_bound(
    renewal: LifecycleLab,
) -> None:
    lab = renewal
    admin = await operator(lab)
    async with lab.client() as browser:
        await lab.login(browser)
        original = await issue(lab, browser)
        assert original.response.refresh_token is not None
        next_key = await admin.prepare_key()
        await admin.activate_key(next_key.key_id, original.evidence.signing_key_id)
        response = await browser.post(
            f"{lab.stack.issuer}/token",
            data=refresh_parameters(lab, original.response.refresh_token),
        )
        assert response.status_code == HTTPStatus.OK
        current = next(key for key in await admin.signing_keys() if key.key_id == next_key.key_id)
        assert current.verification_deadline == lab.clock.now() + 300
        assert (
            await lab.idp().security.check_access(
                SecretStr(response.json()["access_token"]), authenticated_client="sp-a"
            )
        ).active
        replacement = await admin.prepare_key()
        await admin.contain_key(next_key.key_id, replacement.key_id, next_key.key_id)
        assert not (
            await lab.idp().security.check_access(
                SecretStr(response.json()["access_token"]), authenticated_client="sp-a"
            )
        ).active
        denied = await browser.post(
            f"{lab.stack.issuer}/token",
            data=refresh_parameters(lab, response.json()["refresh_token"]),
        )
        assert denied.json()["error"] == "invalid_grant"
    await admin.logout()


@pytest.mark.parametrize("mode", ["force", "recent"])
async def test_reauthentication_requires_password_rotates_cookie_and_preserves_other_sp(
    renewal: LifecycleLab, mode: str
) -> None:
    lab = renewal
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        await lab.sign_in(browser, ServiceId.SP_B)
        original_cookie = cookie(browser)
        before_b = (await lab.account(browser, ServiceId.SP_B)).json()
        lab.clock.value += 61
        page = await browser.get(f"{lab.stack.origin(ServiceId.SP_A)}/auth/reauthenticate")
        started = await browser.post(
            f"{lab.stack.origin(ServiceId.SP_A)}/auth/reauthenticate",
            headers={"Origin": lab.stack.origin(ServiceId.SP_A)},
            data={"csrf": action_challenge(page), "mode": mode, "max_age": "60"},
        )
        assert started.status_code == HTTPStatus.SEE_OTHER
        form = await browser.get(started.headers["location"])
        assert form.status_code == HTTPStatus.OK and "name='password'" in form.text
        rejected = await browser.post(
            f"{lab.stack.issuer}/login",
            headers={"Origin": lab.stack.issuer},
            data={
                "csrf": action_challenge(form),
                "username": lab.user.username,
                "password": "not-the-password",
            },
        )
        assert rejected.status_code == HTTPStatus.UNAUTHORIZED
        accepted = await submit_password(browser, lab.stack.issuer, rejected, lab.user)
        assert accepted.status_code == HTTPStatus.FOUND
        completed = await browser.get(accepted.headers["location"])
        assert completed.status_code == HTTPStatus.SEE_OTHER
        assert cookie(browser) != original_cookie
        after = (await lab.account(browser)).json()
        assert after["auth_time"] == lab.clock.now()
        after_b = (await lab.account(browser, ServiceId.SP_B)).json()
        assert after_b["auth_time"] == before_b["auth_time"]


async def test_reauthentication_cannot_substitute_another_account(renewal: LifecycleLab) -> None:
    lab = renewal
    material = await asyncio.to_thread(
        load_seeded_users, lab.stack.root / "idp", lab.assets[ServiceId.IDP].envelope
    )
    bob = next(user for user in material.users if user.username == "bob")
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        original_cookie = cookie(browser)
        page = await browser.get(f"{lab.stack.origin(ServiceId.SP_A)}/auth/reauthenticate")
        started = await browser.post(
            f"{lab.stack.origin(ServiceId.SP_A)}/auth/reauthenticate",
            headers={"Origin": lab.stack.origin(ServiceId.SP_A)},
            data={"csrf": action_challenge(page), "mode": "force", "max_age": "0"},
        )
        form = await browser.get(started.headers["location"])
        rejected = await submit_password(browser, lab.stack.issuer, form, bob)
        assert rejected.status_code == HTTPStatus.UNAUTHORIZED
        assert cookie(browser) == original_cookie
        assert (await lab.account(browser)).json()["subject"] == lab.user.subject


async def test_concurrent_wire_refresh_replay_has_one_rotation_then_containment(
    renewal: LifecycleLab,
) -> None:
    lab = renewal
    async with lab.client() as browser:
        await lab.login(browser)
        original = await issue(lab, browser)
        assert original.response.refresh_token is not None
        responses = await asyncio.gather(
            *(
                browser.post(
                    f"{lab.stack.issuer}/token",
                    data=refresh_parameters(lab, original.response.refresh_token),
                )
                for _ in range(8)
            )
        )
        successes = [response for response in responses if response.is_success]
        assert len(successes) == 1
        assert all(
            response.json()["error"] == "invalid_grant"
            for response in responses
            if not response.is_success
        )
        assert not (
            await lab.idp().security.check_access(
                SecretStr(successes[0].json()["access_token"]), authenticated_client="sp-a"
            )
        ).active


async def test_failed_idp_refresh_commit_preserves_predecessor_and_replay_reservation(
    renewal: LifecycleLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab = renewal
    async with lab.client() as browser:
        await lab.login(browser)
        original = await issue(lab, browser)
        assert original.response.refresh_token is not None
        parameters = refresh_parameters(lab, original.response.refresh_token)
        commit = lab.idp().security.commit_refresh_in

        async def marked(
            work: SecurityUnitOfWork,
            predecessor: SecretStr,
            evidence: LoginEvidence,
            *,
            access_token: SecretStr,
            refresh_token: SecretStr,
            authenticated_client: str,
        ) -> IssuedCredentials:
            result = await commit(
                work,
                predecessor,
                evidence,
                access_token=access_token,
                refresh_token=refresh_token,
                authenticated_client=authenticated_client,
            )
            work.session.info["fail_idp_refresh"] = True
            return result

        def fail(session: Session) -> None:
            if session.info.get("fail_idp_refresh"):
                raise RuntimeError("Injected IDP refresh commit failure")

        event.listen(Session, "before_commit", fail)
        try:
            with monkeypatch.context() as patch:
                patch.setattr(lab.idp().security, "commit_refresh_in", marked)
                with pytest.raises(RuntimeError, match="Injected IDP"):
                    await browser.post(f"{lab.stack.issuer}/token", data=parameters)
        finally:
            event.remove(Session, "before_commit", fail)
        retry = await browser.post(f"{lab.stack.issuer}/token", data=parameters)
        assert retry.status_code == HTTPStatus.OK
        async with lab.idp().oidc.database.sessions() as session:
            signed = list(
                await session.scalars(
                    select(RefreshIssuanceRow).where(
                        RefreshIssuanceRow.family_id == original.context.family.family_id
                    )
                )
            )
            assert len(signed) == 1


async def test_refresh_history_and_predecessor_cannot_be_rewritten(renewal: LifecycleLab) -> None:
    lab = renewal
    async with lab.client() as browser:
        await lab.login(browser)
        original = await issue(lab, browser)
        assert original.response.refresh_token is not None
        rotated = await browser.post(
            f"{lab.stack.issuer}/token",
            data=refresh_parameters(lab, original.response.refresh_token),
        )
        assert rotated.status_code == HTTPStatus.OK
        for statement in (
            "UPDATE refresh_issuances SET expires_at=expires_at+1 WHERE family_id=:family",
            "UPDATE refresh_credentials SET predecessor_digest=NULL "
            "WHERE family_id=:family AND generation=1",
        ):
            with pytest.raises(DBAPIError, match="immutable"):
                async with lab.idp().oidc.database.engine.begin() as connection:
                    await connection.execute(
                        text(statement), {"family": original.context.family.family_id}
                    )


@pytest.mark.parametrize("kind", ["idle", "absolute"])
async def test_expired_local_session_cannot_use_its_refresh_credential(
    renewal: LifecycleLab, kind: str
) -> None:
    lab = renewal
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        before = (await lab.account(browser)).json()
        lab.clock.value = before["idle_expires_at" if kind == "idle" else "expires_at"]
        assert (await lab.account(browser)).status_code == HTTPStatus.UNAUTHORIZED


async def test_disabled_user_cannot_renew_without_an_active_parent_account(
    renewal: LifecycleLab,
) -> None:
    lab = renewal
    async with lab.client() as browser:
        await lab.login(browser)
        original = await issue(lab, browser)
        assert original.response.refresh_token is not None
        try:
            async with lab.idp().oidc.database.sessions() as session:
                row = await session.get(UserRow, lab.user.subject)
                assert row is not None
                row.enabled = False
                await session.commit()
            response = await browser.post(
                f"{lab.stack.issuer}/token",
                data=refresh_parameters(lab, original.response.refresh_token),
            )
            assert response.json()["error"] == "invalid_grant"
        finally:
            async with lab.idp().oidc.database.sessions() as session:
                row = await session.get(UserRow, lab.user.subject)
                assert row is not None
                row.enabled = True
                await session.commit()


@pytest.mark.parametrize("case", ["origin", "purpose", "replay", "bad_age"])
async def test_reauthentication_intent_is_bound_and_cannot_be_replayed(
    renewal: LifecycleLab, case: str
) -> None:
    lab = renewal
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        page = await browser.get(f"{lab.stack.origin(ServiceId.SP_A)}/auth/reauthenticate")
        csrf = action_challenge(page)
        if case == "purpose":
            csrf = action_challenge(
                await browser.get(f"{lab.stack.origin(ServiceId.SP_A)}/auth/logout")
            )
        data = {"csrf": csrf, "mode": "force", "max_age": "invalid" if case == "bad_age" else "0"}
        origin = (
            lab.stack.origin(ServiceId.SP_B)
            if case == "origin"
            else lab.stack.origin(ServiceId.SP_A)
        )
        response = await browser.post(
            f"{lab.stack.origin(ServiceId.SP_A)}/auth/reauthenticate",
            headers={"Origin": origin},
            data=data,
        )
        if case == "replay":
            assert response.status_code == HTTPStatus.SEE_OTHER
            response = await browser.post(
                f"{lab.stack.origin(ServiceId.SP_A)}/auth/reauthenticate",
                headers={"Origin": origin},
                data=data,
            )
        assert response.status_code in {HTTPStatus.FORBIDDEN, HTTPStatus.BAD_REQUEST}
