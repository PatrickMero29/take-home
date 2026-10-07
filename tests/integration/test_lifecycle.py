"""Phase 3 lifecycle/security scenarios share one actual TLS PostgreSQL deployment."""

import asyncio
import secrets
from collections.abc import AsyncIterator
from http import HTTPStatus

import pytest
import pytest_asyncio
from pydantic import SecretStr
from sqlalchemy import event, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from federated_identity.cli.probe_runtime import command, postgres_bin
from federated_identity.common.persistence.actions import PostgresBrowserActions
from federated_identity.common.security.actions import BrowserAction, BrowserActionPurpose
from federated_identity.common.security.model import LifecyclePolicy, RevocationReason
from federated_identity.common.security.oidc import VerifiedLogin
from federated_identity.common.settings.policy import verifier_digest
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.repositories.security import SecurityUnitOfWork
from federated_identity.idp.repositories.security_tables import FederationGrantRow, IdpSessionRow
from federated_identity.idp.services.security_model import IdpSecurityModel
from federated_identity.sp.protocol.oidc import AuthorizationTransaction, OidcClient
from tests.helpers import ASSERTION_TYPE, callback_code
from tests.lifecycle_helpers import LifecycleLab, action_challenge, lifecycle_lab, next_scenario

pytestmark = [pytest.mark.integration, pytest.mark.asyncio(loop_scope="module")]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def shared_lifecycle() -> AsyncIterator[LifecycleLab]:
    async with lifecycle_lab() as lab:
        yield lab


@pytest_asyncio.fixture(loop_scope="module")
async def life(shared_lifecycle: LifecycleLab) -> LifecycleLab:
    next_scenario(shared_lifecycle)
    return shared_lifecycle


async def test_local_logout_rejects_cookie_and_pending_callback_without_ending_sso(
    life: LifecycleLab,
) -> None:
    async with life.client() as browser:
        await life.login(browser)
        await life.sign_in(browser)
        await life.sign_in(browser, ServiceId.SP_B)
        old = browser.cookies.get("__Host-fid-sp-a")
        form = await browser.get(f"{life.stack.origin(ServiceId.SP_A)}/auth/logout")
        start = await browser.get(f"{life.stack.origin(ServiceId.SP_A)}/auth/login")
        callback = (await browser.get(start.headers["location"])).headers["location"]
        challenge = action_challenge(form)
        result = await life.post_action(browser, ServiceId.SP_A, "/auth/logout", challenge)
        assert (
            result.status_code == HTTPStatus.SEE_OTHER
            and "max-age=0" in result.headers["set-cookie"].lower()
        )
        assert browser.cookies.get("__Host-fid-sp-a") is None
        assert (await life.account(browser)).status_code == HTTPStatus.UNAUTHORIZED
        replay = await browser.get(
            f"{life.stack.origin(ServiceId.SP_A)}/account",
            headers={"Cookie": f"__Host-fid-sp-a={old}"},
        )
        assert replay.status_code == HTTPStatus.UNAUTHORIZED
        assert (await life.account(browser, ServiceId.SP_B)).status_code == HTTPStatus.OK
        assert (await life.account(browser, ServiceId.IDP)).status_code == HTTPStatus.OK
        stale = await browser.get(callback, headers={"Cookie": f"__Host-fid-sp-a={old}"})
        assert stale.status_code == HTTPStatus.BAD_REQUEST
        await life.sign_in(browser)
        assert browser.cookies.get("__Host-fid-sp-a") != old
        assert (
            await life.post_action(browser, ServiceId.SP_A, "/auth/logout", challenge)
        ).status_code == HTTPStatus.FORBIDDEN
        assert (await life.account(browser)).status_code == HTTPStatus.OK


async def test_idp_logout_revokes_both_grants_and_never_authenticates_old_cookie(
    life: LifecycleLab,
) -> None:
    async with life.client() as browser:
        await life.login(browser)
        await life.sign_in(browser)
        await life.sign_in(browser, ServiceId.SP_B)
        account = (await life.account(browser, ServiceId.IDP)).json()
        old = browser.cookies.get("__Host-fid-idp")
        form = await browser.get(f"{life.stack.issuer}/logout")
        assert (await life.account(browser, ServiceId.IDP)).status_code == HTTPStatus.OK
        response = await life.post_action(browser, ServiceId.IDP, "/logout", action_challenge(form))
        assert (
            response.status_code == HTTPStatus.SEE_OTHER
            and browser.cookies.get("__Host-fid-idp") is None
        )
        for service in (ServiceId.IDP, ServiceId.SP_A, ServiceId.SP_B):
            assert (await life.account(browser, service)).status_code == HTTPStatus.UNAUTHORIZED
        old_response = await browser.get(
            f"{life.stack.issuer}/account", headers={"Cookie": f"__Host-fid-idp={old}"}
        )
        assert old_response.status_code == HTTPStatus.UNAUTHORIZED
        async with life.idp().oidc.database.sessions() as session:
            parent = await session.get(IdpSessionRow, account["sid"])
            grants = list(
                await session.scalars(
                    select(FederationGrantRow).where(
                        FederationGrantRow.session_id == account["sid"]
                    )
                )
            )
            assert parent is not None and parent.revoked_at == life.clock.now()
            assert len(grants) == 2 and all(
                grant.revoked_at == parent.revoked_at for grant in grants
            )
        await life.login(browser)
        assert (await life.account(browser, ServiceId.IDP)).json()["sid"] != account["sid"]


async def test_idp_user_revoke_is_scoped_to_the_selected_application_grant(
    life: LifecycleLab,
) -> None:
    async with life.client() as browser:
        await life.login(browser)
        await life.sign_in(browser)
        await life.sign_in(browser, ServiceId.SP_B)
        grants = await browser.get(f"{life.stack.issuer}/grants")
        challenge = action_challenge(grants, "Revoke sp-a access")
        response = await life.post_action(browser, ServiceId.IDP, "/grants/revoke", challenge)
        assert response.status_code == HTTPStatus.SEE_OTHER
        assert (await life.account(browser)).status_code == HTTPStatus.UNAUTHORIZED
        assert (await life.account(browser, ServiceId.SP_B)).status_code == HTTPStatus.OK
        assert (await life.account(browser, ServiceId.IDP)).status_code == HTTPStatus.OK
        assert (
            await life.post_action(browser, ServiceId.IDP, "/grants/revoke", challenge)
        ).status_code == HTTPStatus.FORBIDDEN


async def test_sp_revoke_uses_own_private_key_and_ends_only_its_grant(life: LifecycleLab) -> None:
    async with life.client() as browser:
        await life.login(browser)
        await life.sign_in(browser)
        await life.sign_in(browser, ServiceId.SP_B)
        old = SecretStr(str(browser.cookies.get("__Host-fid-sp-a")))
        loaded = await life.sp().security.repository.load(old)
        assert loaded is not None
        form = await browser.get(f"{life.stack.origin(ServiceId.SP_A)}/auth/revoke")
        assert (
            await life.post_action(browser, ServiceId.SP_A, "/auth/revoke", action_challenge(form))
        ).status_code == HTTPStatus.SEE_OTHER
        assert not (await life.sp().grants.check(loaded[1])).active
        assert (await life.account(browser)).status_code == HTTPStatus.UNAUTHORIZED
        assert (await life.account(browser, ServiceId.SP_B)).status_code == HTTPStatus.OK
        assert (await life.account(browser, ServiceId.IDP)).status_code == HTTPStatus.OK


@pytest.mark.parametrize(
    "service,path", [(ServiceId.SP_A, "/auth/logout"), (ServiceId.IDP, "/logout")]
)
@pytest.mark.parametrize(
    "attack", ["missing", "foreign_origin", "other_browser", "expired", "wrong_purpose"]
)
async def test_logout_intent_is_origin_browser_purpose_and_expiry_bound(
    life: LifecycleLab, service: ServiceId, path: str, attack: str
) -> None:
    async with life.client() as browser, life.client() as other:
        await life.login(browser)
        await life.sign_in(browser)
        form = await browser.get(f"{life.stack.origin(service)}{path}")
        csrf = action_challenge(form)
        headers = {
            "Origin": life.stack.origin(service),
            "Content-Type": "application/x-www-form-urlencoded",
        }
        data = {"csrf": csrf}
        target = browser
        if attack == "missing":
            data = {}
        elif attack == "foreign_origin":
            headers["Origin"] = life.stack.origin(ServiceId.SP_B)
        elif attack == "other_browser":
            await life.login(other)
            if service == ServiceId.SP_A:
                await life.sign_in(other)
            target = other
        elif attack == "expired":
            life.clock.value += 300
        else:
            path = "/auth/revoke" if service == ServiceId.SP_A else "/grants/revoke"
        response = await target.post(
            f"{life.stack.origin(service)}{path}", headers=headers, data=data
        )
        assert response.status_code == HTTPStatus.FORBIDDEN
        cookie = browser.cookies.get(
            "__Host-fid-sp-a" if service == ServiceId.SP_A else "__Host-fid-idp"
        )
        assert cookie is not None and "set-cookie" not in response.headers
        assert (await life.account(browser, ServiceId.IDP)).status_code == HTTPStatus.OK
        if attack != "expired":
            assert (await life.account(browser)).status_code == HTTPStatus.OK


async def test_user_cannot_revoke_a_different_idp_session_even_with_a_server_intent(
    life: LifecycleLab,
) -> None:
    async with life.client() as owner, life.client() as other:
        await life.login(owner)
        await life.sign_in(owner)
        await life.login(other)
        target = await life.idp().browser.grants(
            SecretStr(str(owner.cookies.get("__Host-fid-idp")))
        )
        cookie = SecretStr(str(other.cookies.get("__Host-fid-idp")))
        malformed = await life.idp().browser.actions.issue(
            cookie,
            BrowserAction(purpose=BrowserActionPurpose.IDP_REVOKE, target=target[0].grant_id),
            expires_at=life.clock.now() + 300,
        )
        assert (
            await life.post_action(
                other, ServiceId.IDP, "/grants/revoke", malformed.get_secret_value()
            )
        ).status_code == HTTPStatus.FORBIDDEN
        assert (await life.account(owner)).status_code == HTTPStatus.OK


async def test_authenticated_revocation_and_introspection_are_recipient_scoped(
    life: LifecycleLab,
) -> None:
    async with life.client() as browser:
        await life.login(browser)
        await life.sign_in(browser)
        cookie = SecretStr(str(browser.cookies.get("__Host-fid-sp-a")))
        loaded = await life.sp().security.repository.load(cookie)
        assert loaded is not None
        token = loaded[1].get_secret_value()
        fields = {
            "token": token,
            "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": life.assertion(ServiceId.SP_B, "/revoke"),
        }
        wrong = await browser.post(f"{life.stack.issuer}/revoke", data=fields)
        assert wrong.status_code == HTTPStatus.OK and not wrong.content
        assert (await life.sp().grants.check(loaded[1])).active
        assert not (await life.sp(ServiceId.SP_B).grants.check(loaded[1])).active
        fields["client_assertion"] = life.assertion(ServiceId.SP_A, "/introspect")
        assert (await browser.post(f"{life.stack.issuer}/revoke", data=fields)).json()[
            "error"
        ] == "invalid_client"
        fields.update(
            client_assertion=life.assertion(ServiceId.SP_A, "/revoke"),
            token_type_hint="unrecognized",
        )
        valid = await browser.post(f"{life.stack.issuer}/revoke", data=fields)
        assert valid.status_code == HTTPStatus.OK and not valid.content
        assert not (await life.sp().grants.check(loaded[1])).active
        assert (await browser.post(f"{life.stack.issuer}/revoke", data=fields)).json()[
            "error"
        ] == "invalid_client"
        fields.update(
            token=secrets.token_urlsafe(32),
            client_assertion=life.assertion(ServiceId.SP_A, "/revoke"),
        )
        assert (
            await browser.post(f"{life.stack.issuer}/revoke", data=fields)
        ).status_code == HTTPStatus.OK
        assert (await browser.post(f"{life.stack.issuer}/revoke", data={"token": token})).json()[
            "error"
        ] == "invalid_client"


async def test_authenticated_code_replay_requires_original_callback_and_pkce_before_containment(
    life: LifecycleLab,
) -> None:
    async with life.client() as browser:
        await life.login(browser)
        await life.sign_in(browser, ServiceId.SP_B)
        transaction = life.sp().oidc.begin()
        callback = (await browser.get(transaction.authorization_url)).headers["location"]
        login = await life.sp().oidc.exchange_verified(transaction, callback)
        for change in ("client", "verifier", "redirect", "missing_verifier"):
            fields = life.token_parameters(transaction, callback)
            if change == "client":
                fields.update(
                    client_id="sp-b", client_assertion=life.assertion(ServiceId.SP_B, "/token")
                )
            elif change == "verifier":
                fields["code_verifier"] = "incorrect" * 8
            elif change == "redirect":
                fields["redirect_uri"] += "/"
            else:
                del fields["code_verifier"]
            rejected = await browser.post(f"{life.stack.issuer}/token", data=fields)
            assert rejected.status_code == HTTPStatus.BAD_REQUEST
            assert (await life.sp().grants.check(SecretStr(login.response.access_token))).active
        life.clock.value += 60  # Consumed proofs still contain active grants after code expiry.
        replay = await browser.post(
            f"{life.stack.issuer}/token", data=life.token_parameters(transaction, callback)
        )
        assert (
            replay.status_code == HTTPStatus.BAD_REQUEST
            and replay.json()["error"] == "invalid_grant"
        )
        assert not (await life.sp().grants.check(SecretStr(login.response.access_token))).active
        assert (await life.account(browser, ServiceId.SP_B)).status_code == HTTPStatus.OK
        assert (await life.account(browser, ServiceId.IDP)).status_code == HTTPStatus.OK
        async with life.idp().oidc.database.sessions() as session:
            grant = await session.get(FederationGrantRow, login.context.grant.grant_id)
            assert (
                grant is not None and grant.revocation_reason == RevocationReason.CODE_REPLAY.value
            )
        with pytest.raises(DBAPIError, match="retained"):
            async with life.idp().oidc.database.engine.begin() as connection:
                await connection.execute(
                    text("DELETE FROM authorization_codes WHERE code_digest=:digest"),
                    {"digest": verifier_digest(callback_code(callback))},
                )


@pytest.mark.parametrize("kind", ["idle", "absolute", "idp", "grant", "access"])
async def test_exact_server_expiry_rejects_a_cookie_still_held_by_the_browser(
    life: LifecycleLab, kind: str
) -> None:
    if kind == "idle":
        life.sp().security.lifecycle = LifecyclePolicy(sp_session_seconds=120, sp_idle_seconds=30)
    elif kind == "absolute":
        life.sp().security.lifecycle = LifecyclePolicy(sp_session_seconds=120, sp_idle_seconds=60)
    elif kind == "idp":
        life.idp().security.lifecycle = LifecyclePolicy(idp_session_seconds=60)
    elif kind == "grant":
        life.idp().security.lifecycle = LifecyclePolicy(grant_seconds=60)
    async with life.client() as browser:
        await life.login(browser)
        await life.sign_in(browser)
        old = browser.cookies.get("__Host-fid-sp-a")
        if kind == "absolute":
            started = life.clock.now()
            for delta in (59, 118):
                life.clock.value = started + delta
                assert (await life.account(browser)).status_code == HTTPStatus.OK
            life.clock.value = started + 120
        else:
            life.clock.value += 30 if kind == "idle" else 60 if kind in {"idp", "grant"} else 300
        response = await life.account(browser)
        expected_access = HTTPStatus.OK if kind == "access" else HTTPStatus.UNAUTHORIZED
        assert response.status_code == expected_access and "set-cookie" not in response.headers
        assert browser.cookies.get("__Host-fid-sp-a") == old
        expected = HTTPStatus.UNAUTHORIZED if kind == "idp" else HTTPStatus.OK
        assert (await life.account(browser, ServiceId.IDP)).status_code == expected


@pytest.mark.parametrize(
    "service,path", [(ServiceId.SP_A, "/auth/logout"), (ServiceId.IDP, "/logout")]
)
async def test_failed_lifecycle_commit_preserves_session_cookie_and_retryable_intent(
    life: LifecycleLab, service: ServiceId, path: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = PostgresBrowserActions.consume_in

    async def consume(
        self: PostgresBrowserActions,
        session: AsyncSession,
        challenge: SecretStr,
        browser: SecretStr,
        purpose: BrowserActionPurpose,
    ) -> BrowserAction:
        result = await original(self, session, challenge, browser, purpose)
        session.info["fail_lifecycle"] = True
        return result

    def fail(session: Session) -> None:
        if session.info.get("fail_lifecycle"):
            raise RuntimeError("Injected lifecycle commit failure")

    async with life.client() as browser:
        await life.login(browser)
        await life.sign_in(browser)
        form = await browser.get(f"{life.stack.origin(service)}{path}")
        challenge = action_challenge(form)
        before = {cookie.name: cookie.value for cookie in browser.cookies.jar}
        event.listen(Session, "before_commit", fail)
        try:
            with monkeypatch.context() as patch:
                patch.setattr(PostgresBrowserActions, "consume_in", consume)
                with pytest.raises(RuntimeError, match="Injected lifecycle"):
                    await life.post_action(browser, service, path, challenge)
        finally:
            event.remove(Session, "before_commit", fail)
        assert {cookie.name: cookie.value for cookie in browser.cookies.jar} == before
        assert (await life.account(browser)).status_code == HTTPStatus.OK
        assert (await life.account(browser, ServiceId.IDP)).status_code == HTTPStatus.OK
        assert (
            await life.post_action(browser, service, path, challenge)
        ).status_code == HTTPStatus.SEE_OTHER


async def test_callback_exchange_racing_logout_cannot_revive_its_initiating_cookie(
    life: LifecycleLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    entered, release = asyncio.Event(), asyncio.Event()
    original = OidcClient.exchange_verified

    async def exchange(
        self: OidcClient, transaction: AuthorizationTransaction, callback_url: str
    ) -> VerifiedLogin:
        result = await original(self, transaction, callback_url)
        entered.set()
        await release.wait()
        return result

    async with life.client() as browser:
        await life.login(browser)
        await life.sign_in(browser)
        old = browser.cookies.get("__Host-fid-sp-a")
        form = await browser.get(f"{life.stack.origin(ServiceId.SP_A)}/auth/logout")
        start = await browser.get(f"{life.stack.origin(ServiceId.SP_A)}/auth/login")
        callback = (await browser.get(start.headers["location"])).headers["location"]
        monkeypatch.setattr(OidcClient, "exchange_verified", exchange)
        pending = asyncio.create_task(browser.get(callback))
        try:
            await asyncio.wait_for(entered.wait(), timeout=3)
            assert (
                await life.post_action(
                    browser, ServiceId.SP_A, "/auth/logout", action_challenge(form)
                )
            ).status_code == HTTPStatus.SEE_OTHER
        finally:
            release.set()
        result = await asyncio.wait_for(pending, timeout=3)
        assert result.status_code == HTTPStatus.BAD_REQUEST and "set-cookie" not in result.headers
        assert browser.cookies.get("__Host-fid-sp-a") is None
        forced = await browser.get(
            f"{life.stack.origin(ServiceId.SP_A)}/account",
            headers={"Cookie": f"__Host-fid-sp-a={old}"},
        )
        assert forced.status_code == HTTPStatus.UNAUTHORIZED


async def test_idp_and_database_outages_fail_closed_recover_and_allow_local_logout(
    life: LifecycleLab,
) -> None:
    async with life.client() as browser:
        await life.login(browser)
        await life.sign_in(browser)
        await life.sign_in(browser, ServiceId.SP_B)
        old = browser.cookies.get("__Host-fid-sp-a")
        life.transport.unavailable.add(ServiceId.IDP.hostname)
        unavailable = await life.account(browser)
        assert (
            unavailable.status_code == HTTPStatus.SERVICE_UNAVAILABLE
            and "set-cookie" not in unavailable.headers
        )
        form = await browser.get(f"{life.stack.origin(ServiceId.SP_A)}/auth/logout")
        assert (
            await life.post_action(browser, ServiceId.SP_A, "/auth/logout", action_challenge(form))
        ).status_code == HTTPStatus.SEE_OTHER
        life.transport.unavailable.clear()
        await life.sign_in(browser)
        assert browser.cookies.get("__Host-fid-sp-a") != old
        before = {cookie.name: cookie.value for cookie in browser.cookies.jar}
        executable = str(postgres_bin() / "pg_ctl")
        await command(executable, "-D", str(life.stack.root / "pgdata"), "-w", "stop")
        try:
            # Force cold connections as well as stale pooled handles. A refused
            # socket must follow the same fail-closed, session-preserving path.
            await life.idp().oidc.database.dispose()
            for service in (ServiceId.SP_A, ServiceId.SP_B):
                await life.sp(service).database.dispose()
            for service in (ServiceId.IDP, ServiceId.SP_A, ServiceId.SP_B):
                blocked = await life.account(browser, service)
                assert (
                    blocked.status_code == HTTPStatus.SERVICE_UNAVAILABLE
                    and "set-cookie" not in blocked.headers
                )
        finally:
            await command(
                executable,
                "-D",
                str(life.stack.root / "pgdata"),
                "-l",
                str(life.stack.root / "postgres.log"),
                "-w",
                "-o",
                life.stack.postgres_options,
                "start",
            )
        for service in (ServiceId.IDP, ServiceId.SP_A, ServiceId.SP_B):
            assert (await life.account(browser, service)).status_code == HTTPStatus.OK
        assert {cookie.name: cookie.value for cookie in browser.cookies.jar} == before


async def test_reconstruction_preserves_active_revoked_and_pending_browser_state(
    life: LifecycleLab,
) -> None:
    async with life.client() as browser:
        await life.login(browser)
        await life.sign_in(browser)
        await life.sign_in(browser, ServiceId.SP_B)
        old_a = browser.cookies.get("__Host-fid-sp-a")
        form = await browser.get(f"{life.stack.origin(ServiceId.SP_A)}/auth/logout")
        for service in (ServiceId.IDP, ServiceId.SP_A, ServiceId.SP_B):
            await life.restart(service)
            assert (await life.account(browser, service)).status_code == HTTPStatus.OK
        assert (
            await life.post_action(browser, ServiceId.SP_A, "/auth/logout", action_challenge(form))
        ).status_code == HTTPStatus.SEE_OTHER
        await life.restart(ServiceId.SP_A)
        replay = await browser.get(
            f"{life.stack.origin(ServiceId.SP_A)}/account",
            headers={"Cookie": f"__Host-fid-sp-a={old_a}"},
        )
        assert replay.status_code == HTTPStatus.UNAUTHORIZED
        form = await browser.get(f"{life.stack.issuer}/logout")
        assert (
            await life.post_action(browser, ServiceId.IDP, "/logout", action_challenge(form))
        ).status_code == HTTPStatus.SEE_OTHER
        await life.restart(ServiceId.IDP)
        await life.restart(ServiceId.SP_B)
        assert (await life.account(browser, ServiceId.SP_B)).status_code == HTTPStatus.UNAUTHORIZED


@pytest.mark.parametrize(
    "service,path", [(ServiceId.SP_A, "/auth/logout"), (ServiceId.IDP, "/logout")]
)
async def test_concurrent_logout_intent_has_one_committed_effect(
    life: LifecycleLab, service: ServiceId, path: str
) -> None:
    async with life.client() as browser:
        await life.login(browser)
        await life.sign_in(browser)
        form = await browser.get(f"{life.stack.origin(service)}{path}")
        challenge = action_challenge(form)
        cookie_name = f"__Host-fid-{service.value}"
        cookie = browser.cookies.get(cookie_name)
        responses = await asyncio.gather(
            *(
                browser.post(
                    f"{life.stack.origin(service)}{path}",
                    headers={
                        "Origin": life.stack.origin(service),
                        "Cookie": f"{cookie_name}={cookie}",
                    },
                    data={"csrf": challenge},
                )
                for _ in range(4)
            )
        )
        assert sorted(response.status_code for response in responses) == [303, 403, 403, 403]
        assert (await life.account(browser)).status_code == HTTPStatus.UNAUTHORIZED


async def test_failed_remote_revocation_preserves_local_session_and_requires_a_new_intent(
    life: LifecycleLab,
) -> None:
    async with life.client() as browser:
        await life.login(browser)
        await life.sign_in(browser)
        old = browser.cookies.get("__Host-fid-sp-a")
        form = await browser.get(f"{life.stack.origin(ServiceId.SP_A)}/auth/revoke")
        challenge = action_challenge(form)
        life.transport.unavailable.add(ServiceId.IDP.hostname)
        response = await life.post_action(browser, ServiceId.SP_A, "/auth/revoke", challenge)
        assert response.status_code == HTTPStatus.SERVICE_UNAVAILABLE
        assert "set-cookie" not in response.headers
        assert browser.cookies.get("__Host-fid-sp-a") == old
        life.transport.unavailable.clear()
        assert (await life.account(browser)).status_code == HTTPStatus.OK
        assert (
            await life.post_action(browser, ServiceId.SP_A, "/auth/revoke", challenge)
        ).status_code == HTTPStatus.FORBIDDEN
        fresh = await browser.get(f"{life.stack.origin(ServiceId.SP_A)}/auth/revoke")
        assert (
            await life.post_action(browser, ServiceId.SP_A, "/auth/revoke", action_challenge(fresh))
        ).status_code == HTTPStatus.SEE_OTHER


async def test_idle_expiry_renews_browser_binding_before_a_new_sso_callback(
    life: LifecycleLab,
) -> None:
    life.sp().security.lifecycle = LifecyclePolicy(sp_session_seconds=120, sp_idle_seconds=30)
    async with life.client() as browser:
        await life.login(browser)
        await life.sign_in(browser)
        old = browser.cookies.get("__Host-fid-sp-a")
        life.clock.value += 30
        assert (await life.account(browser)).status_code == HTTPStatus.UNAUTHORIZED
        await life.sign_in(browser)
        assert browser.cookies.get("__Host-fid-sp-a") != old
        assert (await life.account(browser)).status_code == HTTPStatus.OK


async def test_code_replay_containment_and_assertion_reservation_roll_back_on_commit_failure(
    life: LifecycleLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = IdpSecurityModel.revoke_grant_in

    async def mark(
        self: IdpSecurityModel,
        work: SecurityUnitOfWork,
        grant_id: str,
        *,
        authenticated_client: str,
        reason: RevocationReason,
    ) -> bool:
        result = await original(
            self, work, grant_id, authenticated_client=authenticated_client, reason=reason
        )
        work.session.info["fail_code_replay"] = True
        return result

    def fail(session: Session) -> None:
        if session.info.get("fail_code_replay"):
            raise RuntimeError("Injected code replay commit failure")

    async with life.client() as browser:
        await life.login(browser)
        transaction = life.sp().oidc.begin()
        callback = (await browser.get(transaction.authorization_url)).headers["location"]
        login = await life.sp().oidc.exchange_verified(transaction, callback)
        fields = life.token_parameters(transaction, callback)
        event.listen(Session, "before_commit", fail)
        try:
            with monkeypatch.context() as patch:
                patch.setattr(IdpSecurityModel, "revoke_grant_in", mark)
                with pytest.raises(RuntimeError, match="Injected code replay"):
                    await browser.post(f"{life.stack.issuer}/token", data=fields)
        finally:
            event.remove(Session, "before_commit", fail)
        assert (await life.sp().grants.check(SecretStr(login.response.access_token))).active
        replay = await browser.post(f"{life.stack.issuer}/token", data=fields)
        assert replay.json()["error"] == "invalid_grant"
        assert not (await life.sp().grants.check(SecretStr(login.response.access_token))).active
