"""Phase 2 acceptance uses real credentials, independent HTTPS processes, and actual databases."""

import asyncio
import secrets
from collections.abc import AsyncIterator
from http import HTTPStatus
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import pytest
import pytest_asyncio
from pydantic import SecretStr
from sqlalchemy import delete, func, select

from federated_identity.cli.architecture_probe import ArchitectureStack, architecture_stack
from federated_identity.cli.login_probe import (
    credential_challenge,
    seeded_user,
    submit_password,
    verify_login_on_stack,
)
from federated_identity.cli.phase0 import process_settings
from federated_identity.common.persistence.sessions import BrowserSessionRow
from federated_identity.common.security.model import Assurance
from federated_identity.common.settings.policy import SystemClock, verifier_digest
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.repositories.browser import LoginChallengeRow
from federated_identity.idp.repositories.security_tables import (
    AuthenticationEventRow,
    AuthenticationEvidenceRow,
    FederationGrantRow,
)
from federated_identity.idp.repositories.tables import AuthorizationCodeRow
from federated_identity.idp.repositories.throttling import AuthenticationLimitRow
from federated_identity.idp.repositories.users import UserRow
from federated_identity.idp.schemas.users import SeededUser
from federated_identity.sp.protocol.oidc import InvalidIdToken, validate_id_token
from federated_identity.sp.repositories.security import SpSecurityRepository
from federated_identity.sp.repositories.security_tables import SpAuthenticationRow
from federated_identity.sp.repositories.transactions import AuthorizationTransactionRow
from tests.browser_helpers import (
    assertion,
    complete_sso,
    login_at_idp,
    runtime_assets,
    runtime_database,
    runtime_rp,
    sso_callback,
    start_sp_login,
)
from tests.helpers import ASSERTION_TYPE, callback_code

pytestmark = [pytest.mark.integration, pytest.mark.asyncio(loop_scope="module")]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def login_stack() -> AsyncIterator[ArchitectureStack]:
    async with architecture_stack() as stack:
        yield stack


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def alice(login_stack: ArchitectureStack) -> SeededUser:
    return await seeded_user(login_stack)


@pytest_asyncio.fixture(autouse=True, loop_scope="module")
async def isolated_authentication_budgets(login_stack: ArchitectureStack) -> None:
    # This module shares real processes and one account across independent cases.
    # Keep each case's full production budget without inheriting prior attempts;
    # budgets still persist across requests/restarts within the case itself.
    database = await runtime_database(login_stack, ServiceId.IDP)
    try:
        async with database.sessions() as session:
            async with session.begin():
                await session.execute(delete(AuthenticationLimitRow))
    finally:
        await database.dispose()


async def test_deployed_credential_login_probe(login_stack: ArchitectureStack) -> None:
    result = await verify_login_on_stack(login_stack)
    assert result["sso_without_second_password"]
    assert result["independent_opaque_sessions"]
    assert result["callback_replay_rejected"]


async def test_browser_sso_commits_one_event_and_separate_sp_evidence(
    login_stack: ArchitectureStack, alice: SeededUser
) -> None:
    stack = login_stack
    async with stack.client() as browser:
        form = await browser.get(await start_sp_login(stack, browser))
        assert form.status_code == HTTPStatus.OK
        old_idp = browser.cookies.get("__Host-fid-idp")
        old_a = browser.cookies.get("__Host-fid-sp-a")
        authorized = await submit_password(browser, stack.issuer, form, alice)
        assert authorized.status_code == HTTPStatus.FOUND
        callback = authorized.headers["location"]
        finished = await browser.get(callback)
        assert finished.status_code == HTTPStatus.SEE_OTHER and finished.headers["location"] == "/"
        a = (await browser.get(f"{stack.origin(ServiceId.SP_A)}/account")).json()
        b = (await complete_sso(stack, browser, ServiceId.SP_B)).json()
        idp = (await browser.get(f"{stack.issuer}/account")).json()
        assert a["subject"] == b["subject"] == idp["subject"] == alice.subject
        assert idp["username"] == "alice"
        assert a["sid"] == b["sid"] == idp["sid"]
        assert a["auth_time"] == b["auth_time"] == idp["auth_time"]
        assert a["acr"] == b["acr"] == Assurance.PASSWORD.value
        assert a["amr"] == b["amr"] == ["pwd"]
        assert a["service"] == "sp-a" and b["service"] == "sp-b"
        cookies = {
            service: browser.cookies.get(process_settings(stack, service).cookie_name)
            for service in (ServiceId.IDP, ServiceId.SP_A, ServiceId.SP_B)
        }
        assert len(set(cookies.values())) == 3
        assert cookies[ServiceId.IDP] != old_idp and cookies[ServiceId.SP_A] != old_a
        for service in (ServiceId.IDP, ServiceId.SP_A, ServiceId.SP_B):
            home = await browser.get(stack.origin(service))
            assert home.status_code == HTTPStatus.OK and alice.subject in home.text
            assert "Not signed in" not in home.text
            assert home.headers["cache-control"] == "no-store"
            assert home.headers["referrer-policy"] == "no-referrer"
            assert "frame-ancestors 'none'" in home.headers["content-security-policy"]
        database = await runtime_database(stack, ServiceId.IDP)
        try:
            async with database.sessions() as session:
                events = list(
                    await session.scalars(
                        select(AuthenticationEventRow).where(
                            AuthenticationEventRow.session_id == a["sid"]
                        )
                    )
                )
                grants = list(
                    await session.scalars(
                        select(FederationGrantRow).where(FederationGrantRow.session_id == a["sid"])
                    )
                )
                assert len(events) == 1 and events[0].methods == ["pwd"]
                assert {grant.client_id for grant in grants} == {"sp-a", "sp-b"}
                assert len(grants) == 2 and len({grant.grant_id for grant in grants}) == 2
                for grant in grants:
                    evidence = (
                        await session.scalars(
                            select(AuthenticationEvidenceRow).where(
                                AuthenticationEvidenceRow.grant_id == grant.grant_id
                            )
                        )
                    ).one()
                    assert evidence.signing_key_id == grant.root_signing_key_id
                assert await session.get(BrowserSessionRow, verifier_digest(str(old_idp))) is None
        finally:
            await database.dispose()
        for service in (ServiceId.SP_A, ServiceId.SP_B):
            assets = await runtime_assets(stack, service)
            database = await runtime_database(stack, service)
            try:
                cookie = SecretStr(str(cookies[service]))
                loaded = await SpSecurityRepository(database, assets.envelope).load(cookie)
                assert (
                    loaded is not None and loaded[0].authentication.event_id == events[0].event_id
                )
                assert loaded[0].client_id == service.value and loaded[0].subject == alice.subject
                async with database.sessions() as session:
                    row = await session.get(
                        SpAuthenticationRow, verifier_digest(cookie.get_secret_value())
                    )
                    assert row is not None and row.encrypted_refresh_token is not None
                    assert loaded[1].get_secret_value().encode() not in row.encrypted_access_token
                    payload = assets.envelope.decrypt(
                        row.encrypted_refresh_token, purpose="sp-refresh-token"
                    )
                    assert isinstance(payload.get("token"), str)
                    refresh = SecretStr(str(payload["token"]))
                    assert refresh != loaded[1]
                    assert refresh.get_secret_value().encode() not in row.encrypted_refresh_token
                    if service == ServiceId.SP_A:
                        assert (
                            await session.get(BrowserSessionRow, verifier_digest(str(old_a)))
                            is None
                        )
                assert loaded[1].get_secret_value() not in finished.text
            finally:
                await database.dispose()
        for service, old in ((ServiceId.IDP, old_idp), (ServiceId.SP_A, old_a)):
            response = await browser.get(
                f"{stack.origin(service)}/account",
                headers={"Cookie": f"{process_settings(stack, service).cookie_name}={old}"},
            )
            assert response.status_code == HTTPStatus.UNAUTHORIZED


async def test_pending_forms_transactions_sessions_and_replay_survive_restart(
    login_stack: ArchitectureStack, alice: SeededUser
) -> None:
    stack = login_stack
    async with stack.client() as browser:
        form = await browser.get(await start_sp_login(stack, browser))
        old_idp = browser.cookies.get("__Host-fid-idp")
        await stack.stop(ServiceId.IDP)
        await stack.start(ServiceId.IDP)
        authorized = await submit_password(browser, stack.issuer, form, alice)
        assert authorized.status_code == HTTPStatus.FOUND
        callback = authorized.headers["location"]
        await stack.stop(ServiceId.SP_A)
        await stack.start(ServiceId.SP_A)
        assert (await browser.get(callback)).status_code == HTTPStatus.SEE_OTHER
        await complete_sso(stack, browser, ServiceId.SP_B)
        before = {cookie.name: cookie.value for cookie in browser.cookies.jar}
        for service in (ServiceId.IDP, ServiceId.SP_A, ServiceId.SP_B):
            await stack.stop(service)
            await stack.start(service)
            account = await browser.get(f"{stack.origin(service)}/account")
            assert (
                account.status_code == HTTPStatus.OK and account.json()["subject"] == alice.subject
            )
        assert {cookie.name: cookie.value for cookie in browser.cookies.jar} == before
        assert (await browser.get(callback)).status_code == HTTPStatus.BAD_REQUEST
        replay = await browser.post(
            f"{stack.issuer}/login",
            headers={"Origin": stack.issuer, "Cookie": f"__Host-fid-idp={old_idp}"},
            data={
                "csrf": credential_challenge(form.text).get_secret_value(),
                "username": alice.username,
                "password": alice.password.get_secret_value(),
            },
        )
        assert replay.status_code == HTTPStatus.FORBIDDEN


@pytest.mark.parametrize("case", ["client", "redirect"])
async def test_authenticated_code_exchange_is_client_and_original_callback_bound(
    login_stack: ArchitectureStack, alice: SeededUser, case: str
) -> None:
    stack = login_stack
    rp = await runtime_rp(stack)
    transaction = rp.begin()
    async with stack.client() as browser:
        await login_at_idp(stack, browser, alice)
        callback = (await browser.get(transaction.authorization_url)).headers["location"]
        service = ServiceId.SP_B if case == "client" else ServiceId.SP_A
        fields = {
            "grant_type": "authorization_code",
            "client_id": service.value,
            "code": callback_code(callback),
            "redirect_uri": transaction.redirect_uri
            if case == "client"
            else f"{transaction.redirect_uri}/",
            "code_verifier": transaction.verifier,
            "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": await assertion(stack, service),
        }
        rejected = await browser.post(f"{stack.issuer}/token", data=fields)
        assert rejected.status_code == HTTPStatus.BAD_REQUEST
        assert rejected.json()["error"] == "invalid_grant"
        database = await runtime_database(stack, ServiceId.IDP)
        try:
            async with database.sessions() as session:
                row = await session.get(
                    AuthorizationCodeRow, verifier_digest(callback_code(callback))
                )
                assert row is not None and row.consumed_at is None
        finally:
            await database.dispose()
        login = await rp.exchange_verified(transaction, callback)
        assert login.claims.aud == "sp-a" and login.claims.sub == alice.subject
        _, keys = await rp.provider()
        other_rp = await runtime_rp(stack, ServiceId.SP_B)
        with pytest.raises(InvalidIdToken):
            validate_id_token(
                login.response,
                settings=other_rp.settings,
                nonce=transaction.nonce,
                keys=keys,
                clock=SystemClock(),
            )


async def test_id_tokens_never_authenticate_sp_or_idp_user_or_operator_endpoints(
    login_stack: ArchitectureStack, alice: SeededUser
) -> None:
    stack = login_stack
    rp = await runtime_rp(stack)
    transaction = rp.begin()
    async with stack.client() as owner:
        await login_at_idp(stack, owner, alice)
        callback = (await owner.get(transaction.authorization_url)).headers["location"]
        login = await rp.exchange_verified(transaction, callback)
    async with stack.client() as attacker:
        for service in (ServiceId.IDP, ServiceId.SP_A, ServiceId.SP_B):
            for headers in (
                {"Authorization": f"Bearer {login.response.id_token}"},
                {
                    "Cookie": (
                        f"{process_settings(stack, service).cookie_name}={login.response.id_token}"
                    )
                },
            ):
                rejected = await attacker.get(f"{stack.origin(service)}/account", headers=headers)
                assert rejected.status_code == HTTPStatus.UNAUTHORIZED
                assert "set-cookie" not in rejected.headers
        other = (await runtime_rp(stack, ServiceId.SP_B)).begin()
        response = await attacker.get(
            other.authorization_url, headers={"Authorization": f"Bearer {login.response.id_token}"}
        )
        assert response.status_code == HTTPStatus.OK
        assert "name='password'" in response.text and "location" not in response.headers
        assert (
            await attacker.get(f"{stack.issuer}/account")
        ).status_code == HTTPStatus.UNAUTHORIZED
        operator = await attacker.get(
            f"{stack.issuer}/admin", headers={"Authorization": f"Bearer {login.response.id_token}"}
        )
        assert operator.status_code == HTTPStatus.SEE_OTHER
        assert operator.headers["location"] == "/admin/login"
        assert "set-cookie" not in operator.headers


async def test_sp_cookie_transplant_does_not_establish_another_service_identity(
    login_stack: ArchitectureStack, alice: SeededUser
) -> None:
    stack = login_stack
    async with stack.client() as browser:
        await login_at_idp(stack, browser, alice)
        await complete_sso(stack, browser)
        cookie = browser.cookies.get("__Host-fid-sp-a")
        for service in (ServiceId.SP_B, ServiceId.IDP):
            for name in ("__Host-fid-sp-a", process_settings(stack, service).cookie_name):
                response = await browser.get(
                    f"{stack.origin(service)}/account", headers={"Cookie": f"{name}={cookie}"}
                )
                assert response.status_code == HTTPStatus.UNAUTHORIZED
        await complete_sso(stack, browser, ServiceId.SP_B)
        assert browser.cookies.get("__Host-fid-sp-a") == cookie
        assert browser.cookies.get("__Host-fid-sp-b") != cookie


@pytest.mark.parametrize(
    "case",
    [
        "missing_state",
        "wrong_state",
        "duplicate_state",
        "duplicate_code",
        "missing_cookie",
        "both_code_and_error",
        "unexpected_nonce",
        "provider_error",
    ],
)
async def test_callback_ambiguity_state_and_cookie_attacks_fail_before_authentication(
    login_stack: ArchitectureStack, alice: SeededUser, case: str
) -> None:
    stack = login_stack
    async with stack.client() as browser:
        await login_at_idp(stack, browser, alice)
        callback = await sso_callback(stack, browser)
        fields = dict(parse_qsl(urlsplit(callback).query))
        cookie = browser.cookies.get("__Host-fid-sp-a")
        headers: dict[str, str] = {}
        if case == "missing_state":
            del fields["state"]
        elif case == "wrong_state":
            fields["state"] = secrets.token_urlsafe(32)
        elif case == "missing_cookie":
            headers["Cookie"] = ""
        elif case == "both_code_and_error":
            fields["error"] = "login_required"
        elif case == "unexpected_nonce":
            fields["nonce"] = secrets.token_urlsafe(32)
        elif case == "provider_error":
            del fields["code"]
            fields.update(
                error="login_required", error_description="<script>hostile provider text</script>"
            )
        query = urlencode(fields)
        if case in {"duplicate_state", "duplicate_code"}:
            name = case.removeprefix("duplicate_")
            query += f"&{name}={fields[name]}"
        rejected = await browser.get(
            f"{stack.origin(ServiceId.SP_A)}/auth/callback?{query}", headers=headers
        )
        assert rejected.status_code == HTTPStatus.BAD_REQUEST
        assert (
            "hostile provider text" not in rejected.text
            and callback_code(callback) not in rejected.text
        )
        assert (
            "set-cookie" not in rejected.headers
            and browser.cookies.get("__Host-fid-sp-a") == cookie
        )
        assert (
            await browser.get(f"{stack.origin(ServiceId.SP_A)}/account")
        ).status_code == HTTPStatus.UNAUTHORIZED
        rightful = await browser.get(callback)
        assert rightful.status_code == (
            HTTPStatus.BAD_REQUEST if case == "provider_error" else HTTPStatus.SEE_OTHER
        )


async def test_callback_cannot_be_transplanted_to_another_browser_or_recipient(
    login_stack: ArchitectureStack, alice: SeededUser
) -> None:
    stack = login_stack
    async with stack.client() as owner, stack.client() as other:
        await login_at_idp(stack, owner, alice)
        callback = await sso_callback(stack, owner)
        await start_sp_login(stack, other)
        assert (await other.get(callback)).status_code == HTTPStatus.BAD_REQUEST
        assert (
            await other.get(f"{stack.origin(ServiceId.SP_A)}/account")
        ).status_code == HTTPStatus.UNAUTHORIZED
        b_callback = await sso_callback(stack, owner, ServiceId.SP_B)
        fields = dict(parse_qsl(urlsplit(b_callback).query))
        fields["code"] = callback_code(callback)
        rejected = await owner.get(
            f"{stack.origin(ServiceId.SP_B)}/auth/callback?{urlencode(fields)}"
        )
        assert rejected.status_code == HTTPStatus.BAD_REQUEST
        assert (
            await owner.get(f"{stack.origin(ServiceId.SP_B)}/account")
        ).status_code == HTTPStatus.UNAUTHORIZED
        assert (await owner.get(callback)).status_code == HTTPStatus.SEE_OTHER
        await complete_sso(stack, owner, ServiceId.SP_B)


@pytest.mark.parametrize(
    "case",
    [
        "nonce",
        "challenge",
        "missing_nonce",
        "missing_challenge",
        "missing_method",
        "plain",
        "missing_state",
    ],
)
async def test_nonce_and_mandatory_pkce_remain_bound_to_the_original_sp_transaction(
    login_stack: ArchitectureStack, alice: SeededUser, case: str
) -> None:
    stack = login_stack
    async with stack.client() as browser:
        await login_at_idp(stack, browser, alice)
        authorization = await start_sp_login(stack, browser)
        fields = dict(parse_qsl(urlsplit(authorization).query))
        if case == "nonce":
            fields["nonce"] = secrets.token_urlsafe(32)
        elif case == "challenge":
            fields["code_challenge"] = secrets.token_urlsafe(32)
        elif case == "missing_nonce":
            del fields["nonce"]
        elif case == "missing_challenge":
            del fields["code_challenge"]
        elif case == "missing_method":
            del fields["code_challenge_method"]
        elif case == "plain":
            fields["code_challenge_method"] = "plain"
        else:
            del fields["state"]
        authorized = await browser.get(f"{stack.issuer}/authorize?{urlencode(fields)}")
        assert authorized.status_code == HTTPStatus.FOUND
        rejected = await browser.get(authorized.headers["location"])
        assert (
            rejected.status_code == HTTPStatus.BAD_REQUEST and "set-cookie" not in rejected.headers
        )
        assert (
            await browser.get(f"{stack.origin(ServiceId.SP_A)}/account")
        ).status_code == HTTPStatus.UNAUTHORIZED
        await complete_sso(stack, browser)


@pytest.mark.parametrize(
    "case", ["foreign_origin", "other_sp", "trailing_slash", "unregistered_client"]
)
async def test_unvalidated_authorization_return_paths_never_reach_a_login_form(
    login_stack: ArchitectureStack, case: str
) -> None:
    stack = login_stack
    async with stack.client() as browser:
        authorization = await start_sp_login(stack, browser)
        fields = dict(parse_qsl(urlsplit(authorization).query))
        if case == "foreign_origin":
            fields["redirect_uri"] = "https://attacker.example/collect"
        elif case == "other_sp":
            fields["redirect_uri"] = process_settings(stack, ServiceId.SP_B).redirect_uri
        elif case == "trailing_slash":
            fields["redirect_uri"] += "/"
        else:
            fields["client_id"] = "sp-c"
        response = await browser.get(f"{stack.issuer}/authorize?{urlencode(fields)}")
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert "location" not in response.headers and "set-cookie" not in response.headers
        assert "name='password'" not in response.text


@pytest.mark.parametrize(
    "case",
    [
        "missing_csrf",
        "wrong_csrf",
        "wrong_origin",
        "missing_origin",
        "duplicate_username",
        "query_continuation",
        "posted_identity",
        "json",
    ],
)
async def test_credential_form_csrf_origin_and_input_contracts_fail_closed(
    login_stack: ArchitectureStack, alice: SeededUser, case: str
) -> None:
    stack = login_stack
    async with stack.client() as browser:
        form = await browser.get(f"{stack.issuer}/login")
        fields = {
            "csrf": credential_challenge(form.text).get_secret_value(),
            "username": alice.username,
            "password": alice.password.get_secret_value(),
        }
        headers = {"Origin": stack.issuer}
        url = f"{stack.issuer}/login"
        if case == "missing_csrf":
            del fields["csrf"]
        elif case == "wrong_csrf":
            fields["csrf"] = secrets.token_urlsafe(32)
        elif case == "wrong_origin":
            headers["Origin"] = stack.origin(ServiceId.SP_B)
        elif case == "missing_origin":
            del headers["Origin"]
        elif case == "query_continuation":
            url += "?next=https%3A%2F%2Fattacker.example%2F"
        elif case == "posted_identity":
            fields["subject"] = alice.subject
        if case == "duplicate_username":
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            rejected = await browser.post(
                url, headers=headers, content=urlencode([*fields.items(), ("username", "bob")])
            )
        elif case == "json":
            rejected = await browser.post(url, headers=headers, json=fields)
        else:
            rejected = await browser.post(url, headers=headers, data=fields)
        assert rejected.status_code in {
            HTTPStatus.BAD_REQUEST,
            HTTPStatus.FORBIDDEN,
            HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
        }
        assert "set-cookie" not in rejected.headers
        assert (await browser.get(f"{stack.issuer}/account")).status_code == HTTPStatus.UNAUTHORIZED
        rightful = await submit_password(browser, stack.issuer, form, alice)
        assert rightful.status_code == HTTPStatus.SEE_OTHER


async def test_login_form_cannot_be_transplanted_to_another_browser(
    login_stack: ArchitectureStack, alice: SeededUser
) -> None:
    stack = login_stack
    async with stack.client() as owner, stack.client() as victim:
        form = await owner.get(f"{stack.issuer}/login")
        await victim.get(f"{stack.issuer}/login")
        rejected = await submit_password(victim, stack.issuer, form, alice)
        assert rejected.status_code == HTTPStatus.FORBIDDEN
        assert (await victim.get(f"{stack.issuer}/account")).status_code == HTTPStatus.UNAUTHORIZED
        assert (
            await submit_password(owner, stack.issuer, form, alice)
        ).status_code == HTTPStatus.SEE_OTHER


async def test_wrong_password_requires_a_fresh_form_and_actual_credential_verification(
    login_stack: ArchitectureStack, alice: SeededUser
) -> None:
    stack = login_stack
    async with stack.client() as browser:
        form = await browser.get(await start_sp_login(stack, browser))
        old = browser.cookies.get("__Host-fid-idp")
        wrong = alice.model_copy(update={"password": SecretStr(secrets.token_urlsafe(32))})
        rejected = await submit_password(browser, stack.issuer, form, wrong)
        assert (
            rejected.status_code == HTTPStatus.UNAUTHORIZED
            and "Invalid username or password" in rejected.text
        )
        assert browser.cookies.get("__Host-fid-idp") == old
        assert credential_challenge(rejected.text) != credential_challenge(form.text)
        assert (await browser.get(f"{stack.issuer}/account")).status_code == HTTPStatus.UNAUTHORIZED
        assert (
            await submit_password(browser, stack.issuer, form, alice)
        ).status_code == HTTPStatus.FORBIDDEN
        authorized = await submit_password(browser, stack.issuer, rejected, alice)
        assert authorized.status_code == HTTPStatus.FOUND
        assert (
            await browser.get(authorized.headers["location"])
        ).status_code == HTTPStatus.SEE_OTHER


async def test_concurrent_credential_form_submission_authenticates_at_most_once(
    login_stack: ArchitectureStack, alice: SeededUser
) -> None:
    stack = login_stack
    database = await runtime_database(stack, ServiceId.IDP)
    try:
        async with database.sessions() as session:
            before = await session.scalar(select(func.count()).select_from(AuthenticationEventRow))
        async with stack.client() as browser:
            form = await browser.get(f"{stack.issuer}/login")
            cookie = browser.cookies.get("__Host-fid-idp")
            fields = {
                "csrf": credential_challenge(form.text).get_secret_value(),
                "username": alice.username,
                "password": alice.password.get_secret_value(),
            }
            responses = await asyncio.gather(
                *(
                    browser.post(
                        f"{stack.issuer}/login",
                        headers={"Origin": stack.issuer, "Cookie": f"__Host-fid-idp={cookie}"},
                        data=fields,
                    )
                    for _ in range(6)
                )
            )
            assert sorted(response.status_code for response in responses) == [
                303,
                403,
                403,
                403,
                403,
                403,
            ]
        async with database.sessions() as session:
            after = await session.scalar(select(func.count()).select_from(AuthenticationEventRow))
        assert before is not None and after == before + 1
    finally:
        await database.dispose()


async def test_concurrent_callback_consumption_establishes_at_most_one_local_session(
    login_stack: ArchitectureStack, alice: SeededUser
) -> None:
    stack = login_stack
    database = await runtime_database(stack, ServiceId.SP_A)
    try:
        async with database.sessions() as session:
            before = await session.scalar(select(func.count()).select_from(SpAuthenticationRow))
        async with stack.client() as browser:
            await login_at_idp(stack, browser, alice)
            callback = await sso_callback(stack, browser)
            cookie = browser.cookies.get("__Host-fid-sp-a")
            responses = await asyncio.gather(
                *(
                    browser.get(callback, headers={"Cookie": f"__Host-fid-sp-a={cookie}"})
                    for _ in range(6)
                )
            )
            assert sorted(response.status_code for response in responses) == [
                303,
                400,
                400,
                400,
                400,
                400,
            ]
            protected = await asyncio.gather(
                *(browser.get(f"{stack.origin(ServiceId.SP_A)}/account") for _ in range(6))
            )
            assert all(response.status_code == HTTPStatus.OK for response in protected)
        async with database.sessions() as session:
            after = await session.scalar(select(func.count()).select_from(SpAuthenticationRow))
        assert before is not None and after == before + 1
    finally:
        await database.dispose()


@pytest.mark.parametrize("case", ["login_form", "sp_transaction"])
async def test_expired_persisted_browser_transactions_cannot_authenticate(
    login_stack: ArchitectureStack, alice: SeededUser, case: str
) -> None:
    stack = login_stack
    async with stack.client() as browser:
        if case == "login_form":
            form = await browser.get(f"{stack.issuer}/login")
            database = await runtime_database(stack, ServiceId.IDP)
            try:
                async with database.sessions() as session:
                    row = await session.get(
                        LoginChallengeRow,
                        verifier_digest(credential_challenge(form.text).get_secret_value()),
                    )
                    assert row is not None
                    row.created_at = SystemClock().now() - 600
                    row.expires_at = SystemClock().now() - 1
                    await session.commit()
            finally:
                await database.dispose()
            assert (
                await submit_password(browser, stack.issuer, form, alice)
            ).status_code == HTTPStatus.FORBIDDEN
        else:
            await login_at_idp(stack, browser, alice)
            callback = await sso_callback(stack, browser)
            state = dict(parse_qsl(urlsplit(callback).query))["state"]
            database = await runtime_database(stack, ServiceId.SP_A)
            try:
                async with database.sessions() as session:
                    transaction_row = await session.get(
                        AuthorizationTransactionRow, verifier_digest(state)
                    )
                    assert transaction_row is not None
                    transaction_row.expires_at = SystemClock().now() - 1
                    await session.commit()
            finally:
                await database.dispose()
            assert (await browser.get(callback)).status_code == HTTPStatus.BAD_REQUEST
            assert (
                await browser.get(f"{stack.origin(ServiceId.SP_A)}/account")
            ).status_code == HTTPStatus.UNAUTHORIZED


@pytest.mark.parametrize("parameters", [{"prompt": "login"}, {"max_age": "0"}])
async def test_explicit_freshness_demands_require_password_and_preserve_subject(
    login_stack: ArchitectureStack, alice: SeededUser, parameters: dict[str, str]
) -> None:
    stack = login_stack
    bob = await seeded_user(stack, "bob")
    async with stack.client() as browser:
        await login_at_idp(stack, browser, alice)
        original = (await browser.get(f"{stack.issuer}/account")).json()
        authorization = urlsplit(await start_sp_login(stack, browser))
        fields = {**dict(parse_qsl(authorization.query)), **parameters}
        form = await browser.get(urlunsplit(authorization._replace(query=urlencode(fields))))
        assert form.status_code == HTTPStatus.OK and "name='password'" in form.text
        substitution = await submit_password(browser, stack.issuer, form, bob)
        assert substitution.status_code == HTTPStatus.UNAUTHORIZED
        assert (await browser.get(f"{stack.issuer}/account")).json()["subject"] == alice.subject
        authorized = await submit_password(browser, stack.issuer, substitution, alice)
        assert authorized.status_code == HTTPStatus.FOUND
        assert (
            await browser.get(authorized.headers["location"])
        ).status_code == HTTPStatus.SEE_OTHER
        idp = (await browser.get(f"{stack.issuer}/account")).json()
        assert idp["sid"] == original["sid"] and idp["subject"] == original["subject"]
        assert idp["auth_time"] >= original["auth_time"] and idp["amr"] == ["pwd"]


async def test_prompt_none_cannot_silently_authenticate_an_anonymous_browser(
    login_stack: ArchitectureStack,
) -> None:
    stack = login_stack
    async with stack.client() as browser:
        authorization = urlsplit(await start_sp_login(stack, browser))
        fields = {**dict(parse_qsl(authorization.query)), "prompt": "none"}
        response = await browser.get(urlunsplit(authorization._replace(query=urlencode(fields))))
        assert response.status_code == HTTPStatus.FOUND
        assert (
            dict(parse_qsl(urlsplit(response.headers["location"]).query))["error"]
            == "login_required"
        )
        assert "set-cookie" not in response.headers and "name='password'" not in response.text
        assert (
            await browser.get(response.headers["location"])
        ).status_code == HTTPStatus.BAD_REQUEST


async def test_disabled_account_cannot_login_or_reuse_an_existing_idp_browser_session(
    login_stack: ArchitectureStack, alice: SeededUser
) -> None:
    stack = login_stack
    database = await runtime_database(stack, ServiceId.IDP)
    try:
        async with stack.client() as owner, stack.client() as fresh:
            await login_at_idp(stack, owner, alice)
            async with database.sessions() as session:
                row = await session.get(UserRow, alice.subject)
                assert row is not None
                row.enabled = False
                await session.commit()
            assert (
                await owner.get(f"{stack.issuer}/account")
            ).status_code == HTTPStatus.UNAUTHORIZED
            form = await fresh.get(f"{stack.issuer}/login")
            assert (
                await submit_password(fresh, stack.issuer, form, alice)
            ).status_code == HTTPStatus.UNAUTHORIZED
            form = await owner.get(await start_sp_login(stack, owner))
            assert form.status_code == HTTPStatus.OK and "name='password'" in form.text
    finally:
        async with database.sessions() as session:
            row = await session.get(UserRow, alice.subject)
            assert row is not None
            row.enabled = True
            await session.commit()
        await database.dispose()


async def test_idp_outage_blocks_authenticated_pages_without_discarding_sp_cookie(
    login_stack: ArchitectureStack, alice: SeededUser
) -> None:
    stack = login_stack
    async with stack.client() as browser:
        await login_at_idp(stack, browser, alice)
        await complete_sso(stack, browser)
        cookie = browser.cookies.get("__Host-fid-sp-a")
        await stack.stop(ServiceId.IDP)
        try:
            response = await browser.get(f"{stack.origin(ServiceId.SP_A)}/account")
            assert response.status_code == HTTPStatus.SERVICE_UNAVAILABLE
            assert "set-cookie" not in response.headers
        finally:
            await stack.start(ServiceId.IDP)
        assert (
            await browser.get(f"{stack.origin(ServiceId.SP_A)}/account")
        ).status_code == HTTPStatus.OK
        assert browser.cookies.get("__Host-fid-sp-a") == cookie
