"""Both live containment paths share factories, TLS PostgreSQL, and injected time."""

import asyncio
import re
import secrets
from collections.abc import AsyncIterator
from http import HTTPStatus

import httpx2 as httpx
import pytest
import pytest_asyncio
from joserfc import jwt
from pydantic import SecretStr
from sqlalchemy import event, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from federated_identity.cli.bootstrap import bootstrap_assets
from federated_identity.cli.credentials import replace_client_key
from federated_identity.cli.databases import initialize_databases
from federated_identity.cli.operator import OperatorClient, OperatorClientError
from federated_identity.cli.phase0 import process_settings
from federated_identity.common.security.model import (
    IssuedCredentials,
    KeyState,
    LoginEvidence,
    SecurityDenied,
)
from federated_identity.common.security.oidc import VerifiedLogin, login_header, validate_id_token
from federated_identity.common.security.secrets import load_runtime_secrets
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.repositories.operator import OperatorRow
from federated_identity.idp.repositories.security import SecurityUnitOfWork
from federated_identity.idp.repositories.security_tables import FederationGrantRow, SigningTrustRow
from federated_identity.idp.repositories.signing import SigningAuditRow
from federated_identity.idp.repositories.tables import ClientRow
from federated_identity.idp.services.clients import ClientAdministration
from federated_identity.idp.services.provisioning import load_seeded_operator
from federated_identity.idp.services.signing import SigningKeyAdministration
from tests.lifecycle_helpers import LifecycleLab, action_challenge, lifecycle_lab, next_scenario

pytestmark = [pytest.mark.integration, pytest.mark.asyncio(loop_scope="module")]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def containment_runtime() -> AsyncIterator[LifecycleLab]:
    async with lifecycle_lab() as lab:
        yield lab


@pytest_asyncio.fixture(loop_scope="module")
async def contained(containment_runtime: LifecycleLab) -> LifecycleLab:
    next_scenario(containment_runtime)
    return containment_runtime


async def operator(lab: LifecycleLab) -> OperatorClient:
    seed = await asyncio.to_thread(
        load_seeded_operator, lab.stack.root / "idp", lab.assets[ServiceId.IDP].envelope
    )
    admin = OperatorClient(lab.stack.issuer, lab.stack.tls, transport=lab.transport)
    await admin.login(seed.username, seed.password)
    return admin


async def recover_client(lab: LifecycleLab, admin: OperatorClient) -> None:
    current = (await admin.inspect("sp-a"))[0]
    public = await asyncio.to_thread(
        replace_client_key,
        process_settings(lab.stack, ServiceId.SP_A),
        expected_key_id=current.key_id,
        expected_version=current.registration_version,
    )
    changed = await admin.replace("sp-a", public)
    assert not changed.enabled
    lab.assets[ServiceId.SP_A] = await asyncio.to_thread(
        load_runtime_secrets, process_settings(lab.stack, ServiceId.SP_A)
    )
    await lab.restart(ServiceId.SP_A)
    await admin.disable("sp-a", changed.registration_version, enabled=True)


async def captured_issuance(
    lab: LifecycleLab, browser: httpx.AsyncClient, monkeypatch: pytest.MonkeyPatch
) -> tuple[VerifiedLogin, IssuedCredentials]:
    original = lab.idp().security.issue_grant_in
    captured: list[IssuedCredentials] = []

    async def capture(
        work: SecurityUnitOfWork,
        evidence: LoginEvidence,
        *,
        access_token: SecretStr,
        refresh_token: SecretStr | None = None,
    ) -> IssuedCredentials:
        result = await original(
            work, evidence, access_token=access_token, refresh_token=refresh_token
        )
        captured.append(result)
        return result

    transaction = lab.sp().oidc.begin()
    callback = (await browser.get(transaction.authorization_url)).headers["location"]
    with monkeypatch.context() as patch:
        patch.setattr(lab.idp().security, "issue_grant_in", capture)
        login = await lab.sp().oidc.exchange_verified(transaction, callback)
    return login, captured[0]


async def test_active_signer_containment_overrides_cached_signatures_and_survives_restart(
    contained: LifecycleLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab = contained
    admin = await operator(lab)
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        await lab.sign_in(browser, ServiceId.SP_B)
        previous, credentials = await captured_issuance(lab, browser, monkeypatch)
        cached = await lab.sp().oidc.jwks.get()
        old = previous.evidence.signing_key_id
        prepared = await admin.prepare_key()
        result = await admin.contain_key(old, prepared.key_id, old)
        assert result.compromised.state == KeyState.REVOKED
        assert result.active.key_id == prepared.key_id
        assert result.revoked_grants >= 3
        assert old in {key.kid for key in cached.keys}
        validated = validate_id_token(
            previous.response,
            settings=lab.sp().oidc.settings,
            nonce=previous.claims.nonce,
            keys=cached,
            clock=lab.clock,
        )
        assert validated.jti == previous.claims.jti
        with pytest.raises(SecurityDenied):
            await lab.sp().security.establish_login(previous)
        with pytest.raises(SecurityDenied):
            await lab.idp().security.rotate_refresh(
                credentials.refresh_token, authenticated_client="sp-a"
            )
        for service in (ServiceId.SP_A, ServiceId.SP_B):
            assert (await lab.account(browser, service)).status_code == HTTPStatus.UNAUTHORIZED
        public = await lab.idp().oidc.keys.public_jwks()
        assert old not in {key.kid for key in public.keys}
        async with lab.idp().oidc.database.sessions() as session:
            audit = await session.scalar(
                select(SigningAuditRow).where(
                    SigningAuditRow.key_id == old, SigningAuditRow.action == "contain"
                )
            )
            assert audit is not None and audit.replacement_key_id == prepared.key_id
            assert audit.previous_active_key_id == old
        await lab.restart(ServiceId.IDP)
        states = {key.key_id: key.state for key in await admin.signing_keys()}
        assert states[old] == KeyState.REVOKED and states[prepared.key_id] == KeyState.ACTIVE
        for service in (ServiceId.SP_A, ServiceId.SP_B):
            await lab.sign_in(browser, service)
    await admin.logout()


async def test_historical_key_containment_preserves_unaffected_client_and_key_lineage(
    contained: LifecycleLab,
) -> None:
    lab = contained
    admin = await operator(lab)
    old = next(key for key in await admin.signing_keys() if key.state == KeyState.ACTIVE)
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        replacement = await admin.prepare_key()
        await admin.activate_key(replacement.key_id, old.key_id)
        await lab.sign_in(browser, ServiceId.SP_B)
        result = await admin.contain_key(old.key_id, replacement.key_id, replacement.key_id)
        assert result.active.key_id == replacement.key_id
        assert (await lab.account(browser)).status_code == HTTPStatus.UNAUTHORIZED
        assert (await lab.account(browser, ServiceId.SP_B)).status_code == HTTPStatus.OK
    await admin.logout()


@pytest.mark.parametrize("case", ["self", "unpublished", "stale"])
async def test_invalid_recovery_never_revokes_current_trust(
    contained: LifecycleLab, case: str
) -> None:
    lab = contained
    admin = await operator(lab)
    old = next(key for key in await admin.signing_keys() if key.state == KeyState.ACTIVE)
    prepared = await admin._request("POST", "/admin/api/signing-keys/prepare", payload={})
    replacement = prepared.json()["key_id"]
    if case != "unpublished":
        await lab.idp().oidc.keys.public_jwks()
    with pytest.raises(OperatorClientError, match="HTTP 409"):
        await admin.contain_key(
            old.key_id,
            old.key_id if case == "self" else replacement,
            "stale-key" if case == "stale" else old.key_id,
        )
    current = next(key for key in await admin.signing_keys() if key.key_id == old.key_id)
    assert current.state == KeyState.ACTIVE
    await admin.logout()


async def test_sp_containment_requires_new_credentials_and_never_revives_old_sessions(
    contained: LifecycleLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab = contained
    admin = await operator(lab)
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        await lab.sign_in(browser, ServiceId.SP_B)
        previous, credentials = await captured_issuance(lab, browser, monkeypatch)
        pending = lab.sp().oidc.begin()
        callback = (await browser.get(pending.authorization_url)).headers["location"]
        current = (await admin.inspect("sp-a"))[0]
        contained_client = await admin.contain_client("sp-a", current.registration_version)
        assert not contained_client.enabled
        assert contained_client.compromised_key_id == current.key_id
        with pytest.raises(OperatorClientError, match="HTTP 409"):
            await admin.disable("sp-a", contained_client.registration_version, enabled=True)
        with pytest.raises(SecurityDenied):
            await lab.idp().security.rotate_refresh(
                credentials.refresh_token, authenticated_client="sp-a"
            )
        old_parameters = lab.token_parameters(pending, callback)
        rejected = await browser.post(f"{lab.stack.issuer}/token", data=old_parameters)
        assert rejected.json()["error"] == "invalid_client"
        assert (await lab.account(browser, ServiceId.SP_B)).status_code == HTTPStatus.OK
        for statement, message in (
            ("UPDATE clients SET enabled=true WHERE client_id='sp-a'", "requires_replacement"),
            (
                "UPDATE clients SET compromised_key_id=NULL WHERE client_id='sp-a'",
                "cannot be cleared",
            ),
        ):
            with pytest.raises(DBAPIError, match=message):
                async with lab.idp().oidc.database.engine.begin() as connection:
                    await connection.execute(text(statement))
        await recover_client(lab, admin)
        assert (await lab.account(browser)).status_code == HTTPStatus.UNAUTHORIZED
        rejected = await browser.post(f"{lab.stack.issuer}/token", data=old_parameters)
        assert rejected.json()["error"] == "invalid_client"
        old_parameters["client_assertion"] = lab.assertion(ServiceId.SP_A, "/token")
        rejected = await browser.post(f"{lab.stack.issuer}/token", data=old_parameters)
        assert rejected.json()["error"] == "invalid_grant"
        assert not (
            await lab.idp().security.check_access(
                SecretStr(previous.response.access_token), authenticated_client="sp-a"
            )
        ).active
        with pytest.raises(SecurityDenied):
            await lab.idp().security.rotate_refresh(
                credentials.refresh_token, authenticated_client="sp-a"
            )
        await asyncio.to_thread(bootstrap_assets, lab.stack.root)
        await initialize_databases(lab.stack.root, host="127.0.0.1", port=lab.stack.postgres_port)
        await lab.restart(ServiceId.IDP)
        after = (await admin.inspect("sp-a"))[0]
        assert after.key_id != current.key_id and after.compromised_key_id == current.key_id
        await lab.sign_in(browser)
    await admin.logout()


@pytest.mark.parametrize("kind", ["key", "client"])
async def test_containment_commit_failure_rolls_back_trust_grants_and_audit(
    contained: LifecycleLab, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab = contained
    admin = await operator(lab)
    active = next(key for key in await admin.signing_keys() if key.state == KeyState.ACTIVE)
    prepared = await admin.prepare_key()
    current = (await admin.inspect("sp-a"))[0]
    original_key_audit = SigningKeyAdministration._audit
    original_client_audit = ClientAdministration._audit

    def key_audit(
        self: SigningKeyAdministration,
        work: SecurityUnitOfWork,
        operator_id: str,
        action: str,
        row: SigningTrustRow,
        previous: str | None = None,
        replacement: str | None = None,
    ) -> None:
        original_key_audit(self, work, operator_id, action, row, previous, replacement)
        if action == "contain":
            work.session.info["fail_containment"] = True

    def client_audit(
        self: ClientAdministration,
        work: SecurityUnitOfWork,
        operator_id: str,
        action: str,
        row: ClientRow,
    ) -> None:
        original_client_audit(self, work, operator_id, action, row)
        if action == "contain":
            work.session.info["fail_containment"] = True

    def fail(session: Session) -> None:
        if session.info.get("fail_containment"):
            raise RuntimeError("Injected containment commit failure")

    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        event.listen(Session, "before_commit", fail)
        try:
            with monkeypatch.context() as patch:
                patch.setattr(SigningKeyAdministration, "_audit", key_audit)
                patch.setattr(ClientAdministration, "_audit", client_audit)
                with pytest.raises(RuntimeError, match="Injected containment"):
                    if kind == "key":
                        await admin.contain_key(active.key_id, prepared.key_id, active.key_id)
                    else:
                        await admin.contain_client("sp-a", current.registration_version)
        finally:
            event.remove(Session, "before_commit", fail)
        assert (await lab.account(browser)).status_code == HTTPStatus.OK
        assert (await admin.inspect("sp-a"))[0] == current
        unchanged = next(key for key in await admin.signing_keys() if key.key_id == active.key_id)
        assert unchanged.state == KeyState.ACTIVE
    await admin.logout()


@pytest.mark.parametrize("kind", ["key", "client"])
async def test_issuance_and_refresh_racing_containment_cannot_restore_revoked_authority(
    contained: LifecycleLab, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab = contained
    admin = await operator(lab)
    active = next(key for key in await admin.signing_keys() if key.state == KeyState.ACTIVE)
    prepared = await admin.prepare_key()
    current = (await admin.inspect("sp-a"))[0]
    async with lab.client() as browser:
        await lab.login(browser)
        _, credentials = await captured_issuance(lab, browser, monkeypatch)
        transactions = [lab.sp().oidc.begin() for _ in range(8)]
        callbacks = [
            (await browser.get(item.authorization_url)).headers["location"] for item in transactions
        ]

        async def exchange(index: int) -> httpx.Response:
            return await browser.post(
                f"{lab.stack.issuer}/token",
                data=lab.token_parameters(transactions[index], callbacks[index]),
            )

        async def refresh() -> IssuedCredentials | None:
            try:
                return await lab.idp().security.rotate_refresh(
                    credentials.refresh_token, authenticated_client="sp-a"
                )
            except SecurityDenied:
                return None

        async def contain() -> None:
            if kind == "key":
                await admin.contain_key(active.key_id, prepared.key_id, active.key_id)
            else:
                await admin.contain_client("sp-a", current.registration_version)

        responses, renewed, _ = await asyncio.gather(
            asyncio.gather(*(exchange(index) for index in range(8))), refresh(), contain()
        )
        for response in responses:
            if response.is_success:
                body = response.json()
                status = await lab.idp().security.check_access(
                    SecretStr(body["access_token"]), authenticated_client="sp-a"
                )
                if status.active:
                    header = login_header(
                        body["id_token"], max_bytes=lab.sp().oidc.settings.policy.max_jwt_bytes
                    )
                    assert kind == "key" and header.kid == prepared.key_id
                    assert status.context is not None
                    assert status.context.evidence.signing_key_id == prepared.key_id
            else:
                assert response.json()["error"] in {"invalid_client", "invalid_grant"}
        if renewed is not None:
            assert not (
                await lab.idp().security.check_access(
                    renewed.access_token, authenticated_client="sp-a"
                )
            ).active
        with pytest.raises(SecurityDenied):
            await lab.idp().security.rotate_refresh(
                credentials.refresh_token, authenticated_client="sp-a"
            )
        async with lab.idp().oidc.database.sessions() as session:
            affected = list(
                await session.scalars(
                    select(FederationGrantRow).where(
                        FederationGrantRow.root_signing_key_id == active.key_id
                        if kind == "key"
                        else FederationGrantRow.client_id == "sp-a"
                    )
                )
            )
            assert affected and all(grant.revoked_at is not None for grant in affected)
        if kind == "client":
            await recover_client(lab, admin)
    await admin.logout()


@pytest.mark.parametrize("case", ["unissued", "altered_subject"])
async def test_vetted_forged_token_cannot_create_a_session_without_exact_committed_evidence(
    contained: LifecycleLab,
    case: str,
) -> None:
    lab = contained
    admin = await operator(lab)
    active = next(key for key in await admin.signing_keys() if key.state == KeyState.ACTIVE)
    await admin.logout()
    signer = lab.idp().oidc.keys._private[active.key_id]
    delegate = lab.transport

    class ForgedResponse(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            response = await delegate.handle_async_request(request)
            if request.url.path != "/token" or not response.is_success:
                return response
            await response.aread()
            body = response.json()
            original = jwt.decode(body["id_token"], signer.key, algorithms=["RS256"])
            claims = dict(original.claims)
            claims["jti" if case == "unissued" else "sub"] = (
                secrets.token_urlsafe(24) if case == "unissued" else "user:forged"
            )
            body["id_token"] = jwt.encode(original.header, claims, signer.key, algorithms=["RS256"])
            return httpx.Response(HTTPStatus.OK, json=body)

    original_transport = lab.sp().oidc.transport
    async with lab.client() as browser:
        await lab.login(browser)
        start = await browser.get(f"{lab.stack.origin(ServiceId.SP_A)}/auth/login")
        callback = (await browser.get(start.headers["location"])).headers["location"]
        lab.sp().oidc.transport = ForgedResponse()
        try:
            rejected = await browser.get(callback)
            assert rejected.status_code == HTTPStatus.BAD_REQUEST
            assert (await lab.account(browser)).status_code == HTTPStatus.UNAUTHORIZED
        finally:
            lab.sp().oidc.transport = original_transport


async def test_containment_permissions_and_browser_intentions_are_distinct_and_one_use(
    contained: LifecycleLab,
) -> None:
    lab = contained
    admin = await operator(lab)
    seed = await asyncio.to_thread(
        load_seeded_operator, lab.stack.root / "idp", lab.assets[ServiceId.IDP].envelope
    )
    old = next(key for key in await admin.signing_keys() if key.state == KeyState.ACTIVE)
    prepared = await admin.prepare_key()
    async with lab.client() as browser:
        form = await browser.get(f"{lab.stack.issuer}/admin/login")
        await browser.post(
            f"{lab.stack.issuer}/admin/login",
            headers={"Origin": lab.stack.issuer},
            data={
                "csrf": action_challenge(form),
                "username": seed.username,
                "password": seed.password.get_secret_value(),
            },
        )
        page = await browser.get(f"{lab.stack.issuer}/admin/signing-keys")
        wrong = action_challenge(page, "Prepare signing key")
        path = f"{lab.stack.issuer}/admin/signing-keys/{old.key_id}/contain"
        data = {
            "csrf": wrong,
            "replacement_key_id": prepared.key_id,
            "expected_active_key_id": old.key_id,
        }
        response = await browser.post(path, headers={"Origin": lab.stack.issuer}, data=data)
        assert response.status_code == HTTPStatus.FORBIDDEN
        for origin in ("https://sp-a.localhost", "null"):
            response = await browser.post(path, headers={"Origin": origin}, data=data)
            assert response.status_code == HTTPStatus.FORBIDDEN
        match = re.search(
            rf"action='/admin/signing-keys/{re.escape(old.key_id)}/contain'>.*?"
            r"name='csrf' value='([^']+)'",
            page.text,
        )
        assert match is not None
        data["csrf"] = match[1]
        wrong_target = f"{lab.stack.issuer}/admin/signing-keys/{prepared.key_id}/contain"
        response = await browser.post(wrong_target, headers={"Origin": lab.stack.issuer}, data=data)
        assert response.status_code == HTTPStatus.FORBIDDEN
        response = await browser.post(path, headers={"Origin": lab.stack.issuer}, data=data)
        assert response.status_code == HTTPStatus.SEE_OTHER
        response = await browser.post(path, headers={"Origin": lab.stack.issuer}, data=data)
        assert response.status_code == HTTPStatus.FORBIDDEN
    try:
        async with lab.idp().oidc.database.sessions() as session:
            row = await session.get(OperatorRow, seed.operator_id)
            assert row is not None
            permissions = row.permissions[:]
            row.permissions = ["clients:read", "keys:read"]
            await session.commit()
        reader = await operator(lab)
        current = (await reader.inspect("sp-a"))[0]
        with pytest.raises(OperatorClientError, match="HTTP 403"):
            await reader.contain_client("sp-a", current.registration_version)
        with pytest.raises(OperatorClientError, match="HTTP 403"):
            await reader.contain_key(old.key_id, prepared.key_id, old.key_id)
        await reader.logout()
    finally:
        async with lab.idp().oidc.database.sessions() as session:
            row = await session.get(OperatorRow, seed.operator_id)
            assert row is not None
            row.permissions = permissions
            await session.commit()
