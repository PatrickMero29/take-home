"""Operator trust and live onboarding share one role-owned TLS database deployment."""

import asyncio
import dataclasses
from collections.abc import AsyncIterator
from http import HTTPStatus

import pytest
import pytest_asyncio
from pydantic import SecretStr
from sqlalchemy import event
from sqlalchemy.orm import Session

from federated_identity.cli.bootstrap import bootstrap_assets
from federated_identity.cli.databases import initialize_databases
from federated_identity.cli.operator import OperatorClient, client_metadata
from federated_identity.cli.phase0 import process_settings
from federated_identity.common.security.actions import BrowserActionPurpose
from federated_identity.common.security.keys import SigningKey
from federated_identity.common.security.passwords import hash_password
from federated_identity.common.security.secrets import load_runtime_secrets
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.repositories.operator import OperatorRow
from federated_identity.idp.repositories.security import SecurityUnitOfWork
from federated_identity.idp.repositories.tables import ClientRow
from federated_identity.idp.schemas.clients import (
    ClientCreate,
    ClientCredentialReplacement,
    ClientUpdate,
)
from federated_identity.idp.schemas.operator import OperatorAuthorization, OperatorChannel
from federated_identity.idp.services.clients import ClientAdministration
from federated_identity.idp.services.provisioning import load_seeded_operator
from federated_identity.sp.services.revocation import AuthenticatedGrantChecker
from tests.lifecycle_helpers import LifecycleLab, action_challenge, lifecycle_lab, next_scenario

pytestmark = [pytest.mark.integration, pytest.mark.asyncio(loop_scope="module")]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def shared_operators() -> AsyncIterator[LifecycleLab]:
    async with lifecycle_lab() as lab:
        lab.assets[ServiceId.SP_C] = await asyncio.to_thread(
            load_runtime_secrets, process_settings(lab.stack, ServiceId.SP_C)
        )
        await lab.restart(ServiceId.SP_C)
        yield lab


@pytest_asyncio.fixture(loop_scope="module")
async def ops(shared_operators: LifecycleLab) -> LifecycleLab:
    next_scenario(shared_operators)
    return shared_operators


async def operator_client(lab: LifecycleLab) -> OperatorClient:
    seed = await asyncio.to_thread(
        load_seeded_operator, lab.stack.root / "idp", lab.assets[ServiceId.IDP].envelope
    )
    client = OperatorClient(lab.stack.issuer, lab.stack.tls, transport=lab.transport)
    await client.login(seed.username, seed.password)
    return client


async def test_register_sp_c_on_running_idp_while_a_and_b_continue(ops: LifecycleLab) -> None:
    async with ops.client() as browser:
        await ops.login(browser)
        await ops.sign_in(browser)
        await ops.sign_in(browser, ServiceId.SP_B)
        current_idp = ops.transport.apps[ServiceId.IDP.hostname]
        transaction = ops.sp(ServiceId.SP_C).oidc.begin()
        unregistered = await browser.get(transaction.authorization_url)
        assert unregistered.status_code == HTTPStatus.BAD_REQUEST
        assert "location" not in unregistered.headers
        unauthorized = await browser.post(
            f"{ops.stack.issuer}/token",
            data={
                "grant_type": "authorization_code",
                "code": "unregistered-client-code",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": ops.assertion(ServiceId.SP_C, "/token"),
            },
        )
        assert unauthorized.json()["error"] == "invalid_client"
        operator = await operator_client(ops)
        try:
            public = await asyncio.to_thread(
                client_metadata, process_settings(ops.stack, ServiceId.SP_C)
            )
            registered = await operator.register(public)
            assert registered.client_id == "sp-c" and registered.registration_version == 1
            await ops.sign_in(browser, ServiceId.SP_C)
            for service in (ServiceId.SP_A, ServiceId.SP_B, ServiceId.SP_C):
                response = await ops.account(browser, service)
                assert (
                    response.status_code == HTTPStatus.OK
                    and response.json()["subject"] == ops.user.subject
                )
            assert ops.transport.apps[ServiceId.IDP.hostname] is current_idp
            inspected = (await operator.inspect("sp-c"))[0]
            assert inspected == registered
        finally:
            await operator.logout()


@pytest.mark.parametrize(
    "kind",
    [
        "user_cookie",
        "renamed_user_cookie",
        "sp_cookie",
        "client_assertion",
        "id_token",
        "user_password",
    ],
)
async def test_federation_credentials_never_acquire_operator_authority(
    ops: LifecycleLab, kind: str
) -> None:
    async with ops.client() as browser:
        await ops.login(browser)
        await ops.sign_in(browser)
        headers: dict[str, str] = {"Cookie": ""}
        if kind == "user_cookie":
            headers["Cookie"] = f"__Host-fid-idp={browser.cookies.get('__Host-fid-idp')}"
        elif kind == "renamed_user_cookie":
            headers["Cookie"] = f"__Host-fid-operator={browser.cookies.get('__Host-fid-idp')}"
        elif kind == "sp_cookie":
            headers["Authorization"] = f"Bearer {browser.cookies.get('__Host-fid-sp-a')}"
        elif kind == "client_assertion":
            headers["Authorization"] = (
                f"Bearer {ops.assertion(ServiceId.SP_A, '/admin/api/clients')}"
            )
        elif kind == "id_token":
            transaction = ops.sp().oidc.begin()
            callback = (await browser.get(transaction.authorization_url)).headers["location"]
            login = await ops.sp().oidc.exchange_verified(transaction, callback)
            headers["Authorization"] = f"Bearer {login.response.id_token}"
        else:
            result = await browser.post(
                f"{ops.stack.issuer}/admin/api/session",
                json={
                    "username": ops.user.username,
                    "password": ops.user.password.get_secret_value(),
                },
            )
            assert result.status_code == HTTPStatus.UNAUTHORIZED
        result = await browser.get(f"{ops.stack.issuer}/admin/api/clients", headers=headers)
        assert result.status_code == HTTPStatus.UNAUTHORIZED
        assert "set-cookie" not in result.headers


async def test_operator_permissions_are_distinct_from_authentication_and_checked_fresh(
    ops: LifecycleLab,
) -> None:
    seed = await asyncio.to_thread(
        load_seeded_operator, ops.stack.root / "idp", ops.assets[ServiceId.IDP].envelope
    )
    old = await operator_client(ops)
    database = ops.idp().oidc.database
    try:
        async with database.sessions() as session:
            row = await session.get(OperatorRow, seed.operator_id)
            assert row is not None
            original = row.permissions[:]
            row.permissions = ["clients:read"]
            await session.commit()
        async with ops.client() as requester:
            assert old.token is not None
            expired = await requester.get(
                f"{ops.stack.issuer}/admin/api/clients",
                headers={"Authorization": f"Bearer {old.token.get_secret_value()}"},
            )
            assert expired.status_code == HTTPStatus.UNAUTHORIZED
        reader = await operator_client(ops)
        try:
            assert {client.client_id for client in await reader.inspect()} >= {"sp-a", "sp-b"}
            async with ops.client() as requester:
                assert reader.token is not None
                denied = await requester.post(
                    f"{ops.stack.issuer}/admin/api/clients",
                    headers={"Authorization": f"Bearer {reader.token.get_secret_value()}"},
                    json={},
                )
                assert denied.status_code == HTTPStatus.FORBIDDEN
        finally:
            await reader.logout()
    finally:
        async with database.sessions() as session:
            row = await session.get(OperatorRow, seed.operator_id)
            assert row is not None
            row.permissions = original
            await session.commit()


async def test_operator_api_and_browser_sessions_are_not_interchangeable(ops: LifecycleLab) -> None:
    client = await operator_client(ops)
    try:
        assert client.token is not None
        async with ops.client() as requester:
            cookies = {"Cookie": f"__Host-fid-operator={client.token.get_secret_value()}"}
            denied = await requester.get(f"{ops.stack.issuer}/admin/api/clients", headers=cookies)
            assert denied.status_code == HTTPStatus.UNAUTHORIZED
            user = await requester.get(
                f"{ops.stack.issuer}/account",
                headers={"Cookie": f"__Host-fid-idp={client.token.get_secret_value()}"},
            )
            assert user.status_code == HTTPStatus.UNAUTHORIZED
            ops.clock.value += 900
            expired = await requester.get(
                f"{ops.stack.issuer}/admin/api/clients",
                headers={"Authorization": f"Bearer {client.token.get_secret_value()}"},
            )
            assert expired.status_code == HTTPStatus.UNAUTHORIZED
    finally:
        client.token = None


async def test_metadata_update_replacement_and_disabling_are_live_and_scoped(
    ops: LifecycleLab,
) -> None:
    operator = await operator_client(ops)
    async with ops.client() as browser:
        await ops.login(browser)
        await ops.sign_in(browser)
        await ops.sign_in(browser, ServiceId.SP_B)
        transaction = ops.sp().oidc.begin()
        callback = (await browser.get(transaction.authorization_url)).headers["location"]
        current = (await operator.inspect("sp-a"))[0]
        updated = await operator.update(
            "sp-a",
            ClientUpdate(
                expected_version=current.registration_version,
                redirect_uris=(
                    *current.redirect_uris,
                    f"{ops.stack.origin(ServiceId.SP_A)}/alternate",
                ),
                post_logout_redirect_uris=(f"{ops.stack.origin(ServiceId.SP_A)}/",),
                backchannel_logout_uri=f"{ops.stack.origin(ServiceId.SP_A)}/backchannel-logout",
            ),
        )
        assert updated.registration_version == current.registration_version + 1
        assert (await ops.account(browser)).status_code == HTTPStatus.UNAUTHORIZED
        assert (await ops.account(browser, ServiceId.SP_B)).status_code == HTTPStatus.OK
        stale = await browser.post(
            f"{ops.stack.issuer}/token", data=ops.token_parameters(transaction, callback)
        )
        assert stale.json()["error"] == "invalid_grant"
        replacement = await asyncio.to_thread(SigningKey.generate)
        replaced = await operator.replace(
            "sp-a",
            ClientCredentialReplacement(
                expected_version=updated.registration_version,
                public_key_pem=replacement.public_pem(),
                key_id=replacement.kid,
            ),
        )
        old = await browser.post(
            f"{ops.stack.issuer}/token", data=ops.token_parameters(transaction, callback)
        )
        assert old.json()["error"] == "invalid_client"
        disabled = await operator.disable("sp-a", replaced.registration_version)
        assert not disabled.enabled
        assert (await ops.account(browser, ServiceId.SP_B)).status_code == HTTPStatus.OK
        # Restore A's original credential only for the isolated fixture using a
        # fresh key id; historical keys themselves remain retired in the registry.
        fresh = await asyncio.to_thread(SigningKey.generate)
        recovered = await operator.replace(
            "sp-a",
            ClientCredentialReplacement(
                expected_version=disabled.registration_version,
                public_key_pem=fresh.public_pem(),
                key_id=fresh.kid,
            ),
        )
        assert not recovered.enabled
        enabled = await operator.disable("sp-a", recovered.registration_version, enabled=True)
        assert enabled.enabled
        # Fresh local signer injection mirrors owner-side credential deployment.
        ops.sp().oidc.key = fresh
        checker = ops.sp().oidc.grant_checker
        assert isinstance(checker, AuthenticatedGrantChecker)
        checker.signer = fresh
        ops.assets[ServiceId.SP_A] = dataclasses.replace(ops.assets[ServiceId.SP_A], signer=fresh)
        await ops.sign_in(browser)
    await operator.logout()


async def test_operator_mutations_and_audit_rollback_together(
    ops: LifecycleLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    operator = await operator_client(ops)
    original = ClientAdministration._audit

    def mark(
        self: ClientAdministration,
        work: SecurityUnitOfWork,
        operator_id: str,
        action: str,
        row: ClientRow,
    ) -> None:
        original(self, work, operator_id, action, row)
        work.session.info["fail_operator_commit"] = True

    def fail(session: Session) -> None:
        if session.info.get("fail_operator_commit"):
            raise RuntimeError("Injected operator commit failure")

    key = await asyncio.to_thread(SigningKey.generate)
    metadata = ClientCreate(
        client_id="sp-rollback",
        redirect_uris=("https://sp-rollback.localhost/auth/callback",),
        public_key_pem=key.public_pem(),
        key_id=key.kid,
    )
    event.listen(Session, "before_commit", fail)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(ClientAdministration, "_audit", mark)
            with pytest.raises(RuntimeError, match="Injected operator"):
                await operator.register(metadata)
    finally:
        event.remove(Session, "before_commit", fail)
    records = await operator.inspect()
    assert "sp-rollback" not in {client.client_id for client in records}
    assert (await operator.register(metadata)).client_id == "sp-rollback"
    await operator.logout()


async def test_operator_browser_csrf_is_session_purpose_origin_and_target_bound(
    ops: LifecycleLab,
) -> None:
    seed = await asyncio.to_thread(
        load_seeded_operator, ops.stack.root / "idp", ops.assets[ServiceId.IDP].envelope
    )
    async with ops.client() as browser:
        form = await browser.get(f"{ops.stack.issuer}/admin/login")
        csrf = action_challenge(form)
        old = browser.cookies.get("__Host-fid-operator")
        logged = await browser.post(
            f"{ops.stack.issuer}/admin/login",
            headers={"Origin": ops.stack.issuer},
            data={
                "csrf": csrf,
                "username": seed.username,
                "password": seed.password.get_secret_value(),
            },
        )
        assert logged.status_code == HTTPStatus.SEE_OTHER
        assert browser.cookies.get("__Host-fid-operator") != old
        new = await browser.get(f"{ops.stack.issuer}/admin/clients/new")
        csrf = action_challenge(new)
        key = await asyncio.to_thread(SigningKey.generate)
        metadata = ClientCreate(
            client_id="sp-browser",
            redirect_uris=("https://sp-browser.localhost/auth/callback",),
            public_key_pem=key.public_pem(),
            key_id=key.kid,
        )
        rejected = await browser.post(
            f"{ops.stack.issuer}/admin/clients/new",
            headers={"Origin": ops.stack.origin(ServiceId.SP_A)},
            data={"csrf": csrf, "metadata": metadata.model_dump_json()},
        )
        assert rejected.status_code == HTTPStatus.FORBIDDEN
        rejected = await browser.post(
            f"{ops.stack.issuer}/admin/api/clients", json=metadata.model_dump(mode="json")
        )
        assert rejected.status_code == HTTPStatus.FORBIDDEN
        created = await browser.post(
            f"{ops.stack.issuer}/admin/clients/new",
            headers={"Origin": ops.stack.issuer},
            data={"csrf": csrf, "metadata": metadata.model_dump_json()},
        )
        assert created.status_code == HTTPStatus.SEE_OTHER
        replay = await browser.post(
            f"{ops.stack.issuer}/admin/clients/new",
            headers={"Origin": ops.stack.issuer},
            data={"csrf": csrf, "metadata": metadata.model_dump_json()},
        )
        assert replay.status_code == HTTPStatus.FORBIDDEN
        cookie = str(browser.cookies.get("__Host-fid-operator"))
        bearer = await browser.get(
            f"{ops.stack.issuer}/admin/api/clients",
            headers={"Cookie": "", "Authorization": f"Bearer {cookie}"},
        )
        assert bearer.status_code == HTTPStatus.UNAUTHORIZED
        authentication = OperatorAuthorization(SecretStr(cookie), OperatorChannel.BROWSER)
        challenge = await ops.idp().operators.action(
            authentication, BrowserActionPurpose.CLIENT_DISABLE, "sp-a"
        )
        record = (await ops.idp().clients.inspect(authentication, "sp-b"))[0]
        wrong_target = await browser.post(
            f"{ops.stack.issuer}/admin/api/clients/sp-b/disable",
            headers={"Origin": ops.stack.issuer, "X-CSRF-Token": challenge.get_secret_value()},
            json={"expected_version": record.registration_version},
        )
        assert wrong_target.status_code == HTTPStatus.FORBIDDEN
        logout = action_challenge(
            await browser.get(f"{ops.stack.issuer}/admin"), "Operator sign out"
        )
        assert (
            await browser.post(
                f"{ops.stack.issuer}/admin/logout",
                headers={"Origin": ops.stack.issuer},
                data={"csrf": logout},
            )
        ).status_code == HTTPStatus.SEE_OTHER
        denied = await browser.get(
            f"{ops.stack.issuer}/admin/api/clients",
            headers={"Cookie": f"__Host-fid-operator={cookie}"},
        )
        assert denied.status_code == HTTPStatus.UNAUTHORIZED


async def test_operator_material_and_live_registrations_survive_initialization_and_restart(
    ops: LifecycleLab,
) -> None:
    seed = await asyncio.to_thread(
        load_seeded_operator, ops.stack.root / "idp", ops.assets[ServiceId.IDP].envelope
    )
    original_material = await asyncio.to_thread(
        (ops.stack.root / "idp" / "seed-operator.enc").read_bytes
    )
    operator = await operator_client(ops)
    before = (await operator.inspect("sp-c"))[0]
    updated = await operator.update(
        "sp-c",
        ClientUpdate(
            expected_version=before.registration_version,
            redirect_uris=before.redirect_uris,
            post_logout_redirect_uris=(f"{ops.stack.origin(ServiceId.SP_C)}/signed-out",),
            backchannel_logout_uri=f"{ops.stack.origin(ServiceId.SP_C)}/logout/backchannel",
        ),
    )
    await asyncio.to_thread(bootstrap_assets, ops.stack.root)
    await initialize_databases(ops.stack.root, host="127.0.0.1", port=ops.stack.postgres_port)
    assert (
        await asyncio.to_thread((ops.stack.root / "idp" / "seed-operator.enc").read_bytes)
        == original_material
    )
    await ops.restart(ServiceId.IDP)
    assert (await operator.inspect("sp-c"))[0] == updated
    async with ops.client() as browser:
        await ops.login(browser)
        await ops.sign_in(browser, ServiceId.SP_C)
    changed = await asyncio.to_thread(
        hash_password, SecretStr("isolated-test-replacement-credential")
    )
    async with ops.idp().oidc.database.sessions() as session:
        row = await session.get(OperatorRow, seed.operator_id)
        assert row is not None
        old_hash = row.password_hash
        row.password_hash = changed.get_secret_value()
        await session.commit()
    try:
        await initialize_databases(ops.stack.root, host="127.0.0.1", port=ops.stack.postgres_port)
        stored = await ops.idp().operators.repository.credential(seed.username)
        assert stored is not None and stored.password_hash == changed
        async with ops.client() as browser:
            assert operator.token is not None
            denied = await browser.get(
                f"{ops.stack.issuer}/admin/api/clients",
                headers={"Authorization": f"Bearer {operator.token.get_secret_value()}"},
            )
            assert denied.status_code == HTTPStatus.UNAUTHORIZED
    finally:
        async with ops.idp().oidc.database.sessions() as session:
            row = await session.get(OperatorRow, seed.operator_id)
            assert row is not None
            row.password_hash = old_hash
            await session.commit()


async def test_registration_and_optimistic_metadata_versions_arbitrate_concurrency(
    ops: LifecycleLab,
) -> None:
    operator = await operator_client(ops)
    key = await asyncio.to_thread(SigningKey.generate)
    metadata = ClientCreate(
        client_id="sp-concurrent",
        redirect_uris=("https://sp-concurrent.localhost/auth/callback",),
        public_key_pem=key.public_pem(),
        key_id=key.kid,
    )
    assert operator.token is not None
    async with ops.client() as requester:
        headers = {"Authorization": f"Bearer {operator.token.get_secret_value()}"}
        outcomes = await asyncio.gather(
            *(
                requester.post(
                    f"{ops.stack.issuer}/admin/api/clients",
                    headers=headers,
                    json=metadata.model_dump(mode="json"),
                )
                for _ in range(4)
            )
        )
        assert sorted(response.status_code for response in outcomes) == [201, 409, 409, 409]
        record = (await operator.inspect("sp-concurrent"))[0]
        update = ClientUpdate(
            expected_version=record.registration_version,
            redirect_uris=record.redirect_uris,
            post_logout_redirect_uris=("https://sp-concurrent.localhost/",),
        )
        outcomes = await asyncio.gather(
            *(
                requester.put(
                    f"{ops.stack.issuer}/admin/api/clients/sp-concurrent",
                    headers=headers,
                    json=update.model_dump(mode="json"),
                )
                for _ in range(2)
            )
        )
        assert sorted(response.status_code for response in outcomes) == [200, 409]
    await operator.logout()
