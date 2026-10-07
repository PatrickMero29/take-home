"""Real database rotation/issuance/cache scenarios share factories and injected time."""

import asyncio
import secrets
from collections.abc import AsyncIterator
from http import HTTPStatus

import pytest
import pytest_asyncio
from cryptography.fernet import Fernet, InvalidToken
from joserfc import jws
from pydantic import SecretBytes
from sqlalchemy import event, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from federated_identity.cli.operator import OperatorClient, OperatorClientError
from federated_identity.common.security.keys import PublicJwks
from federated_identity.common.security.model import KeyState
from federated_identity.common.security.oidc import validate_id_token
from federated_identity.common.security.secrets import EnvelopeCipher
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.repositories.operator import OperatorRow
from federated_identity.idp.repositories.security import SecurityUnitOfWork
from federated_identity.idp.repositories.security_tables import SigningTrustRow
from federated_identity.idp.repositories.signing import SignedArtifactRow, SigningMaterialRow
from federated_identity.idp.schemas.clients import ClientCreate, ClientCredentialReplacement
from federated_identity.idp.schemas.signing import SignedArtifactPurpose
from federated_identity.idp.services.provisioning import load_seeded_operator
from federated_identity.idp.services.signing import SigningKeyAdministration, SigningKeyService
from tests.lifecycle_helpers import LifecycleLab, lifecycle_lab, next_scenario

pytestmark = [pytest.mark.integration, pytest.mark.asyncio(loop_scope="module")]


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def rotation_runtime() -> AsyncIterator[LifecycleLab]:
    async with lifecycle_lab() as lab:
        yield lab


@pytest_asyncio.fixture(loop_scope="module")
async def rotation(rotation_runtime: LifecycleLab) -> LifecycleLab:
    next_scenario(rotation_runtime)
    return rotation_runtime


async def operator(lab: LifecycleLab) -> OperatorClient:
    seed = await asyncio.to_thread(
        load_seeded_operator, lab.stack.root / "idp", lab.assets[ServiceId.IDP].envelope
    )
    client = OperatorClient(lab.stack.issuer, lab.stack.tls, transport=lab.transport)
    await client.login(seed.username, seed.password)
    return client


async def test_publication_precedes_activation_and_private_material_is_never_exposed(
    rotation: LifecycleLab,
) -> None:
    lab = rotation
    admin = await operator(lab)
    assert admin.token is not None
    current = next(key for key in await admin.signing_keys() if key.state == KeyState.ACTIVE)
    async with lab.client() as requester:
        headers = {"Authorization": f"Bearer {admin.token.get_secret_value()}"}
        prepared = await requester.post(
            f"{lab.stack.issuer}/admin/api/signing-keys/prepare", headers=headers, json={}
        )
        assert prepared.status_code == HTTPStatus.CREATED
        body = prepared.json()
        assert body["state"] == "prepared" and body["published_at"] is None
        assert "private" not in prepared.text.lower() and "PRIVATE KEY" not in prepared.text
        before = await requester.post(
            f"{lab.stack.issuer}/admin/api/signing-keys/{body['key_id']}/activate",
            headers=headers,
            json={"expected_active_key_id": current.key_id},
        )
        assert before.status_code == HTTPStatus.CONFLICT
        published = await requester.get(f"{lab.stack.issuer}/jwks.json")
        keys = PublicJwks.model_validate_json(published.content)
        assert body["key_id"] in {key.kid for key in keys.keys}
        assert all(
            set(key) == {"kty", "use", "alg", "kid", "n", "e"} for key in published.json()["keys"]
        )
        activated = await admin.activate_key(body["key_id"], current.key_id)
        assert activated.state == KeyState.ACTIVE and activated.published_at is not None
        async with lab.idp().oidc.database.sessions() as session:
            material = await session.get(SigningMaterialRow, activated.key_id)
            assert material is not None and b"PRIVATE KEY" not in material.encrypted_private_key
            assert b"private_pem" not in material.encrypted_private_key
    await admin.logout()


async def test_both_sp_warm_caches_recover_new_signer_and_old_artifacts_and_sessions_survive(
    rotation: LifecycleLab,
) -> None:
    lab = rotation
    async with lab.client() as browser:
        await lab.login(browser)
        await lab.sign_in(browser)
        await lab.sign_in(browser, ServiceId.SP_B)
        old_cookies = {cookie.name: cookie.value for cookie in browser.cookies.jar}
        transaction = lab.sp().oidc.begin()
        callback = (await browser.get(transaction.authorization_url)).headers["location"]
        previous = await lab.sp().oidc.exchange_verified(transaction, callback)
        for service in (ServiceId.SP_A, ServiceId.SP_B):
            _, warm = await lab.sp(service).oidc.provider()
            assert previous.evidence.signing_key_id in {key.kid for key in warm.keys}
        admin = await operator(lab)
        prepared = await admin.prepare_key()
        assert prepared.published_at is not None
        await admin.activate_key(prepared.key_id, previous.evidence.signing_key_id)
        for service in (ServiceId.SP_A, ServiceId.SP_B):
            assert (await lab.account(browser, service)).status_code == HTTPStatus.OK
        assert {cookie.name: cookie.value for cookie in browser.cookies.jar} == old_cookies
        public = await lab.idp().oidc.keys.public_jwks()
        validated = validate_id_token(
            previous.response,
            settings=lab.sp().oidc.settings,
            nonce=transaction.nonce,
            keys=public,
            clock=lab.clock,
        )
        assert validated.sub == lab.user.subject
        for service in (ServiceId.SP_A, ServiceId.SP_B):
            fresh = lab.sp(service).oidc.begin()
            response = await browser.get(fresh.authorization_url)
            login = await lab.sp(service).oidc.exchange_verified(
                fresh, response.headers["location"]
            )
            assert login.evidence.signing_key_id == prepared.key_id
            cached = await lab.sp(service).oidc.jwks.get()
            assert prepared.key_id in {key.kid for key in cached.keys}
            async with lab.idp().oidc.database.sessions() as session:
                record = await session.get(SignedArtifactRow, login.claims.jti)
                assert (
                    record is not None
                    and record.key_id == prepared.key_id
                    and record.expires_at == login.claims.exp
                )
        await admin.logout()


async def test_retirement_waits_for_every_signed_purpose_and_exact_skew_boundary(
    rotation: LifecycleLab,
) -> None:
    lab = rotation
    admin = await operator(lab)
    async with lab.client() as browser:
        await lab.login(browser)
        transaction = lab.sp().oidc.begin()
        callback = (await browser.get(transaction.authorization_url)).headers["location"]
        issued = await lab.sp().oidc.exchange_verified(transaction, callback)
        original = issued.evidence.signing_key_id
        lab.clock.value += 20
        deadline = lab.clock.now() + 300
        async with lab.idp().security.repository.transaction() as work:
            await lab.idp().security.record_signed_artifact_in(
                work,
                artifact_id=f"logout:{secrets.token_urlsafe(16)}",
                key_id=original,
                purpose=SignedArtifactPurpose.LOGOUT_TOKEN,
                client_id="sp-a",
                issued_at=lab.clock.now(),
                expires_at=deadline,
            )
        prepared = await admin.prepare_key()
        await admin.activate_key(prepared.key_id, original)
        with pytest.raises(OperatorClientError):
            await admin.retire_key(original, issued.claims.exp)
        lab.clock.value = deadline + 4
        with pytest.raises(OperatorClientError):
            await admin.retire_key(original, deadline)
        lab.clock.value += 1
        retired = await admin.retire_key(original, deadline)
        assert retired.state == KeyState.RETIRED
        public = await lab.idp().oidc.keys.public_jwks()
        assert original not in {key.kid for key in public.keys}
        assert prepared.key_id in {key.kid for key in public.keys}
    await admin.logout()


async def test_idp_restart_uses_persisted_active_key_instead_of_bootstrap_volume_identity(
    rotation: LifecycleLab,
) -> None:
    lab = rotation
    admin = await operator(lab)
    original = next(key for key in await admin.signing_keys() if key.state == KeyState.ACTIVE)
    prepared = await admin.prepare_key()
    await admin.activate_key(prepared.key_id, original.key_id)
    before = {key.key_id: key.state for key in await admin.signing_keys()}
    await lab.restart(ServiceId.IDP)
    after = {key.key_id: key.state for key in await admin.signing_keys()}
    assert after == before
    assert after[prepared.key_id] == KeyState.ACTIVE and after[original.key_id] == KeyState.DRAINING
    assert lab.assets[ServiceId.IDP].signer.kid != prepared.key_id
    async with lab.client() as browser:
        await lab.login(browser)
        transaction = lab.sp().oidc.begin()
        callback = (await browser.get(transaction.authorization_url)).headers["location"]
        issued = await lab.sp().oidc.exchange_verified(transaction, callback)
        assert issued.evidence.signing_key_id == prepared.key_id
    await admin.logout()


async def test_rotation_and_concurrent_issuance_share_one_active_signer_decision(
    rotation: LifecycleLab,
) -> None:
    lab = rotation
    admin = await operator(lab)
    original = next(key for key in await admin.signing_keys() if key.state == KeyState.ACTIVE)
    prepared = await admin.prepare_key()
    async with lab.client() as browser:
        await lab.login(browser)
        transactions = [lab.sp().oidc.begin() for _ in range(8)]
        callbacks = [
            (await browser.get(transaction.authorization_url)).headers["location"]
            for transaction in transactions
        ]

        async def exchange(index: int) -> str:
            response = await browser.post(
                f"{lab.stack.issuer}/token",
                data=lab.token_parameters(transactions[index], callbacks[index]),
            )
            assert response.status_code == HTTPStatus.OK
            return str(
                jws.extract_compact(response.json()["id_token"].encode("ascii")).headers()["kid"]
            )

        outcomes = await asyncio.gather(
            *(exchange(index) for index in range(8)),
            admin.activate_key(prepared.key_id, original.key_id),
        )
        assert all(kid in {original.key_id, prepared.key_id} for kid in outcomes[:-1])
        async with lab.idp().oidc.database.sessions() as session:
            active = list(
                await session.scalars(
                    select(SigningTrustRow).where(SigningTrustRow.state == "active")
                )
            )
            assert len(active) == 1 and active[0].key_id == prepared.key_id
            records = list(
                await session.scalars(
                    select(SignedArtifactRow).where(SignedArtifactRow.issued_at == lab.clock.now())
                )
            )
            assert all(record.key_id in {original.key_id, prepared.key_id} for record in records)
    await admin.logout()


async def test_failed_activation_commit_preserves_previous_trust_and_retryable_prepared_key(
    rotation: LifecycleLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab = rotation
    admin = await operator(lab)
    old = next(key for key in await admin.signing_keys() if key.state == KeyState.ACTIVE)
    prepared = await admin.prepare_key()
    original = SigningKeyAdministration._audit

    def mark(
        self: SigningKeyAdministration,
        work: SecurityUnitOfWork,
        operator_id: str,
        action: str,
        row: SigningTrustRow,
        previous: str | None = None,
    ) -> None:
        original(self, work, operator_id, action, row, previous)
        work.session.info["fail_signing_activation"] = True

    def fail(session: Session) -> None:
        if session.info.get("fail_signing_activation"):
            raise RuntimeError("Injected signing activation failure")

    event.listen(Session, "before_commit", fail)
    try:
        with monkeypatch.context() as patch:
            patch.setattr(SigningKeyAdministration, "_audit", mark)
            with pytest.raises(RuntimeError, match="Injected signing"):
                await admin.activate_key(prepared.key_id, old.key_id)
    finally:
        event.remove(Session, "before_commit", fail)
    states = {key.key_id: key.state for key in await admin.signing_keys()}
    assert states[old.key_id] == KeyState.ACTIVE and states[prepared.key_id] == KeyState.PREPARED
    assert (await admin.activate_key(prepared.key_id, old.key_id)).state == KeyState.ACTIVE
    await admin.logout()


async def test_operator_key_permissions_and_issuer_key_namespace_are_explicit(
    rotation: LifecycleLab,
) -> None:
    lab = rotation
    seed = await asyncio.to_thread(
        load_seeded_operator, lab.stack.root / "idp", lab.assets[ServiceId.IDP].envelope
    )
    admin = await operator(lab)
    prepared = await admin.prepare_key()
    async with lab.idp().oidc.database.sessions() as session:
        signer = await session.get(SigningTrustRow, prepared.key_id)
        assert signer is not None
        public_pem = signer.public_key_pem
    registration = (await admin.inspect("sp-a"))[0]
    with pytest.raises(OperatorClientError, match="HTTP 400"):
        await admin.register(
            ClientCreate(
                client_id="key-reuse-probe",
                redirect_uris=("https://key-reuse.localhost/callback",),
                public_key_pem=public_pem,
                key_id=prepared.key_id,
            )
        )
    with pytest.raises(OperatorClientError, match="HTTP 400"):
        await admin.replace(
            "sp-a",
            ClientCredentialReplacement(
                public_key_pem=public_pem,
                key_id=prepared.key_id,
                expected_version=registration.registration_version,
            ),
        )
    assert (await admin.inspect("sp-a"))[0] == registration
    try:
        async with lab.idp().oidc.database.sessions() as session:
            row = await session.get(OperatorRow, seed.operator_id)
            assert row is not None
            permissions = row.permissions[:]
            row.permissions = ["clients:read", "clients:write"]
            await session.commit()
        restricted = await operator(lab)
        try:
            with pytest.raises(OperatorClientError):
                await restricted.prepare_key()
            with pytest.raises(OperatorClientError):
                await restricted.signing_keys()
        finally:
            await restricted.logout()
    finally:
        async with lab.idp().oidc.database.sessions() as session:
            row = await session.get(OperatorRow, seed.operator_id)
            assert row is not None
            row.permissions = permissions
            await session.commit()
        admin.token = None


async def test_database_guards_private_material_signed_history_audit_and_publication(
    rotation: LifecycleLab,
) -> None:
    lab = rotation
    admin = await operator(lab)
    prepared = await admin.prepare_key()
    async with lab.client() as browser:
        await lab.login(browser)
        transaction = lab.sp().oidc.begin()
        callback = (await browser.get(transaction.authorization_url)).headers["location"]
        issued = await lab.sp().oidc.exchange_verified(transaction, callback)
    statements = (
        (
            "UPDATE signing_key_material SET encrypted_private_key=''::bytea "
            "WHERE key_id=:prepared",
            "immutable",
        ),
        (
            "UPDATE signed_artifacts SET expires_at=expires_at+1 WHERE artifact_id=:artifact",
            "immutable",
        ),
        ("DELETE FROM signing_audit WHERE key_id=:prepared", "immutable"),
        ("UPDATE signing_trust SET published_at=NULL WHERE key_id=:prepared", "publication"),
    )
    for statement, message in statements:
        with pytest.raises(DBAPIError, match=message):
            async with lab.idp().oidc.database.engine.begin() as connection:
                await connection.execute(
                    text(statement), {"prepared": prepared.key_id, "artifact": issued.claims.jti}
                )
    current = next(key for key in await admin.signing_keys() if key.key_id == prepared.key_id)
    assert current == prepared
    await admin.logout()


async def test_wrong_cipher_cannot_load_persisted_rotated_key_material(
    rotation: LifecycleLab,
) -> None:
    lab = rotation
    original = lab.idp().security.cipher
    lab.idp().security.cipher = EnvelopeCipher.from_key(SecretBytes(Fernet.generate_key()))
    try:
        keys = SigningKeyService(lab.idp().security, lab.assets[ServiceId.IDP].signer)
        with pytest.raises(InvalidToken):
            await keys.initialize()
    finally:
        lab.idp().security.cipher = original
