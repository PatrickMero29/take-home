import asyncio
import secrets
from http import HTTPStatus
from pathlib import Path

import httpx2 as httpx
import pytest
from alembic import command
from alembic.config import Config
from joserfc import jwt
from pydantic import SecretStr
from sqlalchemy import func, select, text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import DBAPIError

from federated_identity.cli.probe_runtime import FixturePrincipalProvider
from federated_identity.common.persistence.migrations import migrate
from federated_identity.common.security.model import IssuedCredentials, LoginEvidence
from federated_identity.common.security.oidc import InvalidIdToken
from federated_identity.common.settings.policy import verifier_digest
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.api.app import create_app
from federated_identity.idp.protocol.authlib_adapter import OpenIdProfile
from federated_identity.idp.repositories.database import ProtocolRepository
from federated_identity.idp.repositories.security import SecurityUnitOfWork
from federated_identity.idp.repositories.security_tables import (
    AuthenticationEventRow,
    AuthenticationEvidenceRow,
    FederationGrantRow,
    IdpSessionRow,
    RefreshFamilyRow,
    SigningTrustRow,
)
from federated_identity.idp.repositories.tables import (
    AssertionReplayRow,
    AuthorizationCodeRow,
    IssuanceRow,
)
from federated_identity.idp.schemas.models import AuthenticatedPrincipal, TokenResponse
from federated_identity.idp.services.security_model import IdpSecurityModel
from tests.helpers import ASSERTION_TYPE, ProtocolLab, callback_code, require_code_error

pytestmark = pytest.mark.integration


async def test_authenticated_introspection_returns_no_authority_for_unknown_tokens(
    lab: ProtocolLab,
) -> None:
    response = await lab.browser.post(
        "/introspect",
        data={
            "token": secrets.token_urlsafe(32),
            "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": lab.assertion(endpoint=lab.settings.introspection_endpoint),
        },
    )
    assert response.status_code == HTTPStatus.OK, response.text
    assert response.json() == {"active": False}


async def test_code_issuance_and_authoritative_result_share_one_persisted_lineage(
    lab: ProtocolLab,
) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    login = await lab.rp().exchange_verified(transaction, callback)
    assert login.evidence.authentication.event_id == lab.principal.event_id
    assert login.evidence.authentication.session_id == lab.principal.sid
    assert login.evidence.authentication.authenticated_at == lab.principal.auth_time
    async with lab.database.sessions() as session:
        code = await session.get(AuthorizationCodeRow, verifier_digest(callback_code(callback)))
        record = await session.get(IssuanceRow, login.claims.jti)
        evidence = await session.get(AuthenticationEvidenceRow, login.claims.jti)
        trust = await session.get(SigningTrustRow, lab.keys.issuer.kid)
        assert (
            code is not None and record is not None and evidence is not None and trust is not None
        )
        assert code.event_id == lab.principal.event_id and code.consumed_at == lab.clock.now()
        assert record.grant_id == evidence.grant_id == login.context.grant.grant_id
        assert record.id_token_digest == evidence.token_digest == login.evidence.token_digest
        assert trust.verification_deadline == login.claims.exp
        assert await session.scalar(select(func.count()).select_from(AuthenticationEventRow)) == 1


@pytest.mark.parametrize("field", ["event_id", "sub", "auth_time", "acr"])
async def test_supplied_principal_cannot_invent_or_rewrite_persisted_authentication(
    lab: ProtocolLab,
    field: str,
) -> None:
    value: object = lab.clock.now() if field == "auth_time" else "unverified-value"
    modified = lab.principal.model_copy(update={field: value})
    proof = SecretStr(secrets.token_urlsafe(32))
    app = create_app(lab.service, principal_provider=FixturePrincipalProvider(proof, modified))
    transaction = lab.rp().begin()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as browser:
        response = await browser.get(
            transaction.authorization_url,
            headers={"Authorization": f"Bearer {proof.get_secret_value()}"},
        )
    require_code_error(response.headers["location"], "login_required")
    async with lab.database.sessions() as session:
        assert not list(await session.scalars(select(AuthorizationCodeRow)))


@pytest.mark.parametrize("case", ["logout", "expiry"])
async def test_parent_session_state_is_checked_before_code_redemption(
    lab: ProtocolLab,
    case: str,
) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    if case == "logout":
        await lab.security.end_session(lab.principal.sid)
    else:
        async with lab.database.sessions() as session:
            parent = await session.get(IdpSessionRow, lab.principal.sid)
            assert parent is not None
            lab.clock.value = parent.expires_at
    response = await lab.browser.post("/token", data=lab.token_parameters(transaction, callback))
    assert response.json()["error"] == "invalid_grant"
    async with lab.database.sessions() as session:
        code = await session.get(AuthorizationCodeRow, verifier_digest(callback_code(callback)))
        assert code is not None and code.consumed_at is None
        assert not list(await session.scalars(select(FederationGrantRow)))


async def test_code_and_access_lifetimes_are_clamped_to_the_parent_session(
    lab: ProtocolLab,
) -> None:
    async with lab.database.sessions() as session:
        parent = await session.get(IdpSessionRow, lab.principal.sid)
        assert parent is not None
        expires = parent.expires_at
    lab.clock.value = expires - 20
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    login = await lab.rp().exchange_verified(transaction, callback)
    assert login.response.expires_in == 20
    assert login.context.grant.expires_at == login.context.family.expires_at == expires
    async with lab.database.sessions() as session:
        code = await session.get(AuthorizationCodeRow, verifier_digest(callback_code(callback)))
        assert code is not None and code.expires_at == expires


@pytest.mark.parametrize("client", ["sp-a", "sp-b"])
async def test_authenticated_introspection_is_recipient_scoped(
    lab: ProtocolLab, client: str
) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    token, _ = await lab.rp().exchange(transaction, callback)
    response = await lab.browser.post(
        "/introspect",
        data={
            "token": token.access_token,
            "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": lab.assertion(client, endpoint=lab.settings.introspection_endpoint),
        },
    )
    assert response.status_code == HTTPStatus.OK
    if client == "sp-a":
        assert response.json()["active"]
        assert response.json()["context"]["authentication"]["event_id"] == lab.principal.event_id
    else:
        assert response.json() == {"active": False}
    assert response.headers["cache-control"] == "no-store"


async def test_client_assertion_audiences_are_endpoint_specific_and_replay_is_durable(
    lab: ProtocolLab,
) -> None:
    token = secrets.token_urlsafe(32)
    wrong = lab.assertion()
    rejected = await lab.browser.post(
        "/introspect",
        data={
            "token": token,
            "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": wrong,
        },
    )
    assert rejected.json()["error"] == "invalid_client"
    assertion = lab.assertion(endpoint=lab.settings.introspection_endpoint)
    fields = {
        "token": token,
        "client_assertion_type": ASSERTION_TYPE,
        "client_assertion": assertion,
    }
    first = await lab.browser.post("/introspect", data=fields)
    replay = await lab.browser.post("/introspect", data=fields)
    assert first.json() == {"active": False}
    assert replay.json()["error"] == "invalid_client"


async def test_policy_denial_discards_draft_issuance_but_commits_valid_assertion_replay(
    lab: ProtocolLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    assertion = lab.assertion()

    def wrong_subject(
        self: OpenIdProfile, user: AuthenticatedPrincipal, scope: str
    ) -> dict[str, str]:
        return {"sub": "other-account", "sid": user.sid}

    with monkeypatch.context() as patch:
        patch.setattr(OpenIdProfile, "generate_user_info", wrong_subject)
        response = await lab.browser.post(
            "/token", data=lab.token_parameters(transaction, callback, assertion=assertion)
        )
    assert response.json()["error"] == "invalid_grant"
    claims = jwt.decode(assertion, lab.keys.client_a.key, algorithms=["RS256"]).claims
    async with lab.database.sessions() as session:
        assert await session.get(AssertionReplayRow, ("sp-a", claims["jti"])) is not None
        code = await session.get(AuthorizationCodeRow, verifier_digest(callback_code(callback)))
        assert code is not None and code.consumed_at is None
        assert not list(await session.scalars(select(IssuanceRow)))
        assert not list(await session.scalars(select(FederationGrantRow)))
    replay = await lab.browser.post(
        "/token", data=lab.token_parameters(transaction, callback, assertion=assertion)
    )
    assert replay.json()["error"] == "invalid_client"
    await lab.rp().exchange(transaction, callback)


async def test_failure_after_grant_creation_rolls_back_both_protocol_and_security_records(
    lab: ProtocolLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    assertion = lab.assertion()
    original = IdpSecurityModel.issue_grant_in

    async def fail(
        self: IdpSecurityModel,
        work: SecurityUnitOfWork,
        evidence: LoginEvidence,
        *,
        access_token: SecretStr,
        refresh_token: SecretStr | None = None,
    ) -> IssuedCredentials:
        await original(self, work, evidence, access_token=access_token, refresh_token=refresh_token)
        raise RuntimeError("Injected failure after canonical grant creation")

    with monkeypatch.context() as patch:
        patch.setattr(IdpSecurityModel, "issue_grant_in", fail)
        with pytest.raises(RuntimeError, match="after canonical"):
            await lab.browser.post(
                "/token", data=lab.token_parameters(transaction, callback, assertion=assertion)
            )
    async with lab.database.sessions() as session:
        for model in (IssuanceRow, FederationGrantRow, RefreshFamilyRow, AuthenticationEvidenceRow):
            assert not list(await session.scalars(select(model)))
        code = await session.get(AuthorizationCodeRow, verifier_digest(callback_code(callback)))
        assert code is not None and code.consumed_at is None
    # Unexpected failures roll back the replay reservation too.
    response = await lab.browser.post(
        "/token", data=lab.token_parameters(transaction, callback, assertion=assertion)
    )
    assert response.status_code == HTTPStatus.OK


@pytest.mark.parametrize("case", ["logout", "client", "key"])
async def test_redemption_racing_containment_cannot_publish_reusable_authority(
    lab: ProtocolLab,
    case: str,
) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)

    async def contain() -> None:
        if case == "logout":
            await lab.security.end_session(lab.principal.sid)
        elif case == "client":
            await lab.security.disable_client("sp-a")
        else:
            await lab.security.revoke_signer(lab.keys.issuer.kid)

    response, _ = await asyncio.gather(
        lab.browser.post("/token", data=lab.token_parameters(transaction, callback)), contain()
    )
    if response.status_code == HTTPStatus.OK:
        token = TokenResponse.model_validate(response.json())
        status = await lab.security.check_access(
            SecretStr(token.access_token), authenticated_client="sp-a"
        )
        assert not status.active
    else:
        assert response.json()["error"] in {"invalid_client", "invalid_grant"}
    async with lab.database.sessions() as session:
        assert all(
            row.revoked_at is not None for row in await session.scalars(select(FederationGrantRow))
        )


async def test_rp_rejects_valid_signatures_without_matching_authoritative_evidence(
    lab: ProtocolLab,
) -> None:
    transport = httpx.ASGITransport(app=lab.app)

    class SubstitutedTokenTransport(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            response = await transport.handle_async_request(request)
            if request.url.path != "/token" or not response.is_success:
                return response
            await response.aread()
            body = response.json()
            original = jwt.decode(body["id_token"], lab.keys.issuer.key, algorithms=["RS256"])
            claims = dict(original.claims)
            claims["jti"] = secrets.token_urlsafe(24)
            body["id_token"] = jwt.encode(
                original.header, claims, lab.keys.issuer.key, algorithms=["RS256"]
            )
            return httpx.Response(HTTPStatus.OK, json=body)

    rp = lab.rp()
    rp.transport = SubstitutedTokenTransport()
    transaction = rp.begin()
    callback = await lab.authorize(transaction)
    with pytest.raises(InvalidIdToken, match="committed"):
        await rp.exchange_verified(transaction, callback)


async def test_database_refuses_a_success_without_the_protocol_to_grant_binding(
    lab: ProtocolLab,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    assertion = lab.assertion()

    def skip_binding(self: ProtocolRepository, issuance_id: str, grant_id: str) -> None:
        return None

    with monkeypatch.context() as patch:
        patch.setattr(ProtocolRepository, "bind_issuance", skip_binding)
        with pytest.raises(DBAPIError, match="must commit"):
            await lab.browser.post(
                "/token", data=lab.token_parameters(transaction, callback, assertion=assertion)
            )
    assert await lab.database.issuance_count(callback_code(callback)) == 0
    async with lab.database.sessions() as session:
        assert not list(await session.scalars(select(FederationGrantRow)))
        code = await session.get(AuthorizationCodeRow, verifier_digest(callback_code(callback)))
        assert code is not None and code.consumed_at is None
    retry = await lab.browser.post(
        "/token", data=lab.token_parameters(transaction, callback, assertion=assertion)
    )
    assert retry.status_code == HTTPStatus.OK


@pytest.mark.parametrize(
    "change",
    ["expires_at=expires_at+60", "redirect_uri='https://other.example'", "event_id=NULL"],
)
async def test_code_proof_and_lineage_cannot_be_rewritten(lab: ProtocolLab, change: str) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    with pytest.raises(DBAPIError, match="immutable"):
        async with lab.database.engine.begin() as connection:
            await connection.execute(text(f"UPDATE authorization_codes SET {change}"))
    await lab.rp().exchange_verified(transaction, callback)
    with pytest.raises(DBAPIError, match="irreversible"):
        async with lab.database.engine.begin() as connection:
            await connection.execute(text("UPDATE authorization_codes SET consumed_at=NULL"))


async def test_upgrade_preserves_but_never_trusts_unbound_prototype_codes(lab: ProtocolLab) -> None:
    root = await asyncio.to_thread(lambda: Path(__file__).resolve().parents[2])
    configuration = Config()
    configuration.set_main_option("script_location", str(root / "migrations" / "idp"))
    configuration.set_main_option("path_separator", "os")

    def downgrade(connection: Connection) -> None:
        configuration.attributes["connection"] = connection
        command.downgrade(configuration, "idp_security_model_02")

    transaction = lab.rp().begin()
    code = secrets.token_urlsafe(32)
    fields = lab.token_parameters(transaction, f"{transaction.redirect_uri}?code={code}")
    async with lab.database.engine.begin() as connection:
        await connection.run_sync(downgrade)
        await connection.execute(
            text("""
                INSERT INTO authorization_codes
                    (code_digest, client_id, redirect_uri, scope, nonce, code_challenge,
                     created_at, expires_at, consumed_at, sub, sid, auth_time, acr, amr)
                VALUES (:digest, 'sp-a', :redirect, 'openid', :nonce, :challenge,
                        :now, :expires, NULL, :sub, :sid, :auth_time, :acr, :amr)
            """),
            {
                "digest": verifier_digest(code),
                "redirect": transaction.redirect_uri,
                "nonce": transaction.nonce,
                "challenge": "prototype-proof",
                "now": lab.clock.now(),
                "expires": lab.clock.now() + 60,
                "sub": lab.principal.sub,
                "sid": lab.principal.sid,
                "auth_time": lab.principal.auth_time,
                "acr": lab.principal.acr,
                "amr": '["urn:take-home:amr:phase0-fixture"]',
            },
        )
    await migrate(lab.database, ServiceId.IDP)
    response = await lab.browser.post("/token", data=fields)
    assert response.json()["error"] == "invalid_grant"
    async with lab.database.sessions() as session:
        historical = await session.get(AuthorizationCodeRow, verifier_digest(code))
        assert historical is not None and historical.event_id is None
        assert not list(await session.scalars(select(FederationGrantRow)))
