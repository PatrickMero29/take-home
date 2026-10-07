import asyncio
import secrets
from http import HTTPStatus
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx2 as httpx
import pytest

from federated_identity.common.policy import verifier_digest
from federated_identity.idp.api.app import create_app
from federated_identity.idp.repositories.database import Database
from federated_identity.idp.repositories.tables import AuthorizationCodeRow, ClientRow, IssuanceRow
from federated_identity.idp.schemas.models import OAuthErrorResponse, TokenResponse
from federated_identity.idp.services.oidc import OidcService
from federated_identity.sp.protocol.oidc import (
    InvalidAuthorizationResponse,
    InvalidIdToken,
    validate_id_token,
)
from tests.helpers import ASSERTION_TYPE, ProtocolLab, callback_code, require_code_error

pytestmark = pytest.mark.integration


async def test_pkce_oidc_and_private_key_jwt_round_trip(lab: ProtocolLab) -> None:
    rp = lab.rp()
    transaction = rp.begin()
    callback = await lab.authorize(transaction)
    response, claims = await rp.exchange(transaction, callback)

    assert claims.sub == lab.principal.sub
    assert claims.sid == lab.principal.sid
    assert claims.aud == transaction.client_id
    assert claims.nonce == transaction.nonce
    assert claims.auth_time == lab.principal.auth_time
    assert claims.auth_time < claims.iat
    evidence = await lab.database.issuance_evidence(response.access_token)
    assert evidence is not None
    assert evidence.issuance_id == claims.jti
    assert evidence.id_token_digest == verifier_digest(response.id_token)

    async with lab.database.sessions() as session:
        code = await session.get(AuthorizationCodeRow, verifier_digest(callback_code(callback)))
        issuance = await session.get(IssuanceRow, claims.jti)
        assert code is not None and code.consumed_at == lab.clock.now()
        assert issuance is not None
        assert issuance.access_token_digest != response.access_token
        assert issuance.id_token_digest != response.id_token


async def test_concurrent_code_redemption_has_one_issuance(lab: ProtocolLab) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)

    async def redeem() -> httpx.Response:
        return await lab.browser.post("/token", data=lab.token_parameters(transaction, callback))

    responses = await asyncio.gather(*(redeem() for _ in range(8)))
    successes = [response for response in responses if response.status_code == HTTPStatus.OK]
    assert len(successes) == 1
    for response in responses:
        if response.status_code != HTTPStatus.OK:
            assert OAuthErrorResponse.model_validate(response.json()).error == "invalid_grant"
    assert await lab.database.issuance_count(callback_code(callback)) == 1


async def test_code_cannot_cross_clients(lab: ProtocolLab) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    response = await lab.browser.post(
        "/token", data=lab.token_parameters(transaction, callback, client_id="sp-b")
    )
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.json()["error"] == "invalid_grant"
    assert await lab.database.issuance_count(callback_code(callback)) == 0
    # Rejection did not consume the rightful client's code.
    token, _ = await lab.rp().exchange(transaction, callback)
    assert await lab.database.issuance_evidence(token.access_token) is not None


async def test_original_redirect_uri_is_bound_even_when_both_are_registered(
    lab: ProtocolLab,
) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    fields = lab.token_parameters(transaction, callback)
    fields["redirect_uri"] = "https://sp-a.localhost/alternate"
    response = await lab.browser.post("/token", data=fields)
    assert response.json()["error"] == "invalid_grant"
    assert await lab.database.issuance_count(callback_code(callback)) == 0
    await lab.rp().exchange(transaction, callback)


@pytest.mark.parametrize("verifier", [None, "incorrect" * 8])
async def test_missing_or_wrong_verifier_rejected(lab: ProtocolLab, verifier: str | None) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    fields = lab.token_parameters(transaction, callback)
    if verifier is None:
        del fields["code_verifier"]
    else:
        fields["code_verifier"] = verifier
    response = await lab.browser.post("/token", data=fields)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.json()["error"] in {"invalid_request", "invalid_grant"}
    assert await lab.database.issuance_count(callback_code(callback)) == 0
    await lab.rp().exchange(transaction, callback)


@pytest.mark.parametrize("alteration", ["missing_challenge", "missing_method", "plain", "nonce"])
async def test_pkce_downgrade_and_missing_nonce_rejected(lab: ProtocolLab, alteration: str) -> None:
    transaction = lab.rp().begin()
    fields = {
        name: values[0]
        for name, values in parse_qs(urlsplit(transaction.authorization_url).query).items()
    }
    if alteration == "missing_challenge":
        del fields["code_challenge"]
    elif alteration == "missing_method":
        del fields["code_challenge_method"]
    elif alteration == "plain":
        fields["code_challenge_method"] = "plain"
        fields["code_challenge"] = transaction.verifier
    else:
        del fields["nonce"]
    response = await lab.browser.get("/authorize", params=fields, headers=lab.proof_headers)
    assert response.status_code == HTTPStatus.FOUND
    require_code_error(response.headers["location"], "invalid_request")


async def test_code_expiry_uses_issuance_time_and_is_enforced(lab: ProtocolLab) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    lab.clock.value += lab.settings.policy.code_ttl_seconds
    response = await lab.browser.post("/token", data=lab.token_parameters(transaction, callback))
    assert response.json()["error"] == "invalid_grant"
    assert await lab.database.issuance_count(callback_code(callback)) == 0


async def test_id_token_audience_is_checked_independently_of_nonce(lab: ProtocolLab) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    token, _ = await lab.rp().exchange(transaction, callback)
    with pytest.raises(InvalidIdToken):
        validate_id_token(
            token,
            settings=lab.rp_settings("sp-b"),
            nonce=transaction.nonce,
            keys=lab.keys.issuer.public_jwks(),
            clock=lab.clock,
        )


async def test_transplanted_callback_state_rejected_before_redemption(lab: ProtocolLab) -> None:
    first = lab.rp().begin()
    second = lab.rp().begin()
    callback = await lab.authorize(first)
    with pytest.raises(InvalidAuthorizationResponse):
        await lab.rp().exchange(second, callback)
    assert await lab.database.issuance_count(callback_code(callback)) == 0
    await lab.rp().exchange(first, callback)


@pytest.mark.parametrize("case", ["duplicate_state", "duplicate_code", "wrong_uri", "fragment"])
async def test_ambiguous_or_foreign_callbacks_are_rejected_before_redemption(
    lab: ProtocolLab, case: str
) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    if case == "duplicate_state":
        candidate = f"{callback}&state={transaction.state}"
    elif case == "duplicate_code":
        candidate = f"{callback}&code={callback_code(callback)}"
    elif case == "wrong_uri":
        candidate = callback.replace("sp-a.localhost", "attacker.example")
    else:
        candidate = f"{callback}#unexpected"
    with pytest.raises(InvalidAuthorizationResponse):
        await lab.rp().exchange(transaction, candidate)
    assert await lab.database.issuance_count(callback_code(callback)) == 0
    await lab.rp().exchange(transaction, callback)


async def test_disabled_client_rejected(lab: ProtocolLab) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    async with lab.database.sessions() as session:
        client = await session.get(ClientRow, transaction.client_id)
        assert client is not None
        client.enabled = False
        await session.commit()
    response = await lab.browser.post("/token", data=lab.token_parameters(transaction, callback))
    assert response.json()["error"] == "invalid_client"
    assert await lab.database.issuance_count(callback_code(callback)) == 0


async def test_repeated_form_parameters_are_rejected_before_flattening(lab: ProtocolLab) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    fields = lab.token_parameters(transaction, callback)
    body = urlencode([*fields.items(), ("client_id", "sp-b")])
    response = await lab.browser.post(
        "/token", content=body, headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert response.json()["error"] == "invalid_request"
    assert await lab.database.issuance_count(callback_code(callback)) == 0


async def test_unvalidated_redirect_is_never_used_even_on_error(lab: ProtocolLab) -> None:
    fields = {
        "response_type": "unsupported",
        "client_id": "sp-a",
        "redirect_uri": "https://attacker.example/collect",
        "state": secrets.token_urlsafe(24),
    }
    response = await lab.browser.get("/authorize", params=fields, headers=lab.proof_headers)
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "location" not in response.headers


async def test_default_factory_has_no_implicit_authenticated_user(lab: ProtocolLab) -> None:
    app = create_app(lab.service)
    transaction = lab.rp().begin()
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as browser:
        response = await browser.get(transaction.authorization_url, headers=lab.proof_headers)
    require_code_error(response.headers["location"], "login_required")


@pytest.mark.parametrize("parameters", [{"prompt": "login"}, {"max_age": "0"}, {"max_age": "30"}])
async def test_reauthentication_requirements_cannot_be_silently_ignored(
    lab: ProtocolLab, parameters: dict[str, str]
) -> None:
    transaction = lab.rp().begin()
    fields = {
        name: values[0]
        for name, values in parse_qs(urlsplit(transaction.authorization_url).query).items()
    }
    fields.update(parameters)
    response = await lab.browser.get("/authorize", params=fields, headers=lab.proof_headers)
    require_code_error(response.headers["location"], "login_required")


async def test_refresh_is_advertised_and_requires_authenticated_valid_credentials(
    lab: ProtocolLab,
) -> None:
    metadata = (await lab.browser.get("/.well-known/openid-configuration")).json()
    assert metadata["grant_types_supported"] == ["authorization_code", "refresh_token"]
    response = await lab.browser.post("/token", data={"grant_type": "refresh_token"})
    assert response.json()["error"] == "invalid_client"
    authenticated = await lab.browser.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": secrets.token_urlsafe(32),
            "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": lab.assertion(),
        },
    )
    assert authenticated.status_code == HTTPStatus.BAD_REQUEST
    assert authenticated.json()["error"] == "invalid_grant"


async def test_code_only_client_receives_no_refresh_and_cannot_use_the_refresh_grant(
    lab: ProtocolLab,
) -> None:
    async with lab.security.repository.transaction() as work:
        client = await work.get(ClientRow, "sp-a")
        assert client is not None
        client.allowed_grants = ["authorization_code"]
    rp = lab.rp()
    transaction = rp.begin()
    login = await rp.exchange_verified(transaction, await lab.authorize(transaction))
    assert login.response.refresh_token is None
    denied = await lab.browser.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": secrets.token_urlsafe(32),
            "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": lab.assertion(),
        },
    )
    assert denied.json()["error"] == "unauthorized_client"


async def test_jwks_contains_public_key_material_only(lab: ProtocolLab) -> None:
    keys = (await lab.browser.get("/jwks.json")).json()["keys"]
    assert keys[0]["kid"] == lab.keys.issuer.kid
    assert set(keys[0]) == {"kty", "n", "e", "use", "alg", "kid"}


async def test_input_limits_and_transport_policy(lab: ProtocolLab) -> None:
    response = await lab.browser.post(
        "/token",
        content=b"x" * (lab.settings.policy.max_form_bytes + 1),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert response.status_code == HTTPStatus.REQUEST_ENTITY_TOO_LARGE
    response = await lab.browser.post("/token", json={"grant_type": "authorization_code"})
    assert response.status_code == HTTPStatus.UNSUPPORTED_MEDIA_TYPE
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=lab.app)) as client:
        response = await client.post(
            "http://idp.localhost/token",
            data={"grant_type": "authorization_code"},
            headers={"X-Forwarded-Proto": "https"},
        )
        assert response.status_code == HTTPStatus.BAD_REQUEST
        assert response.json()["error"] == "invalid_request"
        response = await client.get("https://attacker.example/.well-known/openid-configuration")
        assert response.status_code == HTTPStatus.BAD_REQUEST


async def test_existing_code_and_evidence_survive_repository_recreation(lab: ProtocolLab) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    fresh_database = Database(lab.settings.database_url)
    try:
        fresh_service = OidcService(
            lab.settings,
            fresh_database,
            lab.keys.issuer,
            lab.clock,
            security=lab.security_for(fresh_database),
        )
        fresh_app = create_app(fresh_service)
        async with httpx.AsyncClient(
            base_url=lab.settings.issuer, transport=httpx.ASGITransport(app=fresh_app)
        ) as browser:
            response = await browser.post(
                "/token", data=lab.token_parameters(transaction, callback)
            )
        token = TokenResponse.model_validate(response.json())
        assert await fresh_database.issuance_evidence(token.access_token) is not None
    finally:
        await fresh_database.dispose()
