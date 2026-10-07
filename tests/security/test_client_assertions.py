import asyncio
import secrets
from http import HTTPStatus

import httpx2 as httpx
import pytest
from sqlalchemy import func, select

from federated_identity.idp.api.app import create_app
from federated_identity.idp.repositories.database import Database
from federated_identity.idp.repositories.tables import AssertionReplayRow
from federated_identity.idp.schemas.models import OAuthErrorResponse
from federated_identity.idp.services.oidc import OidcService
from tests.helpers import ProtocolLab, callback_code, verify_assertion_claims

pytestmark = pytest.mark.integration


@pytest.mark.parametrize(
    "case",
    [
        "wrong_audience",
        "multiple_audiences",
        "wrong_issuer",
        "wrong_subject",
        "expired",
        "future",
        "excessive_lifetime",
        "empty_lifetime",
        "missing_exp",
        "missing_iat",
        "missing_jti",
        "wrong_signature",
        "untrusted_jwk",
        "untrusted_jku",
        "missing_kid",
        "wrong_type",
        "boolean_timestamp",
    ],
)
async def test_invalid_assertion_never_consumes_code(lab: ProtocolLab, case: str) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    now = lab.clock.now()
    claims: dict[str, object] = {}
    header: dict[str, object] = {}
    removed: str | None = None
    signer = lab.keys.client_a
    if case == "wrong_audience":
        claims["aud"] = lab.settings.issuer
    elif case == "multiple_audiences":
        claims["aud"] = [lab.settings.token_endpoint, "https://attacker.example/token"]
    elif case == "wrong_issuer":
        claims["iss"] = "sp-b"
    elif case == "wrong_subject":
        claims["sub"] = "sp-b"
    elif case == "expired":
        claims.update(iat=now - 100, exp=now - 40)
    elif case == "future":
        claims.update(iat=now + 30, exp=now + 60)
    elif case == "excessive_lifetime":
        claims["exp"] = now + lab.settings.policy.assertion_ttl_seconds + 1
    elif case == "empty_lifetime":
        claims["exp"] = now
    elif case.startswith("missing_") and case != "missing_kid":
        removed = case.removeprefix("missing_")
    elif case == "wrong_signature":
        signer = lab.keys.client_b
        # Use the legitimate kid to exercise signature pinning, not only lookup.
        header["kid"] = lab.keys.client_a.kid
    elif case == "untrusted_jwk":
        header["jwk"] = lab.keys.client_b.key.as_dict(private=False)
    elif case == "untrusted_jku":
        header["jku"] = "https://attacker.example/keys"
    elif case == "missing_kid":
        header["kid"] = ""
    elif case == "wrong_type":
        header["typ"] = "logout+jwt"
    elif case == "boolean_timestamp":
        claims["iat"] = True
    else:
        raise AssertionError(f"Unknown test case: {case}")
    assertion = lab.assertion(
        claims_update=claims,
        header_update=header,
        remove_claim=removed,
        signing_key=signer,
    )
    response = await lab.browser.post(
        "/token", data=lab.token_parameters(transaction, callback, assertion=assertion)
    )
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert OAuthErrorResponse.model_validate(response.json()).error == "invalid_client"
    assert await lab.database.issuance_count(callback_code(callback)) == 0
    await lab.rp().exchange(transaction, callback)


async def test_conflicting_body_client_id_rejected(lab: ProtocolLab) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    fields = lab.token_parameters(transaction, callback)
    fields["client_id"] = "sp-b"
    response = await lab.browser.post("/token", data=fields)
    assert response.json()["error"] == "invalid_client"
    assert await lab.database.issuance_count(callback_code(callback)) == 0


async def test_unknown_client_is_rejected(lab: ProtocolLab) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    assertion = lab.assertion(claims_update={"iss": "unknown-client", "sub": "unknown-client"})
    response = await lab.browser.post(
        "/token", data=lab.token_parameters(transaction, callback, assertion=assertion)
    )
    assert response.json()["error"] == "invalid_client"
    assert await lab.database.issuance_count(callback_code(callback)) == 0


async def test_assertion_replay_is_atomic_under_concurrent_requests(lab: ProtocolLab) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    assertion = lab.assertion()
    fields = lab.token_parameters(transaction, callback, assertion=assertion)
    responses = await asyncio.gather(*(lab.browser.post("/token", data=fields) for _ in range(8)))
    assert sum(response.status_code == HTTPStatus.OK for response in responses) == 1
    for response in responses:
        if response.status_code != HTTPStatus.OK:
            assert response.json()["error"] == "invalid_client"
    assert await lab.database.issuance_count(callback_code(callback)) == 1


async def test_authenticated_assertion_is_reserved_even_when_grant_validation_fails(
    lab: ProtocolLab,
) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    assertion = lab.assertion()
    fields = lab.token_parameters(transaction, callback, assertion=assertion)
    fields["code_verifier"] = secrets.token_urlsafe(48)
    response = await lab.browser.post("/token", data=fields)
    assert response.json()["error"] == "invalid_grant"

    fields["code_verifier"] = transaction.verifier
    response = await lab.browser.post("/token", data=fields)
    assert response.json()["error"] == "invalid_client"
    # A fresh assertion can still redeem the unconsumed, rightful code.
    await lab.rp().exchange(transaction, callback)


async def test_failed_signature_does_not_reserve_a_legitimate_jti(lab: ProtocolLab) -> None:
    transaction = lab.rp().begin()
    callback = await lab.authorize(transaction)
    jti = secrets.token_urlsafe(24)
    forged = lab.assertion(
        claims_update={"jti": jti},
        signing_key=lab.keys.client_b,
        header_update={"kid": lab.keys.client_a.kid},
    )
    response = await lab.browser.post(
        "/token", data=lab.token_parameters(transaction, callback, assertion=forged)
    )
    assert response.json()["error"] == "invalid_client"
    legitimate = lab.assertion(claims_update={"jti": jti})
    response = await lab.browser.post(
        "/token", data=lab.token_parameters(transaction, callback, assertion=legitimate)
    )
    assert response.status_code == HTTPStatus.OK


async def test_replay_state_survives_a_new_application_and_pool(lab: ProtocolLab) -> None:
    first = lab.rp().begin()
    callback = await lab.authorize(first)
    assertion = lab.assertion()
    response = await lab.browser.post(
        "/token", data=lab.token_parameters(first, callback, assertion=assertion)
    )
    assert response.status_code == HTTPStatus.OK

    second = lab.rp().begin()
    second_callback = await lab.authorize(second)
    database = Database(lab.settings.database_url)
    try:
        service = OidcService(
            lab.settings, database, lab.keys.issuer, lab.clock, security=lab.security_for(database)
        )
        app = create_app(service)
        async with httpx.AsyncClient(
            base_url=lab.settings.issuer, transport=httpx.ASGITransport(app=app)
        ) as browser:
            response = await browser.post(
                "/token", data=lab.token_parameters(second, second_callback, assertion=assertion)
            )
        assert response.json()["error"] == "invalid_client"
        decoded = verify_assertion_claims(assertion, lab.keys.client_a, lab.clock)
        async with database.sessions() as session:
            count = await session.scalar(
                select(func.count())
                .select_from(AssertionReplayRow)
                .where(
                    AssertionReplayRow.client_id == "sp-a",
                    AssertionReplayRow.jti == decoded["jti"],
                )
            )
            assert count == 1
    finally:
        await database.dispose()


async def test_identity_token_is_not_a_client_assertion(lab: ProtocolLab) -> None:
    first = lab.rp().begin()
    callback = await lab.authorize(first)
    identity_token, _ = await lab.rp().exchange(first, callback)
    second = lab.rp().begin()
    second_callback = await lab.authorize(second)
    response = await lab.browser.post(
        "/token",
        data=lab.token_parameters(second, second_callback, assertion=identity_token.id_token),
    )
    assert response.json()["error"] == "invalid_client"
    assert await lab.database.issuance_count(callback_code(second_callback)) == 0
