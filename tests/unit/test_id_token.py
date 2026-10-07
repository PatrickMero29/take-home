import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass

import pytest
from authlib.oidc.core.grants.util import generate_id_token
from joserfc import jwt
from joserfc.jwk import OctKey

from federated_identity.common.policy import FIXTURE_ACR, FIXTURE_AMR, ProtocolPolicy
from federated_identity.idp.schemas.models import IdTokenClaims, TokenResponse
from federated_identity.sp.protocol.oidc import InvalidIdToken, RpSettings, validate_id_token
from tests.helpers import KeyFixtures, MutableClock


@dataclass(frozen=True)
class MintedToken:
    response: TokenResponse
    settings: RpSettings
    nonce: str
    clock: MutableClock
    keys: KeyFixtures

    def validate(self, response: TokenResponse | None = None) -> IdTokenClaims:
        return validate_id_token(
            response or self.response,
            settings=self.settings,
            nonce=self.nonce,
            keys=self.keys.issuer.public_jwks(),
            clock=self.clock,
        )


@pytest.fixture
def minted(key_fixtures: KeyFixtures) -> MintedToken:
    clock = MutableClock(int(time.time()))
    settings = RpSettings(
        issuer="https://idp.localhost",
        client_id="sp-a",
        redirect_uri="https://sp-a.localhost/callback",
        policy=ProtocolPolicy(clock_skew_seconds=0),
    )
    access_token = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(24)
    # A vetted OIDC encoder provides a positive control, including at_hash.
    mint: Callable[..., str] = generate_id_token
    id_token = mint(
        token={"access_token": access_token},
        user_info={
            "sub": "user:fixture",
            "sid": secrets.token_urlsafe(24),
            "jti": secrets.token_urlsafe(24),
        },
        key=key_fixtures.issuer.key,
        iss=settings.issuer,
        aud=settings.client_id,
        alg="RS256",
        exp=settings.policy.id_token_ttl_seconds,
        nonce=nonce,
        auth_time=clock.now() - 60,
        acr=FIXTURE_ACR,
        amr=[FIXTURE_AMR],
        kid=key_fixtures.issuer.kid,
    )
    return MintedToken(
        TokenResponse(
            token_type="Bearer",
            access_token=access_token,
            id_token=id_token,
            expires_in=settings.policy.access_token_ttl_seconds,
            scope="openid",
        ),
        settings,
        nonce,
        clock,
        key_fixtures,
    )


def test_vetted_encoder_positive_control(minted: MintedToken) -> None:
    claims = minted.validate()
    assert claims.aud == "sp-a"
    assert claims.auth_time < claims.iat


@pytest.mark.parametrize(
    "case",
    [
        "missing_iss",
        "missing_sub",
        "missing_aud",
        "missing_exp",
        "missing_iat",
        "missing_nonce",
        "missing_sid",
        "missing_jti",
        "wrong_issuer",
        "wrong_audience",
        "multiple_audiences",
        "wrong_nonce",
        "expired",
        "future_auth_time",
        "boolean_iat",
        "excessive_lifetime",
        "wrong_type",
        "embedded_key",
        "untrusted_key_url",
    ],
)
def test_signed_but_invalid_claims_are_rejected(minted: MintedToken, case: str) -> None:
    original = jwt.decode(minted.response.id_token, minted.keys.issuer.key, algorithms=["RS256"])
    claims = dict(original.claims)
    header = dict(original.header)
    if case.startswith("missing_"):
        del claims[case.removeprefix("missing_")]
    elif case == "wrong_issuer":
        claims["iss"] = "https://attacker.example"
    elif case == "wrong_audience":
        claims["aud"] = "sp-b"
    elif case == "multiple_audiences":
        claims.update(aud=["sp-a", "sp-b"], azp="sp-a")
    elif case == "wrong_nonce":
        claims["nonce"] = secrets.token_urlsafe(24)
    elif case == "expired":
        claims["exp"] = minted.clock.now() - 1
    elif case == "future_auth_time":
        claims["auth_time"] = minted.clock.now() + 1
    elif case == "boolean_iat":
        claims["iat"] = True
    elif case == "excessive_lifetime":
        claims["exp"] = minted.clock.now() + minted.settings.policy.id_token_ttl_seconds + 1
    elif case == "wrong_type":
        header["typ"] = "logout+jwt"
    elif case == "embedded_key":
        header["jwk"] = minted.keys.client_a.key.as_dict(private=False)
    elif case == "untrusted_key_url":
        header["jku"] = "https://attacker.example/jwks"
    else:
        raise AssertionError(f"Unknown test case: {case}")
    forged = jwt.encode(header, claims, minted.keys.issuer.key, algorithms=["RS256"])
    response = minted.response.model_copy(update={"id_token": forged})
    with pytest.raises(InvalidIdToken):
        minted.validate(response)


def test_expiry_is_rejected_at_the_exact_boundary(minted: MintedToken) -> None:
    claims = minted.validate()
    minted.clock.value = claims.exp
    with pytest.raises(InvalidIdToken):
        minted.validate()


def test_access_token_hash_binds_the_token_pair(minted: MintedToken) -> None:
    response = minted.response.model_copy(update={"access_token": secrets.token_urlsafe(32)})
    with pytest.raises(InvalidIdToken):
        minted.validate(response)


def test_algorithm_is_not_selected_by_the_token(minted: MintedToken) -> None:
    original = jwt.decode(minted.response.id_token, minted.keys.issuer.key, algorithms=["RS256"])
    symmetric = OctKey.generate_key(256)
    token = jwt.encode(
        {"alg": "HS256", "typ": "JWT", "kid": minted.keys.issuer.kid},
        original.claims,
        symmetric,
        algorithms=["HS256"],
    )
    with pytest.raises(InvalidIdToken):
        minted.validate(minted.response.model_copy(update={"id_token": token}))


def test_an_unregistered_signing_key_is_rejected(minted: MintedToken) -> None:
    original = jwt.decode(minted.response.id_token, minted.keys.issuer.key, algorithms=["RS256"])
    token = jwt.encode(
        {"alg": "RS256", "typ": "JWT", "kid": minted.keys.issuer.kid},
        original.claims,
        minted.keys.client_a.key,
        algorithms=["RS256"],
    )
    with pytest.raises(InvalidIdToken):
        minted.validate(minted.response.model_copy(update={"id_token": token}))
