"""Cryptographic positive controls and cross-purpose/recipient/time attack boundaries."""

import secrets
from dataclasses import dataclass

import pytest
from joserfc import jwt
from joserfc.jwk import OctKey

from federated_identity.common.security.artifacts import TokenResponse
from federated_identity.common.security.logout import (
    LOGOUT_EVENT,
    InvalidLogoutToken,
    LogoutClaims,
    VerifiedLogout,
    logout_header,
    sign_logout_token,
    validate_logout_token,
)
from federated_identity.common.security.oidc import (
    InvalidIdToken,
    OidcValidationProfile,
    validate_id_token,
)
from federated_identity.common.settings.policy import ProtocolPolicy
from tests.helpers import KeyFixtures, MutableClock


@dataclass(frozen=True)
class MintedLogout:
    token: str
    claims: LogoutClaims
    keys: KeyFixtures
    profile: OidcValidationProfile
    clock: MutableClock

    def validate(self, token: str | None = None) -> VerifiedLogout:
        return validate_logout_token(
            token or self.token,
            settings=self.profile,
            keys=self.keys.issuer.public_jwks(),
            clock=self.clock,
        )


@pytest.fixture
def minted_logout(key_fixtures: KeyFixtures) -> MintedLogout:
    clock = MutableClock(1800000000)
    claims = LogoutClaims(
        iss="https://idp.localhost",
        aud="sp-a",
        sid=secrets.token_urlsafe(24),
        sub="user:fixture",
        iat=clock.now(),
        exp=clock.now() + 300,
        jti=secrets.token_urlsafe(24),
        events={LOGOUT_EVENT: {}},
    )
    profile = OidcValidationProfile(
        issuer=claims.iss, client_id=claims.aud, policy=ProtocolPolicy(clock_skew_seconds=5)
    )
    return MintedLogout(
        sign_logout_token(claims, key_fixtures.issuer), claims, key_fixtures, profile, clock
    )


def test_logout_has_its_own_type_recipient_event_and_optional_subject(
    minted_logout: MintedLogout,
) -> None:
    minted = minted_logout
    validated = minted.validate()
    assert validated.claims == minted.claims and validated.header.typ == "logout+jwt"
    original = jwt.decode(minted.token, minted.keys.issuer.key, algorithms=["RS256"])
    claims = dict(original.claims)
    assert "nonce" not in claims
    del claims["sub"]
    claims["unknown_extension"] = {"ignored": True}
    token = jwt.encode(original.header, claims, minted.keys.issuer.key, algorithms=["RS256"])
    assert minted.validate(token).claims.sub is None


@pytest.mark.parametrize(
    "case",
    [
        "missing_iss",
        "missing_aud",
        "missing_iat",
        "missing_exp",
        "missing_jti",
        "missing_sid",
        "missing_events",
        "wrong_issuer",
        "wrong_audience",
        "multiple_audiences",
        "expired",
        "future_iat",
        "boolean_iat",
        "boolean_exp",
        "negative_iat",
        "excessive_lifetime",
        "zero_lifetime",
        "nonce",
        "null_nonce",
        "wrong_event",
        "event_not_object",
        "event_value_not_object",
        "empty_jti",
        "wrong_type",
        "missing_type",
        "key_url",
        "embedded_key",
    ],
)
def test_signed_invalid_logout_profiles_are_rejected(
    minted_logout: MintedLogout, case: str
) -> None:
    minted = minted_logout
    original = jwt.decode(minted.token, minted.keys.issuer.key, algorithms=["RS256"])
    claims, header = dict(original.claims), dict(original.header)
    if case.startswith("missing_"):
        if case == "missing_type":
            del header["typ"]
        else:
            del claims[case.removeprefix("missing_")]
    elif case == "wrong_issuer":
        claims["iss"] = "https://attacker.example"
    elif case == "wrong_audience":
        claims["aud"] = "sp-b"
    elif case == "multiple_audiences":
        claims["aud"] = ["sp-a", "sp-b"]
    elif case == "expired":
        claims.update(iat=minted.clock.now() - 300, exp=minted.clock.now() - 5)
    elif case == "future_iat":
        claims.update(iat=minted.clock.now() + 6, exp=minted.clock.now() + 306)
    elif case in {"boolean_iat", "boolean_exp"}:
        claims[case.removeprefix("boolean_")] = True
    elif case == "negative_iat":
        claims["iat"] = -1
    elif case == "excessive_lifetime":
        claims["exp"] = minted.clock.now() + 301
    elif case == "zero_lifetime":
        claims["exp"] = claims["iat"]
    elif case in {"nonce", "null_nonce"}:
        claims["nonce"] = None if case == "null_nonce" else secrets.token_urlsafe(24)
    elif case == "wrong_event":
        claims["events"] = {"https://attacker.example/logout": {}}
    elif case == "event_not_object":
        claims["events"] = [LOGOUT_EVENT]
    elif case == "event_value_not_object":
        claims["events"] = {LOGOUT_EVENT: "logout"}
    elif case == "empty_jti":
        claims["jti"] = ""
    elif case == "wrong_type":
        header["typ"] = "JWT"
    elif case == "key_url":
        header["jku"] = "https://attacker.example/jwks.json"
    elif case == "embedded_key":
        header["jwk"] = minted.keys.client_a.key.as_dict(private=False)
    else:
        raise AssertionError(case)
    token = jwt.encode(header, claims, minted.keys.issuer.key, algorithms=["RS256"])
    with pytest.raises(InvalidLogoutToken):
        minted.validate(token)


def test_expiry_at_exact_skew_boundary_and_logout_is_never_login_evidence(
    minted_logout: MintedLogout,
) -> None:
    minted = minted_logout
    response = TokenResponse(
        token_type="Bearer",
        access_token=secrets.token_urlsafe(32),
        id_token=minted.token,
        scope="openid",
        expires_in=300,
    )
    with pytest.raises(InvalidIdToken):
        validate_id_token(
            response,
            settings=minted.profile,
            keys=minted.keys.issuer.public_jwks(),
            clock=minted.clock,
            nonce=secrets.token_urlsafe(24),
        )
    minted.clock.value = minted.claims.exp + 4
    minted.validate()
    minted.clock.value += 1
    with pytest.raises(InvalidLogoutToken):
        minted.validate()


@pytest.mark.parametrize("case", ["forged", "algorithm", "oversize", "malformed", "unknown_key"])
def test_logout_cannot_select_signature_trust(minted_logout: MintedLogout, case: str) -> None:
    minted = minted_logout
    original = jwt.decode(minted.token, minted.keys.issuer.key, algorithms=["RS256"])
    header = dict(original.header)
    if case == "forged":
        token = jwt.encode(header, original.claims, minted.keys.client_a.key, algorithms=["RS256"])
    elif case == "algorithm":
        header["alg"] = "HS256"
        token = jwt.encode(header, original.claims, OctKey.generate_key(256), algorithms=["HS256"])
    elif case == "oversize":
        token = minted.token + "x" * 8192
    elif case == "malformed":
        token = "not.a.logout.jwt"
    else:
        header["kid"] = "unknown-key"
        token = jwt.encode(header, original.claims, minted.keys.issuer.key, algorithms=["RS256"])
    with pytest.raises(InvalidLogoutToken):
        minted.validate(token)
    if case in {"algorithm", "oversize", "malformed"}:
        with pytest.raises(InvalidLogoutToken):
            logout_header(token, max_bytes=8192)
