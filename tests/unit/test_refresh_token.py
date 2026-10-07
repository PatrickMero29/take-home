"""Refresh is a separate validation context and cannot manufacture authentication history."""

import secrets
from collections.abc import Callable
from dataclasses import dataclass

import pytest
from authlib.oidc.core.grants.util import generate_id_token
from joserfc import jwt

from federated_identity.common.security.artifacts import RefreshTokenResponse, TokenResponse
from federated_identity.common.security.model import (
    Assurance,
    AuthenticationEvent,
    AuthenticationMethod,
    SubjectIdentity,
)
from federated_identity.common.security.oidc import (
    InvalidIdToken,
    OidcValidationProfile,
    validate_login_token,
    validate_refresh_token,
)
from federated_identity.common.settings.policy import ProtocolPolicy
from tests.helpers import KeyFixtures, MutableClock


@dataclass(frozen=True)
class RefreshFixture:
    response: RefreshTokenResponse
    authentication: AuthenticationEvent
    settings: OidcValidationProfile
    clock: MutableClock
    keys: KeyFixtures
    nonce: str

    def validate(self, response: RefreshTokenResponse | None = None) -> None:
        validate_refresh_token(
            response or self.response,
            settings=self.settings,
            authentication=self.authentication,
            nonce=self.nonce,
            keys=self.keys.issuer.public_jwks(),
            clock=self.clock,
        )


@pytest.fixture
def refresh_fixture(key_fixtures: KeyFixtures) -> RefreshFixture:
    clock = MutableClock(1800000000)
    settings = OidcValidationProfile(
        issuer="https://idp.localhost",
        client_id="sp-a",
        policy=ProtocolPolicy(clock_skew_seconds=0),
    )
    authentication = AuthenticationEvent(
        event_id="authentication:fixture",
        session_id="session:fixture",
        subject=SubjectIdentity(issuer=settings.issuer, subject="user:fixture"),
        authenticated_at=clock.now() - 60,
        assurance=Assurance.PASSWORD,
        methods=(AuthenticationMethod.PASSWORD,),
    )
    access = secrets.token_urlsafe(32)
    mint: Callable[..., str] = generate_id_token
    token = mint(
        token={"access_token": access},
        user_info={
            "sub": authentication.subject.subject,
            "sid": authentication.session_id,
            "jti": secrets.token_urlsafe(24),
            "iat": clock.now(),
            "exp": clock.now() + 300,
        },
        key=key_fixtures.issuer.key,
        iss=settings.issuer,
        aud="sp-a",
        alg="RS256",
        auth_time=authentication.authenticated_at,
        acr=authentication.assurance.value,
        amr=["pwd"],
        kid=key_fixtures.issuer.kid,
    )
    return RefreshFixture(
        response=RefreshTokenResponse(
            token_type="Bearer",
            access_token=access,
            id_token=token,
            refresh_token=secrets.token_urlsafe(32),
            expires_in=300,
            scope="openid",
        ),
        authentication=authentication,
        settings=settings,
        clock=clock,
        keys=key_fixtures,
        nonce=secrets.token_urlsafe(24),
    )


def test_refresh_omits_nonce_but_login_still_requires_it(refresh_fixture: RefreshFixture) -> None:
    fixture = refresh_fixture
    fixture.validate()
    response = TokenResponse.model_validate_json(fixture.response.model_dump_json())
    with pytest.raises(InvalidIdToken):
        validate_login_token(
            response,
            settings=fixture.settings,
            nonce=fixture.nonce,
            keys=fixture.keys.issuer.public_jwks(),
            clock=fixture.clock,
        )


def test_present_refresh_nonce_matches_the_original_flow(refresh_fixture: RefreshFixture) -> None:
    fixture = refresh_fixture
    decoded = jwt.decode(fixture.response.id_token, fixture.keys.issuer.key, algorithms=["RS256"])
    decoded.claims["nonce"] = fixture.nonce
    token = jwt.encode(
        decoded.header, decoded.claims, fixture.keys.issuer.key, algorithms=["RS256"]
    )
    fixture.validate(fixture.response.model_copy(update={"id_token": token}))


@pytest.mark.parametrize(
    "case",
    [
        "nonce",
        "subject",
        "session",
        "auth_time",
        "assurance",
        "methods",
        "issuer",
        "audience",
        "type",
        "embedded_key",
        "expired",
        "at_hash",
        "boolean_date",
    ],
)
def test_signed_refresh_substitution_and_fake_freshness_are_rejected(
    refresh_fixture: RefreshFixture, case: str
) -> None:
    fixture = refresh_fixture
    decoded = jwt.decode(fixture.response.id_token, fixture.keys.issuer.key, algorithms=["RS256"])
    header, claims = dict(decoded.header), dict(decoded.claims)
    if case == "nonce":
        claims["nonce"] = secrets.token_urlsafe(24)
    elif case == "subject":
        claims["sub"] = "user:other"
    elif case == "session":
        claims["sid"] = "session:other"
    elif case == "auth_time":
        claims["auth_time"] = fixture.clock.now()
    elif case == "assurance":
        claims["acr"] = Assurance.PASSWORD_TOTP.value
    elif case == "methods":
        claims["amr"] = ["pwd", "otp"]
    elif case == "issuer":
        claims["iss"] = "https://attacker.example"
    elif case == "audience":
        claims["aud"] = "sp-b"
    elif case == "type":
        header["typ"] = "logout+jwt"
    elif case == "embedded_key":
        header["jwk"] = fixture.keys.client_a.key.as_dict(private=False)
    elif case == "expired":
        claims["exp"] = fixture.clock.now()
    elif case == "boolean_date":
        claims["iat"] = True
    else:
        claims["at_hash"] = "not-the-access-hash"
    token = jwt.encode(header, claims, fixture.keys.issuer.key, algorithms=["RS256"])
    with pytest.raises(InvalidIdToken):
        fixture.validate(fixture.response.model_copy(update={"id_token": token}))
