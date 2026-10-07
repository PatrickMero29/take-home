"""Negative registration metadata must never become federation trust."""

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from pydantic import ValidationError

from federated_identity.idp.schemas.clients import ClientCreate
from tests.helpers import KeyFixtures


def metadata(keys: KeyFixtures) -> dict[str, object]:
    return {
        "client_id": "sp-c",
        "redirect_uris": ("https://sp-c.localhost:8446/auth/callback",),
        "public_key_pem": keys.client_a.public_pem(),
        "key_id": keys.client_a.kid,
        "post_logout_redirect_uris": ("https://sp-c.localhost:8446/",),
        "backchannel_logout_uri": "https://sp-c.localhost:8446/backchannel-logout",
    }


def test_public_client_metadata_preserves_exact_paths_and_declares_only_supported_profile(
    key_fixtures: KeyFixtures,
) -> None:
    body = metadata(key_fixtures)
    body["redirect_uris"] = (
        "https://sp-c.localhost:8446/auth/callback",
        "https://sp-c.localhost:8446/alternate",
    )
    record = ClientCreate.model_validate(body)
    assert record.allowed_grants == ("authorization_code", "refresh_token")
    assert record.allowed_scopes == ("openid",)
    assert record.redirect_uris[1].endswith("/alternate")
    assert "PRIVATE" not in record.model_dump_json()


@pytest.mark.parametrize(
    "destination",
    [
        "http://sp-c.localhost/auth/callback",
        "https://user:password@sp-c.localhost/auth/callback",
        "https://sp-c.localhost/auth/callback#fragment",
        "https://sp-c.localhost/auth/callback#",
        "https://*.localhost/auth/callback",
        "https://sp-c.localhost/auth/../callback",
        "https://sp-c.localhost/auth/%2e%2e/callback",
        "https://sp-c.localhost/auth/callback?next=https://attacker.example",
        "https://sp-c.localhost./auth/callback",
        "https://sp-c.localhost:99999/auth/callback",
        "https://sp-c.localhost/auth/\\callback",
        "https://sp-c.localhost/auth/%0d%0a",
    ],
)
def test_ambiguous_insecure_or_unbounded_destinations_are_rejected(
    key_fixtures: KeyFixtures, destination: str
) -> None:
    body = metadata(key_fixtures)
    body["redirect_uris"] = (destination,)
    with pytest.raises(ValidationError):
        ClientCreate.model_validate(body)


@pytest.mark.parametrize(
    "case",
    [
        "private",
        "encrypted_private",
        "mixed",
        "ec",
        "weak_rsa",
        "wrong_algorithm",
        "wrong_auth",
        "unsupported_grant",
        "scope",
        "other_origin",
        "duplicate_uri",
        "embedded_jwk",
    ],
)
def test_private_keys_algorithms_capabilities_and_cross_origin_metadata_fail(
    key_fixtures: KeyFixtures, case: str
) -> None:
    body = metadata(key_fixtures)
    if case == "private":
        body["public_key_pem"] = key_fixtures.client_a.key.as_pem(private=True).decode("ascii")
    elif case == "encrypted_private":
        body["public_key_pem"] = key_fixtures.client_a.key.as_pem(
            private=True, password="not-a-production-secret"
        ).decode("ascii")
    elif case == "mixed":
        body["public_key_pem"] = (
            key_fixtures.client_a.public_pem()
            + key_fixtures.client_a.key.as_pem(private=True).decode("ascii")
        )
    elif case in {"ec", "weak_rsa"}:
        key = (
            ec.generate_private_key(ec.SECP256R1())
            if case == "ec"
            else rsa.generate_private_key(public_exponent=65537, key_size=1024)
        )
        body["public_key_pem"] = (
            key.public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode("ascii")
        )
    elif case == "wrong_algorithm":
        body["token_endpoint_auth_signing_alg"] = "HS256"
    elif case == "wrong_auth":
        body["token_endpoint_auth_method"] = "client_secret_post"
    elif case == "unsupported_grant":
        body["allowed_grants"] = ("authorization_code", "client_credentials")
    elif case == "scope":
        body["allowed_scopes"] = ("openid", "admin")
    elif case == "other_origin":
        body["backchannel_logout_uri"] = "https://sp-b.localhost:8445/backchannel-logout"
    elif case == "duplicate_uri":
        body["redirect_uris"] = ("https://sp-c.localhost:8446/auth/callback",) * 2
    else:
        body["jwk"] = key_fixtures.client_a.key.as_dict(private=True)
    with pytest.raises(ValidationError):
        ClientCreate.model_validate(body)
