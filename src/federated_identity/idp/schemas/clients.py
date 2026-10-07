"""Closed-federation client metadata: exact HTTPS destinations and public-only RSA trust."""

import ipaddress
import re
from typing import Annotated, Literal
from urllib.parse import unquote, urlsplit

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import AfterValidator, Field, field_validator, model_validator

from federated_identity.common.settings.policy import FrozenModel, validate_https_url

type ClientId = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")]
type KeyId = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")]


def exact_client_uri(value: str) -> str:
    validate_https_url(value)
    parsed = urlsplit(value)
    hostname = parsed.hostname or ""
    decoded = unquote(parsed.path)
    if (
        len(value) > 2048
        or "\\" in value
        or "*" in value
        or "#" in value
        or parsed.query
        or not parsed.path.startswith("/")
        or hostname.endswith(".")
        or any(ord(char) < 33 or ord(char) == 127 for char in decoded)
        or "\\" in decoded
        or any(part in {".", ".."} for part in decoded.split("/"))
    ):
        raise ValueError("Client destinations require unambiguous exact HTTPS paths")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        labels = hostname.split(".")
        if len(hostname) > 253 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels
        ):
            raise ValueError("Client destinations require a valid hostname") from None
    return value


type ClientUri = Annotated[str, AfterValidator(exact_client_uri)]


def uri_origin(value: str) -> tuple[str, str, int]:
    parsed = urlsplit(value)
    return parsed.scheme, parsed.hostname or "", parsed.port or 443


def public_authentication_key(value: str) -> str:
    if (
        not 100 <= len(value) <= 8192
        or not value.isascii()
        or "PRIVATE KEY" in value
        or value.count("-----BEGIN ") != 1
        or value.count("-----END ") != 1
    ):
        raise ValueError("A bounded public RSA key is required")
    try:
        key = serialization.load_pem_public_key(value.encode("ascii"))
    except (ValueError, TypeError) as error:
        raise ValueError("Only PEM public authentication keys are accepted") from error
    if (
        not isinstance(key, rsa.RSAPublicKey)
        or not 2048 <= key.key_size <= 4096
        or key.public_numbers().e != 65537
    ):
        raise ValueError("Authentication keys require approved RSA parameters for RS256")
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")


class ClientDestinations(FrozenModel):
    redirect_uris: tuple[ClientUri, ...] = Field(min_length=1, max_length=8)
    allowed_grants: tuple[Literal["authorization_code", "refresh_token"], ...] = (
        "authorization_code",
        "refresh_token",
    )
    allowed_scopes: tuple[Literal["openid"], ...] = ("openid",)
    post_logout_redirect_uris: tuple[ClientUri, ...] = Field(default=(), max_length=8)
    backchannel_logout_uri: ClientUri | None = None

    @model_validator(mode="after")
    def bounded_capabilities_and_origins(self) -> "ClientDestinations":
        if self.allowed_grants not in {
            ("authorization_code",),
            ("authorization_code", "refresh_token"),
        } or self.allowed_scopes != ("openid",):
            raise ValueError(
                "Registration requires the implemented code/optional-refresh openid profile"
            )
        destinations = [*self.redirect_uris, *self.post_logout_redirect_uris]
        if self.backchannel_logout_uri is not None:
            destinations.append(self.backchannel_logout_uri)
        if len({uri_origin(uri) for uri in destinations}) != 1:
            raise ValueError("A client owns one HTTPS origin for login and logout")
        for group in (self.redirect_uris, self.post_logout_redirect_uris):
            if len(set(group)) != len(group):
                raise ValueError("Registered URI allowlists must not contain duplicates")
        return self


class ClientCredential(FrozenModel):
    public_key_pem: str = Field(min_length=100, max_length=8192)
    key_id: KeyId
    token_endpoint_auth_method: Literal["private_key_jwt"] = "private_key_jwt"
    token_endpoint_auth_signing_alg: Literal["RS256"] = "RS256"

    @field_validator("public_key_pem")
    @classmethod
    def public_key(cls, value: str) -> str:
        return public_authentication_key(value)


class ClientMetadata(ClientDestinations, ClientCredential):
    client_id: ClientId

    @field_validator("client_id")
    @classmethod
    def distinct_actor(cls, value: str) -> str:
        if value in {"idp", "operator"}:
            raise ValueError("A federation client must have its own actor identity")
        return value


class ClientRegistration(ClientMetadata):
    enabled: bool = True
    registration_version: int = Field(default=1, ge=1)
    compromised_key_id: KeyId | None = None


class ClientCreate(ClientMetadata):
    enabled: bool = True


class ClientUpdate(ClientDestinations):
    expected_version: int = Field(ge=1)


class ClientStateChange(FrozenModel):
    expected_version: int = Field(ge=1)


class ClientCredentialReplacement(ClientCredential):
    expected_version: int = Field(ge=1)
