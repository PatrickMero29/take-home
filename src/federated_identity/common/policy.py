"""Compatibility imports for the retained protocol proof."""

from federated_identity.common.settings.policy import (
    CLIENT_AUTH_METHOD,
    FIXTURE_ACR,
    FIXTURE_AMR,
    OPENID_SCOPE,
    SIGNING_ALGORITHM,
    Clock,
    FrozenModel,
    HttpsUrl,
    Identifier,
    IdpSettings,
    ProtocolPolicy,
    SystemClock,
    TransactionValue,
    validate_https_url,
    verifier_digest,
)

__all__ = [
    "CLIENT_AUTH_METHOD",
    "FIXTURE_ACR",
    "FIXTURE_AMR",
    "OPENID_SCOPE",
    "SIGNING_ALGORITHM",
    "Clock",
    "FrozenModel",
    "HttpsUrl",
    "Identifier",
    "IdpSettings",
    "ProtocolPolicy",
    "SystemClock",
    "TransactionValue",
    "validate_https_url",
    "verifier_digest",
]
