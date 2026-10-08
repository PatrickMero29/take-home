"""A vetted signature cannot manufacture inconsistent methods or a stronger event."""

import pytest
from joserfc import jwt

from federated_identity.common.security.model import Assurance
from federated_identity.common.security.oidc import InvalidIdToken, validate_login_token
from tests.unit.test_id_token import MintedToken
from tests.unit.test_id_token import minted as minted


@pytest.mark.parametrize(
    "case", ["acr_only", "methods_only", "unknown_methods", "duplicate_methods"]
)
def test_forged_assurance_facts_fail_the_event_contract(minted: MintedToken, case: str) -> None:
    original = jwt.decode(minted.response.id_token, minted.keys.issuer.key, algorithms=["RS256"])
    claims = dict(original.claims)
    if case == "acr_only":
        claims["acr"] = Assurance.PASSWORD_TOTP.value
    elif case == "methods_only":
        claims["amr"] = ["pwd", "otp"]
    elif case == "unknown_methods":
        claims.update(acr=Assurance.PASSWORD_TOTP.value, amr=["pwd", "magic"])
    else:
        claims.update(acr=Assurance.PASSWORD_TOTP.value, amr=["pwd", "otp", "otp"])
    token = jwt.encode(original.header, claims, minted.keys.issuer.key, algorithms=["RS256"])
    validated = validate_login_token(
        minted.response.model_copy(update={"id_token": token}),
        settings=minted.settings,
        nonce=minted.nonce,
        keys=minted.keys.issuer.public_jwks(),
        clock=minted.clock,
    )
    with pytest.raises(InvalidIdToken):
        validated.evidence("untrusted-event")
