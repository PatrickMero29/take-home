"""Public rotation controls and typed IDP artifact retention facts."""

from enum import StrEnum

from pydantic import Field

from federated_identity.common.security.keys import PublicRsaJwk
from federated_identity.common.security.model import KeyState
from federated_identity.common.settings.policy import FrozenModel
from federated_identity.idp.schemas.clients import KeyId


class SignedArtifactPurpose(StrEnum):
    ID_TOKEN = "id_token"
    LOGOUT_TOKEN = "logout_token"


class SigningKeyInfo(FrozenModel):
    key_id: KeyId
    state: KeyState
    created_at: int
    published_at: int | None
    verification_deadline: int
    public_key: PublicRsaJwk


class SigningKeyPrepare(FrozenModel):
    """Empty request: key material is generated inside the IDP."""


class SigningKeyActivation(FrozenModel):
    expected_active_key_id: KeyId


class SigningKeyRetirement(FrozenModel):
    expected_verification_deadline: int = Field(ge=0)


class SigningKeyContainment(FrozenModel):
    replacement_key_id: KeyId
    expected_active_key_id: KeyId


class SigningKeyContainmentResult(FrozenModel):
    compromised: SigningKeyInfo
    active: SigningKeyInfo
    revoked_grants: int = Field(ge=0)
