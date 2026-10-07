"""Shared, immutable security facts and recipient-bound lifecycle snapshots."""

from enum import StrEnum
from typing import Annotated

from pydantic import Field, SecretStr, model_validator

from federated_identity.common.settings.policy import (
    FIXTURE_ACR,
    FIXTURE_AMR,
    FrozenModel,
    HttpsUrl,
    Identifier,
)

type Timestamp = Annotated[int, Field(ge=1)]
type Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class Assurance(StrEnum):
    FIXTURE = FIXTURE_ACR
    PASSWORD = "urn:take-home:acr:password"
    PASSWORD_TOTP = "urn:take-home:acr:password-totp"


class AuthenticationMethod(StrEnum):
    FIXTURE = FIXTURE_AMR
    PASSWORD = "pwd"
    OTP = "otp"


class KeyState(StrEnum):
    PREPARED = "prepared"
    ACTIVE = "active"
    DRAINING = "draining"
    RETIRED = "retired"
    REVOKED = "revoked"


class RevocationReason(StrEnum):
    LOGOUT = "logout"
    CLIENT_COMPROMISE = "client_compromise"
    KEY_COMPROMISE = "key_compromise"
    REFRESH_REPLAY = "refresh_replay"
    CODE_REPLAY = "code_replay"
    TOKEN_REVOCATION = "token_revocation"
    USER_REVOCATION = "user_revocation"
    CLIENT_METADATA_CHANGE = "client_metadata_change"
    CLIENT_KEY_REPLACEMENT = "client_key_replacement"
    OPERATOR = "operator"


class Denial(StrEnum):
    MISSING = "missing"
    RECIPIENT = "wrong_recipient"
    BINDING = "invalid_binding"
    EXPIRED = "expired"
    REVOKED = "revoked"
    CLIENT_DISABLED = "client_disabled"
    KEY_REVOKED = "key_revoked"
    ASSURANCE = "assurance_required"
    RECENCY = "reauthentication_required"
    REPLAY = "refresh_replay"
    PURPOSE = "wrong_artifact_purpose"


class SecurityDenied(ValueError):
    def __init__(self, reason: Denial) -> None:
        super().__init__(reason.value)
        self.reason = reason


class SubjectIdentity(FrozenModel):
    issuer: HttpsUrl
    subject: Identifier

    @model_validator(mode="after")
    def oidc_subject(self) -> "SubjectIdentity":
        if not self.subject.isascii() or any(ord(char) < 33 for char in self.subject):
            raise ValueError("An OIDC subject is a nonempty opaque ASCII identifier")
        return self


def assurance_for(methods: tuple[AuthenticationMethod, ...]) -> Assurance:
    selected = frozenset(methods)
    if len(selected) != len(methods):
        raise ValueError("Authentication methods must not repeat")
    if selected == {AuthenticationMethod.FIXTURE}:
        return Assurance.FIXTURE
    if selected == {AuthenticationMethod.PASSWORD}:
        return Assurance.PASSWORD
    if selected == {AuthenticationMethod.PASSWORD, AuthenticationMethod.OTP}:
        return Assurance.PASSWORD_TOTP
    raise ValueError("No approved assurance class describes these verified methods")


class TrustedAuthentication(FrozenModel):
    """Created by the trusted authenticator, never from incoming JWT or form claims."""

    subject: SubjectIdentity
    authenticated_at: Timestamp
    methods: tuple[AuthenticationMethod, ...]

    @model_validator(mode="after")
    def approved_methods(self) -> "TrustedAuthentication":
        assurance_for(self.methods)
        return self


class IdpSession(FrozenModel):
    session_id: Identifier
    subject: SubjectIdentity
    created_at: Timestamp
    expires_at: Timestamp
    revoked_at: Timestamp | None = None
    revocation_reason: RevocationReason | None = None

    @model_validator(mode="after")
    def lifetime(self) -> "IdpSession":
        if self.expires_at <= self.created_at:
            raise ValueError("An IDP session requires a positive absolute lifetime")
        if (self.revoked_at is None) != (self.revocation_reason is None):
            raise ValueError("Revocation time and reason must be recorded together")
        return self


class AuthenticationEvent(FrozenModel):
    event_id: Identifier
    session_id: Identifier
    subject: SubjectIdentity
    authenticated_at: Timestamp
    assurance: Assurance
    methods: tuple[AuthenticationMethod, ...]

    @model_validator(mode="after")
    def verified_assurance(self) -> "AuthenticationEvent":
        if self.assurance != assurance_for(self.methods):
            raise ValueError("Assurance must describe the actually verified authentication methods")
        return self


class SigningTrust(FrozenModel):
    key_id: Identifier
    state: KeyState
    created_at: Timestamp
    verification_deadline: int = Field(default=0, ge=0)


class LoginEvidence(FrozenModel):
    """JOSE-verified login facts, supplied by the protocol boundary before issuance commits."""

    token_id: Identifier
    token_digest: Digest
    client_id: Identifier
    signing_key_id: Identifier
    authentication: AuthenticationEvent
    issued_at: Timestamp
    expires_at: Timestamp

    @model_validator(mode="after")
    def lifetime(self) -> "LoginEvidence":
        if self.expires_at <= self.issued_at:
            raise ValueError("Login evidence requires a positive artifact lifetime")
        return self


class FederationGrant(FrozenModel):
    grant_id: Identifier
    client_id: Identifier
    session_id: Identifier
    event_id: Identifier
    root_signing_key_id: Identifier
    created_at: Timestamp
    expires_at: Timestamp
    revoked_at: Timestamp | None = None
    revocation_reason: RevocationReason | None = None

    @model_validator(mode="after")
    def lifetime(self) -> "FederationGrant":
        if self.expires_at <= self.created_at:
            raise ValueError("A grant requires a positive absolute lifetime")
        if (self.revoked_at is None) != (self.revocation_reason is None):
            raise ValueError("Revocation time and reason must be recorded together")
        return self


class RefreshFamily(FrozenModel):
    family_id: Identifier
    grant_id: Identifier
    created_at: Timestamp
    expires_at: Timestamp
    generation: int = Field(ge=0)
    revoked_at: Timestamp | None = None

    @model_validator(mode="after")
    def lifetime(self) -> "RefreshFamily":
        if self.expires_at <= self.created_at:
            raise ValueError("A refresh family requires a positive absolute lifetime")
        return self


class GrantSnapshot(FrozenModel):
    grant: FederationGrant
    authentication: AuthenticationEvent
    evidence: LoginEvidence
    session_expires_at: Timestamp
    family: RefreshFamily
    policy_revision: int = Field(ge=0)

    @model_validator(mode="after")
    def consistent_lineage(self) -> "GrantSnapshot":
        if (
            self.grant.session_id != self.authentication.session_id
            or self.grant.event_id != self.authentication.event_id
            or self.evidence.authentication != self.authentication
            or self.evidence.client_id != self.grant.client_id
            or self.evidence.signing_key_id != self.grant.root_signing_key_id
            or self.family.grant_id != self.grant.grant_id
            or self.family.created_at < self.grant.created_at
            or self.family.expires_at > self.grant.expires_at
            or self.grant.expires_at > self.session_expires_at
        ):
            raise ValueError("Grant, event, evidence, family, and session must share one lineage")
        return self


class IssuedCredentials(FrozenModel):
    access_token: SecretStr
    refresh_token: SecretStr
    access_expires_at: Timestamp
    refresh_expires_at: Timestamp
    context: GrantSnapshot

    @model_validator(mode="after")
    def parent_lifetimes(self) -> "IssuedCredentials":
        if (
            self.access_expires_at > self.context.family.expires_at
            or self.access_expires_at <= self.context.grant.created_at
            or self.refresh_expires_at != self.context.family.expires_at
        ):
            raise ValueError("Credentials cannot extend their grant or refresh family")
        return self


class AuthenticationRequirement(FrozenModel):
    minimum: Assurance = Assurance.PASSWORD
    max_age_seconds: int | None = Field(default=None, ge=0, le=86400)
    reauthenticate_since: Timestamp | None = None


class SpSessionEvidence(FrozenModel):
    issuer: HttpsUrl
    client_id: Identifier
    subject: Identifier
    session_id: Identifier
    grant_id: Identifier
    event_id: Identifier
    evidence_id: Identifier
    token_digest: Digest
    signing_key_id: Identifier
    authentication: AuthenticationEvent
    created_at: Timestamp
    expires_at: Timestamp
    last_seen_at: Timestamp
    idle_expires_at: Timestamp
    revoked_at: Timestamp | None = None

    @model_validator(mode="after")
    def bound_session(self) -> "SpSessionEvidence":
        if (
            self.issuer != self.authentication.subject.issuer
            or self.subject != self.authentication.subject.subject
            or self.session_id != self.authentication.session_id
            or self.event_id != self.authentication.event_id
            or not self.created_at <= self.last_seen_at < self.idle_expires_at <= self.expires_at
        ):
            raise ValueError(
                "An SP session needs bound authentication and positive bounded lifetimes"
            )
        return self


class LifecyclePolicy(FrozenModel):
    idp_session_seconds: int = Field(default=3600, ge=60, le=86400)
    grant_seconds: int = Field(default=3600, ge=60, le=86400)
    refresh_family_seconds: int = Field(default=3600, ge=60, le=86400)
    sp_session_seconds: int = Field(default=3600, ge=60, le=86400)
    sp_idle_seconds: int = Field(default=900, ge=30, le=3600)
