"""Purpose, lineage, assurance, and transition policy independent of transport/crypto."""

from enum import StrEnum

from federated_identity.common.security.contracts import GrantStatus, GrantUnavailable
from federated_identity.common.security.model import (
    Assurance,
    AuthenticationEvent,
    AuthenticationRequirement,
    Denial,
    FederationGrant,
    GrantSnapshot,
    IdpSession,
    KeyState,
    SecurityDenied,
    SigningTrust,
    SpSessionEvidence,
)


class ArtifactPurpose(StrEnum):
    ID_TOKEN = "id_token"
    CODE = "authorization_code"
    CLIENT_ASSERTION = "client_assertion"
    ACCESS_TOKEN = "access_token"
    REFRESH_TOKEN = "refresh_token"
    LOGOUT_TOKEN = "logout_token"
    IDP_COOKIE = "idp_cookie"
    SP_COOKIE = "sp_cookie"


class ArtifactUse(StrEnum):
    SP_LOGIN = "sp_login"
    CODE_REDEMPTION = "code_redemption"
    CLIENT_AUTH = "client_authentication"
    RESOURCE_CHECK = "resource_check"
    REFRESH = "refresh"
    BACKCHANNEL_LOGOUT = "backchannel_logout"
    LOGOUT_HINT = "logout_hint"
    IDP_SESSION = "idp_session"
    SP_SESSION = "sp_session"
    ADMIN = "administrator_authentication"


def require_artifact_use(
    purpose: ArtifactPurpose,
    use: ArtifactUse,
    *,
    intended_client: str | None = None,
    authenticated_client: str | None = None,
) -> None:
    allowed = {
        ArtifactPurpose.ID_TOKEN: {ArtifactUse.SP_LOGIN, ArtifactUse.LOGOUT_HINT},
        ArtifactPurpose.CODE: {ArtifactUse.CODE_REDEMPTION},
        ArtifactPurpose.CLIENT_ASSERTION: {ArtifactUse.CLIENT_AUTH},
        ArtifactPurpose.ACCESS_TOKEN: {ArtifactUse.RESOURCE_CHECK},
        ArtifactPurpose.REFRESH_TOKEN: {ArtifactUse.REFRESH},
        ArtifactPurpose.LOGOUT_TOKEN: {ArtifactUse.BACKCHANNEL_LOGOUT},
        ArtifactPurpose.IDP_COOKIE: {ArtifactUse.IDP_SESSION},
        ArtifactPurpose.SP_COOKIE: {ArtifactUse.SP_SESSION},
    }
    if use not in allowed[purpose]:
        raise SecurityDenied(Denial.PURPOSE)
    if purpose not in {ArtifactPurpose.IDP_COOKIE} and (
        intended_client is None or intended_client != authenticated_client
    ):
        raise SecurityDenied(Denial.RECIPIENT)


def require_lineage(
    session: IdpSession,
    event: AuthenticationEvent,
    grant: FederationGrant,
    key: SigningTrust,
    *,
    client_id: str,
    client_enabled: bool,
    now: int,
) -> None:
    if grant.client_id != client_id:
        raise SecurityDenied(Denial.RECIPIENT)
    if (
        event.session_id != session.session_id
        or event.subject != session.subject
        or grant.session_id != session.session_id
        or grant.event_id != event.event_id
        or grant.root_signing_key_id != key.key_id
        or grant.expires_at > session.expires_at
        or event.authenticated_at > now
    ):
        raise SecurityDenied(Denial.BINDING)
    if not client_enabled:
        raise SecurityDenied(Denial.CLIENT_DISABLED)
    if session.revoked_at is not None or grant.revoked_at is not None:
        raise SecurityDenied(Denial.REVOKED)
    if now >= session.expires_at or now >= grant.expires_at:
        raise SecurityDenied(Denial.EXPIRED)
    if key.state == KeyState.REVOKED:
        raise SecurityDenied(Denial.KEY_REVOKED)
    # A prepared key cannot have established a legitimate grant. Retired keys
    # remain meaningful historical evidence; ordinary retirement is not revocation.
    if key.state == KeyState.PREPARED or grant.created_at < session.created_at:
        raise SecurityDenied(Denial.BINDING)


def require_assurance(
    event: AuthenticationEvent, requirement: AuthenticationRequirement, *, now: int
) -> None:
    levels = {Assurance.FIXTURE: 0, Assurance.PASSWORD: 1, Assurance.PASSWORD_TOTP: 2}
    if levels[event.assurance] < levels[requirement.minimum]:
        raise SecurityDenied(Denial.ASSURANCE)
    if event.authenticated_at > now:
        raise SecurityDenied(Denial.BINDING)
    if requirement.max_age_seconds is not None and (
        now - event.authenticated_at > requirement.max_age_seconds
    ):
        raise SecurityDenied(Denial.RECENCY)
    if (
        requirement.reauthenticate_since is not None
        and event.authenticated_at < requirement.reauthenticate_since
    ):
        raise SecurityDenied(Denial.RECENCY)


def require_active_grant(
    status: GrantStatus, *, issuer: str, client_id: str, subject: str, now: int
) -> GrantSnapshot:
    if not status.active:
        raise SecurityDenied(Denial.REVOKED)
    context = status.context
    if context is None or status.expires_at is None:
        raise GrantUnavailable("Active authorization needs its complete bound lineage")
    if (
        status.client_id != client_id
        or context.grant.client_id != client_id
        or status.subject != subject
        or context.authentication.subject.subject != subject
        or context.authentication.subject.issuer != issuer
        or status.expires_at
        > min(context.grant.expires_at, context.family.expires_at, context.session_expires_at)
    ):
        raise SecurityDenied(Denial.BINDING)
    if context.grant.revoked_at is not None or context.family.revoked_at is not None:
        raise SecurityDenied(Denial.REVOKED)
    if now >= min(
        status.expires_at,
        context.grant.expires_at,
        context.family.expires_at,
        context.session_expires_at,
    ):
        raise SecurityDenied(Denial.EXPIRED)
    return context


def require_sp_binding(
    local: SpSessionEvidence,
    remote: GrantSnapshot,
    *,
    expected_issuer: str,
    expected_client: str,
    now: int,
) -> None:
    event = remote.authentication
    if (
        local.issuer != expected_issuer
        or local.client_id != expected_client
        or remote.grant.client_id != expected_client
    ):
        raise SecurityDenied(Denial.RECIPIENT)
    if (
        local.subject != event.subject.subject
        or local.issuer != event.subject.issuer
        or local.session_id != event.session_id
        or local.grant_id != remote.grant.grant_id
        or local.event_id != event.event_id
        or local.evidence_id != remote.evidence.token_id
        or local.token_digest != remote.evidence.token_digest
        or local.signing_key_id != remote.grant.root_signing_key_id
        or local.authentication != event
        or local.expires_at
        > min(remote.grant.expires_at, remote.family.expires_at, remote.session_expires_at)
    ):
        raise SecurityDenied(Denial.BINDING)
    if (
        local.revoked_at is not None
        or remote.grant.revoked_at is not None
        or remote.family.revoked_at is not None
    ):
        raise SecurityDenied(Denial.REVOKED)
    if now >= min(
        local.expires_at,
        local.idle_expires_at,
        remote.grant.expires_at,
        remote.family.expires_at,
        remote.session_expires_at,
    ):
        raise SecurityDenied(Denial.EXPIRED)


def require_key_transition(key: SigningTrust, desired: KeyState, *, now: int, skew: int) -> None:
    allowed = {
        KeyState.PREPARED: {KeyState.ACTIVE, KeyState.REVOKED},
        KeyState.ACTIVE: {KeyState.DRAINING, KeyState.REVOKED},
        KeyState.DRAINING: {KeyState.RETIRED, KeyState.REVOKED},
        KeyState.RETIRED: {KeyState.REVOKED},
        KeyState.REVOKED: set(),
    }
    if desired not in allowed[key.state]:
        raise SecurityDenied(Denial.BINDING)
    if desired == KeyState.RETIRED and now < key.verification_deadline + skew:
        raise SecurityDenied(Denial.EXPIRED)
