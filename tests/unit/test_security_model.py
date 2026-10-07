import json
import secrets
import ssl
from http import HTTPStatus
from urllib.parse import parse_qs

import httpx2 as httpx
import pytest
from joserfc import jwt
from pydantic import SecretStr, ValidationError

from federated_identity.common.security.contracts import GrantUnavailable
from federated_identity.common.security.model import (
    Assurance,
    AuthenticationEvent,
    AuthenticationMethod,
    AuthenticationRequirement,
    Denial,
    FederationGrant,
    GrantSnapshot,
    KeyState,
    LoginEvidence,
    RefreshFamily,
    SecurityDenied,
    SigningTrust,
    SubjectIdentity,
    TrustedAuthentication,
)
from federated_identity.common.security.policies import (
    ArtifactPurpose,
    ArtifactUse,
    require_artifact_use,
    require_assurance,
    require_key_transition,
)
from federated_identity.common.settings.policy import verifier_digest
from federated_identity.common.settings.runtime import RuntimeSettings, ServiceId
from federated_identity.sp.services.revocation import AuthenticatedGrantChecker
from tests.helpers import KeyFixtures, MutableClock


@pytest.fixture
def context() -> GrantSnapshot:
    event = AuthenticationEvent(
        event_id="event-a",
        session_id="session-a",
        subject=SubjectIdentity(issuer="https://idp.localhost:8443", subject="user:fixture"),
        authenticated_at=1000,
        assurance=Assurance.PASSWORD,
        methods=(AuthenticationMethod.PASSWORD,),
    )
    return GrantSnapshot(
        grant=FederationGrant(
            grant_id="grant-a",
            client_id="sp-a",
            session_id=event.session_id,
            event_id=event.event_id,
            root_signing_key_id="issuer-key",
            created_at=1000,
            expires_at=4600,
        ),
        authentication=event,
        evidence=LoginEvidence(
            token_id="evidence-a",
            token_digest=verifier_digest("test evidence"),
            client_id="sp-a",
            signing_key_id="issuer-key",
            authentication=event,
            issued_at=1000,
            expires_at=1300,
        ),
        session_expires_at=4600,
        family=RefreshFamily(
            family_id="family-a",
            grant_id="grant-a",
            created_at=1000,
            expires_at=4600,
            generation=0,
        ),
        policy_revision=0,
    )


@pytest.mark.parametrize(
    ("purpose", "use"),
    [
        (ArtifactPurpose.ID_TOKEN, ArtifactUse.BACKCHANNEL_LOGOUT),
        (ArtifactPurpose.LOGOUT_TOKEN, ArtifactUse.SP_LOGIN),
        (ArtifactPurpose.CLIENT_ASSERTION, ArtifactUse.SP_LOGIN),
        (ArtifactPurpose.ACCESS_TOKEN, ArtifactUse.IDP_SESSION),
        (ArtifactPurpose.CODE, ArtifactUse.SP_LOGIN),
        (ArtifactPurpose.SP_COOKIE, ArtifactUse.IDP_SESSION),
        (ArtifactPurpose.IDP_COOKIE, ArtifactUse.SP_SESSION),
        (ArtifactPurpose.REFRESH_TOKEN, ArtifactUse.RESOURCE_CHECK),
    ],
)
def test_cross_purpose_artifacts_never_establish_unrelated_authority(
    purpose: ArtifactPurpose, use: ArtifactUse
) -> None:
    with pytest.raises(SecurityDenied) as denied:
        require_artifact_use(purpose, use, intended_client="sp-a", authenticated_client="sp-a")
    assert denied.value.reason == Denial.PURPOSE


@pytest.mark.parametrize("purpose", list(ArtifactPurpose))
def test_federation_artifacts_are_not_operator_credentials(purpose: ArtifactPurpose) -> None:
    with pytest.raises(SecurityDenied) as denied:
        require_artifact_use(
            purpose, ArtifactUse.ADMIN, intended_client="sp-a", authenticated_client="sp-a"
        )
    assert denied.value.reason == Denial.PURPOSE


@pytest.mark.parametrize(
    ("purpose", "use"),
    [
        (ArtifactPurpose.CODE, ArtifactUse.CODE_REDEMPTION),
        (ArtifactPurpose.ID_TOKEN, ArtifactUse.LOGOUT_HINT),
        (ArtifactPurpose.ID_TOKEN, ArtifactUse.SP_LOGIN),
    ],
)
def test_protocol_return_paths_are_explicit_and_recipient_bound(
    purpose: ArtifactPurpose, use: ArtifactUse
) -> None:
    require_artifact_use(purpose, use, intended_client="sp-a", authenticated_client="sp-a")
    with pytest.raises(SecurityDenied) as denied:
        require_artifact_use(purpose, use, intended_client="sp-a", authenticated_client="sp-b")
    assert denied.value.reason == Denial.RECIPIENT


@pytest.mark.parametrize(
    "methods",
    [
        (),
        (AuthenticationMethod.OTP,),
        (AuthenticationMethod.PASSWORD, AuthenticationMethod.PASSWORD),
    ],
)
def test_unsupported_or_repeated_methods_cannot_claim_assurance(
    context: GrantSnapshot, methods: tuple[AuthenticationMethod, ...]
) -> None:
    with pytest.raises(ValidationError):
        TrustedAuthentication(
            subject=context.authentication.subject, authenticated_at=1000, methods=methods
        )


def test_claimed_mfa_needs_the_verified_methods(context: GrantSnapshot) -> None:
    inflated = context.authentication.model_dump(mode="json")
    inflated["assurance"] = Assurance.PASSWORD_TOTP.value
    with pytest.raises(ValidationError):
        AuthenticationEvent.model_validate_json(json.dumps(inflated))
    with pytest.raises(ValidationError, match="frozen_instance"):
        context.authentication.__setattr__("authenticated_at", 1100)


def test_recency_is_about_authentication_not_token_issuance(context: GrantSnapshot) -> None:
    event = context.authentication
    requirement = AuthenticationRequirement(max_age_seconds=30)
    require_assurance(event, requirement, now=1030)
    with pytest.raises(SecurityDenied) as denied:
        require_assurance(event, requirement, now=1031)
    assert denied.value.reason == Denial.RECENCY
    with pytest.raises(SecurityDenied) as denied:
        require_assurance(event, AuthenticationRequirement(reauthenticate_since=1001), now=1001)
    assert denied.value.reason == Denial.RECENCY


def test_fixture_events_cannot_meet_password_or_mfa_policy(context: GrantSnapshot) -> None:
    event = context.authentication.model_copy(
        update={
            "assurance": Assurance.FIXTURE,
            "methods": (AuthenticationMethod.FIXTURE,),
        }
    )
    for minimum in (Assurance.PASSWORD, Assurance.PASSWORD_TOTP):
        with pytest.raises(SecurityDenied) as denied:
            require_assurance(event, AuthenticationRequirement(minimum=minimum), now=1000)
        assert denied.value.reason == Denial.ASSURANCE


@pytest.mark.parametrize("case", ["event", "recipient", "key", "family_lifetime", "grant_lifetime"])
def test_untrusted_snapshots_cannot_mix_lineage_or_extend_parents(
    context: GrantSnapshot, case: str
) -> None:
    value = context.model_dump(mode="json")
    if case == "event":
        value["grant"]["event_id"] = "other-event"
    elif case == "recipient":
        value["evidence"]["client_id"] = "sp-b"
    elif case == "key":
        value["evidence"]["signing_key_id"] = "other-key"
    elif case == "family_lifetime":
        value["family"]["expires_at"] = 4601
    else:
        value["grant"]["expires_at"] = 4601
    with pytest.raises(ValidationError):
        GrantSnapshot.model_validate_json(json.dumps(value))


def test_retirement_waits_for_expiry_and_revocation_is_terminal() -> None:
    key = SigningTrust(
        key_id="key-a", state=KeyState.DRAINING, created_at=1000, verification_deadline=1300
    )
    with pytest.raises(SecurityDenied):
        require_key_transition(key, KeyState.RETIRED, now=1304, skew=5)
    require_key_transition(key, KeyState.RETIRED, now=1305, skew=5)
    revoked = key.model_copy(update={"state": KeyState.REVOKED})
    with pytest.raises(SecurityDenied):
        require_key_transition(revoked, KeyState.ACTIVE, now=1305, skew=5)


@pytest.mark.parametrize(
    "case",
    [
        "valid",
        "missing_context",
        "wrong_subject",
        "wrong_issuer",
        "expired_parent",
        "ceiling",
        "delayed_expiry",
    ],
)
async def test_authenticated_grant_responses_need_complete_current_bound_lineage(
    context: GrantSnapshot, key_fixtures: KeyFixtures, case: str
) -> None:
    settings = RuntimeSettings(
        service_id=ServiceId.SP_A, public_url="https://sp-a.localhost:8444", listen_port=8444
    )
    clock = MutableClock(1100)
    value: dict[str, object] = {
        "active": True,
        "client_id": "sp-a",
        "sub": "user:fixture",
        "exp": 1300,
        "context": context.model_dump(mode="json"),
    }
    altered = context.model_dump(mode="json")
    if case == "missing_context":
        del value["context"]
    elif case == "wrong_subject":
        value["sub"] = "other-user"
    elif case == "wrong_issuer":
        for event in (altered["authentication"], altered["evidence"]["authentication"]):
            event["subject"]["issuer"] = "https://other-idp.example"
        value["context"] = altered
    elif case == "expired_parent":
        altered["family"]["expires_at"] = 1100
        value["context"] = altered
    elif case == "ceiling":
        value["exp"] = 4601

    def response(request: httpx.Request) -> httpx.Response:
        form = parse_qs(request.content.decode("ascii"))
        assertion = jwt.decode(
            form["client_assertion"][0], key_fixtures.client_a.key, algorithms=["RS256"]
        )
        assert assertion.claims["aud"] == settings.introspection_endpoint
        assert assertion.claims["iss"] == assertion.claims["sub"] == "sp-a"
        if case == "delayed_expiry":
            clock.value = 1300
        return httpx.Response(HTTPStatus.OK, json=value)

    checker = AuthenticatedGrantChecker(
        settings,
        key_fixtures.client_a,
        ssl.create_default_context(),
        clock,
        transport=httpx.MockTransport(response),
    )
    if case == "valid":
        status = await checker.check(SecretStr(secrets.token_urlsafe(32)))
        assert status.active and status.context == context
    else:
        with pytest.raises(GrantUnavailable):
            await checker.check(SecretStr(secrets.token_urlsafe(32)))
