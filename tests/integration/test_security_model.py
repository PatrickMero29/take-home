import asyncio
import secrets
from collections.abc import Mapping
from typing import Literal

import pytest
from joserfc import jwt
from pydantic import JsonValue, SecretStr
from sqlalchemy import event, func, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from federated_identity.common.persistence.database import AsyncDatabase
from federated_identity.common.persistence.migrations import migrate
from federated_identity.common.security.contracts import GrantStatus, GrantUnavailable
from federated_identity.common.security.keys import SigningKey
from federated_identity.common.security.model import (
    Assurance,
    AuthenticationMethod,
    AuthenticationRequirement,
    Denial,
    IssuedCredentials,
    KeyState,
    LifecyclePolicy,
    RevocationReason,
    SecurityDenied,
)
from federated_identity.common.security.secrets import EnvelopeCipher
from federated_identity.common.settings.policy import verifier_digest
from federated_identity.common.settings.runtime import ServiceId
from federated_identity.idp.repositories.outbox import LogoutOutboxRow
from federated_identity.idp.repositories.security_tables import (
    AccessCredentialRow,
    AuthenticationEventRow,
    FederationGrantRow,
    IdpSessionRow,
    RefreshCredentialRow,
    RefreshFamilyRow,
    SecurityGateRow,
    SigningTrustRow,
)
from federated_identity.sp.protocol.oidc import verified_login_evidence
from federated_identity.sp.repositories.security import SpSecurityRepository
from federated_identity.sp.repositories.security_tables import SpAuthenticationRow
from federated_identity.sp.services.security_model import SpSecurityModel
from tests.security_helpers import SecurityLab

pytestmark = pytest.mark.integration
type Containment = Literal["logout", "client", "key"]


async def authentication_count(lab: SecurityLab, service: ServiceId = ServiceId.SP_A) -> int:
    async with lab.databases[service].sessions() as session:
        return int(await session.scalar(select(func.count()).select_from(SpAuthenticationRow)) or 0)


async def test_migrations_preserve_bound_facts_and_separate_service_storage(
    security_lab: SecurityLab,
) -> None:
    lab = security_lab
    issued = await lab.issue()
    cookie = await lab.sps["sp-a"].establish(issued.proof.evidence, issued.credentials)
    for service, database in lab.databases.items():
        await migrate(database, service)
        async with database.sessions() as session:
            version = await session.scalar(text("SELECT version_num FROM alembic_version"))
            assert version == ("idp_step_up_12" if service == ServiceId.IDP else "sp_step_up_08")
            if service != ServiceId.IDP:
                assert (
                    await session.scalar(text("SELECT to_regclass('authentication_events')"))
                    is None
                )
    authorized = await lab.sps["sp-a"].authorize(cookie, AuthenticationRequirement())
    assert authorized.authentication == issued.credentials.context.authentication
    assert issued.credentials.access_token.get_secret_value() == issued.proof.response.access_token
    async with lab.databases[ServiceId.SP_A].sessions() as session:
        row = await session.get(SpAuthenticationRow, verifier_digest(cookie.get_secret_value()))
        assert row is not None and row.encrypted_refresh_token is not None
        assert b"user:model-fixture" not in row.encrypted_evidence
        assert (
            issued.credentials.access_token.get_secret_value().encode()
            not in row.encrypted_access_token
        )
        assert (
            issued.credentials.refresh_token.get_secret_value().encode()
            not in row.encrypted_refresh_token
        )


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE authentication_events SET authenticated_at=authenticated_at+60 "
        "WHERE event_id=:event",
        "DELETE FROM authentication_evidence WHERE token_id=:evidence",
        "UPDATE access_credentials SET expires_at=expires_at+60 WHERE token_digest=:access",
    ],
)
async def test_database_rejects_rewriting_authentication_or_issued_evidence(
    security_lab: SecurityLab, statement: str
) -> None:
    lab = security_lab
    issued = await lab.issue()
    context = issued.credentials.context
    with pytest.raises(DBAPIError, match="immutable"):
        async with lab.database.engine.begin() as connection:
            await connection.execute(
                text(statement),
                {
                    "event": context.authentication.event_id,
                    "evidence": context.evidence.token_id,
                    "access": verifier_digest(issued.credentials.access_token.get_secret_value()),
                },
            )
    status = await lab.idp.check_access(
        issued.credentials.access_token, authenticated_client="sp-a"
    )
    assert status.active and status.context == context


@pytest.mark.parametrize(
    "table", ["idp_security_sessions", "federation_grants", "refresh_families"]
)
async def test_database_rejects_absolute_lifetime_extension(
    security_lab: SecurityLab, table: str
) -> None:
    lab = security_lab
    await lab.issue()
    with pytest.raises(DBAPIError, match="absolute lifetime"):
        async with lab.database.engine.begin() as connection:
            await connection.execute(text(f"UPDATE {table} SET expires_at=expires_at+60"))


@pytest.mark.parametrize("case", ["event_session", "access_family"])
async def test_database_prevents_cross_lineage_foreign_key_substitution(
    security_lab: SecurityLab, case: str
) -> None:
    lab = security_lab
    first = (await lab.issue()).credentials.context
    second = (await lab.issue()).credentials.context
    with pytest.raises(IntegrityError):
        async with lab.database.sessions() as session:
            async with session.begin():
                if case == "event_session":
                    session.add(
                        FederationGrantRow(
                            grant_id=secrets.token_urlsafe(24),
                            client_id="sp-a",
                            session_id=first.grant.session_id,
                            event_id=second.grant.event_id,
                            root_signing_key_id=first.grant.root_signing_key_id,
                            created_at=lab.clock.now(),
                            expires_at=first.grant.expires_at,
                        )
                    )
                else:
                    session.add(
                        AccessCredentialRow(
                            token_digest=verifier_digest(secrets.token_urlsafe(32)),
                            grant_id=first.grant.grant_id,
                            family_id=second.family.family_id,
                            issued_at=lab.clock.now(),
                            expires_at=lab.clock.now() + 60,
                        )
                    )


async def test_refresh_preserves_expired_login_evidence_history_and_absolute_ceilings(
    security_lab: SecurityLab,
) -> None:
    lab = security_lab
    session, event_fact = await lab.idp.open_session(
        lab.authentication(
            methods=(AuthenticationMethod.PASSWORD, AuthenticationMethod.OTP),
            authenticated_at=lab.clock.now() - 60,
        )
    )
    issued = await lab.issue(event_fact)
    lab.clock.value = issued.proof.evidence.expires_at + 1
    renewed = await lab.idp.rotate_refresh(
        issued.credentials.refresh_token, authenticated_client="sp-a"
    )
    assert renewed.context.authentication == event_fact
    assert renewed.context.evidence == issued.proof.evidence
    assert renewed.context.grant == issued.credentials.context.grant
    assert renewed.context.family.family_id == issued.credentials.context.family.family_id
    assert renewed.context.family.generation == 1
    assert renewed.refresh_expires_at == issued.credentials.refresh_expires_at <= session.expires_at
    assert renewed.access_token != issued.credentials.access_token
    assert renewed.refresh_token != issued.credentials.refresh_token
    assert (await lab.idp.check_access(renewed.access_token, authenticated_client="sp-a")).active
    lab.clock.value = session.expires_at - 1
    final = await lab.idp.rotate_refresh(renewed.refresh_token, authenticated_client="sp-a")
    assert final.access_expires_at == final.refresh_expires_at == session.expires_at
    lab.clock.value = session.expires_at
    assert not (await lab.idp.check_access(final.access_token, authenticated_client="sp-a")).active
    with pytest.raises(SecurityDenied) as denied:
        await lab.idp.rotate_refresh(final.refresh_token, authenticated_client="sp-a")
    assert denied.value.reason == Denial.EXPIRED


async def test_wrong_client_cannot_use_refresh_replay_to_revoke_the_owner(
    security_lab: SecurityLab,
) -> None:
    lab = security_lab
    issued = await lab.issue()
    renewed = await lab.idp.rotate_refresh(
        issued.credentials.refresh_token, authenticated_client="sp-a"
    )
    with pytest.raises(SecurityDenied) as denied:
        await lab.idp.rotate_refresh(issued.credentials.refresh_token, authenticated_client="sp-b")
    assert denied.value.reason == Denial.RECIPIENT
    status = await lab.idp.check_access(renewed.access_token, authenticated_client="sp-a")
    assert status.active and status.context is not None
    assert status.context.family.revoked_at is None and status.context.family.generation == 1
    assert not (
        await lab.idp.check_access(renewed.access_token, authenticated_client="sp-b")
    ).active


async def test_refresh_replay_commits_containment_before_rejection_and_survives_new_pool(
    security_lab: SecurityLab,
) -> None:
    lab = security_lab
    issued = await lab.issue()
    renewed = await lab.idp.rotate_refresh(
        issued.credentials.refresh_token, authenticated_client="sp-a"
    )
    with pytest.raises(SecurityDenied) as denied:
        await lab.idp.rotate_refresh(issued.credentials.refresh_token, authenticated_client="sp-a")
    assert denied.value.reason == Denial.REPLAY
    async with lab.database.sessions() as session:
        grant = await session.get(FederationGrantRow, issued.credentials.context.grant.grant_id)
        family = await session.get(RefreshFamilyRow, issued.credentials.context.family.family_id)
        assert grant is not None and family is not None
        assert grant.revocation_reason == RevocationReason.REFRESH_REPLAY.value
        assert grant.revoked_at == family.revoked_at == lab.clock.now()
    restarted = AsyncDatabase(
        SecretStr(lab.database.engine.url.render_as_string(hide_password=False))
    )
    try:
        model = lab.model(restarted)
        assert not (
            await model.check_access(renewed.access_token, authenticated_client="sp-a")
        ).active
        with pytest.raises(SecurityDenied):
            await model.rotate_refresh(renewed.refresh_token, authenticated_client="sp-a")
    finally:
        await restarted.dispose()


async def test_concurrent_authenticated_refresh_replay_has_one_issuance_then_containment(
    security_lab: SecurityLab,
) -> None:
    lab = security_lab
    issued = await lab.issue()

    async def attempt() -> IssuedCredentials | SecurityDenied:
        try:
            return await lab.idp.rotate_refresh(
                issued.credentials.refresh_token, authenticated_client="sp-a"
            )
        except SecurityDenied as denied:
            return denied

    outcomes = await asyncio.gather(*(attempt() for _ in range(8)))
    winners = [value for value in outcomes if isinstance(value, IssuedCredentials)]
    denials = [value for value in outcomes if isinstance(value, SecurityDenied)]
    assert len(winners) == 1 and len(denials) == 7
    assert any(value.reason == Denial.REPLAY for value in denials)
    assert not (
        await lab.idp.check_access(winners[0].access_token, authenticated_client="sp-a")
    ).active


async def test_consumption_and_revocation_tombstones_cannot_be_reset(
    security_lab: SecurityLab,
) -> None:
    lab = security_lab
    issued = await lab.issue()
    await lab.idp.rotate_refresh(issued.credentials.refresh_token, authenticated_client="sp-a")
    with pytest.raises(DBAPIError, match="irreversible"):
        async with lab.database.engine.begin() as connection:
            await connection.execute(
                text("UPDATE refresh_credentials SET consumed_at=NULL WHERE token_digest=:digest"),
                {"digest": verifier_digest(issued.credentials.refresh_token.get_secret_value())},
            )
    await lab.idp.end_session(issued.credentials.context.authentication.session_id)
    for table in ("idp_security_sessions", "federation_grants", "refresh_families"):
        fields = "revoked_at=NULL" + (
            ", revocation_reason=NULL" if table != "refresh_families" else ""
        )
        with pytest.raises(DBAPIError, match="irreversible"):
            async with lab.database.engine.begin() as connection:
                await connection.execute(text(f"UPDATE {table} SET {fields}"))


async def test_routine_rotation_and_retirement_preserve_established_grant_trust(
    security_lab: SecurityLab,
) -> None:
    lab = security_lab
    issued = await lab.issue()
    cookie = await lab.sps["sp-a"].establish(issued.proof.evidence, issued.credentials)
    replacement = await asyncio.to_thread(SigningKey.generate)
    await lab.idp.prepare_signer(replacement)
    await lab.idp.rotate_trust(replacement.kid)
    assert (await lab.sps["sp-a"].authorize(cookie, AuthenticationRequirement())).grant_id == (
        issued.credentials.context.grant.grant_id
    )
    with pytest.raises(SecurityDenied) as denied:
        await lab.idp.retire_trust(lab.keys.issuer.kid)
    assert denied.value.reason == Denial.EXPIRED
    lab.clock.value = issued.proof.evidence.expires_at - 1
    renewed = await lab.idp.rotate_refresh(
        issued.credentials.refresh_token, authenticated_client="sp-a"
    )
    lab.clock.value = issued.proof.evidence.expires_at + lab.protocol.clock_skew_seconds
    await lab.idp.retire_trust(lab.keys.issuer.kid)
    assert (await lab.idp.check_access(renewed.access_token, authenticated_client="sp-a")).active
    async with lab.database.sessions() as session:
        old = await session.get(SigningTrustRow, lab.keys.issuer.kid)
        active = await session.scalars(
            select(SigningTrustRow).where(SigningTrustRow.state == "active")
        )
        assert old is not None and old.state == KeyState.RETIRED.value
        assert [row.key_id for row in active] == [replacement.kid]


async def test_key_compromise_revokes_only_affected_evidence_and_cannot_be_undone(
    security_lab: SecurityLab,
) -> None:
    lab = security_lab
    root, fact = await lab.idp.open_session(lab.authentication())
    first = await lab.issue(fact)
    replacement = await asyncio.to_thread(SigningKey.generate)
    await lab.idp.prepare_signer(replacement)
    await lab.idp.rotate_trust(replacement.kid)
    unaffected = await lab.issue(fact, client_id="sp-b", signer=replacement)
    await lab.idp.revoke_signer(lab.keys.issuer.kid)
    assert not (
        await lab.idp.check_access(first.credentials.access_token, authenticated_client="sp-a")
    ).active
    assert (
        await lab.idp.check_access(unaffected.credentials.access_token, authenticated_client="sp-b")
    ).active
    # The cached public key still validates the signature; committed trust state wins.
    cached = verified_login_evidence(
        first.proof.response,
        settings=lab.rp_settings(),
        nonce=first.proof.nonce,
        keys=lab.keys.issuer.public_jwks(),
        clock=lab.clock,
        event_id=fact.event_id,
    )
    with pytest.raises(SecurityDenied):
        await lab.sps["sp-a"].establish(cached, first.credentials)
    with pytest.raises(SecurityDenied):
        await lab.idp.register_runtime_signer(lab.keys.issuer)
    with pytest.raises(DBAPIError, match="irreversible"):
        async with lab.database.engine.begin() as connection:
            await connection.execute(
                text("UPDATE signing_trust SET state='active' WHERE key_id=:kid"),
                {"kid": lab.keys.issuer.kid},
            )
    async with lab.database.sessions() as session:
        parent = await session.get(IdpSessionRow, root.session_id)
        assert parent is not None and parent.revoked_at is None


async def test_client_compromise_is_scoped_and_blocks_issuance_and_refresh(
    security_lab: SecurityLab,
) -> None:
    lab = security_lab
    _, fact = await lab.idp.open_session(lab.authentication())
    first = await lab.issue(fact)
    second = await lab.issue(fact, client_id="sp-b")
    await lab.idp.disable_client("sp-a")
    assert not (
        await lab.idp.check_access(first.credentials.access_token, authenticated_client="sp-a")
    ).active
    assert (
        await lab.idp.check_access(second.credentials.access_token, authenticated_client="sp-b")
    ).active
    with pytest.raises(SecurityDenied) as denied:
        await lab.idp.rotate_refresh(first.credentials.refresh_token, authenticated_client="sp-a")
    assert denied.value.reason == Denial.CLIENT_DISABLED
    with pytest.raises(SecurityDenied) as denied:
        await lab.issue(fact)
    assert denied.value.reason == Denial.CLIENT_DISABLED


async def test_logout_atomically_revokes_lineage_with_one_encrypted_intent_per_recipient(
    security_lab: SecurityLab,
) -> None:
    lab = security_lab
    root, fact = await lab.idp.open_session(lab.authentication())
    issued = [await lab.issue(fact), await lab.issue(fact), await lab.issue(fact, client_id="sp-b")]
    await asyncio.gather(lab.idp.end_session(root.session_id), lab.idp.end_session(root.session_id))
    for item in issued:
        assert not (
            await lab.idp.check_access(
                item.credentials.access_token, authenticated_client=item.proof.evidence.client_id
            )
        ).active
    async with lab.database.sessions() as session:
        intents = list(await session.scalars(select(LogoutOutboxRow)))
        assert len(intents) == 2
        assert {row.client_id for row in intents} == {"sp-a", "sp-b"}
        gate = await session.get(SecurityGateRow, 1)
        assert gate is not None and gate.revision == 1
        for row in intents:
            assert row.session_id == root.session_id and row.issuer == lab.issuer
            value = lab.ciphers[ServiceId.IDP].decrypt(
                row.encrypted_payload, purpose="logout-delivery"
            )
            assert value["sid"] == root.session_id and value["client_id"] == row.client_id
            assert root.session_id.encode() not in row.encrypted_payload
            assert row.destination == (
                "https://sp-a.localhost/backchannel-logout" if row.client_id == "sp-a" else None
            )


async def test_logout_outbox_failure_rolls_back_every_revocation(
    security_lab: SecurityLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    lab = security_lab
    root, fact = await lab.idp.open_session(lab.authentication())
    first = await lab.issue(fact)
    await lab.issue(fact, client_id="sp-b")
    original = EnvelopeCipher.encrypt
    calls = 0

    def fail_second(
        self: EnvelopeCipher, payload: Mapping[str, JsonValue], *, purpose: str
    ) -> bytes:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("Injected outbox encryption failure")
        return original(self, payload, purpose=purpose)

    with monkeypatch.context() as patch:
        patch.setattr(EnvelopeCipher, "encrypt", fail_second)
        with pytest.raises(RuntimeError, match="Injected outbox"):
            await lab.idp.end_session(root.session_id)
    assert calls == 2
    assert (
        await lab.idp.check_access(first.credentials.access_token, authenticated_client="sp-a")
    ).active
    async with lab.database.sessions() as session:
        gate = await session.get(SecurityGateRow, 1)
        assert gate is not None and gate.revision == 0
        assert not list(await session.scalars(select(LogoutOutboxRow)))
        assert all(
            row.revoked_at is None for row in await session.scalars(select(RefreshFamilyRow))
        )


async def contain(lab: SecurityLab, credentials: IssuedCredentials, case: Containment) -> None:
    if case == "logout":
        await lab.idp.end_session(credentials.context.authentication.session_id)
    elif case == "client":
        await lab.idp.disable_client(credentials.context.grant.client_id)
    else:
        await lab.idp.revoke_signer(credentials.context.grant.root_signing_key_id)


@pytest.mark.parametrize("case", ["logout", "client", "key"])
async def test_refresh_racing_containment_cannot_resurrect_authority(
    security_lab: SecurityLab, case: Containment
) -> None:
    lab = security_lab
    issued = await lab.issue()

    async def refresh() -> IssuedCredentials | SecurityDenied:
        try:
            return await lab.idp.rotate_refresh(
                issued.credentials.refresh_token, authenticated_client="sp-a"
            )
        except SecurityDenied as denied:
            return denied

    renewed, _ = await asyncio.gather(refresh(), contain(lab, issued.credentials, case))
    if isinstance(renewed, IssuedCredentials):
        assert not (
            await lab.idp.check_access(renewed.access_token, authenticated_client="sp-a")
        ).active
    assert not (
        await lab.idp.check_access(issued.credentials.access_token, authenticated_client="sp-a")
    ).active
    async with lab.database.sessions() as session:
        family = await session.get(RefreshFamilyRow, issued.credentials.context.family.family_id)
        assert family is not None and family.revoked_at is not None


async def test_issuance_racing_client_disable_cannot_escape_durable_revocation(
    security_lab: SecurityLab,
) -> None:
    lab = security_lab
    _, fact = await lab.idp.open_session(lab.authentication())
    proof = lab.proof(fact)

    async def issue() -> IssuedCredentials | SecurityDenied:
        try:
            return await lab.idp.issue_grant(
                proof.evidence, access_token=SecretStr(proof.response.access_token)
            )
        except SecurityDenied as denied:
            return denied

    issued, _ = await asyncio.gather(issue(), lab.idp.disable_client("sp-a"))
    if isinstance(issued, IssuedCredentials):
        assert not (
            await lab.idp.check_access(issued.access_token, authenticated_client="sp-a")
        ).active
    async with lab.database.sessions() as session:
        assert all(
            row.revoked_at is not None for row in await session.scalars(select(FederationGrantRow))
        )


@pytest.mark.parametrize("case", ["issue", "refresh", "logout"])
async def test_failed_commit_cannot_publish_or_partially_change_model_state(
    security_lab: SecurityLab, case: str
) -> None:
    lab = security_lab
    issued = await lab.issue()
    proof = lab.proof(issued.credentials.context.authentication)

    class FailedSyncSession(Session):
        pass

    class FailedAsyncSession(AsyncSession):
        sync_session_class = FailedSyncSession

    def fail(session: Session) -> None:
        raise RuntimeError("Injected security commit failure")

    event.listen(FailedSyncSession, "before_commit", fail)
    database = AsyncDatabase(
        SecretStr(lab.database.engine.url.render_as_string(hide_password=False)),
        session_class=FailedAsyncSession,
    )
    try:
        model = lab.model(database)
        with pytest.raises(RuntimeError, match="Injected security commit failure"):
            if case == "issue":
                await model.issue_grant(
                    proof.evidence, access_token=SecretStr(proof.response.access_token)
                )
            elif case == "refresh":
                await model.rotate_refresh(
                    issued.credentials.refresh_token, authenticated_client="sp-a"
                )
            else:
                await model.end_session(issued.credentials.context.authentication.session_id)
    finally:
        event.remove(FailedSyncSession, "before_commit", fail)
        await database.dispose()
    status = await lab.idp.check_access(
        issued.credentials.access_token, authenticated_client="sp-a"
    )
    assert status.active and status.context == issued.credentials.context
    async with lab.database.sessions() as session:
        assert len(list(await session.scalars(select(AccessCredentialRow)))) == 1
        assert len(list(await session.scalars(select(RefreshCredentialRow)))) == 1
        assert not list(await session.scalars(select(LogoutOutboxRow)))
    if case == "issue":
        await lab.idp.issue_grant(
            proof.evidence, access_token=SecretStr(proof.response.access_token)
        )
    elif case == "refresh":
        await lab.idp.rotate_refresh(issued.credentials.refresh_token, authenticated_client="sp-a")
    else:
        await lab.idp.end_session(issued.credentials.context.authentication.session_id)


async def test_model_publication_waits_for_actual_database_commit(
    security_lab: SecurityLab,
) -> None:
    lab = security_lab
    _, fact = await lab.idp.open_session(lab.authentication())
    proof = lab.proof(fact)
    entered = asyncio.Event()

    class PausedSyncSession(Session):
        pass

    class PausedAsyncSession(AsyncSession):
        sync_session_class = PausedSyncSession

    def pause(session: Session) -> None:
        entered.set()
        session.execute(text("SELECT pg_advisory_xact_lock(984201)"))

    event.listen(PausedSyncSession, "before_commit", pause)
    database = AsyncDatabase(
        SecretStr(lab.database.engine.url.render_as_string(hide_password=False)),
        session_class=PausedAsyncSession,
    )
    try:
        async with lab.database.engine.connect() as blocker:
            await blocker.execute(text("SELECT pg_advisory_lock(984201)"))
            publication = asyncio.create_task(
                lab.model(database).issue_grant(
                    proof.evidence, access_token=SecretStr(proof.response.access_token)
                )
            )
            try:
                await asyncio.wait_for(entered.wait(), timeout=2)
                assert not publication.done()
                async with lab.database.sessions() as session:
                    assert not list(await session.scalars(select(AccessCredentialRow)))
            finally:
                await blocker.execute(text("SELECT pg_advisory_unlock(984201)"))
                credentials = await asyncio.wait_for(publication, timeout=2)
        assert (
            await lab.idp.check_access(credentials.access_token, authenticated_client="sp-a")
        ).active
    finally:
        event.remove(PausedSyncSession, "before_commit", pause)
        await database.dispose()


async def test_dependency_outage_preserves_local_state_for_recovery(
    security_lab: SecurityLab,
) -> None:
    lab = security_lab
    issued = await lab.issue()
    sp = lab.sps["sp-a"]
    cookie = await sp.establish(issued.proof.evidence, issued.credentials)
    before = await sp.repository.load(cookie)
    lab.clock.value += 20
    lab.checkers["sp-a"].available = False
    with pytest.raises(GrantUnavailable):
        await sp.authorize(cookie, AuthenticationRequirement())
    assert await sp.repository.load(cookie) == before
    lab.checkers["sp-a"].available = True
    assert (await sp.authorize(cookie, AuthenticationRequirement())).subject == "user:model-fixture"
    after = await sp.repository.load(cookie)
    assert after is not None and after[0].revoked_at is None
    assert after[0].expires_at == issued.credentials.context.grant.expires_at


async def test_local_logout_during_remote_check_wins_without_holding_a_network_lock(
    security_lab: SecurityLab,
) -> None:
    lab = security_lab
    issued = await lab.issue()
    sp = lab.sps["sp-a"]
    cookie = await sp.establish(issued.proof.evidence, issued.credentials)
    entered = asyncio.Event()
    release = asyncio.Event()

    class PausedChecker:
        async def check(self, token: SecretStr) -> GrantStatus:
            result = await lab.checkers["sp-a"].check(token)
            entered.set()
            await release.wait()
            return result

    sp.checker = PausedChecker()
    authorization = asyncio.create_task(sp.authorize(cookie, AuthenticationRequirement()))
    try:
        await asyncio.wait_for(entered.wait(), timeout=2)
        await asyncio.wait_for(sp.logout_local(cookie), timeout=1)
    finally:
        release.set()
    with pytest.raises(SecurityDenied) as denied:
        await asyncio.wait_for(authorization, timeout=2)
    assert denied.value.reason == Denial.REVOKED


@pytest.mark.parametrize("case", ["idle", "absolute"])
async def test_sp_exact_idle_and_absolute_expiry_are_server_enforced(
    security_lab: SecurityLab, case: str
) -> None:
    lab = security_lab
    issued = await lab.issue()
    sp = lab.sps["sp-a"]
    sp.lifecycle = LifecyclePolicy(sp_session_seconds=120, sp_idle_seconds=60)
    cookie = await sp.establish(issued.proof.evidence, issued.credentials)
    started = lab.clock.now()
    if case == "absolute":
        for seconds in (59, 118):
            lab.clock.value = started + seconds
            await sp.authorize(cookie, AuthenticationRequirement())
        value = await sp.repository.load(cookie)
        assert value is not None and value[0].idle_expires_at == started + 120
    lab.clock.value = started + (60 if case == "idle" else 120)
    calls = lab.checkers["sp-a"].calls
    with pytest.raises(SecurityDenied) as denied:
        await sp.authorize(cookie, AuthenticationRequirement())
    assert denied.value.reason == Denial.EXPIRED
    assert lab.checkers["sp-a"].calls == calls


async def test_sp_restart_preserves_active_and_revoked_cookies_and_db_lifetime_guard(
    security_lab: SecurityLab,
) -> None:
    lab = security_lab
    issued = await lab.issue()
    sp = lab.sps["sp-a"]
    cookie = await sp.establish(issued.proof.evidence, issued.credentials)
    database = AsyncDatabase(
        SecretStr(lab.databases[ServiceId.SP_A].engine.url.render_as_string(hide_password=False))
    )
    try:
        restarted = SpSecurityModel(
            SpSecurityRepository(database, lab.ciphers[ServiceId.SP_A]),
            lab.checkers["sp-a"],
            issuer=lab.issuer,
            client_id="sp-a",
            clock=lab.clock,
            lifecycle=lab.lifecycle,
        )
        assert (await restarted.authorize(cookie, AuthenticationRequirement())).grant_id == (
            issued.credentials.context.grant.grant_id
        )
        with pytest.raises(DBAPIError, match="absolute lifetime"):
            async with database.engine.begin() as connection:
                await connection.execute(
                    text("UPDATE sp_authentication_sessions SET expires_at=expires_at+60")
                )
        await restarted.logout_local(cookie)
        with pytest.raises(SecurityDenied):
            await sp.authorize(cookie, AuthenticationRequirement())
        with pytest.raises(DBAPIError, match="irreversible"):
            async with database.engine.begin() as connection:
                await connection.execute(
                    text("UPDATE sp_authentication_sessions SET revoked_at=NULL")
                )
    finally:
        await database.dispose()


async def test_reauthentication_changes_one_sp_event_without_elevating_other_sessions(
    security_lab: SecurityLab,
) -> None:
    lab = security_lab
    root, password = await lab.idp.open_session(lab.authentication())
    first = await lab.issue(password)
    second = await lab.issue(password, client_id="sp-b")
    sp = lab.sps["sp-a"]
    old_cookie = await sp.establish(first.proof.evidence, first.credentials)
    other_cookie = await lab.sps["sp-b"].establish(second.proof.evidence, second.credentials)
    sensitive = AuthenticationRequirement(minimum=Assurance.PASSWORD_TOTP, max_age_seconds=30)
    with pytest.raises(SecurityDenied) as denied:
        await sp.authorize(old_cookie, sensitive)
    assert denied.value.reason == Denial.ASSURANCE
    lab.clock.value += 10
    mfa = await lab.idp.reauthenticate(
        root.session_id,
        lab.authentication(methods=(AuthenticationMethod.PASSWORD, AuthenticationMethod.OTP)),
    )
    elevated = await lab.issue(mfa)
    new_cookie = await sp.establish(
        elevated.proof.evidence, elevated.credentials, previous_cookie=old_cookie
    )
    assert new_cookie != old_cookie
    assert (await sp.authorize(new_cookie, sensitive)).authentication == mfa
    with pytest.raises(SecurityDenied):
        await sp.authorize(old_cookie, AuthenticationRequirement())
    with pytest.raises(SecurityDenied) as denied:
        await lab.sps["sp-b"].authorize(other_cookie, sensitive)
    assert denied.value.reason == Denial.ASSURANCE
    lab.clock.value += 31
    with pytest.raises(SecurityDenied) as denied:
        await sp.authorize(new_cookie, sensitive)
    assert denied.value.reason == Denial.RECENCY
    renewed = await lab.idp.rotate_refresh(
        elevated.credentials.refresh_token, authenticated_client="sp-a"
    )
    assert renewed.context.authentication == mfa
    async with lab.database.sessions() as session:
        parent = await session.get(IdpSessionRow, root.session_id)
        original = await session.get(AuthenticationEventRow, password.event_id)
        assert parent is not None and parent.expires_at == root.expires_at
        assert original is not None and original.assurance == Assurance.PASSWORD.value


async def test_account_substitution_during_idp_and_sp_reauthentication_is_rejected(
    security_lab: SecurityLab,
) -> None:
    lab = security_lab
    issued = await lab.issue()
    cookie = await lab.sps["sp-a"].establish(issued.proof.evidence, issued.credentials)
    different = lab.authentication(subject="user:other-account")
    with pytest.raises(SecurityDenied) as denied:
        await lab.idp.reauthenticate(
            issued.credentials.context.authentication.session_id, different
        )
    assert denied.value.reason == Denial.BINDING
    _, fact = await lab.idp.open_session(different)
    other = await lab.issue(fact)
    with pytest.raises(SecurityDenied) as denied:
        await lab.sps["sp-a"].establish(
            other.proof.evidence, other.credentials, previous_cookie=cookie
        )
    assert denied.value.reason == Denial.BINDING
    assert (await lab.sps["sp-a"].authorize(cookie, AuthenticationRequirement())).subject == (
        "user:model-fixture"
    )


@pytest.mark.parametrize("case", ["missing_record", "altered_evidence"])
async def test_valid_signatures_without_exact_authoritative_issuance_cannot_create_sessions(
    security_lab: SecurityLab, case: str
) -> None:
    lab = security_lab
    issued = await lab.issue()
    original = jwt.decode(issued.proof.response.id_token, lab.keys.issuer.key, algorithms=["RS256"])
    claims = dict(original.claims)
    claims["jti"] = secrets.token_urlsafe(24)
    forged_token = jwt.encode(original.header, claims, lab.keys.issuer.key, algorithms=["RS256"])
    response = issued.proof.response.model_copy(update={"id_token": forged_token})
    forged = verified_login_evidence(
        response,
        settings=lab.rp_settings(),
        nonce=issued.proof.nonce,
        keys=lab.keys.issuer.public_jwks(),
        clock=lab.clock,
        event_id=issued.credentials.context.authentication.event_id,
    )
    context = issued.credentials.context.model_copy(update={"evidence": forged})
    credentials = issued.credentials.model_copy(
        update={
            "context": context,
            "access_token": SecretStr(secrets.token_urlsafe(32))
            if case == "missing_record"
            else (issued.credentials.access_token),
        }
    )
    assert await authentication_count(lab) == 0
    with pytest.raises(SecurityDenied):
        await lab.sps["sp-a"].establish(forged, credentials)
    assert await authentication_count(lab) == 0
    cookie = await lab.sps["sp-a"].establish(issued.proof.evidence, issued.credentials)
    assert (await lab.sps["sp-a"].authorize(cookie, AuthenticationRequirement())).evidence_id == (
        issued.proof.evidence.token_id
    )


async def test_an_sp_cannot_establish_another_recipient_or_use_another_database_cookie(
    security_lab: SecurityLab,
) -> None:
    lab = security_lab
    issued = await lab.issue()
    cookie = await lab.sps["sp-a"].establish(issued.proof.evidence, issued.credentials)
    with pytest.raises(SecurityDenied):
        await lab.sps["sp-b"].establish(issued.proof.evidence, issued.credentials)
    with pytest.raises(SecurityDenied) as denied:
        await lab.sps["sp-b"].authorize(cookie, AuthenticationRequirement())
    assert denied.value.reason == Denial.MISSING
    assert await authentication_count(lab, ServiceId.SP_B) == 0


async def test_revocation_of_consumed_refresh_is_owner_scoped_and_ends_the_whole_family(
    security_lab: SecurityLab,
) -> None:
    lab = security_lab
    issued = await lab.issue()
    renewed = await lab.idp.rotate_refresh(
        issued.credentials.refresh_token, authenticated_client="sp-a"
    )
    async with lab.idp.repository.transaction() as work:
        await lab.idp.revoke_token_in(
            work,
            issued.credentials.refresh_token,
            authenticated_client="sp-b",
            token_type_hint="refresh_token",
        )
    assert (await lab.idp.check_access(renewed.access_token, authenticated_client="sp-a")).active
    async with lab.idp.repository.transaction() as work:
        await lab.idp.revoke_token_in(
            work,
            issued.credentials.refresh_token,
            authenticated_client="sp-a",
            token_type_hint="access_token",
        )
    assert not (
        await lab.idp.check_access(renewed.access_token, authenticated_client="sp-a")
    ).active
    with pytest.raises(SecurityDenied):
        await lab.idp.rotate_refresh(renewed.refresh_token, authenticated_client="sp-a")
    async with lab.database.sessions() as session:
        grant = await session.get(FederationGrantRow, renewed.context.grant.grant_id)
        parent = await session.get(IdpSessionRow, renewed.context.authentication.session_id)
        assert (
            grant is not None and grant.revocation_reason == RevocationReason.TOKEN_REVOCATION.value
        )
        assert parent is not None and parent.revoked_at is None
