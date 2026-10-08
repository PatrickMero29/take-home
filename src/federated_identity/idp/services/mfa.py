"""Library-based TOTP matching; consumption joins the new event/browser transaction."""

from pydantic import SecretStr
from sqlalchemy.ext.asyncio import AsyncSession

from federated_identity.common.security.contracts import StepUpEngine
from federated_identity.common.security.model import Denial, SecurityDenied
from federated_identity.idp.repositories.mfa import (
    TotpConsumptionRow,
    TotpCredentialRow,
    TotpRepository,
)


class TotpAuthenticator:
    def __init__(self, repository: TotpRepository, engine: StepUpEngine) -> None:
        self.repository, self.engine = repository, engine

    async def match_in(
        self, session: AsyncSession, subject: str, code: SecretStr
    ) -> tuple[TotpCredentialRow, int] | None:
        row = await self.repository.get_in(session, subject)
        if row is None:
            return None
        counter = self.engine.matched_counter(
            self.repository.secret(row), code, now=self.repository.clock.now()
        )
        if counter is None or counter <= row.last_accepted_counter:
            return None
        return row, counter

    def consume_in(
        self,
        session: AsyncSession,
        proof: tuple[TotpCredentialRow, int],
        event_id: str,
        code: SecretStr,
    ) -> None:
        row, counter = proof
        if (
            self.engine.matched_counter(
                self.repository.secret(row), code, now=self.repository.clock.now()
            )
            != counter
        ):
            raise SecurityDenied(Denial.EXPIRED)
        row.last_accepted_counter = counter
        session.add(
            TotpConsumptionRow(
                subject=row.subject,
                counter=counter,
                event_id=event_id,
                accepted_at=self.repository.clock.now(),
            )
        )
