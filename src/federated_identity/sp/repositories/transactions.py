"""Encrypted, one-use OIDC transaction storage bound to the initiating browser."""

from pydantic import SecretStr
from sqlalchemy import BigInteger, LargeBinary, String, delete
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from federated_identity.common.persistence.database import AsyncDatabase
from federated_identity.common.security.model import Assurance
from federated_identity.common.security.secrets import EnvelopeCipher
from federated_identity.common.settings.policy import Clock, verifier_digest
from federated_identity.sp.protocol.oidc import AuthorizationTransaction


class TransactionBase(DeclarativeBase):
    pass


class AuthorizationTransactionRow(TransactionBase):
    __tablename__ = "authorization_transactions"

    state_digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    browser_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    encrypted_payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False)


class PostgresAuthorizationTransactions:
    def __init__(self, database: AsyncDatabase, cipher: EnvelopeCipher, clock: Clock) -> None:
        self.database = database
        self.cipher = cipher
        self.clock = clock

    async def save(
        self, transaction: AuthorizationTransaction, browser: SecretStr, *, ttl: int = 300
    ) -> None:
        if ttl <= 0:
            raise ValueError("A positive transaction lifetime is required")
        payload = {
            "client_id": transaction.client_id,
            "redirect_uri": transaction.redirect_uri,
            "authorization_url": transaction.authorization_url,
            "state": transaction.state,
            "nonce": transaction.nonce,
            "verifier": transaction.verifier,
            "prompt": transaction.prompt,
            "max_age": transaction.max_age,
            "requested_at": transaction.requested_at,
            "acr_values": transaction.acr_values.value if transaction.acr_values else None,
            "expected_subject": transaction.expected_subject,
        }
        async with self.database.sessions() as session:
            session.add(
                AuthorizationTransactionRow(
                    state_digest=verifier_digest(transaction.state),
                    browser_digest=verifier_digest(browser.get_secret_value()),
                    encrypted_payload=self.cipher.encrypt(payload, purpose="oidc-transaction"),
                    expires_at=self.clock.now() + ttl,
                )
            )
            await session.commit()

    async def consume(self, state: str, browser: SecretStr) -> AuthorizationTransaction | None:
        statement = (
            delete(AuthorizationTransactionRow)
            .where(
                AuthorizationTransactionRow.state_digest == verifier_digest(state),
                AuthorizationTransactionRow.browser_digest
                == verifier_digest(browser.get_secret_value()),
                AuthorizationTransactionRow.expires_at > self.clock.now(),
            )
            .returning(AuthorizationTransactionRow.encrypted_payload)
        )
        async with self.database.sessions() as session:
            encrypted = (await session.execute(statement)).scalar_one_or_none()
            if encrypted is None:
                return None
            payload = self.cipher.decrypt(encrypted, purpose="oidc-transaction")
            if not all(
                isinstance(payload.get(name), str)
                for name in (
                    "client_id",
                    "redirect_uri",
                    "authorization_url",
                    "state",
                    "nonce",
                    "verifier",
                )
            ):
                raise ValueError("The stored protocol transaction has invalid field types")
            prompt = payload.get("prompt")
            max_age = payload.get("max_age")
            requested_at = payload.get("requested_at")
            acr = payload.get("acr_values")
            subject = payload.get("expected_subject")
            if (
                prompt not in {None, "login"}
                or (max_age is not None and (type(max_age) is not int or not 0 <= max_age <= 86400))
                or (
                    requested_at is not None
                    and (type(requested_at) is not int or requested_at <= 0)
                )
                or acr not in {None, Assurance.PASSWORD.value, Assurance.PASSWORD_TOTP.value}
                or (
                    subject is not None
                    and (not isinstance(subject, str) or not 1 <= len(subject) <= 255)
                )
            ):
                raise ValueError("Stored freshness policy has invalid field types")
            transaction = AuthorizationTransaction(
                client_id=str(payload["client_id"]),
                redirect_uri=str(payload["redirect_uri"]),
                authorization_url=str(payload["authorization_url"]),
                state=str(payload["state"]),
                nonce=str(payload["nonce"]),
                verifier=str(payload["verifier"]),
                prompt="login" if prompt == "login" else None,
                max_age=max_age if isinstance(max_age, int) else None,
                requested_at=requested_at if isinstance(requested_at, int) else None,
                acr_values=Assurance(acr) if isinstance(acr, str) else None,
                expected_subject=subject if isinstance(subject, str) else None,
            )
            await session.commit()
            return transaction
