"""One async connection pool per application, scoped to its own database role."""

import ssl
from pathlib import Path

from pydantic import SecretStr
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine


class AsyncDatabase:
    def __init__(
        self,
        url: SecretStr,
        *,
        ca_file: Path | None = None,
        session_class: type[AsyncSession] = AsyncSession,
    ) -> None:
        parsed = make_url(url.get_secret_value())
        if parsed.drivername != "postgresql+asyncpg":
            raise ValueError("An asyncpg PostgreSQL connection is required")
        connect_args: dict[str, object] = {}
        socket_host = parsed.query.get("host")
        local_socket = isinstance(socket_host, str) and socket_host.startswith("/")
        if not local_socket:
            connect_args["ssl"] = ssl.create_default_context(
                cafile=str(ca_file) if ca_file else None
            )
        self.engine = create_async_engine(
            parsed,
            connect_args=connect_args,
            pool_size=10,
            max_overflow=10,
            pool_pre_ping=True,
            echo=False,
        )
        self.sessions = async_sessionmaker(
            self.engine, class_=session_class, expire_on_commit=False
        )

    async def ready(self) -> bool:
        async with self.engine.connect() as connection:
            identity = (
                await connection.execute(text("SELECT current_user, current_database()"))
            ).one()
            return bool(
                identity[0] == self.engine.url.username and identity[1] == self.engine.url.database
            )

    async def dispose(self) -> None:
        await self.engine.dispose()
