"""Configured-issuer JWKS trust cache with bounded refresh and single-flight loading."""

import asyncio
from collections.abc import Awaitable, Callable

from federated_identity.common.security.keys import PublicJwks
from federated_identity.common.security.oidc import InvalidIdToken
from federated_identity.common.settings.policy import Clock, validate_https_url


class IssuerJwksCache:
    def __init__(
        self,
        *,
        issuer: str,
        jwks_uri: str,
        clock: Clock,
        loader: Callable[[], Awaitable[PublicJwks]],
        ttl_seconds: int = 300,
        refresh_cooldown_seconds: int = 10,
    ) -> None:
        validate_https_url(issuer)
        if jwks_uri != f"{issuer}/jwks.json" or ttl_seconds <= 0 or refresh_cooldown_seconds <= 0:
            raise ValueError("JWKS cache requires a pinned namespace and positive bounds")
        self.namespace = (issuer, jwks_uri, "RS256")
        self.clock = clock
        self.loader = loader
        self.ttl = ttl_seconds
        self.cooldown = refresh_cooldown_seconds
        self._keys: PublicJwks | None = None
        self._expires_at = 0
        self._last_attempt: int | None = None
        self._last_forced: int | None = None
        self._lock = asyncio.Lock()

    def _copy(self) -> PublicJwks:
        if self._keys is None:
            raise InvalidIdToken("The issuer has no cached verification trust")
        return self._keys.model_copy(deep=True)

    async def _load(self, *, forced: bool) -> None:
        now = self.clock.now()
        self._last_attempt = now
        if forced:
            self._last_forced = now
        keys = await self.loader()
        # Validate public-only shape and importability before replacing good trust.
        checked = PublicJwks.model_validate_json(keys.model_dump_json())
        checked.key_set()
        self._keys = checked
        self._expires_at = self.clock.now() + self.ttl

    async def get(self) -> PublicJwks:
        if self._keys is not None and self.clock.now() < self._expires_at:
            return self._copy()
        async with self._lock:
            if self._keys is not None and self.clock.now() < self._expires_at:
                return self._copy()
            if (
                self._last_attempt is not None
                and self.clock.now() < self._last_attempt + self.cooldown
            ):
                raise InvalidIdToken("Issuer trust refresh is temporarily rate limited")
            await self._load(forced=False)
            return self._copy()

    async def for_key(self, kid: str) -> PublicJwks:
        keys = await self.get()
        if any(key.kid == kid for key in keys.keys):
            return keys
        async with self._lock:
            if self._keys is not None and any(key.kid == kid for key in self._keys.keys):
                return self._copy()
            # One immediate unknown-key refresh is allowed after ordinary warming.
            # All unknown IDs share a cooldown, so random IDs never grow a map
            # or multiply outbound requests. Failed/cancelled attempts spend it.
            if (
                self._last_forced is not None
                and self.clock.now() < self._last_forced + self.cooldown
            ):
                raise InvalidIdToken("Unknown issuer signing key")
            await self._load(forced=True)
            if self._keys is None or not any(key.kid == kid for key in self._keys.keys):
                raise InvalidIdToken("Unknown issuer signing key")
            return self._copy()
