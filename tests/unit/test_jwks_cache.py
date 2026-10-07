"""Public trust caching must recover rotation without giving unknown IDs unbounded work."""

import asyncio
import secrets

import httpx2 as httpx
import pytest
from joserfc import jwt

from federated_identity.common.security.keys import PublicJwks
from federated_identity.common.security.oidc import InvalidIdToken, login_header
from federated_identity.sp.protocol.jwks import IssuerJwksCache
from tests.helpers import KeyFixtures, MutableClock


async def test_cold_and_rotating_key_refresh_are_single_flight(key_fixtures: KeyFixtures) -> None:
    clock = MutableClock(1000)
    first = key_fixtures.issuer.public_jwks()
    second = key_fixtures.client_a.public_jwks()
    loaded = first
    calls = 0
    entered, release = asyncio.Event(), asyncio.Event()

    async def fetch() -> PublicJwks:
        nonlocal calls
        calls += 1
        entered.set()
        await release.wait()
        return loaded

    cache = IssuerJwksCache(
        issuer="https://idp.localhost",
        jwks_uri="https://idp.localhost/jwks.json",
        clock=clock,
        loader=fetch,
    )
    pending = [asyncio.create_task(cache.get()) for _ in range(12)]
    await entered.wait()
    release.set()
    results = await asyncio.gather(*pending)
    assert calls == 1 and all(result == first for result in results)
    results[0].keys.clear()
    assert await cache.get() == first
    loaded = PublicJwks(keys=[*first.keys, *second.keys])
    results = await asyncio.gather(*(cache.for_key(second.keys[0].kid) for _ in range(20)))
    assert calls == 2 and all(result == loaded for result in results)


async def test_random_unknown_ids_have_one_shared_bounded_refresh_budget(
    key_fixtures: KeyFixtures,
) -> None:
    clock, calls = MutableClock(1000), 0

    async def fetch() -> PublicJwks:
        nonlocal calls
        calls += 1
        return key_fixtures.issuer.public_jwks()

    cache = IssuerJwksCache(
        issuer="https://idp.localhost",
        jwks_uri="https://idp.localhost/jwks.json",
        clock=clock,
        loader=fetch,
    )
    await cache.get()
    results = await asyncio.gather(
        *(cache.for_key(secrets.token_urlsafe(24)) for _ in range(100)), return_exceptions=True
    )
    assert calls == 2 and all(isinstance(result, InvalidIdToken) for result in results)
    clock.value += 10
    results = await asyncio.gather(
        *(cache.for_key(secrets.token_urlsafe(24)) for _ in range(100)), return_exceptions=True
    )
    assert calls == 3 and all(isinstance(result, InvalidIdToken) for result in results)


async def test_failed_unknown_refresh_preserves_good_keys_and_spends_budget(
    key_fixtures: KeyFixtures,
) -> None:
    clock = MutableClock(1000)
    failure = False
    calls = 0

    async def fetch() -> PublicJwks:
        nonlocal calls
        calls += 1
        if failure:
            raise httpx.ConnectError("Injected trust dependency outage")
        return key_fixtures.issuer.public_jwks()

    cache = IssuerJwksCache(
        issuer="https://idp.localhost",
        jwks_uri="https://idp.localhost/jwks.json",
        clock=clock,
        loader=fetch,
    )
    known = await cache.get()
    failure = True
    with pytest.raises(httpx.ConnectError):
        await cache.for_key("unknown-key")
    assert await cache.for_key(known.keys[0].kid) == known
    for _ in range(5):
        with pytest.raises(InvalidIdToken):
            await cache.for_key(secrets.token_urlsafe(24))
    assert calls == 2
    clock.value += 300
    with pytest.raises(httpx.ConnectError):
        await cache.get()
    with pytest.raises(InvalidIdToken):
        await cache.get()
    assert calls == 3


async def test_cancelled_unknown_refresh_spends_the_single_flight_budget(
    key_fixtures: KeyFixtures,
) -> None:
    clock, calls = MutableClock(1000), 0
    entered, release = asyncio.Event(), asyncio.Event()

    async def fetch() -> PublicJwks:
        nonlocal calls
        calls += 1
        if calls > 1:
            entered.set()
            await release.wait()
        return key_fixtures.issuer.public_jwks()

    cache = IssuerJwksCache(
        issuer="https://idp.localhost",
        jwks_uri="https://idp.localhost/jwks.json",
        clock=clock,
        loader=fetch,
    )
    await cache.get()
    pending = asyncio.create_task(cache.for_key("unknown-key"))
    await entered.wait()
    pending.cancel()
    with pytest.raises(asyncio.CancelledError):
        await pending
    for _ in range(10):
        with pytest.raises(InvalidIdToken):
            await cache.for_key(secrets.token_urlsafe(24))
    assert calls == 2


async def test_cache_namespaces_never_share_same_kid_trust(key_fixtures: KeyFixtures) -> None:
    a = key_fixtures.issuer.public_jwks().model_copy(deep=True)
    b = key_fixtures.client_b.public_jwks().model_copy(deep=True)
    a.keys[0] = a.keys[0].model_copy(update={"kid": "shared-kid"})
    b.keys[0] = b.keys[0].model_copy(update={"kid": "shared-kid"})

    async def fetch_a() -> PublicJwks:
        return a

    async def fetch_b() -> PublicJwks:
        return b

    first = IssuerJwksCache(
        issuer="https://idp-a.example",
        jwks_uri="https://idp-a.example/jwks.json",
        clock=MutableClock(1000),
        loader=fetch_a,
    )
    second = IssuerJwksCache(
        issuer="https://idp-b.example",
        jwks_uri="https://idp-b.example/jwks.json",
        clock=MutableClock(1000),
        loader=fetch_b,
    )
    assert first.namespace != second.namespace
    assert (await first.for_key("shared-kid")).keys[0].n != (
        await second.for_key("shared-kid")
    ).keys[0].n
    with pytest.raises(ValueError):
        IssuerJwksCache(
            issuer="https://idp-a.example",
            jwks_uri="https://attacker.example/jwks",
            clock=MutableClock(1000),
            loader=fetch_a,
        )


@pytest.mark.parametrize(
    "case", ["wrong_type", "key_url", "embedded_key", "wrong_algorithm", "oversize", "malformed"]
)
def test_untrusted_headers_cannot_select_network_trust(
    key_fixtures: KeyFixtures, case: str
) -> None:
    header: dict[str, object] = {"alg": "RS256", "typ": "JWT", "kid": "unknown-key"}
    if case == "wrong_type":
        header["typ"] = "logout+jwt"
    elif case == "key_url":
        header["jku"] = "https://attacker.example/jwks"
    elif case == "embedded_key":
        header["jwk"] = key_fixtures.client_a.key.as_dict(private=False)
    token = jwt.encode(header, {"sub": "fixture"}, key_fixtures.issuer.key, algorithms=["RS256"])
    if case == "wrong_algorithm":
        # The parser must reject the declaration before a cache loader is invoked.
        token = token.replace(
            token.split(".")[0],
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InVua25vd24ta2V5In0",
        )
    elif case == "oversize":
        token += "x" * 8192
    elif case == "malformed":
        token = "not.a.valid.compact.signature"
    with pytest.raises(InvalidIdToken):
        login_header(token, max_bytes=8192)
