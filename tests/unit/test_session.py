from __future__ import annotations

import hashlib

import pytest

from privacy_gateway.config import RedisConfig
from privacy_gateway.session import SessionStore, SessionStoreUnavailable, session_key, short_id
from tests.fakes import FakeRedis


@pytest.fixture
def fake():
    return FakeRedis()


@pytest.fixture
def store(fake):
    return SessionStore(RedisConfig(), ttl_seconds=600, client=fake)


def test_key_format_and_namespacing():
    k = session_key("openwebui", "sess-1")
    assert k == "privacy:sess:" + hashlib.sha256(b"openwebui\0sess-1").hexdigest()
    assert session_key("n8n", "sess-1") != k
    assert session_key("openwebui", "sess-2") != k
    assert "sess-1" not in k and "openwebui" not in k
    assert short_id(k) == k[-12:] and len(short_id(k)) == 12


async def test_mark_then_hit_refreshes_ttl(store, fake):
    k = session_key("a", "s")
    assert await store.is_sensitive(k) is False
    assert await store.mark_sensitive(k) is True
    assert fake.data[k][0] == "sensitive"
    assert ("set", k, "sensitive", 600) in fake.calls
    assert await store.is_sensitive(k) is True
    assert ("expire", k, 600) in fake.calls


async def test_miss_does_not_create_key(store, fake):
    await store.is_sensitive(session_key("a", "nope"))
    assert fake.data == {}


async def test_ttl_expiry(store, fake):
    clock = [1000.0]
    fake.now = lambda: clock[0]
    k = session_key("a", "s")
    await store.mark_sensitive(k)
    clock[0] += 599
    assert await store.is_sensitive(k) is True  # refreshed to +600
    clock[0] += 599
    assert await store.is_sensitive(k) is True
    clock[0] += 601
    assert await store.is_sensitive(k) is False


async def test_read_failure_raises(store, fake):
    fake.down = True
    with pytest.raises(SessionStoreUnavailable):
        await store.is_sensitive(session_key("a", "s"))


async def test_write_failure_returns_false(store, fake):
    fake.fail_writes = True
    assert await store.mark_sensitive(session_key("a", "s")) is False


async def test_ping(store, fake):
    assert await store.ping() is True
    fake.down = True
    assert await store.ping() is False


async def test_real_client_unreachable_fails_fast():
    import time

    s = SessionStore(RedisConfig(url="redis://127.0.0.1:1/0", connect_timeout_s=0.2, timeout_s=0.2), 60)
    t0 = time.monotonic()
    with pytest.raises(SessionStoreUnavailable):
        await s.is_sensitive("privacy:sess:x")
    assert time.monotonic() - t0 < 2
    assert await s.mark_sensitive("privacy:sess:x") is False
    await s.aclose()
