"""In-memory test doubles."""

from __future__ import annotations

import time

from redis.exceptions import ConnectionError as RedisConnectionError


class FakeRedis:
    """Implements the subset of redis.asyncio.Redis used by SessionStore."""

    def __init__(self) -> None:
        self.data: dict[str, tuple[str, float | None]] = {}
        self.down = False
        self.fail_writes = False
        self.calls: list[tuple] = []
        self.now = time.monotonic

    def _check(self) -> None:
        if self.down:
            raise RedisConnectionError("down")

    def _live(self, key: str):
        item = self.data.get(key)
        if item and item[1] is not None and item[1] <= self.now():
            del self.data[key]
            return None
        return item

    async def get(self, key):
        self.calls.append(("get", key))
        self._check()
        item = self._live(key)
        return item[0] if item else None

    async def set(self, key, value, ex=None):
        self.calls.append(("set", key, value, ex))
        self._check()
        if self.fail_writes:
            raise RedisConnectionError("write failed")
        self.data[key] = (value, self.now() + ex if ex else None)
        return True

    async def expire(self, key, seconds):
        self.calls.append(("expire", key, seconds))
        self._check()
        item = self._live(key)
        if not item:
            return False
        self.data[key] = (item[0], self.now() + seconds)
        return True

    async def ttl(self, key):
        item = self._live(key)
        if not item:
            return -2
        return int(item[1] - self.now()) if item[1] else -1

    async def ping(self):
        self._check()
        return True

    async def aclose(self):
        pass
