"""Sticky sessions in Redis, fail-closed.

Key   "privacy:sess:" + sha256(key_id + "\\0" + session_seed)
Value the literal string "sensitive"
Never stores content, the raw session id or the API key.
Also holds the public-prefix cache (prefix_cache.py) on the same connection.
"""

from __future__ import annotations

import hashlib
from typing import Any

import redis.asyncio as aioredis
from redis.exceptions import RedisError

from .config import RedisConfig
from .prefix_cache import VALUE as PREFIX_VALUE

KEY_PREFIX = "privacy:sess:"
VALUE = "sensitive"


class SessionStoreUnavailable(Exception):
    """Redis could not be read. The caller routes local and does not pin."""


def session_key(key_id: str, seed: str) -> str:
    return KEY_PREFIX + hashlib.sha256(f"{key_id}\0{seed}".encode("utf-8")).hexdigest()


def short_id(key: str) -> str:
    """Last 12 hex characters of the key, for logs."""
    return key[-12:]


class SessionStore:
    def __init__(self, cfg: RedisConfig, ttl_seconds: int, client: Any | None = None) -> None:
        self._ttl = ttl_seconds
        self._redis = client or aioredis.Redis.from_url(
            cfg.url,
            socket_connect_timeout=cfg.connect_timeout_s,
            socket_timeout=cfg.timeout_s,
            retry_on_timeout=False,
            retry=None,
            decode_responses=True,
            health_check_interval=0,
        )

    async def is_sensitive(self, key: str) -> bool:
        try:
            value = await self._redis.get(key)
            if value is None:
                return False
            await self._redis.expire(key, self._ttl)
        except (RedisError, OSError) as exc:
            raise SessionStoreUnavailable(type(exc).__name__) from None
        if isinstance(value, bytes):
            value = value.decode("utf-8", "replace")
        return value == VALUE

    async def mark_sensitive(self, key: str) -> bool:
        """True on success. Failures are reported by the caller (session_store_write_failed)."""
        try:
            await self._redis.set(key, VALUE, ex=self._ttl)
            return True
        except (RedisError, OSError):
            return False

    async def longest_public_prefix(self, keys: list[str]) -> int:
        """Number of messages in the longest cached public prefix (0 = none).

        Raises SessionStoreUnavailable; the caller then ignores the cache.
        """
        try:
            values = await self._redis.mget(keys)
        except (RedisError, OSError) as exc:
            raise SessionStoreUnavailable(type(exc).__name__) from None
        for i in range(len(values) - 1, -1, -1):
            v = values[i]
            if isinstance(v, bytes):
                v = v.decode("utf-8", "replace")
            if v == PREFIX_VALUE:
                return i + 1
        return 0

    async def mark_public_prefix(self, key: str, ttl_seconds: int) -> bool:
        try:
            await self._redis.set(key, PREFIX_VALUE, ex=ttl_seconds)
            return True
        except (RedisError, OSError):
            return False

    async def ping(self) -> bool:
        try:
            return bool(await self._redis.ping())
        except (RedisError, OSError):
            return False

    async def aclose(self) -> None:
        try:
            await self._redis.aclose()
        except Exception:  # noqa: BLE001
            pass
