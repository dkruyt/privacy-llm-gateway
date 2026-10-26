"""Bearer API key → key id. Only SHA-256 hashes are configured; compare in constant time."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Mapping

from .config import AuthConfig


class KeyMap:
    def __init__(self, cfg: AuthConfig) -> None:
        self._keys = [(bytes.fromhex(k.sha256), k.id) for k in cfg.keys]

    @property
    def ids(self) -> list[str]:
        return [kid for _, kid in self._keys]

    def authenticate(self, headers: Mapping[str, str]) -> str | None:
        """key_id for a valid "Authorization: Bearer <key>", else None."""
        value = headers.get("authorization", "")
        scheme, _, token = value.partition(" ")
        token = token.strip()
        if scheme.lower() != "bearer" or not token:
            return None
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        found = None
        for expected, kid in self._keys:  # always compare against every key
            if hmac.compare_digest(digest, expected):
                found = kid
        return found
