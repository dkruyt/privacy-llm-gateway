"""Classification cache per conversation prefix.

Key   "privacy:prefix:" + HMAC chain over (policy fingerprint, session key,
      state without messages, messages[0..k-1])
Value the literal string "public"

Only public outcomes are stored. On the next turn the longest cached prefix is
found with one MGET; only the messages after it are classified. Keys are HMACs
with the stamp key, so Redis never holds plain content fingerprints.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

from .config import PUBLIC, Thresholds
from .decision import ClassifierResult

KEY_PREFIX = "privacy:prefix:"
VALUE = "public"


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def fingerprint(
    classifier_model: str, questions: dict[str, Any], state_notice: str, thresholds: Thresholds, margin: float
) -> str:
    """Changes whenever a cached public decision might no longer hold (SIGHUP invalidates)."""
    return hashlib.sha256(
        _canonical([classifier_model, questions, state_notice, thresholds.model_dump(), margin])
    ).hexdigest()


def chain(key: bytes, fp: str, session_key: str, state: dict[str, Any]) -> list[str] | None:
    """Redis keys for messages[:1] .. messages[:N]; None when the request has no messages list."""
    messages = state.get("messages")
    if not isinstance(messages, list) or not messages:
        return None
    rest = {k: v for k, v in state.items() if k != "messages"}
    h = hmac.new(key, b"\0".join((fp.encode(), session_key.encode(), _canonical(rest))), hashlib.sha256).digest()
    keys: list[str] = []
    for msg in messages:
        h = hmac.new(key, h + _canonical(msg), hashlib.sha256).digest()
        keys.append(KEY_PREFIX + h.hex())
    return keys


def clearly_public(r: ClassifierResult, t: Thresholds, margin: float) -> bool:
    """Public with at least `margin` distance from every threshold."""
    return (
        r.choice == PUBLIC
        and r.probabilities.get(PUBLIC, 0.0) >= t.public_min_prob + margin
        and r.confidence >= t.min_confidence + margin
        and all(p <= t.category_max_prob - margin for p in r.category_probs.values())
        and r.manipulation <= t.manipulation_max_prob - margin
    )
