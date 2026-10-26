"""Request → classifier state, text strings, unsupported flags, session seed.

The classifier state is the COMPLETE request (every role, tool calls, tool
results, tool schemas, response_format, prompt, user, unknown extra fields),
normalised. The original body is what gets forwarded; only the normalised copy
is classified.
"""

from __future__ import annotations

import hashlib
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

# Zero-width characters and bidi controls are removed after NFKC.
_INVISIBLE = re.compile("[​-‍⁠﻿‪-‮⁦-⁩]")
_DATA_URL = re.compile(r"\bdata:[a-z0-9.+-]+/[a-z0-9.+-]+[;,]", re.IGNORECASE)

TEXT_PART_TYPES = frozenset({"text", "input_text", "output_text", "refusal"})
MEDIA_PART_TYPES = {"image_url": "media:image", "input_image": "media:image", "input_audio": "media:audio", "file": "media:file", "input_file": "media:file"}

SessionSource = Literal["header", "metadata", "derived"]


def normalize(s: str) -> str:
    """NFKC, then strip zero-width and bidi control characters."""
    return _INVISIBLE.sub("", unicodedata.normalize("NFKC", s))


@dataclass
class Extraction:
    state: dict[str, Any]
    strings: list[tuple[str, str]] = field(default_factory=list)  # (location, normalised text)
    unsupported: list[str] = field(default_factory=list)
    session_seed: str = ""
    session_source: SessionSource = "derived"

    @property
    def texts(self) -> list[str]:
        return [t for _, t in self.strings]


def _normalise_tree(value: Any, path: str, strings: list[tuple[str, str]]) -> Any:
    """Deep-copy `value`, normalising every string and dict key, collecting strings."""
    if isinstance(value, str):
        n = normalize(value)
        strings.append((path, n))
        return n
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for k, v in value.items():
            nk = normalize(str(k))
            strings.append((f"{path}.<key>", nk))
            out[nk] = _normalise_tree(v, f"{path}.{k}" if path else str(k), strings)
        return out
    if isinstance(value, (list, tuple)):
        return [_normalise_tree(v, f"{path}[{i}]", strings) for i, v in enumerate(value)]
    return value  # numbers, bools, None


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            p.get("text", "") for p in content if isinstance(p, Mapping) and isinstance(p.get("text"), str)
        )
    return ""


def _unsupported(body: Mapping[str, Any], strings: list[tuple[str, str]]) -> list[str]:
    flags: set[str] = set()
    for msg in body.get("messages") or []:
        content = msg.get("content") if isinstance(msg, Mapping) else None
        if not isinstance(content, list):
            continue
        for part in content:
            ptype = part.get("type") if isinstance(part, Mapping) else None
            if ptype in TEXT_PART_TYPES:
                continue
            flags.add(MEDIA_PART_TYPES.get(ptype, "unknown_part_type"))
    prompt = body.get("prompt")
    if isinstance(prompt, list) and prompt and all(
        isinstance(p, int) or (isinstance(p, list) and all(isinstance(x, int) for x in p)) for p in prompt
    ):
        flags.add("token_ids")
    if any(_DATA_URL.search(text) for _, text in strings):
        flags.add("data_url")
    return sorted(flags)


def _derived_seed(body: Mapping[str, Any]) -> str:
    parts: list[str] = []
    first_user: str | None = None
    for msg in body.get("messages") or []:
        if not isinstance(msg, Mapping):
            continue
        role = msg.get("role")
        if role in ("system", "developer"):
            parts.append(f"{role}:{_content_text(msg.get('content'))}")
        elif role == "user" and first_user is None:
            first_user = _content_text(msg.get("content"))
    if first_user is not None:
        parts.append(f"user:{first_user}")
    if "prompt" in body:
        parts.append(f"prompt:{body['prompt']!r}")
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def session_seed(body: Mapping[str, Any], headers: Mapping[str, str], header_name: str) -> tuple[str, SessionSource]:
    h = headers.get(header_name)
    if h and h.strip():
        return h.strip(), "header"
    meta = body.get("metadata")
    if isinstance(meta, Mapping):
        sid = meta.get("session_id")
        if isinstance(sid, (str, int)) and str(sid).strip():
            return str(sid).strip(), "metadata"
    return _derived_seed(body), "derived"


def extract(body: Mapping[str, Any], headers: Mapping[str, str], session_header: str) -> Extraction:
    """`body` is the request after document conversion; it is not modified."""
    strings: list[tuple[str, str]] = []
    state_src = {k: v for k, v in body.items() if k != "model"}
    state = _normalise_tree(state_src, "", strings)
    seed, source = session_seed(body, headers, session_header)
    return Extraction(
        state=state,
        strings=strings,
        unsupported=_unsupported(body, strings),
        session_seed=seed,
        session_source=source,
    )
