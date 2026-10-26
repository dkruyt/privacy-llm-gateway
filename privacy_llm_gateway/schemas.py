"""Accepted request shapes. Unknown fields are kept (they are classified and forwarded)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Fields that would let a client choose where a request goes. Always rejected (400).
ROUTING_FIELDS = frozenset(
    {"api_base", "base_url", "api_key", "custom_llm_provider", "api_version", "fallbacks", "provider", "route"}
)

# Fields the gateway itself adds and never sends upstream. None today: the gateway
# communicates through headers only. Kept as the single place to extend.
GATEWAY_ONLY_FIELDS: frozenset[str] = frozenset()

# Opaque provider reasoning that clients replay on follow-up turns (OpenRouter
# `reasoning_details`): encrypted blobs and signatures. The gateway cannot read them, and
# random base64 skews the classifier and trips detectors, so it removes them before
# classification. Removed, not skipped: nothing reaches an upstream unclassified.
OPAQUE_REASONING_TYPES = frozenset({"reasoning.encrypted"})
OPAQUE_REASONING_KEYS = frozenset({"signature"})

MODEL_AUTO = "auto"
MODEL_LOCAL = "local"


class _Request(BaseModel):
    model_config = ConfigDict(extra="allow")

    model: str = Field(min_length=1)
    stream: bool = False
    metadata: dict[str, Any] | None = None


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="allow")

    role: str = Field(min_length=1)
    content: str | list[dict[str, Any]] | None = None

    @field_validator("content")
    @classmethod
    def _parts(cls, v):
        if isinstance(v, list):
            for part in v:
                if not isinstance(part.get("type"), str):
                    raise ValueError("every content part needs a string 'type'")
        return v


class ChatCompletionRequest(_Request):
    messages: list[ChatMessage] = Field(min_length=1)


class CompletionRequest(_Request):
    prompt: str | list[str] | list[int] | list[list[int]]


def error_body(message: str, type_: str, code: str) -> dict[str, Any]:
    return {"error": {"message": message, "type": type_, "code": code}}


def strip_opaque_reasoning(body: dict[str, Any]) -> tuple[dict[str, Any], int]:
    """Return (body without opaque reasoning, number of removed items/fields). The input is not modified."""
    messages = body.get("messages")
    if not isinstance(messages, list):
        return body, 0
    removed = 0
    out_messages = []
    for msg in messages:
        details = msg.get("reasoning_details") if isinstance(msg, dict) else None
        if not isinstance(details, list):
            out_messages.append(msg)
            continue
        kept = []
        for item in details:
            if isinstance(item, dict) and item.get("type") in OPAQUE_REASONING_TYPES:
                removed += 1
                continue
            if isinstance(item, dict) and OPAQUE_REASONING_KEYS & item.keys():
                removed += len(OPAQUE_REASONING_KEYS & item.keys())
                item = {k: v for k, v in item.items() if k not in OPAQUE_REASONING_KEYS}
            kept.append(item)
        msg = {k: v for k, v in msg.items() if k != "reasoning_details"}
        if kept:
            msg["reasoning_details"] = kept
        out_messages.append(msg)
    if not removed:
        return body, 0
    return {**body, "messages": out_messages}, removed
