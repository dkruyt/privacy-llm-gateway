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
