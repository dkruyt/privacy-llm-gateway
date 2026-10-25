"""
title: Privacy Gateway
description: Models "auto" and "local" through the privacy gateway. Shows above every answer whether it was handled by the local or the public model.
version: 0.1.0
license: MIT

Open WebUI pipe function (manifold). Install with openwebui/install.py or paste it in
Admin Panel → Functions. It replaces the direct OpenAI connection to the gateway: same
models, same requests, plus a status line built from the gateway's x-privacy-* headers.
The answer itself is relayed unchanged.
"""

from __future__ import annotations

import json
import os
from typing import Any, AsyncIterator, Awaitable, Callable, Optional

import aiohttp
from pydantic import BaseModel, Field

EventEmitter = Optional[Callable[[dict], Awaitable[None]]]

LABELS = {
    "local": "🔒 Local model",
    "public": "🌐 Public model",
}


class Pipe:
    class Valves(BaseModel):
        GATEWAY_URL: str = Field(
            default="",
            description="Gateway base URL incl. /v1. Empty: env PRIVACY_GATEWAY_URL, else http://gateway:8080/v1.",
        )
        GATEWAY_API_KEY: str = Field(
            default="",
            description="Gateway bearer key. Empty: env PRIVACY_GATEWAY_KEY.",
        )
        SHOW_REASONS: bool = Field(
            default=True,
            description="For answers routed locally by classification, show the verdict and reason codes.",
        )
        SEND_CHAT_ID_AS_SESSION: bool = Field(
            default=True,
            description="Send the chat id as x-session-id so sticky pinning follows the Open WebUI chat.",
        )
        TIMEOUT_S: int = Field(default=600, description="Total request timeout in seconds.")

    def __init__(self):
        self.type = "manifold"
        self.valves = self.Valves()

    def pipes(self) -> list[dict[str, str]]:
        return [{"id": "auto", "name": "auto"}, {"id": "local", "name": "local"}]

    # ------------------------------------------------------------------ helpers

    def _url(self) -> str:
        base = self.valves.GATEWAY_URL or os.environ.get("PRIVACY_GATEWAY_URL") or "http://gateway:8080/v1"
        return base.rstrip("/") + "/chat/completions"

    def _headers(self, chat_id: Optional[str]) -> dict[str, str]:
        headers = {"content-type": "application/json"}
        key = self.valves.GATEWAY_API_KEY or os.environ.get("PRIVACY_GATEWAY_KEY", "")
        if key:
            headers["authorization"] = f"Bearer {key}"
        if self.valves.SEND_CHAT_ID_AS_SESSION and chat_id:
            headers["x-session-id"] = chat_id
        return headers

    def _describe(self, headers: Any, requested: str) -> str:
        route = headers.get("x-privacy-route", "")
        text = LABELS.get(route, "Route unknown")
        if requested == "local":
            return text + " (selected)"
        # Public means every check agreed; only a local route has reasons worth showing.
        if self.valves.SHOW_REASONS and route == "local":
            verdict = headers.get("x-privacy-verdict", "")
            reasons = headers.get("x-privacy-reasons", "")
            detail = verdict + (f": {reasons.replace(',', ', ')}" if reasons else "")
            if detail:
                text += f" · {detail}"
        return text

    @staticmethod
    async def _status(emit: EventEmitter, description: str, done: bool) -> None:
        if emit:
            await emit({"type": "status", "data": {"description": description, "done": done}})

    @staticmethod
    async def _error_message(resp: aiohttp.ClientResponse) -> str:
        try:
            body = json.loads(await resp.text())
            return body["error"]["message"]
        except Exception:  # noqa: BLE001 - non-OpenAI error body
            return f"Gateway returned HTTP {resp.status}."

    # ------------------------------------------------------------------ pipe

    async def pipe(
        self,
        body: dict,
        __event_emitter__: EventEmitter = None,
        __chat_id__: Optional[str] = None,
        __task__: Optional[str] = None,
    ):
        requested = body["model"].split(".", 1)[-1]
        payload = {**body, "model": requested}
        stream = bool(payload.get("stream"))
        # Background tasks (titles, tags, follow-ups) have no message to put a status on.
        emit = None if __task__ else __event_emitter__

        await self._status(emit, "Sending to local model…" if requested == "local" else "Checking privacy…", False)
        session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.valves.TIMEOUT_S), trust_env=False
        )
        try:
            resp = await session.post(self._url(), json=payload, headers=self._headers(__chat_id__))
        except Exception:
            await session.close()
            await self._status(emit, "Gateway unreachable", True)
            raise

        description = self._describe(resp.headers, requested)
        if resp.status >= 400:
            message = await self._error_message(resp)
            resp.release()
            await session.close()
            failed = f"{description} · error" if "x-privacy-route" in resp.headers else "Gateway error"
            await self._status(emit, failed, True)
            raise Exception(message)

        await self._status(emit, description, True)
        if not stream:
            try:
                return await resp.json(content_type=None)
            finally:
                resp.release()
                await session.close()
        return self._relay(session, resp)

    @staticmethod
    async def _relay(session: aiohttp.ClientSession, resp: aiohttp.ClientResponse) -> AsyncIterator[str]:
        # Pass SSE data lines through as-is (Open WebUI forwards "data:" lines untouched);
        # it appends its own final chunk and [DONE].
        try:
            async for raw in resp.content:
                line = raw.decode("utf-8").strip()
                if line.startswith("data:") and line[5:].strip() != "[DONE]":
                    yield line
        finally:
            resp.release()
            await session.close()
