"""Mock model servers for the integration suite. ROLE=public|local|clef.

Control endpoints (test network only):
  GET  /__stats   {"count": n, "bodies": [...], "arrivals": [t, ...], "clef_done": [t, ...]}
  POST /__reset
  POST /__mode    {"mode": "..."}

public  counts every model call (the core assertion: sensitive → 0 calls).
local   modes: ok | error500 | hang
clef    modes: public | sensitive | uncertain | hang | error500 | malformed | missing |
        bad_probabilities | keyword | category:<name> | high_category:<name> |
        low_confidence | low_public | manipulation | slow
        keyword: personal_data if the state contains "SENSITIVE_KEYWORD", else public.
"""

from __future__ import annotations

import asyncio
import json
import os
import time

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

ROLE = os.environ.get("ROLE", "public")
CATEGORIES = ["public", "personal_data", "credentials_secrets", "private_document",
              "confidential_business", "proprietary_code", "uncertain"]
SENSITIVE = [c for c in CATEGORIES if c not in ("public", "uncertain")]

app = FastAPI()
state = {"count": 0, "bodies": [], "arrivals": [], "clef_done": [], "mode": "public" if ROLE == "clef" else "ok"}


@app.get("/__stats")
async def stats():
    return {k: state[k] for k in ("count", "bodies", "arrivals", "clef_done", "mode")}


@app.post("/__reset")
async def reset():
    state.update(count=0, bodies=[], arrivals=[], clef_done=[], mode="public" if ROLE == "clef" else "ok")
    return {"ok": True}


@app.post("/__mode")
async def mode(req: Request):
    state["mode"] = (await req.json())["mode"]
    return {"ok": True}


# ------------------------------------------------------------------ model servers

SSE_CHUNKS = [
    {"id": "c1", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"role": "assistant", "content": "Hel"}}]},
    {"id": "c1", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {"content": "lo"}, "finish_reason": "stop"}]},
]


async def _model(req: Request):
    state["arrivals"].append(time.time())
    raw = await req.body()
    body = json.loads(raw) if raw else {}
    state["count"] += 1
    state["bodies"].append(body)
    if ROLE == "local":
        if state["mode"] == "error500":
            return JSONResponse({"error": {"message": "local failure"}}, status_code=500)
        if state["mode"] == "hang":
            await asyncio.sleep(3600)
    if body.get("stream"):
        async def gen():
            for chunk in SSE_CHUNKS:
                yield f"data: {json.dumps({**chunk, 'served_by': ROLE})}\n\n".encode()
                await asyncio.sleep(0.05)
            yield b"data: [DONE]\n\n"

        return StreamingResponse(gen(), media_type="text/event-stream")
    return {"id": "x", "object": "chat.completion", "served_by": ROLE, "model": body.get("model"),
            "choices": [{"index": 0, "message": {"role": "assistant", "content": f"hello from {ROLE}"}, "finish_reason": "stop"}]}


if ROLE in ("public", "local"):
    app.post("/v1/chat/completions")(_model)
    app.post("/v1/completions")(_model)
    app.post("/v1/embeddings")(_model)

    @app.get("/v1/models")
    async def models():
        return {"object": "list", "data": [{"id": f"{ROLE}-model", "object": "model"}]}


# ------------------------------------------------------------------ clef


def _answers(choice: str, p_choice: float = 0.95, confidence: float = 0.9, cats=None, manipulation: float = 0.01):
    probs = {c: 0.0 for c in CATEGORIES}
    probs[choice] = p_choice
    other = "uncertain" if choice != "uncertain" else "public"
    probs[other] = round(1 - p_choice, 6)
    answers = {"verdict": {"type": "choice", "choice": choice, "probabilities": probs, "confidence": confidence}}
    for c in SENSITIVE:
        answers[f"has_{c}"] = {"type": "noul", "noul": (cats or {}).get(c, 0.01)}
    answers["manipulation"] = {"type": "noul", "noul": manipulation}
    return {"model": "mock-clef", "answers": answers, "usage": {"input_tokens": 100, "output_tokens": 0}}


if ROLE == "clef":

    @app.post("/v1/systemone")
    async def systemone(req: Request):
        state["arrivals"].append(time.time())
        state["count"] += 1
        raw = await req.body()
        body = json.loads(raw)
        if body.get("state") == "ping":  # gateway health probe
            state["count"] -= 1
            state["arrivals"].pop()
            return {"answers": {"ok": {"type": "noul", "noul": 1.0}}}
        mode = state["mode"]
        try:
            if mode == "hang":
                await asyncio.sleep(3600)
            if mode == "slow":
                await asyncio.sleep(1.5)
                return _answers("public")
            if mode == "error500":
                return Response(status_code=500)
            if mode == "malformed":
                return Response(b"{this is not json", media_type="application/json")
            if mode == "missing":
                a = _answers("public")
                del a["answers"]["manipulation"]
                return a
            if mode == "bad_probabilities":
                a = _answers("public")
                a["answers"]["verdict"]["probabilities"]["public"] = 1.7
                return a
            if mode == "keyword":
                return _answers("personal_data" if "SENSITIVE_KEYWORD" in raw.decode() else "public")
            if mode.startswith("category:"):
                return _answers(mode.split(":", 1)[1])
            if mode.startswith("high_category:"):
                return _answers("public", cats={mode.split(":", 1)[1]: 0.9})
            if mode == "low_confidence":
                return _answers("public", confidence=0.2)
            if mode == "low_public":
                return _answers("public", p_choice=0.6)
            if mode == "manipulation":
                return _answers("public", manipulation=0.95)
            if mode in ("sensitive",):
                return _answers("personal_data")
            if mode == "uncertain":
                return _answers("uncertain", p_choice=0.7)
            return _answers("public")
        finally:
            state["clef_done"].append(time.time())
