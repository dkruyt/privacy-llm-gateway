from __future__ import annotations

import base64
import json
import logging

import httpx
import pytest

from privacy_llm_gateway import metrics
from privacy_llm_gateway.app import create_app, make_holder
from tests.conftest import TEST_KEY, TEST_KEY2
from tests.fakes import FakeRedis
from tests.pdfs import data_url, docx_bytes, text_pdf
from tests.unit.test_classifier import good_response

AUTH = {"authorization": f"Bearer {TEST_KEY}"}
AUTH2 = {"authorization": f"Bearer {TEST_KEY2}"}
SSE = b'data: {"choices":[{"delta":{"content":"Hi"}}]}\n\ndata: [DONE]\n\n'


class Mocks:
    def __init__(self, policy):
        self.policy = policy
        self.events: list[str] = []
        self.public: list[dict] = []
        self.local: list[dict] = []
        self.classifier: list[dict] = []
        self.classifier_mode = "public"
        self.local_mode = "ok"
        self.redis = FakeRedis()

    def transports(self):
        return {"public": httpx.MockTransport(self._public), "local": httpx.MockTransport(self._local),
                "classifier": httpx.MockTransport(self._classifier)}

    def _model_response(self, req, who):
        body = json.loads(req.content)
        if body.get("stream"):
            return httpx.Response(200, content=SSE, headers={"content-type": "text/event-stream"})
        return httpx.Response(200, json={"id": "x", "object": "chat.completion", "served_by": who,
                                         "choices": [{"message": {"role": "assistant", "content": "ok"}}]})

    def _public(self, req):
        self.events.append("public")
        self.public.append(json.loads(req.content))
        return self._model_response(req, "public")

    def _local(self, req):
        self.events.append("local")
        if req.method == "POST" and req.content:
            self.local.append(json.loads(req.content))
        if self.local_mode == "error500":
            return httpx.Response(500, json={"error": "boom"})
        if self.local_mode == "hang":
            raise httpx.ReadTimeout("hang")
        if req.url.path.endswith("/embeddings"):
            return httpx.Response(200, json={"data": [{"embedding": [0.1]}]})
        return self._model_response(req, "local")

    def _classifier(self, req):
        self.events.append("classifier")
        self.classifier.append(json.loads(req.content))
        if self.classifier_mode == "error500":
            return httpx.Response(500)
        if self.classifier_mode == "malformed":
            return httpx.Response(200, content=b"{not json")
        return httpx.Response(200, json=good_response(self.policy, choice=self.classifier_mode))


@pytest.fixture
def mocks(loaded):
    return Mocks(loaded.config.policy)


@pytest.fixture
def holder(loaded, mocks):
    return make_holder(loaded, transports=mocks.transports(), redis_client=mocks.redis)


@pytest.fixture
async def client(holder):
    app = create_app(holder, start_background=False)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://gw") as c:
        yield c


def chat(text="What is the capital of France?", **kw):
    return {"model": "auto", "messages": [{"role": "user", "content": text}], **kw}


# ------------------------------------------------------------------ auth / basics


@pytest.mark.parametrize("headers", [{}, {"authorization": "Bearer wrong"}, {"authorization": TEST_KEY}, {"authorization": "Basic x"}])
async def test_auth_required(client, headers, mocks):
    r = await client.post("/v1/chat/completions", json=chat(), headers=headers)
    assert r.status_code == 401
    assert r.json()["error"]["code"] == "invalid_api_key"
    assert set(r.json()["error"]) == {"message", "type", "code"}
    assert mocks.events == []


async def test_models(client):
    r = await client.get("/v1/models", headers=AUTH)
    assert [m["id"] for m in r.json()["data"]] == ["auto", "local"]
    assert (await client.get("/v1/models")).status_code == 401


async def test_health(client):
    assert (await client.get("/healthz")).json() == {"status": "ok"}
    r = await client.get("/readyz")
    assert r.status_code == 200 and r.json()["redis"] == "up"


async def test_readyz_redis_down(client, mocks):
    mocks.redis.down = True
    r = await client.get("/readyz")
    assert r.status_code == 503 and r.json()["redis"] == "down"


# ------------------------------------------------------------------ routing


async def test_public_route(client, mocks, loaded):
    r = await client.post("/v1/chat/completions", json=chat(temperature=0.2), headers=AUTH)
    assert r.status_code == 200, r.text
    assert r.headers["x-privacy-route"] == "public"
    assert r.headers["x-privacy-verdict"] == "public"
    assert r.headers["x-privacy-reasons"] == ""
    assert r.json()["served_by"] == "public"
    assert len(mocks.public) == 1 and mocks.local == []
    sent = mocks.public[0]
    assert sent["model"] == loaded.config.upstreams.public.model
    assert sent["messages"] == chat()["messages"] and sent["temperature"] == 0.2
    assert mocks.events == ["classifier", "public"]


async def test_detector_routes_local_and_pins(client, mocks, loaded):
    r = await client.post("/v1/chat/completions", json=chat("mail jan@example.com"), headers=AUTH)
    assert r.headers["x-privacy-route"] == "local"
    assert r.headers["x-privacy-reasons"] == "detector:email"
    assert mocks.public == [] and mocks.classifier == []
    assert mocks.local[0]["model"] == loaded.config.upstreams.local.model
    assert len(mocks.redis.data) == 1
    # same session (header), clean content → still local
    r1 = await client.post("/v1/chat/completions", json=chat(), headers={**AUTH, "x-session-id": "s1"})
    assert r1.headers["x-privacy-route"] == "public"
    await client.post("/v1/chat/completions", json=chat("token: hunter2"), headers={**AUTH, "x-session-id": "s1"})
    r2 = await client.post("/v1/chat/completions", json=chat(), headers={**AUTH, "x-session-id": "s1"})
    assert r2.headers["x-privacy-route"] == "local" and r2.headers["x-privacy-reasons"] == "session_sticky"
    # other key, same session id → unaffected
    r3 = await client.post("/v1/chat/completions", json=chat(), headers={**AUTH2, "x-session-id": "s1"})
    assert r3.headers["x-privacy-route"] == "public"
    # other session, same key → unaffected
    r4 = await client.post("/v1/chat/completions", json=chat(), headers={**AUTH, "x-session-id": "s2"})
    assert r4.headers["x-privacy-route"] == "public"
    for key in mocks.redis.data:
        assert "s1" not in key and TEST_KEY not in key and "hunter2" not in key


async def test_model_local_skips_classification(client, mocks):
    r = await client.post("/v1/chat/completions", json=chat(model="local"), headers=AUTH)
    assert r.headers["x-privacy-route"] == "local" and mocks.classifier == [] and mocks.public == []


async def test_public_model_name_is_classified_like_auto(client, mocks, loaded):
    mocks.classifier_mode = "personal_data"
    r = await client.post("/v1/chat/completions", json=chat(model="openai/gpt-4o"), headers=AUTH)
    assert r.headers["x-privacy-route"] == "local" and mocks.public == []
    assert mocks.local[0]["model"] == loaded.config.upstreams.local.model


@pytest.mark.parametrize("field", ["api_base", "base_url", "api_key", "custom_llm_provider", "api_version", "fallbacks", "provider", "route"])
async def test_routing_fields_rejected(client, mocks, field):
    r = await client.post("/v1/chat/completions", json=chat(**{field: "x"}), headers=AUTH)
    assert r.status_code == 400 and r.json()["error"]["code"] == "routing_field_not_allowed"
    assert mocks.events == []


@pytest.mark.parametrize("mode,reason", [("error500", "classifier_error:http_500"), ("malformed", "classifier_error:invalid_json")])
async def test_classifier_failure_local_not_pinned(client, mocks, mode, reason):
    mocks.classifier_mode = mode
    r = await client.post("/v1/chat/completions", json=chat(), headers=AUTH)
    assert r.headers["x-privacy-route"] == "local" and r.headers["x-privacy-reasons"] == reason
    assert mocks.public == [] and mocks.redis.data == {}


async def test_redis_down_routes_local(client, mocks):
    mocks.redis.down = True
    r = await client.post("/v1/chat/completions", json=chat(), headers=AUTH)
    assert r.headers["x-privacy-route"] == "local"
    assert r.headers["x-privacy-reasons"] == "session_store_unavailable"
    assert mocks.public == [] and mocks.classifier == []


async def test_pipeline_exception_routes_local(client, mocks, monkeypatch):
    import privacy_llm_gateway.app as appmod

    async def boom(**_):
        raise RuntimeError("SECRET-IN-EXCEPTION")

    monkeypatch.setattr(appmod, "evaluate", boom)
    r = await client.post("/v1/chat/completions", json=chat(), headers=AUTH)
    assert r.headers["x-privacy-route"] == "local"
    assert r.headers["x-privacy-reasons"] == "classifier_internal_error"
    assert mocks.public == [] and mocks.redis.data == {}


async def test_egress_guard_blocks_bad_stamp(client, mocks, holder, monkeypatch):
    rt = holder.current
    monkeypatch.setattr(rt.upstreams, "stamp", lambda route, body: "0" * 64)
    blocked = metrics.REGISTRY.get_sample_value("privacy_egress_total", {"route": "public", "result": "blocked"}) or 0
    r = await client.post("/v1/chat/completions", json=chat(), headers=AUTH)
    assert r.status_code == 500 and r.json()["error"]["code"] == "egress_blocked"
    assert mocks.public == [] and mocks.local == []
    assert metrics.REGISTRY.get_sample_value("privacy_egress_total", {"route": "public", "result": "blocked"}) == blocked + 1


# ------------------------------------------------------------------ errors


async def test_request_too_large(client, holder):
    limit = holder.current.config.server.request_max_bytes
    r = await client.post("/v1/chat/completions", content=b"x" * (limit + 1), headers={**AUTH, "content-type": "application/json"})
    assert r.status_code == 413 and r.json()["error"]["code"] == "request_too_large"


@pytest.mark.parametrize("content,code", [(b"{bad", "invalid_json"), (b"[1]", "invalid_json"), (b'{"model":"auto"}', "invalid_request"),
                                          (b'{"model":"auto","messages":[]}', "invalid_request")])
async def test_bad_bodies(client, content, code):
    r = await client.post("/v1/chat/completions", content=content, headers=AUTH)
    assert r.status_code == 400 and r.json()["error"]["code"] == code


async def test_validation_error_does_not_echo_input(client):
    body = {"model": "auto", "messages": [{"role": 123, "content": "SECRET-VALUE-MARK"}]}
    r = await client.post("/v1/chat/completions", json=body, headers=AUTH)
    assert r.status_code == 400 and "SECRET-VALUE-MARK" not in r.text


@pytest.mark.parametrize("mode,status,code", [("error500", 502, "upstream_http_5xx"), ("hang", 504, "upstream_timeout")])
async def test_local_failure_is_client_error_no_fallback(client, mocks, mode, status, code):
    mocks.local_mode = mode
    r = await client.post("/v1/chat/completions", json=chat("my iban NL91ABNA0417164300"), headers=AUTH)
    assert r.status_code == status and r.json()["error"]["code"] == code
    assert r.headers["x-privacy-route"] == "local"
    assert mocks.public == []


async def test_other_endpoints(client, mocks, holder, loaded):
    r = await client.post("/v1/embeddings", json={"model": "auto", "input": "x"}, headers=AUTH)
    assert r.status_code == 400 and r.json()["error"]["code"] == "endpoint_requires_local"
    r = await client.post("/v1/embeddings", json={"model": "local", "input": "x"}, headers=AUTH)
    assert r.status_code == 404
    r = await client.get("/v1/files", headers=AUTH)
    assert r.status_code == 400
    r = await client.get("/admin", headers=AUTH)
    assert r.status_code == 404 and r.json()["error"]["code"] == "not_found"
    assert mocks.events == []


async def test_passthrough_when_configured(loaded, mocks, write_cfg, cfg_dict):
    from privacy_llm_gateway.config import load_config

    cfg_dict["upstreams"]["local"]["passthrough_paths"] = ["/embeddings"]
    lc = load_config(write_cfg(cfg_dict))
    holder = make_holder(lc, transports=mocks.transports(), redis_client=mocks.redis)
    app = create_app(holder, start_background=False)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw") as c:
        r = await c.post("/v1/embeddings", json={"model": "local", "input": "x"}, headers=AUTH)
        assert r.status_code == 200 and r.json()["data"][0]["embedding"] == [0.1]
        assert mocks.local[-1]["model"] == lc.config.upstreams.local.model
        r = await c.post("/v1/embeddings", json={"model": "auto", "input": "x"}, headers=AUTH)
        assert r.status_code == 400
    assert mocks.public == []


# ------------------------------------------------------------------ attachments


async def test_pdf_attachment_local_and_pinned(client, mocks):
    pdf = text_pdf(["Contract between parties", "lorem ipsum dolor sit amet"])
    body = {"model": "auto", "messages": [{"role": "user", "content": [
        {"type": "text", "text": "summarise"},
        {"type": "file", "file": {"filename": "c.pdf", "file_data": data_url("application/pdf", pdf)}}]}]}
    r = await client.post("/v1/chat/completions", json=body, headers=AUTH)
    assert r.headers["x-privacy-route"] == "local"
    assert r.headers["x-privacy-reasons"] == "document_attached:pdf"
    assert mocks.public == [] and mocks.classifier == [] and len(mocks.redis.data) == 1
    part = mocks.local[0]["messages"][0]["content"][1]
    assert part["type"] == "text" and part["text"].startswith("[Attached document: c.pdf]")
    assert "base64" not in json.dumps(mocks.local[0])


async def test_docx_rejected(client, mocks):
    body = {"model": "auto", "messages": [{"role": "user", "content": [
        {"type": "file", "file": {"filename": "x.docx", "file_data": data_url("application/vnd.openxmlformats-officedocument.wordprocessingml.document", docx_bytes())}}]}]}
    r = await client.post("/v1/chat/completions", json=body, headers=AUTH)
    assert r.status_code == 400 and r.json()["error"]["code"] == "unsupported_document_type"
    assert mocks.events == []


# ------------------------------------------------------------------ streaming


async def test_streaming_public_passthrough(client, mocks):
    r = await client.post("/v1/chat/completions", json=chat(stream=True), headers=AUTH)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    assert r.headers["x-privacy-route"] == "public"
    assert r.content == SSE
    assert mocks.events == ["classifier", "public"]  # classified before the upstream connection


async def test_streaming_sensitive_local(client, mocks):
    r = await client.post("/v1/chat/completions", json=chat("ssn 111222333", stream=True), headers=AUTH)
    assert r.headers["x-privacy-route"] == "local" and r.content == SSE and mocks.public == []


async def test_completions_endpoint(client, mocks):
    r = await client.post("/v1/completions", json={"model": "auto", "prompt": "Once upon a time"}, headers=AUTH)
    assert r.headers["x-privacy-route"] == "public" and mocks.public[0]["prompt"] == "Once upon a time"
    r = await client.post("/v1/completions", json={"model": "auto", "prompt": [1, 2, 3]}, headers=AUTH)
    assert r.headers["x-privacy-route"] == "local" and r.headers["x-privacy-reasons"] == "unsupported:token_ids"


# ------------------------------------------------------------------ hygiene


async def test_logs_are_content_free(client, mocks, caplog):
    from privacy_llm_gateway.logs import JsonFormatter

    caplog.set_level(logging.DEBUG)
    secret = "SECRET-PLANTED-" + base64.b16encode(b"x").decode()
    await client.post("/v1/chat/completions", json=chat(f"{secret} jan@example.com"), headers=AUTH)
    await client.post("/v1/chat/completions", json=chat(secret), headers={**AUTH, "x-session-id": "SESSION-ID-MARK"})
    fmt = JsonFormatter()
    out = "\n".join(fmt.format(r) for r in caplog.records)
    assert "decision" in out
    for needle in (secret, "jan@example.com", "SESSION-ID-MARK", TEST_KEY):
        assert needle not in out
    lines = [json.loads(line) for line in out.splitlines()]
    d = [x for x in lines if x.get("event") == "decision"]
    assert len(d) == 2 and d[0]["route"] == "local" and len(d[0]["session"]) == 12


# ------------------------------------------------------------------ opaque reasoning


def replayed(details):
    return {"model": "auto", "messages": [
        {"role": "user", "content": "Tell me a fun fact"},
        {"role": "assistant", "content": "Vespasian taxed urine.", "reasoning_details": details},
        {"role": "user", "content": "Another one"},
    ]}


async def test_encrypted_reasoning_is_removed_before_classification_and_forwarding(client, mocks):
    # An IBAN inside the opaque blob would fire the detector if the blob were scanned.
    blob = {"type": "reasoning.encrypted", "data": "NL91 ABNA 0417 1643 00", "index": 1}
    summary = {"type": "reasoning.summary", "summary": "A fun fact.", "index": 0}
    before = metrics.OPAQUE_REASONING._value.get()
    r = await client.post("/v1/chat/completions", json=replayed([summary, blob]), headers=AUTH)
    assert r.headers["x-privacy-route"] == "public", r.headers["x-privacy-reasons"]
    assert "NL91" not in json.dumps(mocks.classifier) and "NL91" not in json.dumps(mocks.public)
    assert mocks.public[0]["messages"][1]["reasoning_details"] == [summary]
    assert metrics.OPAQUE_REASONING._value.get() == before + 1


async def test_readable_reasoning_is_still_classified(client, mocks):
    summary = {"type": "reasoning.summary", "summary": "User's IBAN is NL91 ABNA 0417 1643 00.", "index": 0}
    r = await client.post("/v1/chat/completions", json=replayed([summary]), headers=AUTH)
    assert r.headers["x-privacy-route"] == "local" and "detector:iban" in r.headers["x-privacy-reasons"]
    assert mocks.public == []


# ------------------------------------------------------------------ prefix cache


@pytest.fixture
async def prefix_client(cfg_dict, write_cfg, mocks):
    from privacy_llm_gateway.config import load_config

    cfg_dict["policy"]["session"]["prefix_cache"] = {"enabled": True}
    holder = make_holder(load_config(write_cfg(cfg_dict)), transports=mocks.transports(), redis_client=mocks.redis)
    app = create_app(holder, start_background=False)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw") as c:
        yield c


async def test_prefix_cache_second_turn_classifies_delta(prefix_client, mocks):
    hdr = {**AUTH, "x-session-id": "chat-1"}
    turn1 = chat("What is the capital of France?")
    r = await prefix_client.post("/v1/chat/completions", json=turn1, headers=hdr)
    assert r.headers["x-privacy-route"] == "public"
    new = [{"role": "assistant", "content": "Paris."}, {"role": "user", "content": "And Spain?"}]
    turn2 = {**turn1, "messages": turn1["messages"] + new}
    r = await prefix_client.post("/v1/chat/completions", json=turn2, headers=hdr)
    assert r.headers["x-privacy-route"] == "public"
    assert len(mocks.classifier) == 2
    assert mocks.classifier[1]["state"]["request"] == {"messages": new}
    # other session: no shared cache entry → full classification
    r = await prefix_client.post("/v1/chat/completions", json=turn2, headers={**AUTH, "x-session-id": "chat-2"})
    assert mocks.classifier[2]["state"]["request"]["messages"] == turn2["messages"]


async def test_prefix_cache_off_by_default(client, mocks):
    hdr = {**AUTH, "x-session-id": "chat-1"}
    turn1 = chat()
    await client.post("/v1/chat/completions", json=turn1, headers=hdr)
    turn2 = {**turn1, "messages": turn1["messages"] + [{"role": "assistant", "content": "x"}, {"role": "user", "content": "y"}]}
    await client.post("/v1/chat/completions", json=turn2, headers=hdr)
    assert mocks.classifier[1]["state"]["request"]["messages"] == turn2["messages"]
    assert not any(k.startswith("privacy:prefix:") for k in mocks.redis.data)
