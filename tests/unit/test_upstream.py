from __future__ import annotations

import ast
import json
import secrets
from pathlib import Path

import httpx
import pytest
import respx

from privacy_gateway import metrics
from privacy_gateway.upstream import EgressBlocked, UpstreamFailure, Upstreams, make_stamp

KEY = secrets.token_bytes(32)
PUB = "https://openrouter.ai/api/v1/chat/completions"
LOCAL = "http://127.0.0.1:8081/v1/chat/completions"


def body(text="hello"):
    return {"model": "openai/gpt-5-mini", "messages": [{"role": "user", "content": text}]}


def egress_value(route, result):
    return metrics.REGISTRY.get_sample_value("privacy_egress_total", {"route": route, "result": result}) or 0.0


@pytest.fixture
def ups(loaded):
    return Upstreams(loaded.config.upstreams, KEY)


async def test_public_with_valid_stamp_is_allowed(ups):
    b = body()
    before = egress_value("public", "allowed")
    with respx.mock() as m:
        route = m.post(PUB).respond(200, json={"ok": True})
        r = await ups.send("public", "/chat/completions", b, ups.stamp("public", b), stream=False)
    assert r.status == 200 and json.loads(r.content) == {"ok": True}
    assert route.call_count == 1
    sent = route.calls.last.request
    assert json.loads(sent.content) == b
    assert sent.headers["authorization"] == "Bearer public-secret-value"
    assert egress_value("public", "allowed") == before + 1


@pytest.mark.parametrize(
    "case",
    ["unstamped", "empty", "forged", "tampered", "local_stamped", "other_key"],
)
async def test_public_blocked(ups, case):
    b = body()
    stamp = {
        "unstamped": lambda: None,
        "empty": lambda: "",
        "forged": lambda: secrets.token_hex(32),
        "tampered": lambda: ups.stamp("public", body("something else")),
        "local_stamped": lambda: ups.stamp("local", b),
        "other_key": lambda: make_stamp(secrets.token_bytes(32), "public", b),
    }[case]()
    blocked_before = egress_value("public", "blocked")
    allowed_before = egress_value("public", "allowed")
    with respx.mock(assert_all_called=False) as m:
        route = m.post(PUB).respond(200, json={})
        with pytest.raises(EgressBlocked):
            await ups.send("public", "/chat/completions", b, stamp, stream=False)
    assert route.call_count == 0
    assert egress_value("public", "blocked") == blocked_before + 1
    assert egress_value("public", "allowed") == allowed_before


async def test_body_mutated_after_stamp_is_blocked(ups):
    b = body()
    stamp = ups.stamp("public", b)
    b["messages"].append({"role": "user", "content": "my email is x@y.example"})
    with respx.mock(assert_all_called=False) as m:
        route = m.post(PUB).respond(200, json={})
        with pytest.raises(EgressBlocked):
            await ups.send("public", "/chat/completions", b, stamp, stream=False)
    assert route.call_count == 0


async def test_stamp_ignores_model_only(ups):
    a, b = body(), body()
    b["model"] = "something/else"
    assert ups.stamp("public", a) == ups.stamp("public", b)
    b["temperature"] = 0.1
    assert ups.stamp("public", a) != ups.stamp("public", b)


async def test_local_does_not_need_stamp(ups):
    with respx.mock() as m:
        m.post(LOCAL).respond(200, json={"ok": 1})
        r = await ups.send("local", "/chat/completions", body(), None, stream=False)
    assert r.status == 200


async def test_local_host_outside_allowlist_blocked(loaded):
    cfg = loaded.config.upstreams
    bad_local = cfg.local.model_copy(update={"base_url": "https://api.example.com/v1"})
    ups = Upstreams(cfg.model_copy(update={"local": bad_local}), KEY)
    with respx.mock(assert_all_called=False) as m:
        route = m.post("https://api.example.com/v1/chat/completions").respond(200)
        with pytest.raises(EgressBlocked):
            await ups.send("local", "/chat/completions", body(), None, stream=False)
    assert route.call_count == 0


@pytest.mark.parametrize(
    "mock,status,kind",
    [
        (dict(status_code=500), 502, "http_5xx"),
        (dict(status_code=400), 502, "http_4xx"),
        (dict(status_code=302, headers={"location": "https://evil.example"}), 502, "http_4xx"),
        (dict(side_effect=httpx.ReadTimeout("t")), 504, "timeout"),
        (dict(side_effect=httpx.ConnectError("c")), 502, "transport"),
    ],
)
async def test_upstream_failures(ups, mock, status, kind):
    with respx.mock() as m:
        r = m.post(LOCAL)
        if "side_effect" in mock:
            r.mock(side_effect=mock["side_effect"])
        else:
            r.respond(**mock)
        with pytest.raises(UpstreamFailure) as ei:
            await ups.send("local", "/chat/completions", body(), None, stream=False)
    assert (ei.value.status, ei.value.kind) == (status, kind)
    assert r.call_count == 1  # no retries


async def test_streaming_passthrough_unchanged(ups):
    sse = b'data: {"choices":[{"delta":{"content":"Hi"}}]}\n\ndata: [DONE]\n\n'
    with respx.mock() as m:
        m.post(LOCAL).respond(200, content=sse, headers={"content-type": "text/event-stream"})
        r = await ups.send("local", "/chat/completions", body(), None, stream=True)
        got = b"".join([c async for c in r.stream])
    assert got == sse and r.content_type == "text/event-stream"


def test_clients_ignore_environment(ups, monkeypatch):
    for c in ups._clients.values():
        assert c._trust_env is False and c.follow_redirects is False


def test_only_upstream_and_clef_create_http_clients():
    pkg = Path(__file__).resolve().parents[2] / "privacy_gateway"
    offenders = []
    for path in pkg.glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            name = None
            if isinstance(node, ast.Call):
                f = node.func
                name = f.attr if isinstance(f, ast.Attribute) else f.id if isinstance(f, ast.Name) else None
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                mods = [a.name for a in node.names] + ([node.module] if isinstance(node, ast.ImportFrom) and node.module else [])
                if any(m and m.split(".")[0] in ("requests", "urllib3", "aiohttp", "http") for m in mods):
                    offenders.append(f"{path.name}: imports {mods}")
                if any(m in ("urlopen", "Request") for m in mods):
                    offenders.append(f"{path.name}: imports {mods}")
            if name in ("AsyncClient", "Client", "AsyncHTTPTransport", "HTTPTransport", "stream", "urlopen") or (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == "httpx"
            ):
                if path.name not in ("upstream.py", "clef.py"):
                    offenders.append(f"{path.name}:{node.lineno}")
    assert offenders == []
