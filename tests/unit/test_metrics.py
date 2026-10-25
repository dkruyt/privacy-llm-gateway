from __future__ import annotations

import re

import httpx
import pytest
from prometheus_client.parser import text_string_to_metric_families

from privacy_gateway import metrics
from privacy_gateway.app import create_app, make_holder
from tests.conftest import TEST_KEY
from tests.unit.test_app import AUTH, Mocks, chat

PLANTED = [
    "PLANTED-SECRET-MARK-7f3a",
    "jan.planted@example.com",
    "NL91ABNA0417164300",
    "AKIAZ7Q3XWERTYUIOPAS",
    "planted-session-id-42",
    "client-chosen-model-xyz",
    TEST_KEY,
]

ALLOWED_LABELS = {
    "privacy_requests_total": {
        "key_id": {"openwebui", "n8n"},
        "endpoint": set(metrics.ENDPOINTS),
        "requested": set(metrics.REQUESTED),
        "route": set(metrics.ROUTES),
        "verdict": set(metrics.VERDICTS),
        "stream": {"true", "false"},
    },
    "privacy_classifier_calls_total": {"result": set(metrics.CLASSIFIER_RESULTS)},
    "privacy_classifier_skipped_total": {"why": set(metrics.SKIP_WHY)},
    "privacy_session_events_total": {"event": set(metrics.SESSION_EVENTS)},
    "privacy_prefix_cache_total": {"result": set(metrics.PREFIX_RESULTS)},
    "privacy_documents_total": {"type": set(metrics.DOC_TYPES), "result": set(metrics.DOC_RESULTS)},
    "privacy_egress_total": {"route": set(metrics.ROUTES), "result": set(metrics.EGRESS_RESULTS)},
    "privacy_upstream_errors_total": {"route": set(metrics.ROUTES), "kind": set(metrics.UPSTREAM_KINDS)},
    "privacy_config_reloads_total": {"result": {"ok", "failed"}},
    "privacy_upstream_ttfb_seconds": {"route": set(metrics.ROUTES)},
    "privacy_request_seconds": {"route": set(metrics.ROUTES), "stream": {"true", "false"}},
    "privacy_inflight_requests": {"route": set(metrics.ROUTES)},
    "privacy_up": {"dependency": set(metrics.DEPENDENCIES)},
}
REASON_RE = re.compile(
    r"^(detector:[a-z_]+|detector:custom:[a-z0-9_]+|detector:detect_secrets:[A-Za-z0-9]+|unsupported:[a-z_:]+"
    r"|classifier_error:[a-z0-9_]+|classifier_choice:[a-z_]+|classifier_category:[a-z_]+|document_attached:(pdf|text)"
    r"|too_large_for_classifier|classifier_low_public_prob|classifier_low_confidence|classifier_manipulation_score|session_sticky"
    r"|session_store_unavailable|classifier_internal_error|not_classified|other)$"
)


@pytest.fixture
async def gw(loaded):
    mocks = Mocks(loaded.config.policy)
    holder = make_holder(loaded, transports=mocks.transports(), redis_client=mocks.redis)
    app = create_app(holder, start_background=False)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://gw") as c:
        await app.state.probe_once()
        yield c, mocks, holder


async def drive_traffic(c, mocks):
    """Every planted value goes through as many code paths as possible."""
    s = PLANTED
    await c.post("/v1/chat/completions", json=chat(" ".join(s)), headers={**AUTH, "x-session-id": s[4]})
    await c.post("/v1/chat/completions", json=chat(s[0], model=s[5]), headers={**AUTH, "x-session-id": s[4]})
    await c.post("/v1/chat/completions", json=chat(s[0], metadata={"session_id": s[4]}), headers=AUTH)
    await c.post("/v1/chat/completions", json=chat(s[0], stream=True), headers=AUTH)
    await c.post("/v1/chat/completions", json=chat(s[0], api_base="http://x"), headers=AUTH)
    await c.post("/v1/chat/completions", json={"model": s[5], "messages": [{"role": s[0]}]}, headers=AUTH)
    await c.post("/v1/chat/completions", json=chat(s[0]), headers={"authorization": f"Bearer {s[0]}"})
    await c.post(f"/v1/{s[0]}", json={"model": "auto"}, headers=AUTH)
    await c.post("/v1/chat/completions", json={"model": "auto", "messages": [{"role": "user", "content": [
        {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="}}, {"type": s[0]}]}]}, headers=AUTH)
    mocks.classifier_mode = "personal_data"
    await c.post("/v1/chat/completions", json=chat(s[0]), headers=AUTH)
    mocks.classifier_mode = "error500"
    await c.post("/v1/chat/completions", json=chat(s[0]), headers=AUTH)
    mocks.local_mode = "error500"
    await c.post("/v1/chat/completions", json=chat(s[1]), headers=AUTH)
    mocks.redis.down = True
    await c.post("/v1/chat/completions", json=chat(s[0]), headers=AUTH)


def scrape() -> str:
    return metrics.render().decode()


async def test_labels_from_allowed_sets_only(gw):
    c, mocks, _ = gw
    await drive_traffic(c, mocks)
    text = scrape()
    seen = set()
    for fam in text_string_to_metric_families(text):
        for sample in fam.samples:
            name = fam.name + ("_total" if fam.type == "counter" else "")
            allowed = ALLOWED_LABELS.get(name) or ALLOWED_LABELS.get(fam.name)
            labels = {k: v for k, v in sample.labels.items() if k != "le"}
            if fam.name == "privacy_route_reasons":
                assert REASON_RE.match(labels["reason"]), labels
                seen.add(labels["reason"])
            elif fam.name == "privacy_config_info":
                assert re.fullmatch(r"[0-9a-f]{64}", labels["config_sha256"])
            elif fam.name == "privacy_build_info":
                assert re.fullmatch(r"\d+\.\d+\.\d+", labels["version"])
            elif fam.name == "privacy_client_errors":
                assert re.fullmatch(r"[a-z0-9_]{1,40}", labels["code"])
            elif allowed is not None:
                for k, v in labels.items():
                    assert v in allowed[k], (name, k, v)
            elif fam.name.startswith("privacy_"):
                assert labels == {}, (fam.name, labels)
    assert "detector:email" in seen and "session_store_unavailable" in seen


async def test_no_planted_secret_in_metrics(gw):
    c, mocks, _ = gw
    await drive_traffic(c, mocks)
    text = scrape()
    for needle in PLANTED:
        assert needle not in text, needle
        assert needle.lower() not in text.lower(), needle


async def test_expected_series_present(gw):
    c, mocks, _ = gw
    await c.post("/v1/chat/completions", json=chat(), headers=AUTH)
    text = scrape()
    for name in [
        "privacy_requests_total", "privacy_route_reasons_total", "privacy_classifier_calls_total", "privacy_classifier_skipped_total",
        "privacy_session_events_total", "privacy_documents_total", "privacy_egress_total", "privacy_upstream_errors_total",
        "privacy_client_errors_total", "privacy_config_reloads_total", "privacy_classification_seconds",
        "privacy_classifier_seconds", "privacy_upstream_ttfb_seconds", "privacy_request_seconds", "privacy_classifier_p_public",
        "privacy_classifier_confidence", "privacy_classifier_category_max_prob", "privacy_classifier_manipulation_prob",
        "privacy_classifier_input_tokens", "privacy_inflight_requests", "privacy_config_info", "privacy_build_info", "privacy_up",
    ]:
        assert f"# TYPE {name.removesuffix('_total')}" in text, name
    assert 'privacy_egress_total{result="blocked",route="public"} ' in text  # pre-created series
    assert 'privacy_up{dependency="redis"} 1.0' in text


async def test_metrics_app_auth():
    app = metrics.make_metrics_app(lambda: "tok")
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://m") as c:
        assert (await c.get("/metrics")).status_code == 401
        assert (await c.get("/metrics", headers={"authorization": "Bearer nope"})).status_code == 401
        r = await c.get("/metrics", headers={"authorization": "Bearer tok"})
        assert r.status_code == 200 and "privacy_build_info" in r.text
        assert (await c.get("/other")).status_code == 404
    open_app = metrics.make_metrics_app(lambda: None)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=open_app), base_url="http://m") as c:
        assert (await c.get("/metrics")).status_code == 200


async def test_metrics_not_on_api_port(gw):
    c, _, _ = gw
    assert (await c.get("/metrics")).status_code == 404


def test_reason_sanitising():
    known = {"detector:email", "classifier_choice:public"}
    assert metrics.safe_reason("detector:email", known) == "detector:email"
    assert metrics.safe_reason("detector:not_configured", known) == "other"
    assert metrics.safe_reason("free text with jan@example.com", known) == "other"
    assert metrics.safe_reason("classifier_error:http_503", known) == "classifier_error:http_503"


async def test_reload_metric_and_config_info(gw, cfg_dict, write_cfg):
    _, _, holder = gw
    before = metrics.REGISTRY.get_sample_value("privacy_config_reloads_total", {"result": "failed"}) or 0
    from pathlib import Path

    Path(holder.loaded.path).write_text("broken: [")
    assert holder.reload() is False
    assert metrics.REGISTRY.get_sample_value("privacy_config_reloads_total", {"result": "failed"}) == before + 1
    cfg_dict["policy"]["thresholds"]["public_min_prob"] = 0.9
    write_cfg(cfg_dict)
    assert holder.reload() is True
    assert metrics.REGISTRY.get_sample_value("privacy_config_info", {"config_sha256": holder.loaded.sha256}) == 1


def test_known_series_precreated_at_zero():
    """increase() cannot see the first increment of a new series; known series must start at 0."""
    metrics.init_label_sets(["svc"], ["detector:iban", "classifier_choice:personal_data"])
    get = metrics.REGISTRY.get_sample_value
    assert get("privacy_route_reasons_total", {"reason": "detector:iban"}) is not None
    assert get("privacy_route_reasons_total", {"reason": "session_sticky"}) is not None
    assert get("privacy_requests_total", {"key_id": "svc", "endpoint": "chat_completions", "requested": "auto",
                                          "route": "local", "verdict": "sensitive", "stream": "false"}) == 0
    assert get("privacy_client_errors_total", {"code": "invalid_api_key"}) is not None
