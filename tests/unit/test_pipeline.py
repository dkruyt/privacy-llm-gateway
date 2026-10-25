from __future__ import annotations

import json

import pytest
import respx

from privacy_gateway.classifier import ClassifierClient
from privacy_gateway.config import PolicyConfig
from privacy_gateway.detectors import Detectors
from privacy_gateway.pipeline import evaluate
from tests.unit.test_classifier import good_response


@pytest.fixture
def parts(loaded):
    cfg = loaded.config
    return cfg, Detectors(cfg.policy.detectors), ClassifierClient(cfg.classifier, cfg.policy)


def chat(text, **extra):
    return {"model": "auto", "messages": [{"role": "user", "content": text}], **extra}


async def run(parts, body, documents=(), policy: PolicyConfig | None = None, classifier_json=None, status=200):
    cfg, det, classifier = parts
    policy = policy or cfg.policy
    with respx.mock(assert_all_mocked=True, assert_all_called=False) as m:
        route = m.post(cfg.classifier.url).respond(status, json=classifier_json or good_response(policy))
        ev = await evaluate(body=body, headers={}, policy=policy, detectors=det, classifier=classifier, documents=list(documents))
    return ev, route


async def test_clean_public(parts):
    ev, route = await run(parts, chat("What is the capital of France?"))
    assert ev.decision.route == "public" and route.call_count == 1
    assert ev.classifier_scores()["choice"] == "public"
    assert "classification" in ev.timings_ms and "classifier" in ev.timings_ms


async def test_detector_hit_skips_classifier(parts):
    ev, route = await run(parts, chat("mail me at jan@example.com"))
    assert route.call_count == 0
    assert ev.decision.route == "local" and ev.decision.sticky
    assert ev.decision.reasons == ["detector:email"]


async def test_unsupported_skips_classifier(parts):
    body = {"model": "auto", "messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "https://x/y.png"}}]}]}
    ev, route = await run(parts, body)
    assert route.call_count == 0 and ev.decision.reasons == ["unsupported:media:image"]


async def test_too_large_skips_classifier_not_sticky(parts):
    ev, route = await run(parts, chat("lorem ipsum " * 5000))
    assert route.call_count == 0
    assert ev.decision.reasons == ["too_large_for_classifier"] and not ev.decision.sticky


async def test_document_forced_local_skips_classifier(parts):
    ev, route = await run(parts, chat("[Attached document: x]\nhello"), documents=["pdf"])
    assert route.call_count == 0 and ev.decision.reasons == ["document_attached:pdf"] and ev.decision.sticky


async def test_document_allow_public_classifies(parts):
    cfg = parts[0]
    pol = PolicyConfig.model_validate({**cfg.policy.model_dump(), "documents": {"allow_public": True}})
    ev, route = await run(parts, chat("[Attached document: x]\nhello world"), documents=["text"], policy=pol)
    assert route.call_count == 1 and ev.decision.route == "public"


async def test_classifier_error_local_not_sticky(parts):
    ev, route = await run(parts, chat("hello"), status=500)
    assert route.call_count == 1
    assert ev.decision.reasons == ["classifier_error:http_500"] and not ev.decision.sticky
    assert ev.classifier_scores() == {"error": "http_500"}


async def test_classifier_sensitive(parts):
    cfg = parts[0]
    ev, _ = await run(parts, chat("hello"), classifier_json=good_response(cfg.policy, choice="personal_data"))
    assert ev.decision.route == "local" and "classifier_choice:personal_data" in ev.decision.reasons


async def test_state_is_full_request(parts):
    cfg, det, classifier = parts
    body = chat("hi", tools=[{"type": "function", "function": {"name": "f", "description": "TOOLDESC"}}])
    with respx.mock() as m:
        route = m.post(cfg.classifier.url).respond(200, json=good_response(cfg.policy))
        await evaluate(body=body, headers={}, policy=cfg.policy, detectors=det, classifier=classifier, documents=[])
    sent = json.loads(route.calls.last.request.content)
    assert sent["state"]["request"]["tools"][0]["function"]["description"] == "TOOLDESC"
    assert "model" not in sent["state"]["request"]
