from __future__ import annotations

import json
import math

import httpx
import pytest
import respx

from privacy_gateway.clef import ClefClient, ClefError, StateTooLarge, build_questions, parse_response


@pytest.fixture
def policy(loaded):
    return loaded.config.policy


@pytest.fixture
def clef_cfg(loaded):
    return loaded.config.clef


def good_response(policy, choice="public"):
    cats = list(policy.categories)
    probs = {c: 0.0 for c in cats}
    probs[choice] = 0.9
    probs["uncertain" if choice != "uncertain" else "public"] = 0.1
    answers = {"verdict": {"type": "choice", "choice": choice, "probabilities": probs, "confidence": 0.8}}
    for c in policy.sensitive_categories:
        answers[f"has_{c}"] = {"type": "noul", "noul": 0.05}
    answers["manipulation"] = {"type": "noul", "noul": 0.01}
    return {"model": "clef-flash", "answers": answers, "usage": {"input_tokens": 321, "output_tokens": 0}}


# ------------------------------------------------------------------ questions / payload


def test_questions_shape(policy):
    q = build_questions(policy)
    assert q["verdict"]["type"] == "choice"
    assert set(q["verdict"]["criteria"]) == set(policy.categories)
    assert "public" in q["verdict"]["criteria"] and "uncertain" in q["verdict"]["criteria"]
    for c in policy.sensitive_categories:
        assert q[f"has_{c}"] == {"type": "noul", "instructions": policy.categories[c].question}
    assert "has_public" not in q and "has_uncertain" not in q
    assert q["manipulation"] == {"type": "noul", "instructions": policy.manipulation_instructions}


def test_payload_state_contains_notice_and_full_request(clef_cfg, policy):
    c = ClefClient(clef_cfg, policy)
    body, size = c.payload({"messages": [{"role": "user", "content": "hi"}]})
    assert body["model"] == clef_cfg.model
    assert body["state"] == {"notice": policy.state_notice, "request": {"messages": [{"role": "user", "content": "hi"}]}}
    assert size == len(json.dumps(body["state"], ensure_ascii=False, separators=(",", ":")))


def test_too_large_is_never_truncated(clef_cfg, policy):
    c = ClefClient(clef_cfg, policy)
    with pytest.raises(StateTooLarge):
        c.payload({"messages": [{"role": "user", "content": "x" * clef_cfg.max_state_chars}]})


# ------------------------------------------------------------------ valid parse


def test_parse_valid(policy):
    r = parse_response(good_response(policy), policy)
    assert r.choice == "public" and r.probabilities["public"] == 0.9 and r.confidence == 0.8
    assert set(r.category_probs) == set(policy.sensitive_categories)
    assert r.manipulation == 0.01 and r.input_tokens == 321


def test_parse_valid_without_usage(policy):
    d = good_response(policy)
    del d["usage"]
    assert parse_response(d, policy).input_tokens is None


def test_tolerance_and_ties(policy):
    d = good_response(policy)
    d["answers"]["verdict"]["probabilities"].update({"public": 0.5, "uncertain": 0.5})
    assert parse_response(d, policy).choice == "public"  # tie: choice is a max
    d["answers"]["verdict"]["probabilities"].update({"public": 0.51, "uncertain": 0.5})
    parse_response(d, policy)  # sum 1.01 within ±0.02


# ------------------------------------------------------------------ every invalid shape


def mutate(policy, fn):
    d = good_response(policy)
    fn(d)
    return d


INVALID = {
    "not_object": (lambda d: d.clear() or d.update({"answers": "nope"}), "missing_answers"),
    "no_answers": (lambda d: d.pop("answers"), "missing_answers"),
    "no_verdict": (lambda d: d["answers"].pop("verdict"), "missing_verdict"),
    "no_category": (lambda d: d["answers"].pop("has_personal_data"), "missing_category"),
    "no_manipulation": (lambda d: d["answers"].pop("manipulation"), "missing_manipulation"),
    "verdict_wrong_type": (lambda d: d["answers"]["verdict"].update(type="noul"), "wrong_type"),
    "category_wrong_type": (lambda d: d["answers"]["has_personal_data"].update(type="choice"), "wrong_type"),
    "manip_wrong_type": (lambda d: d["answers"]["manipulation"].update(type="score"), "wrong_type"),
    "answer_not_object": (lambda d: d["answers"].update(verdict=["public"]), "wrong_type"),
    "probabilities_not_object": (lambda d: d["answers"]["verdict"].update(probabilities=[0.9]), "wrong_type"),
    "unknown_choice": (lambda d: d["answers"]["verdict"].update(choice="totally_fine"), "unknown_choice"),
    "choice_not_string": (lambda d: d["answers"]["verdict"].update(choice=1), "unknown_choice"),
    "unknown_prob_key": (lambda d: d["answers"]["verdict"]["probabilities"].update(other=0.0), "unknown_choice"),
    "prob_string": (lambda d: d["answers"]["verdict"]["probabilities"].update(public="0.9"), "invalid_number"),
    "prob_bool": (lambda d: d["answers"]["verdict"]["probabilities"].update(public=True), "invalid_number"),
    "prob_null": (lambda d: d["answers"]["verdict"]["probabilities"].update(public=None), "invalid_number"),
    "prob_nan": (lambda d: d["answers"]["verdict"]["probabilities"].update(public=math.nan), "prob_out_of_range"),
    "prob_inf": (lambda d: d["answers"]["verdict"]["probabilities"].update(public=math.inf), "prob_out_of_range"),
    "prob_neg": (lambda d: d["answers"]["verdict"]["probabilities"].update(uncertain=-0.1), "prob_out_of_range"),
    "prob_gt1": (lambda d: d["answers"]["verdict"]["probabilities"].update(public=1.5), "prob_out_of_range"),
    "confidence_string": (lambda d: d["answers"]["verdict"].update(confidence="high"), "invalid_number"),
    "confidence_missing": (lambda d: d["answers"]["verdict"].pop("confidence"), "invalid_number"),
    "confidence_bool": (lambda d: d["answers"]["verdict"].update(confidence=False), "invalid_number"),
    "confidence_nan": (lambda d: d["answers"]["verdict"].update(confidence=math.nan), "prob_out_of_range"),
    "noul_string": (lambda d: d["answers"]["has_personal_data"].update(noul="no"), "invalid_number"),
    "noul_missing": (lambda d: d["answers"]["manipulation"].pop("noul"), "invalid_number"),
    "noul_gt1": (lambda d: d["answers"]["manipulation"].update(noul=2), "prob_out_of_range"),
    "noul_inf": (lambda d: d["answers"]["has_personal_data"].update(noul=-math.inf), "prob_out_of_range"),
    "sum_low": (lambda d: d["answers"]["verdict"]["probabilities"].update(public=0.5), "probabilities_not_normalized"),
    "sum_high": (lambda d: d["answers"]["verdict"]["probabilities"].update(personal_data=0.5), "probabilities_not_normalized"),
    "not_argmax": (
        lambda d: d["answers"]["verdict"]["probabilities"].update(public=0.1, uncertain=0.9),
        "choice_not_argmax",
    ),
}


@pytest.mark.parametrize("case", list(INVALID))
def test_invalid_shapes(policy, case):
    fn, code = INVALID[case]
    with pytest.raises(ClefError) as ei:
        parse_response(mutate(policy, fn), policy)
    assert ei.value.code == code


def test_top_level_not_object(policy):
    with pytest.raises(ClefError, match="missing_answers"):
        parse_response([1, 2], policy)


# ------------------------------------------------------------------ transport


@pytest.fixture
def client(clef_cfg, policy):
    return ClefClient(clef_cfg, policy)


async def test_classify_ok_sends_auth_and_body(client, clef_cfg, policy):
    with respx.mock(assert_all_called=True) as m:
        route = m.post(clef_cfg.url).respond(200, json=good_response(policy))
        r = await client.classify({"messages": [{"role": "user", "content": "hello"}]})
    assert r.choice == "public"
    req = route.calls.last.request
    assert req.headers["authorization"] == "Bearer clef-secret-value"
    sent = json.loads(req.content)
    assert sent["state"]["request"]["messages"][0]["content"] == "hello"
    assert set(sent["questions"]) == set(build_questions(policy))


@pytest.mark.parametrize(
    "side_effect,code",
    [
        (httpx.ReadTimeout("t"), "timeout"),
        (httpx.ConnectTimeout("t"), "timeout"),
        (httpx.ConnectError("refused"), "transport_error"),
        (httpx.RemoteProtocolError("bad"), "transport_error"),
    ],
)
async def test_transport_errors(client, clef_cfg, side_effect, code):
    with respx.mock() as m:
        m.post(clef_cfg.url).mock(side_effect=side_effect)
        with pytest.raises(ClefError) as ei:
            await client.classify({"messages": []})
    assert ei.value.code == code
    assert ei.value.metric_result == code


@pytest.mark.parametrize("status", [400, 404, 500, 503])
async def test_http_status(client, clef_cfg, status):
    with respx.mock() as m:
        m.post(clef_cfg.url).respond(status, json={"error": "x"})
        with pytest.raises(ClefError) as ei:
            await client.classify({})
    assert ei.value.code == f"http_{status}" and ei.value.metric_result == "http_error"


async def test_invalid_json(client, clef_cfg):
    with respx.mock() as m:
        m.post(clef_cfg.url).respond(200, content=b"<html>oops")
        with pytest.raises(ClefError) as ei:
            await client.classify({})
    assert ei.value.code == "invalid_json" and ei.value.metric_result == "invalid"


async def test_redirect_not_followed(client, clef_cfg):
    with respx.mock() as m:
        m.post(clef_cfg.url).respond(302, headers={"location": "https://evil.example/"})
        with pytest.raises(ClefError, match="http_302"):
            await client.classify({})


def test_client_ignores_env_proxies(clef_cfg, policy, monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.invalid:3128")
    c = ClefClient(clef_cfg, policy)
    assert c._client._trust_env is False


async def test_error_message_has_no_content(client, clef_cfg, policy):
    d = good_response(policy)
    d["answers"]["verdict"]["choice"] = "SECRET-CONTENT-MARK"
    with respx.mock() as m:
        m.post(clef_cfg.url).respond(200, json=d)
        with pytest.raises(ClefError) as ei:
            await client.classify({"messages": [{"role": "user", "content": "SECRET-CONTENT-MARK"}]})
    assert "SECRET" not in str(ei.value) and "SECRET" not in repr(ei.value)
