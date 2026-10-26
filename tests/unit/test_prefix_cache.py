from __future__ import annotations

import json

import httpx
import pytest
import respx

from privacy_llm_gateway import metrics
from privacy_llm_gateway.classifier import ClassifierClient
from privacy_llm_gateway.config import RedisConfig, Thresholds
from privacy_llm_gateway.decision import ClassifierResult
from privacy_llm_gateway.detectors import Detectors
from privacy_llm_gateway.pipeline import PrefixContext, evaluate
from privacy_llm_gateway.prefix_cache import KEY_PREFIX, chain, clearly_public, fingerprint
from privacy_llm_gateway.session import SessionStore
from tests.fakes import FakeRedis
from tests.unit.test_classifier import good_response

KEY = b"k" * 32
FP = "fp"


def msgs(*texts):
    roles = ("user", "assistant")
    return [{"role": roles[i % 2], "content": t} for i, t in enumerate(texts)]


# ------------------------------------------------------------------ chain


def test_chain_one_key_per_message_and_stable():
    state = {"messages": msgs("a", "b", "c"), "temperature": 0.2}
    keys = chain(KEY, FP, "s", state)
    assert len(keys) == 3 and all(k.startswith(KEY_PREFIX) for k in keys)
    assert chain(KEY, FP, "s", {"temperature": 0.2, "messages": msgs("a", "b", "c")}) == keys
    # a longer conversation shares the prefix keys
    assert chain(KEY, FP, "s", {"messages": msgs("a", "b", "c", "d"), "temperature": 0.2})[:3] == keys


@pytest.mark.parametrize(
    "change",
    [
        lambda: (KEY, FP, "s", {"messages": msgs("X", "b"), "temperature": 0.2}),  # earlier message
        lambda: (KEY, FP, "s", {"messages": msgs("a", "b"), "temperature": 0.3}),  # other field
        lambda: (KEY, FP, "s", {"messages": msgs("a", "b"), "temperature": 0.2, "tools": []}),
        lambda: (KEY, "fp2", "s", {"messages": msgs("a", "b"), "temperature": 0.2}),  # policy
        lambda: (KEY, FP, "s2", {"messages": msgs("a", "b"), "temperature": 0.2}),  # session
        lambda: (b"x" * 32, FP, "s", {"messages": msgs("a", "b"), "temperature": 0.2}),  # hmac key
    ],
)
def test_chain_changes(change):
    base = chain(KEY, FP, "s", {"messages": msgs("a", "b"), "temperature": 0.2})
    assert chain(*change())[-1] != base[-1]


def test_chain_not_applicable():
    assert chain(KEY, FP, "s", {"prompt": "hi"}) is None
    assert chain(KEY, FP, "s", {"messages": []}) is None


def test_fingerprint_follows_policy():
    t = Thresholds()
    q = {"verdict": {}}
    a = fingerprint("m", q, "n", t, 0.1)
    assert a == fingerprint("m", q, "n", t, 0.1)
    assert a != fingerprint("m2", q, "n", t, 0.1)
    assert a != fingerprint("m", q, "n", t, 0.2)
    assert a != fingerprint("m", q, "n", Thresholds(public_min_prob=0.9), 0.1)


def _result(p_public=0.95, conf=0.9, cat=0.0, manip=0.0, choice="public"):
    return ClassifierResult(choice, {"public": p_public}, conf, {"personal_data": cat}, manip)


@pytest.mark.parametrize(
    "r,expected",
    [
        (_result(), True),
        (_result(p_public=0.90), True),  # exactly 0.80 + 0.10
        (_result(p_public=0.89), False),
        (_result(conf=0.69), False),
        (_result(cat=0.21), False),
        (_result(manip=0.21), False),
        (_result(choice="uncertain"), False),
    ],
)
def test_clearly_public(r, expected):
    assert clearly_public(r, Thresholds(), 0.10) is expected


# ------------------------------------------------------------------ session store


async def test_store_longest_prefix():
    fake = FakeRedis()
    store = SessionStore(RedisConfig(), 60, client=fake)
    assert await store.longest_public_prefix(["a", "b", "c"]) == 0
    await store.mark_public_prefix("b", 120)
    assert fake.data["b"][0] == "public"
    assert await store.longest_public_prefix(["a", "b", "c"]) == 2
    fake.data["c"] = ("sensitive", None)  # never mistaken for a public prefix
    assert await store.longest_public_prefix(["a", "b", "c"]) == 2


# ------------------------------------------------------------------ pipeline


@pytest.fixture
def env(loaded):
    cfg = loaded.config
    fake = FakeRedis()
    store = SessionStore(cfg.redis, 60, client=fake)
    prefix = PrefixContext(store=store, stamp_key=KEY, session_key="sess", fingerprint=FP, margin=0.1, ttl_seconds=600)
    return cfg, Detectors(cfg.policy.detectors), ClassifierClient(cfg.classifier, cfg.policy), prefix, fake


def response(policy, p_public=0.95, choice="public", cat=0.05):
    r = good_response(policy, choice=choice)
    probs = {c: 0.0 for c in policy.categories}
    probs[choice] = p_public
    probs["uncertain" if choice != "uncertain" else "public"] = round(1 - p_public, 4)
    r["answers"]["verdict"]["probabilities"] = probs
    r["answers"]["verdict"]["confidence"] = 0.9
    for c in policy.sensitive_categories:
        r["answers"][f"has_{c}"]["noul"] = cat
    return r


async def turn(env, messages, *responses, classifier=None, prefix="default"):
    cfg, det, clf, pc, _ = env
    with respx.mock(assert_all_mocked=True, assert_all_called=False) as m:
        route = m.post(cfg.classifier.url)
        route.side_effect = [httpx.Response(200, json=r) for r in responses] or [httpx.Response(500)]
        ev = await evaluate(
            body={"model": "auto", "messages": messages}, headers={}, policy=cfg.policy, detectors=det,
            classifier=classifier or clf, documents=[], prefix=pc if prefix == "default" else prefix,
        )
    sent = [json.loads(c.request.content)["state"]["request"] for c in route.calls]
    return ev, sent


async def test_miss_then_delta_then_full_hit(env):
    cfg = env[0]
    pol = cfg.policy
    ev, sent = await turn(env, msgs("capital of France?"), response(pol))
    assert ev.decision.route == "public" and len(sent) == 1
    assert ev.classifier_scores()["mode"] == "full" and ev.classifier_scores()["prefix_messages"] == 0

    conv = msgs("capital of France?", "Paris.", "and of Spain?")
    ev, sent = await turn(env, conv, response(pol))
    assert ev.decision.route == "public"
    assert sent == [{"messages": conv[1:]}]  # only the new messages
    assert ev.classifier_scores()["mode"] == "delta" and ev.prefix_messages == 1

    ev, sent = await turn(env, conv)  # regenerate: identical request
    assert ev.decision.route == "public" and sent == []
    assert ev.classifier_scores() == {"mode": "cached", "prefix_messages": 3}


async def test_borderline_delta_runs_full(env):
    pol = env[0].policy
    await turn(env, msgs("hello"), response(pol))
    conv = msgs("hello", "hi!", "tell me more")
    ev, sent = await turn(env, conv, response(pol, p_public=0.85), response(pol, p_public=0.95))
    assert len(sent) == 2 and sent[0] == {"messages": conv[1:]} and sent[1]["messages"] == conv
    assert ev.decision.route == "public" and ev.classifier_mode == "delta_full"


async def test_borderline_delta_full_decides_local(env):
    pol = env[0].policy
    await turn(env, msgs("hello"), response(pol))
    ev, sent = await turn(env, msgs("hello", "hi!", "x"), response(pol, p_public=0.85), response(pol, p_public=0.5))
    assert len(sent) == 2 and ev.decision.route == "local"
    assert "classifier_low_public_prob" in ev.decision.reasons


async def test_sensitive_delta_local_and_sticky_one_call(env):
    pol = env[0].policy
    await turn(env, msgs("hello"), response(pol))
    ev, sent = await turn(env, msgs("hello", "hi!", "x"), response(pol, choice="personal_data", cat=0.9))
    assert len(sent) == 1 and ev.decision.route == "local" and ev.decision.sticky
    assert ev.decision.verdict == "sensitive"


async def test_delta_classifier_error_local(env):
    pol = env[0].policy
    await turn(env, msgs("hello"), response(pol))
    ev, sent = await turn(env, msgs("hello", "hi!", "x"))  # classifier returns 500
    assert len(sent) == 1 and ev.decision.reasons == ["classifier_error:http_500"] and not ev.decision.sticky


async def test_local_decision_not_cached(env):
    pol = env[0].policy
    ev, _ = await turn(env, msgs("hello"), response(pol, p_public=0.5))
    assert ev.decision.route == "local"
    assert not any(k.startswith(KEY_PREFIX) for k in env[4].data)
    _, sent = await turn(env, msgs("hello", "hi", "x"), response(pol))
    assert sent[0]["messages"] == msgs("hello", "hi", "x")  # full classification


async def test_detector_hit_in_old_message_still_local(env):
    pol = env[0].policy
    await turn(env, msgs("hello"), response(pol))
    # a client rewriting history: different prefix anyway, and detectors scan everything
    ev, sent = await turn(env, msgs("mail jan@example.com", "ok", "x"), response(pol))
    assert sent == [] and ev.decision.reasons == ["detector:email"]


async def test_redis_down_falls_back_to_full(env):
    pol = env[0].policy
    await turn(env, msgs("hello"), response(pol))
    env[4].down = True
    before = metrics.PREFIX_CACHE.labels(result="unavailable")._value.get()
    ev, sent = await turn(env, msgs("hello", "hi", "x"), response(pol))
    assert ev.decision.route == "public" and sent[0]["messages"] == msgs("hello", "hi", "x")
    assert ev.classifier_mode is None
    assert metrics.PREFIX_CACHE.labels(result="unavailable")._value.get() == before + 1


async def test_disabled_unchanged(env):
    pol = env[0].policy
    ev, sent = await turn(env, msgs("hello"), response(pol), prefix=None)
    assert ev.decision.route == "public" and "mode" not in ev.classifier_scores()
    assert env[4].data == {}


async def test_too_large_conversation_classified_by_delta(env):
    cfg = env[0]
    small = ClassifierClient(cfg.classifier.model_copy(update={"max_state_chars": 3000}), cfg.policy)
    pol = cfg.policy
    first = msgs("word " * 300)
    await turn(env, first, response(pol), classifier=small)
    second = first + [{"role": "assistant", "content": "ok"}, {"role": "user", "content": "next?"}]
    ev, sent = await turn(env, second, response(pol), classifier=small)
    assert ev.decision.route == "public" and len(sent) == 1 and len(sent[0]["messages"]) == 2

    # borderline delta → full is too large → local
    long = second + [{"role": "assistant", "content": "sure " * 300}, {"role": "user", "content": "more"}]
    ev, sent = await turn(env, long, response(pol, p_public=0.85), classifier=small)
    assert len(sent) == 1 and ev.decision.reasons == ["too_large_for_classifier"]
