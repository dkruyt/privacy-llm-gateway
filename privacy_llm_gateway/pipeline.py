"""evaluate(): extract → detectors → (short-circuit) → [prefix cache] → classifier → decide.

Runs entirely before any upstream connection is opened. The caller wraps it so
that ANY exception routes local (classifier_internal_error).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from . import metrics
from .classifier import ClassifierClient, ClassifierError, StateTooLarge
from .config import PolicyConfig
from .decision import ClassifierResult, Decision, decide
from .detectors import Detectors
from .extract import Extraction, extract
from .prefix_cache import chain, clearly_public
from .session import SessionStore, SessionStoreUnavailable


@dataclass
class PrefixContext:
    """Everything evaluate() needs for the prefix cache (policy.session.prefix_cache.enabled)."""

    store: SessionStore
    stamp_key: bytes
    session_key: str
    fingerprint: str
    margin: float
    ttl_seconds: int


@dataclass
class Evaluation:
    decision: Decision
    extraction: Extraction
    classifier_result: ClassifierResult | None = None
    classifier_error: str | None = None
    timings_ms: dict[str, float] = field(default_factory=dict)
    # Prefix cache only: "full" | "delta" | "delta_full" | "cached", and cached prefix length.
    classifier_mode: str | None = None
    prefix_messages: int = 0

    def classifier_scores(self) -> dict[str, Any] | None:
        """Scores for the decision log (numbers and category names only)."""
        scores = self._scores()
        if self.classifier_mode is not None:
            scores = {**(scores or {}), "mode": self.classifier_mode, "prefix_messages": self.prefix_messages}
        return scores

    def _scores(self) -> dict[str, Any] | None:
        r = self.classifier_result
        if r is None:
            return {"error": self.classifier_error} if self.classifier_error else None
        return {
            "choice": r.choice,
            "p_public": round(r.probabilities.get("public", 0.0), 4),
            "confidence": round(r.confidence, 4),
            "categories": {k: round(v, 4) for k, v in r.category_probs.items()},
            "manipulation": round(r.manipulation, 4),
            "input_tokens": r.input_tokens,
        }


def _observe_classifier(r: ClassifierResult) -> None:
    metrics.CLASSIFIER_P_PUBLIC.observe(r.probabilities.get("public", 0.0))
    metrics.CLASSIFIER_CONFIDENCE.observe(r.confidence)
    metrics.CLASSIFIER_CATEGORY_MAX.observe(max(r.category_probs.values(), default=0.0))
    metrics.CLASSIFIER_MANIPULATION.observe(r.manipulation)
    if r.input_tokens is not None:
        metrics.CLASSIFIER_INPUT_TOKENS.observe(r.input_tokens)


async def _call(
    classifier: ClassifierClient, payload: dict[str, Any], timings: dict[str, float]
) -> tuple[ClassifierResult | None, str | None]:
    """One classifier call: (result, None) or (None, error code). Adds to timings["classifier"]."""
    t = time.perf_counter()
    try:
        r = await classifier.send(payload)
        metrics.CLASSIFIER_CALLS.labels(result="ok").inc()
        _observe_classifier(r)
        return r, None
    except ClassifierError as exc:
        metrics.CLASSIFIER_CALLS.labels(result=exc.metric_result).inc()
        return None, exc.code
    finally:
        elapsed = time.perf_counter() - t
        metrics.CLASSIFIER_SECONDS.observe(elapsed)
        timings["classifier"] = timings.get("classifier", 0.0) + elapsed * 1000


async def _lookup(prefix: PrefixContext, state: dict[str, Any]) -> tuple[list[str] | None, int]:
    """(chain keys, cached prefix length). Keys None: cache not applicable or Redis failed."""
    keys = chain(prefix.stamp_key, prefix.fingerprint, prefix.session_key, state)
    if keys is None:
        return None, 0
    try:
        return keys, await prefix.store.longest_public_prefix(keys)
    except SessionStoreUnavailable:
        metrics.prefix_cache("unavailable")
        return None, 0


async def evaluate(
    *,
    body: Mapping[str, Any],
    headers: Mapping[str, str],
    policy: PolicyConfig,
    detectors: Detectors,
    classifier: ClassifierClient,
    documents: list[str],
    prefix: PrefixContext | None = None,
) -> Evaluation:
    """`body` is the request after document conversion (what will be forwarded)."""
    t0 = time.perf_counter()
    timings: dict[str, float] = {}
    ex = extract(body, headers, policy.session.header)

    t = time.perf_counter()
    hits = await asyncio.to_thread(detectors.scan, ex.texts)
    timings["detectors"] = (time.perf_counter() - t) * 1000

    docs_force_local = bool(documents) and not policy.documents.allow_public
    classifier_result: ClassifierResult | None = None
    classifier_error: str | None = None
    too_large = False
    keys: list[str] | None = None
    cached = 0
    mode: str | None = None
    run_full = cached_public = False

    if hits:
        metrics.classifier_skipped("detector")
    elif docs_force_local:
        metrics.classifier_skipped("document")
    elif ex.unsupported:
        metrics.classifier_skipped("unsupported")
    else:
        keys, cached = await _lookup(prefix, ex.state) if prefix else (None, 0)
        if keys is not None:
            mode = "full"
        if keys and cached == len(keys):
            # The identical request (same policy, session, fields, messages) was public.
            metrics.prefix_cache("hit_full")
            mode, cached_public = "cached", True
        elif keys and cached:
            mode = "delta"
            delta_result, classifier_error = await _delta(classifier, ex.state["messages"][cached:], timings)
            if delta_result is not None:
                if clearly_public(delta_result, policy.thresholds, prefix.margin):
                    metrics.prefix_cache("hit_delta")
                    classifier_result = delta_result
                elif _decide(delta_result, policy).verdict == "sensitive":
                    metrics.prefix_cache("delta_sensitive")
                    classifier_result = delta_result
                else:
                    metrics.prefix_cache("borderline")
                    mode = "delta_full"
                    run_full = True
            elif classifier_error is None:  # delta itself too large: let the full path decide
                metrics.prefix_cache("borderline")
                mode = "delta_full"
                run_full = True
        else:
            if keys is not None:
                metrics.prefix_cache("miss")
            run_full = True

        if run_full:
            try:
                payload, _ = classifier.payload(ex.state)  # never truncated
            except StateTooLarge:
                too_large = True
                metrics.classifier_skipped("too_large")
            else:
                classifier_result, classifier_error = await _call(classifier, payload, timings)

    if cached_public:
        decision = Decision("public", "public", [], False)
    else:
        decision = decide(
            detector_hits=hits,
            unsupported=ex.unsupported,
            documents=documents,
            documents_allow_public=policy.documents.allow_public,
            too_large=too_large,
            classifier_result=classifier_result,
            classifier_error=classifier_error,
            thresholds=policy.thresholds,
            sticky_on_uncertain=policy.session.sticky_on_uncertain,
        )
    if keys and decision.route == "public":
        ok = await prefix.store.mark_public_prefix(keys[-1], prefix.ttl_seconds)
        metrics.prefix_cache("stored" if ok else "store_failed")
    total = time.perf_counter() - t0
    metrics.CLASSIFICATION_SECONDS.observe(total)
    timings["classification"] = total * 1000
    return Evaluation(decision, ex, classifier_result, classifier_error, timings, mode, cached)


def _decide(r: ClassifierResult, policy: PolicyConfig) -> Decision:
    return decide(
        classifier_result=r, thresholds=policy.thresholds, sticky_on_uncertain=policy.session.sticky_on_uncertain
    )


async def _delta(
    classifier: ClassifierClient, messages: list[Any], timings: dict[str, float]
) -> tuple[ClassifierResult | None, str | None]:
    """Classify only the new messages. (None, None) when even the delta is too large."""
    try:
        payload, _ = classifier.payload({"messages": messages})
    except StateTooLarge:
        return None, None
    return await _call(classifier, payload, timings)
