"""evaluate(): extract → detectors → (short-circuit) → classifier → decide.

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


@dataclass
class Evaluation:
    decision: Decision
    extraction: Extraction
    classifier_result: ClassifierResult | None = None
    classifier_error: str | None = None
    timings_ms: dict[str, float] = field(default_factory=dict)

    def classifier_scores(self) -> dict[str, Any] | None:
        """Scores for the decision log (numbers and category names only)."""
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


async def evaluate(
    *,
    body: Mapping[str, Any],
    headers: Mapping[str, str],
    policy: PolicyConfig,
    detectors: Detectors,
    classifier: ClassifierClient,
    documents: list[str],
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

    if hits:
        metrics.classifier_skipped("detector")
    elif docs_force_local:
        metrics.classifier_skipped("document")
    elif ex.unsupported:
        metrics.classifier_skipped("unsupported")
    else:
        try:
            payload, _ = classifier.payload(ex.state)  # never truncated
        except StateTooLarge:
            too_large = True
            metrics.classifier_skipped("too_large")
        else:
            t = time.perf_counter()
            try:
                classifier_result = await classifier.send(payload)
                metrics.CLASSIFIER_CALLS.labels(result="ok").inc()
                _observe_classifier(classifier_result)
            except ClassifierError as exc:
                classifier_error = exc.code
                metrics.CLASSIFIER_CALLS.labels(result=exc.metric_result).inc()
            finally:
                elapsed = time.perf_counter() - t
                metrics.CLASSIFIER_SECONDS.observe(elapsed)
                timings["classifier"] = elapsed * 1000

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
    total = time.perf_counter() - t0
    metrics.CLASSIFICATION_SECONDS.observe(total)
    timings["classification"] = total * 1000
    return Evaluation(decision, ex, classifier_result, classifier_error, timings)
