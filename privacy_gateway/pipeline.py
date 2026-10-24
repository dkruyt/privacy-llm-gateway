"""evaluate(): extract → detectors → (short-circuit) → Clef → decide.

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
from .clef import ClefClient, ClefError, StateTooLarge
from .config import PolicyConfig
from .decision import ClefResult, Decision, decide
from .detectors import Detectors
from .extract import Extraction, extract


@dataclass
class Evaluation:
    decision: Decision
    extraction: Extraction
    clef_result: ClefResult | None = None
    clef_error: str | None = None
    timings_ms: dict[str, float] = field(default_factory=dict)

    def clef_scores(self) -> dict[str, Any] | None:
        """Scores for the decision log (numbers and category names only)."""
        r = self.clef_result
        if r is None:
            return {"error": self.clef_error} if self.clef_error else None
        return {
            "choice": r.choice,
            "p_public": round(r.probabilities.get("public", 0.0), 4),
            "confidence": round(r.confidence, 4),
            "categories": {k: round(v, 4) for k, v in r.category_probs.items()},
            "manipulation": round(r.manipulation, 4),
            "input_tokens": r.input_tokens,
        }


def _observe_clef(r: ClefResult) -> None:
    metrics.CLEF_P_PUBLIC.observe(r.probabilities.get("public", 0.0))
    metrics.CLEF_CONFIDENCE.observe(r.confidence)
    metrics.CLEF_CATEGORY_MAX.observe(max(r.category_probs.values(), default=0.0))
    metrics.CLEF_MANIPULATION.observe(r.manipulation)
    if r.input_tokens is not None:
        metrics.CLEF_INPUT_TOKENS.observe(r.input_tokens)


async def evaluate(
    *,
    body: Mapping[str, Any],
    headers: Mapping[str, str],
    policy: PolicyConfig,
    detectors: Detectors,
    clef: ClefClient,
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
    clef_result: ClefResult | None = None
    clef_error: str | None = None
    too_large = False

    if hits:
        metrics.clef_skipped("detector")
    elif docs_force_local:
        metrics.clef_skipped("document")
    elif ex.unsupported:
        metrics.clef_skipped("unsupported")
    else:
        try:
            payload, _ = clef.payload(ex.state)  # never truncated
        except StateTooLarge:
            too_large = True
            metrics.clef_skipped("too_large")
        else:
            t = time.perf_counter()
            try:
                clef_result = await clef.send(payload)
                metrics.CLEF_CALLS.labels(result="ok").inc()
                _observe_clef(clef_result)
            except ClefError as exc:
                clef_error = exc.code
                metrics.CLEF_CALLS.labels(result=exc.metric_result).inc()
            finally:
                elapsed = time.perf_counter() - t
                metrics.CLEF_SECONDS.observe(elapsed)
                timings["clef"] = elapsed * 1000

    decision = decide(
        detector_hits=hits,
        unsupported=ex.unsupported,
        documents=documents,
        documents_allow_public=policy.documents.allow_public,
        too_large=too_large,
        clef_result=clef_result,
        clef_error=clef_error,
        thresholds=policy.thresholds,
        sticky_on_uncertain=policy.session.sticky_on_uncertain,
    )
    total = time.perf_counter() - t0
    metrics.CLASSIFICATION_SECONDS.observe(total)
    timings["classification"] = total * 1000
    return Evaluation(decision, ex, clef_result, clef_error, timings)
