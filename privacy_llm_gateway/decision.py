"""Routing decision: a pure function with no I/O.

Public is the exception: it requires a valid classifier result and zero reasons.
Everything else (including anything unexpected) routes local.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from .config import PUBLIC, UNCERTAIN, Thresholds

Route = Literal["local", "public"]
Verdict = Literal["public", "sensitive", "uncertain"]


@dataclass(frozen=True)
class ClassifierResult:
    choice: str
    probabilities: dict[str, float]
    confidence: float
    category_probs: dict[str, float]  # sensitive category -> p(has_<category>)
    manipulation: float
    input_tokens: int | None = None


@dataclass(frozen=True)
class Decision:
    route: Route
    verdict: Verdict
    reasons: list[str] = field(default_factory=list)
    sticky: bool = False


def forced_local(reason: str, verdict: Verdict = "uncertain", sticky: bool = False) -> Decision:
    """Decision for paths that never reach decide() (session pin, store down, errors)."""
    return Decision("local", verdict, [reason], sticky)


def decide(
    *,
    detector_hits: list[str] = (),  # type: ignore[assignment]
    unsupported: list[str] = (),  # type: ignore[assignment]
    documents: list[str] = (),  # type: ignore[assignment]  # "pdf"/"text" per converted doc
    documents_allow_public: bool = False,
    too_large: bool = False,
    classifier_result: ClassifierResult | None = None,
    classifier_error: str | None = None,
    thresholds: Thresholds,
    sticky_on_uncertain: bool,
) -> Decision:
    reasons: list[str] = []
    sensitive = uncertain = sticky = False

    def add(reason: str) -> None:
        if reason not in reasons:
            reasons.append(reason)

    for rule in detector_hits:
        add(f"detector:{rule}")
        sensitive = sticky = True

    for flag in unsupported:
        add(f"unsupported:{flag}")
        uncertain = True
        sticky = sticky or sticky_on_uncertain

    if not documents_allow_public:
        for doc_type in documents:
            add(f"document_attached:{doc_type}")
            sensitive = sticky = True

    if too_large:
        add("too_large_for_classifier")
        uncertain = True

    if classifier_error is not None:
        add(f"classifier_error:{classifier_error}")
        uncertain = True

    if classifier_result is not None:
        r, t = classifier_result, thresholds
        if r.choice == UNCERTAIN:
            add("classifier_choice:uncertain")
            uncertain = True
            sticky = sticky or sticky_on_uncertain
        elif r.choice != PUBLIC:
            add(f"classifier_choice:{r.choice}")
            sensitive = sticky = True
        if r.probabilities.get(PUBLIC, 0.0) < t.public_min_prob:
            add("classifier_low_public_prob")
            uncertain = True
            sticky = sticky or sticky_on_uncertain
        if r.confidence < t.min_confidence:
            add("classifier_low_confidence")
            uncertain = True
            sticky = sticky or sticky_on_uncertain
        for category, p in r.category_probs.items():
            if p > t.category_max_prob:
                add(f"classifier_category:{category}")
                sensitive = sticky = True
        if r.manipulation > t.manipulation_max_prob:
            add("classifier_manipulation_score")
            sensitive = sticky = True
    elif not reasons:
        add("not_classified")  # defensive: should never happen
        uncertain = True

    if not reasons and classifier_result is not None and classifier_error is None:
        return Decision("public", "public", [], False)
    verdict: Verdict = "sensitive" if sensitive else "uncertain"
    return Decision("local", verdict, reasons, sticky)
