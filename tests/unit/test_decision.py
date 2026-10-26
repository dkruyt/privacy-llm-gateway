from __future__ import annotations

import itertools

import pytest

from privacy_llm_gateway.config import Thresholds
from privacy_llm_gateway.decision import ClassifierResult, Decision, decide, forced_local

T = Thresholds(public_min_prob=0.8, min_confidence=0.6, category_max_prob=0.3, manipulation_max_prob=0.3)
CATS = ["personal_data", "credentials_secrets"]


def classifier(choice="public", p_public=0.95, confidence=0.9, cats=None, manipulation=0.01):
    probs = {"public": p_public, "personal_data": 0.0, "uncertain": 0.0}
    rest = round(1 - p_public, 6)
    if choice == "public":
        probs["uncertain"] = rest
    else:
        probs[choice] = max(rest, p_public + 0.01)
        probs["public"] = p_public
    return ClassifierResult(
        choice=choice,
        probabilities=probs,
        confidence=confidence,
        category_probs=cats if cats is not None else {c: 0.01 for c in CATS},
        manipulation=manipulation,
        input_tokens=10,
    )


def run(sticky_on_uncertain=True, **kw):
    return decide(thresholds=T, sticky_on_uncertain=sticky_on_uncertain, **kw)


# ---------------------------------------------------------------- the one public row


def test_clean_classifier_result_is_public():
    assert run(classifier_result=classifier()) == Decision("public", "public", [], False)


def test_threshold_boundaries_are_inclusive_for_public():
    r = classifier(p_public=0.8, confidence=0.6, cats={c: 0.3 for c in CATS}, manipulation=0.3)
    assert run(classifier_result=r).route == "public"


# ---------------------------------------------------------------- each row of the table


@pytest.mark.parametrize("sou", [True, False])
def test_detector_hit(sou):
    d = run(sou, detector_hits=["email", "jwt"])
    assert d == Decision("local", "sensitive", ["detector:email", "detector:jwt"], True)


@pytest.mark.parametrize("sou", [True, False])
def test_unsupported(sou):
    d = run(sou, unsupported=["media:image"], classifier_result=classifier())
    assert d == Decision("local", "uncertain", ["unsupported:media:image"], sou)


@pytest.mark.parametrize("sou", [True, False])
def test_too_large_never_sticky(sou):
    assert run(sou, too_large=True) == Decision("local", "uncertain", ["too_large_for_classifier"], False)


@pytest.mark.parametrize("sou", [True, False])
def test_classifier_error_never_sticky(sou):
    assert run(sou, classifier_error="timeout") == Decision("local", "uncertain", ["classifier_error:timeout"], False)


@pytest.mark.parametrize("sou", [True, False])
def test_classifier_choice_uncertain(sou):
    r = classifier(choice="uncertain", p_public=0.3)
    d = run(sou, classifier_result=r)
    assert d.route == "local" and d.verdict == "uncertain" and d.sticky is sou
    assert d.reasons == ["classifier_choice:uncertain", "classifier_low_public_prob"]


@pytest.mark.parametrize("sou", [True, False])
def test_classifier_choice_sensitive_category(sou):
    r = classifier(choice="personal_data", p_public=0.1)
    d = run(sou, classifier_result=r)
    assert d.verdict == "sensitive" and d.sticky is True
    assert d.reasons == ["classifier_choice:personal_data", "classifier_low_public_prob"]


@pytest.mark.parametrize("sou", [True, False])
def test_low_public_prob(sou):
    d = run(sou, classifier_result=classifier(p_public=0.79))
    assert d == Decision("local", "uncertain", ["classifier_low_public_prob"], sou)


@pytest.mark.parametrize("sou", [True, False])
def test_low_confidence(sou):
    d = run(sou, classifier_result=classifier(confidence=0.59))
    assert d == Decision("local", "uncertain", ["classifier_low_confidence"], sou)


@pytest.mark.parametrize("sou", [True, False])
def test_single_high_category(sou):
    d = run(sou, classifier_result=classifier(cats={"personal_data": 0.31, "credentials_secrets": 0.0}))
    assert d == Decision("local", "sensitive", ["classifier_category:personal_data"], True)


@pytest.mark.parametrize("sou", [True, False])
def test_manipulation(sou):
    d = run(sou, classifier_result=classifier(manipulation=0.31))
    assert d == Decision("local", "sensitive", ["classifier_manipulation_score"], True)


def test_not_classified_defensive():
    assert run() == Decision("local", "uncertain", ["not_classified"], False)


def test_document_forces_local_and_pin():
    d = run(documents=["pdf", "text"], classifier_result=classifier())
    assert d == Decision("local", "sensitive", ["document_attached:pdf", "document_attached:text"], True)


def test_document_allowed_public_continues_classification():
    assert run(documents=["pdf"], documents_allow_public=True, classifier_result=classifier()).route == "public"


def test_missing_public_probability_is_low():
    r = ClassifierResult("public", {"uncertain": 1.0}, 0.9, {}, 0.0)
    assert run(classifier_result=r).reasons == ["classifier_low_public_prob"]


def test_classifier_error_and_result_never_public():
    d = run(classifier_error="invalid_json", classifier_result=classifier())
    assert d.route == "local" and d.reasons == ["classifier_error:invalid_json"]


def test_forced_local():
    assert forced_local("session_sticky", "sensitive", True) == Decision(
        "local", "sensitive", ["session_sticky"], True
    )
    assert forced_local("classifier_internal_error") == Decision(
        "local", "uncertain", ["classifier_internal_error"], False
    )


# ---------------------------------------------------------------- combinations

SIGNALS = {
    "detector": dict(detector_hits=["email"]),
    "unsupported": dict(unsupported=["data_url"]),
    "too_large": dict(too_large=True),
    "classifier_error": dict(classifier_error="http_500"),
    "document": dict(documents=["pdf"]),
}
CLASSIFIER_VARIANTS = {
    "none": None,
    "clean": classifier(),
    "uncertain": classifier(choice="uncertain", p_public=0.2),
    "sensitive": classifier(choice="personal_data", p_public=0.2),
    "low_p": classifier(p_public=0.5),
    "low_conf": classifier(confidence=0.1),
    "category": classifier(cats={"personal_data": 0.9}),
    "manip": classifier(manipulation=0.9),
}
SENSITIVE_SIGNALS = {"detector", "document"}
SENSITIVE_CLASSIFIER = {"sensitive", "category", "manip"}
STICKY_ON_UNCERTAIN_SIGNALS = {"unsupported"}
STICKY_ON_UNCERTAIN_CLASSIFIER = {"uncertain", "low_p", "low_conf"}


@pytest.mark.parametrize("sou", [True, False])
@pytest.mark.parametrize("classifier_key", list(CLASSIFIER_VARIANTS))
@pytest.mark.parametrize(
    "signals",
    [c for n in range(0, len(SIGNALS) + 1) for c in itertools.combinations(SIGNALS, n)],
    ids=lambda c: "+".join(c) or "none",
)
def test_combinations(signals, classifier_key, sou):
    kw = {}
    for s in signals:
        kw.update(SIGNALS[s])
    d = run(sou, classifier_result=CLASSIFIER_VARIANTS[classifier_key], **kw)

    expect_public = not signals and classifier_key == "clean"
    assert (d.route == "public") is expect_public
    if expect_public:
        assert d.verdict == "public" and d.reasons == [] and d.sticky is False
        return

    # classifier_error is passed alongside a result here; the result is still evaluated.
    sensitive = bool(set(signals) & SENSITIVE_SIGNALS) or classifier_key in SENSITIVE_CLASSIFIER
    assert d.verdict == ("sensitive" if sensitive else "uncertain")
    assert d.reasons, "a local decision always carries a reason"

    sticky = sensitive or (
        sou
        and (bool(set(signals) & STICKY_ON_UNCERTAIN_SIGNALS) or classifier_key in STICKY_ON_UNCERTAIN_CLASSIFIER)
    )
    assert d.sticky is sticky


def test_duplicate_signals_are_deduplicated():
    d = run(detector_hits=["email", "email"], documents=["pdf", "pdf"])
    assert d.reasons == ["detector:email", "document_attached:pdf"]
