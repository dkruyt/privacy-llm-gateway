from __future__ import annotations

import itertools

import pytest

from privacy_gateway.config import Thresholds
from privacy_gateway.decision import ClefResult, Decision, decide, forced_local

T = Thresholds(public_min_prob=0.8, min_confidence=0.6, category_max_prob=0.3, manipulation_max_prob=0.3)
CATS = ["personal_data", "credentials_secrets"]


def clef(choice="public", p_public=0.95, confidence=0.9, cats=None, manipulation=0.01):
    probs = {"public": p_public, "personal_data": 0.0, "uncertain": 0.0}
    rest = round(1 - p_public, 6)
    if choice == "public":
        probs["uncertain"] = rest
    else:
        probs[choice] = max(rest, p_public + 0.01)
        probs["public"] = p_public
    return ClefResult(
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


def test_clean_clef_result_is_public():
    assert run(clef_result=clef()) == Decision("public", "public", [], False)


def test_threshold_boundaries_are_inclusive_for_public():
    r = clef(p_public=0.8, confidence=0.6, cats={c: 0.3 for c in CATS}, manipulation=0.3)
    assert run(clef_result=r).route == "public"


# ---------------------------------------------------------------- each row of the table


@pytest.mark.parametrize("sou", [True, False])
def test_detector_hit(sou):
    d = run(sou, detector_hits=["email", "jwt"])
    assert d == Decision("local", "sensitive", ["detector:email", "detector:jwt"], True)


@pytest.mark.parametrize("sou", [True, False])
def test_unsupported(sou):
    d = run(sou, unsupported=["media:image"], clef_result=clef())
    assert d == Decision("local", "uncertain", ["unsupported:media:image"], sou)


@pytest.mark.parametrize("sou", [True, False])
def test_too_large_never_sticky(sou):
    assert run(sou, too_large=True) == Decision("local", "uncertain", ["too_large_for_classifier"], False)


@pytest.mark.parametrize("sou", [True, False])
def test_clef_error_never_sticky(sou):
    assert run(sou, clef_error="timeout") == Decision("local", "uncertain", ["clef_error:timeout"], False)


@pytest.mark.parametrize("sou", [True, False])
def test_clef_choice_uncertain(sou):
    r = clef(choice="uncertain", p_public=0.3)
    d = run(sou, clef_result=r)
    assert d.route == "local" and d.verdict == "uncertain" and d.sticky is sou
    assert d.reasons == ["clef_choice:uncertain", "clef_low_public_prob"]


@pytest.mark.parametrize("sou", [True, False])
def test_clef_choice_sensitive_category(sou):
    r = clef(choice="personal_data", p_public=0.1)
    d = run(sou, clef_result=r)
    assert d.verdict == "sensitive" and d.sticky is True
    assert d.reasons == ["clef_choice:personal_data", "clef_low_public_prob"]


@pytest.mark.parametrize("sou", [True, False])
def test_low_public_prob(sou):
    d = run(sou, clef_result=clef(p_public=0.79))
    assert d == Decision("local", "uncertain", ["clef_low_public_prob"], sou)


@pytest.mark.parametrize("sou", [True, False])
def test_low_confidence(sou):
    d = run(sou, clef_result=clef(confidence=0.59))
    assert d == Decision("local", "uncertain", ["clef_low_confidence"], sou)


@pytest.mark.parametrize("sou", [True, False])
def test_single_high_category(sou):
    d = run(sou, clef_result=clef(cats={"personal_data": 0.31, "credentials_secrets": 0.0}))
    assert d == Decision("local", "sensitive", ["clef_category:personal_data"], True)


@pytest.mark.parametrize("sou", [True, False])
def test_manipulation(sou):
    d = run(sou, clef_result=clef(manipulation=0.31))
    assert d == Decision("local", "sensitive", ["clef_manipulation"], True)


def test_not_classified_defensive():
    assert run() == Decision("local", "uncertain", ["not_classified"], False)


def test_document_forces_local_and_pin():
    d = run(documents=["pdf", "text"], clef_result=clef())
    assert d == Decision("local", "sensitive", ["document_attached:pdf", "document_attached:text"], True)


def test_document_allowed_public_continues_classification():
    assert run(documents=["pdf"], documents_allow_public=True, clef_result=clef()).route == "public"


def test_missing_public_probability_is_low():
    r = ClefResult("public", {"uncertain": 1.0}, 0.9, {}, 0.0)
    assert run(clef_result=r).reasons == ["clef_low_public_prob"]


def test_clef_error_and_result_never_public():
    d = run(clef_error="invalid_json", clef_result=clef())
    assert d.route == "local" and d.reasons == ["clef_error:invalid_json"]


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
    "clef_error": dict(clef_error="http_500"),
    "document": dict(documents=["pdf"]),
}
CLEF_VARIANTS = {
    "none": None,
    "clean": clef(),
    "uncertain": clef(choice="uncertain", p_public=0.2),
    "sensitive": clef(choice="personal_data", p_public=0.2),
    "low_p": clef(p_public=0.5),
    "low_conf": clef(confidence=0.1),
    "category": clef(cats={"personal_data": 0.9}),
    "manip": clef(manipulation=0.9),
}
SENSITIVE_SIGNALS = {"detector", "document"}
SENSITIVE_CLEF = {"sensitive", "category", "manip"}
STICKY_ON_UNCERTAIN_SIGNALS = {"unsupported"}
STICKY_ON_UNCERTAIN_CLEF = {"uncertain", "low_p", "low_conf"}


@pytest.mark.parametrize("sou", [True, False])
@pytest.mark.parametrize("clef_key", list(CLEF_VARIANTS))
@pytest.mark.parametrize(
    "signals",
    [c for n in range(0, len(SIGNALS) + 1) for c in itertools.combinations(SIGNALS, n)],
    ids=lambda c: "+".join(c) or "none",
)
def test_combinations(signals, clef_key, sou):
    kw = {}
    for s in signals:
        kw.update(SIGNALS[s])
    d = run(sou, clef_result=CLEF_VARIANTS[clef_key], **kw)

    expect_public = not signals and clef_key == "clean"
    assert (d.route == "public") is expect_public
    if expect_public:
        assert d.verdict == "public" and d.reasons == [] and d.sticky is False
        return

    # clef_error is passed alongside a result here; the result is still evaluated.
    sensitive = bool(set(signals) & SENSITIVE_SIGNALS) or clef_key in SENSITIVE_CLEF
    assert d.verdict == ("sensitive" if sensitive else "uncertain")
    assert d.reasons, "a local decision always carries a reason"

    sticky = sensitive or (
        sou
        and (bool(set(signals) & STICKY_ON_UNCERTAIN_SIGNALS) or clef_key in STICKY_ON_UNCERTAIN_CLEF)
    )
    assert d.sticky is sticky


def test_duplicate_signals_are_deduplicated():
    d = run(detector_hits=["email", "email"], documents=["pdf", "pdf"])
    assert d.reasons == ["detector:email", "document_attached:pdf"]
