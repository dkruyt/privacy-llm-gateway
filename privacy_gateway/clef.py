"""Clef (TypeSafe-compatible decision model) client: POST /v1/systemone.

Builds the question set from the policy, sends the complete request state and
validates the response strictly. Any deviation raises ClefError(code); the
caller routes local without pinning.
"""

from __future__ import annotations

import json
import math
from typing import Any

import httpx

from .config import ClefConfig, PolicyConfig
from .decision import ClefResult

NORMALISATION_TOLERANCE = 0.02

# Fixed set of error codes (reason clef_error:<code>), plus http_<status>.
ERROR_CODES = (
    "timeout",
    "transport_error",
    "invalid_json",
    "missing_answers",
    "missing_verdict",
    "missing_category",
    "missing_manipulation",
    "unknown_choice",
    "invalid_number",
    "prob_out_of_range",
    "probabilities_not_normalized",
    "choice_not_argmax",
    "wrong_type",
)


class ClefError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code

    @property
    def metric_result(self) -> str:
        if self.code == "timeout":
            return "timeout"
        if self.code == "transport_error":
            return "transport_error"
        if self.code.startswith("http_"):
            return "http_error"
        return "invalid"


class StateTooLarge(Exception):
    """The compact-JSON state exceeds clef.max_state_chars. Never truncated."""


def build_questions(policy: PolicyConfig) -> dict[str, Any]:
    questions: dict[str, Any] = {
        "verdict": {
            "type": "choice",
            "instructions": policy.verdict_instructions,
            "criteria": {name: cat.description for name, cat in policy.categories.items()},
        }
    }
    for name in policy.sensitive_categories:
        questions[f"has_{name}"] = {"type": "noul", "instructions": policy.categories[name].question}
    questions["manipulation"] = {"type": "noul", "instructions": policy.manipulation_instructions}
    return questions


def build_state(policy: PolicyConfig, request_state: dict[str, Any]) -> dict[str, Any]:
    return {"notice": policy.state_notice, "request": request_state}


def compact_json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _number(v: Any) -> float:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise ClefError("invalid_number")
    f = float(v)
    if not math.isfinite(f) or f < 0.0 or f > 1.0:
        raise ClefError("prob_out_of_range")
    return f


def _answer(answers: dict[str, Any], key: str, missing_code: str, type_: str) -> dict[str, Any]:
    a = answers.get(key)
    if a is None:
        raise ClefError(missing_code)
    if not isinstance(a, dict) or a.get("type") != type_:
        raise ClefError("wrong_type")
    return a


def parse_response(data: Any, policy: PolicyConfig) -> ClefResult:
    """Strictly validate a /v1/systemone response body (already JSON-decoded)."""
    if not isinstance(data, dict) or not isinstance(data.get("answers"), dict):
        raise ClefError("missing_answers")
    answers = data["answers"]
    categories = set(policy.categories)

    verdict = _answer(answers, "verdict", "missing_verdict", "choice")
    raw_categories = {
        name: _answer(answers, f"has_{name}", "missing_category", "noul").get("noul")
        for name in policy.sensitive_categories
    }
    manip = _answer(answers, "manipulation", "missing_manipulation", "noul")

    choice = verdict.get("choice")
    probs = verdict.get("probabilities")
    if not isinstance(probs, dict):
        raise ClefError("wrong_type")
    if not isinstance(choice, str) or choice not in categories:
        raise ClefError("unknown_choice")
    if any(not isinstance(k, str) or k not in categories for k in probs):
        raise ClefError("unknown_choice")

    probabilities = {k: _number(v) for k, v in probs.items()}
    confidence = _number(verdict.get("confidence"))
    category_probs = {k: _number(v) for k, v in raw_categories.items()}
    manipulation = _number(manip.get("noul"))

    if abs(sum(probabilities.values()) - 1.0) > NORMALISATION_TOLERANCE:
        raise ClefError("probabilities_not_normalized")
    if probabilities.get(choice, 0.0) < max(probabilities.values()):
        raise ClefError("choice_not_argmax")

    usage = data.get("usage")
    input_tokens = None
    if isinstance(usage, dict):
        it = usage.get("input_tokens")
        if isinstance(it, int) and not isinstance(it, bool) and it >= 0:
            input_tokens = it

    return ClefResult(
        choice=choice,
        probabilities=probabilities,
        confidence=confidence,
        category_probs=category_probs,
        manipulation=manipulation,
        input_tokens=input_tokens,
    )


class ClefClient:
    """One instance per config generation. Rebuilt (and the old one closed) on reload."""

    def __init__(self, cfg: ClefConfig, policy: PolicyConfig, transport: httpx.AsyncBaseTransport | None = None):
        self._cfg = cfg
        self._policy = policy
        self._questions = build_questions(policy)
        headers = {"content-type": "application/json"}
        if cfg.api_key:
            headers["authorization"] = f"Bearer {cfg.api_key}"
        self._client = httpx.AsyncClient(
            trust_env=False,
            timeout=httpx.Timeout(cfg.timeout_s),
            headers=headers,
            follow_redirects=False,
            transport=transport,
        )

    @property
    def questions(self) -> dict[str, Any]:
        return self._questions

    def payload(self, request_state: dict[str, Any]) -> tuple[dict[str, Any], int]:
        """The request body and the compact-JSON state length. Raises StateTooLarge."""
        state = build_state(self._policy, request_state)
        size = len(compact_json(state))
        if size > self._cfg.max_state_chars:
            raise StateTooLarge()
        return {"model": self._cfg.model, "state": state, "questions": self._questions}, size

    async def classify(self, request_state: dict[str, Any]) -> ClefResult:
        body, _ = self.payload(request_state)
        try:
            resp = await self._client.post(self._cfg.url, content=compact_json(body).encode("utf-8"))
        except httpx.TimeoutException:
            raise ClefError("timeout") from None
        except httpx.HTTPError:
            raise ClefError("transport_error") from None
        if resp.status_code != 200:
            raise ClefError(f"http_{resp.status_code}")
        try:
            data = resp.json()
        except (ValueError, UnicodeDecodeError):
            raise ClefError("invalid_json") from None
        return parse_response(data, self._policy)

    async def probe(self) -> bool:
        """Liveness probe for privacy_up{dependency="clef"}: a tiny, content-free request."""
        body = {
            "model": self._cfg.model,
            "state": "ping",
            "questions": {"ok": {"type": "noul", "instructions": "Is this a ping?"}},
        }
        try:
            resp = await self._client.post(self._cfg.url, content=compact_json(body).encode())
            return resp.status_code == 200 and isinstance(resp.json().get("answers"), dict)
        except Exception:  # noqa: BLE001
            return False

    async def aclose(self) -> None:
        await self._client.aclose()
