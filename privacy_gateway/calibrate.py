"""Score a labelled JSONL file through Clef and print a threshold sweep.

Input: one JSON object per line
  {"label": "public" | "sensitive", "text": "..."}            → sent as one user message
  {"label": "public" | "sensitive", "request": {...chat body}} → the full request
Optional "id" and "note" fields are echoed in --output (the text never is).

For each threshold setting the sweep reports
  leaked    sensitive examples that would be routed PUBLIC (must be 0)
  released  public examples that would be routed public (higher = more useful)
both for Clef alone and for the full pipeline (detectors first, then Clef).

Exit status: 0 when the CURRENT config leaks no sensitive example, 1 otherwise,
2 on input errors.
"""

from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass
from typing import Any

from .clef import ClefClient, ClefError, StateTooLarge
from .config import LoadedConfig, Thresholds
from .decision import ClefResult, decide
from .detectors import Detectors
from .extract import extract

SWEEP_PUBLIC_MIN_PROB = (0.5, 0.6, 0.7, 0.8, 0.85, 0.9, 0.95, 0.98, 0.99)
SWEEP_MIN_CONFIDENCE = (0.0, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9)
SWEEP_CATEGORY_MAX = (0.1, 0.2, 0.3, 0.4, 0.5)


@dataclass
class Scored:
    idx: int
    id: str
    label: str
    detector_hits: list[str]
    unsupported: list[str]
    too_large: bool
    result: ClefResult | None
    error: str | None


def _load(path: str) -> list[dict[str, Any]]:
    rows = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                row = json.loads(line)
            except ValueError:
                raise SystemExit(f"{path}:{n}: invalid JSON") from None
            if row.get("label") not in ("public", "sensitive"):
                raise SystemExit(f"{path}:{n}: label must be 'public' or 'sensitive'")
            if not isinstance(row.get("text"), str) and not isinstance(row.get("request"), dict):
                raise SystemExit(f"{path}:{n}: needs 'text' or 'request'")
            rows.append(row)
    if not rows:
        raise SystemExit(f"{path}: no examples")
    return rows


def _body(row: dict[str, Any]) -> dict[str, Any]:
    if isinstance(row.get("request"), dict):
        return {"model": "auto", **row["request"]}
    return {"model": "auto", "messages": [{"role": "user", "content": row["text"]}]}


async def score_all(loaded: LoadedConfig, rows: list[dict[str, Any]], concurrency: int) -> list[Scored]:
    cfg = loaded.config
    detectors = Detectors(cfg.policy.detectors)
    clef = ClefClient(cfg.clef, cfg.policy)
    sem = asyncio.Semaphore(max(1, concurrency))

    async def one(i: int, row: dict[str, Any]) -> Scored:
        ex = extract(_body(row), {}, cfg.policy.session.header)
        hits = await asyncio.to_thread(detectors.scan, ex.texts)
        result = error = None
        too_large = False
        try:
            async with sem:
                result = await clef.classify(ex.state)
        except StateTooLarge:
            too_large = True
        except ClefError as exc:
            error = exc.code
        return Scored(i, str(row.get("id", i)), row["label"], hits, ex.unsupported, too_large, result, error)

    try:
        return list(await asyncio.gather(*(one(i, r) for i, r in enumerate(rows))))
    finally:
        await clef.aclose()


def _route(s: Scored, t: Thresholds, with_detectors: bool, sticky_on_uncertain: bool) -> str:
    return decide(
        detector_hits=s.detector_hits if with_detectors else [],
        unsupported=s.unsupported,
        too_large=s.too_large,
        clef_result=s.result,
        clef_error=s.error,
        thresholds=t,
        sticky_on_uncertain=sticky_on_uncertain,
    ).route


def sweep_rows(scored: list[Scored], base: Thresholds, sticky: bool) -> list[tuple[str, Thresholds]]:
    settings: list[tuple[str, Thresholds]] = [("current config", base)]
    for p in SWEEP_PUBLIC_MIN_PROB:
        settings.append((f"public_min_prob={p}", base.model_copy(update={"public_min_prob": p})))
    for c in SWEEP_MIN_CONFIDENCE:
        settings.append((f"min_confidence={c}", base.model_copy(update={"min_confidence": c})))
    for m in SWEEP_CATEGORY_MAX:
        settings.append((f"category_max_prob={m}", base.model_copy(update={"category_max_prob": m})))
    return settings


def evaluate_setting(scored: list[Scored], t: Thresholds, with_detectors: bool, sticky: bool) -> tuple[int, int]:
    leaked = sum(1 for s in scored if s.label == "sensitive" and _route(s, t, with_detectors, sticky) == "public")
    released = sum(1 for s in scored if s.label == "public" and _route(s, t, with_detectors, sticky) == "public")
    return leaked, released


def report(scored: list[Scored], loaded: LoadedConfig, out=sys.stdout) -> int:
    pol = loaded.config.policy
    n_sens = sum(1 for s in scored if s.label == "sensitive")
    n_pub = len(scored) - n_sens
    errors = sum(1 for s in scored if s.error)
    print(f"examples: {len(scored)} ({n_sens} sensitive, {n_pub} public); clef errors: {errors}; "
          f"too large: {sum(s.too_large for s in scored)}", file=out)
    print(f"model: {loaded.config.clef.model}   config thresholds: {pol.thresholds.model_dump()}", file=out)
    print("", file=out)
    hdr = f"{'setting':<26} {'clef only: leaked':>18} {'released':>10}   {'pipeline: leaked':>17} {'released':>10}"
    print(hdr, file=out)
    print("-" * len(hdr), file=out)
    sticky = pol.session.sticky_on_uncertain
    current_leaks = 0
    for name, t in sweep_rows(scored, pol.thresholds, sticky):
        cl, cr = evaluate_setting(scored, t, False, sticky)
        pl, pr = evaluate_setting(scored, t, True, sticky)
        if name == "current config":
            current_leaks = pl
        flag = "  <-- LEAKS" if pl else ""
        print(f"{name:<26} {cl:>9}/{n_sens:<8} {cr:>4}/{n_pub:<5}   {pl:>8}/{n_sens:<8} {pr:>4}/{n_pub:<5}{flag}", file=out)
    print("", file=out)
    leaks = [s for s in scored if s.label == "sensitive"
             and _route(s, pol.thresholds, True, sticky) == "public"]
    if leaks:
        print("sensitive examples routed PUBLIC with the current config (ids):", ", ".join(s.id for s in leaks), file=out)
    print("leaked = sensitive → public (must be 0). released = public → public. "
          "Thresholds are not calibrated until this shows 0 leaks on a labelled set from YOUR traffic.", file=out)
    return 1 if current_leaks else 0


def write_scores(scored: list[Scored], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for s in scored:
            r = s.result
            f.write(json.dumps({
                "id": s.id, "label": s.label, "detectors": s.detector_hits, "error": s.error, "too_large": s.too_large,
                "choice": r.choice if r else None,
                "p_public": r.probabilities.get("public") if r else None,
                "confidence": r.confidence if r else None,
                "categories": r.category_probs if r else None,
                "manipulation": r.manipulation if r else None,
            }) + "\n")


def run(loaded: LoadedConfig, path: str, concurrency: int = 4, output: str | None = None) -> int:
    try:
        rows = _load(path)
    except SystemExit as exc:
        print(f"calibrate: {exc}", file=sys.stderr)
        return 2
    scored = asyncio.run(score_all(loaded, rows, concurrency))
    if output:
        write_scores(scored, output)
    return report(scored, loaded)
