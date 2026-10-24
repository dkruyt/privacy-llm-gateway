from __future__ import annotations

import io
import json

import respx

from privacy_gateway.calibrate import _load, report, run, score_all
from tests.unit.test_clef import good_response


def write_rows(tmp_path, rows):
    p = tmp_path / "ex.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n")
    return p


ROWS = [
    {"id": "p1", "label": "public", "text": "What is the capital of France?"},
    {"id": "s1", "label": "sensitive", "text": "Patient notes about a named person"},
    {"id": "s2", "label": "sensitive", "text": "mail jan@example.com"},
    {"id": "s3", "label": "sensitive", "request": {"messages": [{"role": "user", "content": "x"}]}},
]


async def test_score_and_report_leak(loaded, tmp_path):
    rows = _load(str(write_rows(tmp_path, ROWS)))
    with respx.mock() as m:
        m.post(loaded.config.clef.url).respond(200, json=good_response(loaded.config.policy))  # Clef says public
        scored = await score_all(loaded, rows, 2)
    assert {s.id: s.detector_hits for s in scored}["s2"] == ["email"]
    out = io.StringIO()
    assert report(scored, loaded, out) == 1  # s1 and s3 leak with this (bad) classifier
    text = out.getvalue()
    assert "LEAKS" in text and "s1" in text and "s3" in text and "s2" not in text.split("(ids):")[1]
    assert "Patient notes" not in text and "jan@example.com" not in text


async def test_report_no_leak(loaded, tmp_path):
    rows = _load(str(write_rows(tmp_path, ROWS[:1] + ROWS[2:3])))
    with respx.mock() as m:
        m.post(loaded.config.clef.url).respond(200, json=good_response(loaded.config.policy))
        scored = await score_all(loaded, rows, 1)
    assert report(scored, loaded, io.StringIO()) == 0


def test_bad_input_exit_2(loaded, tmp_path):
    p = tmp_path / "bad.jsonl"
    p.write_text('{"label": "maybe", "text": "x"}\n')
    assert run(loaded, str(p)) == 2
