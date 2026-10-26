from __future__ import annotations

import hashlib
import json

import pytest

from privacy_llm_gateway.extract import extract, normalize

H = "x-session-id"


def full_request():
    return {
        "model": "auto",
        "messages": [
            {"role": "system", "content": "SYS-MARK"},
            {"role": "developer", "content": [{"type": "text", "text": "DEV-MARK"}]},
            {"role": "user", "content": [{"type": "text", "text": "USER-PART-MARK"}, {"type": "input_text", "text": "USER-PART2"}]},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {"id": "c1", "type": "function", "function": {"name": "TOOLNAME-MARK", "arguments": '{"q": "ARGS-MARK"}'}}
                ],
                "function_call": {"name": "legacy_fn", "arguments": '{"x": "LEGACY-MARK"}'},
            },
            {"role": "tool", "tool_call_id": "c1", "content": "TOOL-RESULT-MARK"},
            {"role": "function", "name": "legacy_fn", "content": "FUNCTION-RESULT-MARK"},
            {"role": "assistant", "content": [{"type": "refusal", "refusal": "REFUSAL-MARK"}]},
        ],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "lookup",
                    "description": "TOOL-DESC-MARK",
                    "parameters": {"type": "object", "properties": {"SCHEMA-PROP-MARK": {"type": "string", "description": "PARAM-DESC-MARK"}}},
                },
            }
        ],
        "functions": [{"name": "legacy_fn", "description": "FUNCTIONS-DESC-MARK"}],
        "response_format": {"type": "json_schema", "json_schema": {"name": "out", "schema": {"description": "RESPONSE-FORMAT-MARK"}}},
        "user": "USER-FIELD-MARK",
        "rag_context": [{"doc": "RAG-MARK", "nested": {"deep": ["RAG-DEEP-MARK"]}}],
        "documents": "EXTRA-DOCUMENTS-MARK",
    }


MARKS = [
    "SYS-MARK", "DEV-MARK", "USER-PART-MARK", "USER-PART2", "TOOLNAME-MARK", "ARGS-MARK", "LEGACY-MARK",
    "TOOL-RESULT-MARK", "FUNCTION-RESULT-MARK", "REFUSAL-MARK", "TOOL-DESC-MARK", "SCHEMA-PROP-MARK",
    "PARAM-DESC-MARK", "FUNCTIONS-DESC-MARK", "RESPONSE-FORMAT-MARK", "USER-FIELD-MARK", "RAG-MARK",
    "RAG-DEEP-MARK", "EXTRA-DOCUMENTS-MARK",
]


@pytest.mark.parametrize("mark", MARKS)
def test_every_part_reaches_state_and_strings(mark):
    ex = extract(full_request(), {}, H)
    assert mark in json.dumps(ex.state)
    assert any(mark in t for t in ex.texts)


def test_completion_prompt_reaches_state():
    ex = extract({"model": "auto", "prompt": "PROMPT-MARK", "suffix": "SUFFIX-MARK"}, {}, H)
    assert "PROMPT-MARK" in json.dumps(ex.state) and "SUFFIX-MARK" in json.dumps(ex.state)


def test_locations_are_recorded():
    ex = extract(full_request(), {}, H)
    locs = dict((t, loc) for loc, t in ex.strings)
    assert locs['{"q": "ARGS-MARK"}'] == "messages[3].tool_calls[0].function.arguments"
    assert locs["TOOL-RESULT-MARK"] == "messages[4].content"


def test_model_not_in_state_but_original_untouched():
    body = full_request()
    before = json.dumps(body)
    ex = extract(body, {}, H)
    assert "model" not in ex.state
    assert json.dumps(body) == before


def test_normalisation_in_state_only():
    body = {"model": "auto", "messages": [{"role": "user", "content": "ｊｏｈｎ​@‮example.com"}]}
    ex = extract(body, {}, H)
    assert ex.state["messages"][0]["content"] == "john@example.com"
    assert body["messages"][0]["content"] == "ｊｏｈｎ​@‮example.com"


@pytest.mark.parametrize("ch", ["​", "‌", "‍", "⁠", "﻿", "‪", "‫", "‬", "‭", "‮", "⁦", "⁧", "⁨", "⁩"])
def test_invisible_characters_removed(ch):
    assert normalize(f"a{ch}b") == "ab"


def test_keys_are_normalised_and_scanned():
    ex = extract({"model": "auto", "messages": [{"role": "user", "content": "x"}], "meta": {"ｋｅｙ@ex.com": 1}}, {}, H)
    assert "key@ex.com" in ex.texts


# ------------------------------------------------------------------ unsupported


def msg(*parts):
    return {"model": "auto", "messages": [{"role": "user", "content": list(parts)}]}


@pytest.mark.parametrize(
    "part,flags",
    [
        ({"type": "image_url", "image_url": {"url": "https://example.com/cat.png"}}, ["media:image"]),
        ({"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="}}, ["data_url", "media:image"]),
        ({"type": "input_audio", "input_audio": {"data": "AAAA", "format": "wav"}}, ["media:audio"]),
        ({"type": "file", "file": {"file_id": "file-123"}}, ["media:file"]),
        ({"type": "video_url", "video_url": {"url": "https://x/v.mp4"}}, ["unknown_part_type"]),
        ({"type": "text", "text": "see data:text/plain;base64,aGVsbG8="}, ["data_url"]),
        ({"type": "text", "text": "plain"}, []),
    ],
)
def test_unsupported_flags(part, flags):
    assert extract(msg(part), {}, H).unsupported == flags


@pytest.mark.parametrize("prompt,flag", [([1, 2, 3], True), ([[1, 2], [3]], True), (["a", "b"], False), ("x", False)])
def test_token_id_prompt(prompt, flag):
    ex = extract({"model": "auto", "prompt": prompt}, {}, H)
    assert ("token_ids" in ex.unsupported) is flag


# ------------------------------------------------------------------ session seed


def test_session_from_header():
    ex = extract(msg({"type": "text", "text": "x"}), {H: "abc"}, H)
    assert (ex.session_seed, ex.session_source) == ("abc", "header")


def test_session_from_metadata():
    body = msg({"type": "text", "text": "x"}) | {"metadata": {"session_id": "m-1"}}
    ex = extract(body, {}, H)
    assert (ex.session_seed, ex.session_source) == ("m-1", "metadata")


def test_header_wins_over_metadata():
    body = msg({"type": "text", "text": "x"}) | {"metadata": {"session_id": "m-1"}}
    assert extract(body, {H: "h-1"}, H).session_seed == "h-1"


def test_derived_seed_stable_across_turns():
    turn1 = {"model": "auto", "messages": [{"role": "system", "content": "S"}, {"role": "user", "content": "first"}]}
    turn2 = {
        "model": "auto",
        "messages": turn1["messages"] + [{"role": "assistant", "content": "reply"}, {"role": "user", "content": "second"}],
    }
    a, b = extract(turn1, {}, H), extract(turn2, {}, H)
    assert a.session_source == "derived"
    assert a.session_seed == b.session_seed
    assert len(a.session_seed) == 64 and "first" not in a.session_seed


def test_derived_seed_differs_per_conversation():
    a = extract({"model": "auto", "messages": [{"role": "user", "content": "one"}]}, {}, H)
    b = extract({"model": "auto", "messages": [{"role": "user", "content": "two"}]}, {}, H)
    assert a.session_seed != b.session_seed


def test_derived_seed_is_sha256():
    ex = extract({"model": "auto", "messages": [{"role": "user", "content": "hi"}]}, {}, H)
    assert ex.session_seed == hashlib.sha256(b"user:hi").hexdigest()
