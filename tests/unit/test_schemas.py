from __future__ import annotations

from privacy_gateway.schemas import strip_opaque_reasoning

SUMMARY = {"type": "reasoning.summary", "summary": "Picked a fun fact.", "format": "openai-responses-v1", "index": 0}
ENCRYPTED = {"type": "reasoning.encrypted", "data": "gAAAAB" + "x" * 64, "format": "openai-responses-v1", "index": 1}
TEXT_SIGNED = {"type": "reasoning.text", "text": "Thinking...", "signature": "EqQBCkYIBxgC", "index": 2}


def convo(details):
    return {
        "model": "auto",
        "messages": [
            {"role": "user", "content": "fun fact"},
            {"role": "assistant", "content": "Vespasian...", "reasoning_details": details},
            {"role": "user", "content": "another"},
        ],
    }


def test_removes_encrypted_items_and_signatures_keeps_readable_reasoning():
    body = convo([SUMMARY, ENCRYPTED, TEXT_SIGNED])
    out, n = strip_opaque_reasoning(body)
    assert n == 2
    assert out["messages"][1]["reasoning_details"] == [SUMMARY, {k: v for k, v in TEXT_SIGNED.items() if k != "signature"}]
    assert out["messages"][1]["content"] == "Vespasian..."
    assert body["messages"][1]["reasoning_details"] == [SUMMARY, ENCRYPTED, TEXT_SIGNED]  # input untouched


def test_drops_the_field_when_nothing_readable_is_left():
    out, n = strip_opaque_reasoning(convo([ENCRYPTED]))
    assert n == 1 and "reasoning_details" not in out["messages"][1]


def test_no_change_returns_same_object():
    body = convo([SUMMARY])
    assert strip_opaque_reasoning(body) == (body, 0)
    completion = {"model": "auto", "prompt": "hi"}
    assert strip_opaque_reasoning(completion) == (completion, 0)


def test_tolerates_odd_shapes():
    body = {"messages": ["not a dict", {"role": "assistant", "reasoning_details": "not a list"},
                         {"role": "assistant", "reasoning_details": [ENCRYPTED, "str item"]}]}
    out, n = strip_opaque_reasoning(body)
    assert n == 1
    assert out["messages"][:2] == body["messages"][:2]
    assert out["messages"][2]["reasoning_details"] == ["str item"]
