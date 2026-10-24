from __future__ import annotations

import base64
import json

import pytest

from privacy_gateway.config import DocumentPolicy
from privacy_gateway.documents import DocumentRejected, convert
from tests.pdfs import blank_pdf, broken_pdf, data_url, docx_bytes, encrypted_pdf, text_pdf

POLICY = DocumentPolicy()
LINES = ["Quarterly report for ACME", "Revenue grew by twelve percent", "DOC-BODY-MARK"]


def body_with(part):
    return {"model": "auto", "messages": [{"role": "user", "content": [{"type": "text", "text": "summarise"}, part]}]}


def image_url_part(mime, data):
    return {"type": "image_url", "image_url": {"url": data_url(mime, data)}}


def file_part(filename, mime, data):
    return {"type": "file", "file": {"filename": filename, "file_data": data_url(mime, data)}}


async def test_pdf_via_image_url():
    conv = await convert(body_with(image_url_part("application/pdf", text_pdf(LINES))), POLICY)
    assert conv.documents == ["pdf"]
    part = conv.body["messages"][0]["content"][1]
    assert part["type"] == "text"
    assert part["text"].startswith("[Attached document: document]\n")
    assert "DOC-BODY-MARK" in part["text"]
    assert "base64" not in json.dumps(conv.body)


async def test_pdf_via_file_part():
    conv = await convert(body_with(file_part("report.pdf", "application/pdf", text_pdf(LINES))), POLICY)
    assert conv.documents == ["pdf"]
    assert conv.body["messages"][0]["content"][1]["text"].startswith("[Attached document: report.pdf]\n")


async def test_file_part_raw_base64_uses_extension():
    part = {"type": "file", "file": {"filename": "notes.txt", "file_data": base64.b64encode(b"hello TEXT-MARK").decode()}}
    conv = await convert(body_with(part), POLICY)
    assert conv.documents == ["text"]
    assert "TEXT-MARK" in conv.body["messages"][0]["content"][1]["text"]


@pytest.mark.parametrize("mime", ["text/plain", "text/markdown", "text/csv", "application/json", "application/xml", "application/x-yaml"])
async def test_text_types(mime):
    conv = await convert(body_with(image_url_part(mime, "naïve TEXT-MARK".encode())), POLICY)
    assert conv.documents == ["text"]
    assert conv.body["messages"][0]["content"][1]["text"].endswith("naïve TEXT-MARK")


async def test_original_body_untouched():
    body = body_with(image_url_part("application/pdf", text_pdf(LINES)))
    before = json.dumps(body)
    await convert(body, POLICY)
    assert json.dumps(body) == before


async def test_page_limit():
    pdf = text_pdf(["page text that is long enough"], pages=5)
    conv = await convert(body_with(image_url_part("application/pdf", pdf)), DocumentPolicy(max_pages=2))
    assert conv.body["messages"][0]["content"][1]["text"].count("page text") == 2


async def test_images_are_left_alone():
    part = image_url_part("image/png", b"\x89PNG\r\n")
    conv = await convert(body_with(part), POLICY)
    assert conv.documents == [] and conv.body["messages"][0]["content"][1] == part


async def test_remote_urls_and_file_ids_left_alone():
    for part in (
        {"type": "image_url", "image_url": {"url": "https://example.com/x.pdf"}},
        {"type": "file", "file": {"file_id": "file-abc"}},
    ):
        conv = await convert(body_with(part), POLICY)
        assert conv.documents == [] and conv.body["messages"][0]["content"][1] == part


@pytest.mark.parametrize(
    "part,status,code,doc_type",
    [
        (image_url_part("application/pdf", blank_pdf()), 400, "pdf_no_text_layer", "pdf"),
        (image_url_part("application/pdf", encrypted_pdf(LINES)), 400, "pdf_encrypted", "pdf"),
        (image_url_part("application/pdf", broken_pdf()), 400, "pdf_unreadable", "pdf"),
        (file_part("x.pdf", "application/pdf", b"not a pdf at all"), 400, "pdf_unreadable", "pdf"),
        (
            file_part("x.docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document", docx_bytes()),
            400,
            "unsupported_document_type",
            "other",
        ),
        (image_url_part("application/zip", docx_bytes()), 400, "unsupported_document_type", "other"),
        (file_part("x.bin", "application/octet-stream", b"\x00\x01"), 400, "unsupported_document_type", "other"),
        (image_url_part("text/plain", b"\xff\xfe\xfa invalid"), 400, "text_not_utf8", "text"),
        (
            {"type": "image_url", "image_url": {"url": "data:application/pdf;base64,@@@notbase64@@@"}},
            400,
            "document_invalid_base64",
            "pdf",
        ),
    ],
)
async def test_rejections(part, status, code, doc_type):
    with pytest.raises(DocumentRejected) as ei:
        await convert(body_with(part), POLICY)
    assert (ei.value.status, ei.value.code, ei.value.doc_type) == (status, code, doc_type)


async def test_too_large():
    with pytest.raises(DocumentRejected) as ei:
        await convert(body_with(image_url_part("text/plain", b"x" * 2000)), DocumentPolicy(max_bytes=1000))
    assert (ei.value.status, ei.value.code) == (413, "document_too_large")


async def test_rejection_message_has_no_content():
    with pytest.raises(DocumentRejected) as ei:
        await convert(body_with(file_part("SECRET-NAME.pdf", "application/pdf", b"SECRET-CONTENT")), POLICY)
    assert "SECRET" not in str(ei.value)


async def test_no_messages_body_passthrough():
    conv = await convert({"model": "auto", "prompt": "x"}, POLICY)
    assert conv.body == {"model": "auto", "prompt": "x"} and conv.documents == []
