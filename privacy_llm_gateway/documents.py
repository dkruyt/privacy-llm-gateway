"""Attachment conversion: PDF / text documents → a text part. Runs before classification.

Two input shapes are recognised:
  {"type": "image_url", "image_url": {"url": "data:application/pdf;base64,..."}}
  {"type": "file", "file": {"filename": "x.pdf", "file_data": "data:application/pdf;base64,..."}}

Images (data:image/...) are not documents and are left alone (→ unsupported:media:image).
The upstream model receives the extracted text, never the binary.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import io
import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

from .config import DocumentPolicy

logging.getLogger("pypdf").setLevel(logging.ERROR)

DocType = Literal["pdf", "text"]

PDF_MIMES = {"application/pdf", "application/x-pdf"}
TEXT_MIMES = {"application/json", "application/xml", "application/x-yaml", "application/yaml", "text/yaml"}
TEXT_EXTENSIONS = {".txt", ".md", ".markdown", ".csv", ".tsv", ".json", ".xml", ".yaml", ".yml", ".log", ".html", ".htm"}

_DATA_URL = re.compile(r"^data:([a-z0-9.+-]+/[a-z0-9.+-]+)?((?:;[a-z0-9.+-]+=[^;,]*)*)(;base64)?,", re.IGNORECASE)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class DocumentRejected(Exception):
    def __init__(self, status: int, code: str, doc_type: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.doc_type = doc_type  # "pdf" | "text" | "other" (metrics label)


@dataclass
class Conversion:
    body: dict[str, Any]
    documents: list[DocType] = field(default_factory=list)


def _classify(mime: str | None, filename: str | None) -> str:
    """pdf | text | image | other"""
    m = (mime or "").lower()
    if m in PDF_MIMES:
        return "pdf"
    if m.startswith("text/") or m in TEXT_MIMES:
        return "text"
    if m.startswith("image/"):
        return "image"
    if (not m or m == "application/octet-stream") and filename:
        name = filename.lower()
        if name.endswith(".pdf"):
            return "pdf"
        if any(name.endswith(ext) for ext in TEXT_EXTENSIONS):
            return "text"
    return "other"


def _decode(payload: str, max_bytes: int, doc_type: str) -> bytes:
    compact = re.sub(r"\s+", "", payload)
    if len(compact) * 3 // 4 > max_bytes + 3:
        raise DocumentRejected(413, "document_too_large", doc_type)
    try:
        data = base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True)
    except (binascii.Error, ValueError):
        raise DocumentRejected(400, "document_invalid_base64", doc_type) from None
    if len(data) > max_bytes:
        raise DocumentRejected(413, "document_too_large", doc_type)
    return data


def _pdf_text(data: bytes, policy: DocumentPolicy) -> str:
    from pypdf import PdfReader

    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        if reader.is_encrypted:
            raise DocumentRejected(400, "pdf_encrypted", "pdf")
        texts = []
        for i, page in enumerate(reader.pages):
            if i >= policy.max_pages:
                break
            texts.append(page.extract_text() or "")
    except DocumentRejected:
        raise
    except Exception:  # noqa: BLE001 - any pypdf failure
        raise DocumentRejected(400, "pdf_unreadable", "pdf") from None
    text = "\n".join(t.strip() for t in texts if t.strip())
    if len(text.strip()) < policy.min_text_chars:
        raise DocumentRejected(400, "pdf_no_text_layer", "pdf")
    return text


def _text(data: bytes) -> str:
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise DocumentRejected(400, "text_not_utf8", "text") from None


def _safe_name(name: Any) -> str:
    if not isinstance(name, str) or not name.strip():
        return "document"
    return _CONTROL.sub("", name).strip()[:200] or "document"


def _find(part: Mapping[str, Any]) -> tuple[str, str | None, str | None] | None:
    """(data_url_or_base64, mime, filename) if the part may be a document, else None."""
    ptype = part.get("type")
    if ptype == "image_url":
        iu = part.get("image_url")
        url = iu.get("url") if isinstance(iu, Mapping) else iu if isinstance(iu, str) else None
        if isinstance(url, str):
            m = _DATA_URL.match(url)
            if m and m.group(3):
                return url, m.group(1), None
        return None
    if ptype == "file":
        f = part.get("file")
        if not isinstance(f, Mapping) or not isinstance(f.get("file_data"), str):
            return None  # e.g. file_id only → stays unsupported:media:file
        data, filename = f["file_data"], f.get("filename")
        m = _DATA_URL.match(data)
        if m:
            if not m.group(3):
                return None
            return data, m.group(1), filename
        return "data:;base64," + data, None, filename
    return None


async def convert(body: Mapping[str, Any], policy: DocumentPolicy) -> Conversion:
    """Return a copy of body with documents replaced by text parts. Raises DocumentRejected."""
    messages = body.get("messages")
    if not isinstance(messages, list):
        return Conversion(dict(body))
    new_messages: list[Any] = []
    docs: list[DocType] = []
    changed = False
    for msg in messages:
        content = msg.get("content") if isinstance(msg, Mapping) else None
        if not isinstance(content, list):
            new_messages.append(msg)
            continue
        new_content: list[Any] = []
        for part in content:
            found = _find(part) if isinstance(part, Mapping) else None
            if not found:
                new_content.append(part)
                continue
            url, mime, filename = found
            kind = _classify(mime, filename)
            if kind == "image":
                new_content.append(part)
                continue
            if kind == "other":
                raise DocumentRejected(400, "unsupported_document_type", "other")
            data = _decode(url.split(",", 1)[1], policy.max_bytes, kind)
            if kind == "pdf":
                text = await asyncio.to_thread(_pdf_text, data, policy)
            else:
                text = _text(data)
            new_content.append({"type": "text", "text": f"[Attached document: {_safe_name(filename)}]\n{text}"})
            docs.append(kind)  # type: ignore[arg-type]
            changed = True
        new_messages.append({**msg, "content": new_content})
    if not changed:
        return Conversion(dict(body))
    return Conversion({**body, "messages": new_messages}, docs)
