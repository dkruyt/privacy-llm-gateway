"""Build small PDFs for tests without external tools."""

from __future__ import annotations

import base64
import io


def text_pdf(lines: list[str], pages: int = 1) -> bytes:
    """A minimal valid PDF with a real text layer (Helvetica, one Tj per line)."""
    objs: list[bytes] = []
    page_ids = []
    font_id = 3
    objs.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objs.append(b"")  # pages placeholder (obj 2)
    objs.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    for _ in range(pages):
        ops = ["BT", "/F1 12 Tf", "72 720 Td", "14 TL"]
        for line in lines:
            esc = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            ops.append(f"({esc}) Tj T*")
        ops.append("ET")
        stream = "\n".join(ops).encode("latin-1")
        objs.append(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
        content_id = len(objs)
        objs.append(
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents %d 0 R "
            b"/Resources << /Font << /F1 %d 0 R >> >> >>" % (content_id, font_id)
        )
        page_ids.append(len(objs))
    kids = b" ".join(b"%d 0 R" % i for i in page_ids)
    objs[1] = b"<< /Type /Pages /Kids [" + kids + b"] /Count %d >>" % len(page_ids)
    return _assemble(objs)


def blank_pdf() -> bytes:
    """A valid PDF with a page but no text layer (like a scan without OCR)."""
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>",
    ]
    return _assemble(objs)


def encrypted_pdf(lines: list[str]) -> bytes:
    from pypdf import PdfReader, PdfWriter

    w = PdfWriter(clone_from=PdfReader(io.BytesIO(text_pdf(lines))))
    w.encrypt(user_password="user-pw", owner_password="owner-pw", algorithm="RC4-128")
    buf = io.BytesIO()
    w.write(buf)
    return buf.getvalue()


def broken_pdf() -> bytes:
    return b"%PDF-1.4\n1 0 obj << /Type /Catalog /Pages 9 0 R >> endobj\ngarbage\n%%EOF"


def docx_bytes() -> bytes:
    # Not a real docx; the gateway rejects on type before parsing.
    return b"PK\x03\x04" + b"\x00" * 100


def _assemble(objs: list[bytes]) -> bytes:
    out = io.BytesIO()
    out.write(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(out.tell())
        out.write(b"%d 0 obj\n" % i + body + b"\nendobj\n")
    xref = out.tell()
    out.write(b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1))
    for off in offsets:
        out.write(b"%010d 00000 n \n" % off)
    out.write(b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref))
    return out.getvalue()


def data_url(mime: str, data: bytes) -> str:
    return f"data:{mime};base64," + base64.b64encode(data).decode()
