"""Content-free JSON logging.

Never logs prompts, responses, filenames, session ids or exception messages:
exceptions are reduced to their type name (tracebacks are dropped, because
exception messages can quote request content).
"""

from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any

LOGGER_NAME = "privacy_gateway"


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        out: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)) + f".{int(record.msecs):03d}Z",
            "level": record.levelname.lower(),
            "logger": record.name,
        }
        fields = getattr(record, "fields", None)
        if fields is not None:
            out["event"] = record.msg
            out.update(fields)
        else:
            # Third-party records (uvicorn, httpx, ...): keep the static template only,
            # never the interpolated args, which may carry request data.
            out["event"] = "library_log"
            out["message"] = str(record.msg)[:200]
        if record.exc_info and record.exc_info[0] is not None:
            out["exc_type"] = record.exc_info[0].__name__
        return json.dumps(out, ensure_ascii=False, default=str)

    def formatException(self, ei) -> str:  # never render tracebacks
        return ""


class EventLogger:
    def __init__(self, name: str = LOGGER_NAME) -> None:
        self._log = logging.getLogger(name)

    def event(self, name: str, level: int = logging.INFO, **fields: Any) -> None:
        self._log.log(level, name, extra={"fields": fields})

    def warning(self, name: str, **fields: Any) -> None:
        self.event(name, logging.WARNING, **fields)

    def error(self, name: str, exc: BaseException | None = None, **fields: Any) -> None:
        if exc is not None:
            fields["exc_type"] = type(exc).__name__
        self.event(name, logging.ERROR, **fields)


log = EventLogger()


def setup(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    for name in ("uvicorn", "uvicorn.error"):
        lg = logging.getLogger(name)
        lg.handlers = []
        lg.propagate = True
    # No access log (paths/queries are not needed; the decision log covers requests).
    logging.getLogger("uvicorn.access").disabled = True
    # httpx/httpcore log full URLs and headers at DEBUG/INFO.
    for name in ("httpx", "httpcore", "hpack", "pypdf", "multipart", "python_multipart"):
        logging.getLogger(name).setLevel(logging.WARNING)


def decision_log(
    *,
    key_id: str,
    endpoint: str,
    requested: str,
    route: str,
    verdict: str,
    reasons: list[str],
    stream: bool,
    session: str | None,
    session_source: str | None,
    clef: dict[str, Any] | None,
    timings_ms: dict[str, float],
    status: int | None = None,
    documents: list[str] | None = None,
) -> None:
    log.event(
        "decision",
        key_id=key_id,
        endpoint=endpoint,
        requested=requested,
        route=route,
        verdict=verdict,
        reasons=reasons,
        stream=stream,
        session=session,
        session_source=session_source,
        clef=clef,
        documents=documents or [],
        status=status,
        timings_ms={k: round(v, 2) for k, v in timings_ms.items()},
    )
