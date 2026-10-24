"""Prometheus metrics (dedicated registry) and the /metrics app on server.metrics_listen.

Labels are low-cardinality and content-free: key_id from config is the only
client label; reasons come from a fixed code set; never session ids, prompts or
client-chosen model names.

workers > 1: PROMETHEUS_MULTIPROC_DIR must be set BEFORE this module is imported
(the CLI does that); the parent process then serves /metrics by aggregating all
workers' files.
"""

from __future__ import annotations

import hmac
import os
import re
from collections.abc import Iterable

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)

from . import __version__

MULTIPROCESS = bool(os.environ.get("PROMETHEUS_MULTIPROC_DIR"))
REGISTRY = CollectorRegistry(auto_describe=True)

_LAT = (0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30)
_LONG = (0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600, 900)
_PROB = tuple(round(0.05 * i, 2) for i in range(1, 21))
_TOKENS = (128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)

# Fixed label value sets (enforced by the helpers below).
ENDPOINTS = ("chat_completions", "completions", "models", "passthrough", "other")
REQUESTED = ("auto", "local")
ROUTES = ("local", "public")
VERDICTS = ("public", "sensitive", "uncertain")
CLEF_RESULTS = ("ok", "timeout", "transport_error", "http_error", "invalid")
SKIP_WHY = ("detector", "unsupported", "too_large", "session", "local_model", "document")
SESSION_EVENTS = ("hit", "pinned", "store_unavailable", "write_failed")
DOC_TYPES = ("pdf", "text", "other")
DOC_RESULTS = ("converted", "rejected")
EGRESS_RESULTS = ("allowed", "blocked")
UPSTREAM_KINDS = ("http_4xx", "http_5xx", "timeout", "transport")
DEPENDENCIES = ("redis", "clef", "local")


def _c(name, doc, labels=()):
    return Counter(name, doc, labels, registry=REGISTRY)


def _h(name, doc, buckets, labels=()):
    return Histogram(name, doc, labels, buckets=buckets, registry=REGISTRY)


def _g(name, doc, labels, mode):
    return Gauge(name, doc, labels, registry=REGISTRY, multiprocess_mode=mode)


REQUESTS = _c(
    "privacy_requests_total",
    "Requests by client key, endpoint, requested model, route, verdict and streaming.",
    ("key_id", "endpoint", "requested", "route", "verdict", "stream"),
)
ROUTE_REASONS = _c("privacy_route_reasons_total", "Routing reasons (fixed code set).", ("reason",))
CLEF_CALLS = _c("privacy_clef_calls_total", "Clef calls by result.", ("result",))
CLEF_SKIPPED = _c("privacy_clef_skipped_total", "Requests not sent to Clef, by cause.", ("why",))
SESSION_EVENTS_TOTAL = _c("privacy_session_events_total", "Sticky-session events.", ("event",))
DOCUMENTS = _c("privacy_documents_total", "Attached documents by type and result.", ("type", "result"))
EGRESS = _c(
    "privacy_egress_total",
    "Outbound model calls by route and egress-guard result. result=blocked must stay 0.",
    ("route", "result"),
)
UPSTREAM_ERRORS = _c("privacy_upstream_errors_total", "Upstream model errors.", ("route", "kind"))
CLIENT_ERRORS = _c("privacy_client_errors_total", "Requests rejected with 4xx, by error code.", ("code",))
CONFIG_RELOADS = _c("privacy_config_reloads_total", "SIGHUP config reloads.", ("result",))

CLASSIFICATION_SECONDS = _h(
    "privacy_classification_seconds", "Whole classification pipeline duration.", _LAT
)
CLEF_SECONDS = _h("privacy_clef_seconds", "Clef call duration.", _LAT)
UPSTREAM_TTFB = _h("privacy_upstream_ttfb_seconds", "Time to upstream response headers.", _LONG, ("route",))
REQUEST_SECONDS = _h("privacy_request_seconds", "Total request duration.", _LONG, ("route", "stream"))
CLEF_P_PUBLIC = _h("privacy_clef_p_public", "Clef p(verdict=public).", _PROB)
CLEF_CONFIDENCE = _h("privacy_clef_confidence", "Clef verdict confidence.", _PROB)
CLEF_CATEGORY_MAX = _h("privacy_clef_category_max_prob", "Highest has_<category> probability.", _PROB)
CLEF_MANIPULATION = _h("privacy_clef_manipulation_prob", "Clef manipulation probability.", _PROB)
CLEF_INPUT_TOKENS = _h("privacy_clef_input_tokens", "Clef input tokens per call.", _TOKENS)

INFLIGHT = _g("privacy_inflight_requests", "Requests in flight per route.", ("route",), "livesum")
CONFIG_INFO = _g("privacy_config_info", "Active config (sha256 of the file) = 1.", ("config_sha256",), "livemostrecent")
BUILD_INFO = _g("privacy_build_info", "Build version = 1.", ("version",), "livemax")
UP = _g("privacy_up", "Dependency reachable (background probe, every 30 s).", ("dependency",), "livemostrecent")

BUILD_INFO.labels(version=__version__).set(1)

# --------------------------------------------------------------------------- helpers

_REASON_PREFIXES = re.compile(
    r"^(?:detector:(?:[a-z_]+|custom:[a-z0-9_]+|detect_secrets:[A-Za-z0-9]+)"
    r"|unsupported:(?:media:(?:image|audio|file)|data_url|unknown_part_type|token_ids)"
    r"|clef_error:[a-z0-9_]+"
    r"|clef_choice:[a-z0-9_]+|clef_category:[a-z0-9_]+"
    r"|document_attached:(?:pdf|text)"
    r"|too_large_for_classifier|clef_low_public_prob|clef_low_confidence|clef_manipulation"
    r"|session_sticky|session_store_unavailable|classifier_internal_error|not_classified)$"
)


def _check(value: str, allowed: Iterable[str]) -> str:
    return value if value in allowed else "other"


def safe_reason(reason: str, known: set[str] | None = None) -> str:
    """Only reason codes from the fixed set become labels; anything else → "other"."""
    if known is not None and reason not in known and not reason.startswith("clef_error:http_"):
        # detector/category reasons must name a configured rule or category
        if reason.split(":", 1)[0] in ("detector", "clef_choice", "clef_category"):
            return "other"
    return reason if _REASON_PREFIXES.match(reason) else "other"


def record_request(*, key_id: str, endpoint: str, requested: str, route: str, verdict: str, stream: bool,
                   reasons: list[str], known_reasons: set[str] | None = None) -> None:
    REQUESTS.labels(
        key_id=key_id,
        endpoint=_check(endpoint, ENDPOINTS),
        requested=_check(requested, REQUESTED),
        route=_check(route, ROUTES),
        verdict=_check(verdict, VERDICTS),
        stream="true" if stream else "false",
    ).inc()
    for r in reasons:
        ROUTE_REASONS.labels(reason=safe_reason(r, known_reasons)).inc()


def client_error(code: str) -> None:
    CLIENT_ERRORS.labels(code=code if re.fullmatch(r"[a-z0-9_]{1,40}", code) else "other").inc()


def clef_skipped(why: str) -> None:
    CLEF_SKIPPED.labels(why=_check(why, SKIP_WHY)).inc()


def session_event(event: str) -> None:
    SESSION_EVENTS_TOTAL.labels(event=_check(event, SESSION_EVENTS)).inc()


def document(doc_type: str, result: str) -> None:
    DOCUMENTS.labels(type=_check(doc_type, DOC_TYPES), result=_check(result, DOC_RESULTS)).inc()


def egress(route: str, result: str) -> None:
    EGRESS.labels(route=_check(route, ROUTES), result=_check(result, EGRESS_RESULTS)).inc()


def upstream_error(route: str, kind: str) -> None:
    UPSTREAM_ERRORS.labels(route=_check(route, ROUTES), kind=_check(kind, UPSTREAM_KINDS)).inc()


_current_config_sha: list[str] = []


def set_config_info(sha256: str) -> None:
    for old in _current_config_sha:
        if old != sha256:
            CONFIG_INFO.labels(config_sha256=old).set(0)
            if not MULTIPROCESS:
                try:
                    CONFIG_INFO.remove(old)
                except KeyError:
                    pass
    _current_config_sha[:] = [sha256]
    CONFIG_INFO.labels(config_sha256=sha256).set(1)


def config_reload(ok: bool) -> None:
    CONFIG_RELOADS.labels(result="ok" if ok else "failed").inc()


def set_up(dependency: str, up: bool) -> None:
    UP.labels(dependency=_check(dependency, DEPENDENCIES)).set(1 if up else 0)


def init_label_sets() -> None:
    """Pre-create zero series so alerts and ratios work from the first scrape."""
    for route in ROUTES:
        EGRESS.labels(route=route, result="allowed")
        EGRESS.labels(route=route, result="blocked")
        INFLIGHT.labels(route=route)
    for r in CLEF_RESULTS:
        CLEF_CALLS.labels(result=r)
    for res in ("ok", "failed"):
        CONFIG_RELOADS.labels(result=res)


# --------------------------------------------------------------------------- exposition


def render() -> bytes:
    if MULTIPROCESS:
        from prometheus_client import multiprocess

        reg = CollectorRegistry()
        multiprocess.MultiProcessCollector(reg)
        return generate_latest(reg)
    return generate_latest(REGISTRY)


def make_metrics_app(get_token):
    """ASGI app serving GET /metrics only. get_token() → optional bearer token."""

    async def app(scope, receive, send):
        if scope["type"] == "lifespan":
            while True:
                msg = await receive()
                if msg["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif msg["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return
        if scope["path"] != "/metrics" or scope["method"] not in ("GET", "HEAD"):
            await _respond(send, 404, b"not found\n", b"text/plain")
            return
        token = get_token()
        if token:
            auth = dict(scope["headers"]).get(b"authorization", b"").decode("latin-1")
            if not hmac.compare_digest(auth.encode(), f"Bearer {token}".encode()):
                await _respond(send, 401, b"unauthorized\n", b"text/plain")
                return
        await _respond(send, 200, render(), CONTENT_TYPE_LATEST.encode())

    return app


async def _respond(send, status: int, body: bytes, ctype: bytes) -> None:
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", ctype), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})
