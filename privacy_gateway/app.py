"""FastAPI API app: OpenAI-compatible routes, request handling, error mapping, lifespan."""

from __future__ import annotations

import asyncio
import contextlib
import json
import secrets
import signal
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import ValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import logs, metrics
from .auth import KeyMap
from .classifier import ERROR_CODES, ClassifierClient
from .config import ConfigHolder, LoadedConfig
from .decision import Decision, forced_local
from .detectors import Detectors
from .documents import DocumentRejected, convert
from .extract import session_seed
from .logs import log
from .pipeline import Evaluation, PrefixContext, evaluate
from .prefix_cache import fingerprint as prefix_fingerprint
from .schemas import (
    GATEWAY_ONLY_FIELDS,
    MODEL_LOCAL,
    ROUTING_FIELDS,
    ChatCompletionRequest,
    CompletionRequest,
    error_body,
    strip_opaque_reasoning,
)
from .session import SessionStore, SessionStoreUnavailable, session_key, short_id
from .upstream import EgressBlocked, UpstreamFailure, Upstreams

PROBE_INTERVAL_S = 30.0
_PROCESS_STAMP_KEY = secrets.token_bytes(32)  # used when stamp.key_file is null


# --------------------------------------------------------------------------- runtime


@dataclass
class Runtime:
    """Everything derived from one config generation. Swapped atomically on reload."""

    loaded: LoadedConfig
    keys: KeyMap
    detectors: Detectors
    classifier: ClassifierClient
    upstreams: Upstreams
    sessions: SessionStore
    known_reasons: set[str] = field(default_factory=set)
    stamp_key: bytes = b""
    prefix_fingerprint: str = ""

    @property
    def config(self):
        return self.loaded.config

    async def aclose(self) -> None:
        await self.classifier.aclose()
        await self.upstreams.aclose()
        await self.sessions.aclose()

    def aclose_later(self) -> None:
        """Close after in-flight requests (bounded by the longest upstream timeout) finish."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        ups = self.config.upstreams
        delay = max(ups.local.timeout_s, ups.public.timeout_s, self.config.classifier.timeout_s) + 10
        loop.call_later(delay, lambda: asyncio.ensure_future(self.aclose()))


def build_runtime(loaded: LoadedConfig, transports: dict | None = None, redis_client: Any = None) -> Runtime:
    cfg = loaded.config
    transports = transports or {}
    detectors = Detectors(cfg.policy.detectors)
    known = {f"detector:{r}" for r in detectors.rule_ids}
    known |= {f"classifier_choice:{c}" for c in cfg.policy.categories}
    known |= {f"classifier_category:{c}" for c in cfg.policy.sensitive_categories}
    known |= {f"classifier_error:{c}" for c in ERROR_CODES}
    stamp_key = loaded.stamp_key or _PROCESS_STAMP_KEY
    classifier = ClassifierClient(cfg.classifier, cfg.policy, transport=transports.get("classifier"))
    return Runtime(
        loaded=loaded,
        keys=KeyMap(cfg.auth),
        detectors=detectors,
        classifier=classifier,
        upstreams=Upstreams(cfg.upstreams, stamp_key, transports),
        sessions=SessionStore(cfg.redis, cfg.policy.session.ttl_seconds, client=redis_client),
        known_reasons=known,
        stamp_key=stamp_key,
        prefix_fingerprint=prefix_fingerprint(
            cfg.classifier.model, classifier.questions, cfg.policy.state_notice, cfg.policy.thresholds,
            cfg.policy.session.prefix_cache.borderline_margin,
        ),
    )


# --------------------------------------------------------------------------- errors


class ClientError(Exception):
    def __init__(self, status: int, code: str, message: str, type_: str = "invalid_request_error"):
        super().__init__(code)
        self.status, self.code, self.message, self.type = status, code, message, type_


def _error(status: int, code: str, message: str, type_: str = "invalid_request_error", headers=None) -> JSONResponse:
    return JSONResponse(error_body(message, type_, code), status_code=status, headers=headers)


def _privacy_headers(d: Decision) -> dict[str, str]:
    return {
        "x-privacy-route": d.route,
        "x-privacy-verdict": d.verdict,
        "x-privacy-reasons": ",".join(d.reasons),
    }


# --------------------------------------------------------------------------- helpers


async def _read_body(request: Request, limit: int) -> bytes:
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > limit:
        raise ClientError(413, "request_too_large", f"Request body exceeds {limit} bytes.")
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > limit:
            raise ClientError(413, "request_too_large", f"Request body exceeds {limit} bytes.")
        chunks.append(chunk)
    return b"".join(chunks)


def _parse_json(raw: bytes) -> dict[str, Any]:
    try:
        body = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise ClientError(400, "invalid_json", "Request body is not valid JSON.") from None
    if not isinstance(body, dict):
        raise ClientError(400, "invalid_json", "Request body must be a JSON object.")
    return body


def _validate(model_cls, body: dict[str, Any]) -> None:
    try:
        model_cls.model_validate(body)
    except ValidationError as exc:
        # Field paths only; pydantic messages can echo input values.
        locs = sorted({".".join(str(p) for p in e["loc"]) for e in exc.errors(include_input=False)})
        raise ClientError(400, "invalid_request", f"Invalid request fields: {', '.join(locs)[:300]}") from None


def _routing_fields(body: dict[str, Any]) -> None:
    bad = sorted(ROUTING_FIELDS & set(body))
    if bad:
        raise ClientError(400, "routing_field_not_allowed", f"Routing fields are not accepted: {', '.join(bad)}.")


def _outbound(body: dict[str, Any], model: str) -> dict[str, Any]:
    out = {k: v for k, v in body.items() if k not in GATEWAY_ONLY_FIELDS}
    out["model"] = model
    return out


# --------------------------------------------------------------------------- app


def create_app(holder: ConfigHolder, *, start_background: bool = True, install_sighup: bool = False) -> FastAPI:
    state: dict[str, Any] = {"classifier_up": None}

    async def probe_once() -> None:
        rt: Runtime = holder.current
        redis_ok, classifier_ok, local_ok = await asyncio.gather(
            rt.sessions.ping(), rt.classifier.probe(), rt.upstreams.probe_local()
        )
        metrics.set_up("redis", redis_ok)
        metrics.set_up("classifier", classifier_ok)
        metrics.set_up("local", local_ok)
        state["classifier_up"] = classifier_ok

    async def probe_loop() -> None:
        while True:
            try:
                await probe_once()
            except Exception as exc:  # noqa: BLE001
                log.error("probe_failed", exc)
            await asyncio.sleep(PROBE_INTERVAL_S)

    @contextlib.asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        rt0: Runtime = holder.current
        metrics.init_label_sets(rt0.keys.ids, rt0.known_reasons)
        metrics.set_config_info(holder.loaded.sha256)
        task = asyncio.create_task(probe_loop()) if start_background else None
        loop = asyncio.get_running_loop()
        if install_sighup:
            loop.add_signal_handler(signal.SIGHUP, holder.reload)
        try:
            yield
        finally:
            if install_sighup:
                loop.remove_signal_handler(signal.SIGHUP)
            if task:
                task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await task
            await holder.current.aclose()

    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.holder = holder
    app.state.probe_once = probe_once

    # ------------------------------------------------------------------ errors

    @app.exception_handler(ClientError)
    async def _client_error(_req: Request, exc: ClientError):
        metrics.client_error(exc.code)
        log.event("client_error", status=exc.status, code=exc.code)
        return _error(exc.status, exc.code, exc.message, exc.type)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_req: Request, exc: StarletteHTTPException):
        code = {404: "not_found", 405: "method_not_allowed"}.get(exc.status_code, f"http_{exc.status_code}")
        if exc.status_code < 500:
            metrics.client_error(code)
        return _error(exc.status_code, code, "Not found." if exc.status_code == 404 else "Request not allowed.")

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_req: Request, _exc: RequestValidationError):
        metrics.client_error("invalid_request")
        return _error(400, "invalid_request", "Invalid request.")

    @app.exception_handler(Exception)
    async def _internal(_req: Request, exc: Exception):
        log.error("internal_error", exc)
        return _error(500, "internal_error", "Internal server error.", "server_error")

    # ------------------------------------------------------------------ health

    @app.get("/healthz")
    async def healthz():
        return {"status": "ok"}

    @app.get("/readyz")
    async def readyz():
        rt: Runtime = holder.current
        redis_ok = await rt.sessions.ping()
        body = {
            "status": "ready" if redis_ok else "not_ready",
            "config_sha256": holder.loaded.sha256,
            "redis": "up" if redis_ok else "down",
            "classifier": {None: "unknown", True: "up", False: "down"}[state["classifier_up"]],
        }
        return JSONResponse(body, status_code=200 if redis_ok else 503)

    # ------------------------------------------------------------------ API

    def _auth(request: Request, rt: Runtime) -> str:
        key_id = rt.keys.authenticate(request.headers)
        if key_id is None:
            raise ClientError(401, "invalid_api_key", "Missing or invalid API key.", "authentication_error")
        return key_id

    @app.get("/v1/models")
    async def models(request: Request):
        rt: Runtime = holder.current
        _auth(request, rt)
        data = [
            {"id": mid, "object": "model", "created": 0, "owned_by": "privacy-gateway"}
            for mid in ("auto", "local")
        ]
        return {"object": "list", "data": data}

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request):
        return await _handle(request, "chat_completions", "/chat/completions", ChatCompletionRequest)

    @app.post("/v1/completions")
    async def completions(request: Request):
        return await _handle(request, "completions", "/completions", CompletionRequest)

    @app.api_route("/v1/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def other(request: Request, path: str):
        rt: Runtime = holder.current
        key_id = _auth(request, rt)
        raw = await _read_body(request, rt.config.server.request_max_bytes)
        model = parsed = None
        if raw:
            with contextlib.suppress(ValueError, UnicodeDecodeError):
                parsed = json.loads(raw)
                model = parsed.get("model") if isinstance(parsed, dict) else None
        sub = "/" + path
        if model != MODEL_LOCAL:
            # "auto" (or anything not "local") cannot be classified on other endpoints.
            raise ClientError(400, "endpoint_requires_local", "Only model \"local\" is supported on this endpoint.")
        if sub not in rt.config.upstreams.local.passthrough_paths:
            raise ClientError(404, "not_found", "Endpoint not available.")
        if isinstance(parsed, dict):
            _routing_fields(parsed)
            parsed["model"] = rt.config.upstreams.local.model
            raw = json.dumps(parsed, ensure_ascii=False).encode("utf-8")
        t0 = time.perf_counter()
        metrics.INFLIGHT.labels(route="local").inc()
        try:
            resp = await rt.upstreams.send_passthrough(
                request.method, sub, raw, request.headers.get("content-type")
            )
        except UpstreamFailure as exc:
            return _error(exc.status, f"upstream_{exc.kind}", "Upstream model error.", "upstream_error")
        finally:
            metrics.INFLIGHT.labels(route="local").dec()
        d = Decision("local", "uncertain", [], False)
        metrics.record_request(key_id=key_id, endpoint="passthrough", requested="local", route="local",
                               verdict="uncertain", stream=False, reasons=[])
        metrics.REQUEST_SECONDS.labels(route="local", stream="false").observe(time.perf_counter() - t0)
        return Response(resp.content, status_code=resp.status, media_type=resp.content_type, headers=_privacy_headers(d))

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"], include_in_schema=False)
    async def not_found(path: str):
        raise ClientError(404, "not_found", "Not found.")

    # ------------------------------------------------------------------ core

    async def _handle(request: Request, endpoint: str, path: str, schema) -> Response:
        t_start = time.perf_counter()
        rt: Runtime = holder.current  # one config generation for the whole request
        cfg = rt.config
        key_id = _auth(request, rt)
        raw = await _read_body(request, cfg.server.request_max_bytes)
        body = _parse_json(raw)
        _routing_fields(body)
        _validate(schema, body)
        stream = bool(body.get("stream", False))
        requested = "local" if body.get("model") == MODEL_LOCAL else "auto"

        # Attachments → text parts (both routes: the upstream never receives binaries).
        try:
            conv = await convert(body, cfg.policy.documents)
        except DocumentRejected as exc:
            metrics.document(exc.doc_type, "rejected")
            log.event("document_rejected", code=exc.code)
            raise ClientError(exc.status, exc.code, "The attached document could not be processed.") from None
        for doc_type in conv.documents:
            metrics.document(doc_type, "converted")
        body, opaque = strip_opaque_reasoning(conv.body)
        if opaque:
            metrics.opaque_reasoning_stripped(opaque)

        timings: dict[str, float] = {}
        ev: Evaluation | None = None
        sess_short: str | None = None
        sess_source: str | None = None

        if requested == "local":
            metrics.classifier_skipped("local_model")
            decision = Decision("local", "uncertain", [], False)
        else:
            seed, sess_source = session_seed(body, request.headers, cfg.policy.session.header)
            skey = session_key(key_id, seed)
            sess_short = short_id(skey)
            decision = None
            try:
                if await rt.sessions.is_sensitive(skey):
                    metrics.session_event("hit")
                    metrics.classifier_skipped("session")
                    decision = forced_local("session_sticky", "sensitive", sticky=False)
            except (SessionStoreUnavailable, Exception) as exc:  # noqa: BLE001 - fail closed
                if not isinstance(exc, SessionStoreUnavailable):
                    log.error("session_store_error", exc)
                metrics.session_event("store_unavailable")
                metrics.classifier_skipped("session")
                decision = forced_local("session_store_unavailable")
            if decision is None:
                pc = cfg.policy.session.prefix_cache
                prefix = PrefixContext(
                    store=rt.sessions, stamp_key=rt.stamp_key, session_key=skey,
                    fingerprint=rt.prefix_fingerprint, margin=pc.borderline_margin, ttl_seconds=pc.ttl_seconds,
                ) if pc.enabled else None
                try:
                    ev = await evaluate(
                        body=body,
                        headers=request.headers,
                        policy=cfg.policy,
                        detectors=rt.detectors,
                        classifier=rt.classifier,
                        documents=list(conv.documents),
                        prefix=prefix,
                    )
                    decision = ev.decision
                    timings.update(ev.timings_ms)
                except Exception as exc:  # noqa: BLE001 - ANY failure → local
                    log.error("classifier_internal_error", exc)
                    decision = forced_local("classifier_internal_error")
                if decision.sticky:
                    if await rt.sessions.mark_sensitive(skey):
                        metrics.session_event("pinned")
                    else:
                        metrics.session_event("write_failed")
                        log.warning("session_store_write_failed", session=sess_short)

        route = decision.route
        upstream_cfg = cfg.upstreams.public if route == "public" else cfg.upstreams.local
        outbound = _outbound(body, upstream_cfg.model)
        stamp = rt.upstreams.stamp(route, outbound)

        def finish(status: int) -> None:
            total = time.perf_counter() - t_start
            timings["total"] = total * 1000
            metrics.REQUEST_SECONDS.labels(route=route, stream=str(stream).lower()).observe(total)
            metrics.record_request(
                key_id=key_id, endpoint=endpoint, requested=requested, route=route,
                verdict=decision.verdict, stream=stream, reasons=decision.reasons,
                known_reasons=rt.known_reasons,
            )
            logs.decision_log(
                key_id=key_id, endpoint=endpoint, requested=requested, route=route,
                verdict=decision.verdict, reasons=decision.reasons, stream=stream,
                session=sess_short, session_source=sess_source,
                classifier=ev.classifier_scores() if ev else None, timings_ms=timings, status=status,
                documents=list(conv.documents),
            )

        headers = _privacy_headers(decision)
        metrics.INFLIGHT.labels(route=route).inc()
        inflight_released = False

        def release() -> None:
            nonlocal inflight_released
            if not inflight_released:
                inflight_released = True
                metrics.INFLIGHT.labels(route=route).dec()

        try:
            t_up = time.perf_counter()
            resp = await rt.upstreams.send(route, path, outbound, stamp, stream)
            timings["upstream_ttfb"] = (time.perf_counter() - t_up) * 1000
        except EgressBlocked:
            release()
            finish(500)
            return _error(500, "egress_blocked", "Request blocked by the egress guard.", "server_error", headers)
        except UpstreamFailure as exc:
            release()
            finish(exc.status)
            msg = "Upstream model timed out." if exc.kind == "timeout" else "Upstream model error."
            return _error(exc.status, f"upstream_{exc.kind}", msg, "upstream_error", headers)
        except BaseException:
            release()
            raise

        if not stream:
            release()
            finish(resp.status)
            return Response(resp.content, status_code=resp.status, media_type=resp.content_type, headers=headers)

        async def relay() -> AsyncIterator[bytes]:
            try:
                async for chunk in resp.stream:
                    yield chunk
            finally:
                await resp.close()
                release()
                finish(resp.status)

        return StreamingResponse(
            relay(),
            status_code=resp.status,
            media_type=resp.content_type,
            headers={**headers, "cache-control": "no-cache", "x-accel-buffering": "no"},
        )

    return app


def make_holder(loaded: LoadedConfig, **build_kw) -> ConfigHolder:
    def on_reload(ok: bool, new: LoadedConfig | None) -> None:
        metrics.config_reload(ok)
        if ok and new is not None:
            metrics.set_config_info(new.sha256)
            with contextlib.suppress(Exception):
                rt = holder_ref[0].current
                metrics.init_label_sets(rt.keys.ids, rt.known_reasons)
            logs.set_level(new.config.logging.level)

    holder_ref: list[ConfigHolder] = []
    holder = ConfigHolder(loaded, build=lambda lc: build_runtime(lc, **build_kw), on_reload=on_reload, logger=log)
    holder_ref.append(holder)
    return holder
