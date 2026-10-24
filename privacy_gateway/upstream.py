"""The ONLY module allowed to call model servers (egress guard).

Two httpx clients (local, public), both trust_env=False (no proxy/env
influence), no redirects, no retries, no fallback. Rebuilt on config reload.

  local route   the target host must be in upstreams.local_hosts
  public route  the HMAC stamp is recomputed over exactly the body being sent;
                any mismatch raises EgressBlocked (log blocked_external_call,
                metric privacy_egress_total{route="public",result="blocked"})

Stamp = HMAC-SHA256(key, f"{route}|{sha256(canonical_json(body without model))}")
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx

from . import metrics
from .config import UpstreamsConfig
from .logs import log

Route = Literal["local", "public"]


class EgressBlocked(Exception):
    """The egress guard refused an outbound call. Never retried, never rerouted."""


class UpstreamFailure(Exception):
    """Upstream returned an error or could not be reached. Maps to 502/504."""

    def __init__(self, status: int, kind: str) -> None:
        super().__init__(kind)
        self.status = status  # status for the client: 502 or 504
        self.kind = kind  # http_4xx | http_5xx | timeout | transport


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def body_digest(body: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_json({k: v for k, v in body.items() if k != "model"})).hexdigest()


def make_stamp(key: bytes, route: str, body: Mapping[str, Any]) -> str:
    return hmac.new(key, f"{route}|{body_digest(body)}".encode(), hashlib.sha256).hexdigest()


@dataclass
class UpstreamResponse:
    status: int
    content_type: str
    content: bytes | None = None  # non-streaming
    stream: AsyncIterator[bytes] | None = None  # streaming (raw bytes, passed through unchanged)
    close: Any = None  # async callable closing the upstream response


def _kind(status: int) -> str:
    return "http_5xx" if status >= 500 else "http_4xx"


class Upstreams:
    def __init__(
        self,
        cfg: UpstreamsConfig,
        stamp_key: bytes,
        transports: Mapping[str, httpx.AsyncBaseTransport] | None = None,
    ) -> None:
        self._cfg = cfg
        self._key = stamp_key
        transports = transports or {}
        self._clients: dict[str, httpx.AsyncClient] = {}
        for route in ("local", "public"):
            up = getattr(cfg, route)
            headers = {"accept": "application/json, text/event-stream"}
            if up.api_key:
                headers["authorization"] = f"Bearer {up.api_key}"
            self._clients[route] = httpx.AsyncClient(
                trust_env=False,
                follow_redirects=False,
                timeout=httpx.Timeout(up.timeout_s, connect=min(10.0, up.timeout_s)),
                headers=headers,
                transport=transports.get(route),
            )

    # ------------------------------------------------------------------ guard

    def stamp(self, route: Route, body: Mapping[str, Any]) -> str:
        return make_stamp(self._key, route, body)

    def _guard(self, route: Route, url: str, body: Mapping[str, Any] | None, stamp: str | None) -> None:
        host = (urlsplit(url).hostname or "").lower()
        if route == "local":
            if host not in self._cfg.local_hosts:
                self._blocked(route, "host_not_local")
            return
        if route != "public":
            self._blocked("local", "unknown_route")
        if body is None or not stamp:
            self._blocked(route, "missing_stamp")
        expected = make_stamp(self._key, "public", body)  # type: ignore[arg-type]
        if not hmac.compare_digest(expected, stamp):  # type: ignore[arg-type]
            self._blocked(route, "stamp_mismatch")
        if host in self._cfg.local_hosts or host != urlsplit(self._cfg.public.base_url).hostname:
            self._blocked(route, "host_mismatch")

    def _blocked(self, route: str, why: str) -> None:
        metrics.egress(route, "blocked")
        log.error("blocked_external_call", route=route, why=why)
        raise EgressBlocked(why)

    # ------------------------------------------------------------------ send

    def _url(self, route: Route, path: str) -> str:
        return getattr(self._cfg, route).base_url + path

    async def send(
        self,
        route: Route,
        path: str,
        body: dict[str, Any],
        stamp: str | None,
        stream: bool,
    ) -> UpstreamResponse:
        """POST body (exactly as stamped) to route's base_url + path."""
        url = self._url(route, path)
        self._guard(route, url, body, stamp)
        content = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        metrics.egress(route, "allowed")
        if route == "public":
            log.event("external_call_allowed", route=route, path=path, body_sha256=body_digest(body)[:16])
        return await self._do(route, "POST", url, content, {"content-type": "application/json"}, stream)

    async def send_passthrough(
        self, method: str, path: str, content: bytes, content_type: str | None
    ) -> UpstreamResponse:
        """Local-only passthrough for endpoints listed in upstreams.local.passthrough_paths."""
        url = self._url("local", path)
        self._guard("local", url, None, None)
        metrics.egress("local", "allowed")
        headers = {"content-type": content_type} if content_type else {}
        return await self._do("local", method, url, content, headers, stream=False)

    async def _do(
        self, route: Route, method: str, url: str, content: bytes, headers: dict[str, str], stream: bool
    ) -> UpstreamResponse:
        client = self._clients[route]
        req = client.build_request(method, url, content=content, headers=headers)
        t0 = time.perf_counter()
        try:
            resp = await client.send(req, stream=True)
        except httpx.TimeoutException:
            metrics.upstream_error(route, "timeout")
            raise UpstreamFailure(504, "timeout") from None
        except httpx.HTTPError:
            metrics.upstream_error(route, "transport")
            raise UpstreamFailure(502, "transport") from None
        metrics.UPSTREAM_TTFB.labels(route=route).observe(time.perf_counter() - t0)

        if resp.status_code >= 400 or (300 <= resp.status_code < 400):
            await resp.aclose()
            kind = _kind(resp.status_code)  # redirects are never followed; counted as http_4xx
            metrics.upstream_error(route, kind)
            raise UpstreamFailure(502, kind)

        ctype = resp.headers.get("content-type", "application/json")
        if not stream:
            try:
                data = await resp.aread()
            except httpx.TimeoutException:
                metrics.upstream_error(route, "timeout")
                raise UpstreamFailure(504, "timeout") from None
            except httpx.HTTPError:
                metrics.upstream_error(route, "transport")
                raise UpstreamFailure(502, "transport") from None
            finally:
                await resp.aclose()
            return UpstreamResponse(resp.status_code, ctype, content=data)

        async def body_iter() -> AsyncIterator[bytes]:
            try:
                async for chunk in resp.aiter_raw():
                    yield chunk
            except httpx.TimeoutException:
                metrics.upstream_error(route, "timeout")
            except httpx.HTTPError:
                metrics.upstream_error(route, "transport")
            finally:
                await resp.aclose()

        return UpstreamResponse(resp.status_code, ctype, stream=body_iter(), close=resp.aclose)

    # ------------------------------------------------------------------ misc

    async def probe_local(self) -> bool:
        """privacy_up{dependency="local"}. Never probes the public upstream."""
        url = self._url("local", "/models")
        try:
            self._guard("local", url, None, None)
            resp = await self._clients["local"].get(url, timeout=5.0)
            return resp.status_code == 200
        except Exception:  # noqa: BLE001
            return False

    async def aclose(self) -> None:
        for c in self._clients.values():
            await c.aclose()
