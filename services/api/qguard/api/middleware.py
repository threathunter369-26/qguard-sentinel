"""HTTP middleware: request identity, security headers, rate limiting, size caps.

Each middleware addresses a specific requirement from the platform's own
hardening checklist. They are deliberately small and independent so one can be
replaced (for example, swapping the in-process rate limiter for a shared one)
without touching the others.
"""

from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp

from qguard.common.config import get_settings
from qguard.common.logging import (
    actor_id_var,
    get_logger,
    org_id_var,
    request_id_var,
)

log = get_logger(__name__)

RequestHandler = Callable[[Request], Awaitable[Response]]


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assign a request id, bind logging context and record timing.

    The id is echoed as ``X-Request-ID`` and stored on every audit entry, so a
    user-reported problem can be traced to exact log lines and audit records.
    """

    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        incoming = request.headers.get("x-request-id", "")
        # An inbound id is accepted for trace continuity but constrained, since
        # it ends up in logs and in the audit trail.
        request_id = (
            incoming
            if incoming and len(incoming) <= 64 and incoming.replace("-", "").isalnum()
            else str(uuid.uuid4())
        )
        request.state.request_id = request_id
        token = request_id_var.set(request_id)
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            duration_ms = (time.perf_counter() - started) * 1000
            log.exception(
                "http.request_failed",
                method=request.method,
                path=request.url.path,
                duration_ms=round(duration_ms, 2),
            )
            raise
        finally:
            request_id_var.reset(token)
            actor_id_var.set(None)
            org_id_var.set(None)

        duration_ms = (time.perf_counter() - started) * 1000
        response.headers["X-Request-ID"] = request_id
        response.headers["Server-Timing"] = f"app;dur={duration_ms:.1f}"
        if request.url.path not in ("/health", "/health/live", "/metrics"):
            log.info(
                "http.request",
                method=request.method,
                path=request.url.path,
                status=response.status_code,
                duration_ms=round(duration_ms, 2),
            )
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Apply defensive response headers.

    The API serves JSON, so the CSP is maximally restrictive: nothing is meant
    to be loaded or framed from an API response, and a permissive policy here
    would only help an attacker who found a reflected-content bug.
    """

    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        response = await call_next(request)
        settings = get_settings()

        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        )
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=(), payment=(), usb=()",
        )
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")

        # Security findings, evidence metadata and reports must not be cached
        # by an intermediary or left in a browser's disk cache.
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store, no-cache, must-revalidate")
            response.headers.setdefault("Pragma", "no-cache")

        if settings.is_production or settings.secure_cookies:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response


class BodySizeLimitMiddleware:
    """Reject oversized bodies before they are buffered.

    Checked from ``Content-Length`` so a large upload is refused at the first
    byte rather than after the platform has already read it into memory.
    """

    def __init__(self, app: ASGIApp, max_bytes: int | None = None) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        limit = self.max_bytes or get_settings().max_upload_bytes
        headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope["headers"]}
        content_length = headers.get("content-length")
        if content_length and content_length.isdigit() and int(content_length) > limit:
            response = JSONResponse(
                status_code=413,
                content={
                    "error": {
                        "code": "payload_too_large",
                        "message": (
                            f"The request body is {int(content_length)} bytes, which exceeds "
                            f"the {limit} byte limit."
                        ),
                    }
                },
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Sliding-window rate limiter.

    In-process and therefore per-instance: adequate for a single deployment and
    for slowing credential stuffing, but a horizontally scaled deployment
    should enforce limits at the ingress as well. Authentication endpoints get
    a much tighter budget than the rest of the API, since that is where
    guessing attacks land.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._auth_paths = (
            "/api/v1/auth/login",
            "/api/v1/auth/mfa/verify",
            "/api/v1/auth/refresh",
            "/api/v1/auth/password",
        )

    @staticmethod
    def _parse(spec: str) -> tuple[int, float]:
        count, _, unit = spec.partition("/")
        seconds = {"second": 1.0, "minute": 60.0, "hour": 3600.0, "day": 86400.0}.get(
            unit.strip().lower(), 60.0
        )
        try:
            return int(count), seconds
        except ValueError:
            return 300, 60.0

    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        settings = get_settings()
        if not settings.rate_limit_enabled or request.url.path in (
            "/health",
            "/health/live",
            "/health/ready",
            "/metrics",
        ):
            return await call_next(request)

        is_auth = any(request.url.path.startswith(p) for p in self._auth_paths)
        limit, window = self._parse(
            settings.rate_limit_auth if is_auth else settings.rate_limit_default
        )

        # Key on the credential where there is one, so a shared NAT address
        # does not let one caller exhaust everybody else's budget.
        api_key = request.headers.get("x-api-key")
        auth = request.headers.get("authorization", "")
        if api_key:
            identity = f"key:{api_key[:12]}"
        elif auth.lower().startswith("bearer "):
            identity = f"tok:{auth[7:39]}"
        else:
            identity = f"ip:{request.client.host if request.client else 'unknown'}"
        bucket_key = f"{'auth' if is_auth else 'api'}:{identity}"

        now = time.monotonic()
        bucket = self._hits[bucket_key]
        while bucket and now - bucket[0] > window:
            bucket.popleft()

        if len(bucket) >= limit:
            retry_after = max(1, int(window - (now - bucket[0])))
            log.warning(
                "http.rate_limited",
                path=request.url.path,
                bucket=bucket_key.split(":")[0],
                limit=limit,
            )
            response = JSONResponse(
                status_code=429,
                content={
                    "error": {
                        "code": "rate_limit_exceeded",
                        "message": (
                            f"Too many requests: the limit is {limit} per "
                            f"{int(window)} seconds. Retry in {retry_after} seconds."
                        ),
                    }
                },
            )
            response.headers["Retry-After"] = str(retry_after)
            response.headers["X-RateLimit-Limit"] = str(limit)
            response.headers["X-RateLimit-Remaining"] = "0"
            return response

        bucket.append(now)
        passthrough: Response = await call_next(request)
        passthrough.headers["X-RateLimit-Limit"] = str(limit)
        passthrough.headers["X-RateLimit-Remaining"] = str(max(0, limit - len(bucket)))

        # Keep the dictionary from growing without bound on a long-lived process.
        if len(self._hits) > 20_000:
            stale = [k for k, v in self._hits.items() if not v or now - v[-1] > window * 2]
            for key in stale:
                self._hits.pop(key, None)
        return response
