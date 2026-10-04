"""FastAPI application factory.

Assembles middleware, exception handlers and the versioned router tree. Kept
separate from any module-level app instance so tests can build an isolated
application per configuration.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import ValidationError as PydanticValidationError
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from qguard import __version__
from qguard.api.middleware import (
    BodySizeLimitMiddleware,
    RateLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from qguard.common.config import get_settings
from qguard.common.database import dispose_engine, session_scope
from qguard.common.errors import ConflictError, QGuardError, ValidationError
from qguard.common.logging import configure_logging, get_logger

log = get_logger(__name__)

DESCRIPTION = """
Unified security assessment, penetration testing, digital forensics and
incident response platform for authorized internal security operations.

**Authentication.** Send `Authorization: Bearer <access token>` or
`X-API-Key: <key>`. Access tokens are short-lived; rotate them with
`POST /api/v1/auth/refresh`.

**Authorization.** Every endpoint enforces a fine-grained permission
server-side. `GET /api/v1/auth/me` returns the caller's effective permissions.

**Tenancy.** Every request is scoped to the caller's organization by both
PostgreSQL row level security and application-level filtering.

**Active testing.** Engines that send traffic to a target refuse to run unless
an approved, in-date test authorization covers that target. A refusal is
recorded as an `unauthorized` engine run and audited; it is never reported as
a clean result.
""".strip()

TAGS_METADATA: list[dict[str, Any]] = [
    {"name": "health", "description": "Liveness, readiness and build information."},
    {"name": "auth", "description": "Sign-in, MFA, sessions and API keys."},
    {"name": "dashboard", "description": "Security posture metrics derived from platform data."},
    {"name": "assets", "description": "Asset inventory and relationships."},
    {"name": "authorizations", "description": "Test authorizations governing active assessment."},
    {"name": "scans", "description": "Scan orchestration, engine runs and profiles."},
    {"name": "findings", "description": "Raw per-engine observations."},
    {"name": "vulnerabilities", "description": "Correlated, deduplicated issues under management."},
    {"name": "secrets", "description": "Detected credentials, always redacted."},
    {"name": "sast", "description": "Static application security testing."},
    {"name": "sca", "description": "Software composition analysis and dependency risk."},
    {"name": "web", "description": "Web application assessment."},
    {"name": "api-security", "description": "API inventory and endpoint assessment."},
    {"name": "mobile", "description": "Android and iOS package analysis."},
    {"name": "infrastructure", "description": "Container, Kubernetes and network assessment."},
    {"name": "cloud", "description": "Cloud posture via provider adapters."},
    {"name": "crypto", "description": "Cryptographic inventory and post-quantum readiness."},
    {"name": "risk", "description": "Risk scoring with a transparent factor breakdown."},
    {"name": "pentest", "description": "Penetration testing engagements."},
    {"name": "dfir", "description": "Forensic cases, artifacts and timelines."},
    {"name": "evidence", "description": "Evidence ingestion, integrity and chain of custody."},
    {"name": "incidents", "description": "Incident response lifecycle."},
    {"name": "threat-intelligence", "description": "Indicators, actors, campaigns and feeds."},
    {"name": "compliance", "description": "Framework mapping and control assessment."},
    {"name": "reports", "description": "Report generation and download."},
    {"name": "audit", "description": "Tamper-evident audit trail."},
    {"name": "jobs", "description": "Background job visibility and control."},
    {"name": "events", "description": "Real-time event streams (SSE and WebSocket)."},
    {"name": "admin", "description": "Organization, user, team and project administration."},
]


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Start-up and shutdown.

    Start-up is intentionally light: it verifies the database is reachable and
    reconciles the built-in roles and permission catalogue, so a platform
    upgrade that adds a permission takes effect without a manual step.
    """
    settings = get_settings()
    configure_logging()
    log.info(
        "platform.starting",
        version=__version__,
        env=settings.env,
        auth_provider=settings.auth_provider,
        storage_backend=settings.storage_backend,
    )

    try:
        async with session_scope() as session:
            from qguard.auth.rbac import ensure_system_roles

            roles = await ensure_system_roles(session)
            log.info("platform.roles_ready", role_count=len(roles))
    except Exception as exc:
        # Refusing to serve is correct here: running without the permission
        # catalogue would mean every authorization check silently denies.
        log.error("platform.startup_failed", error=str(exc), exc_info=True)
        raise

    app.state.ready = True
    try:
        yield
    finally:
        app.state.ready = False
        log.info("platform.stopping")
        await dispose_engine()


def create_app(**overrides: Any) -> FastAPI:
    settings = get_settings()
    configure_logging()

    app = FastAPI(
        title="QGuard Sentinel",
        description=DESCRIPTION,
        version=__version__,
        openapi_tags=TAGS_METADATA,
        lifespan=lifespan,
        root_path=settings.api_root_path,
        # Interactive docs are useful internally but are not exposed in
        # production, where the schema would advertise the attack surface.
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None if settings.is_production else "/redoc",
        openapi_url=None if settings.is_production else "/openapi.json",
        swagger_ui_parameters={"persistAuthorization": True},
        **overrides,
    )

    _install_middleware(app, settings)
    _install_exception_handlers(app)
    _install_routers(app)
    return app


def _install_middleware(app: FastAPI, settings: Any) -> None:
    # Order matters: the outermost middleware runs first on the way in. Body
    # size is checked before anything reads the body; the request id is bound
    # before anything logs.
    app.add_middleware(BodySizeLimitMiddleware)
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)

    if settings.rate_limit_enabled:
        app.add_middleware(RateLimitMiddleware)

    if settings.trusted_hosts and settings.is_production:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts)

    if settings.cors_origins:
        app.add_middleware(
            CORSMiddleware,
            # Explicit origins only. `allow_credentials` with a wildcard is
            # refused by browsers anyway, and the production config validator
            # rejects a wildcard outright.
            allow_origins=settings.cors_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
            allow_headers=[
                "Authorization",
                "Content-Type",
                "X-API-Key",
                "X-Request-ID",
                "Accept",
            ],
            expose_headers=["X-Request-ID", "X-RateLimit-Remaining", "Retry-After"],
            max_age=600,
        )


def _install_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(QGuardError)
    async def handle_qguard_error(request: Request, exc: QGuardError) -> JSONResponse:
        request_id = getattr(request.state, "request_id", None)
        if exc.status_code >= 500:
            log.error(
                "api.error",
                code=exc.code,
                message=exc.message,
                path=request.url.path,
                exc_info=True,
            )
        else:
            log.info("api.client_error", code=exc.code, path=request.url.path)
        headers = {}
        if exc.status_code == 401:
            headers["WWW-Authenticate"] = "Bearer"
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.to_payload(request_id),
            headers=headers,
        )

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        # Normalised into the platform's envelope, with the offending field
        # paths but without echoing the submitted values, which may be secrets.
        errors = [
            {
                "field": ".".join(str(p) for p in err.get("loc", ())[1:]) or "body",
                "message": err.get("msg", "Invalid value."),
                "type": err.get("type"),
            }
            for err in exc.errors()
        ]
        return JSONResponse(
            status_code=422,
            content=ValidationError(
                "The request could not be processed because of invalid input.",
                details={"errors": errors},
            ).to_payload(getattr(request.state, "request_id", None)),
        )

    @app.exception_handler(PydanticValidationError)
    async def handle_pydantic_error(request: Request, exc: PydanticValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=422,
            content=ValidationError(
                "A value failed validation.",
                details={"errors": [e.get("msg", "") for e in exc.errors()]},
            ).to_payload(getattr(request.state, "request_id", None)),
        )

    @app.exception_handler(IntegrityError)
    async def handle_integrity_error(request: Request, exc: IntegrityError) -> JSONResponse:
        # A constraint the platform relies on was violated. The constraint name
        # is reported because the schema's constraints encode real domain rules
        # ("a failed engine run must state a reason"), and naming the one that
        # fired is what makes the response actionable. The SQL itself is not.
        constraint = getattr(getattr(exc.orig, "diag", None), "constraint_name", None)
        log.warning(
            "api.integrity_error",
            constraint=constraint,
            path=request.url.path,
        )
        message = "The request conflicts with a constraint on the stored data."
        if constraint and constraint.startswith("uq_"):
            message = "A record with those identifying values already exists."
        return JSONResponse(
            status_code=409,
            content=ConflictError(
                message,
                details={"constraint": constraint} if constraint else None,
            ).to_payload(getattr(request.state, "request_id", None)),
        )

    @app.exception_handler(SQLAlchemyError)
    async def handle_database_error(request: Request, exc: SQLAlchemyError) -> JSONResponse:
        log.error("api.database_error", path=request.url.path, exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "database_error",
                    "message": "The database could not complete the request.",
                    "request_id": getattr(request.state, "request_id", None),
                }
            },
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_exception(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        codes = {
            400: "bad_request",
            401: "authentication_required",
            403: "permission_denied",
            404: "not_found",
            405: "method_not_allowed",
            409: "conflict",
            413: "payload_too_large",
            415: "unsupported_media_type",
            429: "rate_limit_exceeded",
        }
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": codes.get(exc.status_code, "http_error"),
                    "message": str(exc.detail),
                    "request_id": getattr(request.state, "request_id", None),
                }
            },
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(Exception)
    async def handle_unexpected(request: Request, exc: Exception) -> JSONResponse:
        # Full detail to the operator's logs, nothing but a correlation id to
        # the caller: a stack trace in a response body is an information leak.
        log.error(
            "api.unhandled_exception",
            path=request.url.path,
            error_type=type(exc).__name__,
            exc_info=True,
        )
        return JSONResponse(
            status_code=500,
            content={
                "error": {
                    "code": "internal_error",
                    "message": (
                        "An unexpected error occurred. Quote the request id when reporting this."
                    ),
                    "request_id": getattr(request.state, "request_id", None),
                }
            },
        )


def _install_routers(app: FastAPI) -> None:
    from qguard.api.v1 import api_router
    from qguard.api.v1.routers import health

    app.include_router(health.router)
    app.include_router(api_router, prefix="/api/v1")
