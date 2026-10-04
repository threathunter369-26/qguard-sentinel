"""FastAPI dependencies: database sessions, the principal, and authorization.

One database session per request, inside one transaction. Tenant context is
applied to that transaction as soon as authentication resolves the
organization, so every subsequent query in the request is covered by row level
security as well as by the explicit application-level filters.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Callable
from typing import Annotated

from fastapi import Depends, Header, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from qguard.audit.service import AuditContext, AuditService
from qguard.auth.principal import Principal
from qguard.auth.service import AuthService
from qguard.common.database import get_session_factory
from qguard.common.errors import (
    AuthenticationError,
    NotFoundError,
    PermissionDeniedError,
)
from qguard.common.logging import actor_id_var, get_logger, org_id_var

log = get_logger(__name__)

#: `auto_error=False` so a missing header produces the platform's own error
#: envelope rather than FastAPI's default shape.
bearer_scheme = HTTPBearer(auto_error=False, scheme_name="Bearer token")

API_KEY_HEADER = "X-API-Key"


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    """One transactional session per request."""
    factory = get_session_factory()
    async with factory() as session:
        await session.begin()
        request.state.db_session = session
        try:
            yield session
            if session.in_transaction():
                await session.commit()
        except Exception:
            if session.in_transaction():
                await session.rollback()
            raise


def get_audit_context(request: Request) -> AuditContext:
    return AuditContext(
        request_id=getattr(request.state, "request_id", None),
        ip_address=client_ip(request),
        user_agent=request.headers.get("user-agent"),
        request_method=request.method,
        request_path=request.url.path,
    )


def client_ip(request: Request) -> str | None:
    """Best-effort client address.

    ``X-Forwarded-For`` is only trusted when the platform is configured to run
    behind a proxy, because an unvalidated header would let a caller forge the
    address recorded in the audit trail.
    """
    from qguard.common.config import get_settings

    settings = get_settings()
    if settings.trusted_hosts:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()[:64]
    return request.client.host if request.client else None


async def get_auth_service(
    session: Annotated[AsyncSession, Depends(get_session)],
    audit_context: Annotated[AuditContext, Depends(get_audit_context)],
) -> AuthService:
    return AuthService(session, audit_context)


async def get_principal(
    request: Request,
    session: Annotated[AsyncSession, Depends(get_session)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)] = None,
    api_key: Annotated[str | None, Header(alias=API_KEY_HEADER)] = None,
) -> Principal:
    """Authenticate the request and resolve the caller's permissions.

    Accepts a bearer access token or an API key, never both: presenting two
    credentials is ambiguous about which identity should be audited.
    """
    if credentials is not None and api_key:
        raise AuthenticationError("Send either a bearer token or an API key, not both.")

    service = AuthService(session, get_audit_context(request))
    ip = client_ip(request)
    user_agent = request.headers.get("user-agent")

    if api_key:
        principal = await service.principal_from_api_key(
            api_key, ip_address=ip, user_agent=user_agent
        )
    elif credentials is not None and credentials.scheme.lower() == "bearer":
        principal = await service.principal_from_access_token(
            credentials.credentials, ip_address=ip, user_agent=user_agent
        )
    else:
        raise AuthenticationError(
            "This endpoint requires authentication. Send an Authorization: Bearer "
            f"header or an {API_KEY_HEADER} header."
        )

    request.state.principal = principal
    actor_id_var.set(str(principal.user_id) if principal.user_id else None)
    org_id_var.set(str(principal.org_id))
    return principal


CurrentPrincipal = Annotated[Principal, Depends(get_principal)]
DbSession = Annotated[AsyncSession, Depends(get_session)]


async def get_audit_service(
    session: DbSession,
    audit_context: Annotated[AuditContext, Depends(get_audit_context)],
) -> AuditService:
    return AuditService(session, audit_context)


AuditDep = Annotated[AuditService, Depends(get_audit_service)]


def require_permission(*permissions: str, require_all: bool = False) -> Callable[..., Principal]:
    """Dependency factory enforcing one or more permissions.

    The check is server-side and unconditional. The frontend also hides
    controls the caller lacks, but that is presentation; this is the control.
    """

    async def _dependency(principal: CurrentPrincipal) -> Principal:
        if require_all:
            _require_all(principal, permissions)
        elif len(permissions) == 1:
            principal.require(permissions[0])
        else:
            principal.require_any(*permissions)
        return principal

    return _dependency


def _require_all(principal: Principal, permissions: tuple[str, ...]) -> None:
    missing = [p for p in permissions if not principal.has_permission(p)]
    if missing:
        raise PermissionDeniedError(
            "This action requires permissions you do not hold.",
            details={"missing_permissions": sorted(missing)},
        )


def require_mfa(principal: CurrentPrincipal) -> Principal:
    """Require that the current session actually completed a second factor.

    Applied to the most sensitive operations (evidence export, authorization
    approval) so a stolen access token alone is not enough.
    """
    if not principal.mfa_satisfied:
        raise PermissionDeniedError(
            "This action requires a session verified with multi-factor authentication.",
            code="mfa_verification_required",
        )
    return principal


MfaVerified = Annotated[Principal, Depends(require_mfa)]


async def resolve_project_id(
    principal: CurrentPrincipal,
    project_id: uuid.UUID | None = None,
) -> uuid.UUID | None:
    """Validate an optional project filter against the caller's access."""
    if project_id is None:
        return None
    if not principal.has_permission_in_project("project:read", project_id):
        # A project in another tenant is invisible under RLS, so a 404 here is
        # accurate and avoids confirming that the id exists elsewhere.
        raise NotFoundError("That project was not found.")
    return project_id
