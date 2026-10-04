"""Liveness, readiness and build information."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Response
from sqlalchemy.ext.asyncio import AsyncSession

from qguard import __version__
from qguard.api.deps import get_session
from qguard.common.config import get_settings
from qguard.common.database import healthcheck
from qguard.common.events import get_event_bus
from qguard.common.logging import get_logger

log = get_logger(__name__)
router = APIRouter(tags=["health"])


@router.get("/health/live", summary="Liveness probe")
async def live() -> dict[str, str]:
    """Confirms the process is running. Deliberately does no I/O."""
    return {"status": "ok"}


@router.get("/health", summary="Health and readiness")
async def health(
    response: Response,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """Reports dependency health.

    Returns 503 when the database is unreachable so an orchestrator removes
    the instance from rotation rather than serving failing requests.
    """
    settings = get_settings()
    payload: dict[str, Any] = {
        "status": "ok",
        "version": __version__,
        "environment": settings.env,
        "instance": settings.instance_name,
        "checks": {},
    }

    try:
        db = await healthcheck(session)
        payload["checks"]["database"] = {
            "status": "ok" if db["connected"] else "error",
            "schema_version": db["schema_version"],
        }
    except Exception as exc:
        log.warning("health.database_unavailable", error=str(exc))
        payload["checks"]["database"] = {"status": "error", "error": str(exc)[:200]}
        payload["status"] = "degraded"
        response.status_code = 503

    payload["checks"]["event_bus"] = {
        "status": "ok",
        "subscribers": get_event_bus().subscriber_count,
    }
    return payload


@router.get("/health/ready", summary="Readiness probe")
async def ready(
    response: Response,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    """Confirms the schema is migrated to a known revision.

    An instance running against an un-migrated database is not ready: it would
    fail on first use in a way that looks like data loss.
    """
    try:
        db = await healthcheck(session)
    except Exception as exc:
        response.status_code = 503
        return {"ready": False, "reason": f"The database is unreachable: {exc}"}

    if not db["schema_version"]:
        response.status_code = 503
        return {
            "ready": False,
            "reason": "The database schema has not been migrated. Run `alembic upgrade head`.",
        }
    return {"ready": True, "schema_version": db["schema_version"]}
