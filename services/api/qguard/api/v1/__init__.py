"""Version 1 of the HTTP API.

Routers are mounted here so the whole surface is visible in one place and the
URL layout stays stable as modules are added.
"""

from __future__ import annotations

from fastapi import APIRouter

from qguard.api.v1.routers import assets, auth

# Health is mounted at the application root by the app factory, not here:
# a liveness probe must not sit behind a versioned prefix.
api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(assets.router)

__all__ = ["api_router"]
