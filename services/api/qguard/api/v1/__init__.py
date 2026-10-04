"""Version 1 of the HTTP API.

Routers are mounted here so the whole surface is visible in one place and the
URL layout stays stable as modules are added.
"""

from __future__ import annotations

from fastapi import APIRouter

from qguard.api.v1.routers import auth

api_router = APIRouter()
api_router.include_router(auth.router)

__all__ = ["api_router"]
