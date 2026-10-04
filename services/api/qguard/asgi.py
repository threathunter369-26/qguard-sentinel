"""ASGI entry point for uvicorn, gunicorn and container runtimes."""

from __future__ import annotations

from qguard.app import create_app

app = create_app()
