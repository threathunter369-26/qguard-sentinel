"""Job handler registry.

A handler is an async callable that takes a :class:`JobContext` and either
returns a result dictionary or raises. Mapping job kinds to handlers in a
registry means a new background capability is added by registering a handler,
not by editing the worker loop.
"""

from __future__ import annotations

import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from qguard.workers.queue import ClaimedJob, JobQueue
from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(slots=True)
class JobContext:
    """What a handler is given for one job."""

    job: ClaimedJob
    session: AsyncSession
    queue: JobQueue
    worker_id: str
    scratch_dir: str | None = None
    stats: dict[str, Any] = field(default_factory=dict)

    @property
    def org_id(self) -> uuid.UUID:
        return self.job.org_id

    @property
    def payload(self) -> dict[str, Any]:
        return self.job.payload

    async def progress(self, percent: int, message: str) -> bool:
        """Report progress and extend the lease.

        Returns ``False`` when cancellation has been requested, which the
        handler should honour by stopping cleanly — a worker killed mid-write
        could leave a scan half-ingested.
        """
        return await self.queue.heartbeat(self.job.job_id, progress=percent, message=message)

    def option(self, key: str, default: Any = None) -> Any:
        return self.payload.get(key, default)


JobHandler = Callable[[JobContext], Awaitable[dict[str, Any]]]

_handlers: dict[str, JobHandler] = {}


def register_handler(kind: str) -> Callable[[JobHandler], JobHandler]:
    def decorator(handler: JobHandler) -> JobHandler:
        if kind in _handlers and _handlers[kind] is not handler:
            raise ValueError(f"A handler for job kind {kind!r} is already registered.")
        _handlers[kind] = handler
        return handler

    return decorator


def get_handler(kind: str) -> JobHandler | None:
    return _handlers.get(kind)


def registered_kinds() -> list[str]:
    return sorted(_handlers)
