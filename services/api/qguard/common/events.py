"""In-process publish/subscribe bus backing real-time UI updates.

Workers and API handlers publish domain events; SSE and WebSocket endpoints
subscribe and relay them to connected clients. This removes the need for the
frontend to poll for scan progress.

Events are fanned out per organization, and a subscriber only ever receives
events for the organization its token resolved to — the transport cannot be used
to cross a tenant boundary.

A single-process bus is adequate for one API instance. For horizontally scaled
deployments the same interface is backed by PostgreSQL ``LISTEN/NOTIFY``
(:class:`PostgresEventBridge`), so publishers and subscribers need no changes.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from qguard.common.logging import get_logger

log = get_logger(__name__)

#: Bounded per-subscriber queue. A slow client is dropped rather than allowed
#: to grow memory without limit.
SUBSCRIBER_QUEUE_SIZE = 256


@dataclass(slots=True)
class Event:
    """A real-time domain event."""

    type: str
    org_id: str
    payload: dict[str, Any] = field(default_factory=dict)
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    at: datetime = field(default_factory=lambda: datetime.now(UTC))
    resource_type: str | None = None
    resource_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "at": self.at.isoformat(),
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "payload": self.payload,
        }

    def to_sse(self) -> str:
        body = json.dumps(self.to_dict(), default=str)
        return f"id: {self.id}\nevent: {self.type}\ndata: {body}\n\n"


class EventBus:
    """Async fan-out bus with per-organization topics."""

    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue[Event]]] = {}
        self._lock = asyncio.Lock()
        self._dropped = 0

    async def publish(self, event: Event) -> None:
        async with self._lock:
            queues = list(self._subscribers.get(event.org_id, ()))
        for queue in queues:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                # Never block a publisher on a stalled client.
                self._dropped += 1
                log.warning(
                    "event_bus.subscriber_lagging",
                    event_type=event.type,
                    dropped_total=self._dropped,
                )

    async def publish_many(self, events: list[Event]) -> None:
        for event in events:
            await self.publish(event)

    @contextlib.asynccontextmanager
    async def subscribe(self, org_id: str) -> AsyncIterator[asyncio.Queue[Event]]:
        queue: asyncio.Queue[Event] = asyncio.Queue(maxsize=SUBSCRIBER_QUEUE_SIZE)
        async with self._lock:
            self._subscribers.setdefault(org_id, set()).add(queue)
        try:
            yield queue
        finally:
            async with self._lock:
                bucket = self._subscribers.get(org_id)
                if bucket is not None:
                    bucket.discard(queue)
                    if not bucket:
                        self._subscribers.pop(org_id, None)

    async def stream(
        self,
        org_id: str,
        *,
        types: set[str] | None = None,
        keepalive_seconds: float = 20.0,
    ) -> AsyncIterator[Event | None]:
        """Yield events for an organization; ``None`` signals a keepalive tick."""
        async with self.subscribe(org_id) as queue:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=keepalive_seconds)
                except TimeoutError:
                    yield None
                    continue
                if types and event.type not in types:
                    continue
                yield event

    @property
    def subscriber_count(self) -> int:
        return sum(len(queues) for queues in self._subscribers.values())


_bus: EventBus | None = None


def get_event_bus() -> EventBus:
    global _bus
    if _bus is None:
        _bus = EventBus()
    return _bus


async def emit(
    event_type: str,
    org_id: uuid.UUID | str,
    payload: dict[str, Any] | None = None,
    *,
    resource_type: str | None = None,
    resource_id: uuid.UUID | str | None = None,
) -> Event:
    """Convenience publisher used throughout the services layer."""
    event = Event(
        type=event_type,
        org_id=str(org_id),
        payload=payload or {},
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id else None,
    )
    await get_event_bus().publish(event)
    return event


class EventType:
    """Canonical real-time event names (also the SSE ``event:`` field)."""

    SCAN_QUEUED = "scan.queued"
    SCAN_STARTED = "scan.started"
    SCAN_PROGRESS = "scan.progress"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    ENGINE_STARTED = "engine.started"
    ENGINE_PROGRESS = "engine.progress"
    ENGINE_COMPLETED = "engine.completed"
    ENGINE_FAILED = "engine.failed"
    JOB_UPDATED = "job.updated"
    FINDING_CREATED = "finding.created"
    VULNERABILITY_CREATED = "vulnerability.created"
    VULNERABILITY_UPDATED = "vulnerability.updated"
    EVIDENCE_UPLOADED = "evidence.uploaded"
    EVIDENCE_PROCESSED = "evidence.processed"
    INCIDENT_CREATED = "incident.created"
    INCIDENT_UPDATED = "incident.updated"
    IOC_MATCHED = "ioc.matched"
    REPORT_READY = "report.ready"
    REPORT_FAILED = "report.failed"
    RISK_RECALCULATED = "risk.recalculated"
    SECURITY_EVENT = "security.event"
    NOTIFICATION = "notification.created"
