"""PostgreSQL-backed job queue.

Long-running work — scans, mobile package analysis, evidence processing, report
rendering — must never block an API request, so every such operation becomes a
durable job.

The queue lives in PostgreSQL rather than a separate broker. That is a
deliberate trade: the platform runs with one dependency instead of two, a job
and the rows it produces commit in the same transaction (so a scan can never
be recorded as finished while its findings are lost), and crash recovery falls
out of lease expiry. Claiming uses ``SELECT ... FOR UPDATE SKIP LOCKED`` inside
a SECURITY DEFINER function, so workers scale horizontally without contending
for or double-running a job.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from qguard.common.config import get_settings
from qguard.common.enums import JobKind, JobStatus
from qguard.common.events import EventType, emit
from qguard.common.logging import get_logger
from qguard.models.scanning import Job

log = get_logger(__name__)

#: Lower runs first. Interactive work must not queue behind a nightly sweep.
PRIORITY = {
    "interactive": 10,
    "scan": 50,
    "analysis": 100,
    "correlation": 200,
    "report": 300,
    "intelligence": 500,
    "maintenance": 900,
}

DEFAULT_PRIORITY_BY_KIND: dict[str, int] = {
    JobKind.SCAN: PRIORITY["scan"],
    JobKind.WEB_ASSESSMENT: PRIORITY["scan"],
    JobKind.API_ASSESSMENT: PRIORITY["scan"],
    JobKind.NETWORK_ASSESSMENT: PRIORITY["scan"],
    JobKind.SAST_ANALYSIS: PRIORITY["analysis"],
    JobKind.SCA_ANALYSIS: PRIORITY["analysis"],
    JobKind.SECRETS_ANALYSIS: PRIORITY["analysis"],
    JobKind.MOBILE_ANALYSIS: PRIORITY["analysis"],
    JobKind.CONTAINER_ANALYSIS: PRIORITY["analysis"],
    JobKind.KUBERNETES_ANALYSIS: PRIORITY["analysis"],
    JobKind.CLOUD_ASSESSMENT: PRIORITY["analysis"],
    JobKind.CRYPTO_ASSESSMENT: PRIORITY["analysis"],
    JobKind.EVIDENCE_PROCESSING: PRIORITY["analysis"],
    JobKind.CORRELATION: PRIORITY["correlation"],
    JobKind.RISK_RECALCULATION: PRIORITY["correlation"],
    JobKind.COMPLIANCE_ASSESSMENT: PRIORITY["correlation"],
    JobKind.REPORT_GENERATION: PRIORITY["report"],
    JobKind.THREAT_INTEL_INGEST: PRIORITY["intelligence"],
    JobKind.RETENTION_SWEEP: PRIORITY["maintenance"],
}


@dataclass(slots=True)
class ClaimedJob:
    """A job leased to a worker."""

    job_id: uuid.UUID
    org_id: uuid.UUID
    kind: str
    payload: dict[str, Any]
    attempts: int
    max_attempts: int
    scan_id: uuid.UUID | None = None
    engine_run_id: uuid.UUID | None = None

    @property
    def is_final_attempt(self) -> bool:
        return self.attempts >= self.max_attempts


class JobQueue:
    """Enqueue, claim and complete background jobs."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    # ---------------------------------------------------------------- enqueue
    async def enqueue(
        self,
        *,
        org_id: uuid.UUID,
        kind: str,
        payload: dict[str, Any] | None = None,
        priority: int | None = None,
        scan_id: uuid.UUID | None = None,
        engine_run_id: uuid.UUID | None = None,
        report_id: uuid.UUID | None = None,
        evidence_id: uuid.UUID | None = None,
        requested_by: uuid.UUID | None = None,
        run_after: datetime | None = None,
        max_attempts: int | None = None,
    ) -> Job:
        settings = get_settings()
        job = Job(
            org_id=org_id,
            kind=kind,
            status=JobStatus.QUEUED,
            priority=priority if priority is not None else DEFAULT_PRIORITY_BY_KIND.get(kind, 100),
            payload=payload or {},
            scan_id=scan_id,
            engine_run_id=engine_run_id,
            report_id=report_id,
            evidence_id=evidence_id,
            requested_by=requested_by,
            run_after=run_after or datetime.now(UTC),
            max_attempts=max_attempts or settings.job_max_attempts,
        )
        self.session.add(job)
        await self.session.flush()
        log.info("job.enqueued", job_id=str(job.id), kind=kind, priority=job.priority)
        return job

    # ------------------------------------------------------------------ claim
    async def claim(
        self, worker_id: str, kinds: list[str] | None = None, lease_seconds: int | None = None
    ) -> ClaimedJob | None:
        """Atomically lease the next runnable job.

        Workers serve every tenant, so this goes through the privileged
        ``app.claim_next_job`` function. ``FOR UPDATE SKIP LOCKED`` inside that
        function is what lets several workers poll the same queue safely.
        """
        settings = get_settings()
        row = (
            await self.session.execute(
                text(
                    "SELECT job_id, org_id, kind, payload, attempts, max_attempts, "
                    "scan_id, engine_run_id "
                    "FROM app.claim_next_job(:worker, :kinds, :lease)"
                ),
                {
                    "worker": worker_id,
                    "kinds": kinds or [],
                    "lease": lease_seconds or settings.job_lease_seconds,
                },
            )
        ).first()
        if row is None:
            return None
        claimed = ClaimedJob(
            job_id=row[0],
            org_id=row[1],
            kind=row[2],
            payload=row[3] or {},
            attempts=row[4],
            max_attempts=row[5],
            scan_id=row[6],
            engine_run_id=row[7],
        )
        log.info(
            "job.claimed",
            job_id=str(claimed.job_id),
            kind=claimed.kind,
            attempt=claimed.attempts,
            worker=worker_id,
        )
        return claimed

    async def reclaim_expired(self) -> int:
        """Requeue jobs whose worker stopped responding.

        This is what makes the queue crash-safe: a worker that dies leaves a
        lease behind, and the job is retried rather than lost. A job that has
        exhausted its attempts is failed with a stated reason instead of
        sitting in ``running`` forever.
        """
        count = (await self.session.execute(text("SELECT app.reclaim_expired_jobs()"))).scalar_one()
        if count:
            log.warning("job.leases_reclaimed", count=int(count))
        return int(count)

    # ----------------------------------------------------------- progress
    async def heartbeat(
        self,
        job_id: uuid.UUID,
        *,
        progress: int | None = None,
        message: str | None = None,
        lease_seconds: int | None = None,
    ) -> bool:
        """Extend the lease and record progress.

        Returns ``False`` when cancellation has been requested, which the
        worker treats as a signal to stop cleanly.
        """
        settings = get_settings()
        values: dict[str, Any] = {
            "heartbeat_at": datetime.now(UTC),
            "lease_expires_at": datetime.now(UTC)
            + timedelta(seconds=lease_seconds or settings.job_lease_seconds),
        }
        if progress is not None:
            values["progress"] = max(0, min(100, progress))
        if message is not None:
            values["progress_message"] = message[:500]

        row = (
            await self.session.execute(
                update(Job)
                .where(Job.id == job_id)
                .values(**values)
                .returning(Job.cancel_requested, Job.org_id, Job.kind, Job.progress)
            )
        ).first()
        if row is None:
            return False
        cancel_requested, org_id, kind, current_progress = row

        if progress is not None:
            await emit(
                EventType.JOB_UPDATED,
                org_id,
                {
                    "job_id": str(job_id),
                    "kind": kind,
                    "progress": current_progress,
                    "message": message,
                },
                resource_type="job",
                resource_id=job_id,
            )
        return not cancel_requested

    # ----------------------------------------------------------- completion
    async def complete(self, job_id: uuid.UUID, result: dict[str, Any] | None = None) -> None:
        now = datetime.now(UTC)
        row = (
            await self.session.execute(
                update(Job)
                .where(Job.id == job_id)
                .values(
                    status=JobStatus.COMPLETED,
                    finished_at=now,
                    progress=100,
                    result=result or {},
                    locked_by=None,
                    lease_expires_at=None,
                    error_message=None,
                )
                .returning(Job.org_id, Job.kind, Job.started_at)
            )
        ).first()
        if row is None:
            return
        org_id, kind, started_at = row
        log.info(
            "job.completed",
            job_id=str(job_id),
            kind=kind,
            duration_seconds=round((now - started_at).total_seconds(), 2) if started_at else None,
        )
        await emit(
            EventType.JOB_UPDATED,
            org_id,
            {"job_id": str(job_id), "kind": kind, "status": "completed", "progress": 100},
            resource_type="job",
            resource_id=job_id,
        )

    async def fail(
        self,
        job_id: uuid.UUID,
        error: BaseException | str,
        *,
        traceback_text: str | None = None,
        retry: bool = True,
    ) -> bool:
        """Record a failure, retrying with backoff while attempts remain.

        Returns ``True`` when the job was requeued. The reason is always
        stored, so a failed job explains itself in the UI instead of appearing
        to have simply stopped.
        """
        message = str(error) if not isinstance(error, str) else error
        error_type = type(error).__name__ if isinstance(error, BaseException) else "JobError"

        job = (await self.session.execute(select(Job).where(Job.id == job_id))).scalar_one_or_none()
        if job is None:
            return False

        will_retry = retry and job.attempts < job.max_attempts
        now = datetime.now(UTC)

        if will_retry:
            # Exponential backoff: a transient dependency failure gets time to
            # recover rather than burning the retry budget in three seconds.
            delay = min(600, 15 * (2 ** (job.attempts - 1)))
            job.status = JobStatus.QUEUED
            job.run_after = now + timedelta(seconds=delay)
            job.locked_by = None
            job.locked_at = None
            job.lease_expires_at = None
            job.error_message = (
                f"{error_type}: {message} (attempt {job.attempts} of {job.max_attempts}; "
                f"retrying in {delay}s)"
            )
        else:
            job.status = JobStatus.FAILED
            job.finished_at = now
            job.locked_by = None
            job.lease_expires_at = None
            job.error_message = f"{error_type}: {message}"
        job.error_traceback = traceback_text

        log.error(
            "job.failed",
            job_id=str(job_id),
            kind=job.kind,
            attempt=job.attempts,
            will_retry=will_retry,
            error=message,
        )
        await emit(
            EventType.JOB_UPDATED,
            job.org_id,
            {
                "job_id": str(job_id),
                "kind": job.kind,
                "status": "queued" if will_retry else "failed",
                "error": job.error_message,
                "will_retry": will_retry,
            },
            resource_type="job",
            resource_id=job_id,
        )
        return will_retry

    async def request_cancel(self, job_id: uuid.UUID, org_id: uuid.UUID) -> bool:
        """Ask a job to stop.

        Cooperative: a queued job is cancelled at once, while a running job is
        flagged and stops at its next heartbeat. Killing a worker mid-write
        could leave a scan half-ingested, so the job is asked rather than
        terminated.
        """
        job = (
            await self.session.execute(select(Job).where(Job.id == job_id, Job.org_id == org_id))
        ).scalar_one_or_none()
        if job is None:
            return False
        if job.status == JobStatus.QUEUED:
            job.status = JobStatus.CANCELLED
            job.finished_at = datetime.now(UTC)
            job.error_message = "Cancelled before it started."
        elif job.status == JobStatus.RUNNING:
            job.cancel_requested = True
        else:
            return False
        return True

    async def is_cancel_requested(self, job_id: uuid.UUID) -> bool:
        return bool(
            (
                await self.session.execute(select(Job.cancel_requested).where(Job.id == job_id))
            ).scalar_one_or_none()
        )

    async def mark_cancelled(self, job_id: uuid.UUID) -> None:
        await self.session.execute(
            update(Job)
            .where(Job.id == job_id)
            .values(
                status=JobStatus.CANCELLED,
                finished_at=datetime.now(UTC),
                locked_by=None,
                lease_expires_at=None,
                error_message="Cancelled at the request of an operator.",
            )
        )

    # -------------------------------------------------------------- queries
    async def queue_depth(self, org_id: uuid.UUID | None = None) -> dict[str, int]:
        stmt = select(Job.status, Job.kind).where(
            Job.status.in_([JobStatus.QUEUED, JobStatus.RUNNING])
        )
        if org_id is not None:
            stmt = stmt.where(Job.org_id == org_id)
        rows = (await self.session.execute(stmt)).all()
        depth: dict[str, int] = {"queued": 0, "running": 0}
        for status, kind in rows:
            depth[status] = depth.get(status, 0) + 1
            depth[f"{status}:{kind}"] = depth.get(f"{status}:{kind}", 0) + 1
        return depth

    async def purge_old(self, retention_days: int | None = None) -> int:
        """Delete long-finished jobs.

        Jobs are operational telemetry, not security records: the audit trail
        and the scan history are what persist. Keeping every job row forever
        would bloat the busiest table in the schema.
        """
        settings = get_settings()
        cutoff = datetime.now(UTC) - timedelta(days=retention_days or settings.job_retention_days)
        result = await self.session.execute(
            Job.__table__.delete().where(
                Job.status.in_([JobStatus.COMPLETED, JobStatus.CANCELLED]),
                Job.finished_at < cutoff,
            )
        )
        return int(result.rowcount or 0)
