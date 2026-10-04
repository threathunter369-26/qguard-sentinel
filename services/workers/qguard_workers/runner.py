"""The worker loop.

Each worker runs a small pool of slots. A slot claims one job, runs its
handler, and reports the outcome. Properties that matter in operation:

* **Crash safety.** A claim takes a lease. If the worker dies, the lease
  expires and the job is requeued rather than lost — which is why a scan
  cannot silently vanish when a container is recycled.
* **Graceful shutdown.** On SIGTERM the worker stops claiming new work and
  lets in-flight jobs finish, so a deploy does not abort a running scan.
* **Honest failure.** A handler exception is recorded against the job with its
  real reason and retried with backoff until the budget is spent, then failed
  visibly.
"""

from __future__ import annotations

import asyncio
import os
import signal
import socket
import tempfile
import traceback
from contextlib import suppress
from typing import Any

from qguard.common.config import get_settings
from qguard.common.database import apply_tenant_context, dispose_engine, session_scope
from qguard.common.logging import configure_logging, get_logger

from qguard_workers.registry import JobContext, get_handler, registered_kinds

log = get_logger(__name__)


class Worker:
    """Polls the job queue and executes handlers."""

    def __init__(
        self,
        *,
        worker_id: str | None = None,
        concurrency: int | None = None,
        kinds: list[str] | None = None,
        poll_interval: float | None = None,
    ) -> None:
        settings = get_settings()
        self.worker_id = worker_id or f"{socket.gethostname()}:{os.getpid()}"
        self.concurrency = concurrency or settings.worker_concurrency
        self.kinds = kinds or []
        self.poll_interval = poll_interval or settings.worker_poll_interval_seconds
        self._shutdown = asyncio.Event()
        self._active: set[asyncio.Task[None]] = set()
        self.jobs_processed = 0
        self.jobs_failed = 0

    # ------------------------------------------------------------------- run
    async def run(self) -> None:
        configure_logging()
        log.info(
            "worker.starting",
            worker_id=self.worker_id,
            concurrency=self.concurrency,
            kinds=self.kinds or "all",
            handlers=registered_kinds(),
        )
        self._install_signal_handlers()

        reclaimer = asyncio.create_task(self._reclaim_loop())
        slots = [asyncio.create_task(self._slot(i)) for i in range(self.concurrency)]

        try:
            await asyncio.gather(*slots)
        finally:
            reclaimer.cancel()
            # Let in-flight work finish rather than aborting it mid-write.
            if self._active:
                log.info("worker.draining", in_flight=len(self._active))
                await asyncio.gather(*self._active, return_exceptions=True)
            await dispose_engine()
            log.info(
                "worker.stopped",
                worker_id=self.worker_id,
                processed=self.jobs_processed,
                failed=self.jobs_failed,
            )

    def _install_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGTERM, signal.SIGINT):
            # Not available on non-POSIX platforms; the worker still runs,
            # it just will not drain gracefully on a signal there.
            with suppress(NotImplementedError):
                loop.add_signal_handler(sig, self.request_shutdown)

    def request_shutdown(self) -> None:
        if not self._shutdown.is_set():
            log.info("worker.shutdown_requested", worker_id=self.worker_id)
            self._shutdown.set()

    # ----------------------------------------------------------------- slots
    async def _slot(self, index: int) -> None:
        """One concurrent execution slot."""
        slot_id = f"{self.worker_id}#{index}"
        idle_cycles = 0

        while not self._shutdown.is_set():
            claimed = None
            try:
                async with session_scope() as session:
                    from qguard.workers.queue import JobQueue

                    claimed = await JobQueue(session).claim(slot_id, self.kinds or None)
            except Exception as exc:
                log.error("worker.claim_failed", slot=slot_id, error=str(exc))
                await self._sleep(min(30.0, self.poll_interval * 5))
                continue

            if claimed is None:
                idle_cycles += 1
                # Back off while idle so an empty queue is not polled hard, but
                # stay responsive to the first job after a quiet period.
                await self._sleep(min(10.0, self.poll_interval * min(idle_cycles, 5)))
                continue

            idle_cycles = 0
            task = asyncio.create_task(self._execute(claimed, slot_id))
            self._active.add(task)
            task.add_done_callback(self._active.discard)
            await task

    async def _sleep(self, seconds: float) -> None:
        """Sleep, but wake immediately if shutdown is requested."""
        with suppress(TimeoutError):
            await asyncio.wait_for(self._shutdown.wait(), timeout=seconds)

    # --------------------------------------------------------------- execute
    async def _execute(self, claimed: Any, slot_id: str) -> None:
        handler = get_handler(claimed.kind)
        if handler is None:
            async with session_scope() as session:
                from qguard.workers.queue import JobQueue

                await JobQueue(session).fail(
                    claimed.job_id,
                    (
                        f"No handler is registered for job kind {claimed.kind!r}. "
                        f"This deployment handles: {', '.join(registered_kinds())}."
                    ),
                    retry=False,
                )
            self.jobs_failed += 1
            return

        scratch = tempfile.mkdtemp(prefix=f"qguard-{claimed.kind}-")
        log.info(
            "worker.job_started",
            job_id=str(claimed.job_id),
            kind=claimed.kind,
            slot=slot_id,
            attempt=claimed.attempts,
        )

        try:
            async with session_scope() as session:
                from qguard.workers.queue import JobQueue

                queue = JobQueue(session)
                # The job and everything it writes commit together: a scan can
                # never be recorded as finished while its findings are lost.
                await apply_tenant_context(session, claimed.org_id, None)
                ctx = JobContext(
                    job=claimed,
                    session=session,
                    queue=queue,
                    worker_id=slot_id,
                    scratch_dir=scratch,
                )
                result = await handler(ctx)
                await queue.complete(claimed.job_id, result or {})
            self.jobs_processed += 1
            log.info("worker.job_completed", job_id=str(claimed.job_id), kind=claimed.kind)

        except asyncio.CancelledError:
            async with session_scope() as session:
                from qguard.workers.queue import JobQueue

                await JobQueue(session).mark_cancelled(claimed.job_id)
            log.info("worker.job_cancelled", job_id=str(claimed.job_id))
            raise

        except Exception as exc:
            self.jobs_failed += 1
            tb = traceback.format_exc()
            log.error(
                "worker.job_failed",
                job_id=str(claimed.job_id),
                kind=claimed.kind,
                error=str(exc),
                attempt=claimed.attempts,
            )
            try:
                async with session_scope() as session:
                    from qguard.workers.queue import JobQueue

                    # A separate session: the job's own transaction has rolled
                    # back, so the failure must be recorded independently or it
                    # would be lost with the work.
                    await JobQueue(session).fail(claimed.job_id, exc, traceback_text=tb)
                    await self._mark_scan_run_failed(session, claimed, exc)
            except Exception as record_exc:
                log.critical(
                    "worker.failure_not_recorded",
                    job_id=str(claimed.job_id),
                    original_error=str(exc),
                    recording_error=str(record_exc),
                )

        finally:
            _remove_tree(scratch)

    @staticmethod
    async def _mark_scan_run_failed(session: Any, claimed: Any, exc: BaseException) -> None:
        """Surface a job failure on its engine run.

        Without this the job would show failed while the scan still showed the
        engine as pending — the scan would appear stuck instead of reporting
        "Scanner Status: Failed" with the reason.
        """
        if claimed.engine_run_id is None:
            return
        from datetime import UTC, datetime

        from qguard.common.enums import EngineRunStatus
        from qguard.models.scanning import ScanEngineRun
        from sqlalchemy import update

        await apply_tenant_context(session, claimed.org_id, None)
        await session.execute(
            update(ScanEngineRun)
            .where(ScanEngineRun.id == claimed.engine_run_id)
            .values(
                status=EngineRunStatus.FAILED,
                error_type=type(exc).__name__,
                error_message=str(exc) or type(exc).__name__,
                finished_at=datetime.now(UTC),
            )
        )
        if claimed.scan_id is not None:
            from qguard.scanning.orchestrator import ScanOrchestrator

            await ScanOrchestrator(session).finalize(claimed.scan_id, claimed.org_id)

    # -------------------------------------------------------------- reclaimer
    async def _reclaim_loop(self) -> None:
        """Periodically requeue jobs whose worker stopped responding."""
        settings = get_settings()
        interval = max(30.0, float(settings.worker_heartbeat_seconds) * 4)
        while not self._shutdown.is_set():
            await self._sleep(interval)
            if self._shutdown.is_set():
                return
            try:
                async with session_scope() as session:
                    from qguard.workers.queue import JobQueue

                    await JobQueue(session).reclaim_expired()
            except Exception as exc:
                log.warning("worker.reclaim_failed", error=str(exc))


def _remove_tree(path: str) -> None:
    import shutil

    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception as exc:
        log.warning("worker.scratch_cleanup_failed", path=path, error=str(exc))
