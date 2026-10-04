"""Scan orchestration.

Turns a request ("assess these assets with these engines") into a durable scan
with one job per engine run, then assembles the per-engine outcomes into an
honest scan status.

Two behaviours are load-bearing:

* **Authorization is resolved up front.** Every (engine, target) pair is
  decided before any job is queued. A pair that is refused is recorded as an
  ``unauthorized`` engine run with its reason — the scan still runs its
  permitted parts, and the refused part is visible rather than missing.

* **A scan's status reflects its engines.** All completed is ``completed``;
  some failed is ``partial``; all failed is ``failed``. A scan never reports
  success on the back of engines that did not run.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from qguard_scanner.sdk.registry import get_registry
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from qguard.audit.service import AuditService
from qguard.auth.principal import Principal
from qguard.common.enums import (
    EngineKey,
    EngineRunStatus,
    JobKind,
    ScanStatus,
    ScanType,
    SecurityEventKind,
)
from qguard.common.errors import NotFoundError, ValidationError
from qguard.common.events import EventType, emit
from qguard.common.logging import get_logger
from qguard.common.references import next_reference
from qguard.models.assets import Asset
from qguard.models.audit import AuditAction
from qguard.models.scanning import Scan, ScanEngineRun, ScanProfile
from qguard.scanning.authorization import AuthorizationDecision, AuthorizationService
from qguard.workers.queue import JobQueue

log = get_logger(__name__)

#: Which engines a scan type runs by default. A scan type is a shorthand for a
#: sensible engine set, not a separate code path.
SCAN_TYPE_ENGINES: dict[str, tuple[str, ...]] = {
    ScanType.WEB_APPLICATION: (EngineKey.WEB, EngineKey.CRYPTO, EngineKey.CERTIFICATE),
    ScanType.API: (EngineKey.API, EngineKey.CRYPTO),
    ScanType.MOBILE: (EngineKey.MOBILE, EngineKey.SECRETS, EngineKey.CRYPTO),
    ScanType.SOURCE_CODE: (EngineKey.SAST, EngineKey.SECRETS, EngineKey.SCA),
    ScanType.DEPENDENCY: (EngineKey.SCA,),
    ScanType.SECRETS: (EngineKey.SECRETS,),
    ScanType.CONTAINER: (EngineKey.CONTAINER, EngineKey.SECRETS, EngineKey.SCA),
    ScanType.KUBERNETES: (EngineKey.KUBERNETES,),
    ScanType.CLOUD: (EngineKey.CLOUD,),
    ScanType.NETWORK: (EngineKey.NETWORK, EngineKey.CERTIFICATE, EngineKey.CRYPTO),
    ScanType.CRYPTOGRAPHY: (EngineKey.CRYPTO, EngineKey.CERTIFICATE),
    ScanType.FULL_ASSESSMENT: (
        EngineKey.WEB,
        EngineKey.API,
        EngineKey.SAST,
        EngineKey.SCA,
        EngineKey.SECRETS,
        EngineKey.CONTAINER,
        EngineKey.KUBERNETES,
        EngineKey.CRYPTO,
        EngineKey.CERTIFICATE,
        EngineKey.NETWORK,
    ),
}

#: Which target kind an asset type presents to an engine.
ASSET_TARGET_KIND: dict[str, str] = {
    "web_application": "url",
    "url": "url",
    "api": "url",
    "domain": "host",
    "subdomain": "host",
    "ip_address": "host",
    "server": "host",
    "database": "host",
    "network_range": "host",
    "repository": "directory",
    "mobile_application": "file",
    "container_image": "image",
    "kubernetes_resource": "kubernetes_manifest",
    "cloud_resource": "cloud_account",
    "dependency": "manifest",
    "certificate": "host",
    "endpoint": "url",
}


@dataclass(slots=True)
class PlannedRun:
    """One engine against one target, with its authorization decision."""

    engine_key: str
    asset_id: uuid.UUID | None
    target: str
    target_kind: str
    decision: AuthorizationDecision | None
    skip_reason: str | None = None


@dataclass(slots=True)
class ScanPlan:
    """The complete plan for a scan, including what will not run and why."""

    runs: list[PlannedRun] = field(default_factory=list)
    refused: list[PlannedRun] = field(default_factory=list)
    skipped: list[PlannedRun] = field(default_factory=list)

    @property
    def runnable_count(self) -> int:
        return len(self.runs)

    def summary(self) -> dict[str, Any]:
        return {
            "runnable": len(self.runs),
            "refused": len(self.refused),
            "skipped": len(self.skipped),
            "engines": sorted({r.engine_key for r in self.runs}),
            "refusals": [
                {
                    "engine": r.engine_key,
                    "target": r.target,
                    "reason": r.decision.reason if r.decision else "unknown",
                }
                for r in self.refused[:20]
            ],
            "skips": [
                {"engine": r.engine_key, "target": r.target, "reason": r.skip_reason}
                for r in self.skipped[:20]
            ],
        }


class ScanOrchestrator:
    """Plans, launches and finalises scans."""

    def __init__(
        self,
        session: AsyncSession,
        audit: AuditService | None = None,
    ) -> None:
        self.session = session
        self.audit = audit or AuditService(session)
        self.authorization = AuthorizationService(session, self.audit)
        self.queue = JobQueue(session)
        self.registry = get_registry()

    # ------------------------------------------------------------------ plan
    async def plan(
        self,
        *,
        org_id: uuid.UUID,
        scan_type: str,
        asset_ids: list[uuid.UUID] | None = None,
        targets: list[str] | None = None,
        engines: list[str] | None = None,
        project_id: uuid.UUID | None = None,
        authorization_id: uuid.UUID | None = None,
        intrusive: bool = False,
    ) -> ScanPlan:
        """Work out exactly what will run, and what will not, before starting.

        Planning is separate from launching so the API can show an operator the
        authorization outcome — including refusals — before anything touches a
        target.
        """
        selected = list(engines or SCAN_TYPE_ENGINES.get(scan_type, ()))
        if not selected:
            raise ValidationError(
                f"No engines are defined for scan type {scan_type!r}, and none were given.",
                details={"known_scan_types": sorted(SCAN_TYPE_ENGINES)},
            )

        unknown = [key for key in selected if key not in self.registry]
        available = self.registry.keys()
        if unknown:
            raise ValidationError(
                "Some requested engines are not installed in this deployment.",
                details={"unknown_engines": unknown, "available_engines": available},
            )

        assets: list[Asset] = []
        if asset_ids:
            assets = list(
                (
                    await self.session.execute(
                        select(Asset).where(
                            Asset.org_id == org_id,
                            Asset.id.in_(asset_ids),
                            Asset.deleted_at.is_(None),
                        )
                    )
                )
                .scalars()
                .all()
            )
            found = {a.id for a in assets}
            if missing := [str(a) for a in asset_ids if a not in found]:
                raise NotFoundError(
                    "Some of the requested assets were not found.",
                    details={"missing_asset_ids": missing},
                )

        plan = ScanPlan()
        pairs: list[tuple[uuid.UUID | None, str, str]] = []
        for asset in assets:
            kind = ASSET_TARGET_KIND.get(asset.asset_type, "host")
            pairs.append((asset.id, self._asset_target(asset), kind))
        for raw_target in targets or []:
            pairs.append((None, raw_target, "url" if "://" in raw_target else "host"))

        if not pairs:
            raise ValidationError("A scan needs at least one asset or target.")

        for engine_key in selected:
            engine_cls = self.registry.get(engine_key)
            if engine_cls is None:
                continue
            metadata = engine_cls.metadata

            for asset_id, target, target_kind in pairs:
                if target_kind not in metadata.target_kinds:
                    plan.skipped.append(
                        PlannedRun(
                            engine_key=engine_key,
                            asset_id=asset_id,
                            target=target,
                            target_kind=target_kind,
                            decision=None,
                            skip_reason=(
                                f"The {metadata.name} engine handles "
                                f"{', '.join(metadata.target_kinds)} targets, not "
                                f"{target_kind!r}."
                            ),
                        )
                    )
                    continue

                if not metadata.requires_authorization:
                    # Passive engines send no traffic to the target, so they
                    # need no authorization.
                    plan.runs.append(
                        PlannedRun(
                            engine_key=engine_key,
                            asset_id=asset_id,
                            target=target,
                            target_kind=target_kind,
                            decision=AuthorizationDecision(
                                allowed=True,
                                reason=(
                                    f"The {metadata.name} engine is passive and sends no "
                                    "traffic to the target, so no test authorization is "
                                    "required."
                                ),
                            ),
                        )
                    )
                    continue

                decision = await self.authorization.decide(
                    org_id=org_id,
                    target=target,
                    engine_key=engine_key,
                    project_id=project_id,
                    authorization_id=authorization_id,
                    intrusive=intrusive or metadata.is_intrusive,
                )
                run = PlannedRun(
                    engine_key=engine_key,
                    asset_id=asset_id,
                    target=target,
                    target_kind=target_kind,
                    decision=decision,
                )
                (plan.runs if decision.allowed else plan.refused).append(run)

        return plan

    @staticmethod
    def _asset_target(asset: Asset) -> str:
        """Derive the string an engine should be pointed at."""
        if asset.url:
            return asset.url
        if asset.asset_type in ("web_application", "api", "url", "endpoint"):
            scheme = "https"
            host = asset.hostname or asset.domain or asset.identifier
            port = f":{asset.port}" if asset.port and asset.port not in (80, 443) else ""
            return f"{scheme}://{host}{port}"
        return asset.hostname or asset.identifier

    # ---------------------------------------------------------------- launch
    async def launch(
        self,
        *,
        principal: Principal,
        scan_type: str,
        asset_ids: list[uuid.UUID] | None = None,
        targets: list[str] | None = None,
        engines: list[str] | None = None,
        project_id: uuid.UUID | None = None,
        profile_id: uuid.UUID | None = None,
        authorization_id: uuid.UUID | None = None,
        engagement_id: uuid.UUID | None = None,
        config: dict[str, Any] | None = None,
        intrusive: bool = False,
        name: str | None = None,
        triggered_by: str = "user",
    ) -> Scan:
        """Create a scan and queue one job per permitted engine run."""
        org_id = principal.org_id
        config = dict(config or {})

        if profile_id is not None:
            profile = (
                await self.session.execute(
                    select(ScanProfile).where(
                        ScanProfile.id == profile_id, ScanProfile.org_id == org_id
                    )
                )
            ).scalar_one_or_none()
            if profile is None:
                raise NotFoundError("That scan profile was not found.")
            engines = engines or list(profile.engines)
            scan_type = scan_type or profile.scan_type
            config = {**profile.engine_config, **config}

        plan = await self.plan(
            org_id=org_id,
            scan_type=scan_type,
            asset_ids=asset_ids,
            targets=targets,
            engines=engines,
            project_id=project_id,
            authorization_id=authorization_id,
            intrusive=intrusive,
        )

        reference = await next_reference(self.session, "scan", org_id)
        scan = Scan(
            org_id=org_id,
            reference=reference,
            name=name,
            scan_type=scan_type,
            status=ScanStatus.QUEUED,
            project_id=project_id,
            profile_id=profile_id,
            authorization_id=authorization_id,
            engagement_id=engagement_id,
            requested_by=principal.user_id,
            triggered_by=triggered_by,
            asset_ids=list(asset_ids or []),
            targets=list(targets or []),
            engines=sorted({r.engine_key for r in (*plan.runs, *plan.refused)}),
            config=config,
            engines_total=len(plan.runs) + len(plan.refused),
        )
        self.session.add(scan)
        await self.session.flush()

        # Refused runs are recorded first, so the scan's record is complete
        # even if every engine was refused. A missing row would read as "not
        # attempted" rather than "refused for this reason".
        for refused in plan.refused:
            self.session.add(
                ScanEngineRun(
                    org_id=org_id,
                    scan_id=scan.id,
                    engine_key=refused.engine_key,
                    asset_id=refused.asset_id,
                    target=refused.target,
                    status=EngineRunStatus.UNAUTHORIZED,
                    error_type="ScopeAuthorizationError",
                    error_message=(
                        refused.decision.reason if refused.decision else "Not authorized."
                    ),
                    scope_decision=refused.decision.as_dict() if refused.decision else {},
                    finished_at=datetime.now(UTC),
                )
            )

        for skipped in plan.skipped:
            self.session.add(
                ScanEngineRun(
                    org_id=org_id,
                    scan_id=scan.id,
                    engine_key=skipped.engine_key,
                    asset_id=skipped.asset_id,
                    target=skipped.target,
                    status=EngineRunStatus.SKIPPED,
                    warnings=[skipped.skip_reason or "Not applicable to this target."],
                    finished_at=datetime.now(UTC),
                )
            )

        queued = 0
        for run in plan.runs:
            engine_run = ScanEngineRun(
                org_id=org_id,
                scan_id=scan.id,
                engine_key=run.engine_key,
                asset_id=run.asset_id,
                target=run.target,
                status=EngineRunStatus.PENDING,
                scope_decision=run.decision.as_dict() if run.decision else {},
            )
            self.session.add(engine_run)
            await self.session.flush()

            await self.queue.enqueue(
                org_id=org_id,
                kind=JobKind.SCAN,
                payload={
                    "scan_id": str(scan.id),
                    "engine_run_id": str(engine_run.id),
                    "engine_key": run.engine_key,
                    "target": run.target,
                    "target_kind": run.target_kind,
                    "asset_id": str(run.asset_id) if run.asset_id else None,
                    "project_id": str(project_id) if project_id else None,
                    "engagement_id": str(engagement_id) if engagement_id else None,
                    "config": config,
                    "allow_intrusive": intrusive,
                    "scope_decision": run.decision.as_dict() if run.decision else {},
                },
                scan_id=scan.id,
                engine_run_id=engine_run.id,
                requested_by=principal.user_id,
            )
            queued += 1

        if queued == 0:
            # Nothing could run. Failing the scan immediately with the reasons
            # is the honest outcome; a perpetually-queued scan would look like
            # a stuck platform rather than a refused request.
            scan.status = ScanStatus.FAILED
            scan.finished_at = datetime.now(UTC)
            scan.error_message = (
                "No engine run could be started. "
                + (
                    f"{len(plan.refused)} run(s) were refused by authorization; "
                    if plan.refused
                    else ""
                )
                + (
                    f"{len(plan.skipped)} run(s) did not apply to the given targets."
                    if plan.skipped
                    else ""
                )
            ).strip()

        await self.audit.record(
            action=AuditAction.SCAN_STARTED,
            org_id=org_id,
            actor=principal,
            resource_type="scan",
            resource_id=scan.id,
            resource_label=scan.reference,
            after={
                "scan_type": scan_type,
                "engines": scan.engines,
                "asset_count": len(asset_ids or []),
                "target_count": len(targets or []),
                "intrusive": intrusive,
            },
            metadata=plan.summary(),
        )
        await self.audit.record_security_event(
            org_id=org_id,
            kind=SecurityEventKind.SCAN_STARTED,
            severity="info",
            source="orchestrator",
            title=f"Scan {scan.reference} started",
            message=(
                f"{queued} engine run(s) queued across {len(scan.engines)} engine(s)."
                + (f" {len(plan.refused)} refused by authorization." if plan.refused else "")
            ),
            resource_type="scan",
            resource_id=scan.id,
            project_id=project_id,
            data=plan.summary(),
        )
        await emit(
            EventType.SCAN_QUEUED,
            org_id,
            {
                "scan_id": str(scan.id),
                "reference": scan.reference,
                "scan_type": scan_type,
                "engines": scan.engines,
                "runs_queued": queued,
                "runs_refused": len(plan.refused),
            },
            resource_type="scan",
            resource_id=scan.id,
        )
        log.info(
            "scan.launched",
            scan_id=str(scan.id),
            reference=scan.reference,
            queued=queued,
            refused=len(plan.refused),
            skipped=len(plan.skipped),
        )
        return scan

    # -------------------------------------------------------------- finalise
    async def finalize(self, scan_id: uuid.UUID, org_id: uuid.UUID) -> Scan | None:
        """Compute a scan's final status from its engine runs.

        Called when a run finishes. The status is derived, never asserted: a
        scan with any failed engine is ``partial``, and one where every engine
        failed is ``failed``.
        """
        scan = (
            await self.session.execute(
                select(Scan).where(Scan.id == scan_id, Scan.org_id == org_id)
            )
        ).scalar_one_or_none()
        if scan is None:
            return None

        runs = list(
            (
                await self.session.execute(
                    select(ScanEngineRun).where(ScanEngineRun.scan_id == scan_id)
                )
            )
            .scalars()
            .all()
        )
        terminal = {
            EngineRunStatus.COMPLETED,
            EngineRunStatus.DEGRADED,
            EngineRunStatus.FAILED,
            EngineRunStatus.SKIPPED,
            EngineRunStatus.CANCELLED,
            EngineRunStatus.UNAUTHORIZED,
        }
        pending = [r for r in runs if r.status not in terminal]
        if pending:
            # Still in flight; update progress only.
            scan.engines_completed = sum(
                1 for r in runs if r.status in (EngineRunStatus.COMPLETED, EngineRunStatus.DEGRADED)
            )
            scan.progress = int(100 * (len(runs) - len(pending)) / len(runs)) if runs else 0
            return scan

        completed = [r for r in runs if r.status == EngineRunStatus.COMPLETED]
        degraded = [r for r in runs if r.status == EngineRunStatus.DEGRADED]
        failed = [r for r in runs if r.status == EngineRunStatus.FAILED]
        unauthorized = [r for r in runs if r.status == EngineRunStatus.UNAUTHORIZED]
        cancelled = [r for r in runs if r.status == EngineRunStatus.CANCELLED]
        attempted = completed + degraded + failed

        if cancelled and not attempted:
            status = ScanStatus.CANCELLED
        elif not attempted or (failed and not (completed or degraded)):
            status = ScanStatus.FAILED
        elif failed or degraded or unauthorized:
            # `partial` is a first-class outcome: it says plainly that some of
            # what was asked for did not happen.
            status = ScanStatus.PARTIAL
        else:
            status = ScanStatus.COMPLETED

        severity_totals: dict[str, int] = dict.fromkeys(
            ("critical", "high", "medium", "low", "info"), 0
        )
        findings_total = 0
        for run in runs:
            findings_total += run.findings_count
            for key, value in (run.stats or {}).get("severity_counts", {}).items():
                severity_totals[key] = severity_totals.get(key, 0) + int(value)

        now = datetime.now(UTC)
        scan.status = status
        scan.finished_at = now
        scan.progress = 100
        scan.engines_completed = len(completed) + len(degraded)
        scan.engines_failed = len(failed)
        scan.findings_created = findings_total
        scan.findings_by_severity = severity_totals
        if scan.started_at:
            scan.duration_seconds = (now - _aware(scan.started_at)).total_seconds()

        if status in (ScanStatus.FAILED, ScanStatus.PARTIAL):
            problems: list[str] = []
            for run in failed:
                problems.append(
                    f"{run.engine_key} failed: {run.error_message or 'no reason recorded'}"
                )
            for run in degraded:
                problems.append(
                    f"{run.engine_key} produced incomplete results: {run.degraded_reason}"
                )
            for run in unauthorized:
                problems.append(f"{run.engine_key} was refused: {run.error_message}")
            scan.error_message = " | ".join(problems[:10]) or None

        await self.audit.record(
            action=(
                AuditAction.SCAN_COMPLETED
                if status == ScanStatus.COMPLETED
                else AuditAction.SCAN_FAILED
            ),
            org_id=org_id,
            actor_type="worker",
            actor_label="scanner",
            resource_type="scan",
            resource_id=scan.id,
            resource_label=scan.reference,
            result="success" if status == ScanStatus.COMPLETED else "failure",
            failure_reason=scan.error_message,
            after={
                "status": status,
                "engines_completed": scan.engines_completed,
                "engines_failed": scan.engines_failed,
                "findings_created": findings_total,
                "severity_counts": severity_totals,
            },
        )
        if failed:
            await self.audit.record_security_event(
                org_id=org_id,
                kind=SecurityEventKind.ENGINE_FAILED,
                severity="medium",
                source="orchestrator",
                title=f"{len(failed)} engine(s) failed during scan {scan.reference}",
                message=scan.error_message,
                resource_type="scan",
                resource_id=scan.id,
                data={
                    "failed_engines": [
                        {"engine": r.engine_key, "reason": r.error_message} for r in failed
                    ]
                },
            )
        await emit(
            EventType.SCAN_COMPLETED if status != ScanStatus.FAILED else EventType.SCAN_FAILED,
            org_id,
            {
                "scan_id": str(scan.id),
                "reference": scan.reference,
                "status": status,
                "findings_created": findings_total,
                "severity_counts": severity_totals,
                "engines_completed": scan.engines_completed,
                "engines_failed": scan.engines_failed,
                "error_message": scan.error_message,
            },
            resource_type="scan",
            resource_id=scan.id,
        )
        log.info(
            "scan.finalized",
            scan_id=str(scan.id),
            status=status,
            findings=findings_total,
            failed_engines=len(failed),
        )
        return scan

    async def cancel(self, principal: Principal, scan_id: uuid.UUID) -> Scan:
        scan = (
            await self.session.execute(
                select(Scan).where(Scan.id == scan_id, Scan.org_id == principal.org_id)
            )
        ).scalar_one_or_none()
        if scan is None:
            raise NotFoundError("That scan was not found.")
        if scan.status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
            raise ValidationError(f"This scan has already finished with status {scan.status!r}.")

        scan.cancel_requested = True
        from qguard.models.scanning import Job

        jobs = (
            (
                await self.session.execute(
                    select(Job).where(Job.scan_id == scan_id, Job.org_id == principal.org_id)
                )
            )
            .scalars()
            .all()
        )
        for job in jobs:
            await self.queue.request_cancel(job.id, principal.org_id)

        await self.audit.record(
            action=AuditAction.SCAN_CANCELLED,
            org_id=principal.org_id,
            actor=principal,
            resource_type="scan",
            resource_id=scan.id,
            resource_label=scan.reference,
            metadata={"jobs_signalled": len(jobs)},
        )
        return scan


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
