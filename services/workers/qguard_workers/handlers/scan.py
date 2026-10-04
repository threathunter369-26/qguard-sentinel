"""Handler that runs one security engine against one target.

The whole flow — engine lookup, authorization re-check, execution, ingestion,
engine-run bookkeeping and scan finalisation — happens in one transaction, so
a scan can never be recorded as finished while the findings it produced are
lost.

Authorization is re-checked here even though the orchestrator already decided
it. The decision is made at planning time and the job may run minutes later,
by which point the authorization could have been revoked or expired. Re-
checking means a revocation takes effect on queued work too.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from qguard.common.enums import EngineRunStatus, JobKind
from qguard.common.events import EventType, emit
from qguard.common.logging import get_logger
from qguard.findings.ingestion import FindingIngestionService
from qguard.models.assets import Asset
from qguard.models.scanning import ScanEngineRun
from qguard.risk.engine import RiskEngine
from qguard.scanning.authorization import AuthorizationService
from qguard.scanning.orchestrator import ScanOrchestrator
from qguard_scanner.sdk.engine import (
    EngineContext,
    EngineResult,
    EngineStatus,
    ScopeChecker,
    ScopeVerdict,
)
from qguard_scanner.sdk.finding import ScanTarget
from qguard_scanner.sdk.registry import get_registry
from sqlalchemy import select

from qguard_workers.registry import JobContext, register_handler

log = get_logger(__name__)

#: Map an engine's terminal status onto the engine-run status stored for the UI.
STATUS_MAP: dict[EngineStatus, str] = {
    EngineStatus.COMPLETED: EngineRunStatus.COMPLETED,
    EngineStatus.DEGRADED: EngineRunStatus.DEGRADED,
    EngineStatus.FAILED: EngineRunStatus.FAILED,
    EngineStatus.SKIPPED: EngineRunStatus.SKIPPED,
    EngineStatus.CANCELLED: EngineRunStatus.CANCELLED,
    EngineStatus.UNAUTHORIZED: EngineRunStatus.UNAUTHORIZED,
}


@register_handler(JobKind.SCAN)
async def run_engine(ctx: JobContext) -> dict[str, Any]:
    """Execute one engine run and persist everything it produced."""
    payload = ctx.payload
    engine_key = payload["engine_key"]
    engine_run_id = uuid.UUID(payload["engine_run_id"])
    scan_id = uuid.UUID(payload["scan_id"]) if payload.get("scan_id") else None
    asset_id = uuid.UUID(payload["asset_id"]) if payload.get("asset_id") else None
    project_id = uuid.UUID(payload["project_id"]) if payload.get("project_id") else None
    engagement_id = uuid.UUID(payload["engagement_id"]) if payload.get("engagement_id") else None
    target_value = payload["target"]
    target_kind = payload.get("target_kind", "host")

    engine_run = (
        await ctx.session.execute(select(ScanEngineRun).where(ScanEngineRun.id == engine_run_id))
    ).scalar_one_or_none()
    if engine_run is None:
        return {"status": "orphaned", "reason": "The engine run record no longer exists."}

    engine = get_registry().create(engine_key)
    if engine is None:
        # An engine named in a queued job is no longer installed. Reported as a
        # failure with the reason, never as an empty clean result.
        return await _record_result(
            ctx,
            engine_run,
            EngineResult.failed(
                engine_key,
                (
                    f"The {engine_key!r} engine is not installed in this deployment. "
                    f"Available engines: {', '.join(get_registry().keys()) or 'none'}."
                ),
            ),
            scan_id=scan_id,
            asset_id=asset_id,
            project_id=project_id,
            engagement_id=engagement_id,
        )

    engine_run.status = EngineRunStatus.RUNNING
    engine_run.started_at = datetime.now(UTC)
    engine_run.engine_version = engine.metadata.version
    await ctx.session.flush()

    from qguard.models.scanning import Scan

    if scan_id is not None:
        scan = (
            await ctx.session.execute(select(Scan).where(Scan.id == scan_id))
        ).scalar_one_or_none()
        if scan is not None and scan.started_at is None:
            scan.started_at = datetime.now(UTC)
            from qguard.common.enums import ScanStatus

            scan.status = ScanStatus.RUNNING

    await emit(
        EventType.ENGINE_STARTED,
        ctx.org_id,
        {
            "scan_id": str(scan_id) if scan_id else None,
            "engine_run_id": str(engine_run_id),
            "engine": engine_key,
            "target": target_value,
        },
        resource_type="scan_engine_run",
        resource_id=engine_run_id,
    )

    # --- Re-check authorization at execution time -------------------------
    verdict: ScopeVerdict | None = None
    if engine.metadata.requires_authorization:
        decision = await AuthorizationService(ctx.session).decide(
            org_id=ctx.org_id,
            target=target_value,
            engine_key=engine_key,
            project_id=project_id,
            intrusive=bool(payload.get("allow_intrusive")) or engine.metadata.is_intrusive,
        )
        verdict = decision.to_verdict()
        if not decision.allowed:
            log.warning(
                "scan.authorization_revoked_before_run",
                engine=engine_key,
                target=target_value,
                reason=decision.reason,
            )
            engine_run.scope_decision = decision.as_dict()
            return await _record_result(
                ctx,
                engine_run,
                EngineResult.unauthorized(engine_key, verdict),
                scan_id=scan_id,
                asset_id=asset_id,
                project_id=project_id,
                engagement_id=engagement_id,
            )
        engine_run.scope_decision = decision.as_dict()

    # --- Build the engine context -----------------------------------------
    settings_config = dict(payload.get("config") or {})
    from qguard.common.config import get_settings

    settings = get_settings()

    async def report(percent: int, message: str) -> None:
        engine_run.progress = percent
        engine_run.progress_message = message
        await ctx.progress(percent, f"{engine_key}: {message}")
        await emit(
            EventType.ENGINE_PROGRESS,
            ctx.org_id,
            {
                "scan_id": str(scan_id) if scan_id else None,
                "engine_run_id": str(engine_run_id),
                "engine": engine_key,
                "progress": percent,
                "message": message,
            },
            resource_type="scan_engine_run",
            resource_id=engine_run_id,
        )

    cancelled = False

    def is_cancelled() -> bool:
        return cancelled

    engine_ctx = EngineContext(
        target=ScanTarget(
            kind=target_kind,
            value=target_value,
            asset_id=str(asset_id) if asset_id else None,
            project_id=str(project_id) if project_id else None,
        ),
        config=settings_config,
        workdir=Path(ctx.scratch_dir) if ctx.scratch_dir else None,
        scope_checker=_fixed_scope_checker(verdict)
        if verdict is not None
        else _passive_scope_checker(engine_key),
        progress=report,
        max_requests_per_second=settings.scan_max_requests_per_second,
        max_concurrency=settings.scan_max_concurrency,
        http_timeout_seconds=settings.scan_http_timeout_seconds,
        user_agent=settings.scan_user_agent,
        allow_intrusive=bool(payload.get("allow_intrusive")),
        deadline_seconds=float(settings_config.get("deadline_seconds", 1800)),
        cancelled=is_cancelled,
    )

    result = await engine.run(engine_ctx)

    return await _record_result(
        ctx,
        engine_run,
        result,
        scan_id=scan_id,
        asset_id=asset_id,
        project_id=project_id,
        engagement_id=engagement_id,
    )


def _fixed_scope_checker(verdict: ScopeVerdict) -> ScopeChecker:
    """A scope checker that returns one already-made authorization decision.

    The decision is taken once, against the stored authorization, before the
    engine runs. Returning it unchanged for every target the engine asks about
    is correct only because the orchestrator has already confirmed the engine
    is scanning that single authorized target.
    """

    def check(_target: str) -> ScopeVerdict:
        return verdict

    return check


def _passive_scope_checker(engine_key: str) -> Any:
    """Scope checker for a passive engine.

    A passive engine sends nothing to the target, so it needs no authorization.
    It still receives a checker, so that if it ever did try to reach the
    network the attempt would be refused rather than silently permitted.
    """

    def check(target: str) -> ScopeVerdict:
        return ScopeVerdict(
            allowed=False,
            reason=(
                f"The {engine_key!r} engine is registered as passive, so it has no "
                f"authorization to contact {target}. This is a bug in the engine if it "
                "reached this check."
            ),
        )

    return check


async def _record_result(
    ctx: JobContext,
    engine_run: ScanEngineRun,
    result: EngineResult,
    *,
    scan_id: uuid.UUID | None,
    asset_id: uuid.UUID | None,
    project_id: uuid.UUID | None,
    engagement_id: uuid.UUID | None,
) -> dict[str, Any]:
    """Persist an engine result: findings, run bookkeeping, scan status."""
    run_status = STATUS_MAP.get(result.status, EngineRunStatus.FAILED)

    ingestion_summary: dict[str, Any] = {}
    if result.findings:
        summary = await FindingIngestionService(ctx.session).ingest(
            org_id=ctx.org_id,
            findings=result.findings,
            asset_id=asset_id,
            project_id=project_id,
            scan_id=scan_id,
            engine_run_id=engine_run.id,
            engagement_id=engagement_id,
            engine_key=engine_run.engine_key,
            run_status=run_status,
        )
        ingestion_summary = summary.as_dict()
    elif run_status == EngineRunStatus.COMPLETED and asset_id:
        # A completed run with no findings is meaningful: it is what lets
        # previously-reported issues be marked absent and auto-resolved.
        summary = await FindingIngestionService(ctx.session).ingest(
            org_id=ctx.org_id,
            findings=[],
            asset_id=asset_id,
            project_id=project_id,
            scan_id=scan_id,
            engine_run_id=engine_run.id,
            engine_key=engine_run.engine_key,
            run_status=run_status,
        )
        ingestion_summary = summary.as_dict()

    engine_run.status = run_status
    engine_run.finished_at = datetime.now(UTC)
    engine_run.duration_seconds = result.duration_seconds
    engine_run.progress = 100
    engine_run.findings_count = len(result.findings)
    engine_run.checks_executed = result.checks_executed
    engine_run.items_examined = result.items_examined
    engine_run.requests_sent = result.requests_sent
    engine_run.error_type = result.error_type
    engine_run.error_message = result.error_message
    engine_run.degraded_reason = result.degraded_reason
    engine_run.warnings = list(result.warnings)
    engine_run.stats = {
        **result.stats,
        "severity_counts": result.severity_counts(),
        "is_trustworthy": result.is_trustworthy,
        "ingestion": ingestion_summary,
    }
    if result.scope_verdict is not None and not engine_run.scope_decision:
        engine_run.scope_decision = {
            "allowed": result.scope_verdict.allowed,
            "reason": result.scope_verdict.reason,
            "matched_rule": result.scope_verdict.matched_rule,
            "authorization_id": result.scope_verdict.authorization_id,
        }
    await ctx.session.flush()

    # Risk depends on inputs that change outside a scan, but a brand-new
    # finding must not sit without a score until the next nightly pass.
    if ingestion_summary.get("vulnerabilities_created") or ingestion_summary.get(
        "vulnerabilities_updated"
    ):
        await RiskEngine(ctx.session).recalculate_org(ctx.org_id)
        if asset_id:
            posture = await RiskEngine(ctx.session).assess_asset(ctx.org_id, asset_id)
            await _update_asset_posture(ctx, asset_id, posture, scan_id)

    await emit(
        EventType.ENGINE_COMPLETED if result.succeeded else EventType.ENGINE_FAILED,
        ctx.org_id,
        {
            "scan_id": str(scan_id) if scan_id else None,
            "engine_run_id": str(engine_run.id),
            **result.as_dict(),
        },
        resource_type="scan_engine_run",
        resource_id=engine_run.id,
    )

    if scan_id is not None:
        await ScanOrchestrator(ctx.session).finalize(scan_id, ctx.org_id)

    log.info(
        "scan.engine_run_recorded",
        engine=engine_run.engine_key,
        status=run_status,
        findings=len(result.findings),
        trustworthy=result.is_trustworthy,
    )
    return {
        "engine": engine_run.engine_key,
        "status": run_status,
        **result.as_dict(),
        "ingestion": ingestion_summary,
    }


async def _update_asset_posture(
    ctx: JobContext,
    asset_id: uuid.UUID,
    posture: dict[str, Any],
    scan_id: uuid.UUID | None,
) -> None:
    """Record an asset's posture and keep a historical assessment row.

    The history is what makes the dashboard's trend lines real measurements
    rather than reconstructions.
    """
    from qguard.models.assets import AssetAssessment

    asset = (
        await ctx.session.execute(select(Asset).where(Asset.id == asset_id))
    ).scalar_one_or_none()
    if asset is None or "error" in posture:
        return

    asset.security_score = posture.get("security_score")
    asset.risk_score = posture.get("risk_score")
    asset.last_assessed_at = datetime.now(UTC)
    asset.last_scan_id = scan_id

    counts = posture.get("counts", {})
    ctx.session.add(
        AssetAssessment(
            org_id=ctx.org_id,
            asset_id=asset_id,
            scan_id=scan_id,
            security_score=posture.get("security_score"),
            risk_score=posture.get("risk_score"),
            critical_count=counts.get("critical", 0),
            high_count=counts.get("high", 0),
            medium_count=counts.get("medium", 0),
            low_count=counts.get("low", 0),
            info_count=counts.get("info", 0),
            engines_run=[],
            summary={
                "posture_grade": posture.get("posture_grade"),
                "explanation": posture.get("explanation"),
                "open_vulnerability_count": posture.get("open_vulnerability_count"),
            },
        )
    )
