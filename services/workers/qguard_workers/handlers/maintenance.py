"""Maintenance handlers: correlation, risk, retention and posture snapshots."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from qguard.common.enums import (
    OPEN_VULNERABILITY_STATUSES,
    JobKind,
)
from qguard.common.logging import get_logger
from qguard.risk.engine import RiskEngine, posture_grade
from qguard.workers.queue import JobQueue
from sqlalchemy import func, select

from qguard_workers.registry import JobContext, register_handler

log = get_logger(__name__)


@register_handler(JobKind.RISK_RECALCULATION)
async def recalculate_risk(ctx: JobContext) -> dict[str, Any]:
    """Rescore every open vulnerability for an organization.

    Risk depends on inputs that change without any scan running — an asset
    reclassified as critical, a CVE added to the KEV catalogue — so scores are
    refreshed on a schedule as well as on ingest.
    """
    await ctx.progress(10, "Recomputing vulnerability risk scores")
    count = await RiskEngine(ctx.session).recalculate_org(ctx.org_id)
    await ctx.progress(70, "Writing the posture snapshot")
    snapshot = await _write_risk_snapshot(ctx)
    return {"vulnerabilities_rescored": count, "snapshot": snapshot}


@register_handler(JobKind.CORRELATION)
async def write_posture_snapshot(ctx: JobContext) -> dict[str, Any]:
    """Record today's organization-level posture measurement."""
    return {"snapshot": await _write_risk_snapshot(ctx)}


async def _write_risk_snapshot(ctx: JobContext) -> dict[str, Any]:
    """Store one day's measured posture.

    Written as a snapshot rather than recomputed on demand so a trend chart
    shows what the platform actually measured on each day, including days when
    coverage was poor.
    """
    from qguard.models.assets import Asset
    from qguard.models.findings import Vulnerability
    from qguard.models.risk import RiskSnapshot

    org_id = ctx.org_id
    today = datetime.now(UTC).date()

    severity_rows = (
        await ctx.session.execute(
            select(Vulnerability.severity, func.count(Vulnerability.id))
            .where(
                Vulnerability.org_id == org_id,
                Vulnerability.status.in_(OPEN_VULNERABILITY_STATUSES),
            )
            .group_by(Vulnerability.severity)
        )
    ).all()
    counts = dict.fromkeys(("critical", "high", "medium", "low", "info"), 0)
    for severity, count in severity_rows:
        counts[severity] = int(count)

    totals = (
        await ctx.session.execute(
            select(
                func.count(Vulnerability.id),
                func.count(Vulnerability.id).filter(Vulnerability.is_exploitable.is_(True)),
                func.count(Vulnerability.id).filter(Vulnerability.is_known_exploited.is_(True)),
                func.count(Vulnerability.id).filter(Vulnerability.sla_breached.is_(True)),
                func.max(Vulnerability.risk_score),
            ).where(
                Vulnerability.org_id == org_id,
                Vulnerability.status.in_(OPEN_VULNERABILITY_STATUSES),
            )
        )
    ).one()
    open_count = int(totals[0] or 0)

    asset_totals = (
        await ctx.session.execute(
            select(
                func.count(Asset.id),
                func.count(Asset.id).filter(Asset.last_assessed_at.is_not(None)),
            ).where(Asset.org_id == org_id, Asset.deleted_at.is_(None), Asset.is_active.is_(True))
        )
    ).one()
    asset_count, assessed_count = int(asset_totals[0] or 0), int(asset_totals[1] or 0)

    period_start = datetime.now(UTC) - timedelta(days=1)
    period = (
        await ctx.session.execute(
            select(
                func.count(Vulnerability.id).filter(Vulnerability.first_seen_at >= period_start),
                func.count(Vulnerability.id).filter(Vulnerability.resolved_at >= period_start),
            ).where(Vulnerability.org_id == org_id)
        )
    ).one()

    mttr = (
        await ctx.session.execute(
            select(
                func.avg(
                    func.extract("epoch", Vulnerability.resolved_at - Vulnerability.first_seen_at)
                    / 3600.0
                )
            ).where(
                Vulnerability.org_id == org_id,
                Vulnerability.resolved_at.is_not(None),
            )
        )
    ).scalar_one_or_none()

    penalty = (
        counts["critical"] * 25 + counts["high"] * 12 + counts["medium"] * 4 + counts["low"] * 1
    )
    security_score = max(0.0, 100.0 - min(100.0, float(penalty)))

    # Coverage is applied honestly: an estate where most assets have never been
    # assessed does not get to claim a clean posture.
    coverage = (assessed_count / asset_count) if asset_count else 0.0
    if asset_count and coverage < 1.0:
        security_score *= 0.5 + 0.5 * coverage

    risk_score = float(totals[4] or 0.0)

    existing = (
        await ctx.session.execute(
            select(RiskSnapshot).where(
                RiskSnapshot.org_id == org_id,
                RiskSnapshot.scope_type == "organization",
                RiskSnapshot.snapshot_date == today,
            )
        )
    ).scalar_one_or_none()

    factors = {
        "severity_counts": counts,
        "penalty_points": penalty,
        "assessment_coverage": round(coverage, 4),
        "coverage_adjustment": (
            "Security score scaled by assessment coverage: assets never assessed are "
            "not counted as secure."
            if asset_count and coverage < 1.0
            else "Every active asset has been assessed at least once."
        ),
        "risk_basis": "Highest open vulnerability risk score in the organization.",
    }

    values = {
        "risk_score": risk_score,
        "security_score": round(security_score, 2),
        "posture_grade": posture_grade(security_score),
        "critical_count": counts["critical"],
        "high_count": counts["high"],
        "medium_count": counts["medium"],
        "low_count": counts["low"],
        "info_count": counts["info"],
        "exploitable_count": int(totals[1] or 0),
        "kev_count": int(totals[2] or 0),
        "overdue_count": int(totals[3] or 0),
        "asset_count": asset_count,
        "assessed_asset_count": assessed_count,
        "open_vulnerability_count": open_count,
        "new_in_period": int(period[0] or 0),
        "resolved_in_period": int(period[1] or 0),
        "mean_time_to_resolve_hours": round(float(mttr), 2) if mttr is not None else None,
        "factors": factors,
    }

    if existing is None:
        ctx.session.add(
            RiskSnapshot(org_id=org_id, scope_type="organization", snapshot_date=today, **values)
        )
    else:
        for key, value in values.items():
            setattr(existing, key, value)

    await ctx.session.flush()
    return {"date": today.isoformat(), **values, "factors": None}


@register_handler(JobKind.RETENTION_SWEEP)
async def retention_sweep(ctx: JobContext) -> dict[str, Any]:
    """Apply retention policy and purge finished job rows.

    Jobs are operational telemetry; the audit trail and scan history persist.
    Items under legal hold are always exempt.
    """
    await ctx.progress(20, "Purging finished job records")
    purged = await JobQueue(ctx.session).purge_old()
    await ctx.progress(60, "Applying retention policies")
    applied = await _apply_retention_policies(ctx)
    return {"jobs_purged": purged, "policies_applied": applied}


async def _apply_retention_policies(ctx: JobContext) -> list[dict[str, Any]]:
    from qguard.models.audit import RetentionPolicy, SecurityEvent

    policies = list(
        (
            await ctx.session.execute(
                select(RetentionPolicy).where(
                    RetentionPolicy.org_id == ctx.org_id,
                    RetentionPolicy.is_enabled.is_(True),
                )
            )
        )
        .scalars()
        .all()
    )
    results: list[dict[str, Any]] = []
    for policy in policies:
        cutoff = datetime.now(UTC) - timedelta(days=policy.retain_days)
        affected = 0
        if policy.resource_type == "security_events" and policy.action == "delete":
            result = await ctx.session.execute(
                SecurityEvent.__table__.delete().where(
                    SecurityEvent.org_id == ctx.org_id,
                    SecurityEvent.occurred_at < cutoff,
                )
            )
            affected = int(result.rowcount or 0)
        else:
            # Anything with its own integrity requirements (evidence, the audit
            # trail) is reported rather than touched automatically: deleting it
            # on a timer is how chain of custody gets broken.
            results.append(
                {
                    "resource_type": policy.resource_type,
                    "action": policy.action,
                    "affected": 0,
                    "note": (
                        "Not applied automatically: this resource type has integrity or "
                        "legal-hold requirements and must be reviewed by an operator."
                    ),
                }
            )
            continue
        policy.last_applied_at = datetime.now(UTC)
        policy.last_affected_count = affected
        results.append(
            {
                "resource_type": policy.resource_type,
                "action": policy.action,
                "affected": affected,
            }
        )
    return results
