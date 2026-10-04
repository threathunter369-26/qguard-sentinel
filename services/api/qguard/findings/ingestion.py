"""Finding ingestion, deduplication and cross-engine correlation.

This is where the platform stops being a collection of scanners and becomes one
security picture. Three distinct operations happen on every ingest:

**Deduplication.** A finding's ``fingerprint`` identifies it as reported by one
engine at one location. Re-scanning updates ``last_seen_at`` and the occurrence
count on the existing row instead of inserting a near-identical duplicate, so a
nightly scan does not multiply the backlog by the number of nights it has run.

**Correlation.** A finding's ``correlation_key`` identifies the *underlying
defect*, independently of which engine saw it. Findings sharing a key attach to
one :class:`~qguard.models.findings.Vulnerability`, so the same weakness found
by SAST, DAST and SCA is one item to triage carrying three corroborating
sources — and a vulnerability confirmed by several independent engines is
scored as more certain than one seen once.

**Resolution detection.** Findings an engine previously reported but did not
see on its latest successful run are marked absent, and a vulnerability whose
every source has gone absent is resolved automatically. This only happens for
an engine run that *completed*: a failed or degraded run proves nothing about
whether an issue was fixed, so nothing is closed on the strength of it.
"""

from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from qguard_scanner.sdk.finding import ScanFinding
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from qguard.audit.service import AuditService
from qguard.common.enums import (
    OPEN_VULNERABILITY_STATUSES,
    EngineRunStatus,
    FindingStatus,
    SecurityEventKind,
    Severity,
    VulnerabilityStatus,
    severity_rank,
)
from qguard.common.events import EventType, emit
from qguard.common.logging import get_logger
from qguard.common.references import allocate_references
from qguard.models.audit import AuditAction
from qguard.models.findings import DetectedSecret, Finding, Vulnerability, VulnerabilityEvent

log = get_logger(__name__)

#: Remediation SLA in days, by severity. Used to set a vulnerability's due date
#: so overdue work is visible rather than implicit.
DEFAULT_SLA_DAYS: dict[str, int] = {
    Severity.CRITICAL: 7,
    Severity.HIGH: 30,
    Severity.MEDIUM: 90,
    Severity.LOW: 180,
    Severity.INFO: 365,
}


@dataclass(slots=True)
class IngestionSummary:
    """What an ingest actually changed. Returned so the UI can be specific."""

    findings_created: int = 0
    findings_updated: int = 0
    findings_marked_absent: int = 0
    vulnerabilities_created: int = 0
    vulnerabilities_updated: int = 0
    vulnerabilities_reopened: int = 0
    vulnerabilities_auto_resolved: int = 0
    secrets_recorded: int = 0
    severity_counts: dict[str, int] = field(
        default_factory=lambda: dict.fromkeys(("critical", "high", "medium", "low", "info"), 0)
    )
    correlated_clusters: int = 0
    skipped: list[str] = field(default_factory=list)

    def merge(self, other: IngestionSummary) -> None:
        self.findings_created += other.findings_created
        self.findings_updated += other.findings_updated
        self.findings_marked_absent += other.findings_marked_absent
        self.vulnerabilities_created += other.vulnerabilities_created
        self.vulnerabilities_updated += other.vulnerabilities_updated
        self.vulnerabilities_reopened += other.vulnerabilities_reopened
        self.vulnerabilities_auto_resolved += other.vulnerabilities_auto_resolved
        self.secrets_recorded += other.secrets_recorded
        self.correlated_clusters += other.correlated_clusters
        self.skipped.extend(other.skipped)
        for key, value in other.severity_counts.items():
            self.severity_counts[key] = self.severity_counts.get(key, 0) + value

    def as_dict(self) -> dict[str, Any]:
        return {
            "findings_created": self.findings_created,
            "findings_updated": self.findings_updated,
            "findings_marked_absent": self.findings_marked_absent,
            "vulnerabilities_created": self.vulnerabilities_created,
            "vulnerabilities_updated": self.vulnerabilities_updated,
            "vulnerabilities_reopened": self.vulnerabilities_reopened,
            "vulnerabilities_auto_resolved": self.vulnerabilities_auto_resolved,
            "secrets_recorded": self.secrets_recorded,
            "correlated_clusters": self.correlated_clusters,
            "severity_counts": self.severity_counts,
            "skipped": self.skipped[:20],
        }


class FindingIngestionService:
    """Persists engine output into the correlated security data model."""

    def __init__(self, session: AsyncSession, audit: AuditService | None = None) -> None:
        self.session = session
        self.audit = audit or AuditService(session)

    # ------------------------------------------------------------------ ingest
    async def ingest(
        self,
        *,
        org_id: uuid.UUID,
        findings: list[ScanFinding],
        asset_id: uuid.UUID | None = None,
        project_id: uuid.UUID | None = None,
        scan_id: uuid.UUID | None = None,
        engine_run_id: uuid.UUID | None = None,
        engagement_id: uuid.UUID | None = None,
        engine_key: str | None = None,
        run_status: str = EngineRunStatus.COMPLETED,
    ) -> IngestionSummary:
        """Store a batch of engine findings, deduplicating and correlating."""
        summary = IngestionSummary()
        if not findings:
            # An engine that completed and found nothing is a real result, and
            # it is the strongest evidence of remediation there is: everything
            # this engine previously reported on this asset is now gone. A run
            # that failed proves nothing and must not close anything.
            if run_status == EngineRunStatus.COMPLETED and engine_key and asset_id:
                summary.findings_marked_absent = await self._mark_absent(
                    org_id=org_id,
                    asset_id=asset_id,
                    engine_key=engine_key,
                    seen_fingerprints=set(),
                )
                summary.vulnerabilities_auto_resolved = await self._auto_resolve(
                    org_id=org_id, asset_id=asset_id
                )
                await self.session.flush()
            return summary

        asset_key = str(asset_id) if asset_id else None
        now = datetime.now(UTC)

        # Group by fingerprint first so a batch containing the same finding
        # twice (a crawler reaching one page by two routes) collapses before
        # touching the database.
        by_fingerprint: dict[str, ScanFinding] = {}
        duplicate_counts: dict[str, int] = defaultdict(int)
        for finding in findings:
            fingerprint = finding.fingerprint(asset_key=asset_key)
            duplicate_counts[fingerprint] += 1
            existing = by_fingerprint.get(fingerprint)
            # Keep the most severe instance when the same fingerprint repeats.
            if existing is None or severity_rank(finding.effective_severity()) > severity_rank(
                existing.effective_severity()
            ):
                by_fingerprint[fingerprint] = finding

        fingerprints = list(by_fingerprint)
        stored = {
            row.fingerprint: row
            for row in (
                await self.session.execute(
                    select(Finding).where(
                        Finding.org_id == org_id, Finding.fingerprint.in_(fingerprints)
                    )
                )
            )
            .scalars()
            .all()
        }

        new_fingerprints = [f for f in fingerprints if f not in stored]
        references = await allocate_references(
            self.session, "finding", org_id, len(new_fingerprints)
        )
        reference_by_fingerprint = dict(zip(new_fingerprints, references, strict=True))

        persisted: list[tuple[Finding, ScanFinding]] = []
        for fingerprint, scan_finding in by_fingerprint.items():
            severity = scan_finding.effective_severity()
            summary.severity_counts[severity] = summary.severity_counts.get(severity, 0) + 1
            payload = scan_finding.to_payload()
            correlation_key = scan_finding.correlation_key(asset_key=asset_key)

            row = stored.get(fingerprint)
            if row is None:
                row = Finding(
                    org_id=org_id,
                    reference=reference_by_fingerprint[fingerprint],
                    asset_id=asset_id,
                    project_id=project_id,
                    scan_id=scan_id,
                    engine_run_id=engine_run_id,
                    engagement_id=engagement_id,
                    source=scan_finding.engine,
                    engine=scan_finding.engine,
                    rule_id=scan_finding.rule_id,
                    category=scan_finding.category,
                    severity=severity,
                    confidence=scan_finding.confidence,
                    title=scan_finding.title,
                    description=scan_finding.description,
                    impact=payload["impact"],
                    remediation=payload["remediation"],
                    reproduction=payload["reproduction"],
                    references=payload["references"],
                    evidence=payload["evidence"],
                    location=payload["location"],
                    cve=payload["cve"],
                    cwe=payload["cwe"],
                    cvss_vector=payload["cvss_vector"],
                    cvss_score=payload["cvss_score"],
                    cvss_version=payload["cvss_version"],
                    epss_score=payload["epss_score"],
                    owasp_top10=payload["owasp_top10"],
                    owasp_api_top10=payload["owasp_api_top10"],
                    owasp_asvs=payload["owasp_asvs"],
                    owasp_masvs=payload["owasp_masvs"],
                    mastg_tests=payload["mastg_tests"],
                    mitre_techniques=payload["mitre_techniques"],
                    capec=payload["capec"],
                    fingerprint=fingerprint,
                    correlation_key=correlation_key,
                    status=FindingStatus.NEW,
                    first_seen_at=now,
                    last_seen_at=now,
                    occurrence_count=duplicate_counts[fingerprint],
                    is_exploitable=scan_finding.is_exploitable,
                    exploitability_note=scan_finding.exploitability_note,
                    raw=payload["raw"],
                )
                self.session.add(row)
                summary.findings_created += 1
            else:
                was_absent = row.status == FindingStatus.ABSENT
                row.last_seen_at = now
                row.occurrence_count += duplicate_counts[fingerprint]
                row.scan_id = scan_id or row.scan_id
                row.engine_run_id = engine_run_id or row.engine_run_id
                # Refresh the mutable substance: evidence, severity and
                # intelligence can all legitimately change between scans.
                row.severity = severity
                row.confidence = scan_finding.confidence
                row.title = scan_finding.title
                row.description = scan_finding.description
                row.evidence = payload["evidence"]
                row.location = payload["location"]
                row.remediation = payload["remediation"] or row.remediation
                row.cvss_score = payload["cvss_score"] or row.cvss_score
                row.epss_score = payload["epss_score"] or row.epss_score
                row.is_exploitable = scan_finding.is_exploitable or row.is_exploitable
                if scan_finding.exploitability_note:
                    row.exploitability_note = scan_finding.exploitability_note
                row.status = FindingStatus.REGRESSED if was_absent else FindingStatus.ACTIVE
                row.correlation_key = correlation_key
                summary.findings_updated += 1

            persisted.append((row, scan_finding))

        await self.session.flush()

        # Correlate into managed vulnerabilities.
        correlation_summary = await self._correlate(
            org_id=org_id,
            persisted=persisted,
            asset_id=asset_id,
            project_id=project_id,
        )
        summary.merge(correlation_summary)

        # Secrets get a dedicated row so rotation can be tracked. The raw
        # credential is never stored — only a redacted preview and an HMAC
        # fingerprint, which is enough to recognise it again and to confirm it
        # was actually rotated.
        summary.secrets_recorded = await self._record_secrets(
            org_id=org_id, persisted=persisted, asset_id=asset_id
        )

        # Only a run that completed is evidence of absence.
        if run_status == EngineRunStatus.COMPLETED and engine_key and asset_id:
            summary.findings_marked_absent = await self._mark_absent(
                org_id=org_id,
                asset_id=asset_id,
                engine_key=engine_key,
                seen_fingerprints=set(fingerprints),
            )
            summary.vulnerabilities_auto_resolved = await self._auto_resolve(
                org_id=org_id, asset_id=asset_id
            )

        await self.session.flush()
        await self._emit_events(org_id, summary, scan_id)
        return summary

    # --------------------------------------------------------------- correlate
    async def _correlate(
        self,
        *,
        org_id: uuid.UUID,
        persisted: list[tuple[Finding, ScanFinding]],
        asset_id: uuid.UUID | None,
        project_id: uuid.UUID | None,
    ) -> IngestionSummary:
        """Attach findings to managed vulnerabilities by correlation key."""
        summary = IngestionSummary()
        clusters: dict[str, list[tuple[Finding, ScanFinding]]] = defaultdict(list)
        for row, scan_finding in persisted:
            clusters[row.correlation_key].append((row, scan_finding))
        summary.correlated_clusters = len(clusters)

        keys = list(clusters)
        existing = {
            row.correlation_key: row
            for row in (
                await self.session.execute(
                    select(Vulnerability).where(
                        Vulnerability.org_id == org_id,
                        Vulnerability.correlation_key.in_(keys),
                    )
                )
            )
            .scalars()
            .all()
        }

        now = datetime.now(UTC)
        new_keys = [k for k in keys if k not in existing]
        references = await allocate_references(self.session, "vulnerability", org_id, len(new_keys))
        reference_by_key = dict(zip(new_keys, references, strict=True))

        for key, members in clusters.items():
            # The cluster's severity is the worst of its members: if DAST
            # demonstrates exploitation of something SAST rated medium, the
            # managed item is critical.
            worst = max(members, key=lambda m: severity_rank(m[0].severity))
            worst_row = worst[0]
            engines = sorted({row.engine for row, _ in members})
            exploitable = any(row.is_exploitable for row, _ in members)
            cves = sorted({row.cve for row, _ in members if row.cve})
            max_cvss = max(
                (float(row.cvss_score) for row, _ in members if row.cvss_score is not None),
                default=None,
            )
            max_epss = max(
                (float(row.epss_score) for row, _ in members if row.epss_score is not None),
                default=None,
            )

            vulnerability = existing.get(key)
            if vulnerability is None:
                sla_days = DEFAULT_SLA_DAYS.get(worst_row.severity, 90)
                vulnerability = Vulnerability(
                    org_id=org_id,
                    reference=reference_by_key[key],
                    correlation_key=key,
                    asset_id=asset_id,
                    project_id=project_id,
                    title=worst_row.title,
                    description=worst_row.description,
                    category=worst_row.category,
                    severity=worst_row.severity,
                    cve=cves[0] if cves else None,
                    cve_list=cves,
                    cwe=worst_row.cwe,
                    cvss_score=max_cvss,
                    cvss_vector=worst_row.cvss_vector,
                    epss_score=max_epss,
                    status=VulnerabilityStatus.OPEN,
                    remediation=worst_row.remediation,
                    is_exploitable=exploitable,
                    source_engines=engines,
                    finding_count=len(members),
                    confirmation_count=len(engines),
                    first_seen_at=now,
                    last_seen_at=now,
                    sla_days=sla_days,
                    due_at=now + timedelta(days=sla_days),
                )
                self.session.add(vulnerability)
                await self.session.flush()
                self.session.add(
                    VulnerabilityEvent(
                        org_id=org_id,
                        vulnerability_id=vulnerability.id,
                        actor_type="system",
                        event_type="created",
                        to_status=VulnerabilityStatus.OPEN,
                        note=(
                            f"Created from {len(members)} finding(s) reported by "
                            f"{', '.join(engines)}."
                        ),
                        changes={"source_engines": engines, "severity": worst_row.severity},
                    )
                )
                summary.vulnerabilities_created += 1
            else:
                previous_status = vulnerability.status
                vulnerability.last_seen_at = now
                vulnerability.finding_count = len(members)
                vulnerability.source_engines = sorted(
                    set(vulnerability.source_engines) | set(engines)
                )
                vulnerability.confirmation_count = len(vulnerability.source_engines)
                vulnerability.is_exploitable = vulnerability.is_exploitable or exploitable
                if cves:
                    vulnerability.cve_list = sorted(set(vulnerability.cve_list) | set(cves))
                    vulnerability.cve = vulnerability.cve or cves[0]
                if max_cvss is not None:
                    vulnerability.cvss_score = max_cvss
                if max_epss is not None:
                    vulnerability.epss_score = max_epss
                # Only raise severity automatically. Lowering it is an analyst
                # decision, recorded as an override with a justification.
                if severity_rank(worst_row.severity) > severity_rank(vulnerability.severity):
                    vulnerability.severity = worst_row.severity
                    sla_days = DEFAULT_SLA_DAYS.get(worst_row.severity, 90)
                    vulnerability.sla_days = sla_days
                    vulnerability.due_at = min(
                        vulnerability.due_at or (now + timedelta(days=sla_days)),
                        now + timedelta(days=sla_days),
                    )

                # Something previously closed has been seen again. Reopening is
                # automatic because a resolved issue that is still detectable
                # was not actually resolved.
                if previous_status in (
                    VulnerabilityStatus.RESOLVED,
                    VulnerabilityStatus.VERIFIED,
                ):
                    vulnerability.status = VulnerabilityStatus.REOPENED
                    vulnerability.reopened_count += 1
                    vulnerability.resolved_at = None
                    vulnerability.verified_at = None
                    self.session.add(
                        VulnerabilityEvent(
                            org_id=org_id,
                            vulnerability_id=vulnerability.id,
                            actor_type="system",
                            event_type="reopened",
                            from_status=previous_status,
                            to_status=VulnerabilityStatus.REOPENED,
                            note=(
                                "Detected again after being marked "
                                f"{previous_status.replace('_', ' ')}; the remediation did "
                                "not hold."
                            ),
                            changes={"detected_by": engines},
                        )
                    )
                    summary.vulnerabilities_reopened += 1
                    await self.audit.record_security_event(
                        org_id=org_id,
                        kind=SecurityEventKind.VULNERABILITY_REOPENED,
                        severity=vulnerability.severity,
                        source="correlation",
                        title=f"{vulnerability.reference} has reappeared",
                        message=(
                            f"{vulnerability.title} was previously "
                            f"{previous_status.replace('_', ' ')} but was detected again by "
                            f"{', '.join(engines)}."
                        ),
                        resource_type="vulnerability",
                        resource_id=vulnerability.id,
                        asset_id=asset_id,
                    )
                summary.vulnerabilities_updated += 1

            for row, _ in members:
                row.vulnerability_id = vulnerability.id

        await self.session.flush()
        return summary

    # ----------------------------------------------------------------- secrets
    async def _record_secrets(
        self,
        *,
        org_id: uuid.UUID,
        persisted: list[tuple[Finding, ScanFinding]],
        asset_id: uuid.UUID | None,
    ) -> int:
        """Record detected credentials for rotation tracking."""
        from qguard.common.enums import FindingCategory, SecretValidationStatus

        recorded = 0
        for row, scan_finding in persisted:
            if row.category != FindingCategory.EXPOSED_SECRET:
                continue
            raw = scan_finding.raw or {}
            fingerprint = raw.get("secret_fingerprint")
            if not fingerprint:
                continue

            source_path = (row.location or {}).get("file_path")
            line_number = (row.location or {}).get("start_line")
            already = (
                await self.session.execute(
                    select(DetectedSecret).where(
                        DetectedSecret.org_id == org_id,
                        DetectedSecret.secret_fingerprint == fingerprint,
                        DetectedSecret.source_path == source_path,
                        DetectedSecret.line_number == line_number,
                    )
                )
            ).scalar_one_or_none()
            if already is not None:
                already.finding_id = row.id
                continue

            self.session.add(
                DetectedSecret(
                    org_id=org_id,
                    finding_id=row.id,
                    asset_id=asset_id,
                    secret_type=raw.get("secret_type", "unknown"),
                    detector=raw.get("detector", scan_finding.rule_id),
                    detection_method=raw.get("detection_method", "pattern"),
                    # Only a short, non-recoverable preview is stored.
                    redacted_preview=raw.get("redacted_preview", "*" * 12)[:64],
                    secret_fingerprint=fingerprint,
                    entropy=raw.get("entropy"),
                    source_path=source_path,
                    line_number=line_number,
                    commit_sha=raw.get("commit_sha"),
                    is_in_history=bool(raw.get("is_in_history", False)),
                    exposure=raw.get("exposure", "internal"),
                    validation_status=SecretValidationStatus.UNVERIFIED,
                )
            )
            recorded += 1
        if recorded:
            await self.session.flush()
        return recorded

    # ------------------------------------------------------- absence handling
    async def _mark_absent(
        self,
        *,
        org_id: uuid.UUID,
        asset_id: uuid.UUID,
        engine_key: str,
        seen_fingerprints: set[str],
    ) -> int:
        """Mark findings this engine previously reported but no longer sees.

        Scoped to one engine and one asset: an engine can only speak to what it
        looks at, so a SAST run must never mark a DAST finding absent.
        """
        stmt = select(Finding).where(
            Finding.org_id == org_id,
            Finding.asset_id == asset_id,
            Finding.engine == engine_key,
            Finding.status != FindingStatus.ABSENT,
        )
        if seen_fingerprints:
            stmt = stmt.where(Finding.fingerprint.notin_(seen_fingerprints))

        rows = (await self.session.execute(stmt)).scalars().all()
        for row in rows:
            row.status = FindingStatus.ABSENT
        if rows:
            # Flushed explicitly: the session runs with autoflush disabled, and
            # `_auto_resolve` reads these statuses back with a SELECT. Without
            # the flush it would still see them as active and would never
            # resolve anything — the auto-resolution path would look
            # implemented but do nothing.
            await self.session.flush()
        return len(rows)

    async def _auto_resolve(self, *, org_id: uuid.UUID, asset_id: uuid.UUID) -> int:
        """Resolve vulnerabilities whose every supporting finding is absent.

        Deliberately conservative. A vulnerability is only auto-resolved when
        it is still in an open state, has at least one finding, and *all* of
        them are absent. An item an analyst accepted or marked a false positive
        is left alone, and the transition is recorded as system-initiated so it
        is distinguishable from a human verification.
        """
        candidates = (
            (
                await self.session.execute(
                    select(Vulnerability).where(
                        Vulnerability.org_id == org_id,
                        Vulnerability.asset_id == asset_id,
                        Vulnerability.status.in_(OPEN_VULNERABILITY_STATUSES),
                    )
                )
            )
            .scalars()
            .all()
        )
        if not candidates:
            return 0

        resolved = 0
        for vulnerability in candidates:
            counts = (
                await self.session.execute(
                    select(
                        func.count(Finding.id),
                        func.count(Finding.id).filter(Finding.status == FindingStatus.ABSENT),
                    ).where(
                        Finding.org_id == org_id,
                        Finding.vulnerability_id == vulnerability.id,
                    )
                )
            ).one()
            total, absent = int(counts[0] or 0), int(counts[1] or 0)
            if total == 0 or absent < total:
                continue

            previous = vulnerability.status
            vulnerability.status = VulnerabilityStatus.RESOLVED
            vulnerability.resolved_at = datetime.now(UTC)
            vulnerability.resolution_note = (
                "Automatically resolved: every finding supporting this issue was absent "
                "from the latest completed scan of this asset. Verify before closing."
            )
            self.session.add(
                VulnerabilityEvent(
                    org_id=org_id,
                    vulnerability_id=vulnerability.id,
                    actor_type="system",
                    event_type="auto_resolved",
                    from_status=previous,
                    to_status=VulnerabilityStatus.RESOLVED,
                    note=vulnerability.resolution_note,
                    changes={"findings_absent": absent, "findings_total": total},
                )
            )
            resolved += 1
        return resolved

    # ------------------------------------------------------------------ events
    async def _emit_events(
        self, org_id: uuid.UUID, summary: IngestionSummary, scan_id: uuid.UUID | None
    ) -> None:
        if summary.findings_created or summary.findings_updated:
            await emit(
                EventType.FINDING_CREATED,
                org_id,
                {
                    "scan_id": str(scan_id) if scan_id else None,
                    **summary.as_dict(),
                },
                resource_type="scan",
                resource_id=scan_id,
            )
        critical = summary.severity_counts.get("critical", 0)
        if critical:
            await self.audit.record_security_event(
                org_id=org_id,
                kind=SecurityEventKind.CRITICAL_FINDING,
                severity="critical",
                source="ingestion",
                title=f"{critical} critical finding(s) recorded",
                message=(
                    f"A scan recorded {critical} critical finding(s). Review them before "
                    "anything else in the queue."
                ),
                resource_type="scan",
                resource_id=scan_id,
            )

    # -------------------------------------------------------- manual findings
    async def record_manual_finding(
        self,
        *,
        org_id: uuid.UUID,
        actor_id: uuid.UUID | None,
        scan_finding: ScanFinding,
        asset_id: uuid.UUID | None,
        project_id: uuid.UUID | None = None,
        engagement_id: uuid.UUID | None = None,
    ) -> Finding:
        """Record an analyst-entered finding (the pentest workspace).

        Goes through the same ingestion path as engine output, so a manual
        finding correlates with scanner findings and appears in reports and
        risk scoring identically. A tester confirming by hand what a scanner
        suspected should strengthen one item, not create a second.
        """
        summary = await self.ingest(
            org_id=org_id,
            findings=[scan_finding],
            asset_id=asset_id,
            project_id=project_id,
            engagement_id=engagement_id,
            engine_key=None,
            # A human observation says nothing about what else is absent.
            run_status=EngineRunStatus.DEGRADED,
        )
        row = (
            await self.session.execute(
                select(Finding).where(
                    Finding.org_id == org_id,
                    Finding.fingerprint
                    == scan_finding.fingerprint(asset_key=str(asset_id) if asset_id else None),
                )
            )
        ).scalar_one()
        await self.audit.record(
            action=AuditAction.FINDING_CREATED,
            org_id=org_id,
            actor_id=actor_id,
            actor_type="user",
            resource_type="finding",
            resource_id=row.id,
            resource_label=row.reference,
            after={
                "title": row.title,
                "severity": row.severity,
                "category": row.category,
                "source": "manual",
            },
            metadata=summary.as_dict(),
        )
        return row
