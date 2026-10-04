"""Findings, correlated vulnerabilities, secrets and the CVE cache.

The platform deliberately separates two concepts:

``Finding``
    One **observation** by one engine at one point in time. Raw, immutable
    evidence of what a scanner saw.

``Vulnerability``
    The **correlated issue** that one or more findings point at. This is what
    carries lifecycle state, ownership, SLA and risk, so the same weakness seen
    by SAST, DAST and SCA appears once in vulnerability management with three
    corroborating sources instead of three separate items to triage.

Correlation is driven by ``Finding.correlation_key``: a deterministic hash of
the underlying defect (asset + category + normalised location + CVE/CWE),
*excluding* the engine that reported it.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from qguard.common.database import (
    Base,
    OrgScopedMixin,
    TimestampMixin,
    UUIDArray,
    UUIDPrimaryKeyMixin,
)
from qguard.common.enums import (
    Confidence,
    FindingStatus,
    LicenseRisk,
    SecretValidationStatus,
    Severity,
    VulnerabilityStatus,
)


class Finding(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """A single normalised observation from one engine.

    Every engine emits this shape, which is what makes cross-engine
    correlation, compliance mapping and reporting uniform.
    """

    __tablename__ = "findings"

    reference: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    """Stable human-facing id, e.g. ``FND-2026-014882``."""

    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), index=True
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="SET NULL"), index=True
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), index=True
    )
    engine_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_engine_runs.id", ondelete="SET NULL"), index=True
    )
    vulnerability_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="SET NULL"), index=True
    )
    engagement_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("engagements.id", ondelete="SET NULL"), index=True
    )

    source: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    """Where the finding came from: an engine key, ``manual``, or an importer name."""
    engine: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    engine_version: Mapped[str | None] = mapped_column(String(32))
    rule_id: Mapped[str | None] = mapped_column(String(120), index=True)
    """The engine's own rule identifier, e.g. ``py.subprocess-shell-true``."""

    category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    confidence: Mapped[str] = mapped_column(
        String(16), nullable=False, default=Confidence.MEDIUM, server_default="'medium'"
    )
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    impact: Mapped[str | None] = mapped_column(Text)
    remediation: Mapped[str | None] = mapped_column(Text)
    references: Mapped[list[str]] = mapped_column(
        ARRAY(String(1024)), nullable=False, default=list, server_default="{}"
    )

    evidence: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    """Proof the finding is real: request/response pairs, code excerpts, hashes.

    Secrets are stored redacted here; the raw credential is never persisted.
    """
    location: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    """Normalised position: ``{file, start_line, end_line, url, method, parameter}``."""
    reproduction: Mapped[str | None] = mapped_column(Text)
    """Steps an engineer can follow to re-observe the finding."""

    cve: Mapped[str | None] = mapped_column(String(32), index=True)
    cwe: Mapped[str | None] = mapped_column(String(16), index=True)
    cvss_vector: Mapped[str | None] = mapped_column(String(160))
    cvss_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
    cvss_version: Mapped[str | None] = mapped_column(String(8))
    epss_score: Mapped[float | None] = mapped_column(Numeric(6, 5))
    owasp_top10: Mapped[str | None] = mapped_column(String(16))
    owasp_api_top10: Mapped[str | None] = mapped_column(String(16))
    owasp_asvs: Mapped[list[str]] = mapped_column(
        ARRAY(String(16)), nullable=False, default=list, server_default="{}"
    )
    owasp_masvs: Mapped[list[str]] = mapped_column(
        ARRAY(String(24)), nullable=False, default=list, server_default="{}"
    )
    mastg_tests: Mapped[list[str]] = mapped_column(
        ARRAY(String(24)), nullable=False, default=list, server_default="{}"
    )
    mitre_techniques: Mapped[list[str]] = mapped_column(
        ARRAY(String(16)), nullable=False, default=list, server_default="{}"
    )
    capec: Mapped[list[str]] = mapped_column(
        ARRAY(String(16)), nullable=False, default=list, server_default="{}"
    )

    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    """Identity of this finding *as reported by this engine*. Re-scans update
    the existing row rather than inserting a duplicate."""
    correlation_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    """Identity of the underlying defect, engine-independent. Drives clustering."""

    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default=FindingStatus.NEW, index=True, server_default="'new'"
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    occurrence_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    is_exploitable: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, index=True, server_default="false"
    )
    """Set only when the engine or an analyst actually demonstrated exploitation."""
    exploitability_note: Mapped[str | None] = mapped_column(Text)
    raw: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    """Engine-native payload, retained so an import is never lossy."""

    vulnerability: Mapped[Vulnerability | None] = relationship(
        back_populates="findings", lazy="noload"
    )

    __table_args__ = (
        UniqueConstraint("org_id", "fingerprint", name="uq_findings_org_id_fingerprint"),
        Index("ix_findings_org_severity_status", "org_id", "severity", "status"),
        Index("ix_findings_org_correlation", "org_id", "correlation_key"),
        Index("ix_findings_asset_engine", "asset_id", "engine"),
        Index("ix_findings_org_category_sev", "org_id", "category", "severity"),
        Index("ix_findings_location", "location", postgresql_using="gin"),
        # Trigram index: the findings table is searched with leading-wildcard
        # ILIKE, which would otherwise sequentially scan millions of rows.
        Index(
            "ix_findings_title_trgm",
            "title",
            postgresql_using="gin",
            postgresql_ops={"title": "gin_trgm_ops"},
        ),
        Index(
            "ix_findings_open_critical",
            "org_id",
            "last_seen_at",
            postgresql_where=text("severity IN ('critical','high') AND status <> 'absent'"),
        ),
        CheckConstraint(
            "severity IN ('critical','high','medium','low','info')", name="finding_severity_valid"
        ),
        CheckConstraint(
            "cvss_score IS NULL OR (cvss_score >= 0 AND cvss_score <= 10)",
            name="finding_cvss_range",
        ),
        CheckConstraint(
            "epss_score IS NULL OR (epss_score >= 0 AND epss_score <= 1)",
            name="finding_epss_range",
        ),
        CheckConstraint("cve IS NULL OR cve ~ '^CVE-[0-9]{4}-[0-9]{4,}$'", name="cve_format"),
        CheckConstraint("cwe IS NULL OR cwe ~ '^CWE-[0-9]+$'", name="cwe_format"),
    )


class Vulnerability(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """A correlated, deduplicated security issue under active management.

    One row per real defect per asset, regardless of how many engines found it.
    """

    __tablename__ = "vulnerabilities"

    reference: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    """e.g. ``VULN-2026-000291`` — the id used in reports and tickets."""
    correlation_key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)

    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), index=True
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="SET NULL"), index=True
    )

    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    """Highest severity among the correlated findings."""
    severity_override: Mapped[str | None] = mapped_column(String(16))
    severity_override_reason: Mapped[str | None] = mapped_column(Text)
    """An analyst may adjust severity, but the engine-derived value is retained."""

    cve: Mapped[str | None] = mapped_column(String(32), index=True)
    cve_list: Mapped[list[str]] = mapped_column(
        ARRAY(String(32)), nullable=False, default=list, server_default="{}"
    )
    cwe: Mapped[str | None] = mapped_column(String(16), index=True)
    cvss_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
    cvss_vector: Mapped[str | None] = mapped_column(String(160))
    epss_score: Mapped[float | None] = mapped_column(Numeric(6, 5))
    is_known_exploited: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, index=True, server_default="false"
    )
    """Present in the CISA Known Exploited Vulnerabilities catalogue."""

    status: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        default=VulnerabilityStatus.OPEN,
        index=True,
        server_default="'open'",
    )
    resolution_note: Mapped[str | None] = mapped_column(Text)
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    remediation: Mapped[str | None] = mapped_column(Text)
    remediation_effort: Mapped[str | None] = mapped_column(String(24))
    external_ticket_url: Mapped[str | None] = mapped_column(String(1024))

    risk_score: Mapped[float | None] = mapped_column(Numeric(5, 2), index=True)
    risk_factors: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    """Every input and weight behind ``risk_score``, so the number is auditable."""
    risk_calculated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    is_exploitable: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, index=True, server_default="false"
    )
    source_engines: Mapped[list[str]] = mapped_column(
        ARRAY(String(32)), nullable=False, default=list, server_default="{}"
    )
    finding_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    confirmation_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default="1"
    )
    """Number of independent engines corroborating this issue."""

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verified_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    reopened_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )

    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    sla_days: Mapped[int | None] = mapped_column(Integer)
    sla_breached: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, index=True, server_default="false"
    )

    tags: Mapped[list[str]] = mapped_column(
        ARRAY(String(80)), nullable=False, default=list, server_default="{}"
    )

    findings: Mapped[list[Finding]] = relationship(back_populates="vulnerability", lazy="noload")
    events: Mapped[list[VulnerabilityEvent]] = relationship(
        back_populates="vulnerability", cascade="all, delete-orphan", lazy="noload"
    )

    __table_args__ = (
        UniqueConstraint(
            "org_id", "correlation_key", name="uq_vulnerabilities_org_id_correlation_key"
        ),
        UniqueConstraint("org_id", "reference", name="uq_vulnerabilities_org_id_reference"),
        Index("ix_vulnerabilities_org_status_severity", "org_id", "status", "severity"),
        Index("ix_vulnerabilities_org_risk", "org_id", "risk_score"),
        Index(
            "ix_vulnerabilities_open",
            "org_id",
            "severity",
            "risk_score",
            postgresql_where=text("status IN ('open','confirmed','in_progress','reopened')"),
        ),
        Index("ix_vulnerabilities_project_status", "project_id", "status"),
        Index(
            "ix_vulnerabilities_title_trgm",
            "title",
            postgresql_using="gin",
            postgresql_ops={"title": "gin_trgm_ops"},
        ),
        CheckConstraint(
            "severity IN ('critical','high','medium','low','info')",
            name="vulnerability_severity_valid",
        ),
        CheckConstraint(
            "status IN ('open','confirmed','false_positive','accepted_risk','in_progress',"
            "'resolved','verified','reopened')",
            name="vulnerability_status_valid",
        ),
        CheckConstraint(
            "risk_score IS NULL OR (risk_score >= 0 AND risk_score <= 100)",
            name="vulnerability_risk_range",
        ),
        # Severity may only be overridden with a written justification.
        CheckConstraint(
            "severity_override IS NULL OR severity_override_reason IS NOT NULL",
            name="severity_override_requires_reason",
        ),
    )

    @property
    def effective_severity(self) -> str:
        return self.severity_override or self.severity


class VulnerabilityEvent(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """Immutable lifecycle history for a vulnerability."""

    __tablename__ = "vulnerability_events"

    vulnerability_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True
    )
    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    actor_type: Mapped[str] = mapped_column(
        String(24), nullable=False, default="user", server_default="'user'"
    )
    event_type: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    from_status: Mapped[str | None] = mapped_column(String(24))
    to_status: Mapped[str | None] = mapped_column(String(24))
    note: Mapped[str | None] = mapped_column(Text)
    changes: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )

    vulnerability: Mapped[Vulnerability] = relationship(back_populates="events", lazy="noload")

    __table_args__ = (
        Index("ix_vulnerability_events_vuln_time", "vulnerability_id", "occurred_at"),
    )


class DetectedSecret(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """A credential discovered by secrets detection.

    The platform stores an HMAC fingerprint and a short redacted preview only.
    The credential itself is never written to the database, logs or reports, so
    the platform does not become a second copy of the secret store. The
    fingerprint is still enough to recognise the same secret elsewhere and to
    confirm that rotation actually happened.
    """

    __tablename__ = "detected_secrets"

    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), index=True
    )
    secret_type: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    detector: Mapped[str] = mapped_column(String(80), nullable=False)
    detection_method: Mapped[str] = mapped_column(
        String(32), nullable=False, default="pattern", server_default="'pattern'"
    )
    """``pattern``, ``entropy`` or ``pattern+entropy``."""
    redacted_preview: Mapped[str] = mapped_column(String(64), nullable=False)
    secret_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    entropy: Mapped[float | None] = mapped_column(Numeric(6, 3))
    source_path: Mapped[str | None] = mapped_column(String(2048))
    line_number: Mapped[int | None] = mapped_column(Integer)
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    is_in_history: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    exposure: Mapped[str] = mapped_column(
        String(32), nullable=False, default="internal", server_default="'internal'"
    )
    """``public``, ``internal``, ``build_artifact``, ``mobile_package``."""
    validation_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=SecretValidationStatus.UNVERIFIED,
        index=True,
        server_default="'unverified'",
    )
    validation_note: Mapped[str | None] = mapped_column(Text)
    """Validation is operator-initiated and never performs the privileged
    action a credential grants — it only establishes whether rotation is still
    outstanding."""
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint(
            "org_id",
            "secret_fingerprint",
            "source_path",
            "line_number",
            name="uq_detected_secrets_location",
        ),
        Index("ix_detected_secrets_org_type", "org_id", "secret_type"),
        Index("ix_detected_secrets_org_validation", "org_id", "validation_status"),
    )


class CVERecord(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Local cache of public vulnerability intelligence.

    Not tenant-scoped: CVE data is public reference material. Caching it means
    SCA still works offline, and when the cache is stale the engine run is
    marked ``degraded`` rather than reporting a clean result from missing data.
    """

    __tablename__ = "cve_records"

    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    summary: Mapped[str | None] = mapped_column(Text)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cvss_v3_score: Mapped[float | None] = mapped_column(Numeric(3, 1), index=True)
    cvss_v3_vector: Mapped[str | None] = mapped_column(String(160))
    cvss_v4_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
    cvss_v4_vector: Mapped[str | None] = mapped_column(String(200))
    severity: Mapped[str | None] = mapped_column(String(16), index=True)
    cwe_ids: Mapped[list[str]] = mapped_column(
        ARRAY(String(16)), nullable=False, default=list, server_default="{}"
    )
    epss_score: Mapped[float | None] = mapped_column(Numeric(6, 5))
    epss_percentile: Mapped[float | None] = mapped_column(Numeric(6, 5))
    is_known_exploited: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, index=True, server_default="false"
    )
    kev_added_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    has_public_exploit: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    affected_ranges: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    fixed_versions: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    references: Mapped[list[str]] = mapped_column(
        ARRAY(String(1024)), nullable=False, default=list, server_default="{}"
    )
    aliases: Mapped[list[str]] = mapped_column(
        ARRAY(String(64)), nullable=False, default=list, server_default="{}"
    )
    data_source: Mapped[str] = mapped_column(
        String(32), nullable=False, default="osv", server_default="'osv'"
    )
    fetched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )

    __table_args__ = (
        Index("ix_cve_records_severity_kev", "severity", "is_known_exploited"),
        CheckConstraint("cve_id ~ '^(CVE|GHSA|PYSEC|OSV|RUSTSEC|GO)-'", name="cve_id_format"),
    )


class LicenseFinding(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """A dependency licence that conflicts with organizational policy."""

    __tablename__ = "license_findings"

    dependency_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dependencies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    license_id: Mapped[str] = mapped_column(String(120), nullable=False)
    risk: Mapped[str] = mapped_column(
        String(24), nullable=False, default=LicenseRisk.UNKNOWN, server_default="'unknown'"
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    is_acknowledged: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )

    __table_args__ = (
        UniqueConstraint("dependency_id", "license_id", name="uq_license_findings_dependency"),
    )


class FindingComment(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """Analyst discussion attached to a vulnerability."""

    __tablename__ = "finding_comments"

    vulnerability_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="CASCADE"), index=True
    )
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), index=True
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    body: Mapped[str] = mapped_column(Text, nullable=False)
    is_internal: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    """Internal comments are excluded from client-facing report exports."""
    mentions: Mapped[list[uuid.UUID]] = mapped_column(
        UUIDArray, nullable=False, default=list, server_default="{}"
    )

    __table_args__ = (
        CheckConstraint(
            "vulnerability_id IS NOT NULL OR finding_id IS NOT NULL",
            name="comment_requires_target",
        ),
    )


# Severity ordering helper used by aggregate dashboard queries. Defined here so
# the SQL ordering matches the Python `severity_rank` helper exactly.
SEVERITY_SQL_ORDER = text(
    "CASE severity WHEN 'critical' THEN 5 WHEN 'high' THEN 4 WHEN 'medium' THEN 3 "
    "WHEN 'low' THEN 2 WHEN 'info' THEN 1 ELSE 0 END"
)

__all__ = [
    "SEVERITY_SQL_ORDER",
    "CVERecord",
    "DetectedSecret",
    "Finding",
    "FindingComment",
    "LicenseFinding",
    "Severity",
    "Vulnerability",
    "VulnerabilityEvent",
]
