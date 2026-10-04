"""Scan orchestration, test authorizations, per-engine runs and the job queue."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from qguard.common.database import (
    AuthorMixin,
    Base,
    OrgScopedMixin,
    TimestampMixin,
    UUIDArray,
    UUIDPrimaryKeyMixin,
)
from qguard.common.enums import (
    AuthorizationStatus,
    EngineRunStatus,
    JobStatus,
    ScanStatus,
)


class TestAuthorization(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin, AuthorMixin):
    """Written authorization permitting active security testing of named targets.

    This is the platform's hard safety boundary. Every active engine checks the
    requested target against an authorization that is ``active``, inside its
    validity window and whose scope rules cover the target. If no authorization
    matches, the engine run is recorded as ``unauthorized`` and refused — the
    scan is never silently downgraded or reported as clean.
    """

    __tablename__ = "test_authorizations"

    name: Mapped[str] = mapped_column(String(240), nullable=False)
    reference: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    """Internal change/ticket reference tying the authorization to a paper trail."""
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=AuthorizationStatus.DRAFT,
        index=True,
        server_default="'draft'",
    )

    scope_allow: Mapped[list[str]] = mapped_column(
        ARRAY(String(512)), nullable=False, default=list, server_default="{}"
    )
    """In-scope rules: hosts, host globs, CIDRs, URL prefixes, host:port ranges."""
    scope_deny: Mapped[list[str]] = mapped_column(
        ARRAY(String(512)), nullable=False, default=list, server_default="{}"
    )
    """Explicit exclusions. Always evaluated first and always win."""

    rules_of_engagement: Mapped[str] = mapped_column(
        Text, nullable=False, default="", server_default="''"
    )
    permitted_engines: Mapped[list[str]] = mapped_column(
        ARRAY(String(32)), nullable=False, default=list, server_default="{}"
    )
    """Empty means every engine is permitted within the scope rules."""
    allow_intrusive: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    """Gates checks that modify state or are noticeably disruptive."""
    max_requests_per_second: Mapped[float | None] = mapped_column(Numeric(8, 2))
    testing_window: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    """Optional permitted hours, e.g. ``{"timezone":"UTC","hours":[[22,0],[6,0]]}``."""
    emergency_contact: Mapped[str | None] = mapped_column(String(320))

    requested_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    approved_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    approver_note: Mapped[str | None] = mapped_column(Text)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_reason: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        UniqueConstraint("org_id", "reference", name="uq_test_authorizations_org_id_reference"),
        Index("ix_test_authorizations_active", "org_id", "status", "valid_until"),
        CheckConstraint(
            "status IN ('draft','pending_approval','active','expired','revoked','rejected')",
            name="authorization_status_valid",
        ),
        CheckConstraint(
            "valid_from IS NULL OR valid_until IS NULL OR valid_until > valid_from",
            name="authorization_window_ordered",
        ),
        # An active authorization must have been approved by somebody: scope
        # approval can never be self-granted implicitly by creating a row.
        CheckConstraint(
            "status <> 'active' OR (approved_by IS NOT NULL AND approved_at IS NOT NULL)",
            name="active_authorization_requires_approval",
        ),
    )


class ScanProfile(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin, AuthorMixin):
    """A reusable, named combination of engines and their configuration."""

    __tablename__ = "scan_profiles"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    scan_type: Mapped[str] = mapped_column(String(48), nullable=False)
    engines: Mapped[list[str]] = mapped_column(
        ARRAY(String(32)), nullable=False, default=list, server_default="{}"
    )
    engine_config: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    is_system: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    is_passive_only: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    """Passive profiles need no test authorization — they send no traffic to targets."""

    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_scan_profiles_org_id_name"),)


class Scan(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin, AuthorMixin):
    """One orchestrated assessment across one or more engines."""

    __tablename__ = "scans"

    reference: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    """Human-readable identifier, e.g. ``SCAN-2026-000412``."""
    name: Mapped[str | None] = mapped_column(String(240))
    scan_type: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default=ScanStatus.QUEUED, index=True, server_default="'queued'"
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="SET NULL"), index=True
    )
    profile_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_profiles.id", ondelete="SET NULL")
    )
    authorization_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("test_authorizations.id", ondelete="SET NULL"), index=True
    )
    engagement_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("engagements.id", ondelete="SET NULL"), index=True
    )
    requested_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    triggered_by: Mapped[str] = mapped_column(
        String(32), nullable=False, default="user", server_default="'user'"
    )
    """``user``, ``schedule``, ``api``, ``ci``, ``webhook``."""

    asset_ids: Mapped[list[uuid.UUID]] = mapped_column(
        UUIDArray, nullable=False, default=list, server_default="{}"
    )
    targets: Mapped[list[str]] = mapped_column(
        ARRAY(String(2048)), nullable=False, default=list, server_default="{}"
    )
    engines: Mapped[list[str]] = mapped_column(
        ARRAY(String(32)), nullable=False, default=list, server_default="{}"
    )
    config: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )

    queued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    duration_seconds: Mapped[float | None] = mapped_column(Numeric(12, 3))

    progress: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, default=0, server_default="0"
    )
    engines_total: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    engines_completed: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    engines_failed: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    findings_created: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    findings_by_severity: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    error_message: Mapped[str | None] = mapped_column(Text)
    """Populated verbatim on failure. Never replaced with a generic success state."""
    cancel_requested: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )

    engine_runs: Mapped[list[ScanEngineRun]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )

    __table_args__ = (
        UniqueConstraint("org_id", "reference", name="uq_scans_org_id_reference"),
        Index("ix_scans_org_status_queued", "org_id", "status", "queued_at"),
        Index("ix_scans_org_project_finished", "org_id", "project_id", "finished_at"),
        CheckConstraint(
            "status IN ('queued','running','completed','partial','failed','cancelled')",
            name="scan_status_valid",
        ),
        CheckConstraint("progress BETWEEN 0 AND 100", name="scan_progress_range"),
    )


class ScanEngineRun(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """The outcome of one engine within a scan.

    Engine outcomes are recorded individually and surfaced in the UI so a
    failure is visible as ``Scanner Status: Failed`` with its real reason,
    rather than disappearing into an aggregate "completed" scan.
    """

    __tablename__ = "scan_engine_runs"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    engine_key: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    engine_version: Mapped[str | None] = mapped_column(String(32))
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), index=True
    )
    target: Mapped[str | None] = mapped_column(String(2048))
    status: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        default=EngineRunStatus.PENDING,
        index=True,
        server_default="'pending'",
    )
    progress: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, default=0, server_default="0"
    )
    progress_message: Mapped[str | None] = mapped_column(String(500))

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_seconds: Mapped[float | None] = mapped_column(Numeric(12, 3))

    findings_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    checks_executed: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    items_examined: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    requests_sent: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )

    error_type: Mapped[str | None] = mapped_column(String(80))
    error_message: Mapped[str | None] = mapped_column(Text)
    degraded_reason: Mapped[str | None] = mapped_column(Text)
    """Why results are incomplete, e.g. an unreachable vulnerability database."""
    scope_decision: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    """The recorded authorization decision for this run, allowed or refused."""
    stats: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    warnings: Mapped[list[str]] = mapped_column(
        ARRAY(Text), nullable=False, default=list, server_default="{}"
    )

    scan: Mapped[Scan] = relationship(back_populates="engine_runs", lazy="raise_on_sql")

    __table_args__ = (
        Index("ix_scan_engine_runs_scan_engine", "scan_id", "engine_key"),
        CheckConstraint(
            "status IN ('pending','running','completed','degraded','failed','skipped',"
            "'cancelled','unauthorized')",
            name="engine_run_status_valid",
        ),
        # A terminal failure must always carry a reason.
        CheckConstraint(
            "status <> 'failed' OR error_message IS NOT NULL",
            name="failed_run_requires_reason",
        ),
        CheckConstraint(
            "status <> 'degraded' OR degraded_reason IS NOT NULL",
            name="degraded_run_requires_reason",
        ),
    )


class Job(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """A durable background work item.

    The queue lives in PostgreSQL and is claimed with ``SELECT ... FOR UPDATE
    SKIP LOCKED``, so the platform needs no extra broker to run, while workers
    scale horizontally and a crashed worker's lease expires and is retried.
    """

    __tablename__ = "jobs"

    kind: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default=JobStatus.QUEUED, index=True, server_default="'queued'"
    )
    priority: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, default=100, server_default="100"
    )
    """Lower runs first. Interactive scans use 50; retention sweeps use 900."""
    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    result: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )

    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), index=True
    )
    engine_run_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scan_engine_runs.id", ondelete="CASCADE")
    )
    report_id: Mapped[uuid.UUID | None] = mapped_column()
    evidence_id: Mapped[uuid.UUID | None] = mapped_column()
    requested_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )

    attempts: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, default=0, server_default="0"
    )
    max_attempts: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, default=3, server_default="3"
    )
    run_after: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    locked_by: Mapped[str | None] = mapped_column(String(120))
    locked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    progress: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, default=0, server_default="0"
    )
    progress_message: Mapped[str | None] = mapped_column(String(500))
    error_message: Mapped[str | None] = mapped_column(Text)
    error_traceback: Mapped[str | None] = mapped_column(Text)
    """Retained for operators; never included in an API response body."""
    cancel_requested: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )

    __table_args__ = (
        # The claim query's covering index: ready jobs in priority order.
        Index(
            "ix_jobs_claimable",
            "status",
            "priority",
            "run_after",
            postgresql_where=text("status = 'queued'"),
        ),
        Index("ix_jobs_org_kind_status", "org_id", "kind", "status"),
        Index(
            "ix_jobs_stale_leases",
            "lease_expires_at",
            postgresql_where=text("status = 'running'"),
        ),
        CheckConstraint(
            "status IN ('queued','running','completed','failed','cancelled')",
            name="job_status_valid",
        ),
        CheckConstraint("attempts <= max_attempts + 1", name="job_attempts_bounded"),
        CheckConstraint("progress BETWEEN 0 AND 100", name="job_progress_range"),
    )


class ScanSchedule(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin, AuthorMixin):
    """Recurring scan definition evaluated by the worker's scheduler tick."""

    __tablename__ = "scan_schedules"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    profile_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_profiles.id", ondelete="CASCADE"), nullable=False
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE")
    )
    authorization_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("test_authorizations.id", ondelete="SET NULL")
    )
    asset_ids: Mapped[list[uuid.UUID]] = mapped_column(
        UUIDArray, nullable=False, default=list, server_default="{}"
    )
    asset_filter: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    cron_expression: Mapped[str] = mapped_column(String(120), nullable=False)
    timezone: Mapped[str] = mapped_column(
        String(64), nullable=False, default="UTC", server_default="'UTC'"
    )
    is_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, index=True, server_default="true"
    )
    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_scan_id: Mapped[uuid.UUID | None] = mapped_column()
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    consecutive_failures: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, default=0, server_default="0"
    )

    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_scan_schedules_org_id_name"),)


class ScanMetric(Base, UUIDPrimaryKeyMixin, OrgScopedMixin):
    """Rolled-up counters used for scan-activity charts without table scans."""

    __tablename__ = "scan_metrics"

    bucket_date: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    engine_key: Mapped[str | None] = mapped_column(String(32))
    scans_total: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    scans_failed: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    findings_total: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    duration_seconds_total: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )

    __table_args__ = (
        UniqueConstraint("org_id", "bucket_date", "engine_key", name="uq_scan_metrics_bucket"),
    )
