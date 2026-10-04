"""Report templates and generated report artifacts."""

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
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from qguard.common.database import (
    AuthorMixin,
    Base,
    OrgScopedMixin,
    TimestampMixin,
    UUIDArray,
    UUIDPrimaryKeyMixin,
)
from qguard.common.enums import ReportStatus


class ReportTemplate(Base, UUIDPrimaryKeyMixin, TimestampMixin, AuthorMixin):
    """A report definition: which sections, in what order, from which data."""

    __tablename__ = "report_templates"

    org_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    """Null for the system templates shipped with the platform."""
    key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(240), nullable=False)
    report_kind: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    sections: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    """Ordered section descriptors; each names the data provider that fills it."""
    default_formats: Mapped[list[str]] = mapped_column(
        ARRAY(String(8)), nullable=False, default=list, server_default="{}"
    )
    include_internal_notes: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    """Client-facing templates exclude internal analyst commentary."""
    classification_label: Mapped[str] = mapped_column(
        String(48), nullable=False, default="CONFIDENTIAL", server_default="'CONFIDENTIAL'"
    )
    is_system: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    branding: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )

    __table_args__ = (
        UniqueConstraint("org_id", "key", name="uq_report_templates_org_key"),
        CheckConstraint(
            "report_kind IN ('executive','technical','vulnerability','penetration_test',"
            "'mobile_security','web_security','api_security','dfir','incident','compliance',"
            "'cryptographic_assessment','quantum_readiness','asset_inventory','scan_summary')",
            name="report_kind_valid",
        ),
    )


class Report(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """A generated report.

    ``data_snapshot`` preserves the exact figures used at generation time, so a
    report re-read months later still reconciles with what it stated, even
    though the live data has moved on. Every number in it came from platform
    records.
    """

    __tablename__ = "reports"

    reference: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(400), nullable=False)
    report_kind: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    template_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("report_templates.id", ondelete="SET NULL")
    )
    report_format: Mapped[str] = mapped_column(String(8), nullable=False)
    status: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        default=ReportStatus.QUEUED,
        index=True,
        server_default="'queued'",
    )

    project_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="SET NULL"), index=True
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    engagement_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("engagements.id", ondelete="SET NULL"), index=True
    )
    case_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("cases.id", ondelete="SET NULL"))
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL")
    )
    assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("compliance_assessments.id", ondelete="SET NULL")
    )
    asset_ids: Mapped[list[uuid.UUID]] = mapped_column(
        UUIDArray, nullable=False, default=list, server_default="{}"
    )

    parameters: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    data_snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    record_counts: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    """How many of each record type the report drew on. Makes coverage explicit."""
    classification_label: Mapped[str] = mapped_column(
        String(48), nullable=False, default="CONFIDENTIAL", server_default="'CONFIDENTIAL'"
    )

    storage_backend: Mapped[str | None] = mapped_column(String(24))
    storage_key: Mapped[str | None] = mapped_column(String(1024))
    file_sha256: Mapped[str | None] = mapped_column(String(64))
    """Lets a distributed report be proven unmodified."""
    size_bytes: Mapped[int | None] = mapped_column(BigInteger)
    page_count: Mapped[int | None] = mapped_column()

    requested_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    generated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    generation_duration_seconds: Mapped[float | None] = mapped_column()
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)
    download_count: Mapped[int] = mapped_column(nullable=False, default=0, server_default="0")

    __table_args__ = (
        UniqueConstraint("org_id", "reference", name="uq_reports_org_reference"),
        Index("ix_reports_org_kind_status", "org_id", "report_kind", "status"),
        CheckConstraint(
            "report_format IN ('pdf','docx','json','csv','html')", name="report_format_valid"
        ),
        CheckConstraint(
            "status IN ('queued','generating','available','failed','expired')",
            name="report_status_valid",
        ),
        CheckConstraint(
            "status <> 'available' OR (storage_key IS NOT NULL AND file_sha256 IS NOT NULL)",
            name="available_report_requires_artifact",
        ),
        CheckConstraint(
            "status <> 'failed' OR error_message IS NOT NULL",
            name="failed_report_requires_reason",
        ),
    )
