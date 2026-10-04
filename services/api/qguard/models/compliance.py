"""Compliance framework mapping engine.

Framework knowledge lives in data, never inside scanners. A scanner emits a
normalised finding with its CWE, OWASP and category metadata; the mapping table
translates those keys into control references for any framework. Adding a
framework is a data load, not a code change, and a scanner never needs to know
which frameworks exist.
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
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from qguard.common.database import (
    AuthorMixin,
    Base,
    OrgScopedMixin,
    TimestampMixin,
    UUIDArray,
    UUIDPrimaryKeyMixin,
)
from qguard.common.enums import ControlAssessmentStatus


class ComplianceFramework(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A security standard or regulation. Global reference data."""

    __tablename__ = "compliance_frameworks"

    key: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    """``owasp_top10``, ``owasp_asvs``, ``owasp_masvs``, ``nist_csf``, ``nist_800_53``,
    ``nist_800_61``, ``nist_800_218``, ``cis_controls``, ``iso_27001``, ``mitre_attack``."""
    name: Mapped[str] = mapped_column(String(240), nullable=False)
    version: Mapped[str] = mapped_column(
        String(32), nullable=False, default="", server_default="''"
    )
    authority: Mapped[str | None] = mapped_column(String(160))
    description: Mapped[str | None] = mapped_column(Text)
    url: Mapped[str | None] = mapped_column(String(600))
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    control_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )

    controls: Mapped[list[ComplianceControl]] = relationship(
        back_populates="framework", cascade="all, delete-orphan", lazy="noload"
    )


class ComplianceControl(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """One control within a framework. Hierarchical via ``parent_id``."""

    __tablename__ = "compliance_controls"

    framework_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    control_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    """The framework's own identifier, e.g. ``A01:2021``, ``AC-3``, ``MASVS-CRYPTO-1``."""
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    family: Mapped[str | None] = mapped_column(String(160), index=True)
    parent_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("compliance_controls.id", ondelete="CASCADE")
    )
    level: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")
    priority: Mapped[str | None] = mapped_column(String(16))
    is_automatable: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    """Whether platform data alone can evidence this control, or human attestation is required."""
    testing_guidance: Mapped[str | None] = mapped_column(Text)

    framework: Mapped[ComplianceFramework] = relationship(back_populates="controls", lazy="noload")

    __table_args__ = (
        UniqueConstraint("framework_id", "control_id", name="uq_compliance_controls_framework_id"),
        Index("ix_compliance_controls_framework_family", "framework_id", "family"),
    )


class ControlMapping(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Translates a finding attribute into a framework control reference.

    The reusable mapping layer. ``source_type``/``source_key`` is matched against
    a finding's CWE, OWASP category, finding category or MITRE technique; the
    mapped control is then evidenced by that finding.
    """

    __tablename__ = "control_mappings"

    source_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    source_key: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    control_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("compliance_controls.id", ondelete="CASCADE"), nullable=False, index=True
    )
    relationship_kind: Mapped[str] = mapped_column(
        String(24), nullable=False, default="maps_to", server_default="'maps_to'"
    )
    """``maps_to``, ``partially_maps``, ``related``. Partial maps weight lower in scoring."""
    weight: Mapped[float] = mapped_column(
        Numeric(3, 2), nullable=False, default=1.0, server_default="1.0"
    )
    rationale: Mapped[str | None] = mapped_column(Text)
    is_system: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )

    __table_args__ = (
        UniqueConstraint(
            "source_type", "source_key", "control_id", name="uq_control_mappings_triple"
        ),
        Index("ix_control_mappings_lookup", "source_type", "source_key"),
        CheckConstraint(
            "source_type IN ('cwe','cve','owasp_top10','owasp_asvs','owasp_masvs',"
            "'owasp_api_top10','finding_category','mitre_attack','capec','engine')",
            name="mapping_source_type_valid",
        ),
        CheckConstraint("weight > 0 AND weight <= 1", name="mapping_weight_range"),
    )


class ComplianceAssessment(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin, AuthorMixin):
    """A point-in-time evaluation of one framework for a project or organization.

    The score is computed from evidenced control results. Controls that cannot
    be evidenced by platform data are reported as ``not_assessed`` rather than
    being assumed compliant.
    """

    __tablename__ = "compliance_assessments"

    framework_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("compliance_frameworks.id", ondelete="CASCADE"), nullable=False, index=True
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="in_progress", server_default="'in_progress'"
    )
    scope_description: Mapped[str | None] = mapped_column(Text)

    compliance_score: Mapped[float | None] = mapped_column(Numeric(5, 2))
    controls_total: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    controls_passed: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    controls_failed: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    controls_partial: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    controls_not_applicable: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    controls_not_assessed: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    """Honest reporting of coverage gaps instead of inflating the score."""

    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    assessor_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    summary: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    score_breakdown: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )

    control_results: Mapped[list[ControlAssessment]] = relationship(
        back_populates="assessment", cascade="all, delete-orphan", lazy="noload"
    )

    __table_args__ = (
        Index("ix_compliance_assessments_org_framework", "org_id", "framework_id"),
        CheckConstraint(
            "compliance_score IS NULL OR (compliance_score >= 0 AND compliance_score <= 100)",
            name="compliance_score_range",
        ),
        CheckConstraint(
            "status IN ('in_progress','completed','failed','cancelled')",
            name="compliance_assessment_status_valid",
        ),
    )


class ControlAssessment(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """The evaluated result for one control, with the evidence behind it."""

    __tablename__ = "control_assessments"

    assessment_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("compliance_assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    control_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("compliance_controls.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        default=ControlAssessmentStatus.NOT_ASSESSED,
        index=True,
        server_default="'not_assessed'",
    )
    determination: Mapped[str] = mapped_column(
        String(24), nullable=False, default="automated", server_default="'automated'"
    )
    """``automated`` (derived from findings) or ``manual`` (analyst attestation)."""
    finding_ids: Mapped[list[uuid.UUID]] = mapped_column(
        UUIDArray, nullable=False, default=list, server_default="{}"
    )
    vulnerability_ids: Mapped[list[uuid.UUID]] = mapped_column(
        UUIDArray, nullable=False, default=list, server_default="{}"
    )
    evidence_ids: Mapped[list[uuid.UUID]] = mapped_column(
        UUIDArray, nullable=False, default=list, server_default="{}"
    )
    evidence_summary: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    """Exactly why the control passed or failed, so the result is defensible."""
    notes: Mapped[str | None] = mapped_column(Text)
    gap_description: Mapped[str | None] = mapped_column(Text)
    remediation_plan: Mapped[str | None] = mapped_column(Text)
    assessed_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    assessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    assessment: Mapped[ComplianceAssessment] = relationship(
        back_populates="control_results", lazy="noload"
    )

    __table_args__ = (
        UniqueConstraint("assessment_id", "control_id", name="uq_control_assessments_pair"),
        Index("ix_control_assessments_assessment_status", "assessment_id", "status"),
        CheckConstraint(
            "status IN ('pass','fail','partial','not_applicable','not_assessed')",
            name="control_assessment_status_valid",
        ),
        CheckConstraint(
            "status <> 'fail' OR gap_description IS NOT NULL",
            name="failed_control_requires_gap",
        ),
        CheckConstraint(
            "status <> 'not_applicable' OR notes IS NOT NULL",
            name="not_applicable_requires_justification",
        ),
    )
