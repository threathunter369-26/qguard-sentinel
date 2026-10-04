"""Incident response: incidents, tasks, responders, updates and IOC linkage.

The lifecycle follows NIST SP 800-61: detection → triage → investigation →
containment → eradication → recovery → lessons learned. Phase transitions are
timestamped individually so response metrics (time to contain, time to recover)
are measured from recorded events rather than estimated.
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
    UUIDPrimaryKeyMixin,
)
from qguard.common.enums import (
    TLP,
    IncidentCategory,
    IncidentPhase,
    IncidentStatus,
    TaskStatus,
)


class Incident(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin, AuthorMixin):
    """A declared security incident."""

    __tablename__ = "incidents"

    incident_number: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    """e.g. ``INC-2026-0071``."""
    title: Mapped[str] = mapped_column(String(400), nullable=False)
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default="medium", index=True, server_default="'medium'"
    )
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default=IncidentStatus.OPEN, index=True, server_default="'open'"
    )
    phase: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=IncidentPhase.DETECTION,
        index=True,
        server_default="'detection'",
    )
    category: Mapped[str] = mapped_column(
        String(48),
        nullable=False,
        default=IncidentCategory.OTHER,
        index=True,
        server_default="'other'",
    )
    tlp: Mapped[str] = mapped_column(
        String(16), nullable=False, default=TLP.AMBER, server_default="'amber'"
    )

    summary: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="''")
    impact_assessment: Mapped[str | None] = mapped_column(Text)
    business_impact: Mapped[str | None] = mapped_column(Text)
    containment_strategy: Mapped[str | None] = mapped_column(Text)
    eradication_actions: Mapped[str | None] = mapped_column(Text)
    recovery_actions: Mapped[str | None] = mapped_column(Text)
    root_cause: Mapped[str | None] = mapped_column(Text)
    contributing_factors: Mapped[str | None] = mapped_column(Text)
    lessons_learned: Mapped[str | None] = mapped_column(Text)

    is_data_breach: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    requires_notification: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    """Set when a regulator or data subject notification obligation may apply."""
    notification_note: Mapped[str | None] = mapped_column(Text)
    records_affected: Mapped[int | None] = mapped_column(Integer)

    commander_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    case_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cases.id", ondelete="SET NULL"), index=True
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="SET NULL")
    )
    source_vulnerability_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("vulnerabilities.id", ondelete="SET NULL")
    )
    """Set when the incident is traced back to a known, tracked vulnerability."""

    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    detected_by: Mapped[str | None] = mapped_column(String(240))
    detection_source: Mapped[str | None] = mapped_column(String(120))
    declared_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    triaged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    contained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    eradicated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    recovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    sla_response_minutes: Mapped[int | None] = mapped_column(Integer)
    sla_breached: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(String(80)), nullable=False, default=list, server_default="{}"
    )
    mitre_techniques: Mapped[list[str]] = mapped_column(
        ARRAY(String(16)), nullable=False, default=list, server_default="{}"
    )
    metrics: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )

    tasks: Mapped[list[IncidentTask]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", lazy="noload"
    )
    updates: Mapped[list[IncidentUpdate]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", lazy="noload"
    )
    responders: Mapped[list[IncidentResponder]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", lazy="noload"
    )

    __table_args__ = (
        UniqueConstraint("org_id", "incident_number", name="uq_incidents_org_id_number"),
        Index("ix_incidents_org_status_severity", "org_id", "status", "severity"),
        Index("ix_incidents_org_phase", "org_id", "phase"),
        Index("ix_incidents_org_detected", "org_id", "detected_at"),
        CheckConstraint(
            "phase IN ('detection','triage','investigation','containment','eradication',"
            "'recovery','lessons_learned','closed')",
            name="incident_phase_valid",
        ),
        CheckConstraint(
            "status IN ('open','monitoring','contained','resolved','closed','false_alarm')",
            name="incident_status_valid",
        ),
        CheckConstraint(
            "severity IN ('critical','high','medium','low','info')",
            name="incident_severity_valid",
        ),
        # Closing an incident requires both a timestamp and a root cause, so
        # post-incident review cannot be skipped by flipping a status.
        CheckConstraint(
            "status <> 'closed' OR (closed_at IS NOT NULL AND root_cause IS NOT NULL)",
            name="closed_incident_requires_root_cause",
        ),
        CheckConstraint(
            "contained_at IS NULL OR contained_at >= detected_at",
            name="containment_after_detection",
        ),
    )


class IncidentAsset(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """An asset involved in an incident, and how."""

    __tablename__ = "incident_assets"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    involvement: Mapped[str] = mapped_column(
        String(48), nullable=False, default="affected", server_default="'affected'"
    )
    """``affected``, ``compromised``, ``entry_point``, ``lateral_target``, ``exfil_path``."""
    impact_note: Mapped[str | None] = mapped_column(Text)
    is_contained: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    contained_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_recovered: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    recovered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (UniqueConstraint("incident_id", "asset_id", name="uq_incident_assets_pair"),)


class IncidentTask(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """A response action tracked within an incident."""

    __tablename__ = "incident_tasks"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(400), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    phase: Mapped[str] = mapped_column(
        String(32), nullable=False, default=IncidentPhase.TRIAGE, server_default="'triage'"
    )
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default=TaskStatus.TODO, index=True, server_default="'todo'"
    )
    priority: Mapped[str] = mapped_column(
        String(16), nullable=False, default="medium", server_default="'medium'"
    )
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    outcome: Mapped[str | None] = mapped_column(Text)
    blocked_reason: Mapped[str | None] = mapped_column(Text)
    order_index: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")

    incident: Mapped[Incident] = relationship(back_populates="tasks", lazy="noload")

    __table_args__ = (
        Index("ix_incident_tasks_incident_status", "incident_id", "status"),
        CheckConstraint(
            "status IN ('todo','in_progress','blocked','done','cancelled')",
            name="incident_task_status_valid",
        ),
        CheckConstraint(
            "status <> 'done' OR completed_at IS NOT NULL",
            name="done_task_requires_timestamp",
        ),
        CheckConstraint(
            "status <> 'blocked' OR blocked_reason IS NOT NULL",
            name="blocked_task_requires_reason",
        ),
    )


class IncidentResponder(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    __tablename__ = "incident_responders"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    responder_role: Mapped[str] = mapped_column(
        String(48), nullable=False, default="responder", server_default="'responder'"
    )
    """``commander``, ``investigator``, ``communications``, ``legal``, ``scribe``."""
    joined_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    left_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    incident: Mapped[Incident] = relationship(back_populates="responders", lazy="noload")

    __table_args__ = (
        UniqueConstraint(
            "incident_id", "user_id", "responder_role", name="uq_incident_responders_role"
        ),
    )


class IncidentUpdate(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """A log entry, status change or stakeholder communication on an incident."""

    __tablename__ = "incident_updates"

    incident_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    update_kind: Mapped[str] = mapped_column(
        String(32), nullable=False, default="note", server_default="'note'"
    )
    """``note``, ``action``, ``status_change``, ``phase_change``, ``communication``, ``finding``."""
    audience: Mapped[str] = mapped_column(
        String(32), nullable=False, default="internal", server_default="'internal'"
    )
    """``internal``, ``leadership``, ``customer``, ``regulator``, ``public``."""
    title: Mapped[str | None] = mapped_column(String(300))
    body: Mapped[str] = mapped_column(Text, nullable=False)
    from_value: Mapped[str | None] = mapped_column(String(64))
    to_value: Mapped[str | None] = mapped_column(String(64))
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    attachments: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )

    incident: Mapped[Incident] = relationship(back_populates="updates", lazy="noload")

    __table_args__ = (
        Index("ix_incident_updates_incident_time", "incident_id", "occurred_at"),
        CheckConstraint(
            "update_kind IN ('note','action','status_change','phase_change','communication',"
            "'finding')",
            name="incident_update_kind_valid",
        ),
    )
