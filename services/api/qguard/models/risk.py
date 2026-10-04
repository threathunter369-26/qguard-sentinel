"""Risk posture snapshots.

Trend charts are built from recorded snapshots, not recomputed guesses: a
historical risk score is whatever the platform actually measured on that day,
with the contributing factors stored alongside it.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from qguard.common.database import Base, OrgScopedMixin, UUIDPrimaryKeyMixin


class RiskSnapshot(Base, UUIDPrimaryKeyMixin, OrgScopedMixin):
    """Daily risk and posture measurement for an organization, project or asset."""

    __tablename__ = "risk_snapshots"

    scope_type: Mapped[str] = mapped_column(String(24), nullable=False, index=True)
    """``organization``, ``project`` or ``asset``."""
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), index=True
    )
    snapshot_date: Mapped[date] = mapped_column(Date, nullable=False, index=True)

    risk_score: Mapped[float] = mapped_column(Numeric(5, 2), nullable=False)
    security_score: Mapped[float] = mapped_column(Numeric(5, 2), nullable=False)
    posture_grade: Mapped[str] = mapped_column(String(2), nullable=False)
    """A-F, derived from ``security_score`` using fixed, documented thresholds."""

    critical_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    high_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    medium_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    low_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    info_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    exploitable_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    kev_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    overdue_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    asset_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    assessed_asset_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    """Coverage is reported honestly: unassessed assets are not counted as clean."""
    open_vulnerability_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    resolved_in_period: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    new_in_period: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    mean_time_to_resolve_hours: Mapped[float | None] = mapped_column(Numeric(10, 2))

    factors: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    """The full factor breakdown behind ``risk_score``, so it can be explained."""
    computed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "org_id",
            "scope_type",
            "project_id",
            "asset_id",
            "snapshot_date",
            name="uq_risk_snapshots_scope_date",
        ),
        Index("ix_risk_snapshots_org_scope_date", "org_id", "scope_type", "snapshot_date"),
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="risk_snapshot_score_range"),
        CheckConstraint(
            "security_score >= 0 AND security_score <= 100", name="security_snapshot_score_range"
        ),
        CheckConstraint(
            "scope_type IN ('organization','project','asset')", name="risk_scope_type_valid"
        ),
        CheckConstraint("posture_grade IN ('A','B','C','D','E','F')", name="posture_grade_valid"),
        CheckConstraint(
            "(scope_type = 'organization' AND project_id IS NULL AND asset_id IS NULL) OR "
            "(scope_type = 'project' AND project_id IS NOT NULL AND asset_id IS NULL) OR "
            "(scope_type = 'asset' AND asset_id IS NOT NULL)",
            name="risk_scope_ids_match_type",
        ),
    )
