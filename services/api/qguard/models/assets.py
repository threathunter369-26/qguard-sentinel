"""Centralised asset inventory and the relationships between assets."""

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
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from qguard.common.database import (
    AuthorMixin,
    Base,
    OrgScopedMixin,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from qguard.common.enums import (
    AssetRelation,
    Criticality,
    DataSensitivity,
    Environment,
)


class Asset(
    Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin, SoftDeleteMixin, AuthorMixin
):
    """Anything the organization owns that can be assessed.

    ``identifier`` is the canonical, normalised handle for the asset (hostname,
    URL, package coordinate, image reference, ARN...). It is unique per
    organization and asset type, which is what lets independent scanners
    converge on the same asset row instead of creating duplicates.
    """

    __tablename__ = "assets"

    name: Mapped[str] = mapped_column(String(300), nullable=False)
    asset_type: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    identifier: Mapped[str] = mapped_column(String(600), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text)

    project_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="SET NULL"), index=True
    )
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    owning_team_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("teams.id", ondelete="SET NULL")
    )
    parent_asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), index=True
    )

    environment: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=Environment.UNKNOWN,
        index=True,
        server_default="'unknown'",
    )
    criticality: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=Criticality.MEDIUM,
        index=True,
        server_default="'medium'",
    )
    business_value: Mapped[str | None] = mapped_column(Text)
    data_sensitivity: Mapped[str] = mapped_column(
        String(32), nullable=False, default=DataSensitivity.UNKNOWN, server_default="'unknown'"
    )
    internet_facing: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, index=True, server_default="false"
    )
    requires_authentication: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    compensating_controls: Mapped[list[str]] = mapped_column(
        ARRAY(String(80)), nullable=False, default=list, server_default="{}"
    )
    """Mitigations such as ``waf``, ``mfa``, ``network_segmentation``. Feeds risk scoring."""

    hostname: Mapped[str | None] = mapped_column(String(300), index=True)
    domain: Mapped[str | None] = mapped_column(String(300), index=True)
    ip_address: Mapped[str | None] = mapped_column(INET, index=True)
    port: Mapped[int | None] = mapped_column(Integer)
    url: Mapped[str | None] = mapped_column(String(2048))
    operating_system: Mapped[str | None] = mapped_column(String(160))
    technology: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    """Fingerprinted stack, e.g. ``{"server": "nginx/1.25", "framework": "next.js"}``."""
    cloud_provider: Mapped[str | None] = mapped_column(String(32))
    cloud_account_id: Mapped[str | None] = mapped_column(String(160))
    cloud_region: Mapped[str | None] = mapped_column(String(64))

    tags: Mapped[list[str]] = mapped_column(
        ARRAY(String(80)), nullable=False, default=list, server_default="{}"
    )
    attributes: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )

    security_score: Mapped[float | None] = mapped_column(Numeric(5, 2))
    """0-100, derived from open findings. Null until the asset has been assessed."""
    risk_score: Mapped[float | None] = mapped_column(Numeric(5, 2))
    last_assessed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    last_scan_id: Mapped[uuid.UUID | None] = mapped_column()
    discovery_source: Mapped[str] = mapped_column(
        String(48), nullable=False, default="manual", server_default="'manual'"
    )
    """How the asset entered the inventory: ``manual``, ``discovery``, ``import``, ``api``."""
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, index=True, server_default="true"
    )

    assessments: Mapped[list[AssetAssessment]] = relationship(
        back_populates="asset", cascade="all, delete-orphan", lazy="noload"
    )

    __table_args__ = (
        UniqueConstraint(
            "org_id", "asset_type", "identifier", name="uq_assets_org_id_asset_type_identifier"
        ),
        Index("ix_assets_org_project_type", "org_id", "project_id", "asset_type"),
        Index("ix_assets_org_criticality", "org_id", "criticality"),
        Index("ix_assets_tags", "tags", postgresql_using="gin"),
        Index("ix_assets_technology", "technology", postgresql_using="gin"),
        Index(
            "ix_assets_name_trgm",
            "name",
            postgresql_using="gin",
            postgresql_ops={"name": "gin_trgm_ops"},
        ),
        Index(
            "ix_assets_identifier_trgm",
            "identifier",
            postgresql_using="gin",
            postgresql_ops={"identifier": "gin_trgm_ops"},
        ),
        Index(
            "ix_assets_exposure",
            "org_id",
            "internet_facing",
            postgresql_where=text("deleted_at IS NULL AND is_active"),
        ),
        CheckConstraint(
            "asset_type IN ('domain','subdomain','ip_address','url','web_application','api',"
            "'mobile_application','server','database','cloud_resource','container_image',"
            "'kubernetes_resource','certificate','cryptographic_key','repository','dependency',"
            "'endpoint','network_range','workstation','other')",
            name="asset_type_valid",
        ),
        CheckConstraint(
            "criticality IN ('critical','high','medium','low')", name="criticality_valid"
        ),
        CheckConstraint(
            "security_score IS NULL OR (security_score >= 0 AND security_score <= 100)",
            name="security_score_range",
        ),
        CheckConstraint("port IS NULL OR (port > 0 AND port <= 65535)", name="port_range"),
    )


class AssetRelationship(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """A directed edge in the asset graph, used for blast-radius analysis."""

    __tablename__ = "asset_relationships"

    source_asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    target_asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    relation: Mapped[str] = mapped_column(
        String(48), nullable=False, default=AssetRelation.DEPENDS_ON, server_default="'depends_on'"
    )
    confidence: Mapped[str] = mapped_column(
        String(24), nullable=False, default="high", server_default="'high'"
    )
    discovered_by: Mapped[str | None] = mapped_column(String(48))
    attributes: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )

    __table_args__ = (
        UniqueConstraint(
            "source_asset_id", "target_asset_id", "relation", name="uq_asset_relationship_edge"
        ),
        CheckConstraint("source_asset_id <> target_asset_id", name="no_self_relationship"),
    )


class AssetAssessment(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """Point-in-time record of an asset's posture after a scan.

    Kept as history so posture trends on the dashboard are computed from real
    recorded measurements rather than reconstructed estimates.
    """

    __tablename__ = "asset_assessments"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id", ondelete="SET NULL"), index=True
    )
    assessed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    security_score: Mapped[float | None] = mapped_column(Numeric(5, 2))
    risk_score: Mapped[float | None] = mapped_column(Numeric(5, 2))
    critical_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    high_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    medium_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    low_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    info_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    engines_run: Mapped[list[str]] = mapped_column(
        ARRAY(String(32)), nullable=False, default=list, server_default="{}"
    )
    summary: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )

    asset: Mapped[Asset] = relationship(back_populates="assessments", lazy="noload")

    __table_args__ = (Index("ix_asset_assessments_asset_time", "asset_id", "assessed_at"),)


class Dependency(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """A software component discovered by composition analysis (SBOM row)."""

    __tablename__ = "dependencies"

    asset_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id", ondelete="SET NULL"))
    ecosystem: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    """One of: npm, PyPI, Maven, Go, crates.io, NuGet, Packagist, RubyGems."""
    name: Mapped[str] = mapped_column(String(300), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(120), nullable=False)
    purl: Mapped[str | None] = mapped_column(String(600), index=True)
    """Package URL, the canonical cross-ecosystem coordinate."""
    is_direct: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    depth: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    parent_name: Mapped[str | None] = mapped_column(String(300))
    dependency_scope: Mapped[str] = mapped_column(
        String(32), nullable=False, default="runtime", server_default="'runtime'"
    )
    manifest_path: Mapped[str | None] = mapped_column(String(1024))
    license: Mapped[str | None] = mapped_column(String(200))
    license_risk: Mapped[str] = mapped_column(
        String(24), nullable=False, default="unknown", server_default="'unknown'"
    )
    latest_version: Mapped[str | None] = mapped_column(String(120))
    is_outdated: Mapped[bool | None] = mapped_column(Boolean)
    vulnerability_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    max_severity: Mapped[str | None] = mapped_column(String(16))
    attributes: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (
        UniqueConstraint(
            "asset_id",
            "ecosystem",
            "name",
            "version",
            "manifest_path",
            name="uq_dependencies_coordinate",
        ),
        Index("ix_dependencies_org_ecosystem_name", "org_id", "ecosystem", "name"),
        Index("ix_dependencies_vulnerable", "org_id", "vulnerability_count"),
    )
