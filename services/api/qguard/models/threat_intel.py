"""Threat intelligence: IOCs, actors, campaigns, MITRE ATT&CK and feeds.

Feed ingestion is adapter-based: a feed is a row with a kind and a
configuration, and the worker dispatches to the adapter registered for that
kind. New sources are added by registering an adapter, not by editing ingestion
logic. Outbound feed polling is off by default and gated by configuration.
"""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Date,
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
from sqlalchemy.orm import Mapped, mapped_column

from qguard.common.database import (
    AuthorMixin,
    Base,
    OrgScopedMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from qguard.common.enums import TLP


class IOC(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin, AuthorMixin):
    """An indicator of compromise.

    ``value_normalized`` is the deduplication key: domains are lower-cased and
    IDNA-encoded, hashes lower-cased, URLs stripped of default ports. Without
    it the same indicator arrives repeatedly in slightly different spellings.
    """

    __tablename__ = "iocs"

    ioc_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    value: Mapped[str] = mapped_column(String(2048), nullable=False)
    value_normalized: Mapped[str] = mapped_column(String(2048), nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text)

    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default="medium", index=True, server_default="'medium'"
    )
    confidence: Mapped[str] = mapped_column(
        String(16), nullable=False, default="medium", server_default="'medium'"
    )
    tlp: Mapped[str] = mapped_column(
        String(16), nullable=False, default=TLP.AMBER, server_default="'amber'"
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, index=True, server_default="true"
    )
    is_false_positive: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    allowlisted: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    """Known-good indicator (e.g. a corporate egress IP) excluded from matching."""

    source: Mapped[str] = mapped_column(
        String(160), nullable=False, default="manual", server_default="'manual'"
    )
    feed_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("threat_feeds.id", ondelete="SET NULL"), index=True
    )
    external_id: Mapped[str | None] = mapped_column(String(240))
    case_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cases.id", ondelete="SET NULL"), index=True
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), index=True
    )
    threat_actor_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("threat_actors.id", ondelete="SET NULL")
    )
    campaign_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("campaigns.id", ondelete="SET NULL")
    )

    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    last_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    """Indicators age out; stale IOCs generate noise rather than signal."""
    match_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    last_matched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    mitre_techniques: Mapped[list[str]] = mapped_column(
        ARRAY(String(16)), nullable=False, default=list, server_default="{}"
    )
    malware_families: Mapped[list[str]] = mapped_column(
        ARRAY(String(120)), nullable=False, default=list, server_default="{}"
    )
    related_cves: Mapped[list[str]] = mapped_column(
        ARRAY(String(32)), nullable=False, default=list, server_default="{}"
    )
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(String(80)), nullable=False, default=list, server_default="{}"
    )
    context: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )

    __table_args__ = (
        UniqueConstraint("org_id", "ioc_type", "value_normalized", name="uq_iocs_org_type_value"),
        Index("ix_iocs_org_active_type", "org_id", "is_active", "ioc_type"),
        Index("ix_iocs_org_severity", "org_id", "severity"),
        Index(
            "ix_iocs_value_trgm",
            "value_normalized",
            postgresql_using="gin",
            postgresql_ops={"value_normalized": "gin_trgm_ops"},
        ),
        CheckConstraint(
            "ioc_type IN ('ipv4','ipv6','domain','url','md5','sha1','sha256','email',"
            "'file_path','file_name','registry_key','user_agent','asn','mutex','ja3',"
            "'bitcoin_address','cve','yara_rule')",
            name="ioc_type_valid",
        ),
        CheckConstraint("value_normalized = lower(value_normalized)", name="ioc_normalized_lower"),
    )


class IOCMatch(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """A sighting of an IOC inside platform data."""

    __tablename__ = "ioc_matches"

    ioc_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("iocs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("assets.id", ondelete="SET NULL"), index=True
    )
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), index=True
    )
    artifact_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("forensic_artifacts.id", ondelete="CASCADE")
    )
    case_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("cases.id", ondelete="SET NULL"))
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL")
    )
    matched_value: Mapped[str] = mapped_column(String(2048), nullable=False)
    match_source: Mapped[str] = mapped_column(String(80), nullable=False)
    """Where the match occurred: ``evidence_scan``, ``artifact``, ``asset_inventory``."""
    source_location: Mapped[str | None] = mapped_column(String(2048))
    context: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    matched_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    is_reviewed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    review_verdict: Mapped[str | None] = mapped_column(String(32))
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        Index("ix_ioc_matches_org_time", "org_id", "matched_at"),
        Index("ix_ioc_matches_ioc_time", "ioc_id", "matched_at"),
    )


class ThreatActor(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin, AuthorMixin):
    __tablename__ = "threat_actors"

    name: Mapped[str] = mapped_column(String(240), nullable=False)
    aliases: Mapped[list[str]] = mapped_column(
        ARRAY(String(160)), nullable=False, default=list, server_default="{}"
    )
    description: Mapped[str | None] = mapped_column(Text)
    actor_type: Mapped[str | None] = mapped_column(String(48))
    """``nation_state``, ``criminal``, ``hacktivist``, ``insider``, ``unknown``."""
    motivation: Mapped[list[str]] = mapped_column(
        ARRAY(String(48)), nullable=False, default=list, server_default="{}"
    )
    sophistication: Mapped[str | None] = mapped_column(String(32))
    suspected_origin: Mapped[str | None] = mapped_column(String(120))
    target_sectors: Mapped[list[str]] = mapped_column(
        ARRAY(String(120)), nullable=False, default=list, server_default="{}"
    )
    mitre_group_ids: Mapped[list[str]] = mapped_column(
        ARRAY(String(16)), nullable=False, default=list, server_default="{}"
    )
    mitre_techniques: Mapped[list[str]] = mapped_column(
        ARRAY(String(16)), nullable=False, default=list, server_default="{}"
    )
    is_relevant_to_org: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    relevance_note: Mapped[str | None] = mapped_column(Text)
    first_observed: Mapped[date | None] = mapped_column(Date)
    last_observed: Mapped[date | None] = mapped_column(Date)
    references: Mapped[list[str]] = mapped_column(
        ARRAY(String(1024)), nullable=False, default=list, server_default="{}"
    )

    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_threat_actors_org_name"),)


class Campaign(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin, AuthorMixin):
    __tablename__ = "campaigns"

    name: Mapped[str] = mapped_column(String(240), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    threat_actor_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("threat_actors.id", ondelete="SET NULL"), index=True
    )
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="active", server_default="'active'"
    )
    first_observed: Mapped[date | None] = mapped_column(Date)
    last_observed: Mapped[date | None] = mapped_column(Date)
    targeted_sectors: Mapped[list[str]] = mapped_column(
        ARRAY(String(120)), nullable=False, default=list, server_default="{}"
    )
    mitre_techniques: Mapped[list[str]] = mapped_column(
        ARRAY(String(16)), nullable=False, default=list, server_default="{}"
    )
    exploited_cves: Mapped[list[str]] = mapped_column(
        ARRAY(String(32)), nullable=False, default=list, server_default="{}"
    )
    affects_org: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    references: Mapped[list[str]] = mapped_column(
        ARRAY(String(1024)), nullable=False, default=list, server_default="{}"
    )

    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_campaigns_org_name"),)


class MitreTechnique(Base, TimestampMixin):
    """MITRE ATT&CK technique catalogue.

    Global reference data, not tenant-scoped, loaded from a bundled seed file
    and refreshable from the official STIX bundle.
    """

    __tablename__ = "mitre_techniques"

    technique_id: Mapped[str] = mapped_column(String(16), primary_key=True)
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    tactics: Mapped[list[str]] = mapped_column(
        ARRAY(String(48)), nullable=False, default=list, server_default="{}"
    )
    platforms: Mapped[list[str]] = mapped_column(
        ARRAY(String(48)), nullable=False, default=list, server_default="{}"
    )
    is_subtechnique: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    parent_technique_id: Mapped[str | None] = mapped_column(String(16), index=True)
    detection_guidance: Mapped[str | None] = mapped_column(Text)
    mitigations: Mapped[list[str]] = mapped_column(
        ARRAY(String(16)), nullable=False, default=list, server_default="{}"
    )
    attack_version: Mapped[str | None] = mapped_column(String(16))
    url: Mapped[str | None] = mapped_column(String(600))

    __table_args__ = (
        Index("ix_mitre_techniques_tactics", "tactics", postgresql_using="gin"),
        CheckConstraint("technique_id ~ '^T[0-9]{4}(\\.[0-9]{3})?$'", name="technique_id_format"),
    )


class ThreatFeed(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin, AuthorMixin):
    """A configured external intelligence source.

    Credentials are stored encrypted. The feed URL is validated through the
    SSRF guard before every fetch, so a feed definition cannot be used to reach
    internal services.
    """

    __tablename__ = "threat_feeds"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    feed_kind: Mapped[str] = mapped_column(String(48), nullable=False)
    """Adapter key: ``stix2``, ``misp``, ``csv``, ``json``, ``taxii2``, ``kev``, ``openioc``."""
    url: Mapped[str | None] = mapped_column(String(2048))
    is_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, index=True, server_default="false"
    )
    poll_interval_minutes: Mapped[int] = mapped_column(
        Integer, nullable=False, default=360, server_default="360"
    )
    auth_config_encrypted: Mapped[str | None] = mapped_column(Text)
    parser_config: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    default_tlp: Mapped[str] = mapped_column(
        String(16), nullable=False, default=TLP.AMBER, server_default="'amber'"
    )
    default_confidence: Mapped[str] = mapped_column(
        String(16), nullable=False, default="medium", server_default="'medium'"
    )
    indicator_ttl_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=90, server_default="90"
    )

    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_status: Mapped[str | None] = mapped_column(String(24))
    last_error: Mapped[str | None] = mapped_column(Text)
    """Surfaced in the UI; an unreachable feed is never reported as a clean run."""
    next_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    total_indicators: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    last_run_indicators: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    consecutive_failures: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )

    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_threat_feeds_org_name"),
        CheckConstraint(
            "last_status IS NULL OR last_status IN ('success','partial','failed','degraded')",
            name="feed_status_valid",
        ),
    )
