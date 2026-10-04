"""Digital forensics: cases, evidence, chain of custody, artifacts and timelines.

Evidence integrity is the foundation of this module. Every stored item carries a
SHA-256 computed at ingestion, every custody transition is appended to a
hash-linked chain, and every access is logged. Nothing here supports editing
history: integrity is verifiable, and tampering is detectable.
"""

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
    TimestampMixin,
    UUIDArray,
    UUIDPrimaryKeyMixin,
)
from qguard.common.enums import (
    TLP,
    CasePriority,
    CaseStatus,
    CaseType,
    EvidenceStatus,
)


class Case(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin, AuthorMixin):
    """An investigation workspace grouping evidence, artifacts and findings."""

    __tablename__ = "cases"

    case_number: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    """e.g. ``CASE-2026-0043``."""
    title: Mapped[str] = mapped_column(String(400), nullable=False)
    case_type: Mapped[str] = mapped_column(
        String(48), nullable=False, default=CaseType.OTHER, index=True, server_default="'other'"
    )
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=CaseStatus.OPEN, index=True, server_default="'open'"
    )
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default="medium", index=True, server_default="'medium'"
    )
    priority: Mapped[str] = mapped_column(
        String(8), nullable=False, default=CasePriority.P3, server_default="'p3'"
    )
    tlp: Mapped[str] = mapped_column(
        String(16), nullable=False, default=TLP.AMBER, server_default="'amber'"
    )

    summary: Mapped[str | None] = mapped_column(Text)
    scope_statement: Mapped[str | None] = mapped_column(Text)
    """What the investigation is authorised to examine."""
    hypothesis: Mapped[str | None] = mapped_column(Text)
    findings_summary: Mapped[str | None] = mapped_column(Text)
    closure_summary: Mapped[str | None] = mapped_column(Text)
    legal_hold: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    """Blocks retention-driven deletion of the case and its evidence."""

    lead_investigator_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        # `cases` and `incidents` reference each other: an incident can spawn a
        # forensic case and a case can be escalated into an incident. The
        # constraint is added with ALTER after both tables exist so the DDL
        # ordering is resolvable.
        ForeignKey("incidents.id", ondelete="SET NULL", use_alter=True),
        index=True,
    )
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="SET NULL")
    )
    opened_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(String(80)), nullable=False, default=list, server_default="{}"
    )
    affected_asset_ids: Mapped[list[uuid.UUID]] = mapped_column(
        UUIDArray, nullable=False, default=list, server_default="{}"
    )

    evidence_items: Mapped[list[Evidence]] = relationship(
        back_populates="case", lazy="raise_on_sql"
    )
    notes: Mapped[list[CaseNote]] = relationship(
        back_populates="case", cascade="all, delete-orphan", lazy="raise_on_sql"
    )

    __table_args__ = (
        UniqueConstraint("org_id", "case_number", name="uq_cases_org_id_case_number"),
        Index("ix_cases_org_status_severity", "org_id", "status", "severity"),
        CheckConstraint(
            "status IN ('open','in_progress','pending_review','on_hold','closed','archived')",
            name="case_status_valid",
        ),
        CheckConstraint(
            "status NOT IN ('closed','archived') OR closed_at IS NOT NULL",
            name="closed_case_requires_timestamp",
        ),
    )


class CaseMember(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """Investigator assigned to a case.

    Case membership is an access control input: DFIR data is restricted to
    assigned investigators unless the caller holds an organization-wide
    forensics permission.
    """

    __tablename__ = "case_members"

    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    case_role: Mapped[str] = mapped_column(
        String(48), nullable=False, default="investigator", server_default="'investigator'"
    )
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    __table_args__ = (UniqueConstraint("case_id", "user_id", name="uq_case_members_case_user"),)


class CaseNote(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """Investigator notes. Edits are versioned rather than overwriting history."""

    __tablename__ = "case_notes"

    case_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True
    )
    author_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    title: Mapped[str | None] = mapped_column(String(300))
    body: Mapped[str] = mapped_column(Text, nullable=False)
    note_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default="analysis", server_default="'analysis'"
    )
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    evidence_ids: Mapped[list[uuid.UUID]] = mapped_column(
        UUIDArray, nullable=False, default=list, server_default="{}"
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1, server_default="1")
    supersedes_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("case_notes.id", ondelete="SET NULL")
    )
    is_current: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )

    case: Mapped[Case] = relationship(back_populates="notes", lazy="raise_on_sql")

    __table_args__ = (Index("ix_case_notes_case_current", "case_id", "is_current"),)


class Evidence(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """A forensic item under chain of custody.

    The ``sha256`` recorded at ingestion is authoritative. Re-verification
    recomputes it from stored bytes and a mismatch raises an integrity failure
    rather than being silently corrected.
    """

    __tablename__ = "evidence"

    evidence_number: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    """e.g. ``EV-2026-00128`` — the identifier used in custody documentation."""
    name: Mapped[str] = mapped_column(String(400), nullable=False)
    description: Mapped[str | None] = mapped_column(Text)

    case_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cases.id", ondelete="SET NULL"), index=True
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), index=True
    )
    engagement_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("engagements.id", ondelete="SET NULL"), index=True
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    finding_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("findings.id", ondelete="SET NULL")
    )

    source_type: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    source_detail: Mapped[str | None] = mapped_column(String(600))
    """Where it came from: host name, cloud account, mailbox, device identifier."""
    original_filename: Mapped[str | None] = mapped_column(String(512))
    mime_type: Mapped[str] = mapped_column(
        String(160),
        nullable=False,
        default="application/octet-stream",
        server_default="'application/octet-stream'",
    )
    size_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default="0"
    )

    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    sha1: Mapped[str | None] = mapped_column(String(40), index=True)
    md5: Mapped[str | None] = mapped_column(String(32), index=True)

    storage_backend: Mapped[str] = mapped_column(
        String(24), nullable=False, default="local", server_default="'local'"
    )
    storage_key: Mapped[str] = mapped_column(String(1024), nullable=False)
    is_encrypted_at_rest: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )

    acquisition_method: Mapped[str | None] = mapped_column(String(160))
    acquisition_tool: Mapped[str | None] = mapped_column(String(160))
    collected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    """When the evidence was captured at source, not when it was uploaded."""
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )
    collected_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    collected_by_name: Mapped[str | None] = mapped_column(String(240))
    """Free-text collector for evidence handed over by someone without an account."""
    custodian_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )

    status: Mapped[str] = mapped_column(
        String(24),
        nullable=False,
        default=EvidenceStatus.PENDING,
        index=True,
        server_default="'pending'",
    )
    tlp: Mapped[str] = mapped_column(
        String(16), nullable=False, default=TLP.AMBER_STRICT, server_default="'amber_strict'"
    )
    is_sealed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    """A sealed item is immutable; only verification and access logging remain."""
    legal_hold: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )

    integrity_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    integrity_ok: Mapped[bool | None] = mapped_column(Boolean, index=True)
    integrity_note: Mapped[str | None] = mapped_column(Text)
    custody_chain_head: Mapped[str | None] = mapped_column(String(64))
    """Hash of the most recent custody entry — the tip of this item's chain."""

    processing_status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="pending", server_default="'pending'"
    )
    processing_error: Mapped[str | None] = mapped_column(Text)
    artifact_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    ioc_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    extracted_metadata: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    retention_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(String(80)), nullable=False, default=list, server_default="{}"
    )

    case: Mapped[Case | None] = relationship(back_populates="evidence_items", lazy="raise_on_sql")
    custody_entries: Mapped[list[ChainOfCustodyEntry]] = relationship(
        back_populates="evidence", cascade="all, delete-orphan", lazy="raise_on_sql"
    )

    __table_args__ = (
        UniqueConstraint("org_id", "evidence_number", name="uq_evidence_org_id_number"),
        Index("ix_evidence_org_case_status", "org_id", "case_id", "status"),
        Index("ix_evidence_org_collected", "org_id", "collected_at"),
        CheckConstraint("sha256 ~ '^[0-9a-f]{64}$'", name="evidence_sha256_format"),
        CheckConstraint("size_bytes >= 0", name="evidence_size_non_negative"),
        CheckConstraint(
            "status IN ('pending','processing','available','quarantined','failed',"
            "'sealed','disposed')",
            name="evidence_status_valid",
        ),
    )


class ChainOfCustodyEntry(Base, UUIDPrimaryKeyMixin, OrgScopedMixin):
    """One append-only link in an evidence item's custody chain.

    ``entry_hash = SHA256(prev_hash || canonical_json(entry))``. Any retroactive
    edit to an earlier entry invalidates every later hash, which
    ``POST /evidence/{id}/verify`` detects and reports. The migration revokes
    UPDATE and DELETE on this table so even the application role cannot rewrite
    custody history.
    """

    __tablename__ = "chain_of_custody"

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True
    )
    sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    action: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    actor_name: Mapped[str] = mapped_column(String(240), nullable=False)
    """Denormalised so the record stays complete if the account is later removed."""
    from_custodian_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    to_custodian_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    purpose: Mapped[str | None] = mapped_column(Text)
    note: Mapped[str | None] = mapped_column(Text)
    hash_at_event: Mapped[str] = mapped_column(String(64), nullable=False)
    """The item's SHA-256 as observed at this moment, so drift is attributable."""
    location: Mapped[str | None] = mapped_column(String(400))
    ip_address: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(String(512))
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    evidence: Mapped[Evidence] = relationship(back_populates="custody_entries", lazy="raise_on_sql")

    __table_args__ = (
        UniqueConstraint("evidence_id", "sequence", name="uq_chain_of_custody_sequence"),
        Index("ix_chain_of_custody_evidence_seq", "evidence_id", "sequence"),
        CheckConstraint("sequence >= 0", name="custody_sequence_non_negative"),
        CheckConstraint(
            "action IN ('collected','received','transferred','accessed','analyzed',"
            "'exported','verified','sealed','disposed')",
            name="custody_action_valid",
        ),
        CheckConstraint(
            "action <> 'transferred' OR to_custodian_id IS NOT NULL",
            name="transfer_requires_recipient",
        ),
    )


class EvidenceAccessLog(Base, UUIDPrimaryKeyMixin, OrgScopedMixin):
    """Every read, download or export of an evidence item.

    Separate from the custody chain: custody records handling decisions, this
    records routine access, which is high-volume and queried differently.
    """

    __tablename__ = "evidence_access_log"

    evidence_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), index=True
    )
    action: Mapped[str] = mapped_column(String(32), nullable=False)
    """``view_metadata``, ``download``, ``export``, ``verify``, ``denied``."""
    was_permitted: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    denial_reason: Mapped[str | None] = mapped_column(String(300))
    bytes_served: Mapped[int | None] = mapped_column(BigInteger)
    ip_address: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(String(512))
    request_id: Mapped[str | None] = mapped_column(String(64))
    accessed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )

    __table_args__ = (
        Index("ix_evidence_access_log_evidence_time", "evidence_id", "accessed_at"),
        Index("ix_evidence_access_log_user_time", "user_id", "accessed_at"),
    )


class ForensicArtifact(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """A structured record parsed out of an evidence item."""

    __tablename__ = "forensic_artifacts"

    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("evidence.id", ondelete="CASCADE"), index=True
    )
    case_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), index=True
    )
    artifact_type: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(500), nullable=False)
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    source_path: Mapped[str | None] = mapped_column(String(2048))
    source_line: Mapped[int | None] = mapped_column(Integer)
    data: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    confidence: Mapped[str] = mapped_column(
        String(16), nullable=False, default="medium", server_default="'medium'"
    )
    extracted_by: Mapped[str] = mapped_column(
        String(80), nullable=False, default="parser", server_default="'parser'"
    )
    is_suspicious: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, index=True, server_default="false"
    )
    suspicion_reason: Mapped[str | None] = mapped_column(Text)
    related_ioc_ids: Mapped[list[uuid.UUID]] = mapped_column(
        UUIDArray, nullable=False, default=list, server_default="{}"
    )

    __table_args__ = (
        Index("ix_forensic_artifacts_case_type_time", "case_id", "artifact_type", "occurred_at"),
        Index("ix_forensic_artifacts_data", "data", postgresql_using="gin"),
    )


class TimelineEvent(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """A normalised entry on an investigation's super-timeline.

    Events come from parsed artifacts, scanner activity, incident actions and
    analyst entries, all reduced to a single comparable shape so a case timeline
    can be reconstructed across sources.
    """

    __tablename__ = "timeline_events"

    case_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("cases.id", ondelete="CASCADE"), index=True
    )
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    evidence_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("evidence.id", ondelete="SET NULL")
    )
    artifact_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("forensic_artifacts.id", ondelete="SET NULL")
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))

    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    occurred_at_precision: Mapped[str] = mapped_column(
        String(16), nullable=False, default="second", server_default="'second'"
    )
    """Timestamp fidelity of the source, so coarse data is not over-interpreted."""
    timezone_note: Mapped[str | None] = mapped_column(String(80))
    event_type: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(80), nullable=False)
    actor: Mapped[str | None] = mapped_column(String(300))
    target: Mapped[str | None] = mapped_column(String(600))
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default="info", server_default="'info'"
    )
    confidence: Mapped[str] = mapped_column(
        String(16), nullable=False, default="medium", server_default="'medium'"
    )
    is_key_event: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    mitre_techniques: Mapped[list[str]] = mapped_column(
        ARRAY(String(16)), nullable=False, default=list, server_default="{}"
    )
    tags: Mapped[list[str]] = mapped_column(
        ARRAY(String(80)), nullable=False, default=list, server_default="{}"
    )
    data: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    created_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        Index("ix_timeline_events_case_time", "case_id", "occurred_at"),
        Index("ix_timeline_events_incident_time", "incident_id", "occurred_at"),
        Index("ix_timeline_events_org_time", "org_id", "occurred_at"),
        CheckConstraint(
            "occurred_at_precision IN ('microsecond','second','minute','hour','day','unknown')",
            name="timeline_precision_valid",
        ),
        CheckConstraint(
            "case_id IS NOT NULL OR incident_id IS NOT NULL",
            name="timeline_requires_container",
        ),
    )
