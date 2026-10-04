"""Audit trail, security events, notifications and retention policy.

The audit log is append-only and hash-chained:
``entry_hash = SHA256(prev_hash || canonical_json(entry))``. Any retroactive
modification breaks the chain at that point and every entry after it, which
``GET /api/v1/audit/verify`` detects and reports with the first broken
sequence number.

The migration revokes UPDATE and DELETE on this table from the application
role, so the running service cannot rewrite its own history even if an
application-level flaw were found.
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
    Identity,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from qguard.common.database import (
    Base,
    OrgScopedMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from qguard.common.enums import ActorType, AuditResult


class AuditLogEntry(Base):
    """One recorded action.

    Uses a monotonic integer primary key rather than a UUID: the hash chain
    needs a strict, gap-free order, and a sequence gives that directly.
    """

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=False), primary_key=True)
    org_id: Mapped[uuid.UUID | None] = mapped_column(index=True)
    """Null only for pre-authentication events such as a failed sign-in."""

    actor_id: Mapped[uuid.UUID | None] = mapped_column(index=True)
    actor_type: Mapped[str] = mapped_column(
        String(24), nullable=False, default=ActorType.USER, server_default="'user'"
    )
    actor_label: Mapped[str | None] = mapped_column(String(320))
    """Denormalised identity, retained if the account is later deleted."""
    api_key_id: Mapped[uuid.UUID | None] = mapped_column()
    on_behalf_of: Mapped[uuid.UUID | None] = mapped_column()

    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    resource_type: Mapped[str | None] = mapped_column(String(64), index=True)
    resource_id: Mapped[str | None] = mapped_column(String(128), index=True)
    resource_label: Mapped[str | None] = mapped_column(String(400))
    result: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        default=AuditResult.SUCCESS,
        index=True,
        server_default="'success'",
    )
    failure_reason: Mapped[str | None] = mapped_column(Text)

    before_state: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    after_state: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    """Both states are scrubbed of credentials before being written."""
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        "metadata", JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )

    ip_address: Mapped[str | None] = mapped_column(INET)
    user_agent: Mapped[str | None] = mapped_column(String(512))
    request_id: Mapped[str | None] = mapped_column(String(64), index=True)
    request_method: Mapped[str | None] = mapped_column(String(10))
    request_path: Mapped[str | None] = mapped_column(String(600))
    session_id: Mapped[uuid.UUID | None] = mapped_column()

    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    sequence: Mapped[int] = mapped_column(BigInteger, nullable=False)
    """Per-organization position in the hash chain."""
    prev_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    entry_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)

    __table_args__ = (
        UniqueConstraint("org_id", "sequence", name="uq_audit_log_org_sequence"),
        Index("ix_audit_log_org_time", "org_id", "occurred_at"),
        Index("ix_audit_log_org_action_time", "org_id", "action", "occurred_at"),
        Index("ix_audit_log_actor_time", "actor_id", "occurred_at"),
        Index("ix_audit_log_resource", "resource_type", "resource_id"),
        CheckConstraint(
            "result IN ('success','failure','denied','error')", name="audit_result_valid"
        ),
        CheckConstraint(
            "actor_type IN ('user','api_key','system','worker','anonymous')",
            name="audit_actor_type_valid",
        ),
        CheckConstraint("sequence >= 0", name="audit_sequence_non_negative"),
    )


class AuditAction:
    """Canonical audit action names.

    Centralised so queries, retention rules and alerting can rely on exact
    strings rather than scattered literals.
    """

    LOGIN = "LOGIN"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGOUT = "LOGOUT"
    MFA_ENROLLED = "MFA_ENROLLED"
    MFA_DISABLED = "MFA_DISABLED"
    MFA_CHALLENGE_FAILED = "MFA_CHALLENGE_FAILED"
    PASSWORD_CHANGED = "PASSWORD_CHANGED"
    TOKEN_REFRESHED = "TOKEN_REFRESHED"
    TOKEN_REUSE_DETECTED = "TOKEN_REUSE_DETECTED"
    SESSION_REVOKED = "SESSION_REVOKED"

    USER_CREATED = "USER_CREATED"
    USER_UPDATED = "USER_UPDATED"
    USER_DISABLED = "USER_DISABLED"
    PERMISSION_CHANGED = "PERMISSION_CHANGED"
    ROLE_CREATED = "ROLE_CREATED"
    ROLE_UPDATED = "ROLE_UPDATED"
    ROLE_ASSIGNED = "ROLE_ASSIGNED"
    ROLE_REVOKED = "ROLE_REVOKED"
    API_KEY_CREATED = "API_KEY_CREATED"
    API_KEY_REVOKED = "API_KEY_REVOKED"

    ASSET_ADDED = "ASSET_ADDED"
    ASSET_UPDATED = "ASSET_UPDATED"
    ASSET_REMOVED = "ASSET_REMOVED"

    AUTHORIZATION_CREATED = "AUTHORIZATION_CREATED"
    AUTHORIZATION_APPROVED = "AUTHORIZATION_APPROVED"
    AUTHORIZATION_REVOKED = "AUTHORIZATION_REVOKED"
    SCOPE_VIOLATION_BLOCKED = "SCOPE_VIOLATION_BLOCKED"

    SCAN_STARTED = "SCAN_STARTED"
    SCAN_COMPLETED = "SCAN_COMPLETED"
    SCAN_FAILED = "SCAN_FAILED"
    SCAN_CANCELLED = "SCAN_CANCELLED"
    ENGINE_FAILED = "ENGINE_FAILED"

    FINDING_CREATED = "FINDING_CREATED"
    FINDING_UPDATED = "FINDING_UPDATED"
    VULNERABILITY_CREATED = "VULNERABILITY_CREATED"
    VULNERABILITY_UPDATED = "VULNERABILITY_UPDATED"
    VULNERABILITY_STATUS_CHANGED = "VULNERABILITY_STATUS_CHANGED"
    SEVERITY_OVERRIDDEN = "SEVERITY_OVERRIDDEN"
    RISK_RECALCULATED = "RISK_RECALCULATED"

    EVIDENCE_UPLOADED = "EVIDENCE_UPLOADED"
    EVIDENCE_ACCESSED = "EVIDENCE_ACCESSED"
    EVIDENCE_DOWNLOADED = "EVIDENCE_DOWNLOADED"
    EVIDENCE_EXPORTED = "EVIDENCE_EXPORTED"
    EVIDENCE_VERIFIED = "EVIDENCE_VERIFIED"
    EVIDENCE_INTEGRITY_FAILED = "EVIDENCE_INTEGRITY_FAILED"
    EVIDENCE_SEALED = "EVIDENCE_SEALED"
    CUSTODY_TRANSFERRED = "CUSTODY_TRANSFERRED"

    CASE_CREATED = "CASE_CREATED"
    CASE_UPDATED = "CASE_UPDATED"
    CASE_CLOSED = "CASE_CLOSED"
    INCIDENT_DECLARED = "INCIDENT_DECLARED"
    INCIDENT_UPDATED = "INCIDENT_UPDATED"
    INCIDENT_PHASE_CHANGED = "INCIDENT_PHASE_CHANGED"
    INCIDENT_CLOSED = "INCIDENT_CLOSED"

    ENGAGEMENT_CREATED = "ENGAGEMENT_CREATED"
    ENGAGEMENT_UPDATED = "ENGAGEMENT_UPDATED"
    ENGAGEMENT_SCOPE_CHANGED = "ENGAGEMENT_SCOPE_CHANGED"

    IOC_CREATED = "IOC_CREATED"
    IOC_MATCHED = "IOC_MATCHED"
    THREAT_FEED_INGESTED = "THREAT_FEED_INGESTED"

    REPORT_GENERATED = "REPORT_GENERATED"
    REPORT_DOWNLOADED = "REPORT_DOWNLOADED"
    COMPLIANCE_ASSESSED = "COMPLIANCE_ASSESSED"

    SECRET_VALIDATED = "SECRET_VALIDATED"
    SECRET_ROTATION_RECORDED = "SECRET_ROTATION_RECORDED"
    DATA_EXPORTED = "DATA_EXPORTED"
    RETENTION_APPLIED = "RETENTION_APPLIED"
    SETTINGS_CHANGED = "SETTINGS_CHANGED"


#: Actions that must always be recorded even when bulk auditing is throttled.
CRITICAL_AUDIT_ACTIONS: frozenset[str] = frozenset(
    {
        AuditAction.PERMISSION_CHANGED,
        AuditAction.ROLE_ASSIGNED,
        AuditAction.ROLE_REVOKED,
        AuditAction.AUTHORIZATION_APPROVED,
        AuditAction.SCOPE_VIOLATION_BLOCKED,
        AuditAction.EVIDENCE_DOWNLOADED,
        AuditAction.EVIDENCE_EXPORTED,
        AuditAction.EVIDENCE_INTEGRITY_FAILED,
        AuditAction.CUSTODY_TRANSFERRED,
        AuditAction.TOKEN_REUSE_DETECTED,
        AuditAction.DATA_EXPORTED,
        AuditAction.SEVERITY_OVERRIDDEN,
    }
)


class SecurityEvent(Base, UUIDPrimaryKeyMixin, OrgScopedMixin):
    """An operationally interesting platform event.

    Distinct from the audit log: audit answers "who did what", this answers
    "what is happening in the environment". It backs the dashboard's recent
    activity feed, so that feed reflects real occurrences only.
    """

    __tablename__ = "security_events"

    kind: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default="info", index=True, server_default="'info'"
    )
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(400), nullable=False)
    message: Mapped[str | None] = mapped_column(Text)
    resource_type: Mapped[str | None] = mapped_column(String(64))
    resource_id: Mapped[str | None] = mapped_column(String(128))
    project_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("projects.id", ondelete="SET NULL")
    )
    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    data: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    is_acknowledged: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    acknowledged_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )

    __table_args__ = (
        Index("ix_security_events_org_time", "org_id", "occurred_at"),
        Index("ix_security_events_org_kind_time", "org_id", "kind", "occurred_at"),
    )


class NotificationChannel(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """A configured delivery target for alerts."""

    __tablename__ = "notification_channels"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    channel_kind: Mapped[str] = mapped_column(String(24), nullable=False)
    config_encrypted: Mapped[str | None] = mapped_column(Text)
    """Webhook URLs and tokens are encrypted; the URL is SSRF-validated on send."""
    is_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    subscribed_events: Mapped[list[str]] = mapped_column(
        ARRAY(String(48)), nullable=False, default=list, server_default="{}"
    )
    min_severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default="high", server_default="'high'"
    )
    last_delivery_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_delivery_status: Mapped[str | None] = mapped_column(String(24))
    last_delivery_error: Mapped[str | None] = mapped_column(Text)
    consecutive_failures: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )

    __table_args__ = (
        UniqueConstraint("org_id", "name", name="uq_notification_channels_org_name"),
        CheckConstraint(
            "channel_kind IN ('email','webhook','slack','in_app')",
            name="notification_channel_kind_valid",
        ),
    )


class Notification(Base, UUIDPrimaryKeyMixin, OrgScopedMixin):
    """An in-app notification for a specific user."""

    __tablename__ = "notifications"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    kind: Mapped[str] = mapped_column(String(48), nullable=False)
    severity: Mapped[str] = mapped_column(
        String(16), nullable=False, default="info", server_default="'info'"
    )
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    body: Mapped[str | None] = mapped_column(Text)
    link: Mapped[str | None] = mapped_column(String(600))
    resource_type: Mapped[str | None] = mapped_column(String(64))
    resource_id: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now(), index=True
    )
    read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (Index("ix_notifications_user_unread", "user_id", "read_at", "created_at"),)


class RetentionPolicy(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """Per-resource data retention rule, applied by the retention sweep job.

    Items under legal hold are always exempt, and the audit log itself can only
    be archived, never deleted, by policy.
    """

    __tablename__ = "retention_policies"

    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    retain_days: Mapped[int] = mapped_column(Integer, nullable=False)
    action: Mapped[str] = mapped_column(
        String(24), nullable=False, default="archive", server_default="'archive'"
    )
    """``archive``, ``anonymize`` or ``delete``."""
    is_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    respect_legal_hold: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    last_applied_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_affected_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )

    __table_args__ = (
        UniqueConstraint("org_id", "resource_type", name="uq_retention_policies_org_resource"),
        CheckConstraint("retain_days BETWEEN 1 AND 36500", name="retain_days_range"),
        CheckConstraint(
            "action IN ('archive','anonymize','delete')", name="retention_action_valid"
        ),
        # The audit trail is never deleted outright by an automated policy.
        CheckConstraint(
            "resource_type <> 'audit_log' OR action = 'archive'",
            name="audit_log_archive_only",
        ),
    )
