"""Organizations, users, teams, projects, roles and credentials."""

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
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from qguard.common.database import (
    Base,
    OrgScopedMixin,
    SoftDeleteMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from qguard.common.enums import (
    ProjectKind,
    ScopeType,
    TeamKind,
    UserStatus,
)


class Organization(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """A tenant. The root of every ownership chain in the platform."""

    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(80), nullable=False, unique=True, index=True)
    description: Mapped[str | None] = mapped_column(Text)
    industry: Mapped[str | None] = mapped_column(String(120))
    is_demo: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    """Marks a seeded demo tenant so demo data is never mistaken for real findings."""
    settings: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    retention_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=365, server_default="365"
    )

    users: Mapped[list[User]] = relationship(back_populates="organization", lazy="raise_on_sql")
    teams: Mapped[list[Team]] = relationship(back_populates="organization", lazy="raise_on_sql")
    projects: Mapped[list[Project]] = relationship(
        back_populates="organization", lazy="raise_on_sql"
    )

    __table_args__ = (
        CheckConstraint("retention_days BETWEEN 1 AND 3650", name="retention_days_range"),
        Index("ix_organizations_is_demo", "is_demo"),
    )


class User(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin, SoftDeleteMixin):
    """A platform operator.

    ``password_hash`` is null for accounts federated through Supabase; those
    accounts authenticate against the identity provider instead.
    """

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    full_name: Mapped[str] = mapped_column(String(200), nullable=False)
    job_title: Mapped[str | None] = mapped_column(String(160))
    password_hash: Mapped[str | None] = mapped_column(String(255))
    auth_provider: Mapped[str] = mapped_column(
        String(32), nullable=False, default="local", server_default="'local'"
    )
    external_id: Mapped[str | None] = mapped_column(String(255), index=True)
    """Supabase ``auth.users.id`` when federated."""
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=UserStatus.ACTIVE, index=True, server_default="'active'"
    )
    is_superadmin: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )

    mfa_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    mfa_secret_encrypted: Mapped[str | None] = mapped_column(Text)
    """AES-256-GCM envelope; never returned by any API response."""
    mfa_recovery_hashes: Mapped[list[str]] = mapped_column(
        ARRAY(String(128)), nullable=False, default=list, server_default="{}"
    )
    mfa_enrolled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_login_ip: Mapped[str | None] = mapped_column(String(64))
    password_changed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    failed_login_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default="0"
    )
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    timezone: Mapped[str] = mapped_column(
        String(64), nullable=False, default="UTC", server_default="'UTC'"
    )
    preferences: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )

    organization: Mapped[Organization] = relationship(
        back_populates="users",
        primaryjoin="User.org_id == Organization.id",
        foreign_keys="User.org_id",
        lazy="raise_on_sql",
    )
    role_assignments: Mapped[list[UserRole]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        lazy="selectin",
        # `user_roles` also references `users` through `granted_by`, so the
        # linking column has to be stated explicitly on both sides.
        foreign_keys="UserRole.user_id",
    )

    __table_args__ = (
        UniqueConstraint("org_id", "email", name="uq_users_org_id_email"),
        Index("ix_users_org_status", "org_id", "status"),
        CheckConstraint("email = lower(email)", name="email_lowercase"),
        CheckConstraint(
            "auth_provider IN ('local','supabase','oidc','saml')", name="auth_provider_valid"
        ),
    )


class Permission(Base, TimestampMixin):
    """Catalogue of fine-grained permissions.

    Global (not tenant-scoped): the permission vocabulary is a property of the
    software version, while role→permission grants are per tenant.
    """

    __tablename__ = "permissions"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    resource: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(50), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    is_sensitive: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    """Sensitive permissions always produce an audit event when exercised."""


class Role(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A named permission bundle.

    ``org_id`` is null for the built-in system roles shipped with the platform;
    tenants may additionally define their own.
    """

    __tablename__ = "roles"

    org_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), index=True
    )
    key: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="''")
    is_system: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    rank: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    """Higher rank may manage lower-ranked roles; prevents privilege escalation."""

    permissions: Mapped[list[RolePermission]] = relationship(
        back_populates="role", cascade="all, delete-orphan", lazy="selectin"
    )

    __table_args__ = (
        UniqueConstraint("org_id", "key", name="uq_roles_org_id_key"),
        Index("ix_roles_system_key", "is_system", "key"),
    )


class RolePermission(Base, TimestampMixin):
    """Join row granting one permission to one role.

    Has no ``org_id`` of its own, so it carries no row level security policy:
    access is governed by the parent role's policy.
    """

    __tablename__ = "role_permissions"
    __table_args__ = {
        "comment": (
            "Child of roles. Access is governed by the parent role's policy; "
            "this table has no org_id of its own."
        )
    }

    role_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    )
    permission_key: Mapped[str] = mapped_column(
        ForeignKey("permissions.key", ondelete="CASCADE"), primary_key=True
    )

    role: Mapped[Role] = relationship(back_populates="permissions", lazy="raise_on_sql")


class UserRole(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """A role granted to a user, optionally narrowed to a team or project."""

    __tablename__ = "user_roles"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), nullable=False, index=True
    )
    scope_type: Mapped[str] = mapped_column(
        String(32), nullable=False, default=ScopeType.ORGANIZATION, server_default="'organization'"
    )
    scope_id: Mapped[uuid.UUID | None] = mapped_column(index=True)
    """Team or project id; null when the grant is organization-wide."""
    granted_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    """Supports time-boxed elevation (for example, break-glass admin access)."""

    user: Mapped[User] = relationship(
        back_populates="role_assignments", foreign_keys=[user_id], lazy="raise_on_sql"
    )
    role: Mapped[Role] = relationship(lazy="selectin")

    __table_args__ = (
        UniqueConstraint(
            "user_id", "role_id", "scope_type", "scope_id", name="uq_user_roles_grant"
        ),
        CheckConstraint("scope_type IN ('organization','team','project')", name="scope_type_valid"),
        CheckConstraint(
            "(scope_type = 'organization' AND scope_id IS NULL) OR "
            "(scope_type <> 'organization' AND scope_id IS NOT NULL)",
            name="scope_id_matches_type",
        ),
    )


class Team(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin, SoftDeleteMixin):
    __tablename__ = "teams"

    name: Mapped[str] = mapped_column(String(160), nullable=False)
    kind: Mapped[str] = mapped_column(
        String(48), nullable=False, default=TeamKind.OTHER, server_default="'other'"
    )
    description: Mapped[str | None] = mapped_column(Text)
    lead_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    contact_email: Mapped[str | None] = mapped_column(String(320))

    organization: Mapped[Organization] = relationship(
        back_populates="teams",
        primaryjoin="Team.org_id == Organization.id",
        foreign_keys="Team.org_id",
        lazy="raise_on_sql",
    )
    members: Mapped[list[TeamMember]] = relationship(
        back_populates="team", cascade="all, delete-orphan", lazy="raise_on_sql"
    )

    __table_args__ = (UniqueConstraint("org_id", "name", name="uq_teams_org_id_name"),)


class TeamMember(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    __tablename__ = "team_members"

    team_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("teams.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    team_role: Mapped[str] = mapped_column(
        String(48), nullable=False, default="member", server_default="'member'"
    )

    team: Mapped[Team] = relationship(back_populates="members", lazy="raise_on_sql")

    __table_args__ = (
        UniqueConstraint("team_id", "user_id", name="uq_team_members_team_id_user_id"),
    )


class Project(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin, SoftDeleteMixin):
    """A scope boundary for assets, scans, findings and engagements."""

    __tablename__ = "projects"

    name: Mapped[str] = mapped_column(String(200), nullable=False)
    key: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    """Short uppercase code used in finding and case identifiers (e.g. ``WEBAPP``)."""
    kind: Mapped[str] = mapped_column(
        String(48), nullable=False, default=ProjectKind.MIXED, server_default="'mixed'"
    )
    description: Mapped[str | None] = mapped_column(Text)
    owning_team_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("teams.id", ondelete="SET NULL"), index=True
    )
    owner_user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL")
    )
    business_criticality: Mapped[str] = mapped_column(
        String(32), nullable=False, default="medium", server_default="'medium'"
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default="true"
    )
    compliance_scope: Mapped[list[str]] = mapped_column(
        ARRAY(String(64)), nullable=False, default=list, server_default="{}"
    )
    """Framework keys this project must be assessed against (e.g. ``iso27001``)."""
    settings: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )

    organization: Mapped[Organization] = relationship(
        back_populates="projects",
        primaryjoin="Project.org_id == Organization.id",
        foreign_keys="Project.org_id",
        lazy="raise_on_sql",
    )
    members: Mapped[list[ProjectMember]] = relationship(
        back_populates="project", cascade="all, delete-orphan", lazy="raise_on_sql"
    )

    __table_args__ = (
        UniqueConstraint("org_id", "key", name="uq_projects_org_id_key"),
        Index("ix_projects_org_active", "org_id", "is_active"),
    )


class ProjectMember(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    __tablename__ = "project_members"

    project_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("projects.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    project_role: Mapped[str] = mapped_column(
        String(48), nullable=False, default="member", server_default="'member'"
    )

    project: Mapped[Project] = relationship(back_populates="members", lazy="raise_on_sql")

    __table_args__ = (
        UniqueConstraint("project_id", "user_id", name="uq_project_members_project_id_user_id"),
    )


class UserSession(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """A refresh-token-backed login session.

    Only hashes are stored, so a database compromise does not yield usable
    session credentials. Rotation is tracked so refresh-token reuse — a strong
    signal of token theft — can be detected and the family revoked.
    """

    __tablename__ = "user_sessions"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    refresh_token_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    parent_session_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("user_sessions.id", ondelete="SET NULL")
    )
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    device_label: Mapped[str | None] = mapped_column(String(160))
    mfa_satisfied: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default="false"
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_reason: Mapped[str | None] = mapped_column(String(120))

    __table_args__ = (Index("ix_user_sessions_user_active", "user_id", "revoked_at"),)


class ApiKey(Base, UUIDPrimaryKeyMixin, OrgScopedMixin, TimestampMixin):
    """A machine credential for CI pipelines and scanner integrations.

    Keys carry an explicit permission subset; a key can never exceed the
    permissions of the user that created it.
    """

    __tablename__ = "api_keys"

    name: Mapped[str] = mapped_column(String(160), nullable=False)
    prefix: Mapped[str] = mapped_column(String(32), nullable=False, unique=True, index=True)
    key_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True, index=True)
    created_by: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    scopes: Mapped[list[str]] = mapped_column(
        ARRAY(String(100)), nullable=False, default=list, server_default="{}"
    )
    project_ids: Mapped[list[uuid.UUID]] = mapped_column(
        ARRAY(PGUUID(as_uuid=True)), nullable=False, default=list, server_default="{}"
    )
    """Restricts the key to specific projects; empty means organization-wide."""
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_used_ip: Mapped[str | None] = mapped_column(String(64))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (Index("ix_api_keys_org_revoked", "org_id", "revoked_at"),)
