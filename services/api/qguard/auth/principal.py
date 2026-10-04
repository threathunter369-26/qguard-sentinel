"""The authenticated caller and how authorization decisions are made about it.

A :class:`Principal` is resolved once per request and is the only thing the
authorization layer consults. It carries the effective permission set already
flattened from the caller's role grants, plus the scopes (teams, projects)
those grants apply to, so a permission check never needs another query.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from qguard.auth.permissions import SENSITIVE_PERMISSION_KEYS
from qguard.common.enums import ActorType, ScopeType
from qguard.common.errors import PermissionDeniedError


@dataclass(frozen=True, slots=True)
class RoleGrant:
    """One role assignment and the scope it applies within."""

    role_key: str
    role_rank: int
    scope_type: str
    scope_id: uuid.UUID | None
    permissions: frozenset[str]


@dataclass(slots=True)
class Principal:
    """The authenticated caller for the current request.

    ``permissions`` is the union of every granted role's permissions, which is
    used for the coarse "may this caller ever do X" check. ``grants`` retains
    the per-scope detail, so an endpoint operating on a specific project can
    additionally confirm the permission applies *there* rather than anywhere.
    """

    user_id: uuid.UUID | None
    org_id: uuid.UUID
    actor_type: str = ActorType.USER
    email: str | None = None
    full_name: str | None = None
    is_superadmin: bool = False
    permissions: frozenset[str] = field(default_factory=frozenset)
    grants: tuple[RoleGrant, ...] = ()
    team_ids: frozenset[uuid.UUID] = field(default_factory=frozenset)
    project_ids: frozenset[uuid.UUID] = field(default_factory=frozenset)
    case_ids: frozenset[uuid.UUID] = field(default_factory=frozenset)
    session_id: uuid.UUID | None = None
    api_key_id: uuid.UUID | None = None
    mfa_satisfied: bool = False
    #: For API keys: the key's own scope list, which further narrows whatever
    #: the creating user could do. A key can never exceed its creator.
    token_scopes: frozenset[str] | None = None
    ip_address: str | None = None
    user_agent: str | None = None

    # ------------------------------------------------------------- properties
    @property
    def is_authenticated(self) -> bool:
        return self.actor_type != ActorType.ANONYMOUS

    @property
    def max_role_rank(self) -> int:
        return max((g.role_rank for g in self.grants), default=0)

    @property
    def label(self) -> str:
        if self.actor_type == ActorType.API_KEY:
            return f"api-key:{self.api_key_id}"
        return self.email or str(self.user_id or "anonymous")

    @property
    def effective_permissions(self) -> frozenset[str]:
        """Permissions after applying any API key scope restriction."""
        if self.token_scopes is None:
            return self.permissions
        return frozenset(self.permissions & self.token_scopes)

    # ------------------------------------------------------------- predicates
    def has_permission(self, permission: str) -> bool:
        return permission in self.effective_permissions

    def has_any(self, *permissions: str) -> bool:
        effective = self.effective_permissions
        return any(p in effective for p in permissions)

    def has_all(self, *permissions: str) -> bool:
        effective = self.effective_permissions
        return all(p in effective for p in permissions)

    def has_permission_in_project(self, permission: str, project_id: uuid.UUID | None) -> bool:
        """Check a permission against a specific project.

        An organization-wide grant applies everywhere. A project-scoped grant
        applies only to its own project, and a team-scoped grant applies to the
        projects that team owns (resolved when the principal is built).
        """
        if not self.has_permission(permission):
            return False
        if project_id is None:
            return True
        for grant in self.grants:
            if permission not in grant.permissions:
                continue
            if grant.scope_type == ScopeType.ORGANIZATION:
                return True
            if grant.scope_type == ScopeType.PROJECT and grant.scope_id == project_id:
                return True
            if grant.scope_type == ScopeType.TEAM and project_id in self.project_ids:
                return True
        return False

    def can_grant_role(self, role_rank: int) -> bool:
        """Whether this caller may assign a role of the given rank.

        A caller can never grant a role at or above their own highest rank.
        Without this, anyone holding ``user:manage_roles`` could promote
        themselves to administrator.
        """
        return role_rank < self.max_role_rank

    def can_access_case(self, case_id: uuid.UUID, lead_investigator_id: uuid.UUID | None) -> bool:
        """Forensic cases are restricted to their assigned investigators.

        An organization-wide ``case:read_all`` grant overrides this; otherwise
        the caller must lead the case or be an assigned member.
        """
        if self.has_permission("case:read_all"):
            return True
        if lead_investigator_id is not None and lead_investigator_id == self.user_id:
            return True
        return case_id in self.case_ids

    # -------------------------------------------------------------- enforcement
    def require(self, permission: str, *, detail: str | None = None) -> None:
        if not self.has_permission(permission):
            raise PermissionDeniedError(
                detail or f"This action requires the {permission!r} permission.",
                details={"required_permission": permission},
            )

    def require_any(self, *permissions: str) -> None:
        if not self.has_any(*permissions):
            raise PermissionDeniedError(
                "This action requires one of several permissions you do not hold.",
                details={"required_any_of": sorted(permissions)},
            )

    def require_in_project(self, permission: str, project_id: uuid.UUID | None) -> None:
        if not self.has_permission_in_project(permission, project_id):
            raise PermissionDeniedError(
                f"This action requires the {permission!r} permission for that project.",
                details={
                    "required_permission": permission,
                    "project_id": str(project_id) if project_id else None,
                },
            )

    def require_same_org(self, org_id: uuid.UUID | None) -> None:
        """Guard against cross-tenant object references in a request body.

        Row level security already prevents reading another tenant's rows; this
        turns an id from a different tenant into an explicit 403 rather than a
        confusing 404.
        """
        from qguard.common.errors import TenantIsolationError

        if org_id is not None and org_id != self.org_id:
            raise TenantIsolationError()

    def is_sensitive(self, permission: str) -> bool:
        return permission in SENSITIVE_PERMISSION_KEYS

    def to_log_context(self) -> dict[str, Any]:
        return {
            "actor_id": str(self.user_id) if self.user_id else None,
            "actor_type": self.actor_type,
            "org_id": str(self.org_id),
            "api_key_id": str(self.api_key_id) if self.api_key_id else None,
        }


def system_principal(org_id: uuid.UUID) -> Principal:
    """A principal representing the platform itself (workers, schedulers).

    Used for actions no human initiated — a scheduled scan, a retention sweep —
    so those still produce attributable audit entries rather than appearing
    anonymous.
    """
    from qguard.auth.permissions import ALL_PERMISSION_KEYS

    return Principal(
        user_id=None,
        org_id=org_id,
        actor_type=ActorType.SYSTEM,
        email=None,
        full_name="QGuard Sentinel (system)",
        permissions=frozenset(ALL_PERMISSION_KEYS),
        grants=(
            RoleGrant(
                role_key="__system__",
                role_rank=1000,
                scope_type=ScopeType.ORGANIZATION,
                scope_id=None,
                permissions=frozenset(ALL_PERMISSION_KEYS),
            ),
        ),
        mfa_satisfied=True,
    )
