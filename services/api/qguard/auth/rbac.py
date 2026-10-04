"""Resolve a database identity into an authorization :class:`Principal`.

Permissions are read from the database on every request rather than baked into
the access token, so revoking a role takes effect at once instead of when the
token happens to expire. The whole resolution is three queries, and the result
is cached for the lifetime of the request only.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import delete as sa_delete
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from qguard.auth.principal import Principal, RoleGrant
from qguard.common.enums import ActorType, ScopeType, UserStatus
from qguard.common.errors import AuthenticationError
from qguard.models.assets import Asset  # noqa: F401 - keeps mapper configuration complete
from qguard.models.dfir import CaseMember
from qguard.models.identity import (
    Project,
    ProjectMember,
    Role,
    RolePermission,
    TeamMember,
    User,
    UserRole,
)


async def resolve_principal(
    session: AsyncSession,
    *,
    user_id: uuid.UUID,
    org_id: uuid.UUID,
    session_id: uuid.UUID | None = None,
    api_key_id: uuid.UUID | None = None,
    token_scopes: frozenset[str] | None = None,
    mfa_satisfied: bool = False,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> Principal:
    """Build the caller's principal, or refuse if the account is not usable."""
    user = (
        await session.execute(
            select(User).where(User.id == user_id, User.org_id == org_id, User.deleted_at.is_(None))
        )
    ).scalar_one_or_none()

    if user is None:
        # The token referenced an account this tenant no longer has. Treat it
        # as unauthenticated rather than leaking whether the id ever existed.
        raise AuthenticationError("The account for this token no longer exists.")

    if user.status != UserStatus.ACTIVE:
        raise AuthenticationError(
            f"This account is {user.status.replace('_', ' ')} and cannot be used to sign in."
        )

    now = datetime.now(UTC)

    # --- role grants -------------------------------------------------------
    grant_rows = (
        await session.execute(
            select(UserRole, Role)
            .join(Role, Role.id == UserRole.role_id)
            .where(
                UserRole.user_id == user_id,
                UserRole.org_id == org_id,
                or_(UserRole.expires_at.is_(None), UserRole.expires_at > now),
            )
        )
    ).all()

    role_ids = {row[1].id for row in grant_rows}
    permissions_by_role: dict[uuid.UUID, set[str]] = {rid: set() for rid in role_ids}
    if role_ids:
        for role_id, permission_key in (
            await session.execute(
                select(RolePermission.role_id, RolePermission.permission_key).where(
                    RolePermission.role_id.in_(role_ids)
                )
            )
        ).all():
            permissions_by_role[role_id].add(permission_key)

    grants: list[RoleGrant] = []
    all_permissions: set[str] = set()
    for user_role, role in grant_rows:
        perms = frozenset(permissions_by_role.get(role.id, set()))
        grants.append(
            RoleGrant(
                role_key=role.key,
                role_rank=role.rank,
                scope_type=user_role.scope_type,
                scope_id=user_role.scope_id,
                permissions=perms,
            )
        )
        all_permissions |= perms

    # --- team, project and case scopes -------------------------------------
    team_ids = set(
        (
            await session.execute(
                select(TeamMember.team_id).where(
                    TeamMember.user_id == user_id, TeamMember.org_id == org_id
                )
            )
        )
        .scalars()
        .all()
    )

    project_ids = set(
        (
            await session.execute(
                select(ProjectMember.project_id).where(
                    ProjectMember.user_id == user_id, ProjectMember.org_id == org_id
                )
            )
        )
        .scalars()
        .all()
    )

    # A team-scoped role grant also reaches the projects that team owns, which
    # is how "the SOC team can triage everything the SOC owns" is expressed.
    scoped_team_ids = {g.scope_id for g in grants if g.scope_type == ScopeType.TEAM and g.scope_id}
    relevant_team_ids = team_ids | scoped_team_ids
    if relevant_team_ids:
        project_ids |= set(
            (
                await session.execute(
                    select(Project.id).where(
                        Project.org_id == org_id,
                        Project.owning_team_id.in_(relevant_team_ids),
                        Project.deleted_at.is_(None),
                    )
                )
            )
            .scalars()
            .all()
        )
    # Project-scoped grants name their project directly.
    project_ids |= {g.scope_id for g in grants if g.scope_type == ScopeType.PROJECT and g.scope_id}

    case_ids = set(
        (
            await session.execute(
                select(CaseMember.case_id).where(
                    CaseMember.user_id == user_id, CaseMember.org_id == org_id
                )
            )
        )
        .scalars()
        .all()
    )

    return Principal(
        user_id=user.id,
        org_id=org_id,
        actor_type=ActorType.API_KEY if api_key_id else ActorType.USER,
        email=user.email,
        full_name=user.full_name,
        is_superadmin=user.is_superadmin,
        permissions=frozenset(all_permissions),
        grants=tuple(grants),
        team_ids=frozenset(team_ids),
        project_ids=frozenset(pid for pid in project_ids if pid),
        case_ids=frozenset(case_ids),
        session_id=session_id,
        api_key_id=api_key_id,
        mfa_satisfied=mfa_satisfied,
        token_scopes=token_scopes,
        ip_address=ip_address,
        user_agent=user_agent,
    )


async def ensure_system_roles(session: AsyncSession) -> dict[str, Role]:
    """Create or update the built-in roles and the permission catalogue.

    Idempotent, and run at startup. Permissions added by a platform upgrade are
    attached to the system roles that should hold them, while roles a tenant
    created are left untouched.
    """
    from sqlalchemy import text

    from qguard.auth.permissions import PERMISSIONS, SYSTEM_ROLES
    from qguard.models.identity import Permission

    # Global (org_id IS NULL) role rows are writable only from the platform's
    # own bootstrap path. The flag is transaction-local, so it cannot outlive
    # this reconciliation, and a tenant-scoped request never raises it.
    await session.execute(text("SELECT set_config('app.platform_bootstrap', 'on', true)"))

    existing_permissions = set((await session.execute(select(Permission.key))).scalars().all())
    for spec in PERMISSIONS:
        if spec.key not in existing_permissions:
            session.add(
                Permission(
                    key=spec.key,
                    resource=spec.resource,
                    action=spec.action,
                    description=spec.description,
                    is_sensitive=spec.sensitive,
                )
            )
    await session.flush()

    roles: dict[str, Role] = {}
    for role_spec in SYSTEM_ROLES:
        role = (
            await session.execute(
                select(Role).where(Role.key == role_spec.key, Role.is_system.is_(True))
            )
        ).scalar_one_or_none()
        if role is None:
            role = Role(
                org_id=None,
                key=role_spec.key,
                name=role_spec.name,
                description=role_spec.description,
                is_system=True,
                rank=role_spec.rank,
            )
            session.add(role)
            await session.flush()
        else:
            role.name = role_spec.name
            role.description = role_spec.description
            role.rank = role_spec.rank

        current = set(
            (
                await session.execute(
                    select(RolePermission.permission_key).where(RolePermission.role_id == role.id)
                )
            )
            .scalars()
            .all()
        )
        for key in role_spec.permissions - current:
            session.add(RolePermission(role_id=role.id, permission_key=key))
        # Permissions removed from a system role's definition are withdrawn, so
        # a tightened default actually takes effect on upgrade.
        for key in current - role_spec.permissions:
            await session.execute(
                sa_delete(RolePermission).where(
                    RolePermission.role_id == role.id,
                    RolePermission.permission_key == key,
                )
            )
        roles[role_spec.key] = role

    await session.flush()
    # Lower the flag explicitly rather than relying on the transaction ending,
    # so nothing later in the same transaction inherits it.
    await session.execute(text("SELECT set_config('app.platform_bootstrap', '', true)"))
    return roles
