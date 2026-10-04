"""Tenant provisioning.

Creating an organization is a platform-level operation, not a tenant one: the
`organizations` row level security policy compares a row's id to the current
tenant context, which by definition does not exist yet for the tenant being
created. Provisioning therefore runs inside an explicit, transaction-local
``app.platform_bootstrap`` window — the same narrow gate that governs writing
the global role catalogue.

Keeping this in one place means there is exactly one code path in the platform
that can create a tenant, and it is auditable.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from qguard.auth.rbac import ensure_system_roles
from qguard.common.cryptoutil import hash_password
from qguard.common.database import apply_tenant_context
from qguard.common.enums import ScopeType, UserStatus
from qguard.common.errors import ConflictError, ValidationError
from qguard.common.logging import get_logger
from qguard.models.identity import Organization, Role, User, UserRole

log = get_logger(__name__)


@asynccontextmanager
async def platform_bootstrap(session: AsyncSession) -> AsyncIterator[None]:
    """Open a transaction-local window in which global rows may be written.

    The flag is lowered on exit — including on error — so no later statement in
    the same transaction inherits platform-level write access.
    """
    await session.execute(text("SELECT set_config('app.platform_bootstrap', 'on', true)"))
    try:
        yield
    finally:
        await session.execute(text("SELECT set_config('app.platform_bootstrap', '', true)"))


def slugify(value: str, *, max_length: int = 80) -> str:
    cleaned = "".join(c if c.isalnum() else "-" for c in value.lower())
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return cleaned.strip("-")[:max_length] or "org"


async def provision_organization(
    session: AsyncSession,
    *,
    name: str,
    slug: str | None = None,
    admin_email: str,
    admin_password: str | None,
    admin_name: str | None = None,
    admin_role_key: str = "platform_admin",
    is_demo: bool = False,
    retention_days: int = 365,
) -> tuple[Organization, User]:
    """Create an organization and its first administrator.

    Returns the organization and the administrator. The caller owns the
    transaction, so a failure part-way leaves no half-provisioned tenant.
    """
    slug = slug or slugify(name)
    admin_email = admin_email.strip().lower()
    if not admin_email or "@" not in admin_email:
        raise ValidationError("A valid administrator email address is required.")

    await ensure_system_roles(session)

    async with platform_bootstrap(session):
        existing = (
            await session.execute(select(Organization.id).where(Organization.slug == slug))
        ).scalar_one_or_none()
        if existing is not None:
            raise ConflictError(
                f"An organization with the slug {slug!r} already exists.",
                details={"slug": slug},
            )

        org = Organization(
            name=name,
            slug=slug,
            is_demo=is_demo,
            retention_days=retention_days,
        )
        session.add(org)
        await session.flush()

    # From here on the new tenant's own context applies, so every row inserted
    # is covered by the ordinary isolation policy.
    await apply_tenant_context(session, org.id, None)

    admin_role = (
        await session.execute(
            select(Role).where(Role.key == admin_role_key, Role.is_system.is_(True))
        )
    ).scalar_one_or_none()
    if admin_role is None:
        raise ValidationError(f"Unknown system role {admin_role_key!r}.")

    user = User(
        org_id=org.id,
        email=admin_email,
        full_name=admin_name or "Platform Administrator",
        password_hash=hash_password(admin_password) if admin_password else None,
        auth_provider="local" if admin_password else "supabase",
        status=UserStatus.ACTIVE,
        is_superadmin=admin_role_key == "platform_admin",
        password_changed_at=datetime.now(UTC) if admin_password else None,
    )
    session.add(user)
    await session.flush()

    session.add(
        UserRole(
            org_id=org.id,
            user_id=user.id,
            role_id=admin_role.id,
            scope_type=ScopeType.ORGANIZATION,
        )
    )
    await session.flush()

    log.info(
        "platform.organization_provisioned",
        org_id=str(org.id),
        slug=slug,
        is_demo=is_demo,
        admin_role=admin_role_key,
    )
    return org, user


async def create_user(
    session: AsyncSession,
    *,
    org_id: uuid.UUID,
    email: str,
    full_name: str | None,
    role_key: str,
    password: str | None,
    job_title: str | None = None,
) -> User:
    """Create a user inside an existing organization with one system role."""
    email = email.strip().lower()
    await apply_tenant_context(session, org_id, None)

    if (
        await session.execute(select(User.id).where(User.org_id == org_id, User.email == email))
    ).scalar_one_or_none() is not None:
        raise ConflictError(f"{email} already exists in this organization.")

    role = (
        await session.execute(select(Role).where(Role.key == role_key, Role.is_system.is_(True)))
    ).scalar_one_or_none()
    if role is None:
        raise ValidationError(f"Unknown system role {role_key!r}.")

    user = User(
        org_id=org_id,
        email=email,
        full_name=full_name or email.split("@")[0],
        job_title=job_title,
        password_hash=hash_password(password) if password else None,
        auth_provider="local" if password else "supabase",
        status=UserStatus.ACTIVE,
        password_changed_at=datetime.now(UTC) if password else None,
    )
    session.add(user)
    await session.flush()
    session.add(
        UserRole(
            org_id=org_id,
            user_id=user.id,
            role_id=role.id,
            scope_type=ScopeType.ORGANIZATION,
        )
    )
    await session.flush()
    return user
