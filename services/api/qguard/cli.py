"""Administrative command line interface.

Covers the operations an operator needs before the web UI is usable, plus the
development-only demo seed. Uses argparse rather than a CLI framework to keep
the deployment's dependency surface small.

    qguard-admin bootstrap --org "Acme Security" --email admin@acme.test
    qguard-admin create-user --email analyst@acme.test --role security_analyst
    qguard-admin verify-audit --org-slug acme
    qguard-admin seed-demo            # refused when QG_ENV=production
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import secrets
import sys
from typing import Any

from sqlalchemy import select

from qguard.auth.permissions import SYSTEM_ROLES_BY_KEY
from qguard.auth.provisioning import (
    create_user,
    platform_bootstrap,
    provision_organization,
)
from qguard.auth.rbac import ensure_system_roles
from qguard.auth.schemas import validate_password_strength
from qguard.common.config import get_settings
from qguard.common.database import apply_tenant_context, session_scope
from qguard.common.errors import QGuardError
from qguard.common.logging import configure_logging, get_logger
from qguard.models.identity import Organization

log = get_logger(__name__)


def _slugify(value: str) -> str:
    cleaned = "".join(c if c.isalnum() else "-" for c in value.lower())
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return cleaned.strip("-")[:80] or "org"


async def _bootstrap(args: argparse.Namespace) -> int:
    """Create the first organization and its platform administrator."""
    password = args.password or _prompt_password()
    try:
        validate_password_strength(password)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    async with session_scope() as session:
        try:
            org, user = await provision_organization(
                session,
                name=args.org,
                slug=args.slug,
                admin_email=args.email,
                admin_password=password,
                admin_name=args.name,
            )
        except QGuardError as exc:
            print(f"error: {exc.message}", file=sys.stderr)
            return 1

    print(f"Organization : {org.name} (slug: {org.slug})")
    print(f"Administrator: {user.email}")
    print("Role         : platform_admin")
    print()
    print("Enable multi-factor authentication on this account before using it for")
    print("anything beyond initial setup — it holds every sensitive permission.")
    return 0


def _prompt_password() -> str:
    first = getpass.getpass("Password: ")
    second = getpass.getpass("Confirm password: ")
    if first != second:
        print("error: the passwords do not match.", file=sys.stderr)
        raise SystemExit(2)
    return first


async def _create_user(args: argparse.Namespace) -> int:
    if args.role not in SYSTEM_ROLES_BY_KEY:
        print(
            f"error: unknown role {args.role!r}. Available roles: "
            + ", ".join(sorted(SYSTEM_ROLES_BY_KEY)),
            file=sys.stderr,
        )
        return 2

    password = args.password or secrets.token_urlsafe(18) + "Aa1!"
    generated = args.password is None

    async with session_scope() as session:
        org = await _resolve_org(session, args.org_slug)
        if org is None:
            print("error: organization not found.", file=sys.stderr)
            return 1
        try:
            user = await create_user(
                session,
                org_id=org.id,
                email=args.email,
                full_name=args.name,
                role_key=args.role,
                password=password,
            )
        except QGuardError as exc:
            print(f"error: {exc.message}", file=sys.stderr)
            return 1

    print(f"Created {user.email} with role {args.role}.")
    if generated:
        print(f"Temporary password: {password}")
        print("Have the user change it at first sign-in.")
    return 0


async def _resolve_org(session: Any, slug: str | None) -> Organization | None:
    """Find an organization from the command line.

    A cross-tenant read by nature, so it runs under the platform bootstrap
    gate — the same narrow window used for provisioning.
    """
    async with platform_bootstrap(session):
        return await _resolve_org_unscoped(session, slug)


async def _resolve_org_unscoped(session: Any, slug: str | None) -> Organization | None:
    if slug:
        return (
            await session.execute(select(Organization).where(Organization.slug == slug))
        ).scalar_one_or_none()
    orgs = (await session.execute(select(Organization).limit(2))).scalars().all()
    if len(orgs) == 1:
        return orgs[0]
    if not orgs:
        return None
    print("error: several organizations exist; pass --org-slug.", file=sys.stderr)
    return None


async def _list_roles(_args: argparse.Namespace) -> int:
    print(f"{'ROLE':24s} {'RANK':>5s}  PERMISSIONS  DESCRIPTION")
    for spec in sorted(SYSTEM_ROLES_BY_KEY.values(), key=lambda r: -r.rank):
        print(f"{spec.key:24s} {spec.rank:5d}  {len(spec.permissions):11d}  {spec.name}")
    return 0


async def _verify_audit(args: argparse.Namespace) -> int:
    """Recompute the audit hash chain and report the first break, if any."""
    from qguard.audit.service import AuditService

    async with session_scope() as session:
        org = await _resolve_org(session, args.org_slug)
        if org is None:
            print("error: organization not found.", file=sys.stderr)
            return 1
        await apply_tenant_context(session, org.id, None)
        result = await AuditService(session).verify_chain(org.id)

    print(f"Organization  : {org.name}")
    print(f"Entries checked: {result['entries_checked']}")
    print(f"Verified      : {result['verified']}")
    print(f"Message       : {result['message']}")
    if not result["verified"]:
        print(f"First break at sequence: {result['first_broken_sequence']}", file=sys.stderr)
        return 1
    return 0


async def _sync_roles(_args: argparse.Namespace) -> int:
    async with session_scope() as session:
        roles = await ensure_system_roles(session)
    print(f"Synchronised {len(roles)} system roles and the permission catalogue.")
    return 0


async def _seed_demo(args: argparse.Namespace) -> int:
    """Seed clearly-labelled demonstration data. Never permitted in production."""
    settings = get_settings()
    if settings.is_production:
        print(
            "error: demo data cannot be seeded in a production environment.",
            file=sys.stderr,
        )
        return 2
    from qguard.seed import seed_demo_organization

    async with session_scope() as session:
        summary = await seed_demo_organization(session, reset=args.reset)
    print("Seeded the DEMO organization. Every record is marked as demo data.")
    for key, value in summary.items():
        print(f"  {key:28s} {value}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qguard-admin",
        description="QGuard Sentinel administration.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("bootstrap", help="Create the first organization and administrator.")
    p.add_argument("--org", required=True, help="Organization display name.")
    p.add_argument("--slug", help="URL slug (derived from the name when omitted).")
    p.add_argument("--email", required=True, help="Administrator email address.")
    p.add_argument("--name", help="Administrator full name.")
    p.add_argument("--password", help="Password (prompted for when omitted).")
    p.set_defaults(func=_bootstrap)

    p = sub.add_parser("create-user", help="Create a user with a system role.")
    p.add_argument("--email", required=True)
    p.add_argument("--name")
    p.add_argument("--role", required=True, help="System role key; see `list-roles`.")
    p.add_argument("--org-slug")
    p.add_argument("--password", help="Password (generated when omitted).")
    p.set_defaults(func=_create_user)

    p = sub.add_parser("list-roles", help="Show the built-in roles.")
    p.set_defaults(func=_list_roles)

    p = sub.add_parser("sync-roles", help="Reconcile roles and permissions after an upgrade.")
    p.set_defaults(func=_sync_roles)

    p = sub.add_parser("verify-audit", help="Verify the audit hash chain.")
    p.add_argument("--org-slug")
    p.set_defaults(func=_verify_audit)

    p = sub.add_parser("seed-demo", help="Seed demonstration data (non-production only).")
    p.add_argument("--reset", action="store_true", help="Remove existing demo data first.")
    p.set_defaults(func=_seed_demo)

    return parser


def main() -> None:
    configure_logging()
    args = build_parser().parse_args()
    raise SystemExit(asyncio.run(args.func(args)))


if __name__ == "__main__":
    main()
