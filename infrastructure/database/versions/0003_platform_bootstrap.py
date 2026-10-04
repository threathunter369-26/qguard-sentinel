"""Allow the platform's own bootstrap path to write global reference rows

`roles` and `report_templates` hold a mix of rows: global ones shipped with the
software (``org_id IS NULL``) and tenant-defined ones. The tenant isolation
policy from revision 0002 lets every tenant *read* the global rows but
deliberately refuses to let one *write* them — otherwise a tenant
administrator could create a role visible to every other tenant, which is a
privilege escalation path across the tenant boundary.

The platform itself still has to write those rows: the permission catalogue and
the built-in roles are reference data tied to the software version, and they
are reconciled on every start-up so an upgrade that adds a permission takes
effect without a manual step.

This revision adds a second, narrowly scoped policy for exactly that path,
keyed on a transaction-local ``app.platform_bootstrap`` flag. The flag is
raised only by `ensure_system_roles()` and by the reference-data seeders, and
being transaction-local it cannot persist beyond the statement that set it.
A tenant-scoped request never raises it, so the escalation path stays closed.

Revision ID: 0003_bootstrap
Revises: 0002_security
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0003_bootstrap"
down_revision: str | None = "0002_security"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

GLOBAL_REFERENCE_TABLES: tuple[str, ...] = ("roles", "report_templates")


def upgrade() -> None:
    op.execute(
        """
        CREATE OR REPLACE FUNCTION app.is_platform_bootstrap() RETURNS boolean
        LANGUAGE sql STABLE PARALLEL SAFE AS $$
          SELECT coalesce(current_setting('app.platform_bootstrap', true), '') = 'on'
        $$
        """
    )
    op.execute(
        """
        COMMENT ON FUNCTION app.is_platform_bootstrap() IS
          'True only inside the platform''s own reference-data reconciliation. '
          'Gates writes to global (org_id IS NULL) rows in roles and '
          'report_templates so a tenant cannot create platform-wide records.'
        """
    )

    for table in GLOBAL_REFERENCE_TABLES:
        op.execute(
            f"""
            CREATE POLICY platform_bootstrap ON {table}
              USING (app.is_platform_bootstrap())
              WITH CHECK (app.is_platform_bootstrap() AND org_id IS NULL)
            """
        )

    # Creating a tenant is the same class of operation and has the same
    # chicken-and-egg problem: the `organizations` policy compares `id` to the
    # current tenant context, which by definition does not exist yet for a
    # tenant being created. Provisioning therefore runs under the same gate.
    op.execute(
        """
        CREATE POLICY platform_bootstrap ON organizations
          USING (app.is_platform_bootstrap())
          WITH CHECK (app.is_platform_bootstrap())
        """
    )

    # Pre-authentication audit rows (a failed sign-in against an address that
    # does not exist) belong to no tenant, so `org_id` is NULL. Two things make
    # them need this gate:
    #
    #   * PostgreSQL applies a policy's USING clause to an INSERT's RETURNING
    #     clause, and `org_id = app.current_org_id()` is never true for NULL.
    #   * Those rows name the address that was targeted. Letting every tenant
    #     read them would disclose which of another tenant's users are being
    #     attacked.
    op.execute(
        """
        CREATE POLICY platform_audit ON audit_log
          USING (org_id IS NULL AND app.is_platform_bootstrap())
          WITH CHECK (org_id IS NULL AND app.is_platform_bootstrap())
        """
    )

    # `role_permissions` is a child of `roles` with no org_id of its own, so it
    # carries no RLS policy. Its parent's policy is what protects it.
    op.execute(
        """
        COMMENT ON TABLE role_permissions IS
          'Child of roles. Access is governed by the parent role''s policy; '
          'this table has no org_id of its own.'
        """
    )


def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS platform_audit ON audit_log")
    for table in (*GLOBAL_REFERENCE_TABLES, "organizations"):
        op.execute(f"DROP POLICY IF EXISTS platform_bootstrap ON {table}")
    op.execute("DROP FUNCTION IF EXISTS app.is_platform_bootstrap()")
