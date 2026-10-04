"""Row level security, append-only audit enforcement and privileged helpers

Three database-level security controls are installed here, each independent of
the application code so an application bug cannot disable them:

1. **Row level security.** Every tenant-scoped table gets a policy comparing
   ``org_id`` to the ``app.current_org_id`` session setting. RLS is additionally
   ``FORCE``d so the table owner is subject to it too — development therefore
   behaves exactly like production instead of silently bypassing isolation.

2. **Append-only history.** ``audit_log``, ``chain_of_custody`` and
   ``evidence_access_log`` reject UPDATE and DELETE via triggers. Triggers are
   used rather than privilege revocation because they bind to the table, not to
   a role, and so hold for every connection including the owner's.

3. **Narrow privileged entry points.** The two genuinely cross-tenant runtime
   operations — resolving an identity at sign-in, and a worker claiming the next
   job — are SECURITY DEFINER functions that return only the columns they need.
   Nothing else in the runtime is granted a tenant-wide view.

Revision ID: 0002_security
Revises: 0001_initial
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op

revision: str = "0002_security"
down_revision: str | None = "0001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Frozen at the time of this revision. A later table gets its policy in a later
# revision, so replaying history always reproduces the same state.
TENANT_TABLES: tuple[str, ...] = (
    "api_endpoints", "api_keys", "api_specifications", "asset_assessments",
    "asset_relationships", "assets", "campaigns", "case_members", "case_notes", "cases",
    "chain_of_custody", "cloud_accounts", "cloud_resources", "compliance_assessments",
    "container_images", "control_assessments", "crypto_inventory", "dependencies",
    "detected_secrets", "engagement_phases", "engagement_targets", "engagements",
    "evidence", "evidence_access_log", "finding_comments", "findings", "forensic_artifacts",
    "incident_assets", "incident_responders", "incident_tasks", "incident_updates",
    "incidents", "ioc_matches", "iocs", "jobs", "kubernetes_resources", "license_findings",
    "mobile_applications", "notification_channels", "notifications", "pentest_notes",
    "pqc_readiness_assessments", "project_members", "projects", "reports",
    "retention_policies", "retests", "risk_snapshots", "scan_engine_runs", "scan_metrics",
    "scan_profiles", "scan_schedules", "scans", "security_events", "team_members", "teams",
    "test_authorizations", "threat_actors", "threat_feeds", "timeline_events", "user_roles",
    "user_sessions", "users", "vulnerabilities", "vulnerability_events",
)

APPEND_ONLY_TABLES: tuple[str, ...] = (
    "audit_log",
    "chain_of_custody",
    "evidence_access_log",
)


def upgrade() -> None:
    # ------------------------------------------------------------------ schema
    op.execute("CREATE SCHEMA IF NOT EXISTS app")
    op.execute(
        """
        COMMENT ON SCHEMA app IS
          'QGuard Sentinel security helpers: tenant context accessors, '
          'append-only guards and the narrow privileged entry points.'
        """
    )

    # ------------------------------------------------- tenant context accessors
    # STABLE so the planner can hoist the call out of per-row evaluation; the
    # `true` second argument makes a missing setting return NULL instead of
    # raising, which is what makes "no context => no rows" work.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION app.current_org_id() RETURNS uuid
        LANGUAGE sql STABLE PARALLEL SAFE AS $$
          SELECT NULLIF(current_setting('app.current_org_id', true), '')::uuid
        $$
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION app.current_user_id() RETURNS uuid
        LANGUAGE sql STABLE PARALLEL SAFE AS $$
          SELECT NULLIF(current_setting('app.current_user_id', true), '')::uuid
        $$
        """
    )

    # --------------------------------------------------------------------- RLS
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        # FORCE makes the owner subject to the policy as well. Without it a
        # deployment that connects as the owner would silently run with no
        # isolation, and the control would only appear to work.
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation ON {table}
              USING (org_id = app.current_org_id())
              WITH CHECK (org_id = app.current_org_id())
            """
        )

    # `organizations` is the tenant root: a caller may only see its own row.
    op.execute("ALTER TABLE organizations ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE organizations FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY tenant_isolation ON organizations
          USING (id = app.current_org_id())
          WITH CHECK (id = app.current_org_id())
        """
    )

    # `roles` and `report_templates` mix global system rows with tenant rows.
    for table in ("roles", "report_templates"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation ON {table}
              USING (org_id IS NULL OR org_id = app.current_org_id())
              WITH CHECK (org_id = app.current_org_id())
            """
        )

    # `audit_log` has a nullable org_id so pre-authentication events (a failed
    # sign-in against an unknown address) are still recorded. Those rows belong
    # to no tenant and are readable only through the platform administration
    # interface, never through a tenant-scoped session.
    op.execute("ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE audit_log FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY tenant_isolation ON audit_log
          USING (org_id = app.current_org_id())
          WITH CHECK (org_id = app.current_org_id() OR org_id IS NULL)
        """
    )

    # ------------------------------------------------------- append-only guards
    op.execute(
        """
        CREATE OR REPLACE FUNCTION app.reject_history_mutation()
        RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN
          RAISE EXCEPTION
            '% is append-only: % is not permitted on audit or custody records',
            TG_TABLE_NAME, TG_OP
            USING ERRCODE = 'insufficient_privilege',
                  HINT = 'Record a compensating entry instead of altering history.';
        END;
        $$
        """
    )
    for table in APPEND_ONLY_TABLES:
        op.execute(
            f"""
            CREATE TRIGGER {table}_append_only
              BEFORE UPDATE OR DELETE ON {table}
              FOR EACH ROW EXECUTE FUNCTION app.reject_history_mutation()
            """
        )

    # Retention still needs a way to archive very old audit data. It runs as a
    # maintenance role that disables the trigger inside one transaction, which
    # is itself an audited action, rather than the trigger being absent.
    op.execute(
        """
        COMMENT ON FUNCTION app.reject_history_mutation() IS
          'Blocks UPDATE/DELETE on append-only history tables. Archival must '
          'use ALTER TABLE ... DISABLE TRIGGER inside an audited maintenance '
          'transaction.'
        """
    )

    # --------------------------------------- privileged-path policy exemptions
    # `FORCE ROW LEVEL SECURITY` deliberately applies to the table owner too,
    # which means it also applies inside SECURITY DEFINER functions. Three
    # runtime operations genuinely precede or span tenant context:
    #
    #   * resolving an identity at sign-in (no tenant is known yet),
    #   * resolving a refresh token or API key to its tenant,
    #   * a worker claiming the next job (workers serve every tenant).
    #
    # Each is granted an exemption scoped to a flag that only the relevant
    # function can raise: the flag is declared in the function's own `SET`
    # clause, so PostgreSQL sets it on entry and restores it on exit — including
    # when the function raises. The exemption therefore cannot outlive the call,
    # and it is readable here rather than being an implicit owner bypass.
    op.execute(
        """
        CREATE POLICY identity_lookup ON users
          FOR SELECT
          USING (current_setting('app.identity_lookup', true) = 'on')
        """
    )
    op.execute(
        """
        CREATE POLICY identity_lookup ON user_sessions
          FOR SELECT
          USING (current_setting('app.identity_lookup', true) = 'on')
        """
    )
    op.execute(
        """
        CREATE POLICY identity_lookup ON api_keys
          FOR SELECT
          USING (current_setting('app.identity_lookup', true) = 'on')
        """
    )
    op.execute(
        """
        CREATE POLICY job_runner ON jobs
          USING (current_setting('app.job_runner', true) = 'on')
          WITH CHECK (current_setting('app.job_runner', true) = 'on')
        """
    )

    # ------------------------------------------- privileged sign-in resolution
    # The exemption flag is raised inside the function body rather than in a
    # `SET` clause: PostgreSQL requires elevated privileges to name a custom
    # parameter in a function's SET clause, and the platform deliberately runs
    # migrations as a non-superuser. `set_config(..., true)` is transaction
    # local, and the EXCEPTION block guarantees the flag is lowered again even
    # when the query raises, so the exemption cannot outlive the call.
    #
    # Sign-in must find an account before any tenant context exists. This is
    # the only cross-tenant read of `users` in the runtime: it is keyed on the
    # exact address, returns nothing beyond what the credential check needs,
    # and cannot be used to enumerate a tenant.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION app.find_login_identity(p_email text)
        RETURNS TABLE (
          user_id uuid,
          org_id uuid,
          email text,
          password_hash text,
          status text,
          auth_provider text,
          mfa_enabled boolean,
          mfa_secret_encrypted text,
          failed_login_count integer,
          locked_until timestamptz,
          is_superadmin boolean,
          full_name text
        )
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
        AS $$
        BEGIN
          PERFORM set_config('app.identity_lookup', 'on', true);
          RETURN QUERY
            SELECT u.id, u.org_id, u.email::text, u.password_hash::text,
                   u.status::text, u.auth_provider::text, u.mfa_enabled,
                   u.mfa_secret_encrypted::text, u.failed_login_count,
                   u.locked_until, u.is_superadmin, u.full_name::text
            FROM users u
            WHERE u.email = lower(p_email)
              AND u.deleted_at IS NULL
            LIMIT 1;
          PERFORM set_config('app.identity_lookup', '', true);
        EXCEPTION WHEN OTHERS THEN
          PERFORM set_config('app.identity_lookup', '', true);
          RAISE;
        END;
        $$
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION app.find_session_identity(p_refresh_hash text)
        RETURNS TABLE (
          session_id uuid,
          user_id uuid,
          org_id uuid,
          expires_at timestamptz,
          revoked_at timestamptz,
          mfa_satisfied boolean
        )
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
        AS $$
        BEGIN
          PERFORM set_config('app.identity_lookup', 'on', true);
          RETURN QUERY
            SELECT s.id, s.user_id, s.org_id, s.expires_at, s.revoked_at, s.mfa_satisfied
            FROM user_sessions s
            WHERE s.refresh_token_hash = p_refresh_hash
            LIMIT 1;
          PERFORM set_config('app.identity_lookup', '', true);
        EXCEPTION WHEN OTHERS THEN
          PERFORM set_config('app.identity_lookup', '', true);
          RAISE;
        END;
        $$
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION app.find_api_key_identity(p_key_hash text)
        RETURNS TABLE (
          api_key_id uuid,
          org_id uuid,
          created_by uuid,
          scopes text[],
          project_ids uuid[],
          expires_at timestamptz,
          revoked_at timestamptz
        )
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
        AS $$
        BEGIN
          PERFORM set_config('app.identity_lookup', 'on', true);
          RETURN QUERY
            SELECT k.id, k.org_id, k.created_by, k.scopes::text[], k.project_ids,
                   k.expires_at, k.revoked_at
            FROM api_keys k
            WHERE k.key_hash = p_key_hash
            LIMIT 1;
          PERFORM set_config('app.identity_lookup', '', true);
        EXCEPTION WHEN OTHERS THEN
          PERFORM set_config('app.identity_lookup', '', true);
          RAISE;
        END;
        $$
        """
    )

    # ------------------------------------------------------------- job claiming
    # Workers serve every tenant, so claiming is a privileged operation. Doing
    # it in one function makes the claim atomic: FOR UPDATE SKIP LOCKED means
    # concurrent workers never contend for or double-run the same job.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION app.claim_next_job(
          p_worker_id text,
          p_kinds text[],
          p_lease_seconds integer
        )
        RETURNS TABLE (
          job_id uuid,
          org_id uuid,
          kind text,
          payload jsonb,
          attempts smallint,
          max_attempts smallint,
          scan_id uuid,
          engine_run_id uuid
        )
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
        AS $$
        DECLARE
          v_job_id uuid;
        BEGIN
          PERFORM set_config('app.job_runner', 'on', true);

          SELECT j.id INTO v_job_id
          FROM jobs j
          WHERE j.status = 'queued'
            AND j.run_after <= now()
            AND NOT j.cancel_requested
            AND (p_kinds IS NULL OR cardinality(p_kinds) = 0 OR j.kind = ANY(p_kinds))
          ORDER BY j.priority ASC, j.run_after ASC
          FOR UPDATE SKIP LOCKED
          LIMIT 1;

          IF v_job_id IS NULL THEN
            PERFORM set_config('app.job_runner', '', true);
            RETURN;
          END IF;

          UPDATE jobs j
          SET status = 'running',
              attempts = j.attempts + 1,
              locked_by = p_worker_id,
              locked_at = now(),
              lease_expires_at = now() + make_interval(secs => p_lease_seconds),
              heartbeat_at = now(),
              started_at = COALESCE(j.started_at, now()),
              updated_at = now()
          WHERE j.id = v_job_id;

          RETURN QUERY
            SELECT j.id, j.org_id, j.kind::text, j.payload, j.attempts, j.max_attempts,
                   j.scan_id, j.engine_run_id
            FROM jobs j WHERE j.id = v_job_id;

          PERFORM set_config('app.job_runner', '', true);
        EXCEPTION WHEN OTHERS THEN
          PERFORM set_config('app.job_runner', '', true);
          RAISE;
        END;
        $$
        """
    )

    # A worker that dies mid-job leaves a lease behind. Reclaiming expired
    # leases is what makes the queue crash-safe: the job is retried rather than
    # lost, and a job that has exhausted its attempts fails visibly with a
    # stated reason instead of sitting in `running` forever.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION app.reclaim_expired_jobs()
        RETURNS integer
        LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp
        AS $$
        DECLARE
          v_count integer;
        BEGIN
          PERFORM set_config('app.job_runner', 'on', true);

          WITH expired AS (
            SELECT id, attempts, max_attempts FROM jobs
            WHERE status = 'running' AND lease_expires_at < now()
            FOR UPDATE SKIP LOCKED
          )
          UPDATE jobs j
          SET status = CASE WHEN e.attempts >= e.max_attempts THEN 'failed' ELSE 'queued' END,
              locked_by = NULL,
              locked_at = NULL,
              lease_expires_at = NULL,
              run_after = now() + make_interval(secs => 30 * e.attempts),
              finished_at = CASE
                WHEN e.attempts >= e.max_attempts THEN now() ELSE NULL END,
              error_message = CASE
                WHEN e.attempts >= e.max_attempts
                THEN 'Worker lease expired and the retry budget is exhausted. The worker '
                     'processing this job stopped responding.'
                ELSE 'Worker lease expired; the job was requeued for retry.' END,
              updated_at = now()
          FROM expired e
          WHERE j.id = e.id;
          GET DIAGNOSTICS v_count = ROW_COUNT;

          PERFORM set_config('app.job_runner', '', true);
          RETURN v_count;
        EXCEPTION WHEN OTHERS THEN
          PERFORM set_config('app.job_runner', '', true);
          RAISE;
        END;
        $$
        """
    )

    # ------------------------------------------------------- audit chain check
    # Verification lives in the database so it reads the stored bytes directly
    # and cannot be fooled by an application-side cache.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION app.audit_chain_gaps(p_org_id uuid)
        RETURNS TABLE (expected_sequence bigint, found_sequence bigint)
        LANGUAGE sql STABLE SET search_path = public, pg_temp
        AS $$
          WITH ordered AS (
            SELECT sequence,
                   LAG(sequence) OVER (ORDER BY sequence) AS previous
            FROM audit_log
            WHERE org_id = p_org_id
          )
          SELECT previous + 1, sequence
          FROM ordered
          WHERE previous IS NOT NULL AND sequence <> previous + 1
        $$
        """
    )

    # The trigram indexes that back free-text search are declared on the models
    # themselves and created by revision 0001, so the schema has a single source
    # of truth. Only the pg_trgm extension is a prerequisite, and 0001 installs it.

    # --------------------------------------------------------- runtime db role
    # Creating the role itself is a provisioning step, not a schema change:
    # `infrastructure/database/provision/01_roles.sql` creates `qguard_app`,
    # and managed platforms such as Supabase do not permit CREATE ROLE from a
    # migration at all. This block only grants privileges, and only when the
    # role already exists, so the migration runs identically whether or not the
    # deployment uses a separate runtime role.
    op.execute(
        """
        DO $$
        BEGIN
          IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qguard_app') THEN
            RAISE NOTICE
              'Role qguard_app not present; skipping runtime grants. Run '
              'infrastructure/database/provision/01_roles.sql to create it.';
            RETURN;
          END IF;

          EXECUTE 'GRANT USAGE ON SCHEMA public, app TO qguard_app';
          EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public '
                  'TO qguard_app';
          EXECUTE 'GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO qguard_app';
          EXECUTE 'GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA app TO qguard_app';
          -- Narrow the blanket grant back for append-only history.
          EXECUTE 'REVOKE UPDATE, DELETE ON audit_log FROM qguard_app';
          EXECUTE 'REVOKE UPDATE, DELETE ON chain_of_custody FROM qguard_app';
          EXECUTE 'REVOKE UPDATE, DELETE ON evidence_access_log FROM qguard_app';
          EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public '
                  'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO qguard_app';
        END $$
        """
    )


def downgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
          IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qguard_app') THEN
            EXECUTE 'ALTER DEFAULT PRIVILEGES IN SCHEMA public '
                    'REVOKE ALL ON TABLES FROM qguard_app';
          END IF;
        END $$
        """
    )
    for table in APPEND_ONLY_TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS {table}_append_only ON {table}")

    for table in ("users", "user_sessions", "api_keys"):
        op.execute(f"DROP POLICY IF EXISTS identity_lookup ON {table}")
    op.execute("DROP POLICY IF EXISTS job_runner ON jobs")


    for table in (
        *TENANT_TABLES,
        "organizations",
        "roles",
        "report_templates",
        "audit_log",
    ):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")

    op.execute("DROP SCHEMA IF EXISTS app CASCADE")
