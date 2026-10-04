-- ===========================================================================
-- QGuard Sentinel — database role provisioning
--
-- Run ONCE per database, as a superuser or a role with CREATEROLE, BEFORE the
-- first `alembic upgrade head`. This is deliberately separate from the
-- migrations: creating roles is a privileged provisioning action, migrations
-- only change schema, and managed platforms (Supabase, RDS) restrict role
-- creation.
--
--   psql "$ADMIN_DATABASE_URL" -v app_password="$(openssl rand -base64 32)" \
--        -f infrastructure/database/provision/01_roles.sql
--
-- Two roles, by design:
--
--   qguard_migrator  owns the schema. Used ONLY by Alembic. Can create and
--                    alter tables, policies and triggers.
--   qguard_app       the runtime role used by the API and the workers. Not the
--                    owner, so it cannot drop an RLS policy, disable an
--                    append-only trigger or alter the schema — a compromised
--                    application process cannot dismantle its own controls.
--
-- `qguard_app` is explicitly NOBYPASSRLS. Row level security is not advisory
-- for the runtime: without a tenant context set, its queries return no rows.
-- ===========================================================================

\set ON_ERROR_STOP on

-- --------------------------------------------------------------- extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid() for primary keys
CREATE EXTENSION IF NOT EXISTS pg_trgm;    -- trigram indexes for text search

-- --------------------------------------------------------------- app role
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qguard_app') THEN
    CREATE ROLE qguard_app LOGIN NOBYPASSRLS NOCREATEDB NOCREATEROLE NOSUPERUSER;
    RAISE NOTICE 'Created role qguard_app. Set its password below.';
  ELSE
    RAISE NOTICE 'Role qguard_app already exists; leaving it as it is.';
  END IF;
END $$;

-- Set the runtime password from the -v app_password argument. Passing it as a
-- psql variable keeps the secret out of this committed file.
\if :{?app_password}
  ALTER ROLE qguard_app PASSWORD :'app_password';
  SELECT 'qguard_app password set.' AS status;
\else
  SELECT 'No app_password supplied; set it manually before deploying.' AS status;
\endif

-- --------------------------------------------------------------- migrator role
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'qguard_migrator') THEN
    CREATE ROLE qguard_migrator LOGIN NOBYPASSRLS NOCREATEROLE NOSUPERUSER;
    RAISE NOTICE 'Created role qguard_migrator.';
  END IF;
END $$;

\if :{?migrator_password}
  ALTER ROLE qguard_migrator PASSWORD :'migrator_password';
\endif

-- The migrator owns the schema; the app role only uses it.
GRANT ALL ON SCHEMA public TO qguard_migrator;
GRANT USAGE ON SCHEMA public TO qguard_app;

-- Statement timeouts, so one pathological analytics query cannot pin a
-- connection indefinitely. Migrations get a longer budget because an index
-- build on a large findings table legitimately takes minutes.
ALTER ROLE qguard_app SET statement_timeout = '30s';
ALTER ROLE qguard_app SET idle_in_transaction_session_timeout = '60s';
ALTER ROLE qguard_app SET lock_timeout = '10s';
ALTER ROLE qguard_migrator SET statement_timeout = '30min';
ALTER ROLE qguard_migrator SET lock_timeout = '30s';

SELECT rolname,
       rolcanlogin  AS can_login,
       rolbypassrls AS bypasses_rls,
       rolsuper     AS is_superuser
FROM pg_roles
WHERE rolname IN ('qguard_app', 'qguard_migrator')
ORDER BY rolname;
