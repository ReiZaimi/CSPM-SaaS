-- CI only. Not used by any deployment.
--
-- The integration tests prove that PostgreSQL itself blocks cross-tenant
-- access, which only means something if the tests connect the way the API
-- does: as `cloudguard_app`, a role that owns no tables and therefore cannot
-- bypass a policy. Running them as the owner would pass while proving nothing
-- (see docs/DECISIONS.md #1).
--
-- GitHub Actions starts a bare postgres service container, so the Supabase
-- roles have to be created here. On Supabase itself they already exist --
-- infrastructure/supabase/roles.sql is the deployment-side equivalent and
-- creates only `cloudguard_app`.

CREATE ROLE authenticated NOLOGIN;
CREATE ROLE anon NOLOGIN;
CREATE ROLE service_role NOLOGIN BYPASSRLS;

CREATE ROLE cloudguard_app LOGIN PASSWORD 'cloudguard_app' NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT authenticated TO cloudguard_app;
GRANT anon TO cloudguard_app;

GRANT CONNECT ON DATABASE cloudguard TO cloudguard_app;

-- The worker's role. Migration 0012 creates it NOLOGIN so its policies have
-- something to name; giving it a password is the operator's decision, and in
-- CI the operator is this file. Without it the integration tests would prove
-- the worker's isolation against the owner connection, which bypasses RLS and
-- would therefore pass while proving nothing -- the same trap the comment
-- above describes for cloudguard_app.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cloudguard_worker') THEN
    CREATE ROLE cloudguard_worker LOGIN PASSWORD 'cloudguard_worker'
      NOSUPERUSER NOCREATEDB NOCREATEROLE;
  ELSE
    ALTER ROLE cloudguard_worker LOGIN PASSWORD 'cloudguard_worker';
  END IF;
END $$;

GRANT CONNECT ON DATABASE cloudguard TO cloudguard_worker;
