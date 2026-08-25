-- Run this ONCE against a fresh Supabase project before the Alembic
-- migrations, using the SQL Editor in the Supabase dashboard (or psql against
-- the direct connection string) as the `postgres` user.
--
-- Unlike local Docker (infrastructure/docker/postgres-init.sql), Supabase
-- already provides `authenticated`, `anon`, and `service_role` -- creating
-- them again would fail. The only thing this project needs that Supabase
-- doesn't already have is the API's own login role: cloudguard_app owns no
-- tables, so it is fully subject to the RLS policies the migrations create.
-- See docs/DECISIONS.md #1 for why that ownership split is the whole point.
--
-- CHANGE THE PASSWORD before running this. Whatever you set here goes into
-- Railway's DATABASE_URL as a secret, never committed to git.

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cloudguard_app') THEN
    CREATE ROLE cloudguard_app LOGIN PASSWORD 'CHANGE-ME-BEFORE-RUNNING' NOSUPERUSER NOCREATEDB NOCREATEROLE;
  END IF;
END $$;

GRANT authenticated TO cloudguard_app;
GRANT anon TO cloudguard_app;
GRANT CONNECT ON DATABASE postgres TO cloudguard_app;
