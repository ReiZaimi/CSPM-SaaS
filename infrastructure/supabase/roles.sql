-- Run this ONCE against a fresh Supabase project before the Alembic
-- migrations, using the SQL Editor in the Supabase dashboard (or psql against
-- the direct connection string) as the `postgres` user.
--
-- Unlike local Docker (infrastructure/docker/postgres-init.sql), Supabase
-- already provides `authenticated`, `anon`, and `service_role` -- creating
-- them again would fail. What this project needs that Supabase doesn't already
-- have is two login roles of its own, and neither owns any table, so both are
-- fully subject to the RLS policies the migrations create.
-- See docs/DECISIONS.md #1 for why that ownership split is the whole point.
--
--   cloudguard_app     every API request. Resolves tenancy through the
--                      signed-in user's membership.
--   cloudguard_worker  the Celery worker's scan work. Has no signed-in user,
--                      so it declares the organization it is acting for and
--                      migration 0012's policy arm holds it to that. Optional:
--                      leave DATABASE_WORKER_URL unset and the worker keeps
--                      using the owner connection, which is what it did before
--                      and which RLS does not constrain at all.
--
-- CHANGE BOTH PASSWORDS when you paste this into the Supabase SQL Editor --
-- in the editor, NOT in this file. Whatever you choose becomes a live database
-- credential and belongs only in Railway's DATABASE_URL and
-- DATABASE_WORKER_URL, never in git.
--
-- CI fails the build if the placeholder below has been edited, precisely
-- because saving a real password here is an easy and expensive mistake.

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cloudguard_app') THEN
    CREATE ROLE cloudguard_app LOGIN PASSWORD 'CHANGE-ME-BEFORE-RUNNING' NOSUPERUSER NOCREATEDB NOCREATEROLE;
  END IF;
END $$;

GRANT authenticated TO cloudguard_app;
GRANT anon TO cloudguard_app;
GRANT CONNECT ON DATABASE postgres TO cloudguard_app;

-- Migration 0012 creates this role NOLOGIN, because its policies need it to
-- exist and nothing else about it should be decided by a migration. This is
-- where it becomes usable. Deliberately NOT granted `authenticated`: the two
-- roles resolve tenancy differently on purpose, and the worker must not
-- inherit the membership-based arm.
DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cloudguard_worker') THEN
    CREATE ROLE cloudguard_worker LOGIN PASSWORD 'CHANGE-ME-BEFORE-RUNNING' NOSUPERUSER NOCREATEDB NOCREATEROLE;
  ELSE
    ALTER ROLE cloudguard_worker LOGIN PASSWORD 'CHANGE-ME-BEFORE-RUNNING';
  END IF;
END $$;

GRANT CONNECT ON DATABASE postgres TO cloudguard_worker;
