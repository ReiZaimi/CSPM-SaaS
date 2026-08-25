-- Runs once on first container start, as the postgres superuser.
--
-- Creates the RLS-CONSTRAINED role the API uses for request handling. This is
-- the whole point of ARCHITECTURE.md section 4 / SECURITY.md section 2: if the API
-- connected as the table owner, RLS would be silently bypassed (owners are
-- exempt unless FORCE ROW LEVEL SECURITY is set) and tenant isolation would
-- collapse back to "we remembered to write the WHERE clause".
--
-- On Supabase these roles already exist; this file is local-dev only.

CREATE ROLE authenticated NOLOGIN;
CREATE ROLE anon NOLOGIN;
CREATE ROLE service_role NOLOGIN BYPASSRLS;

-- The API's login role. It can SET ROLE authenticated but owns nothing.
CREATE ROLE cloudguard_app LOGIN PASSWORD 'cloudguard_app' NOSUPERUSER NOCREATEDB NOCREATEROLE;
GRANT authenticated TO cloudguard_app;
GRANT anon TO cloudguard_app;

GRANT CONNECT ON DATABASE cloudguard TO cloudguard_app;
