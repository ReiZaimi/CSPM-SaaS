# CloudGuard — Security Principles

CloudGuard is itself a security product — security is not a later feature. This doc is the cross-cutting reference; detail lives in `DATABASE.md` (RLS/schema), `AZURE_INTEGRATION.md` (credential handling), and `API.md` (auth flow).

---

## 1. Development Rules

| # | Principle |
|---|---|
| 1 | Do not over-engineer — prefer a working modular monolith |
| 2 | Security first — CloudGuard is itself a security product |
| 3 | Never expose secrets — no Azure credentials or Supabase service-role keys in React |
| 4 | Never trust the frontend — all authorization happens server-side and at the DB layer |
| 5 | Tenant isolation is mandatory — every tenant-owned query is tenant-scoped |
| 6 | Rules are deterministic — no LLM deciding security state |
| 7 | Every rule needs tests |
| 8 | Every finding needs evidence |
| 9 | Every important remediation should be verifiable through a subsequent scan |
| 10 | Build vertically — don't build infrastructure that isn't connected to a user workflow |

---

## 2. Tenant Isolation

Two independent layers, not one:

1. **Application layer** — `organization_id` is always derived server-side from the authenticated user's membership, never trusted from a client-supplied value.
2. **Database layer** — PostgreSQL RLS enforces the same boundary independently, resolving through `authenticated user → organization_members → organization_id → requested row`. See `DATABASE.md` §7.

**RLS only binds a role that is not the owner.** PostgreSQL exempts a table's
owner from its own row-level policies, so an application connecting as the owner
has RLS enabled, policies written, and no boundary at all — the second layer
looks present in every migration and enforces nothing. The database therefore has
three logins, and which one a process uses *is* the security control:

| Role | Used by | RLS |
|---|---|---|
| owner | Alembic migrations only (`DATABASE_OWNER_URL`) | exempt, deliberately |
| `cloudguard_app` | every API request (`DATABASE_URL`) | enforced |
| `cloudguard_worker` | the Celery worker (`DATABASE_WORKER_URL`) | enforced |

The worker connection is separate rather than shared because a scan writes on
behalf of one organization across many tables, which is exactly the code path
where an application-layer mistake would be invisible; running it constrained
moves that guarantee out of our code and into PostgreSQL.

**It is optional, and the fallback is the owner** — `scan_database_url` returns
`DATABASE_WORKER_URL or DATABASE_OWNER_URL`, so leaving it unset puts the whole
scan pipeline on the RLS-exempt connection and the pipeline's own
`organization_id` filters become the entire tenant boundary. Those filters are
correct; they are code rather than a mechanism, which is the distinction this
section exists to draw. `Settings.worker_is_constrained` reports which of the
two is in force, and the worker logs it on its first task.

`infrastructure/supabase/roles.sql` creates both. **CI checks that the file still
carries its placeholder password** — a real credential must never be committed
there.

Automated RLS tests must confirm Organization A can never read Organization B's rows — this is a required test category, not optional coverage (`tests/integration/test_rls.py`, `TESTING.md` §3).

---

## 3. Credential Handling

- Azure access is **read-only**, and this is checkable rather than asserted. Two
  separate grants, neither carrying a write (`app/connectors/azure/auth.py`):

  | Grant | What it reads |
  |---|---|
  | Microsoft Graph, application scopes | `Directory.Read.All`, `User.Read.All`, `RoleManagement.Read.Directory`, `UserAuthenticationMethod.Read.All`, `Policy.Read.All`, `Application.Read.All`, `Group.Read.All`, `IdentityRiskyUser.Read.All`, `AuditLog.Read.All` |
  | Azure RBAC | `Reader`, per subscription |

  All nine are read scopes and the RBAC role is `Reader`. There is no
  code path that writes to a customer tenant, which is why enabling change
  events hands the customer an `az eventgrid` command to run themselves rather
  than creating the subscription for them — CloudGuard could not create it.
- CloudGuard authenticates to customer tenants as itself (multi-tenant app + admin consent) — there is **no per-customer secret to store**. See `AZURE_INTEGRATION.md` §2.
- Supabase service-role/secret keys and Azure app credentials **never** reach the frontend. Only the Supabase publishable key is used client-side.
- Secrets live in environment variables server-side, never committed:

```
APP_ENV=                        -- test / staging / production
APP_URL=                        -- where a consent redirect lands the customer
API_URL=
LOG_LEVEL=
CORS_ORIGINS=                   -- comma-separated or JSON; both are accepted

SUPABASE_URL=
SUPABASE_PUBLISHABLE_KEY=       -- the only one of these the frontend ever sees
SUPABASE_SECRET_KEY=
SUPABASE_JWT_SECRET=            -- verifies every incoming token; a wrong value
JWT_AUDIENCE=                   -- lets anyone mint a token for any user

DATABASE_URL=                   -- cloudguard_app: RLS enforced. The API's login
DATABASE_OWNER_URL=             -- owner: migrations only, RLS-exempt
DATABASE_WORKER_URL=            -- cloudguard_worker. Optional; unset falls back
                                -- to DATABASE_OWNER_URL, which RLS does not bind
REDIS_URL=

AZURE_CLIENT_ID=                -- CloudGuard's own app identity, not a customer's
AZURE_CLIENT_SECRET=
AZURE_TENANT_ID=
AZURE_REDIRECT_URI=
AZURE_CONSENT_STATE_SECRET=     -- signs the consent state parameter, so a
                                -- callback cannot be replayed or forged

SNAPSHOT_RETENTION_DAYS=         -- default 30. The newest capture per scope is
EVIDENCE_RETENTION_DAYS=         -- kept regardless; default 90 for payloads

SENTRY_DSN=
```

`app/core/config.py` refuses to start rather than run degraded on any of these:
a missing JWT secret is not a warning, and a stale `APP_URL` strands a customer
mid-consent with no way back.

---

## 4. Accepted Risk / Exceptions

Users can mark a finding as an intentionally accepted risk rather than remediate it. Store `reason`, `approved_by`, `expires_at`, `status` (see `exceptions` table, `DATABASE.md`). **Accepted risks are never permanently hidden** — they remain auditable via `audit_logs`.

---

## 5. Product Trust Model

The customer is giving CloudGuard permission to inspect its infrastructure. The product must clearly communicate: what CloudGuard accesses, why, what it cannot access, how credentials are protected, how data is isolated, and who can access it. Trust is a product feature, not an afterthought — this shapes the onboarding copy in `AZURE_INTEGRATION.md` §3.
