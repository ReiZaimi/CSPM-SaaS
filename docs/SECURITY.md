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
2. **Database layer** — PostgreSQL RLS enforces the same boundary independently, resolving through `authenticated user → organization_members → organization_id → requested row`. See `DATABASE.md` §6.

Automated RLS tests must confirm Organization A can never read Organization B's rows — this is a required test category, not optional coverage (`TESTING.md`).

---

## 3. Credential Handling

- Azure access is **read-only** for the MVP. No write permissions are ever requested.
- CloudGuard authenticates to customer tenants as itself (multi-tenant app + admin consent) — there is **no per-customer secret to store**. See `AZURE_INTEGRATION.md` §2.
- Supabase service-role/secret keys and Azure app credentials **never** reach the frontend. Only the Supabase publishable key is used client-side.
- Secrets live in environment variables server-side, never committed:

```
APP_ENV=
APP_URL=

SUPABASE_URL=
SUPABASE_PUBLISHABLE_KEY=
SUPABASE_SECRET_KEY=

DATABASE_URL=
REDIS_URL=

AZURE_CLIENT_ID=       -- CloudGuard's own app identity, not a customer's
AZURE_CLIENT_SECRET=
AZURE_TENANT_ID=

SENTRY_DSN=
```

---

## 4. Accepted Risk / Exceptions

Users can mark a finding as an intentionally accepted risk rather than remediate it. Store `reason`, `approved_by`, `expires_at`, `status` (see `exceptions` table, `DATABASE.md`). **Accepted risks are never permanently hidden** — they remain auditable via `audit_logs`.

---

## 5. Product Trust Model

The customer is giving CloudGuard permission to inspect its infrastructure. The product must clearly communicate: what CloudGuard accesses, why, what it cannot access, how credentials are protected, how data is isolated, and who can access it. Trust is a product feature, not an afterthought — this shapes the onboarding copy in `AZURE_INTEGRATION.md` §3.
