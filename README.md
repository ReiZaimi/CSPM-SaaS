# CloudGuard

Azure-first Cloud Security Posture Management. Prototype v0.1.

CloudGuard connects to a customer's Azure environment read-only, discovers what
is there, evaluates it against deterministic security rules, scores the results
as business risks rather than raw alerts, tells the user how to fix the ones
that matter — and then **verifies the fix itself** on the next scan.

The specification this is built from lives in [`docs/`](docs/); start with
[`docs/PRODUCT_SPEC.md`](docs/PRODUCT_SPEC.md).

---

## Running it

CloudGuard is cloud-only. There is no local development mode, no
`docker-compose.yml`, and no localhost defaults anywhere in the configuration —
the API refuses to start unless it has a complete deployment environment.

| Layer | Platform |
|---|---|
| PostgreSQL + Auth | Supabase |
| API + Celery worker + Redis | Railway |
| Frontend | Vercel |

Full walkthrough: **[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)**. Both Railway
and Vercel build directly from this repository and redeploy on every push to
`main`.

### Seeing the product loop before Azure is registered

Scanning a real environment needs an Entra app registration
([`docs/AZURE_INTEGRATION.md`](docs/AZURE_INTEGRATION.md) §2). Until then, the
demo seed runs the **real** pipeline — real normalizer, real rules, real risk
engine — against a recorded Azure snapshot. From the API service's shell on
Railway, with `APP_ENV=staging`:

```bash
python /srv/database/seed/demo_environment.py --email you@example.com
```

Sign in first so Supabase has created your account; the demo organization
attaches to it. Then run it again with `--fix` to watch three findings
auto-resolve and the security score move. Nobody clicks "resolved" — that is
the point.

---

## Tests

Tests run in CI on every push ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)),
which provisions PostgreSQL and Redis as service containers. That is the
supported way to run them.

```
backend    183 tests   pytest, ruff, mypy
frontend    29 tests   vitest, tsc
```

Rule tests run against fixture JSON in `apps/api/tests/fixtures/` — no database,
no network, no Azure. There is deliberately no mock connector in the
application; test plumbing that replays recorded Azure responses lives only in
the test suite and the demo seed.

---

## Layout

```
apps/api/app/
├── core/          config, RLS-scoped sessions, auth, errors, enums
├── domain/        cloud-neutral resource model the rules operate on
├── connectors/    base contract + azure/ (auth, client, collector, normalizer)
├── rules/         base contract, registry, engine, azure/<category>/
├── risk/          scoring config and scorer
├── services/      scanner pipeline, findings, dashboard, cloud accounts
├── models/        SQLAlchemy tables
├── api/routes/    HTTP surface
└── workers/       Celery app and scan task

apps/web/src/      React + TypeScript + Tailwind
database/          migrations (with RLS policies) and the demo seed
infrastructure/    Dockerfile, Railway + Supabase + CI setup
docs/              the specification
```

---

## The parts worth understanding

**Tenant isolation is enforced twice, independently.** The API derives
`organization_id` from the authenticated user's membership and never from the
request. Separately, PostgreSQL enforces the same boundary through Row-Level
Security — and the API connects as `cloudguard_app`, a role that owns no tables
and therefore cannot bypass a policy. See
[`docs/DECISIONS.md`](docs/DECISIONS.md#1-rls-is-enforced-against-a-non-owner-role).

**UNKNOWN is never PASS.** A rule that could not read its data returns UNKNOWN.
That never becomes a finding — there is nothing to report — but it is recorded
in `scan_evaluation_gaps` and surfaced as a coverage figure. A storage API
timeout must never read as "no storage problems".

**Findings and risks are separate.** "RDP is open" is a fact about a config.
"An internet-reachable production jump box accepts RDP from anywhere" is a risk.
The same misconfiguration scores differently on a dev box than on a production
database, and the finding detail page shows the arithmetic.

**Remediation is verified by the scanner, not asserted by a human.** There is no
"mark as fixed" button anywhere in the product, and the API refuses to set a
finding to RESOLVED by hand.

**CloudGuard never handles a password or a customer credential.** Sign-in is a
Supabase magic link; the API only verifies the token. Azure access is a
multi-tenant Entra app plus admin consent, so there is no per-customer secret
to store or leak.
