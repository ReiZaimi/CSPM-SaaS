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

**On the web**, deployed from this GitHub repo (Supabase + Railway + Vercel):
see [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

**Locally**, requires Docker. Nothing else is installed on your machine.

```bash
cp .env.example .env
docker compose up -d
```

| Service | URL |
|---|---|
| Web | http://localhost:5173 |
| API | http://localhost:8000 |
| API docs | http://localhost:8000/docs |

Migrations run automatically when the API container starts.

### Seeing the product loop without an Azure tenant

Registering a multi-tenant Entra application is a prerequisite for scanning a
real environment. Until that exists, the demo seed runs the **real** pipeline —
real normalizer, real rules, real risk engine — against a recorded Azure
snapshot:

```bash
docker compose exec api python /srv/database/seed/demo_environment.py
```

Sign in at http://localhost:5173 as `founder@cloudguard.al`. You will see six
findings, scored and ranked.

Then replay the same environment with two of the problems repaired:

```bash
docker compose exec api python /srv/database/seed/demo_environment.py --fix
```

Three findings move to **Verified fixed**, stamped with the scan that proved it,
and the security score moves. Nobody clicked "resolved" — that is the point.

### Connecting a real Azure environment

Set CloudGuard's own Entra application identity in `.env`:

```
AZURE_CLIENT_ID=
AZURE_CLIENT_SECRET=
AZURE_TENANT_ID=
```

Then, in the app: **Connections** → add a subscription → **Open admin consent**
→ assign the Reader role in Azure → **Verify connection** → **Run scan**.

The customer never gives CloudGuard a password, client secret, or certificate.
CloudGuard authenticates as its own application against their directory, so
there is no credential of theirs to store or leak.

---

## Tests

```bash
docker compose exec api pytest -q          # 156 tests
docker compose exec api ruff check .
docker compose exec api mypy app
docker compose exec web npm test           # 20 tests
docker compose exec web npm run typecheck
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
