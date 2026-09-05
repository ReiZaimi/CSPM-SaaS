# CloudGuard

Azure-first Cloud Security Posture Management. Prototype v0.1.

CloudGuard connects to a customer's cloud read-only, discovers what is there,
evaluates it against deterministic security rules, scores the results as
business risks rather than raw alerts, tells the user how to fix the ones that
matter — and then **verifies the fix itself** on the next scan.

The specification this is built from lives in [`docs/`](docs/); start with
[`docs/PRODUCT_SPEC.md`](docs/PRODUCT_SPEC.md).

### AWS is built and is not offered yet

An AWS connector, its permission manifest, its onboarding flow, change-triggered
scanning and thirty AWS rules exist behind the same seam Azure sits behind
([`docs/AWS_INTEGRATION.md`](docs/AWS_INTEGRATION.md)). **None of it has been
run against a live AWS account.** Every IAM action name, response shape and
CloudFormation string is written from AWS's published reference, so the wizard
shows AWS greyed out with the reason until the fifteen-item checklist in
`AWS_INTEGRATION.md` §1 has passed and `AWS_ENABLED=true` is set.

That is why the line above still says Azure-first. It will stop saying so when
somebody has scanned an AWS account with it, and not before.

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

### Seeing the product loop before a cloud is registered

Scanning a real environment needs an Entra app registration
([`docs/AZURE_INTEGRATION.md`](docs/AZURE_INTEGRATION.md) §2), or an AWS
principal ([`docs/AWS_INTEGRATION.md`](docs/AWS_INTEGRATION.md) §2). Until then,
the demo seed runs the **real** pipeline — real normalizer, real rules, real
risk engine — against a recorded snapshot. From the API service's shell on
Railway, with `APP_ENV=staging`:

```bash
python /srv/database/seed/demo_environment.py --email you@example.com
python /srv/database/seed/demo_environment.py --email you@example.com --provider aws
```

The AWS recording matters more than a demo usually would: it is the only way to
watch that half of the product work end to end, because none of it has been run
against a live account. It exercises the normalizer, thirty rules, the risk
engine and the findings lifecycle. What it cannot prove is whether the payloads
it replays are the payloads AWS actually sends — that is what §1's checklist is
for.

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
backend    1751 tests   pytest, ruff, mypy
frontend    354 tests   vitest, tsc
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
├── connectors/    base contract + azure/ (auth, client, collector, normalizer, rbac)
├── rules/         base contract, registry, engine, azure/<category>/
├── risk/          scoring config and scorer
├── compliance/    framework catalogue and per-control coverage
├── services/      scanner pipeline, findings, dashboard, cloud accounts
├── models/        SQLAlchemy tables
├── api/routes/    HTTP surface
└── workers/       Celery app, the scan step tasks, and the periodic sweeps

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

**A connection is a tenant, and subscriptions are discovered beneath it.** The
customer picks a scope and never types a GUID — not the tenant id, not a
subscription id. Entra reports which directory consented, and that report is the
only thing that ever writes `tenant_id`, which is what binds a connection to a
directory rather than to a claim. Subscriptions are then found by asking Azure,
so one created next month gets scanned instead of quietly missed.

**The read access grant is generated, not described.** After consent CloudGuard
knows its own service principal's object id in the customer's tenant, so it
hands them a Cloud Shell script, Bicep, or Terraform with every parameter
already filled in. Customers who want more than Azure's `Reader` can take the
CloudGuard custom role instead: exactly the read operations the collector
performs, no `*/action` entries at all, generated from the connector so a test
fails if the two ever disagree.

**A scan is durable steps, not one long task.** Planning, one collection per
subscription plus one for the tenant directory, then a single analysis — each
recorded, claimed under a lease, and retried on its own. A redeploy costs the
step in flight rather than the scan, one unreadable subscription does not take
the other forty-nine with it, and every write a running step makes is fenced on
the claim it was made under, so a worker that stalled past its lease cannot
settle a step another worker has taken over. See
[`docs/DECISIONS.md`](docs/DECISIONS.md).

**Compliance is evidence, never a verdict.** The `/compliance` view maps rules
to CIS Azure 2.0, ISO 27001, GDPR and NIST CSF controls — including the controls
nothing checks, so coverage cannot read 100% by omission. A control whose rules
returned UNKNOWN is *inconclusive*, not passing, and the headline figure counts
conclusions rather than passes. "78% GDPR compliant" is a sentence this product
must never produce. Each control also carries the provider readings its verdict
rests on — which listing, when it was taken, under what permission, whether the
bytes are still stored — for the controls that *passed* as much as the ones that
failed, and the whole assessment exports as CSV or JSON.

**CloudGuard's API never handles a password or a customer credential.** Sign-in
is Supabase Auth — Microsoft (Entra ID), email and password, or a magic link.
Whichever route someone takes, a password goes from their browser straight to
Supabase and the API only ever verifies the JWT that comes back. Azure access is
separately a multi-tenant Entra app plus admin consent, so there is no
per-customer cloud secret to store or leak.
