# CloudGuard — Implementation Decisions

Where the build made a choice the specification did not fully determine, or
deviated from it, the reasoning is recorded here. Companion to the spec, not a
replacement for it.

---

## 1. RLS is enforced against a non-owner role

**Spec:** "Tenant isolation enforced by PostgreSQL RLS, independent of app
logic" (requirement 4).

PostgreSQL exempts a table's owner from its own RLS policies unless
`FORCE ROW LEVEL SECURITY` is set. If the API connected as the owner — the
default for most FastAPI/SQLAlchemy setups — every policy in the schema would be
silently inert, and requirement 4 would be decorative.

So there are two database roles:

| Role | Used by | RLS |
|---|---|---|
| `cloudguard` (owner) | migrations, Celery worker | exempt |
| `cloudguard_app` | every API request | **enforced** |

Each request opens a transaction that sets `request.jwt.claims` and switches to
the `authenticated` role — precisely what Supabase's PostgREST does — so one set
of policies works unchanged against local PostgreSQL and a real Supabase
project. `app/core/db.py::rls_session`.

`FORCE ROW LEVEL SECURITY` is deliberately **not** set: the membership lookup
inside a policy runs through a `SECURITY DEFINER` function, and forcing RLS on
the owner would make that function re-enter the policy it is evaluating and
recurse. Not owning the tables is what makes the isolation real; forcing it is
not.

Two tests assert the premise itself rather than only its consequences:
`test_application_role_is_not_the_table_owner` and
`test_application_role_cannot_bypass_rls`.

## 2. Organization creation goes through a SECURITY DEFINER function

Creating an organization is a bootstrap problem: the creator is not yet a
member, so no membership-based INSERT policy can authorize it. Widening the
membership policy enough to allow it would also let any user insert themselves
into any organization.

`app.create_organization()` creates the organization and the creator's OWNER
membership in one transaction. The `organizations` table has no INSERT policy at
all, and `organization_members` accepts inserts only from an existing
OWNER/ADMIN. Covered by `test_cannot_add_self_to_another_organization`.

## 3. Azure is reached over REST with MSAL, not the `azure-mgmt-*` SDKs

**Spec:** "Azure SDK for Python" (`ARCHITECTURE.md` §1).

Requirement 9 says every scan stores a snapshot, and the value of that snapshot
is that it holds the provider's *own* JSON, so a scan can be re-evaluated later
against improved rules. Going through SDK model objects would mean deserializing
Azure's JSON into Python objects and then serializing it back out again — losing
fidelity for no gain. The management SDKs are also synchronous, which fits
poorly with an async collector.

Authentication still uses **MSAL**, Microsoft's own library, which is what
actually matters: the multi-tenant client-credentials flow against each
customer's tenant is not something to hand-roll. `httpx` makes the ARM and Graph
calls. `app/connectors/azure/client.py`.

## 4. Relationship edges are stored once, indexed both ways

`resource_relationships` stores an edge in its natural direction (an NSG
*protects* a VM). Both endpoints need to query it, though: AZ-NET-001 asks an
NSG what it is attached to, AZ-CMP-001 asks a VM what guards it. Rather than
writing each edge twice, `RuleContext` derives the reverse index at
construction. `get_related` / `get_related_inverse`.

## 5. UNKNOWN is distinguished from absent at the normalizer, not the rule

A rule can only report UNKNOWN honestly if the normalizer preserved the
difference between "we read this and it was empty" and "we never read this".
The normalizer therefore emits `None` where a call failed and `[]` where it
succeeded and found nothing — and omits `mfa_methods` entirely for users whose
authentication methods were never queried.

`test_unqueried_user_has_no_mfa_key_at_all` and
`test_empty_diagnostics_list_is_not_none` pin this down, because it is the kind
of distinction that erodes silently.

## 6. A rule that raises is UNKNOWN, never PASS

`RuleEngine._safe_evaluate` catches exceptions from rule code and converts them
to UNKNOWN. A crashing rule must degrade coverage, not report a clean
environment. This is the one broad `except` in the evaluation path and it is
load-bearing.

## 7. Asset context defaults to UNKNOWN, not LOW

The risk formula needs asset criticality, data sensitivity and exposure. Most
real environments are partially tagged. The normalizer infers what it can from
tags and naming conventions, then falls back to `UNKNOWN` — which the risk
engine scores at 3.5, just below HIGH.

Defaulting to LOW would quietly discount every untagged production asset, which
is exactly the population most likely to be untagged.

## 8. `Findings` are keyed on (organization, rule, resource)

A re-detection updates the existing row rather than inserting a new one, so
`first_detected_at` means what it says and a finding keeps its identity across
scans. A finding that was RESOLVED and is detected again is reopened rather than
duplicated — a regression is not a historical record.
`test_findings_are_not_duplicated_across_scans`,
`test_a_regression_reopens_a_resolved_finding`.

## 9. Enum columns are varchar with a coercing type decorator

Columns are `varchar` rather than native PostgreSQL enums so adding a value is a
code change rather than a migration that takes a lock. That alone would return
plain strings on read, making `FindingStatus.is_open` fail at runtime on exactly
the paths that matter. `StrEnumType` (`app/models/base.py`) stores the value and
returns the enum.

## 10. Rescanning a finding runs a full scan

`POST /findings/{id}/rescan` queues a complete scan rather than re-running the
single rule. Fixing one thing frequently changes another — closing a public port
may reroute traffic, disabling public network access may orphan a dependency —
and a narrow re-check could report a fix that a wider view would contradict.

## 11. Authentication is Supabase only

Production authentication is Supabase Auth: the browser completes a passwordless
magic-link sign-in and sends the resulting JWT to this API, which only ever
*verifies* it (`app/core/security.py`). CloudGuard never sees a password and has
no token-minting code — the test suite signs its own tokens rather than the
product shipping a code path that hands out credentials. See #13 for why the
earlier development-only variant was deleted rather than gated.

## 12. shadcn/ui components are hand-written

**Spec:** shadcn/ui (`ARCHITECTURE.md` §1).

shadcn/ui is a copy-in component collection installed via an interactive CLI,
not a dependency. The handful of primitives this prototype needs — badge, card,
button, field, empty state — are written directly in `src/components/ui.tsx` in
the same style (Tailwind + `clsx` + `tailwind-merge`). Running the CLI later to
add richer components remains possible.

## 13. Cloud-only: no local development mode

**Spec:** `ARCHITECTURE.md` §1 listed Docker Compose for local development.

CloudGuard now targets exactly one environment — Supabase, Railway, Vercel —
and cannot be run anywhere else. `docker-compose.yml` and `.env.example` are
gone, there are no localhost defaults in `Settings`, and the API validates its
entire environment at import and refuses to start if anything is missing.

Three things follow, and the third is the point:

* **The dev sign-in route is deleted**, not disabled. It minted a valid token
  for any email address with no password. Gating it behind an environment check
  meant one wrong variable turned it back on in a deployment — as nearly
  happened when Railway's "suggested variables" pre-filled `APP_ENV=development`
  from `.env.example`. Code that cannot be reached by accident is code that is
  not there. `app/core/security.py` now only verifies tokens; the test suite
  signs its own.
* **`APP_ENV` defaults to `production`** and no longer accepts `development`.
  A forgotten variable fails closed rather than silently relaxing every check.
  `test` is the only exemption and exists for CI.
* **Database engines are built lazily.** Removing the localhost defaults meant
  `create_async_engine("")` ran at import and broke test collection. Importing a
  module should not open a connection pool anyway, so `get_app_engine()` /
  `get_owner_engine()` construct on first use.

The cost is real and worth stating: there is no way to run CloudGuard offline,
and the 45 integration tests need the PostgreSQL that CI provisions. The
tradeoff is that a whole class of "worked locally, insecure in production" bug
is now unrepresentable — which for a security product is the right side to
err on.

---

## Open items carried forward

**The security score floors at zero quickly.** The deductions in
`RISK_ENGINE.md` §3 are −20 per Critical-band finding, so five of them reach
zero. The demo environment scores 0/100 before remediation and 52/100 after.
This is the specified formula and it is honest, but it loses resolution at the
bad end: an organization with five Critical findings and one with fifty both
read 0. The spec anticipates tuning these values against real environments;
`app/risk/config.py` is where that happens, and no rule logic needs to change.

**Phase 9 (reports) is not built.** The immediate goal in the build instruction
ends at verified resolution, and PDF generation sits outside that loop.
`jinja2` is installed; WeasyPrint and the report routes are not.

**Compliance mappings are populated but unused.** Every rule carries CIS
Azure 2.0, ISO 27001 and NIST CSF control references in
`rules.compliance_mappings`, surfaced read-only on the finding detail page. No
business logic reads them, per requirement 15.

**Multi-subscription accounts.** `cloud_accounts` holds a single
`subscription_id`, matching `DATABASE.md` §2. The child-table alternative the
spec mentions is a migration away and no core logic assumes one subscription per
tenant.
