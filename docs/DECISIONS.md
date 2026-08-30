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

Production authentication is Supabase Auth. The browser signs in one of four
ways — Microsoft (Entra ID), email and password, a magic link, or a password
reset — and sends the resulting JWT to this API, which only ever *verifies* it
(`app/core/security.py`). The API cannot tell the routes apart and does not need
to: it checks the signature and reads the user id.

Microsoft is offered first because this is an Azure-first product; the account
someone signs in with is usually the same directory account that later grants
admin consent. That sign-in grants CloudGuard no access to Azure *resources* —
scanning access is the separate consent flow in `AZURE_INTEGRATION.md`.

Passwords are Supabase's to hold. One typed into `SignInPage` is posted directly
to Supabase's auth API over TLS; it never reaches this API, is never logged
here, and there is no column for it in this schema. What remains true without
qualification is that CloudGuard has no token-minting code — the test suite
signs its own tokens rather than the product shipping a code path that hands out
credentials. See #13 for why the earlier development-only variant was deleted
rather than gated.

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


## 14. Resource Graph reads inventory; ARM reads everything a rule judges

**Spec:** `AZURE_INTEGRATION.md` collected inventory with the ARM resource
listing, one paged call per subscription.

Inventory is the one collection task that asks for every provider's resources
at once, and it is the one that scales worst as a tenant grows. Azure Resource
Graph answers it in a single KQL query per subscription, and — the part that
decides it — states `totalRecords` for the query, so a short read is caught by
comparing two numbers the service supplied. ARM paging could only ever infer
completeness from whether the page cap was reached, which is a guess about the
tail of a list nobody saw.

The split is deliberate and narrow:

* **Resource Graph collects inventory only.** Its rows are a projection of
  ARM's own state and can be minutes stale — fine for "what exists here",
  wrong for the configuration a rule passes or fails on. Every listing a rule
  reads stays on ARM, where the snapshot keeps the provider's JSON verbatim
  (§3), so replay is unaffected.
* **`ResourceGraphClient` is a separate class,** not more methods on
  `ArmClient`. Same host and same retry behaviour; different paging
  (`$skipToken` rather than `nextLink`), different quota (per principal rather
  than per subscription), different error surface. One class would put two
  paging models behind one name and leave a reader unable to tell which one a
  call is subject to.
* **The projection excludes `properties`.** Inventory answers what exists;
  carrying configuration here would hold a second, staler copy of data no rule
  reads in every snapshot.

**Cost:** the custom role gains `Microsoft.ResourceGraph/resources/read` and
`ROLE_VERSION` moves to `v2`. The action string was verified against the
published RBAC operations reference on 2026-08-30 — it is real, and described
as "Submits a query on resources within specified subscriptions, management
groups or tenant scope", so the template deploys. Whether Resource Graph
actually *checks* it is not established: the service documents its requirement
as read access to the resources being queried, and its only documented 403 is a
subscription list the caller cannot read. Granting it is the cheaper side of
that uncertainty, and the connection probe (§14, validation) will settle it —
a `v1` connection whose Resource Graph probe succeeds proves the action
redundant, and the role can then be narrowed. Connections deployed on `v1` lose inventory —
and only inventory — until the customer redeploys, which the role-drift
machinery already tells them to do. Falling back to the ARM listing when the
query is denied would hide that, and leave the customer on a role that will not
serve the next thing built on Resource Graph either.

## 15. Concurrency is capped over requests, not over tasks

**Spec:** none. The plan capped fan-out per task (`DETAIL_CONCURRENCY`) and the
executor ran a whole wave at once.

Those two limits multiply, and nothing owned the product. A wave of nine tasks
with eight detail calls apiece is seventy-odd requests against one
subscription, and the number moves every time a task joins the plan. Azure
answers that with 429s, which the retry path turns into wall-clock time and,
past the retry budget, into recorded gaps: a scan that collects *less* because
it asked for more at once.

`RequestLimiter` caps what Azure actually meters. One limiter per scan is
shared by every client the plan builds, a permit covers a single HTTP attempt,
and it is released before any `Retry-After` sleep — a throttled call must not
hold a slot while it is deliberately not using the network. The per-task limits
stay as fairness between tasks inside a wave; this is the protection for the
subscription.

It also makes the cost visible: `azure.collection_finished` now carries the
request count, the peak in flight and the time spent queued behind the ceiling,
because a scan that never waits and one that waits a minute are otherwise
indistinguishable — and only the second is evidence the number wants changing.

## 16. A scan's collection plan is derived; carrying evidence forward is opt-in per key

**Spec:** `ARCHITECTURE_REVIEW.md` §7 and §12 item 10 — "the evidence planner:
rule-set union minus fresh evidence".

Two halves, and only the first came out the way the review assumed.

**Derived, not written down.** What a scan collects is now the union of every
enabled rule's `requires_evidence` plus the connector's `baseline_evidence`,
and the provider's plan is filtered through it. Three Azure keys are named by
no rule — inventory, role assignments, role definitions — and they are the
reason the baseline exists rather than an oversight to be tidied away: the
first is what the customer's asset list is made of, and the other two are what
the graph's identity edges are built from. A rule-derived plan without a
declared baseline would have dropped all three while every check carried on
passing.

Today the union equals the plan exactly, so nothing is dropped and no request
is saved. What the derivation buys is that the equality is now checked: a
listing whose last reader was deleted fails a test instead of being collected
at the customer's expense for ever, and a rule added with a new dependency
starts being collected for.

**Reuse is off unless a key earns it.** Evidence has carried provenance and a
content hash since migration 0010, so a complete reading from an earlier scan
can stand in for a new one. Almost none of it should. The strongest claim this
product makes is "verified fixed", and it survives exactly as long as nothing
verifies a fix against evidence collected before the fix: a customer who
corrects a storage account and asks CloudGuard to check must be answered from
the storage account as it is now, or the word means nothing.

So `EvidenceKey.reuse_window` defaults to `None` — read it again — and a window
is granted per key, by the provider that produces it, only where a stale reading
cannot change a verdict. Being expensive to collect or slow to change are
reasons to *want* a window; they are not reasons one is safe. Exactly one Azure
key qualifies today: `role_definitions`, the catalogue of what each role
permits, several hundred near-static rows per subscription that no rule reads.
Role assignments are deliberately excluded on the same reasoning inverted —
they change constantly and every privilege path is drawn from them. A test
fails the build if any key some rule reads is ever given a window.

A carried reading is recorded COMPLETE, because that is what it was: age is not
incompleteness, and degrading it to PARTIAL would tell every rule reading it to
return UNKNOWN. Its evidence row keeps the *original* `collected_at`, so the
next scan's freshness question is asked about the read rather than about the
last scan that reused it — otherwise one reading renews itself for ever.

## 17. Asset context is its own module, and a customer declaration is a floor

**Spec:** `ARCHITECTURE_REVIEW.md` §12 item 11 — "a context engine as its own
module, out of the normalizer, with every fact carrying source and confidence.
Add customer-declared context."

Context — how critical an asset is, how sensitive its data, which environment it
belongs to — is the multiplier that turns a finding into a risk. It lived in
three helper functions inside the Azure normalizer, which was wrong in two ways.
None of it is Azure-specific, so a second connector would have written its own
slightly different copy of the tag vocabulary and the production/development
word lists. And there was nowhere for the customer to disagree: normalization is
a pure function of a capture, and a declaration is not in the capture.

`app/context/` now holds inference and resolution separately. `infer()` stays
pure and runs in the normalizer's path; `resolve()` applies declarations in the
pipeline, where the database is — read at *evaluation* time rather than frozen
into the capture, so marking a subscription production changes how its findings
rank today, including on a replay of an older reading.

**Every value carries its source.** `ContextSource` runs NONE → INFERRED →
TYPE_FLOOR → PROVIDER_TAG → INHERITED → CUSTOMER, and confidence is a property
*of* the source rather than a column beside it, so the two cannot drift apart —
there is no reading of "a naming guess, confidence 0.95" worth being able to
express. `GET /assets/{id}` returns the pair, because the value alone cannot be
argued with: "CRITICAL" invites the question "says who", and the answer used to
exist nowhere.

**A declaration is a floor, not an override.** "This subscription is production"
is a statement about everything in it, so nothing inside it scores below what
was declared — but an asset carrying its own `criticality=critical` tag is the
more specific of the two facts, and lowering it to the subscription's level
would discard the better one. So the higher value wins and the declaration wins
ties. The consequence is the property that makes this safe to hand a customer:
nothing declared can make an asset look *safer* than the capture already showed,
so the worst a mistaken declaration does is over-rank something.

Environment is the exception to the floor, because a name has no maximum: a
person naming it beats a substring match on a resource name every time. That is
the case the feature exists for — the customer whose production runs in a
subscription called `sandbox-eu`.

**Declarations are a table, not columns on `cloud_accounts`.** A discovered
subscription records what Azure said and discovery runs again; a declaration
records what a person said, and mixing the two into one row would make them
untellable apart. The table also carries who declared it and why, because "who
says this is production" is a question people ask of the label rather than of
the audit log. The worker's RLS arm grants SELECT only: a background job that
could write a declaration would be CloudGuard putting words in the customer's
mouth.

**Not done, deliberately.** Per-resource declarations are the obvious next ask
and are a later migration rather than a nullable column nothing writes. And a
declaration does not rescore stored findings on the spot — a risk score is what
a scan concluded, and rewriting one from an API call would leave findings
carrying numbers no observation ever produced.

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

**Compliance mappings drive a coverage view, still without framework logic.**
Every rule carries CIS Azure 2.0, ISO 27001, GDPR and NIST CSF control
references in `rules.compliance_mappings`. `app/compliance/catalog.py` supplies
the other half — what those identifiers mean — as data, and
`app/services/compliance.py` joins the two against the latest scan. Requirement
15 still holds: no rule imports the catalogue, and nothing anywhere branches on
a framework name.

Three choices there are worth keeping:

* **Control titles are CloudGuard's own wording.** CIS Benchmarks and ISO/IEC
  27001 are copyrighted under licences restricting redistribution of their text.
  The identifiers are reproduced; the prose is not. Every framework carries a
  link to its authoritative source.
* **The catalogue lists controls no rule covers.** A catalogue of only what
  CloudGuard checks would report full coverage forever. A test asserts each
  framework has at least one uncovered control, and another asserts every
  control a rule references actually exists — a typo in a mapping would
  otherwise produce evidence that silently goes nowhere.
* **Coverage counts conclusions, not passes.** `coverage_ratio` is the share of
  controls CloudGuard reached a verdict on. UNKNOWN resolves to INCONCLUSIVE and
  is excluded — the same reason UNKNOWN is never PASS in the rule engine, except
  that here the misreading would end up in front of an auditor.

**A connection is a tenant or management group; subscriptions are discovered.**
`cloud_accounts` used to *be* the connection — one row per subscription, tenant
id typed in by hand. That had two problems.

The first was a blind spot. A subscription created after onboarding was invisible
to CloudGuard, because nobody had registered it. An environment that is never
scanned produces no findings, and no findings reads as safe. Everywhere else this
product refuses that trade — UNKNOWN is never PASS, gaps are recorded rather than
dropped — and the connection layer quietly violated it.

The second was a tenant-binding hole. `cloud_accounts.tenant_id` came from the
request body, and validation only checked whether Azure answered. But CloudGuard's
service principal exists in *every* tenant that has ever consented, so naming one
of those tenants on a fresh connection and clicking verify succeeded — the probe
passes, because the access is genuinely there — and the caller was reading an
environment belonging to somebody else. This is the confused-deputy problem AWS
integrations use an ExternalId for.

Both are fixed by the same change. `cloud_connections.tenant_id` is nullable and
written in exactly one place: the consent callback, from the tenant Entra itself
reports. Validation refuses any connection whose own consent has not completed.
A per-connection nonce additionally rides in the deployment artifact and is read
back from the role assignment's description — defence in depth, not the primary
control, since it is consent that binds the tenant.

`scope_type` keeps the narrow option first-class: `SUBSCRIPTION` behaves exactly
as the old model did. The coverage-versus-least-privilege trade is the customer's
to make, and a tenant-wide grant is genuinely broader than they may want.

Everything below a cloud account — scans, resources, findings, risk, compliance —
is untouched by this. Discovered subscriptions are still `cloud_accounts` rows,
so the pipeline never learned that anything changed.

**Supabase connections go through the Session pooler, not the direct host.**
Current Supabase projects resolve `db.<ref>.supabase.co` to an IPv6-only
address, and Railway cannot route IPv6 -- the connection fails with `Network is
unreachable` before it leaves the container. The Session pooler
(`aws-0-<region>.pooler.supabase.com`, port 5432) is IPv4 and behaves like a
normal PostgreSQL connection, including the session-level `SET LOCAL ROLE` and
`request.jwt.claims` that RLS depends on. The Transaction pooler on port 6543
is not an option: it does not support prepared statements, which asyncpg
requires.

**Multi-subscription accounts.** `cloud_accounts` holds a single
`subscription_id`, matching `DATABASE.md` §2. The child-table alternative the
spec mentions is a migration away and no core logic assumes one subscription per
tenant.
