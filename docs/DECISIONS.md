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

**Spec:** the original build spec named "Azure SDK for Python" in
`ARCHITECTURE.md` §1. That table now records the REST decision instead, so this
entry is the reason it changed rather than a live disagreement.

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

## 12. shadcn/ui components are hand-written — **superseded by §24**

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

## 18. A claimed fix is verified on a backoff, and not-verified has three answers

**Spec:** `ARCHITECTURE_REVIEW.md` §12 item 12 — "a verification engine:
expected-state records, targeted plans, backoff for eventual consistency, and
`INSUFFICIENT_EVIDENCE` as an outcome distinct from `STILL_FAILING`".

Marking a task done recorded a timestamp and told the customer to run a scan.
If they did, and if that scan happened to produce a PASS on the same rule and
asset, the finding resolved. Every part of that is a coincidence: nothing
recorded what CloudGuard was expecting to see, nothing looked again on its own,
and every way of *not* being verified came out as the same silence — the finding
stayed open and the customer was told nothing.

`remediation_verifications` holds the expectation, written when the claim is
made: this rule, on this asset, should now PASS. Every scan that reaches a
verdict on that pair settles it or spends one attempt — every scan, not only one
started to verify something, because a nightly scan that passes the rule a
customer fixed this morning has answered their question and making them wait for
a scan with the right label on it would be ceremony.

**The backoff is about the cloud, not about load.** Azure applies a change to
its control plane before every read path agrees about it, so a check run a
minute after the work reads the old state and is right to — the environment
genuinely still said that when it was asked. Four attempts over roughly five
hours (5m, 15m, 1h, 4h), then an answer. It stops rather than retrying
indefinitely because an answer is the product: a verification that never settles
is the same silence this table was built to remove, dressed up as diligence.

**Three outcomes, because "not verified" is three different pieces of news.**
STILL_FAILING is CloudGuard looking and disagreeing. INSUFFICIENT_EVIDENCE is
CloudGuard failing to look — its own problem to explain, not the customer's to
fix. That is exactly the FAIL/UNKNOWN line the rule algebra already draws,
carried up to the one screen where somebody is told whether their work counted.
Telling a customer who has done the work that their fix failed, when the
evidence never arrived, is the same overclaim as a PASS nobody earned, pointed
at the person instead of the environment. A verification that once saw a
definite FAIL settles as STILL_FAILING even if later attempts went blind: having
seen the check fail is the stronger and truer statement.

**A scan settles only what it read.** Spending an attempt on a subscription the
scan never opened would burn the customer's answer on a reading that never
looked at their fix. A pending verification the scan reached no verdict on
*does* count as an attempt, recorded as UNKNOWN — the scan covered the scope and
said nothing about that asset, usually because the asset is no longer there, and
without that a verification whose asset vanished would stay pending for ever
with the scheduler starting scans to settle it.

**Not done:** targeted collection. A verification scan could collect only the
evidence its rule needs — the planner (§16) is the seam for it — but a scan
narrowed that way must also evaluate only what it collected fresh, or it would
re-assert stale verdicts about every rule it did not look at. That is a rule
about what a narrowed scan may conclude, not a planning decision, and it is the
next thing here rather than part of this.

## 19. Privilege escalation is read from role definitions, never from role names

**Spec:** `ARCHITECTURE_REVIEW.md` §12 item 15 — the second correlation
template, which "needs edges the graph does not yet have".

The edge is `CAN_GRANT_ROLES`, drawn beside `GRANTS_ROLE` rather than instead of
it: they are different claims about the same pair of nodes, one saying what a
principal may do today and the other that the ceiling is whatever it decides to
give itself.

Whether to draw it is decided by the role *definition*, and that is the entire
difficulty of this feature. **Owner and Contributor both carry
`actions: ["*"]`.** The only thing separating them is that Contributor excludes
`Microsoft.Authorization/*/Write` in its `notActions`. A check that matched role
names, or that read `actions` without honouring the exclusions, would report
every Contributor assignment in existence as a privilege escalation path — one
false alarm per subscription, on the feature whose whole value is that it finds
the thing no rule can. Reading the definition also catches what a name list
never could: a tenant's own custom role granting exactly that one action, which
is precisely the case worth finding.

Matching is segment-wise and case-insensitive, because ARM patterns are
(`Microsoft.Authorization/*`, `*/read`) and Azure's own definitions mix `/Write`
and `/write` freely.

**A chain ends at the scope, not at the identity.** The scope is the size of the
answer — naming the subscription an identity could take over is what turns an
alarm into something someone can act on. And a chain requires an entry point: a
directory administrator who can hand out roles is over-privileged, not a chain,
and reporting one would invent the half of the story that makes it urgent.

**Unmonitored critical assets stay unbuilt, with a reason.** The third template
the review lists is one finding (missing diagnostic settings) on one asset whose
criticality the finding formula already multiplies by. A scenario for it would
be a second opinion on a single finding rather than several findings seen as one
thing — the same double-count §16 avoids by keeping scenario risks out of the
security score. It earns a template when it spans several assets; as one rule on
one asset, the risk score already says it.

The fixture changed with this: `snapshot_mixed.json` described a role called
Contributor carrying Owner's permissions, which was never a real Azure role. It
now carries the real exclusions, so the fixture proves the distinction rather
than sidestepping it.

## 20. History is a feed of transitions, never a log of having looked

**Spec:** `ARCHITECTURE_REVIEW.md` §2.10 and §12 item 18 — the temporal model.

Three tables, and one rule that shapes all of them: a scan that finds nothing
different writes nothing. The alternative -- a row per scan per asset -- is
easier to write and produces a feed whose signal falls as the customer scans
more often, which is backwards.

**Asset changes are five things, not everything.** An asset appearing or
disappearing, and a change to exposure, sensitivity or criticality -- the three
values the risk engine multiplies a finding by. Diffing whole provider payloads
would be a change feed nobody can read, and the drift that matters is already a
finding.

**Disappearance is a transition, so it needed a column.**
`cloud_resources.absent_since` is set when a scan that covered an asset's scope
does not find it, and cleared when it returns. Derived from `last_seen_at`
instead, an absence would need a scan cadence nobody records, and would
re-report itself on every scan for ever. The row is never deleted: a finding
about the asset is still history worth keeping, and something that vanishes for
a week and comes back is one asset with two events rather than two assets.

**A finding's timeline sits beside the audit log, not instead of it.** They
answer different questions for different readers: the audit log is "what has
anybody in this organization done", for a security reviewer; the timeline is
"what happened to this finding", for whoever is looking at it. Only the second
can be complete, because only it holds the transitions a *scan* made, which no
person did -- and that distinction is the point, since a scan observing a check
pass is verification while a person moving a status is a decision.

**A superseded replay writes no history at all.** It re-evaluates an old capture
and makes no observation, so it records neither changes nor events, exactly as
it records no risk history and resolves no findings.

## 21. Remediation is declared once and the artifacts are generated from it

**Spec:** `ARCHITECTURE_REVIEW.md` §12 item 20 — "`expected_state` and
`verification_spec` beside the human text, with IaC and Policy snippets
generated from the same declaration that generates the RBAC artifact".

The prose stays. `SecurityRule.remediation` is what somebody reads at two in the
morning and it is snapshot-copied onto every finding, so an old finding keeps
the guidance it was raised with. What is new is the half a machine can act on.

**One setting has three names, so the declaration carries three.** The
normalized field the rule reads, the ARM alias a policy matches on, and the
Terraform argument that sets it — and often three values too: ARM says
`publicNetworkAccess: "Disabled"` where the provider says
`public_network_access_enabled = false`. Emitting the ARM spelling into HCL
would produce a line that does not mean what it says.

**The test runs in both directions**, exactly as the RBAC ones do. An asset
built from a rule's own declaration must make that rule PASS; one violating it
must make it FAIL. Without the second half the declaration is documentation, and
documentation drifts — a rule whose check moved on while its remediation stayed
put tells a customer to change something that no longer closes the finding.

**A policy is generated only where it can enforce the whole rule.** One covering
half of it would pass an asset that still fails, and a customer who deployed it
would believe the class was closed. Where no policy can exist — a directory
setting, a condition over a child collection — the API says so rather than
emitting a definition that deploys and checks nothing, which is the same
discipline `rbac.py` records for permission strings nobody verified: an alias
that looks plausible and is not real fails the customer's deployment outright.

**`also_accepts` exists because floors are not equalities.** A rule accepting
TLS 1.2 or higher, expressed as a policy pinned to 1.2, refuses an account
configured better than asked. That is a change-control incident rather than a
bug report, so the accepted set is declared rather than discovered after
deployment.

The generator negates the expected state, because a policy matches what it
refuses. Doing that by hand per rule is how one ends up denying every compliant
resource, which is why it is computed in one place.

**The vocabulary is three comparisons, and stops there.** `EQUALS` for a
setting, `NONE_MATCHING` and `NOT_EMPTY` for the collections most rules actually
judge. That covers eight of the ten rules; anything beyond it stays undeclared
rather than half-declared, because a remediation that describes most of a check
is worse than one that describes none — the customer satisfies what they were
shown and the finding stays open. A collection expectation carries a witness,
which is both the clearest way to say what is being looked for and what lets a
test build the asset a rule must fail.

**An empty expectation has to say why.** Two rules genuinely have none: one
judges a ratio across the directory, the other a relationship between a machine
and the security groups governing it. But an empty declaration is also what a
rule looks like when nobody could be bothered, and those must not be
indistinguishable — so a test requires an empty one to carry a reason and
something the customer can still run.

## 22. The customer wires up change events, because CloudGuard cannot

**Spec:** `ARCHITECTURE_REVIEW.md` §12 item 19 — "change-triggered scans via
Azure Event Grid".

The whole design falls out of one refusal. Creating an Event Grid subscription
is a **write** in the customer's tenant. CloudGuard holds no write permission
anywhere, that is the strongest security claim it makes, and it is not one to
spend on saving a customer a copy-paste. So CloudGuard generates the command —
one per subscription, because that is how Event Grid is scoped — and the
customer runs it, exactly as they deploy the scanner role.

**The webhook is reachable by anyone**, so the signed token is the whole guard.
It is the same HMAC scheme the ARM template endpoint uses and is separated from
it by `purpose` alone, which is why the webhook checks that field rather than
treating a valid signature as proof of intent. Every rejection returns the same
400 whether the token is malformed, expired, or signed for another connection:
distinguishing them would let a caller enumerate connection ids.

**It answers 200 to what it drops.** Event Grid retries a non-2xx for hours, and
redelivering an event CloudGuard has already decided it cannot act on is load
with no possible outcome. The validation handshake is answered before any
database work and for a connection that need not exist yet, because that
exchange happens at the moment the customer is watching their `az eventgrid`
command.

**Three things stand between an event and a scan**, and without them the feature
is a denial of service against the customer's own API limits, paid for by them.
Events outside the resource providers a rule reads are dropped. A burst marks
the connection and the scan waits for quiet, so one deployment is one reading
rather than forty. And a connection is not scanned for a change more often than
a floor, so an afternoon of deployments is not an afternoon of scans — the same
storm arriving more slowly.

**The webhook only records.** Event Grid times the response; starting a scan
behind it would put a queue, a database write and a provider call between Azure
and its acknowledgement. The sweep that acts on a settled burst is a beat task,
using the same advisory lock and in-flight check every other scan trigger uses.

Turning the feature off closes the webhook immediately, before the customer has
deleted anything in Azure — their subscription keeps delivering to an endpoint
that now refuses it. That is the right way round: a switch that appears to stop
something and does not is worse than one that leaves a tidy-up to do.

## 23. The provider seam is tested, not asserted

**Spec:** `MULTI_CLOUD.md` §8, and the claim in `ARCHITECTURE.md` §6 that
everything above `CloudConnector` is provider-neutral.

That claim was false in three places, and each was invisible to every test of
behaviour because with one provider they all give the right answer:

* the scan pipeline imported Azure's evidence-key enum to ask which keys a
  permission category holds, so a second connector's categories would have
  degraded no rules at all;
* the permissions endpoint returned Azure's grants for every provider, so the
  first AWS customer would have been told CloudGuard wanted Entra admin consent;
* the change-event service hard-coded ARM operation names and the `az` command.

All three now ask the connector or the registry. `get_connector_class` answers
the questions that are properties of a *provider* rather than of a connection to
one, so nothing needs credentials to ask what permissions a cloud wants.
`get_change_feed` does the same for change events, which arrive before any
connection has been resolved.

**`sign_state` moved to `app/core/signing.py`.** Nothing in it was ever Azure —
it signs a dictionary — and it lived under `connectors/azure/auth.py` only
because that is where the consent round trip needed it first. Three unrelated
flows now use it, and the next provider's onboarding would have imported Azure's
package to get a HMAC.

**One exception is scheduled rather than accidental.**
`services/cloud_connections.py` still imports Azure's auth, client and RBAC
modules, and `MULTI_CLOUD.md` §8 step 5 deliberately puts that split *after* a
second connector exists: it is a refactor whose right shape is knowable from two
examples and guessable from one. It is named in the test, so it stays one known
exception rather than becoming a habit — a new leak appears in the failure
message beside it.

**The test looks at imports, not text.** A docstring naming Azure is fine and
unavoidable; an import is what makes neutral code depend on one cloud, and what
a second connector would have to break.

## 24. shadcn/ui is now the primitive foundation (supersedes §12)

**Spec:** none. A frontend brief asked for shadcn/ui as the component
foundation, and §12 required a written decision before that swap — this is it.

§12's reasoning was that a handful of badges, cards and buttons did not justify
a runtime primitive dependency, and for those it was right. What it did not
survive is the second half of the product: a findings table with filters, a
remediation panel with tabs, an organization switcher, a mobile navigation
drawer, a command palette. Every one of those is a focus trap, an escape
handler and a set of ARIA relationships, and hand-writing them is how a security
product ends up with a dialog that keyboard users cannot leave.

So the primitives are now `@base-ui/react` through shadcn's registry, vendored
as source under `src/components/ui/`. Base UI rather than Radix because it is
what the current CLI installs by default; the distinction §12 drew — source, not
a runtime black box — still holds, and these files are editable and reviewed
like any other.

**The severity scale stays separate, and that is the load-bearing part.**
shadcn's tokens are chrome — `primary`, `destructive`, `muted`. CloudGuard's are
meaning: `destructive` says "this button deletes something" and `critical` says
"an attacker can reach your data", and a design system that collapsed the two
would eventually paint a cancel button and a public storage account the same
colour. `tailwind.config.js` therefore carries both layers, and
`SeverityBadge` is deliberately *not* shadcn's `Badge`.

UNKNOWN keeps its dashed border and gains an icon. Colour alone would hide the
product's most important distinction — "we could not look" versus "we looked and
it was fine" — from a reader who cannot separate the hues.

**The compatibility seam is gone.** `components/ui.tsx` was written to let ~20
call sites keep passing `title`/`subtitle`/`action` to a card while the
primitives underneath changed. Every one of them has since moved to the composed
API, so the file was deleted rather than left as a second way to build the same
card. `StatusPill` moved out first: it is security vocabulary, not chrome --
RESOLVED means *a scan observed the fix* -- and it now sits in
`components/security/` beside `SeverityBadge`, which is where a reader would
look for it.

**One thing the CLI got wrong, worth recording.** `init` writes Tailwind v4 CSS
(`@theme inline`, `@import "shadcn/tailwind.css"`) and leaves a v3
`tailwind.config.js` untouched, so every `bg-background` referred to a class
that did not exist and the build failed outright. The v3 bridge in
`tailwind.config.js` is hand-written, and maps `var(--x)` directly rather than
through `hsl()` — the variables hold complete oklch colours, and the usual v3
`hsl(var(--x))` recipe would silently render every one of them black.

## 25. The theme is applied before React exists, and "system" is a real choice

**Spec:** none. The dark palette had been defined since §24 — every neutral
token and a re-lit severity scale under `.dark` — with nothing in the product
able to put that class on the document.

Three decisions worth recording.

**Three states, not a switch.** `light`, `dark` and `system` are stored as
given, because "system" is a standing instruction rather than a synonym for
whichever theme the machine happened to prefer at the moment of choosing. A
laptop that goes dark in the evening takes CloudGuard with it, and a boolean
could only ever record one day's answer. The store subscribes to
`prefers-color-scheme` and follows it only while the choice is `system` — an
explicit choice is not a default for the OS to overrule.

**The class is set by an inline script in `index.html`, before the bundle
loads.** React cannot do this: by the time it mounts the browser has painted a
white page, and correcting it afterwards is a flash of white in a dark room —
which for a console people sit in front of at 2am during an incident is worse
than having no dark mode. That script is the one place in the frontend that
duplicates a constant (`cloudguard-theme`, and the `dark` class), so
`lib/__tests__/theme.test.ts` reads the real `index.html` and fails if the two
copies ever drift.

**`next-themes` is gone.** It arrived as a dependency of the vendored `sonner`
component, which nothing mounts. Two theme stores writing one class to one
element is how a toast ends up light on a dark page, so `sonner.tsx` reads
`lib/theme.ts` like everything else and the dependency was removed.

The severity scale is re-lit rather than reused across the two surfaces, for
the reason §24 gives: a light severity background on a dark page glows, and a
glowing badge reads as more urgent than the one beside it — a ranking the rules
never made.

**A React 18 bug this surfaced.** `Button` came from the registry without
`forwardRef`, which is correct for React 19 where a ref is an ordinary prop.
This app is on React 18, so every Base UI trigger rendering a Button
(`render={<Button />}`) handed a ref to a plain function component: React warned,
and the element the popup anchors to was never captured. `Button` now forwards
its ref, which fixes the existing `Sheet` trigger as well as the new menu.

## 26. The command palette searches what can actually be searched

**Spec:** none. `cmdk` was installed with the shadcn primitives and nothing
used it.

The palette (`components/layout/CommandPalette.tsx`, Cmd/Ctrl-K) jumps to any
page, any asset by name, and any rule. Three decisions are worth recording
because each one is a limit rather than a feature.

**Findings are not searched from the palette, and it says so.** At the time it
was built `GET /findings` had no text search; §27 has since added one, and the
palette could now use it. It still does not, because the rows it would return
are the same rows the findings page ranks and filters properly -- the palette
is for jumping to a *thing*, and a finding is reached through its rule
(`/findings?rule_id=`) or its asset. What the palette must never do is the
option that was rejected outright: filtering the loaded page in the browser,
which would search a hundred findings out of thousands and report "nothing
matches" for the rest. The empty state names what was searched rather than
implying everything was.

**One authority over what matched.** `shouldFilter={false}`: assets are matched
by the API (`name ILIKE %search%`) and everything else by the same substring
rule in this file. Leaving cmdk's fuzzy scoring on top would let it re-rank and
sometimes drop rows the server had already decided matched.

**No mutations in it.** No "run a scan" entry, though it would be easy: every
row is one keystroke from being triggered by whatever happens to be
highlighted, and a scan reads a customer's entire environment. Actions with a
cost stay behind a button somebody meant to press.

Pages come from `NAV_GROUPS`, the same source the sidebar renders, so the two
cannot drift; a test asserts every navigable page appears.

## 27. Searching and ordering belong to the database once a list paginates

**Spec:** none. Two pages had the same silent bug and it was worth naming
rather than just fixing.

`GET /findings` and `GET /risks` both paginate and both report a `total`. The
findings and risks pages asked for neither `limit` nor `offset`, took the API's
default hundred rows, and rendered them as the whole set -- so a tenant with
four hundred findings saw a hundred with nothing on screen saying so.

That alone is a display bug. What made it a correctness one is what the pages
then did with those rows: the findings page searched and sorted them **in the
browser**. Search over one page of an estate answers "no findings match" for
data that was never in the browser to match against, and a client-side "worst
first" puts the CRITICAL on page four below the LOW on page one. In a product
whose entire claim is *we tell you what matters*, both are wrong answers rather
than missing features.

So `search` and `sort` moved into the endpoints (`docs/API.md`), the pages
paginate against the real `total`, and a filter change resets to page one
because page four of the old result describes nothing in the new one. An
unrecognised `sort` is a 422 rather than a silent fallback: quietly ordering a
list differently than asked is the same class of lie in a smaller font.

`sort=severity` is a SQL `CASE` over the severity ranking rather than a column
sort, because alphabetically CRITICAL comes before HIGH but LOW comes before
MEDIUM -- an ordering that looks plausible enough on screen to be believed.

The risks page also gained the filters it had never had (level, status, kind,
and a search), all of them server-side. UNKNOWN is offered as a risk level
because the engine genuinely assigns it, and leaving it out of the filter would
hide precisely the risks CloudGuard could not score. Findings and routes stay in
one ranking by default, per §14: a route outranking the findings inside it is
only visible where they are listed together.

## 28. Connect and Scans are split by what each part fetches

**Spec:** none. `Connect.tsx` was 749 lines and `Scans.tsx` 593.

Length alone would not have justified the change. What did is that both files
mixed several independent request lifetimes, and reading either one made it
genuinely hard to see which request fired when: the scan list polls every two
seconds while anything is in flight, a running scan's card polls a second
endpoint every three, and the panels underneath -- stages, what was collected,
how many findings a delete would purge -- each fetch only when opened. Those are
four different answers to "when does this run", and they were interleaved down
one file.

So the split follows the fetching rather than the layout. `components/scans/`
now holds `ScanCard` (the two live polls), `ScanDetailPanel` and
`CollectionPanel` (open-only), and `DeleteScanConfirm` (which reads the purge
count). `components/connections/` holds `ConnectionCard` (polls until the
connection can actually be scanned), `ScheduleControl` and `RemoveConfirm`. Each
page is now a list, a control and the states around them: 125 and 105 lines.

`IN_FLIGHT` lives in its own module because both the page and the card decide
things from it, and a constant exported beside a component switches off fast
refresh for that file.

**Two behavioural notes from the move.** The schedule dropdown is now a Base UI
`Select`, whose options live in a portal that is not mounted while the control
is closed -- so the trigger renders its label from the value rather than
delegating, or an interval the list does not offer would show as a bare number.
And the connection's status ticks gained icons: three signals distinguished only
by green-versus-grey are three signals a colour-blind reader cannot tell apart.

`@testing-library/user-event` is now a dev dependency. The Base UI listbox is
built out of pointer events and `fireEvent.click` never reaches an option, so
the schedule tests were asserting against a control they could not actually
operate.

---

## 29. The remediation queue joins the finding in the browser

**Spec:** none. `UI.md` section 3 describes the queue; nothing said what a row
had to contain.

`GET /remediation` returns the task and nothing of the finding behind it -- no
title, no rule, no asset -- so every row said the same three things: a priority
badge, a status, and a link reading "View finding". Everything on the card was
about the record and nothing was about the problem, and a person deciding what
to work on next had to open each one to find out what it was.

The finding is therefore fetched per task in the browser, under the same
`["finding", id]` cache key its own page uses, so opening a row from the queue
costs no request at all. That is a round trip per task rather than a join, which
is the right trade at this size: the queue is bounded by work a human created,
and the alternative -- widening the endpoint's response -- is a change to a
stable API for a display concern. It stops being the right trade if the queue
ever grows into the hundreds, and at that point the serializer should carry a
finding summary.

`RemediationOut` is otherwise unchanged, and the API note the endpoint returns
when work is marked done is now shown rather than discarded: marking a task done
never closes a finding, and the sentence saying CloudGuard will look again is
the whole reason that is not a broken promise.

## 30. Actions that do not navigate say so in a toast

**Spec:** none.

Three actions on the finding page and one in the remediation queue changed a
record without moving the reader anywhere, and two of them said nothing at all
-- marking a finding in progress and accepting a risk both wrote to the audit
log and left an unchanged screen. `sonner` was already vendored as
`components/ui/sonner.tsx` and never mounted.

Toasts are used for exactly this: the outcome of an action that has no page of
its own. What stays inline is anything a reader must be able to re-read later --
a failed report generation, an expired session, the verified-fixed banner --
because a message that disappears after four seconds is not where a security
product puts a fact somebody may need to act on.

---

## 31. A navigation styled as a button is a link, not a button

**Spec:** none.

Fourteen places dressed a route change as a button by handing Base UI's
`Button` a `render={<Link />}`. Base UI warned on every one of them, and the
warning was right for a reason that matters: it renders with `nativeButton`
true, which asserts native button semantics over an element that has none.

The tempting central fix -- defaulting `nativeButton` to false whenever a
`render` is passed -- is wrong, and the tests caught it. Base UI then gives the
element `role="button"`, so an anchor announces itself as a button to a screen
reader and loses what a link is actually for: middle-click, ctrl-click, "open
in new tab", and the status bar showing where it goes.

So these render a real `Link` wearing the button's classes --
`className={buttonVariants({ variant, size })}`, wrapped in `cn()` when there
is anything to merge -- which is shadcn's own recipe for this case. `Button` is
kept for things that act rather than navigate. The rule is worth stating because
the wrong version reads as more idiomatic: *if it changes the URL it is a
`Link`, whatever it looks like.*

---

## 32. A report can leave things out, but not the terms it is read on

**Spec:** `UI.md` section 3 described two fixed documents. A frontend brief
asked for period, scope and section options.

**Sections and a window, yes.** `GET /reports/{kind}` now takes `days` (the
activity window: verified fixes, completed work, and how much of the trend line
is drawn) and `sections` (a comma-separated subset of top risks, attack paths,
compliance, remediation, findings). Two of those sections are new content
rather than new switches: the report can now carry the shortest attack paths
with the link worth cutting, and remediation progress with work *claimed* and
fixes *proved* side by side and never summed.

Three rules hold the shape:

* **The posture block and the evidence caveats are not optional.** Coverage,
  staleness and collection failures are the terms every number in the document
  is read on. A report that could drop "12% of checks reached no verdict" would
  let somebody produce a cleaner-looking PDF by unticking a box, which is the
  same transformation — "we could not look" into "we looked and it was fine" —
  that this product refuses everywhere else.
* **What was left out is printed on the cover.** Once a PDF has been forwarded
  twice, an omission somebody chose looks exactly like an absence of evidence,
  and only one of those is true.
* **An absent `sections` means all of them; an empty one means none.** The two
  are distinguished rather than collapsed, because collapsing them would make
  the emptiest request produce the fullest document. An unknown section name is
  a 422 rather than a silent omission.

**The window does not touch the posture, and that is deliberate.** A score, the
open findings and the severity split are a reading of *now*. Giving them a date
range would invite "our score over the last quarter", which no scan can answer
and which this product does not measure. What the window legitimately bounds is
activity — fixes verified, work completed — and the trend, which is cut to the
window rather than resampled: every point is a reading that happened.

**Scope is not offered, and the reason is not effort.** A per-subscription
report would have to recompute the score, the coverage ratio and the freshness
for that scope; anything less produces a document whose headline is estate-wide
and whose list is one subscription, which is the most quietly misleading report
this product could print. It stays out until the posture itself can be scoped.

---

## 33. A finding says what it is part of, from its own endpoint

**Spec:** `UI.md` section 3 listed what a finding detail must answer. Nothing
there said whether the finding was one fault or one link in a route.

The graph has been able to answer this since attack paths were built, and the
finding page could not ask: `ResourceSummary` carries the database id and the
routes are keyed by provider resource id, so the browser had nothing to match
on. The gap was real rather than cosmetic — the findings list ranks problems
one at a time, and a medium misconfiguration on a host standing between the
internet and customer data is not a medium problem.

`GET /findings/{id}/attack-paths` answers it. Three choices in that shape:

* **Its own endpoint, not a field on the finding.** It costs a graph build, and
  the page that answers "what is wrong" must not wait on one. The panel is
  fetched after the page renders; a finding with no asset never asks at all.
* **Membership is asked of the whole route.** A misconfiguration on the jump
  box at the start and one on the storage account at the end are the same
  problem seen from two ends. The response says which by way of `asset_role`
  (`ENTRY`/`STEP`/`TARGET`), because that is what decides the action.
* **An empty answer is not an all-clear, and does not read as one.** What counts
  as sensitive is declared per subscription, so an estate that has classified
  nothing yields no routes. The panel says that in as many words rather than
  printing a reassuring dash.

`serialize_path` moved from the attack-paths route into `services/graph.py`,
because two endpoints now render the same object and a second copy of that
serializer is how two screens start disagreeing about one route.

---

## 34. The asset hierarchy is counted server-side, or it is a lie

**Spec:** `UI.md` section 3 described a filterable inventory. A frontend brief
asked for the subscription → resource group → resource tree.

The page already grouped by resource group, in the browser, over the fifty rows
it had. That is fine as a visual aid to one page and wrong as a hierarchy: a
resource group whose assets straddled two pages appeared twice, each time
holding a fraction of its findings — and the number a reader takes away from a
tree is exactly the count it puts beside a group's name.

So `GET /assets/hierarchy` aggregates over the whole estate in one query and
returns it whole. The tree it feeds is a summary, not a page of rows; the list
keeps paging, and the two are offered as two readings of one inventory rather
than as one replacing the other. Expanding a group asks `/assets` for that
group, so no level of the tree is ever assembled out of something it only
partly has.

**The resource group is read, not stored.** An ARM id spells out its own
subscription and resource group, so the fifth segment *is* the group —
`split_part(provider_resource_id, '/', 5)`, positional because ARM treats
`/resourcegroups/` and `/resourceGroups/` as the same path, and guarded by an
`ILIKE '/subscriptions/%'` so a directory principal's id is never sliced into
an invented group. The backend derives containment the same way when it builds
the asset graph, so the tree and the graph agree by construction.

**A directory asset is not an asset with an unknown subscription.** Users and
service principals belong to the tenant, which outlives every subscription
under it, so they are a named scope of their own. For the same reason, assets
sitting directly in a subscription are labelled as that rather than as
"Ungrouped", which would read as somebody's tagging oversight instead of as
where they actually are.

---

## 35. Tailwind v4, because the primitives were already written in it

**Spec:** none. §24 adopted shadcn/ui through the CLI and recorded that the CLI
wrote v4 CSS against a v3 config, patched at the time with a hand-written
bridge in `tailwind.config.js`.

The bridge was not enough, and the way it failed is the point: **v3 does not
error on v4 syntax, it emits nothing.** Four constructs in the vendored
components compiled to empty:

* `p-(--card-spacing)`, `w-(--anchor-width)`, `origin-(--transform-origin)` —
  the parenthesis shorthand. Cards lost every scrap of internal padding;
  popovers, selects and tooltips lost their anchor sizing.
* `[--card-spacing:--spacing(4)]` — emitted the literal `var(--spacing(4))`,
  which is not a value, so the variable was never set either.
* `in-data-[...]`, `@container/...` — dropped variants.
* `ring-foreground/10` — an opacity modifier against an oklch `var()` colour,
  which v3 cannot compute. **This is the one that was visible from across the
  room.** The class was dropped while the `ring-1` beside it survived, so every
  card, dropdown and tooltip fell back to Tailwind's default ring colour —
  blue — and the whole dark theme was outlined in it.

So the app is on v4, which is what the components were written for. The theme
moved into `src/index.css` as `@theme inline` and `tailwind.config.js` is
deleted; `@custom-variant dark (&:is(.dark *))` keeps the class-based theme
§25 requires, and `* { @apply border-border outline-ring/50 }` now resolves,
which is the recipe §24 had to work around.

**The severity scale keeps its own layer, unchanged.** `--color-critical` and
friends are declared beside the semantic tokens and mapped from the same
`--sev-*` variables, for the reason §24 gave: `destructive` says a button
deletes something and `critical` says an attacker can reach your data.

Autoprefixer is gone — v4 prefixes and inlines `@import` itself.

## 36. A provider's failure is stated once, not once per key it cost

**Spec:** none.

Azure reports collection failures per evidence key, so a single missing admin
consent arrives as three entries carrying the same nine-hundred-character
sentence about ungranted Graph scopes. The dashboard printed the joined string
verbatim, and the coverage card — the place a customer goes to find out what
CloudGuard could not see — became a wall of the same paragraph repeated.

Identical causes are now stated once with the keys they cost named beside them,
and the message is clipped with the rest one click away. Clipped rather than
summarised: this is the text an administrator will paste into a search box, and
a paraphrase of an Azure error is not an Azure error. The splitting is
defensive about the provider's own punctuation — a part that does not look like
`key: message` is joined back onto the one before it, because a message cut in
half on its own semicolon is worse than a long one.

---

## 37. The overview is an argument, not a grid of cards

**Spec:** `UI.md` §1 named the parts of the executive dashboard. It did not say
what order they go in, and order is most of what a dashboard is.

The page now reads top to bottom as one argument, each step the precondition for
the next: where the posture stands and which way it moves; what that number is
made of; how much of the estate the opinion was formed from; what to deal with
and what those faults form *together*; whether any of it is being fixed; what
moved while you were away.

Four choices in that shape are load-bearing:

* **Coverage is third, not last.** A score computed over half an environment is
  a different claim from the same number over all of it. Placed after the risk
  list, the caveat arrives once the reader has already acted.
* **UNKNOWN is in the severity strip**, at the end and labelled "no verdict".
  It is not a fifth severity and never a pass, but a reader tallying what is
  wrong has to see what could not be answered in the same glance rather than
  further down the page.
* **A ranked risk carries the terms it was ranked by.** The list is the
  product's whole argument and used to ask the reader to take it on trust; the
  three context levels are already columns on the risk row, so a rank now reads
  as a reason.
* **Inventory counts are not headline figures.** Assets and resource counts are
  true and answer a different question; every pixel one takes is a pixel not
  spent on what is wrong. They remain on the pages that are about them.

**Three requests, deliberately.** `/dashboard` is a set of database aggregates
and answers quickly. Attack paths cost a graph build and changes are a windowed
feed, so folding them in would make the numbers everybody came for wait on the
two panels nobody scrolls to first. Both fail quietly — a dashboard that cannot
draw its last panel is still a dashboard.

**Two small backend additions, both aggregation only.** `coverage.categories`
(one grouped read of the evidence table) says *which* part of the estate could
not be read, because "identity is unreadable" and "storage is unreadable" call
for different people to fix them. `top_risks[]` gained `kind` and the three
context levels, which were already loaded on the row.

**What was left out for lack of data, rather than invented.** "12 fixed this
week, 3 reopened", per-risk effort and impact estimates, and a recommended-next-
actions list ranked by effort all need numbers the API does not expose today.
The remediation panel therefore reports only what is measured: the verified-fix
rate, verified fixes in the last thirty days, and what is still open — and every
one of those counts an observation rather than somebody's claim to have fixed
something.

`SecurityScore` and `CoverageIndicator` were deleted rather than left beside
their replacements. Two components that render the same fact are how two screens
start disagreeing about it.

---

## 38. Every chart has to earn its form

**Spec:** none. A request for "prettier, with charts" — which is a request to
*show* more, and the way that goes wrong is showing it in shapes that flatter
the data.

Five forms, each chosen by the question rather than by variety:

* **Rings only for a whole divided in two or three.** Coverage — reached a
  verdict versus did not — and finding status. A ring encodes one share well
  and comparison badly, so nothing ranked is ever drawn as one.
* **Severity is a single stacked bar**, not a five-slice pie: lengths on one
  line are compared exactly, angles around a circle are not, and it costs 8px
  of height rather than a panel.
* **Risk bands and framework coverage are bars from a common baseline**, which
  is the form a ranking asks for. Both are plain elements — a list of widths
  does not need a charting runtime, a canvas and a resize observer.
* **The posture trend is an area on a fixed 0–100 axis**, with the score bands
  painted behind it at 8% so the height *means* something without the line
  changing colour as the data does. Every reading is dotted, because the points
  are the moments CloudGuard actually looked and a smooth line between them
  invites belief in measurements that were never taken.
* **The estate treemap is the one place area is the right encoding.** A tree
  names the parts and a table ranks them; neither answers "is my problem
  concentrated or spread out", which decides whether a customer sends one team
  or six. Tint is a *rate* — findings per asset — so a large group is not darker
  merely for being large.

**Sparklines carry the series the payload already had and nothing rendered.**
`history[].findings_by_severity` and `attack_path_count` were in every dashboard
response and shown nowhere; they are now the line under each severity count and
beside the attack-path panel. "One critical" and "one critical, and there were
none last week" are the same number and a different Monday.

**No dual axes anywhere.** Route counts and a 0–100 score share no scale; two
y-axes in one frame let any two shapes be made to look correlated, so the second
series is a sparkline of its own instead.

**Status colours stay reserved.** Severity is a status palette, not a
categorical one: it is never spent on "series 4", and every chart that uses it
also prints the label, so nothing is carried by hue alone.

**Motion is a statement about honesty, not polish.** Numbers count up on mount
and when the value actually changes — never on a poll that returned the same
figure, which would make an untouched page twitch three times a minute. Charts
animate once on mount and not on update. Lists stagger by 30ms and cap at eight
rows, past which it reads as a slow page rather than as arrival.
`prefers-reduced-motion` is honoured globally in `index.css` and again per
component, and it degrades to the *finished* state rather than a slower one.

**One backend addition:** `remediation_activity`, eight weeks of findings
raised, verified fixed, and reopened, read from the transition log. Reopenings
are counted separately and never netted against fixes — a fix that did not hold
happened, and subtracting it would hide the pattern the panel exists to show.

**A chunking trap worth recording.** `DonutLegend` lives in its own module away
from `Donut`. Imported from beside the ring, it dragged Recharts into the
dashboard's own chunk — 15kB became 206kB — and quietly undid the lazy loading
the charts were written for.

---

## 39. A select's trigger renders its own label, everywhere

**Spec:** none. Reported from a screenshot: the changes window read `30`
instead of "Last 30 days".

§28 recorded this once, for the schedule dropdown, and fixed it there: Base UI
keeps a select's options in a portal that is **not mounted while the control is
closed**, so `<SelectValue />` has no item to read a label from and falls back
to the raw value. What that entry did not do was generalise, and every other
filter in the product carried the same bug — severity reading `CRITICAL`, group-
by reading `resource_type`, the report window reading `90`. The machine's word
for the thing, shown to the person.

So the pattern is a component now. `SelectField` takes one list of options and
feeds both the trigger and the menu, which closes the second half of the same
problem: a label that was written twice and updated once. Every select in the
product — sixteen of them across nine files — goes through it, and
`components/ui/select.tsx` is imported by nothing else.

**The worst instance was not a filter.** The scans page picks which
subscription to read, keyed by the account's row id, so closed it displayed a
UUID: an identifier the customer has never seen, cannot recognise and cannot
act on. `ScheduleControl`, which §28 had already fixed by hand, moved onto the
same component rather than staying a second implementation of it.

Three details worth keeping: `id` is forwarded so a `FieldLabel`'s `htmlFor`
still lands on the trigger; an unrecognised value falls back to printing itself
— a stored filter from an older build should look odd rather than make the
control look broken; and `fallbackLabel` overrides that where the value is an
identifier rather than a word, so an unknown subscription reads "Unknown
subscription" and an interval the list does not offer keeps its own "18 h".

---

## 40. The risks list shows live risks, and the schedule moved to the scans page

**Spec:** none. Three bugs from screenshots, and two of them had the same
shape — a screen showing something the product itself does not believe.

**The risks page listed every risk row ever raised.** A risk outlives the
finding it was scored from: the finding closes, a later scan supersedes it, and
the row stays. Unfiltered, that rendered four identical "Storage account allows
public access" cards, all marked Open, on an estate the dashboard was
simultaneously reporting two open findings for. The two screens disagreed
because only one was applying the product's own definition of live — a finding
risk counts while its finding is open, a scenario counts until the route
closes — so `GET /risks` now applies it by default. Asking for a status by name
still reaches the rest, which is how a resolved risk is looked up rather than
lost.

**The rule is *settled*, not *strict*, and the difference matters.** A risk is
hidden when its findings say it is over, never merely because they fail to say
it is current: a risk linked to no finding at all stays listed. The link table
is the only thing that could vouch for such a row, so its absence is not
evidence the risk has been dealt with — and hiding it would trade four
duplicates for an empty page, which is the worse failure for a security
product. The first version of this filter was strict, and an integration test
that inserts a risk without links caught it.

**Tabs rendered as a vertical strip beside their own panel.** The registry's
classes matched `data-horizontal`, a bare attribute Base UI never writes: it
writes `data-orientation="horizontal"`. So `data-horizontal:flex-col` compiled
to a rule nothing matched, the root stayed a flex row, and the remediation
panel's Steps/CLI tabs stacked into a narrow column. Same family as §35 —
syntax that is silently inert rather than loudly wrong.

**A select whose value is the empty string had no label.** `SelectField` treated
empty as "nothing selected" and fell through to the placeholder, but the
schedule control's "Manual scanning only" *is* the empty value, so that control
rendered blank — which reads as broken rather than as switched off. Options are
consulted first now, empty string included.

**The schedule is a row inside one panel, not a card inside a card.** Moved as
it was, `ScheduleControl` kept its own border and heading inside the new
panel's border and heading, so one setting rendered as two nested boxes both
titled "Automatic scanning". The control now draws only the control; the panel
around it says what it is, once.

**Automatic scanning moved from the connection card to the scans page**, at the
customer's request and for a reason worth recording: the connections page
answers "can CloudGuard see my cloud", a setup question asked once, while the
scans page answers "when was this last read, and when will it be read next" —
and a schedule is the second half of that sentence. A history of runs with no
visible cadence makes the gaps between them look like something that happened
rather than something that was chosen. The connection card keeps a line saying
where the setting went and what it is currently set to: somebody who configured
it there once should be told it moved, not left to conclude it was dropped.

---

## 41. The remediation queue is reachable from the finding

`POST /remediation` shipped with the API and no screen ever called it. The
queue's own empty state told the reader to "assign a finding from its detail
page", and the detail page had no control that did so — the queue could
therefore only ever be empty, and the one screen that ranks work by impact
against effort was unreachable from every screen that produces work.

The control sits under the recommended fix rather than in the row that holds
"Rescan to verify". Tracking work is a statement about who is going to do the
thing written above it; the verify row is where a person asks for proof, and the
two must not blur into one strip where a button recording intent looks like a
button producing evidence. The caption under it says the finding stays open
until a scan observes the fix, because assigning does move the finding to
`IN_PROGRESS` server-side and that status is the closest thing in the product to
a person marking a security problem solved.

Whether a finding is already tracked is read from `GET /remediation` under the
key the queue page itself uses, rather than by widening the finding detail
response. The detail endpoint is on the hot path of the page the product is
really about, and a join added there to decide the label on one button is a cost
paid by every reader who never presses it. Sharing the cache key also means
opening the queue afterwards costs no request. The API refuses a second open
task per finding, so a button offered unconditionally would be one that
sometimes only produced an error: once a task exists the control is replaced by
what is true — that the work is queued, and where.

A cancelled task does not count as tracking. The work was called off, and the
finding can be picked up again. A verified or accepted finding is offered
nothing at all: one has no work left in it and the other is a recorded decision
not to do the work.

---

## 42. Setup is a wizard at its own URL, and the step is derived, not remembered

Connecting Azure leaves this application twice: to Microsoft for admin consent,
and to Azure Portal for the reader role. Each trip returns through a full page
load, so a dialog over the connections list could not survive either one, and a
step number held in React state is gone before the customer comes back. The
wizard therefore lives at `/connections/new` and `/connections/:id/setup`, and
which step it shows is computed from the connection itself
(`lib/connectionStage.ts`): consent is recorded by the callback, read access by
the probe that runs on every read of the connection. That is the only answer
still correct after the tab is closed, or after the consent link is opened by an
administrator on a different machine.

The consent callback now redirects into that URL rather than to the connections
list, on failure as well as on success — the signed state comes back on a denial
too, so a failure knows which connection it belongs to and can be shown against
the step that produced it, beside the button that starts consent again. Only a
state that cannot be verified at all has nothing to return to, and that is the
one case that still lands on the list.

The steps moved out of `ConnectionCard` entirely. A card that carried a consent
button, a deploy button, a discovery retry and a scope list was the largest
component in the product and the first screen a customer ever used, and it read
as four things to do at once when three of them were not yet possible. The card
now states what a half-finished connection is waiting for and links to the step
it stopped on. What genuinely outlives setup — the subscription scope list, and
the discovery retry, since a subscription created next month appears on the next
read — is shared between the card and the wizard as one component rather than
copied.

Handing the consent link to someone else is a first-class branch of the consent
step, not advice in a paragraph. Admin consent needs a Global Administrator and
the person evaluating CloudGuard usually is not one; the step offers the link
together with a sentence explaining what is being approved, because a bare URL
pasted into a chat window is exactly the request an administrator should refuse.
For the same reason every waiting step offers "Finish later" alongside "Cancel
setup": both grants are somebody else's to give, and a flow that can only be
completed or abandoned makes a customer sit on a spinner waiting for a colleague
who is in a meeting.

A stalled deployment names its three causes — propagation, wrong scope, and
Contributor rather than Owner — with the scope one worded for the scope this
connection actually covers. Changing scope is offered there as discard and start
again, because the scope is what both the consent state and the role assignment
were bound to; there is no edit that would leave either of them meaning what
they meant.

---

## 43. The connections page is a table of rows, and each row answers the same four questions

Four connections as four stacked cards answered "how is this one connection
doing" four times, and never answered the question the page is actually opened
for: is every environment being read, and how recently. That is a comparison, so
the shape is a row — connection, status, subscriptions, last read — with
everything needed to *act* behind a disclosure rather than in front of it.

Column labels sit above the rows, but this is not a `<table>`. Every row opens
into a two-column panel, which a table cell cannot hold without colspan
gymnastics or a nested grid inside a cell; on narrow screens the labels are
hidden and each row stacks carrying its own.

The status column does not print the enum. `ACTIVE` is true of a connection with
every subscription unticked, and `PENDING` is true both of one waiting on an
administrator and of one whose deployment failed an hour ago — so `statusSummary`
answers "is CloudGuard reading this environment" in words, with a second line
saying what to do when the answer is no. Last read is derived from the
subscriptions rather than fetched, including ones now out of scope: the question
is when this environment was last looked at, and one excluded yesterday was
still looked at last week. It is rendered as elapsed time, because an absolute
timestamp asks the reader to subtract against a clock they cannot see.

A closed row costs nothing. The list endpoint already carries subscriptions, so
the per-connection request runs only while a row is open — and the polling that
used to justify itself on this page (a card left open was what noticed a
finished deployment) moved with setup into the wizard. `change_events_enabled`
and `last_change_event_at` are serialized onto the connection for the same
reason: the cadence line needs both halves of the answer, and fetching the
second half from the change-events endpoint would be one request per row to
render one line.

Each subscription row carries its own history — first seen, new since last read,
excluded by you and when. `scope_changed_at` (migration 0021) is stamped only
when the flag actually flips, so a screen re-sending rows it displayed cannot
move the date on subscriptions nobody touched. Without it the product could say
*that* a subscription was excluded and never *when*, which is the difference
between a decision somebody made in August and an environment that has been
silently unscanned for as long as anyone can remember. Long estates collapse
behind a count rather than pushing the panels beside them off the screen.

"Scan now" on a row posts one scan naming any scannable subscription beneath the
connection, because a scan is already connection-scoped server-side: the worker
resolves the subscriptions when it runs, so one discovered between queueing and
running is still read.

The empty state states the read-only claim and then proves it: "Read what
CloudGuard will do" fetches `/cloud-accounts/azure/permissions` and lists the
directory permissions, the Azure role and the writes performed. A hardcoded list
would be a second copy of the claim, free to drift from the one Microsoft's
consent screen actually shows. Its four-step preview is the wizard's own
`SETUP_STEPS`, in the same words, so the list cannot drift from the flow it
previews.

---

## 44. The graph holds present assets, and a rule may group its findings into one risk

Two separate corrections to the same habit of counting rows instead of problems.

**`load_graph` reads assets that are still there.** An asset a scan looked for
and did not find keeps its row — `absent_since` is set rather than the row
deleted, so its findings stay history and so an asset that vanishes for a week
and returns is one asset rather than two. The loader was reading every row the
organization had, so `/attack-paths`, the asset detail page and the PDF report
served routes through resources that no longer existed, while the scanner's own
graph, built from one scan's normalized state, never contained them. Two views
of one tenant disagreeing, with the wrong one facing the customer. Edges are
already dropped when either endpoint is missing from the node set, so filtering
the nodes is the whole fix.

Still unfiltered, deliberately: a subscription the customer excludes stops being
scanned, so its assets never become absent and stay in the graph indefinitely.
That wants scope on the query and is a change to what "the organization's graph"
means, not a bug in this one.

**A rule may declare that its findings are one risk.** `AZ-ID-001` fails once
per privileged account without a second factor, and each of those is separately
fixed and separately verified, so the *findings* stay per resource. As forty
risks it was forty rows saying one sentence, and forty Critical deductions —
which pins the org security score at zero over a single Conditional Access
policy that was never written. The remediation the rule itself prints is one
policy covering every privileged role at once.

So `SecurityRule.risk_grouping` declares it, as a `RiskGrouping` carrying the
singular and plural sentences. Declared rather than inferred from the count:
whether repeated failures are one problem or many is a judgement about the
rule's subject. Two storage accounts left public are two mistakes; two
administrators without MFA are one policy nobody wrote.

The group is **scored as its worst member**, exactly as a scenario is — it
cannot be less serious than the worst thing in it, and must not be more serious
either. Its breakdown is that member's, so "why is this 84?" still names
components measured on a real asset rather than an average of forty. What the
group adds is the count, and the count is in the title.

Identity across scans reuses `scenario_key` (`group:<rule_id>`), the column that
already answers "what identifies a risk that is not identified by a single
finding" — so no migration, and the existing unique index on (organization, key)
covers it. Per-finding risks from before a rule grouped are **deleted** when
absorbed, which is the opposite of what happens to a closed route and for the
opposite reason: nothing ended. The same accounts still fail the same check, and
a resolved duplicate would show a customer a fixed MFA risk beside an open one
for the same people. The findings keep every event they ever had.

Two counting rules follow. A group closes only when nothing in it is still open,
or the first administrator to register an authenticator app would close a risk
covering thirty-nine who had not. And the band queries behind the security score
count `distinct` risks, because the junction fans a risk out across its members
— counting join rows would reinstate the forty deductions the grouping exists to
collapse. `open_finding_count` is now taken from the findings, having been the
width of that band query, which was the same number only while every risk had
exactly one member.

---

## 45. The security score decays instead of subtracting

`max(0, 100 - Σ deductions)` was strict, which was right, and clamped, which was
not. Five open Criticals scored 0. Twenty scored 0. So did the same estate after
seven of them had been fixed and verified. The number stopped moving exactly
where a customer needs it to move most — through the months of a remediation
programme — and `score_delta` on the dashboard, computed from it, reported that
nothing had happened. On the product whose north-star metric is verified risk
reduction, the headline number was structurally incapable of showing it.

The same deduction total now drives `round(100 × exp(-Σd / k))`. Every fix moves
the score; the curve is steepest across the first few Criticals, where the
strictness has to live; and 0 is where a catastrophic estate lands rather than
where an ordinarily bad one starts. One Critical leaves 77, five leave 28,
twelve leave 5, thirty leave 0.

**Fitted to an anchor, not to a rate.** `k` is solved for from
`score_anchor_criticals` and `score_anchor_value` — two Criticals leave 60, the
sentence already in `RISK_ENGINE.md` §3 and already asserted in the tests. The
calibration is therefore the thing configured, and it survives somebody retuning
what a Critical costs, rather than silently parting company with the doc.

Two consequences worth stating because neither is obvious:

- Fitting to the anchor **normalizes** the deductions, so their absolute size is
  absorbed and only their ratios to a Critical decide anything. Doubling every
  deduction changes no score at all — which matters because "make everything
  cost more" is the obvious way to attempt a stricter score. The levers are the
  ratios, and the anchor.
- The integer rounding does flatten the curve eventually, around twenty open
  Criticals. That is a real limit and an acceptable one: the score is read
  rather than computed with, and by then it has said what it has to say. Below
  that, every Critical closed is visible.

The band thresholds the UI colours by (`scoreColor`: 85 / 60 / 40) are unchanged
and still land where they should — two Criticals is amber at 60, five is red at
28, where it used to be red at 0 alongside every other broken estate.

---

## 46. The security score charges for context CloudGuard established, not context it guessed at

`RISK_ENGINE.md` §3 has always said coverage is reported beside the score and
not folded into it. Half of that was true. A check that reaches no verdict
raises no finding, so evidence coverage genuinely never reached the number. But
§1 scores an UNKNOWN criticality, sensitivity or exposure at 3.5 — just under
High — and that band drove the deduction. An estate nobody had labelled was
therefore told its posture was worse, on the strength of what CloudGuard could
not work out rather than anything about the customer's risk, on the same
dashboard that promises the opposite.

The cautious 3.5 is not the mistake and has not changed. It is what stops the
cheapest route to a good score being to tag nothing, and an unclassified
production database must never sort below a labelled dev box. The mistake was
using one number for two jobs.

So the scorer produces both. `risk_score` / `risk_level` rank, cautiously, and
still drive the risks list, the top-risks panel and the band distribution.
`known_score` / `known_risk_level` take every UNKNOWN input at the LOW floor —
not zero, because an asset is at least a low-criticality asset — and the org
Security Score deducts on those. For a fully classified asset the two are
identical, so nothing changes for a customer who has done the labelling.

Recomputed rather than discounted: the weights are not uniform, so which
component was unknown changes how much it mattered, and a blanket multiplier
would get that wrong in both directions.

`known_risk_level` is NULL on scenario risks, and NULL means "not computed"
rather than "no risk" — a route is a statement about wiring rather than about an
asset's context, and it never reaches the org score because the findings it
groups already do. The band queries coalesce to `risk_level`, which also leaves
rows written before migration 0022 scoring exactly as they did rather than
being silently re-banded.

**The consequence is a visible one, and it is the point.** Untagged estates
score higher than they did, immediately, without anyone fixing anything. What
replaces the deduction is a sentence the customer can act on: `coverage.context`
counts the open risks sitting on unclassified assets, shown on the dashboard
beside the evidence-coverage ring and printed on the cover of every PDF, with a
link to the subscription context declarations in Settings. Silently deducting
told them nothing and gave them nothing to do.

---

## 47. Exploitability is required, and it is a ceiling rather than a constant

Two defects in one tag, and both of them are shapes this codebase refuses
everywhere else.

**It defaulted to 0.** `exploitability: int = 0` on `SecurityRule` meant a rule
whose author never thought about the question silently asserted the
misconfiguration was unexploitable — an absence reading as safe, which is the
same overclaim as a PASS nobody earned and the exact thing the UNKNOWN/PASS
distinction exists to prevent. It is now declared without a default, like
`severity`: a rule that omits it raises `AttributeError` at import rather than
quietly scoring 0.

**It was flat across instances.** An NSG rule allowing RDP from the whole
internet scored 5 whether it guarded a production jump box or nothing at all —
on the engine whose entire premise is that the same misconfiguration means
different things in different places. The distinction was already computed:
`_attachment_evidence` records whether the group protects anything, AZ-CMP-001's
own description contrasts itself with "an unattached NSG rule", and the note on
`ResourceRelationship` says an unattached NSG allowing RDP is noise. It reached
the evidence and never reached the score.

So `RuleResult` now carries an optional `exploitability`, and the class value
becomes the **worst** instance of that misconfiguration rather than every
instance of it. Three rules step down where they can already tell:

- an NSG rule protecting nothing → 1. Nobody can connect to a machine it does
  not guard, so what is left is a latent mistake, real and worth fixing before
  something is attached to it.
- a storage account open to every network but with anonymous blob access off →
  3. A key or a SAS token is still required, which is an attacker who already
  has a credential rather than one with a browser.
- a database whose only over-broad firewall rule is Azure's `0.0.0.0-0.0.0.0`
  shortcut → 3. Every Azure tenant is a serious and usually unintended gap, and
  it is not the open internet.

**Down only.** `effective_exploitability` clamps to `0..tag`, so a rule can
never claim an instance is worse than its own tuned value. That number is the
starting value `RULE_ENGINE.md` §5 says to tune against real environments; a
rule able to raise it per finding would be retuning itself in the dark, one
finding at a time. A mistaken override can therefore only understate — the
direction that costs a customer nothing the severity has not already told them.

The starting values themselves are unchanged. Retuning them wants the real
environments the doc asks for, and this change is about the mechanism.

The scale is now written down (`RULE_ENGINE.md` §5) in terms of what the
attacker must already have, from "nothing, anonymous, today" at 5 to "weakens
detection rather than enabling anything" at 1. Eleven magic integers with no
stated basis could not be reviewed; 4 versus 5 is now a question with an answer.

`_upsert_risk` reads the exploitability from the scored inputs rather than from
the rule, so the number shown on the detail page is the number the arithmetic
used.

---

## 48. Compensating controls lower a finding's score and never close it

Every path CloudGuard scored was scored as though nothing in the environment
defended it. An administrator with no registered second factor ranked identically
in a tenant where security defaults challenge every sign-in and in one where
nothing does — which is the same flattening the risk engine exists to refuse,
pointed at defences instead of at assets.

A `Control` (`app/rules/controls.py`) is one observed defence and what it leaves
an attacker needing. A rule returns them on its `RuleResult`, and
`effective_exploitability` takes the minimum of the class tag, any instance
step-down and every control — so several compose to the strongest without any of
them knowing the others exist, and none can ever raise a finding.

Three rules, and each is the product refusing a temptation the category is full
of:

**A control never turns FAIL into PASS.** A policy demanding a second factor of
an account that has never registered one locks that account out of its own
tenant at the first challenge — a real operational problem, not a fixed one —
and the policy can be disabled, rescoped or have that account excluded in a
change nobody reviews. Reporting a pass would be CloudGuard vouching for a state
of affairs it is not observing.

**Only prevention counts.** Detection is not compensation. Defender watching a
storage account changes whether somebody finds out, not what an attacker must
have to get in, and the exploitability scale is written in terms of the second
(§47). A control that only shortens time-to-discovery belongs in a report.

**The control must be observed.** Every one is built from the same capture the
finding came from, and one CloudGuard could not fully read is simply absent.
Absence of evidence lowers nothing.

Implemented for AZ-ID-001 from two Graph readings, both under permissions
already in `REQUIRED_GRAPH_PERMISSIONS` and already consented by every connected
tenant — so this costs nobody a second trip to a Global Administrator.
Security defaults are unconditional. Conditional Access is only accepted when
every part of it resolves: enabled rather than report-only; granting MFA
unambiguously, so `MFA or compliantDevice` under `OR` is discarded because a
stolen password still works on an enrolled machine; covering all applications,
since CloudGuard cannot know which one an attacker would use; and with every
group it names read back, because an unread exclusion group could be the one
holding the account being judged. That last case is why the collector reads the
members of exactly the groups a policy mentions — essentially every real tenant
excludes a break-glass group, and without resolving it the feature would be
theatre.

Role template ids are matched through the tenant's own `directoryRoles` rather
than a table of GUIDs written from memory, for the reason `rbac.py` records
about ARM action strings: a wrong identifier is indistinguishable from a right
one by inspection.

Controls are **not** normalized into `resources`. A Conditional Access policy is
not a thing anybody secures, has no exposure and no data sensitivity, and would
inflate every inventory count with rows a customer never asked to own. They ride
on `NormalizedState.controls` and reach rules through `RuleContext.controls`.

The pipeline writes them onto the finding's evidence under
`compensating_controls`, and the detail page renders them above the raw evidence
under "What is standing in the way" — because a score arrived at through a rule
nobody can see is the kind a customer stops trusting. The copy is deliberately
not reassuring.

**Just-in-time VM access is the obvious next one and is deliberately absent.**
It would need `Microsoft.Security/locations/jitNetworkAccessPolicies/read` in
the scanner role, and `rbac.py` requires every action string to be verified with
`az provider operation show` before it ships — an unverified one fails the
customer's entire role deployment atomically, which is exactly how
`autoProvisioningSettings/read` was caught. It would also cost every existing
customer a role redeploy and a `ROLE_VERSION` bump. It goes in when the string
has been checked against a real tenant.

---

## 49. Choke points: the one change, verified rather than counted

The attack-path list ranks routes shortest-first, which is the right order for
reading them and the wrong one for acting. Fifty routes are fifty things to
read. "Remove this one role assignment and thirty-seven of them close" is one
thing to do — and it is frequently not the fix any single route would have
suggested, because each route's own `cheapest_break` is at its start while the
link they all share sits in the middle.

`AssetGraph.choke_points()` is two passes, and the second one is the whole
point. Counting how many routes a link sits on takes a single walk and
**overstates**: a link on twenty routes closes only the ones with no way round.
So the leading candidates by containment are then checked by removing the link
and re-running the entire traversal, comparing which (entry, target) pairs are
still reachable. That is the only way to distinguish a route that is gone from
one that has merely been made longer.

Verified for the top few rather than for every candidate, because each check is
a full re-traversal. Containment is an upper bound on severance, so the ordering
that selects candidates can never skip a link that would sever more than a
checked one.

Both numbers are reported. `severs` is what closes and `on_routes` is what it
sits on, and where they differ the UI says so — a customer told four routes
close who then sees two remain stops believing the next number too. The severed
routes are named as well as counted: a count is a claim, and those are its
working.

`CONTAINS` is never a candidate. A storage account has to live somewhere, so
offering "stop the resource group containing it" is a recommendation nobody can
take — the same reason `Path.cheapest_break` skips it.

Attack paths only, not escalation chains. They answer a different question, and
one count spanning both would make "routes" mean two things in a single
sentence.

Its own endpoint and its own query, fetched only once the page has routes to be
about. It costs a re-traversal per candidate, and the list is read far more often
than the question is asked.

**Not wired into the remediation queue.** A choke point is a change to make and
frequently corresponds to no finding at all — the shared role assignment may be
perfectly ordinary in isolation. Turning one into a queue item would mean
minting work with no finding behind it, which is a decision about what the queue
*is*, not a detail of this analysis.

---

## 50. Every colour is lit for the surface it sits on

The theme had two blocks, light and dark, and the dark one was not a re-lighting
of the light one so much as a partial copy of it. Measuring every pair found
three things wrong, and they are the same mistake in three places: a colour
chosen against one background and then used against another.

**The chart ramp was one greyscale in both blocks.** `--chart-1` through `-5`
ran 0.87 → 0.269 in lightness, which is a ramp built to sit on white. On the
light page the top of it measured 1.48:1 and was invisible; on the dark page the
bottom measured 1.31:1 and was invisible. Each mode now runs from its own
surface outward, every step clearing 3:1 against both the page and the card,
because a chart lives inside a card.

**`bg-ok text-white` measured 1.95:1 in dark.** `--sev-ok` is a light green
there, as it has to be, and white on it is unreadable. The fix is
`text-background` rather than a new token: it is white in light mode and near
black in dark, it was already the idiom two lines away in the same component,
and it cannot drift from the surface because it *is* the surface.

**Two statuses were written in Tailwind palette classes.** `bg-stone-50` and
`bg-white` in `format.ts` do not flip with the theme, so on a dark page the
"not covered" cell — the quietest status in the product — rendered as the
brightest block on the screen. They are separated by fill and a dashed border
now, not by a hardcoded grey.

The chrome moved as little as possible around those: `--muted-foreground` from
4.73:1 to 5.51:1 (it is every secondary line in the product, and it sat close
enough to the AA line that antialiasing decided it), `--ring` from 2.59:1 to
4.28:1 (the focus indicator is `focus-visible:border-ring` at full opacity, so
that value is what WCAG 1.4.11 measures — the `/50` ring beside it is a halo),
and the two severities under 5:1 on their own tint nudged just past it with
their hues untouched.

One thing was removed rather than adjusted: `--sidebar-primary` in dark was
shadcn's default indigo, the only saturated hue in the chrome of either theme.
An accent that appears in one mode and not the other reads as a bug, and in this
product a colour that means nothing sits badly beside a scale where every colour
means something.

**The rule this leaves.** A colour is not correct or incorrect on its own, only
against a surface — so a token defined in one block is not done until it has
been measured in the other, and a component that names a palette colour has
opted out of the theme rather than styled itself.

---

## 51. Retention keeps the present, whatever the window says

Two things grew without bound and neither had ever been pruned: the raw captures
in `cloud_snapshots`, and the content-addressed payloads in `evidence_blobs`.
Both are the largest rows in the schema and both are kept for real reasons — a
capture is what lets a scan be re-evaluated against improved rules, a payload is
what a citation points at — and neither reason survives indefinitely.

**The newest capture of each scope is never pruned, whatever the window says.**
It is what an *applied* replay reads: replaying the newest snapshots may resolve
findings, while every older one is `evaluation_only` and may not. Pruning it
raises nothing — it turns "did the fix work" into an advisory answer, months
later, on the path the north-star metric runs through. So it is excluded by
construction rather than by choosing a window long enough that it probably will
not happen.

Two scopes, not one. A subscription's resources and the tenant directory read
through a connection are different things, and a tenant-wide replay restores the
directory beside each subscription — pruned out from under it, the identity
rules read nothing while the subscription rules carry on, which is a replay that
half worked.

**Payloads are measured from `last_seen_at`, not `first_stored_at`,** which is
the whole reason that column exists. An estate that has not changed in six
months stores one copy and touches it on every scan; measuring from first
storage would delete the payload behind every current reading, which is
deduplication working against itself.

**And pruning a payload invalidates nothing that cited it.** `finding_evidence`
copies the hash rather than holding a foreign key, so a finding raised last year
still says truthfully what was read, when, and under which permission — the API
reports the payload as unavailable rather than offering a link that fails. That
was designed in §50's neighbourhood before there was anything to prune; this is
the entry that makes use of it.

Evidence *rows* are deliberately not pruned. They are one row per key per
subscription per scan against a payload that is the listing itself, and deleting
the record of what was read to save the size of the record of what was read is
the wrong trade — it is also the trade that makes an old finding unanswerable.

Windows are settings (`snapshot_retention_days` 30, `evidence_retention_days`
90) with defaults rather than required values: a missing one costs disk, not
correctness, which is not the kind of misconfiguration the rest of `config.py`
refuses to boot on.

---

## Settings: the evidence a person supplies

`PATCH /organizations` takes no id in the path. Deleting a *different*
organization from the one on screen is a real thing to want and DELETE keeps
its id; editing one is not, so the target comes from the tenant context and the
membership check has already happened.

Two write shapes sit on this screen and they are deliberately opposite. The
organization profile is patched — only the fields sent are written, so saving a
corrected name cannot clear a country nobody touched. A context declaration is
a *statement*, replaced whole, so a reader always knows what it currently
claims without diffing. `UNKNOWN` is refused by the API and absent from the
menus for the same reason: it is CloudGuard's own answer for "nothing said
anything", and a customer declaring it would assert an absence that leaving the
field unset already asserts.

Declarations are not retroactive and the screen says so. A risk score is what a
scan concluded; rewriting stored scores from a form would leave findings
carrying numbers no observation ever produced.

## Open items carried forward

**The security score floors at zero quickly.** The deductions in
`RISK_ENGINE.md` §3 are −20 per Critical-band finding, so five of them reach
zero. The demo environment scores 0/100 before remediation and 52/100 after.
This is the specified formula and it is honest, but it loses resolution at the
bad end: an organization with five Critical findings and one with fifty both
read 0. The spec anticipates tuning these values against real environments;
`app/risk/config.py` is where that happens, and no rule logic needs to change.

**Phase 9 (reports) is built, generated on request rather than stored.**
Jinja2 renders the report to HTML and WeasyPrint prints that HTML — the stack
`ARCHITECTURE.md` §1 already named. Three choices there are worth keeping:

* **No jobs table, no artifact store.** A report is a read of data that is
  already computed, and the technical report is bounded at
  `MAX_TECHNICAL_FINDINGS` so it cannot grow into something that needs a queue.
  Storing PDFs would additionally owe the customer an answer about which of
  five stored copies is current; regenerating is cheap and always truthful.
* **HTML is the artifact, PDF is the wrapper.** `render_html` is what the
  templates produce and what the tests assert against; `render_pdf` prints it.
  This is not only for testing: WeasyPrint needs native pango/cairo/harfbuzz
  that a developer machine may lack, so the import is lazy and a server without
  them answers 503 with one clear sentence instead of failing every import that
  transitively reaches the module.
* **The trend is drawn on a fixed 0–100 scale.** The report is asked whether
  posture is improving, and a sparkline fitted to its own observed range makes
  a wobble from 81 to 84 climb as steeply as a recovery from 20 to 84. Inline
  SVG, generated by a pure function, because a PDF has no JavaScript and
  nothing in a report may fetch anything. Fewer than two readings draws
  nothing: a line through one point shows a direction nobody measured.
* **The caveats are printed, not hovered.** A PDF outlives the screen it was
  taken from and gets forwarded to auditors and boards, so the cover carries
  when the evidence was collected, how many checks reached no verdict, what
  could not be read at all, and that compliance coverage is evidence rather than
  a verdict. UNKNOWN never renders as a pass, on paper as on screen, and an
  accepted risk is counted in its own right rather than absorbed into
  "not open" — it is a decision to live with a finding, not a fix.

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
