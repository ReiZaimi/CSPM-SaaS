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

## 52. The asset graph is cached against its data, not against a clock

Six callers build the graph and four are request handlers — the attack-path
list, choke points, blast radius, and a finding's routes. Every one read the
whole tenant, every present asset and every edge, and somebody clicking between
those screens paid for it each time. On the one page where a tenant large enough
to have interesting paths is also large enough to be slow.

**Cached on the version of the data rather than on a TTL.** A time-based cache
would make these pages briefly wrong after every scan, and briefly wrong here
means telling somebody an attacker can still reach their data through a route
they closed this morning. §"the graph holds present assets" already established
that a stale path is not a weaker claim than a real one, it is a false one — a
TTL would reintroduce exactly that, on a timer.

The version is three aggregates: the newest `cloud_resources.updated_at`, the
newest `resource_relationships.created_at`, and the count of present assets. The
count is not redundant. A scan that only *removed* an asset moves no timestamp —
the rows that remain were not touched, and the one that went is not there to
carry a time — so without it the graph would go on serving routes through
something no longer in the estate.

Keyed on the data rather than on "the newest scan", though a scan is the only
thing that rewrites assets today. Keying on the scan would be an inference about
which processes write, and the day something else does — a context declaration
applied in place, a manual edit — the cache goes stale silently.

Bounded at eight tenants, LRU. This is a read cache in a process that serves
every customer, and holding a graph per tenant for the life of the process
trades a latency problem for a memory one whose size is a function of how many
customers happened to open one page.

The scan pipeline does not read it: `_correlate_paths` builds from the
normalized state in hand, so it can neither be served a stale graph nor leave
one behind.

---

## 53. The capture is stored twice, and the gate on stopping

`cloud_snapshots.data` holds a whole capture per scan. The per-key payloads in
`evidence_blobs` hold the same bytes, split by reading and content-addressed.
The difference is that the second is deduplicated and the first is not: a daily
scan of an estate that has not changed writes one payload set and a **fresh full
capture every night**, for as long as retention keeps it.

That is worth fixing by making `cloud_snapshots` a manifest — the keys and
hashes of its readings — and rebuilding the capture from blobs on replay. It is
not worth doing on an assumption, which is why `test_evidence_store.py` has
carried the precondition since evidence was per-key: *replay reads
`cloud_snapshots` and must keep doing so until reconstruction holds against real
scans.*

So the gate ships before the change. `TestCaptureReconstruction` asserts, on a
real pipeline run, that the stored readings rebuild the capture exactly, and
that a second scan of an unchanged estate adds no payloads while adding a whole
capture.

**The case a careless flip gets wrong,** and the reason a unit test was not
enough: a task can produce more than one payload key. `authentication_methods`
has no task of its own — the directory's role-map task reads it — so a
reconstruction keyed by task rather than merged by payload drops it, and the MFA
rule then finds nothing to judge while reporting no error at all.

**Two lifetimes to reconcile before flipping.** Captures are pruned at 30 days
and payloads at 90, and the two are independent today because neither depends on
the other. A manifest makes captures depend on payloads, so `prune_blobs` would
have to refuse any hash a retained manifest still names — otherwise retention
would quietly destroy a capture that is inside its own window.

---

## 54. The capture is a manifest, and retention is now interlocked with it

§53 named the waste and shipped the gate. `TestCaptureReconstruction` passed
against real scans, so the flip: `cloud_snapshots` stores everything the capture
recorded *except* the payloads, plus the content hash of each reading. The
payloads live once in `evidence_blobs`, shared by every scan that read identical
bytes.

`data` is kept and made nullable rather than dropped. Captures written before
this carry their payloads inline and must go on being replayable, so the read
path takes whichever it finds — and dropping a column holding the only copy of
anything is not a migration anybody should be able to run by accident.

**A missing blob is refused, not skipped.** `SnapshotUnavailable` rather than a
partial rebuild: half a capture replays as an estate missing whatever the other
half held, and that replay may resolve findings. A resolution reached by
omission is the same overclaim as a PASS nobody earned, arrived at from a
direction the rule engine cannot see.

**The dependency this created, and the interlock that answers it.** A capture
used to be self-contained. It now points at blobs, so a blob can be the only
copy of part of a capture that is well inside its own window — and the two have
different windows (30 days and 90). `prune_blobs` therefore keeps any hash a
surviving manifest still names, whatever its age says. Without it, retention
would delete nothing visibly and fail months later, at the one moment somebody
replays a capture to check whether a fix held.

Two things the tests had to be corrected about while building this, both the
same mistake in different clothes: a fake matched `payload_hashes` in SQL text,
where it is a bound parameter of the `->` operator and never appears; and a fake
`DELETE` reported no rowcount, so every prune looked like a no-op regardless of
what it named. Each made a test pass by proving the opposite of its name.

**And the column default that made all of this fail in CI.**
`cloud_snapshots.data` was created in 0001 as `jsonb NOT NULL DEFAULT
'{}'::jsonb`. 0027 stopped writing the column and dropped its NOT NULL — and
left the default. So every capture written after the flip came back holding an
empty object rather than NULL, and `_rebuild_capture`, which chose between the
inline and manifest forms by asking whether `data` was NULL, took the inline
branch and rebuilt an estate with nothing in it.

Nothing failed where the mistake was. Collection succeeded, the capture was
stored, the payloads were stored, the manifest was correct — and then every
scan died in ANALYZE with `KeyError: 'provider'` on a capture that was
perfectly good. Sixty integration tests failed, all of them downstream of the
one question asked the wrong way round.

The fix is 0029 and a changed question. The default goes, and the rows already
written that way are set back to NULL — guarded on `manifest IS NOT NULL`,
which names exactly the captures written since 0027 and cannot touch a pre-0027
capture that genuinely held an empty object. And `_rebuild_capture` now decides
the form from the *manifest*, because the manifest is the thing that is present
in one form and absent in the other. A column with a default cannot answer "did
anybody write this", and the general lesson is that a nullable column is only a
reliable "unset" signal once its default is gone too.

**A failed listing that returned nothing used to cost no verdict at all.**
A rule reports UNKNOWN from inside `evaluate`, and `evaluate` runs once per
matching resource. So a rule whose evidence failed to collect had nothing to
iterate over and produced nothing: no verdict, no gap row, and a coverage ratio
computed over the rules that happened to have something to look at. Failing to
look cost less than looking and finding a problem — the same overclaim as a
PASS nobody earned, arrived at through silence rather than through a wrong
answer.

It survived this long because a fixture hid it. The recorded snapshot carried
its storage listing even when the test marked storage as failed, so the rules
had resources to iterate and degraded correctly. A real run has no such
listing, and neither does a capture rebuilt from a manifest, which is why §54
surfaced it.

`RuleEngine._run_per_resource` now records one UNKNOWN when a rule matched
nothing *and* its declared `requires_evidence` names a listing that failed. The
two conditions together are the whole point: no resources plus no error is a
customer who has none of them, which is NOT_APPLICABLE and correctly excluded
from the coverage ratio; no resources plus a failed listing is nobody having
looked. The gap carries no `resource_id`, because there is no asset to
attribute it to — that absence *is* the finding about the scan.

**A request must not commit the transaction it was handed.**
`rls_session` wraps a whole request in `session.begin()` and declares who is
asking with `SET LOCAL ROLE authenticated` and `request.jwt.claims`. Both are
transaction-scoped — which is what stops them leaking to the next checkout of a
pooled connection, and equally means a commit inside a request tears down the
settings every RLS policy reads. `commit_unless_externally_managed` exists for
exactly this, and is a no-op under a session that owns its transaction.

`set_change_events` called `session.commit()` directly, the only one of eleven
writes in that file that did. Turning change detection *off* worked, because
nothing ran afterwards. Turning it *on* did not: the route goes on to build the
Event Grid wiring commands, which reads the connection's subscriptions, and
that read ran as the bare `cloudguard_app` role with no claims.

The guard is now a test over `app/services/`, not over the one function that
had it, with per-function exemptions for the code that opens its own session —
per function rather than per module, because `scans.py` holds both the worker's
reaper and endpoints a request reaches, and exempting the file would exempt
those too.

**And the failure was invisible from the browser, which is the worse half.**
The API registered handlers for `AppError`, `HTTPException` and
`RequestValidationError`, and nothing else. Anything unanticipated escaped to
Starlette's `ServerErrorMiddleware`, which sits *outside* `CORSMiddleware`, so
its 500 carried no `Access-Control-Allow-Origin` and the browser refused to
read it. `fetch` then rejected with `TypeError: Failed to fetch` — what a
browser says when a request never arrived at all. So a server-side bug was
indistinguishable from the API being unreachable, and the connections page
reported a network failure for a request that had arrived, run, and raised.

Registering a handler for bare `Exception` does not fix this: Starlette
special-cases that one and hands it to the same outermost layer.
`UnhandledErrorMiddleware` sits inside CORS instead — `main.py` adds it first,
and `add_middleware` inserts at the front, so the last one added is outermost.
The response carries the envelope and a sentence; the stack trace goes to the
log, because rendering one into a browser is a disclosure and this is a
security product.

---

## 56. Rules are bounded by collectors, not by ambition

The catalogue went from 10 rules to 17, and what decided *which* seven is worth
recording, because the obvious approach produces a worse product.

A CSPM is expected to check key vault configuration, database auditing, disk
encryption, activity logs, credential expiry, vulnerabilities and backups.
CloudGuard collects none of those. A rule for each would have been quick to
write and would have answered UNKNOWN for every customer for ever — a catalogue
that looks complete and says nothing, which is the same overclaim as a PASS
nobody earned wearing different clothes. So the rule set is bounded by the 16
evidence keys that exist, and grows when a collector does.

**The RBAC family needed no new collection, and that is why it went first.**
Role assignments were already read for the graph. What was missing was smaller
and stranger: the normalizer recorded a role's *name* only on principals it
minted, never on directory users, on the stated grounds that a traversal reads
the edges anyway. True of a traversal, false of a rule — an edge says a
principal reaches a scope and cannot say as what. "This named person holds Owner
over your subscription" was therefore a fact CloudGuard collected, drew a line
for, and could not state. Three rules fell out of fixing that one line.

`AZ-IAM-003` reads the role *definition's permissions* rather than its name,
because Owner and Contributor both carry `actions: ["*"]` and only Contributor
excludes the assignment write. A name-based check would flag every Contributor
on nearly every subscription in existence, which is how a whole feature gets
switched off.

**Three guard tests caught omissions in this work, and each was fixed in the
code rather than in the test.** `ROLE_DEFINITIONS` carried a seven-day reuse
window justified by "no rule reads them"; `AZ-IAM-003` made that false, so a
customer editing a custom role to remove escalation and rescanning would have
been answered from last week's catalogue — `_REUSE_WINDOWS` is now empty. Every
rule must carry a machine-readable remediation, and the RBAC rules legitimately
have no expected state, so they take the documented empty form that owes a
reason and a command. And `applies_when` could only express metadata, so
`AZ-DB-002` — whose expectation is about a database *holding sensitive data* —
was handed a synthetic asset it declined to judge, and its round-trip test
passed by never running. It now accepts the classification fields the normalizer
computes.

**Scoping is a design decision, not a filter.** `AZ-DB-002` returns
NOT_APPLICABLE below HIGH sensitivity, and a shared-key-access rule was written
and then not shipped: shared key is on by default, so it would have fired on
essentially every storage account in existence. A rule that fires everywhere
teaches people to stop reading, and the cost lands on the finding next to it.

---

## 57. The scanner role reads a vault's configuration and none of its contents

Key vault was the largest gap in the catalogue and the first one closed by
adding collection rather than by writing rules against evidence that already
existed. It is worth recording as a shape, because every remaining gap —
database auditing, disk encryption, activity logs — is the same shape.

**One action, and precisely one.** `Microsoft.KeyVault/vaults/read` is the
management plane: whether the vault can be purged, whether it answers the
public internet, which authorization model it uses. It grants nothing over the
keys, secrets and certificates inside, which live behind
`Microsoft.KeyVault/vaults/secrets/read` and a separate permission model that
CloudGuard does not request and should never request. A product that can tell a
customer their vault is destroyable *without being able to read a single secret
in it* is making a stronger claim than one that can do both, and a test asserts
the role holds no other `Microsoft.KeyVault/` action so that stays true.

**The role is versioned, so the cost lands as a prompt rather than a 403.**
`ROLE_HISTORY` gains a `v3` entry written out literally beside v1 and v2 — never
by reference, for the reason recorded in that file. A customer still on v2 keeps
every other category and loses only the vault checks, which then report UNKNOWN;
`categories_behind("v2")` is exactly `{SECRETS}`, and a test says so, because an
upgrade that quietly cost them an unrelated category would be worse than the gap
it closed.

**Absent and false are different answers, and Azure means different things by
them.** `enableSoftDelete` comes back as a value; `enablePurgeProtection` is
omitted when it has never been set. So AZ-KV-001 reads a missing purge
protection as off and a missing soft delete as missing — reversed, the rule
would either report nothing for the overwhelming majority of vaults that
genuinely lack purge protection, or report a gap CloudGuard invented.

**Sensitivity comes from the context engine, not from the normalizer.** A vault
holds the credentials to everything else, so an untagged one is not an
unclassified asset. That is expressed by adding `KEY_VAULT` to
`DATA_HOLDING_TYPES`, which carries the `TYPE_FLOOR` source with it — a first
attempt overrode criticality inside the normalizer instead, which would have
produced a HIGH nobody could trace to a reason.

**And check whether the gap costs a permission before assuming it does.** The
subscription activity log looked like the next role bump and was not. A
subscription is a scope diagnostic settings apply to like any other, so
`Microsoft.Insights/diagnosticSettings/read` — granted since v1 — already
reaches it, and the collector simply asks about one more id. AZ-LOG-002 is
therefore live for every existing customer with no redeploy, which is worth more
than the two vault rules that need one.

The two logging rules divide cleanly and must keep doing so. AZ-LOG-001 asks
whether a resource records what happens *to* it; AZ-LOG-002 asks whether the
subscription records *who did it*, across every resource including the ones that
no longer exist. A test asserts AZ-LOG-002 applies to subscriptions and nothing
else — if both claimed the same asset, one problem would be raised twice with
two different fixes.

---

## 58. v4 grants one action, because two of the three candidates were not worth one

The plan going into v4 was SQL auditing, transparent data encryption and
managed disk encryption, batched into a single redeploy prompt rather than
three. Two of the three did not survive being looked at.

**Transparent data encryption has been on by default since 2017**, and
**managed disks are always encrypted at rest and cannot be turned off**. Checks
for either would have cost a permission, a per-database fan-out, and a place in
the catalogue, to report PASS for very nearly every customer. That is how a rule
set grows in size and shrinks in signal — the failure mode ROADMAP.md warns
about, arrived at through diligence rather than laziness.

**SQL auditing is the opposite and is the whole of v4.** It is off by default on
every Azure SQL server, so it is a setting most customers have never turned on
rather than one they turned off. It costs one call per server, folded into the
task that already lists them, and it pairs with AZ-DB-001: a publicly reachable
database with no audit trail is the worst combination this catalogue can
describe, and the auditing finding carries `public_network_access` in its
evidence so the two read together.

**The rule declares no expected state, and that is the honest form.**
`Comparison` offers three checks and says in its own docstring that anything
they cannot express stays undeclared rather than half-declared. AZ-DB-003 checks
two things about one nested setting — auditing is on, and it writes somewhere —
which none of the three express. A declaration saying only "state is Enabled"
would have a customer satisfy exactly what they were shown, still be auditing to
nowhere, and watch the finding stay open. So the spec is the empty form, with
the reason in `notes` and the commands still handed over.

**Two failure modes, reported apart.** Off is a switch; on-with-no-destination
is the setting people believe they have. The fix differs, so the finding says
which it found.

**And the UNKNOWN names the role.** A customer still on v3 gets a 403 on this
one call while the server listing and firewall rules succeed, so every SQL
server they own reports UNKNOWN. The message says the deployed role may predate
the permission, because an unexplained UNKNOWN on every database is worse than
the gap it describes.

---

## 59. The access panel stopped calling a stale role verified

`role_upgrade_available` has been on the connection payload since role versions
existed, computed correctly, and read by nothing. So bumping the role to ship a
check — twice in a week, v3 for key vaults and v4 for SQL auditing — left every
existing customer collecting UNKNOWN across whole categories while the access
panel printed their role in the same green as a current one, next to the word
"verified".

That is the failure `role_upgrade_available`'s own docstring says the mechanism
exists to prevent, reached anyway because the last step was never taken. A
backend that knows and a screen that does not is indistinguishable from a
backend that does not know.

**Three states, not two.** The role is now green when current, red when never
granted, and amber when behind. Behind is not a failure — most checks are
running on it — and painting it red would send somebody to fix an outage they do
not have.

**Named, not counted.** "Two categories are degraded" is a notification;
"Databases, Key vaults" is a decision. The categories come from
`degraded_categories`, the same function the scanner uses to explain its own
gaps, so the screen and the scan cannot disagree about which checks are
affected. The customer-facing labels live in the frontend — `secrets` is what
the permission model calls a key vault, and "Key vault" is what the customer
went looking for.

**The panel states the invariant where it is felt.** The affected checks report
"not known" rather than passing, and the alert says so: a customer who assumed
silence meant a pass would draw exactly the wrong conclusion, and this is the
one screen where that assumption is most tempting.

**The redeploy link is the setup wizard's link.** Redeploying is deploying again
— the template carries the current role definition — so a second route would be
inventing one, and it is omitted entirely when there is no template URL to point
at, because a dead button is worse than none.

**And the seam test earned its keep.** The first attempt imported
`rbac.ROLE_VERSION` straight into the route to report which version to redeploy
toward. The route layer is provider-neutral and a role version is not, so it now
asks `required_role_version`, which returns `None` for a provider with no such
notion.

**The collection panel was not the liar; the SQL task was.** The panel reports
each reading's outcome, and the SQL reading came back COMPLETE while every
auditing verdict was UNKNOWN. That task makes three calls -- the servers, then
each server's firewall rules and auditing settings -- and a per-server failure
was recorded on the server for the rules to degrade on and nowhere else. So the
one screen whose job is saying what was and was not read said everything was.
A role predating v4 produces exactly this: a 403 on every auditing call while
the listing and firewall rules succeed. `_arm_task` now accepts a `TaskData`
from a call that knows something about its own completeness the wrapper cannot
see, and reports both reasons when a truncated listing and a half-read server
apply at once.

**And the invariant was stated for PARTIAL and nowhere else.** A scan where
storage failed outright showed a badge, a count, and no word about what it cost
-- leaving "could not read" free to be read as "nothing to report", which is the
one inference this product exists to prevent. Two sentences rather than one
covering both, because the reasons differ: an incomplete listing cannot support
a pass, and an absent one supports nothing at all.

`degraded_categories` on the collection payload is deliberately still not
rendered. It rolls up the same per-reading outcomes the list underneath already
shows one by one, and a summary that repeats the thing below it adds a place for
the two to disagree rather than a fact.

**And making that PARTIAL truthful exposed the next layer of the same
mistake.** A rule degrades on the evidence *keys* it declares, and the SQL
listing was one key covering three calls -- the servers, their firewall rules,
and their auditing settings. So the moment a refused auditing read correctly
made the reading PARTIAL, it also took AZ-DB-001's verdict, over a call that
rule never reads. That is the gap CloudGuard invents rather than finds, and it
is precisely what `requires_evidence` was introduced to stop when rules named
whole categories instead of keys. The same error, one layer down: a key naming
three calls is a category wearing a key's name.

Auditing is now its own key and its own dependent task, keyed per server the
way diagnostics is. AZ-DB-001 declares `SQL_SERVERS`; AZ-DB-003 declares both,
because without the listing there are no servers to judge and without the
auditing read there is no posture to judge them on. A role predating v4 now
costs exactly one rule its verdict, and the reading's detail names the role as
the likely cause rather than leaving a v3 customer with an unexplained partial
on every scan.

The general form, worth stating because there will be a next one: **an evidence
key is the unit a rule depends on, so two calls belong under one key only when
no rule could depend on one without the other.** Separately deniable means
separately keyed.

**`RESOURCES` was checked for the same defect and does not have it — it has a
different one.** No rule declares the inventory, so a failed Resource Graph
query costs no check its verdict; every rule reads its own service listing
instead. Two tests now hold that, and hold the pair to it: the key stays in
`baseline_evidence`, because a plan derived from the rule set would otherwise
stop collecting it silently.

What was wrong was the justification. `BASELINE_EVIDENCE` claimed the customer's
asset list was made of the inventory, and it is not — every asset CloudGuard
shows comes from the per-service listings, normalized into `cloud_resources`.
The Resource Graph payload is stored verbatim in every snapshot and read by
nothing, anywhere. Both docstrings also said "these three" for a set of five,
the two control readings having been added without updating the count.

So the honest statement got written down — and then built. The inventory is the
one reading that covers resource types no rule has been written for, and the
asset list now says so.

**Resources no service listing produced become assets carrying
`ResourceType.UNKNOWN`.** That type is the load-bearing part: no rule's
`applies_to` names it, so nothing judges them and none can become a PASS nobody
earned. They are counted, listed, and reported as unchecked — which is a fact
about CloudGuard's limits rather than about the customer's estate, and the one
thing a customer cannot work out for themselves.

**Nothing is counted twice.** The inventory covers the same storage accounts the
storage listing already produced, in far less detail, so it is filtered against
the assets already normalized — including against itself, since a repeated
Resource Graph row would otherwise be a repeated asset. Two rows for one asset
would be an inventory that miscounts and a graph holding the same thing twice.

**The real Azure type travels with them.** A list row reading "Unknown" would be
a worse answer than the omission it replaced: the point of showing these is that
the customer can see *what* is unchecked, not merely how many. `azure_type` is
null for a modelled asset, whose cloud-neutral label is the better one.

**Exposure stays UNKNOWN rather than LOW.** Resource Graph's projection excludes
`properties` deliberately, so there is no configuration here to establish
exposure from, and LOW would be reassurance CloudGuard did not earn.

**The count is phrased as a limit, not a percentage.** "35 with no checks yet"
rather than "74% coverage": a percentage invites the reader to feel good about a
high one, and the useful question is which resources are unexamined.

---

## 60. A control says why it is inconclusive, not only that it is

The compliance page already distinguished the five verdicts properly — labels,
dashed styling for INCONCLUSIVE so a control CloudGuard could not evaluate never
looks like one it cleared, and NOT_COVERED quieter still. That part was right and
stays.

What it could not answer was the question INCONCLUSIVE raises and the other four
do not. FAILING points at findings. PASSING needs nothing. NOT_COVERED is a fact
about CloudGuard with no action behind it. NOT_ASSESSED resolves itself on the
next scan. "Three rules could not be evaluated" points nowhere — and the
sentence that answers it has been sitting in `scan_evaluation_gaps` since
UNKNOWN became a recorded outcome, written by the rule that gave up, and never
read by this view.

It matters more than it did. Since the scanner role started gaining permissions,
the answer is frequently "your deployed role predates the permission this
needs", which is a thing a customer can act on this afternoon — and the access
panel now says the same thing one screen over, so the two agree.

**Distinct per rule, and capped at three.** The ledger holds one row per
resource, so forty storage accounts that failed for one reason are one sentence.
A tuple rather than a single string because one rule can fail differently on
different resources — a listing that timed out and a configuration that never
arrived are two causes, and collapsing them would name the wrong one for half
the assets. Past the cap it is a scan-level question, and the collection panel
answers it in full.

**The explanation never softens the verdict.** Knowing why CloudGuard could not
look is not the same as having looked, and a test says so explicitly: an
explained UNKNOWN is still INCONCLUSIVE, and a failing rule still outranks it.
This is the one screen somebody might put in front of an auditor.

The page had no test at all before this. It has five now, including the one that
matters most: a control nothing checks and a control that could not tell must
never render the same.

**And one flaky test found on the way, fixed rather than tolerated.** The
finding detail page draws on three independent queries — the finding, its attack
paths, its provenance — which settle in whatever order they settle in. A test
awaited the first sentence and then read two more synchronously, which proves
nothing about the second and third, and lost the race whenever the machine was
busy. Every assertion awaits now.

Worth recording how it was nearly missed: the suite had been run as
`npx vitest run … | tail`, and a pipeline reports the exit code of its *last*
stage, so vitest's failure read as a pass. A verification command that cannot
fail is not a verification command.

**And a React key warning that had been scrolling past in green runs.** The
assets table renders each group as a heading row plus its assets, wrapped in a
`<>` fragment returned from a `.map()`. The rows inside were keyed all along,
which is what made it look fine — but the *wrapper* is what sits in the list,
and the shorthand fragment cannot take a key. React answers a list child it
cannot identify by reusing the wrong DOM under a changed key: rows appearing
under the wrong heading after a regrouping, invisible to any test asserting on
first paint.

The instance is a one-line fix, `<Fragment key={groupName}>`. The interesting
part is that a test asserting on the console does **not** hold it: React
de-duplicates these per call site, so such a test catches the warning only if it
happens to run before every other test that renders the same component. Written
that way it passed with the fix reverted — which is worse than no test, because
it reports a guarantee it does not provide.

So the guard is in the shared test setup instead, and fails any test that
produces one. Narrow on purpose: failing every `console.error` would fail tests
deliberately exercising error paths, and the class worth catching here is
specific. Verified the honest way — with the fix reverted, the suite fails; with
it in place, it passes.

---

## 61. Three more frameworks, and no new scanning

NIST SP 800-53 Rev. 5, the SOC 2 Trust Services Criteria and PCI DSS v4.0.1 are
now catalogued. None of them cost a rule. That is the whole point of the mapping layer: a rule is the
reusable unit, a framework is a set of references to it, and a seventh catalogue
is a data change rather than a scanning engine. A test asserts every rule maps
to all three, and that no rule was written *for* any of them — a rule named after a
standard would be the same technical check duplicated per standard, which is the
failure the compliance layer exists to prevent.

**800-53 is a US Government work and could be quoted; SOC 2's criteria are
AICPA's and cannot.** Both are described in CloudGuard's own words anyway, so
the two pages read alike and the rule at the top of the catalogue holds without
exception. The identifiers are the durable part; `url` points at the
authoritative text.

**SOC 2 is the easiest page in this product to overreach on**, and the catalogue
is shaped to make that hard. Its criteria are mostly about whether an
organization *has* a control and operates it — CC1 through CC5 are control
environment, communication, risk assessment, monitoring and control activities,
and a scanner reads none of them. Nine of twenty-seven criteria are technically
assessable and the rest are listed unassessable rather than omitted, so the page
reports honest partial coverage instead of implying a SOC 2 report is a
configuration problem. The scope note says in as many words that only a licensed
firm can issue the opinion.

A test asserts fewer than half of SOC 2's criteria are assessable, and the first
version of the catalogue failed it at exactly half — because the catalogue was
understating how organizational the standard is, not because the assertion was
wrong. Seven more of the organizational criteria were named. That is the right
direction to resolve that failure in: the honest ratio is a fact about SOC 2,
and a catalogue that flattered CloudGuard's reach would be the thing at fault.

**Both list controls no rule covers**, as every framework here does — 800-53
covers 16 of 24, SOC 2 8 of 27. The uncovered ones are the backlog and the
never: `RA-5` and `SI-2` want vulnerability data CloudGuard does not collect,
`CC6.8` wants anti-malware status, and `PE-3` wants somebody to walk into a
building.

**PCI DSS v4.0.1 followed, and it carries the caveat that matters most.** The
standard applies to the cardholder data environment, and CloudGuard does not
know which resources are in it — scope is a decision a QSA makes with the
merchant about segmentation and data flows, and every figure on that page is
computed over the whole subscription instead. A resource group holding no card
data is counted exactly like the one that does.

That caveat is more consequential than SOC 2's, because PCI is contractual
rather than advisory: a merchant assessed against it can lose the ability to
take payments, so a page implying it had assessed them would be doing harm
rather than merely overreaching. The scope note says so first, before anything
else, and a test asserts it.

PCI's uncovered controls also divide cleanly in a way worth keeping visible.
`9.1.1`, `11.4.1`, `12.1.1` and `12.10.1` — physical access, penetration
testing, policy, incident response — are marked unassessable because no scanner
reaches them. `5.2.1`, `6.3.3` and `11.3.1` — anti-malware, patching,
vulnerability scanning — stay *assessable* and uncovered, because a scanner
could report them and this one does not collect the evidence. Backlog and never
are different answers and the catalogue distinguishes them.

**One bug I introduced and caught before it shipped.** The PCI scope note was
written with markdown emphasis around the scope caveat.
`ComplianceFramework.tsx` renders `{data.scope_note}` straight into JSX, so it
would have reached the customer as two literal asterisks — on the page that
most needs to be believed. A test now rejects markup in any framework's
customer-facing text, because the place a caveat most wants emphasis is exactly
where the next person will reach for it.

The frontend needed no change at all, which is the property worth noting: no
page branches on a framework id, so the compliance views rendered three new
catalogues the moment the API listed them.

---

## 62. Defender's findings are evidence, not verdicts to repeat

Six controls across four frameworks wanted the same thing — NIST `RA-5` and
`SI-2`, SOC 2 `CC6.8`, PCI `5.2.1`, `6.3.3` and `11.3.1` — and no ARM
configuration answers any of them. Whether a machine is patched, and whether an
agent is installed and healthy, are facts only the machine knows. Microsoft
Defender for Cloud is what knows the machine, so v5 of the scanner role reads
its assessments.

**The line worth holding is what a rule does with them.** Defender has already
reached a verdict on every asset it assesses. Mirroring those as CloudGuard
rules would turn two hundred assessments into two hundred findings, none of
which a customer could not already see in the Azure portal — a product that adds
a second inbox rather than a decision.

What CloudGuard has and Defender does not is the graph. So an assessment is read
as evidence: `AZ-VULN-001` fires only where Defender's vulnerability finding
meets CloudGuard's own knowledge that the machine answers the internet, and
returns NOT_APPLICABLE otherwise — explicitly, because Defender raises the
vulnerability on its own terms and there is nothing there CloudGuard knows that
Defender did not say better. The finding is the pairing, which neither says
alone.

**Severity stays Microsoft's, under Microsoft's name.** `provider_severity`
rather than mapped onto CloudGuard's scale: the two were tuned by different
people for different purposes, and quietly equating them would put somebody
else's judgement inside this product's risk formula.

**Only unhealthy assessments are kept.** A healthy one is Defender's verdict
rather than CloudGuard's evidence, and several hundred per subscription in every
snapshot would store a great deal to say nothing. `NotApplicable` is dropped for
a stronger reason: it frequently means the assessment could not run, and reading
it as a pass is the overclaim this engine refuses everywhere.

**And the absence is the case to get right.** A subscription with no Defender
plan returns no assessments. `security_assessments` is therefore absent on an
asset nothing assessed and an empty list on one Defender looked at and cleared —
None is UNKNOWN, `[]` is a PASS somebody earned. Reading the first as clean
would be an absence of evidence reported as evidence of absence, on the class of
finding a customer is most likely to believe.

**One catalogue correction fell out of it.** Mapping these rules gave NIST CSF
100% coverage, which `test_catalogue_lists_controls_no_rule_covers` refused —
correctly, and the fault was the catalogue rather than a mapping. CSF holds over
a hundred subcategories and this catalogue listed thirteen, all from Protect and
Detect, while its own scope note said Identify, Respond and Recover were out of
reach without naming any of them. Five are named now. The same correction as SOC
2's: a framework that reports full coverage is a catalogue understating the
framework.

---

## 63. The last two identity gaps cost a collector, not a consent

Application credential expiry and dormant privileged accounts are the two
categories `RULE_ENGINE.md` names as absent because the evidence is. Both were
assumed to be blocked behind a second Global Administrator consent — a per-tenant
ask heavier than anything CloudGuard has needed since onboarding, and worth
deciding deliberately. Checked rather than assumed, the ask is not there.

**The consent screen is already wider than the collector.**
`REQUIRED_GRAPH_PERMISSIONS` has carried `Application.Read.All` and
`AuditLog.Read.All` since the two-click redesign, alongside
`IdentityRiskyUser.Read.All`. No collector calls anything that needs any of the
three. So every tenant that has ever consented to this application granted them
at the moment they clicked, and the two gaps are collector work under permissions
already in hand — no redeploy, no re-consent, nothing to ask a customer for.

* Credential expiry reads `/applications` and `/servicePrincipals` for
  `passwordCredentials` and `keyCredentials`, which `Application.Read.All`
  covers.
* Dormancy needs no new object at all: role members are already collected. The
  missing field is `signInActivity` on `/users`, which Graph gates on
  `AuditLog.Read.All` *and* `User.Read.All` — both granted.

A tenant that consented against an older registration would be the exception,
and needs no campaign to find: `missing_permissions` reads the granted
permissions out of the token's `roles` claim and names exactly what is absent,
per tenant, on every scan.

**The real gate on dormancy is a licence, and it is not consent's problem.**
`signInActivity` requires Microsoft Entra ID P1 or P2. A Free tenant with
complete consent still gets a 403, and the fix is a licence its administrator may
have decided against on purpose. That has to degrade as its own reason: this
scan could not read sign-in activity because the tenant is not licensed for it —
UNKNOWN with a sentence, like every other gap here. Reporting it as a permission
problem would send a Global Administrator to a consent screen that cannot fix it,
which is the failure `client.py`'s access-denied hints exist to prevent.

**Why the mistake was available to make is worth fixing too.** The ARM half of
the grant asserts this exact thing: `ROLE_ONLY_ACTIONS` derives every action the
role requests that no client call reaches, and a test asserts it empty, so a
permission on a customer's consent screen that nothing uses cannot survive a
build. The Graph half has no equivalent — which is how three unused permissions
sat there long enough for the collector's reach to be read off the code rather
than off the consent screen. The same derivation belongs on the Graph side, and
it turns green as these two collectors land rather than before.

---

## 64. Both collectors landed, and an expiry date is not a finding

§63 established that application credentials and dormant accounts were a
collector rather than a consent. Building them settled four things that were
not obvious from the outside.

**An expired credential is an outage, not an exposure.** The gap was named
"application credential expiry", and the obvious rule — this secret has expired,
or expires next week — is one CloudGuard should not ship. An expired secret
grants nobody anything; an application has stopped working, which the customer's
own alerting is better placed to notice than a security tool is. What an
attacker actually gets from an expiry date is its *remaining* life: a secret
copied out of a pipeline log today keeps working until the day it was issued
for. So AZ-APP-001 asks how long a stolen credential would keep working, fails
above a year, and passes an expired one explicitly.

The registration is the asset rather than each credential. One application with
four long-lived secrets is one thing to fix, and four findings for it would be
the score charged four times for a single rotation.

Service principal credentials are deliberately not read. They exist, and reading
them means listing every service principal in the tenant — several hundred of
them Microsoft's — for the handful a customer created. That is the trade the
Conditional Access collector already made when it read back only the groups a
policy names: a directory dump for a few ids is worse than the narrower answer,
and what a customer rotates is the registration. AZ-APP-001's finding says so rather than claiming to cover
every credential in the tenant.

**A licence is not a consent, and must not be reported as one.**
`signInActivity` needs Entra ID P1 or P2 on top of the grant every tenant
already has. A free-tier tenant with complete consent is refused it with a 403 —
the same status code a missing permission produces, from the same endpoint. The
collector reads Graph's own explanation and rewrites only that case, so the
tenant is told about a licence its administrator may have declined on purpose,
rather than being sent to a consent screen that cannot fix it. Everything else
keeps the existing behaviour of naming the permissions consent did not grant.

**An age has to be measured from the capture.** Days remaining on a credential
and days since a sign-in are the first evidence in this product that is a
duration rather than a value, and a duration computed against `now()` would make
a rule a function of when it was asked instead of what it read — so a replayed
snapshot would reach a different verdict from the same JSON, and "CloudGuard
verified the fix" would mean nothing. `RawSnapshot` carries `collected_at`, it
round-trips through `to_json`, and the normalizer measures every age from it.
The rules see plain numbers and stay pure.

**And the Graph side now asserts what ARM already did.** `ROLE_ONLY_ACTIONS`
has long derived every ARM action the scanner role requests that no collector
reaches, and a test keeps it empty. Graph had no equivalent, which is exactly
how three requested-and-unused permissions went unnoticed long enough for §63's
mistake to be available. `GRAPH_PERMISSION_USE` names the call behind each
permission and a test refuses any that is neither used nor reserved.

`IdentityRiskyUser.Read.All` is the one reserved entry. Trimming it would be the
tidier-looking move and the wrong one: §63's whole point is that a permission
already on the consent screen is one a future collector spends nothing to use,
and dropping it would sell that for a shorter list. Reserved with a reason keeps
it a decision rather than an oversight.

---

## 55. A payload is stored as compressed bytes, not as JSONB

§54 removed the copies. This removes the size of what is left.

`evidence_blobs.payload` was JSONB, which is the wrong representation for what
these rows hold. A payload is a provider listing — five hundred near-identical
objects repeating the same twenty key names, the same resource-group prefix on
every id, the same `"provisioningState": "Succeeded"` on every row — and JSONB
stores that as a parsed tree with the key names held per value. PostgreSQL's
TOAST compression only engages above a couple of kilobytes, and by then the
expensive representation has already been chosen. The column is now `bytea`
holding zlib-compressed bytes: roughly a tenth of the size on this input.

**Nothing was given up, because nothing used it.** A payload is read whole, by
hash, in `_rebuild_capture` and in the evidence planner, or not at all. There is
no query anywhere that reaches into one with a JSONB operator, and the rules
read the *normalized* `CloudResource`, never the stored blob. So the JSONB
operators being lost were never load-bearing — which is the only thing that
makes this a size change rather than a capability change.

**The stored bytes are the hashed bytes.** `canonical()` is the one
serialization the content hash is ever taken over, and it is that exact byte
string that gets compressed and written. So a stored payload is checkable
against the hash it is filed under: inflate, hash, compare, which is what
`test_a_stored_payload_still_hashes_to_the_hash_it_is_filed_under` does against
real scans. A version that compressed a fresh `json.dumps` would round-trip to
an equal dict through a different byte string, and that check would become a
coin toss between a real corruption and a whitespace difference.

**zlib rather than zstd.** zstd would get perhaps a fifth off zlib's result on
this input, at the price of a native wheel in the API image, the worker image
and CI, for bytes already an order of magnitude down. The compression also runs
on the scan's hot path, so the level is 6 rather than 9: level 9 spends
noticeably longer for low single digits on JSON this repetitive.

**No backfill, and a CHECK instead.** Rewriting every historical payload is a
long write on the largest table in the schema, and retention retires those rows
on its own schedule anyway — so `payload` is kept, made nullable, and read as a
fallback, exactly as §54 kept `cloud_snapshots.data`. What 0028 does add is a
CHECK that a row holds one form or the other. Without it, a row that had lost
its bytes would read back as `{}`, and an empty payload is a real thing a
subscription with no storage accounts produces: "the bytes are gone" would be
indistinguishable from "there was nothing there", which is the same class of
error as UNKNOWN being read as PASS.

The downgrade inflates the compressed rows back into `payload` before dropping
the column, in Python and a page at a time. PostgreSQL ships no zlib inflate —
`pg_column_compression` reports how a value is TOASTed and nothing undoes an
application-level `zlib.compress` — so a SQL-only downgrade would have had to
discard every reading taken while compression was in use.

**And the write path stopped reading what it was about to skip.** `_store_blobs`
loaded whole `EvidenceBlob` rows to decide which payloads were already stored,
then set `last_seen_at` on them. On an unchanged estate — the case content
addressing exists for, and the common one — that read every payload it already
held back out of PostgreSQL, decompressed nothing, used none of it, and wrote a
timestamp. It now selects the hashes alone and touches them with one `UPDATE`,
guarded by `last_seen_at < observed_at` so a replay of a capture collected in
March cannot make its payloads look freshly read.

---

## 65. What holds a step, what stops two scans, and what a tenant may keep

Five production problems in the scanning path, all of them invisible in a
demo tenant and all of them certain in a large one. They are recorded together
because four of the five are the same mistake in different places: a mechanism
that was correct about the state it wrote and silent about who was entitled to
write it.

**A step is fenced by the attempt it was claimed under.** The lease made a
redeploy survivable: a step that stops renewing is returned to PENDING and run
again elsewhere. What it did not handle is the worker coming back. A process
paused past its lease -- a throttled container, a database stall, a long
garbage collection -- has not died, and it finished its collection minutes
later and marked the step SUCCEEDED while another worker was in the middle of
the same step. ANALYZE waits on collection *settling*, so the scan then
interpreted a subscription still being written and reported it as a complete
reading: the same overclaim as a PASS nobody earned, arriving through the
orchestrator instead of through a rule. Renewals and settles are now
conditional on the row still carrying the attempt the worker claimed, and a
worker that lost its step writes nothing. The renewal fence matters as much as
the settle: unfenced, the returning worker kept alive the lease of a step
somebody else was running, so the mechanism that reports a lost step was the
thing concealing that two workers held it.

**The lease is held by a clock, not by whatever the phase reports.** Renewal
used to happen inside collection's progress callback, which covered one of the
three step kinds. ANALYZE -- reconstructing every capture, evaluating every
rule, scoring every finding, the longest thing a scan does -- renewed nothing.
A tenant whose analysis ran past `ScanStep.LEASE_SECONDS` had its step reaped
mid-evaluation and restarted while the first was still writing, so the one case
where the reaper reliably fired was the case where nothing had gone wrong, and
it fired more reliably the larger the tenant. A background keeper now renews on
a fraction of the window for every kind of step, and a refused renewal stops the
work at the next opportunity rather than spending the customer's Azure quota on
a capture that will be discarded.

**One target, one lock.** Starting a scan takes a transaction-scoped advisory
lock and then checks whether one is already in flight. The lock was keyed on
whichever ids the caller happened to hold, and the callers do not agree: the API
and the rescan button pass a connection *and* the subscription they resolved it
from, while the scheduler, the change trigger and the verification sweep pass
the connection alone. Those are two different locks over one connection, so a
customer pressing "Scan now" at the moment the scheduler started the same
connection got two scans writing findings for the same resources -- and the
unique index on (organization, rule, resource) turned the overlap into a scan
that failed with nothing a customer could read. The key is now the connection
wherever there is one, which is exactly the set the in-flight check treats as
overlapping.

**A lost message no longer strands a scan.** `unfinished_scan_ids` was written
as the safety net for an advance message the broker never delivered, and nothing
called it. A PENDING step holds no lease to expire, and the scan reaper
deliberately skips a scan with a live step -- so such a scan sat at whatever
percentage it had reached, permanently, with its connection answering "a scan is
already running". The reaper now nudges every scan with work outstanding, which
is a no-op on the normal path where a step enqueues its own successor.

**A step carries its own time limits, and a worker reserves one at a time.**
The general Celery ceiling bounds the short tasks, where anything past a minute
is a fault. A step is not that: one evaluation of an entire tenant legitimately
runs for half an hour, and cutting it at the general limit turned a large tenant
into a killed worker that the reaper retried at the same size -- three attempts,
three kills, and a failure whose only cause was the number of subscriptions the
customer owned. Prefetch drops to one for the same reason: a reserved message is
invisible to every other worker, so the default of four left three tenant-sized
steps idle inside one process while the queue looked empty to the rest of the
pool.

**Retention is a count as well as a window.** Days alone is a policy about time,
and storage is not spent in time. A customer scanning every half hour writes 48
captures a day per subscription and 1,440 inside a 30-day window; a customer
scanning weekly writes 4. Both are inside the same stated retention and their
tables are two orders of magnitude apart, which is how one tenant enabling
change-triggered scanning becomes the reason a shared database fills up. A
per-scope ceiling caps the series, ranked in PostgreSQL by the same
(created_at, id) order the replay path uses -- and the newest capture of a scope
is exempt from the ceiling exactly as it is from the window, because it is what
an applied replay reads.

**Evidence records which scan read the provider.** A reading inside its reuse
window is carried into the next scan, which writes a row of its own under its
own id holding the original's `collected_at`. The age survived; the authorship
did not. `finding_evidence.source_scan_id` exists precisely to say that the
collecting scan is not necessarily the scan that raised the finding, and it was
copied from `evidence.scan_id`, which could only ever name the latter -- so a
customer following a citation back to the reading it rests on was handed a scan
that made no such call. `evidence.source_scan_id` (migration 0031) carries the
collecting scan, NULL meaning this row is the reading, and a carried row's
source is followed rather than restarted so the trail stays one hop long however
many scans have reused it.

**And one performance change with no correctness argument behind it.**
Rebuilding a capture fetched its own stored readings, so an analysis of a
fifty-subscription tenant opened with fifty queries against the largest table in
the schema before a single rule ran. The readings are content-addressed and the
captures share them; they are now fetched once and handed down.

## 66. The frontend's own production failures

Four of them, all invisible in development and none of them a bug in any
feature. Development serves every module from a running dev server, never
redeploys under an open tab, and talks to an API on localhost that either
answers or refuses immediately -- so the conditions below only exist once the
thing is deployed.

**Nothing caught a thrown error, so the page went white.** React unmounts the
whole tree when a render throws and nothing catches it: no message, no way back,
and nothing on screen for a customer to describe to support. For a product whose
job is telling somebody whether their cloud is secure, a blank page is the worst
available answer. There is now a boundary at the root and a second one around
the router's outlet, so a page that throws leaves the reader with the navigation
they arrived by rather than an empty document.

**The most common cause of that blank page was not a bug at all.** Every page is
a dynamic import, and a deploy replaces the hashed files a tab already open was
going to fetch. Somebody who leaves CloudGuard open, gets a release, then clicks
Findings asks for a chunk that no longer exists; the import rejects, and the
`Suspense` boundary above it has nothing to catch it. That is not an error to
report -- it is a page that needs the new build -- so the boundary recognises
the shape of it and reloads once, guarded in session storage. Once, because a
reload that hits the same error again loops for ever, which is a worse blank
page than the one it replaced.

**A hanging request never resolved.** `fetch` has no timeout and neither does
TanStack Query, so a host that accepts the connection and then says nothing --
a container mid-redeploy, a captive portal, a mobile connection that dropped --
left the query in `isLoading` for as long as the tab stayed open. Requests are
now bounded (30s, and 120s for a report, which is rendered on demand and
legitimately slow), and a rejected fetch is reported as an unreachable API
rather than as the browser's own "Failed to fetch", which reads to a customer as
a bug in CloudGuard.

**An expired session read as a broken product.** Only the dashboard noticed a
401, and it noticed by rendering an error where its charts go. Everywhere else
every panel on the page failed with its own message, none of them said "signed
out", and nothing offered the action that fixes it. A 401 now clears the token,
which puts the router back in charge and sends the reader to sign in. A 403 is
deliberately not this: a viewer refused a write is signed in and should stay
signed in, and answering "you may not do that" with "prove who you are" would
land them back at the same refusal.

And one smaller thing found on the way: the query client retried every failure
once, including the ones the server has already answered definitively. Retrying
is now limited to the failures where nobody actually answered -- a 5xx, a
timeout, a dropped connection.

## 67. A control cites its readings, and the whole assessment leaves as a file

The compliance view walked the chain the product claims -- reading, rule,
control, framework -- in one direction only, and stopped one link short at each
end.

**At the evidence end it could only explain failure.** A finding cites the
readings behind it (`finding_evidence`), so "how do you know this is wrong" had
an answer. A *passing* control has no findings, so it had no citations at all:
CloudGuard painted a green row and offered nothing to check it against, on the
one screen somebody might put in front of an auditor. The question an auditor
actually asks first is the other one -- how do you know this control is met --
and the answer was "because no rule complained", which is an assertion, not
evidence.

So a control now carries the provider readings its verdict rests on, taken from
the rules' own declared evidence keys and the latest scan's `evidence` rows:
which listing, when the provider was read, across how many scopes, under which
permission, and whether the payload is still stored. Three choices inside that
are load-bearing:

* **The oldest read and the worst outcome, never an average.** A control is
  only as current and as complete as the least of the things it rests on.
  Averaging would let forty-nine freshly read subscriptions hide the one nobody
  could read, which is the same overclaim as a PASS nobody earned, arriving
  through arithmetic.
* **A key nothing read is listed, not omitted.** It reports no outcome rather
  than a failure -- the provider did not refuse, nothing asked -- and it is the
  case that matters most, because it is precisely how a control ends up green
  on nothing.
* **Retention is reported, not assumed.** The blob store is asked which hashes
  still exist rather than inferring it from the hash being present. A citation
  whose bytes have aged out is still a true statement about what was read, and
  saying so beats offering a link that fails.

The evidence keys come from the `rules` read-mirror rather than the Python
registry (migration 0032 adds `requires_evidence` beside `compliance_mappings`),
for the reason that table exists at all: a rule deleted from the registry keeps
its row, disabled, so the controls it used to answer for do not silently become
uncovered.

**At the other end it could not leave the browser.** An audit is run from a
spreadsheet, and a GRC platform ingests JSON; a screen is neither.
`GET /compliance/{id}/export?format=csv|json` is the assessment as a document --
every control, its verdict, the rules behind it and the readings behind those,
including the controls that passed. It answers with a file rather than the
`{data, error, meta}` envelope, as reports do, because the caller is saving
bytes to disk and an envelope would make every consumer unwrap a shape that
means nothing there.

Two details of the CSV are decisions rather than formatting. **Every row repeats
the framework, its version and when the assessment was read**, which is
redundant on screen and is the only thing that survives what actually happens to
an export: fifteen rows copied into a larger sheet, where a row that no longer
says which reading it came from is a compliance claim with no date on it. And
**booleans are written as yes/no**: a spreadsheet coerces TRUE/FALSE into its
own boolean type and then formats it in the reader's locale, so a German auditor
opens the file and finds WAHR.

Nothing here issues a score. The export says what was checked, what was found,
and what it was found from -- the same position `coverage_ratio` takes on the
screen, carried into the one artefact that outlives it.

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
