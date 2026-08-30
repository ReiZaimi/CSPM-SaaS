# CloudGuard — Architecture Review

A review of the backend as it stands, and the architecture it should grow into.
Written against the repository rather than against a plan: every claim about
what exists names the file it lives in, and every claim about what is missing
was checked before it was made.

`DECISIONS.md` records the choices already taken and why. This document is the
opposite direction — what those choices imply next, what they cannot absorb,
and which of them are load-bearing enough that nothing should be allowed to
drift them.

Contents:

1. [Current state](#1-current-state)
2. [Problems](#2-problems)
3. [Recommended architecture](#3-recommended-architecture)
4. [Data flow](#4-data-flow)
5. [Domain model](#5-domain-model)
6. [Orchestration](#6-orchestration)
7. [Evidence architecture](#7-evidence-architecture)
8. [Attack paths](#8-attack-paths)
9. [Risk](#9-risk)
10. [Scalability](#10-scalability)
11. [Technology decisions](#11-technology-decisions)
12. [Roadmap](#12-roadmap)
13. [The short version](#13-the-short-version)

---

## 1. Current state

```
apps/api/app/
  main.py, api/router.py, api/routes/*        11 routers, envelope {data,error,meta}
  core/       config deps db enums errors logging security urls
  connectors/
    base.py          CloudConnector ABC: validate_connection / collect / normalize
    collection.py    CollectionTask, CollectionRun, waves, CoverageReport
    registry.py
    azure/           auth client collector connector normalizer plan rbac
  rules/      base engine registry
              azure/{compute,database,identity,logging,network,storage} — 10 rules
  risk/       config.py (weights) scorer.py (weighted sum, bands, priority)
  compliance/ catalog.py coverage.py — CIS Azure 2.0, ISO 27001, GDPR, NIST CSF
  services/   scanner.py cloud_connections.py scans dashboard findings ...
  models/     organization cloud_connection cloud_account resource scan finding
              risk remediation rule
  workers/    celery_app.py scan_tasks.py
database/migrations/  7 revisions, RLS policies inline (0001, 0002, 0007)
```

Several components that read as future work in the architecture sketches
already exist and work:

| Component | Where it lives now |
|---|---|
| Collection DAG | `connectors/collection.py` — declared tasks, `depends_on`, topological waves, `asyncio.gather` per wave, per-task `TaskOutcome` |
| Coverage | `CoverageReport` → `snapshot.coverage` → `RawSnapshot.errors` → `RuleContext.collection_errors` → UNKNOWN. Persisted in `scan_collection_results`, `scan_rule_results`, `scan_evaluation_gaps` |
| Raw evidence | `cloud_snapshots.data`, verbatim Azure JSON, one row per (scan, subscription) |
| Normalizer | `azure/normalizer.py` → `CloudResource`, pure function |
| Rule engine | `rules/engine.py` — four-state algebra, rule-raises-is-UNKNOWN, provider-scoped contexts |
| Risk engine | `risk/scorer.py` — six weighted components, persisted breakdown |
| Verification | `scanner.py::_verify_remediations` — auto-resolve on explicit PASS only |

Components that do not exist in any form: an evidence planner (the collection
plan is a fixed list), a context engine (context is three tag-inferred fields
assigned inside the normalizer), an asset graph worth the name (four edge types,
an adjacency dict rebuilt in memory per scan, no path queries), finding
correlation, risk scenarios, attack paths, a remediation engine (remediation is
a string copied onto the finding), and any scheduling at all.

The system is further along than most reviews of an MVP would expect in
evidence integrity, and further behind in orchestration durability and analysis
depth.

---

## 2. Problems

### Critical

**2.1 Identity is collected once per subscription, so a tenant-wide scan
multiplies every user.**

`AzurePlanBuilder.build()` includes `*self._identity_tasks()`, and
`AzureCollector` runs one plan per subscription. A twenty-subscription tenant
reads the whole directory twenty times, and `_role_membership` re-reads
authentication methods per privileged user twenty times.

The cost is the smaller half. `normalizer` emits
`provider_resource_id="/users/{id}"`; `ResourceRecord` is unique on
*(cloud_account_id, provider_resource_id)*, so one administrator becomes twenty
rows. `AzureMfaRule` is `PER_RESOURCE` and iterates `merged.resources`, which
`scanner.py` builds by `.extend`-ing each subscription's state — duplicates and
all. One administrator without MFA therefore produces twenty findings.

Directory data is tenant-scoped and is currently modelled as
subscription-scoped.

**2.2 A scan is one Celery task with no lease, no heartbeat and no reaper — and
a crashed scan blocks the connection permanently.**

`run_scan` has `max_retries=0` and `task_time_limit=1800`. A worker OOM or
redeploy mid-scan leaves `status=DISCOVERING` forever.
`scans_service.scan_in_flight` counts DISCOVERING as active, so `POST /scans`
answers 409 for that connection indefinitely, with no timeout path and no
operator endpoint. The only escape is editing the database by hand.

**2.3 `scan_in_flight` is a read-then-insert race with no constraint behind
it.**

Two concurrent `POST /scans` both read no active scan, both insert, both
enqueue. Two pipelines then write the same `(org, rule_id, resource_id)`
findings; the unique index turns that into an `IntegrityError` inside
`_persist_findings`, caught by the outer handler and reported as an opaque
failed scan. There is no advisory lock and no partial unique index.

**2.4 Whole-tenant table reads inside the per-scan hot path.**

* `_persist_findings` selects every `Finding` in the organization, and every
  `RiskFinding`, into memory on every scan.
* `_persist_relationships` selects the organization's entire edge table.
* `_verify_remediations` loads all open findings, then issues a `RiskFinding`
  query and a `Risk` get *inside the loop* — an N+1 on exactly the path the
  product is sold on.
* `RuleContext` holds every resource, and `for_provider()` copies the resource
  list and rewrites the whole relationship dict.

Invisible at 500 resources. At 50,000 it is the first thing to fall over, and
it fails as a timeout inside a thirty-minute task.

**2.5 Snapshots are unbounded JSONB in the tenant database, with no
retention.**

One row per (scan, subscription) holding the full Resource Graph inventory plus
every ARM listing. Nothing prunes, compresses or tiers. Replay deserializes the
entire payload in worker memory. Twelve months of daily scans and this table
*is* the database.

### High

**2.6 There is no evidence model — only a blob and a coverage report.**
`Finding.evidence` is a rule-authored dict. Nothing links a finding to the API
response it came from. "Traceable to evidence" currently means "traceable to
the scan whose blob contains it somewhere". No provenance fields — API version,
endpoint, permission used, collected-at, hash — exist as data.

**2.7 Collection is static; rules do not drive it.** `build()` returns a fixed
twelve-task list regardless of which rules are enabled.
`SecurityRule.requires_collection` is a list of bare strings that must agree
with `CollectionTask.category` strings, with nothing enforcing the agreement —
a typo silently means "never degrades". A verification rescan is a full scan
(`DECISIONS.md` §10 says so openly).

**2.8 No asset graph.** Four `RelationshipType` values, edges persisted but
never queried — every rule reads the in-memory dict built from that scan's
state. No recursive queries, no reachability, no identity edges, even though
`rbac.py` already collects role assignments. Attack paths are not deferred;
they are unreachable from the current data model.

**2.9 Risk is a per-finding weighted sum with a hand-set constant.**
`exploitability` is an integer literal on each rule class. `Risk` rows are
overwritten in place each scan, so score history does not exist. No
correlation, so five findings on one host are five risks.

**2.10 No temporal model** beyond `first_seen_at` / `last_seen_at` and the
snapshot blobs. No asset change events, no finding state-transition log, no
risk history. "What changed since last week" and "did risk increase" are
answerable only by diffing multi-megabyte blobs in application code.

**2.11 No observability** beyond structlog lines. No metrics, no tracing, no
per-stage timings. `scan.completed` carries counts, not durations. "Why is this
scan slow" has no answer today. `limiter.stats()` is the honourable exception.

**2.12 No scheduling.** No `beat_schedule`, no cron. The product loop's MONITOR
stage has no implementation; every scan is user-initiated.

**2.13 Progress commits on the shared session mid-pipeline.**
`_progress_reporter` commits per completed task on the same session the
pipeline is using for its own uncommitted work. It also computes
`progress_total = total_accounts * plan_size`, which assumes every
subscription's plan is the same size — true today, false the moment plans
become rule-driven or region-fanned.

### Medium

**2.14 Layering is inconsistent.** `routes/remediation.py` constructs models,
computes priority, mutates `Finding.status` and writes audit rows;
`routes/scans.py` builds `Scan` rows and hand-rolls enqueue-failure
compensation. Meanwhile `services/cloud_connections.py` is 988 lines. There is
no repository layer, which is why tenant scoping in the worker is code
discipline rather than a type.

**2.15 The worker bypasses RLS by design, protected only by convention.**
`service_session()` is the owner connection and every `organization_id` filter
in `scanner.py` is hand-written. Correct today — each one was checked — but the
guarantee is "somebody reviewed 1,165 lines carefully", not a mechanism.

**2.16 Azure vocabulary in shared tables** — `tenant_id`, `subscription_id`,
`consent_status`, `service_principal_object_id`. Already documented in
`MULTI_CLOUD.md` §2, with eleven external import sites into `connectors/azure`.

**2.17 `TokenProvider` per subscription.** A new
`msal.ConfidentialClientApplication` with an empty token cache is built for
every `AzureCollector` — per subscription, per scan.

**2.18 Provider-returned ids interpolated into request URLs.**
`list_diagnostic_settings(resource_id)` and `list_sql_firewall_rules(server["id"])`
build paths from ARM-returned strings. Trusting ARM is reasonable; a shape
assertion before interpolation costs nothing and closes the class.

---

## 3. Recommended architecture

```
                              HTTP (Supabase JWT)
                                     │
                    ┌────────────────▼────────────────┐
                    │  API layer  (thin routers)      │  validate, authz, envelope
                    └────────────────┬────────────────┘
                    ┌────────────────▼────────────────┐
                    │  Application services           │  use-cases, transactions
                    │  + Repositories (org-scoped)    │
                    └────────────────┬────────────────┘
                                     │ enqueue(scan_id)
              ══════════════════════ Redis ══════════════════════
                                     │
                    ┌────────────────▼────────────────┐
                    │  SCAN ORCHESTRATOR              │  durable state machine in
                    │  scans + scan_steps (leased)    │  PostgreSQL, run by Celery
                    └────────────────┬────────────────┘
            ┌───────────────┬────────┴────────┬────────────────┐
            ▼               ▼                 ▼                ▼
      step: PLAN      step: COLLECT     step: COLLECT     step: ANALYZE
                      (account A)       (account B)
            │               │                 │                │
            ▼               ▼                 ▼                │
   ┌────────────────┐   ┌───────────────────────────┐          │
   │ EVIDENCE       │   │ COLLECTION RUN            │          │
   │ PLANNER        │──▶│ (the existing executor)   │          │
   │ rules→evidence │   │ waves, outcomes, coverage │          │
   │ minus fresh    │   └─────────────┬─────────────┘          │
   └────────────────┘                 ▼                        │
                        ┌───────────────────────────┐          │
                        │ PROVIDER CAPABILITY PACKS │          │
                        │ azure: arm | graph | arg  │          │
                        └─────────────┬─────────────┘          │
                                      ▼                        │
                        ┌───────────────────────────┐          │
                        │ EVIDENCE STORE            │          │
                        │ blob → object storage     │          │
                        │ row  → evidence metadata  │          │
                        └─────────────┬─────────────┘          │
                                      ▼                        ▼
                        ┌──────────────────────────────────────────┐
                        │ NORMALIZER  (pure, per provider)          │
                        └─────────────┬────────────────────────────┘
                                      ▼
                        ┌──────────────────────────────────────────┐
                        │ CONTEXT ENGINE   network | identity | biz │
                        │ every fact carries source + confidence    │
                        └─────────────┬────────────────────────────┘
                                      ▼
                        ┌──────────────────────────────────────────┐
                        │ ASSET GRAPH   assets + typed edges (PG)   │
                        │ in-memory for traversal, CTEs for queries │
                        └─────────────┬────────────────────────────┘
                    ┌─────────────────┼──────────────────┐
                    ▼                 ▼                  ▼
             ┌────────────┐   ┌───────────────┐  ┌──────────────┐
             │ RULE ENGINE│   │ ATTACK PATH   │  │ EXPOSURE     │
             │ (local)    │   │ ENGINE        │  │ ANALYSIS     │
             └──────┬─────┘   └───────┬───────┘  └──────┬───────┘
                    │ findings        │ paths           │
                    └────────┬────────┴─────────────────┘
                             ▼
                 ┌───────────────────────────┐
                 │ CORRELATION               │  versioned scenario templates
                 └─────────────┬─────────────┘
                               ▼
                 ┌───────────────────────────┐
                 │ RISK ENGINE               │  finding risk + scenario risk
                 └─────────────┬─────────────┘  + risk history
                               ▼
                 ┌───────────────────────────┐
                 │ REMEDIATION               │  action + expected state +
                 └─────────────┬─────────────┘  verification spec, as data
                               ▼
                 ┌───────────────────────────┐
                 │ VERIFICATION              │  targeted plan from the same
                 └───────────────────────────┘  planner, backoff for eventual
                                                consistency
```

Two departures from the obvious arrangement, both deliberate.

**The attack path engine sits beside the rule engine, not after correlation.**
Both consume the graph; correlation consumes both. A path exists whether or not
any rule failed along it, and an internet-to-data path with no failing rule on
it is exactly the finding worth having.

**The evidence planner reads the enabled rule set *and* the evidence store.**
Its job is not "what do rules need" — that is a set union — but "what do rules
need that we do not already hold, fresh enough to use". That second half is
where incremental scans, verification scans and API cost reduction all come
from, and it is one join.

---

## 4. Data flow

```
POST /scans
  → service creates scans row (QUEUED) + scan_steps rows (PLAN)
  → advisory lock on (org_id, connection_id) prevents the duplicate enqueue
  → celery: dispatch_scan(scan_id)

dispatch_scan
  → claims runnable steps atomically:
    UPDATE scan_steps SET status='RUNNING', lease_until = now() + ttl
    WHERE status='PENDING' AND dependencies satisfied RETURNING id
  → enqueues one task per claimed step

step PLAN
  → enabled rules → evidence keys → minus evidence fresh within TTL
  → writes the collection plan; creates COLLECT steps, one per account,
    plus one tenant-scoped COLLECT for directory evidence

step COLLECT                                          retryable, idempotent
  → CollectionRun executes the DAG (unchanged)
  → per task: blob to object storage, row into `evidence` carrying
    evidence_key, outcome, item_count, api_version, endpoint,
    permission_used, collected_at, content_hash, blob_ref

step ANALYZE                                          after all COLLECT settle
  → load evidence rows (some may predate this scan and still be fresh)
  → normalize per provider → CloudResource + edges
  → context engine enriches; every fact carries source and confidence
  → persist assets (diff → asset_change_events), persist edges
  → build graph → rules → findings; attack paths; correlation
  → risk: per-finding score, per-scenario score, append risk_history
  → verification: resolve findings only on an explicit PASS from this scan
  → scan COMPLETED | PARTIAL
```

One rule holds throughout: a step that fails records why and does not block
steps that do not depend on it. That is already how `CollectionRun` behaves
inside a task; the change is making it true *between* tasks.

---

## 5. Domain model

Unchanged: `Organization`, `OrganizationMember`, `CloudConnection`,
`CloudAccount`, `ResourceRecord`, `Finding`, `Risk`, `RemediationTask`,
`RiskException`, `AuditLog`, `Rule`.

Added or reshaped:

```
ScanStep            scan_id, kind(PLAN|COLLECT|ANALYZE), target, status,
                    attempt, lease_until, worker_id, depends_on[], error
                    — makes scans resumable, leasable, reapable

Evidence            org_id, scan_id, cloud_account_id|NULL (NULL = tenant-scoped),
                    provider, evidence_key, outcome, item_count, collected_at,
                    expires_at, api_version, endpoint, permission_used,
                    content_hash, blob_ref, partial_reason
                    — generalizes ScanCollectionResult; replaces the blob as
                      the addressable unit

EvidenceKey         not a table: typed constants shared by rules and tasks,
                    replacing the requires_collection / category string
                    agreement that nothing currently enforces

AssetEdge           replaces ResourceRelationship. Adds capability semantics
                    (GRANTS_ROLE, CAN_REACH, CAN_ASSUME, HOLDS_DATA, EXPOSES,
                    CONTAINS, PROTECTS) plus confidence and source evidence_id

AssetChangeEvent    asset_id, scan_id, change, field_diff, observed_at
FindingEvent        append-only status transitions with scan_id and actor
AttackPath          entry_node, target_node, hops, path_kind, evidence_ids[]
RiskScenario        template_id, template_version, score, status, first/last seen
ScenarioMember      scenario_id → finding_id | attack_path_id
RiskHistory         subject(finding|scenario|org), subject_id, score, observed_at
VerificationAttempt finding_id, expected_state, evidence_ids[], outcome, attempt
```

Nothing is dropped. `cloud_snapshots` becomes a pointer table or folds into
`Evidence`.

On granularity: evidence is per *(scan, account, evidence_key)*, not per API
object. Per-object evidence multiplies rows by resource count for provenance
nobody queries. The task is the thing that fails, truncates, expires and gets
reused, so the task is the thing that gets a row.

---

## 6. Orchestration

**Keep Celery. Do not adopt Temporal. Put the workflow state in PostgreSQL.**

What is actually needed: durable step state, resumability after a worker dies,
per-step retry with backoff, partial-failure semantics, cancellation, and
detection of an abandoned run. Celery supplies none of those — Celery is a
queue. Canvas chords do not close the gap: chord state lives in the Redis
result backend, is not durable, and chord semantics are all-or-nothing, which
is the opposite of what this product is built around.

Temporal supplies all of it, and costs a cluster to operate, a second source of
truth for workflow state outside the RLS-protected database, and determinism
constraints that Python developers get wrong routinely. That is the right trade
at large scale or when a scan spans services. It is not the right trade for a
modular monolith whose workflow has three step kinds.

```
Scan
 ├── PLAN                       depends: —
 ├── COLLECT(directory)         depends: PLAN
 ├── COLLECT(sub-A)             depends: PLAN     ── parallel, separate workers
 ├── COLLECT(sub-B)             depends: PLAN
 └── ANALYZE                    depends: all COLLECT settled
      (settled = terminal, not = succeeded)
```

* **Claim.** `UPDATE ... SET status='RUNNING', lease_until=now()+ttl WHERE
  id=:id AND status='PENDING' RETURNING id`. Only the winner enqueues. This
  replaces `scan_in_flight` as the concurrency control and closes §2.3.
* **Heartbeat.** A running step extends its lease every sixty seconds.
* **Reaper.** One beat task per minute: `lease_until < now()` returns the step
  to PENDING with `attempt + 1`, or FAILED past `max_attempts`. Closes §2.2 —
  a crashed worker's scan recovers by itself instead of blocking the
  connection.
* **Retry.** Per step, not per scan. Idempotency comes from the step being
  *(scan, target, kind)*: re-running COLLECT overwrites that target's evidence
  rows under the same keys. `max_retries=0` was the right call while a scan was
  one indivisible unit; it stops being right once the units are collection
  steps that write nothing durable until they finish.
* **Concurrency.** Dedicated queues: `collect` (IO-bound, high concurrency) and
  `analyze` (memory-bound, low concurrency). Opposite resource profiles; they
  should not share a worker.
* **Throttling.** Move the ceiling from a per-run `RequestLimiter` to a Redis
  token bucket keyed *(tenant_id, service)*. ARM meters per subscription, Graph
  meters per tenant, and three subscriptions collecting in parallel currently
  have no shared Graph budget.
* **Timeouts.** `task_time_limit` now bounds one account's collection rather
  than a whole tenant scan — the difference between a safety net and a ceiling
  on customer size.

Failure semantics stay exactly as they are, because that part is right: no
single API failure fails a scan, every failure lands in the coverage ledger,
and a category that could not be read degrades its rules to UNKNOWN and never
to PASS. The change is extending it upward, so a COLLECT step that dies
outright degrades that account's categories and ANALYZE still runs.

---

## 7. Evidence architecture

```
Rule declares       requires_evidence: (EvidenceKey.AZURE_NSG,
                                        EvidenceKey.AZURE_NIC)
                              ▼
Planner             union over enabled rules,
                    minus evidence WHERE expires_at > now()
                              ▼
Collection task     one per (evidence_key, target); the catalogue maps
                    key → provider call + required permissions
                              ▼
Raw evidence        provider JSON, verbatim → object storage, gzipped,
                    content-hashed so an unchanged listing stores one blob
                              ▼
Provenance          endpoint, api_version, permission_used, collected_at,
                    outcome, item_count, partial_reason, collector_version
                              ▼
Normalization       pure function over evidence rows. Deliberately not stored:
                    normalized state is cheap to recompute, and storing it
                    doubles the schema for something replay already gives us
                              ▼
Reuse               a verification scan collects one evidence key, not twelve;
                    an incremental scan collects only what expired
                              ▼
Evaluation          a rule reads only evidence it declared, so an UNKNOWN names
                    the missing evidence key rather than a whole category
                              ▼
Expiration          per-key TTL. Expired is not deleted: it stops being usable
                    for a fresh verdict and stays available for replay
Retention           blobs tier out on a schedule; evidence rows and the
                    coverage ledger remain
```

Confidence does not belong on evidence. Evidence is either what the provider
said or it is not, and `outcome` already carries the only distinction that
changes a verdict. Confidence belongs on derived *context*.

---

## 8. Attack paths

**A separate engine, reading the graph, running alongside the rule engine.
PostgreSQL for storage, in-memory adjacency for traversal. No graph
database.**

An SME tenant is 10³–10⁵ nodes. That is a Python dict, and `RuleContext`
already builds one. A graph database buys interactive multi-hop queries over
millions of nodes — a problem for enterprise customers who do not exist yet,
bought with a second stateful system that has no RLS and needs its own tenancy
story. Recursive CTEs cover the API-side queries; scan-time traversal is
in-memory and finishes in milliseconds.

The work is not the store. The work is typed edges with capability semantics:

```
network:   CAN_REACH(src, dst, ports, via)      from NSG rules, public IPs, routes
identity:  GRANTS_ROLE(principal, role, scope)  from role assignments (rbac.py
           CAN_ASSUME(principal, principal)      already collects these)
data:      HOLDS_DATA(asset, sensitivity)       from the context engine
topology:  CONTAINS, ATTACHED_TO, PROTECTS      exist today
```

Path finding is bounded breadth-first search from designated entry points
(`INTERNET`, plus externally authenticatable principals) to designated targets
(`HOLDS_DATA` at sensitivity HIGH or above), with traversal gated on a
predicate. Deterministic, explainable, and every hop cites an `evidence_id`.

### A concrete path, from rules that already exist

```
INTERNET
   │  CAN_REACH :3389/tcp
   │  evidence: nsg-prod-web rule "AllowRDP" src 0.0.0.0/0     [AZ-NET-002 FAIL]
   ▼
vm-prod-jump-01                          public_ip 20.61.x.x   [AZ-CMP-001 FAIL]
   │  ATTACHED_TO
   ▼
managed identity  mi-jump-01
   │  GRANTS_ROLE  "Contributor"  scope /subscriptions/xxxx    [AZ-ID-002 FAIL]
   ▼
subscription xxxx
   │  CONTAINS
   ▼
storage account  stprodcustomerdata      allowBlobPublicAccess=true
                                          data_sensitivity HIGH [AZ-STO-001 FAIL]
   │  HOLDS_DATA
   ▼
customer PII
```

Those five findings exist today and are reported as five independent rows. The
path is one fact: the internet can reach a subscription-Contributor identity
and, through it, sensitive data, in three hops. No rule can see this, because a
rule is deliberately local. That gap is the strongest argument in this document
for building the graph properly.

It also identifies the cheapest break. Closing the NSG rule — fifteen minutes —
severs the path at the first hop. That is prioritization derived from structure
rather than from a weighted sum.

---

## 9. Risk

**Two layers, both deterministic.**

`risk/scorer.py` stays as it is, as *finding risk*. It works, the weights live
in one file and are validated to sum to 1.0, the breakdown is persisted, and
UNKNOWN scores at 3.5 rather than being quietly treated as LOW. Do not replace
it with a probability model: calibrating one needs breach outcome data that
will never exist here, and an uncalibrated probability is a weighted sum
wearing a costume.

*Scenario risk* sits on top:

```
scenario_score = max(member_finding_scores)
               + path_amplifier(path)      bounded, e.g. ≤ +25
               + toxicity(template)        fixed per template

path_amplifier is a function of hop count (fewer is worse), entry reachability
(internet is worse), target sensitivity, and privilege gained at the widest hop.
```

Everything stays traceable: a scenario decomposes into member findings, each
into six named components, each into an evidence row.

### The same environment, scored both ways

Today:

```
AZ-NET-002  Public RDP on nsg-prod-web           risk 78  CRITICAL
AZ-CMP-001  VM reachable from internet           risk 71  HIGH
AZ-ID-002   Over-privileged managed identity     risk 66  HIGH
AZ-STO-001  Storage account allows public blobs  risk 84  CRITICAL
AZ-LOG-001  No diagnostic settings on storage    risk 41  MEDIUM
security_score: 100 − 20 − 8 − 8 − 20 − 3 = 41
```

Worked top-down, the customer fixes the storage account first. Correct in
isolation, and it leaves the path intact.

With correlation:

```
SCENARIO  internet-to-sensitive-data                        risk 96  CRITICAL
  template SC-001 v1.2 — internet-reachable host with subscription-wide
                         identity reaching sensitive storage
  members  AZ-NET-002, AZ-CMP-001, AZ-ID-002, AZ-STO-001 + attack_path #7
  score    max(84) + path_amplifier(3 hops, internet entry, HIGH target) = +12
  break    AZ-NET-002 — remove 0.0.0.0/0:3389 from nsg-prod-web, ~15 min,
           severs the path at hop 1
  note     AZ-LOG-001 — this path would leave no trace
```

Same five findings, same deterministic scorer, one structural fact added — and
the recommended first action changes.

---

## 10. Scalability

| Scale | What binds | What to do |
|---|---|---|
| 1 tenant | Nothing | — |
| 100 tenants | §2.4's whole-tenant reads; the single-task ceiling; snapshot growth | Steps and leases (§6). Scope hot-path reads by account or scan. Blobs to object storage. Two Celery queues. Mandatory, not optional |
| 1,000 tenants | Write throughput on `findings` and `evidence`; large tenants starving small ones; connection pool exhaustion | Partition `evidence`, `scan_*` and `asset_change_events` by month and drop old partitions. Per-tenant fair scheduling. PgBouncer. Read replica for dashboards |
| 10,000+ | Analysis CPU; graph memory for the largest tenants; cross-tenant analytics | Split ANALYZE per account with a tenant-wide merge step. Dedicated analysis pool with memory limits. Reporting off the OLTP database. Only here do event streaming or a graph database begin to earn their complexity |

What makes this hold without a rewrite is that the seams are already in the
right places. `CloudConnector`, `CollectionRun`, `SecurityRule` and
`CloudResource` know nothing about scale, tenancy or storage. Every row above
is a change to orchestration, storage or scheduling, not to the domain.

One decision is expensive to defer: **where evidence blobs live**. Moving them
out of `cloud_snapshots.data` at 100 tenants is a background migration. At
1,000 it is a weekend outage.

---

## 11. Technology decisions

| Technology | Verdict | Reasoning |
|---|---|---|
| FastAPI | **Keep** | Correctly used; the dependency chain for auth and tenant resolution is good design. Only fix is pushing logic out of the fatter routers |
| Python 3.12 | **Keep** | The workload is IO-bound with modest CPU. Types are strict and enforced |
| Celery | **Keep, change how it is used** | Fine as a queue; stop using it as a workflow engine. Steps, leases and a reaper in PostgreSQL; two queues; beat for scheduling |
| Temporal | **Defer** | Solves durable workflow, which PostgreSQL also solves for a three-step DAG without a cluster or a second tenancy story |
| Redis | **Keep** | Broker and rate-limit token buckets. Not a result store for anything that matters |
| PostgreSQL / Supabase | **Keep** | Dual-enforced RLS against a non-owner role is the right architecture. JSONB, recursive CTEs and partitioning cover graph, temporal and analytics needs for a long time |
| Object storage | **Add** | Evidence blobs. The only new infrastructure warranted before large scale |
| SQLAlchemy 2 async | **Keep, change how it is used** | Add a repository layer so `organization_id` scoping is structural. Fix the whole-tenant reads and the N+1 in `_verify_remediations` |
| REST + MSAL over `azure-mgmt-*` | **Keep** | Load-bearing: verbatim JSON is what makes replay possible, and the SDKs are synchronous |
| Microsoft Graph | **Keep, fix scoping** | The API is right; the scoping is wrong (§2.1) |
| Graph database | **Defer, probably indefinitely** | PostgreSQL plus in-memory traversal covers 10³–10⁵ nodes |
| Kafka / event bus | **Defer** | `LISTEN`/`NOTIFY` plus the step table covers every in-process event today |
| Warehouse (ClickHouse etc.) | **Defer** | Partitioned PostgreSQL and materialized views cover reporting for now |
| React + Vite + TanStack Query | **Keep** | Nothing in it constrains the backend |
| An LLM in the verdict path | **Never** | Copilot narrates deterministic output. Nothing else |

---

## 12. Roadmap

Correctness and durability before architecture: a platform that loses scans
does not get to have an attack path engine.

### Phase 0 — bugs — **done**

1. ~~Tenant-scope directory collection~~ (§2.1). `AzurePlanBuilder` now builds
   an account plan and a directory plan; `CloudConnector` gained
   `collect_directory`; migration 0008 makes an asset, a snapshot and a
   coverage row belong to either a subscription or the tenant, with a CHECK
   forbidding neither and partial unique indexes keying the tenant-scoped rows.
2. ~~Leases and a reaper~~ (§2.2). Migration 0009 adds `scans.lease_until`,
   extended by every phase change and every progress write; a beat task closes
   scans whose lease expired or that were never claimed. The worker start
   command gained `--beat`.
3. ~~Advisory lock on scan creation~~ (§2.3). `lock_scan_target` wraps the
   check-then-insert in all three routes that start a scan.
4. ~~Scope the pipeline's reads~~ (§2.4). `_asset_scope` / `_finding_scope`
   replace the organization-wide selects in `_persist_findings`,
   `_persist_relationships` and `_verify_remediations`; the resolve path's N+1
   is batched into two statements.
5. ~~Move progress off the pipeline's session~~ (§2.13). `_ScanProgress` writes
   through its own session and accumulates across phases instead of assuming
   every phase is the size of the one currently reporting.

Not verified locally: the integration suite needs the PostgreSQL that CI
provisions, so migrations 0008 and 0009 and the tests added alongside them have
been collected and type-checked but not executed. Run them in CI before relying
on the reaper.

### Phase 1 — foundations

6. **Done, differently** — §2.15. The review proposed a repository layer
   taking `organization_id` at construction. What shipped is stronger and
   smaller: migration 0012 adds a `cloudguard_worker` role whose
   policy arm on every tenant-owned table trusts `app.current_org()`, and the
   pipeline runs each scan in a session that declares its organization for the
   length of a transaction. PostgreSQL refuses a read or a write outside it
   however the query is written — a repository layer would still have been a
   convention, enforced by whoever remembered to use it.

   The arm is granted to that role alone. Adding it to the policies the request
   path uses would have handed `authenticated` a bypass it never needs, which
   is the guarantee being strengthened, weakened.

   Two deliberate limits. Housekeeping — the reapers, which look for abandoned
   work across every organization — stays on the owner connection, because
   that is exactly what a per-organization session cannot see, and a claim
   meaning "see everything" would be a bypass with a friendly name. And
   `DATABASE_WORKER_URL` is optional: unset, the worker falls back to the owner
   connection and logs that it has, so adopting the role is a deployment step
   rather than a flag day.
7. **Mostly done** — scan steps and the orchestrator. (§6, §2.2) Migration
   0011 adds `scan_steps`; `app/services/orchestrator.py` decides what may run,
   claims it with an `UPDATE ... WHERE status = 'PENDING' RETURNING id`, and
   derives the scan's status from what its steps add up to. `ScanPipeline.run`
   became `plan` / `collect` / `analyze`, cut at the seam that already existed:
   collection writes captures, and everything after a capture is a pure
   function of it — so ANALYZE reconstructs from the database exactly what the
   single task used to carry in memory, sharing that reconstruction with
   replay.

   A redeploy now costs the step in flight rather than the scan, a tenant of
   fifty subscriptions is fifty retryable units, and one unreadable
   subscription no longer withholds the other forty-nine.

   Split queues are done too: `collect`, `analyze` and the default queue for
   the short database-only tasks, with a test that fails if a step is routed to
   a queue the deployment does not consume.

   **The shared rate budget is deliberately not built**, and the reasoning is
   worth keeping. §6 called for moving the ceiling from a per-run
   `RequestLimiter` to a Redis token bucket keyed *(tenant, service)*, on the
   grounds that parallel subscriptions would contend for one budget. Checked
   against how the surfaces actually meter:

   * **ARM** meters per subscription, and a COLLECT step reads exactly one — so
     parallel steps draw on different budgets and the per-step ceiling of 16 is
     already the right ceiling.
   * **Microsoft Graph** meters per tenant, and the directory is read by exactly
     one step per scan. That is what the directory split bought, and it bought
     this as well.
   * **Resource Graph** meters per tenant and *is* in the per-subscription plan,
     so N subscriptions now issue N concurrent queries against one budget. This
     is real new exposure — and it is one query per subscription, on the single
     collection task no rule reads, degrading through the existing Retry-After
     path to a PARTIAL on inventory.

   A distributed token bucket would therefore be new infrastructure protecting
   the least consequential task in the plan. The trigger to build it is a
   tenant-metered surface that a *rule* depends on becoming parallel per
   subscription — not the parallelism on its own.
8. **Partly done** — the evidence model. (§7, §2.5, §2.6) Migration 0010
   renames `scan_collection_results` to `evidence` and gives a reading the
   provenance it lacked: the provider, when it was collected, the permissions
   the read was made under, and the hash of what it produced. `evidence_blobs`
   stores those payloads content-addressed and scoped per organization, so an
   unchanged listing is kept once rather than once per scan.

   Still to do: blobs in object storage rather than PostgreSQL, a retention
   policy that prunes them, and the flip that makes replay read evidence
   instead of `cloud_snapshots`. The last of those is gated on
   `test_the_payloads_reconstruct_the_capture_exactly` holding against real
   scans, which is why both are written for now.
9. ~~Typed `EvidenceKey`~~ (§2.7). Keys are an enum per provider, each carrying
   its category, so a task no longer declares one and the two cannot disagree.
   Rules declare `requires_evidence` as keys rather than category names, which
   also removed a real defect: `has_collection_error("identity", "mfa")` named
   evidence nothing produces, so half that call had never checked anything.
   `tests/unit/test_evidence_keys.py` fails the build if a rule ever again
   depends on evidence no task collects.

### Phase 2 — planning and context

10. **Done, and one half of it deliberately does almost nothing.**
    `app/services/evidence_planner.py` builds a `CollectionPlan` before every
    collection step: the union of every enabled rule's `requires_evidence` plus
    the connector's `baseline_evidence`, minus whatever is already held fresh
    enough to stand in for a new read. The provider's plan is filtered through
    it, and `CollectionRun` takes the dependency closure of what survives —
    dependencies are declared on the tasks, where they belong, so a planner
    that knows only what the rules asked for cannot be expected to know that
    diagnostic settings need the storage and SQL listings first.

    The rule-set half is exact today: union equals plan, nothing is dropped, no
    request is saved. That is the intended result rather than a disappointing
    one — what it buys is that the equality is now *checked*. Three keys are
    named by no rule (inventory, role assignments, role definitions), and the
    connector declares them as baseline rather than the plan carrying them by
    habit; a listing whose last reader is deleted now fails a test instead of
    being collected for ever.

    The freshness half is where the review's arithmetic and the product part
    company. "Minus fresh evidence" reads as a cost optimization, and applied
    broadly it would quietly destroy the claim the whole system is built to
    support: a scan that verifies a fix against a reading taken before the fix
    is not a cheaper scan, it is a wrong one. Reuse is therefore per key and off
    by default (`EvidenceKey.reuse_window`), justified by the provider only
    where a stale reading cannot change a verdict — which today is
    `role_definitions` and nothing else, with a test failing the build if a key
    any rule reads is ever given a window. See `DECISIONS.md` §16.

    Targeted verification scans are the part still owed, and they are item 12's
    to finish rather than this one's: narrowing a scan to one rule needs the
    engine to evaluate only what it collected fresh and leave every other
    finding untouched, or a targeted scan would re-assert stale verdicts about
    everything it did not look at. The planner is the seam that makes that
    buildable; the rule about what a narrowed scan may conclude is not a
    planning decision.
11. **Done for the backend.** `app/context/` holds inference and resolution:
    `infer()` is pure and runs in the normalizer's path, `resolve()` applies
    what the customer declared, in the pipeline, at evaluation time rather than
    frozen into the capture. Every value carries a `ContextSource`, persisted
    beside it on `cloud_resources`, with confidence derived from the source so
    the two cannot disagree. `context_declarations` holds what a customer said
    about a subscription, written over `PUT /cloud-accounts/{id}/context` and
    read by the pipeline; `GET /assets/{id}` returns each value's provenance.

    Two decisions worth keeping. A declaration is a **floor**, never an
    override — it can raise an asset above what the capture supported but not
    lower it, so the worst a mistaken declaration can do is over-rank
    something, which is the direction a security product may be wrong in.
    Environment is exempt, because a name has no maximum and the case the
    feature exists for is the customer whose production runs in a subscription
    called `sandbox-eu`.

    Still to do: the screen. The API and the storage are here and the pipeline
    reads them, so the remaining work is `apps/web`. Per-resource declarations
    are a later migration rather than a nullable column nothing writes, and a
    declaration deliberately does not rescore stored findings on the spot — a
    score is what a scan concluded. See `DECISIONS.md` §17.
12. **Done, except the targeted plans.** `remediation_verifications` (migration
    0017) records the expectation the moment a customer marks work done — this
    rule, on this asset, should now PASS — and `app/services/verification.py`
    settles it from whatever any scan observes. A beat task looks again on a
    widening backoff (5m, 15m, 1h, 4h) because a cloud applies a change before
    every read path agrees about it, so an early FAIL is the environment not
    having caught up rather than a failed fix.

    `INSUFFICIENT_EVIDENCE` and `STILL_FAILING` are separate outcomes, which is
    the FAIL/UNKNOWN line carried up to the one screen where somebody is told
    whether their work counted; a verification that once saw a definite FAIL
    settles as STILL_FAILING even if later attempts went blind. The finding
    detail returns the verification, so "checking, it has not appeared yet" is
    something the customer can read rather than infer from a finding that has
    not moved.

    Targeted plans are deliberately still open. A verification scan could
    collect only its rule's evidence, but a scan narrowed that way must also
    evaluate only what it collected fresh or it re-asserts stale verdicts about
    everything it did not look at — a rule about what a narrowed scan may
    conclude rather than a planning decision. See `DECISIONS.md` §18.

### Phase 3 — analysis depth

13. **Done** — the asset graph. (§2.8, §8) `app/graph/` holds it: typed
    capability edges, bounded breadth-first traversal, and the two questions
    worth asking — where an exposed asset can reach, and what one identity can
    act on.

    Two corrections to what §8 assumed. Role assignments were *not* already
    collected — the ARM permission was in the role from v1 but nothing read it,
    so `AzureEvidence.ROLE_ASSIGNMENTS` and `ROLE_DEFINITIONS` are new tasks
    under a new `AUTHORIZATION` category. And there are **no synthetic nodes**:
    §8 drew an `INTERNET` vertex and a `SENSITIVE_DATA` vertex, and both would
    have been CloudGuard inventing endpoints. Exposure and sensitivity are
    already per-asset attributes, so an entry point is a predicate over nodes
    rather than an edge from a fiction — and UNKNOWN is excluded from both,
    because manufacturing an attack path out of failed collection is the same
    overclaim as a PASS nobody earned.

    Network reachability beyond `public_exposure` is deliberately absent. Real
    host-to-host reachability needs subnet, route and peering data nothing
    collects, and edges guessed from what is on hand would be the one kind of
    wrong that reads as authoritative.

14. **Done for reachability** — `AssetGraph.attack_paths()` and
    `blast_radius()`, exposed at `GET /attack-paths` and
    `/attack-paths/blast-radius/{id}`. Computed from stored assets and edges
    rather than persisted: a path is a pure function of those, and a stored one
    could describe a route the customer has already closed. What that costs is
    history — "did a new path appear this week" needs an `attack_paths` table,
    worth building once paths are being acted on rather than looked at.

    The page at `/attack-paths` leads with the route rather than its endpoints,
    and marks the severable hop in the route itself as well as calling it out
    below — reading the two separately makes the customer hold both in their
    head to see which link the fix refers to. Its empty state distinguishes
    three different nothings, because they call for three different actions and
    a single "no attack paths" would read as reassurance in all of them. The
    one that matters: no sensitive targets means CloudGuard does not know what
    would cost the customer anything, which is a gap in what it was told rather
    than a clean environment.
15. **Done for the one template the graph can support** — correlation. A route
    from an exposed asset to a sensitive one becomes a single risk grouping the
    open findings along it, in the `risks` table beside the findings it groups.
    No new table: `risk_findings` was written as a junction precisely so several
    findings could become one risk later, and its comment said that later would
    be a change in the pipeline rather than a migration. It was.

    Two rules kept it honest. A route with **no failing check on it** creates no
    risk — that is architecture rather than a mistake, and minting one would
    mean inventing a severity no rule assigned. And a route that closes is
    **resolved, not deleted**, exactly as a fixed finding is.

    **Privilege escalation chains are now built.** They needed one edge the
    graph did not have: `CAN_GRANT_ROLES`, drawn beside `GRANTS_ROLE` when a
    principal's role definition permits
    `Microsoft.Authorization/roleAssignments/write`. Read from the definition
    rather than the role name, and that is the whole difficulty — **Owner and
    Contributor both carry `actions: ["*"]`**, and only Contributor excludes
    `Microsoft.Authorization/*/Write` in its `notActions`. Matching on names
    would report every Contributor assignment in existence as an escalation
    path, which is the kind of false alarm that gets a feature switched off
    rather than fixed. Reading the definition also finds the case a name list
    never could: a tenant's own custom role granting exactly that one action.

    `AssetGraph.escalation_chains()` answers the resulting question, and it is
    a different one from `attack_paths()` rather than a variation on it — not
    what an attacker reaches, but what they could be *given* once they arrive.
    A route ends at the **scope**, because the scope is the size of the answer:
    "this VM runs as an identity that can grant itself Owner" is alarming, and
    naming the subscription it can do that over is what makes it actionable.
    An entry point is required, deliberately — a directory administrator who
    can hand out roles is over-privileged and is not a chain, and reporting one
    would invent the half of the story that makes it urgent.

    Both templates share `_correlate_template`, so the same discipline applies
    to each: a route with no failing check on it creates no risk, a route that
    closes is resolved rather than deleted, and a route seen again keeps the
    risk it had. Scoring differs in one input — an escalation's
    `target_sensitivity` is the most sensitive thing *under* the scope, taken
    over known levels only, because that is what the escalation would be an
    escalation to.

    **Unmonitored critical assets are deliberately not a template.** The
    conjunction is one finding (AZ-LOG-001, missing diagnostic settings) on one
    asset whose criticality the finding formula already multiplies by — so a
    scenario for it would be a second opinion on a single finding rather than
    several findings seen as one thing, and would charge the customer twice for
    one problem. That is the same argument item 16 makes for keeping scenario
    risks out of the security score. It becomes worth building if a template
    ever spans several assets; as one asset and one rule, it is what the risk
    score already says.

16. **Done for scenario risk; history still open.** `scenario_score` floors at
    the worst member and adds a bounded amplifier that is mostly about
    shortness. The floor means a scenario can never rank below its own
    evidence; the bound means a long chain of ordinary facts can never outrank
    a genuinely critical finding. Every term is in the persisted breakdown,
    including the uncapped total, so a score of 100 explains why it is not 101.

    **Scenario risks are excluded from the security score**, because the score
    joins risks through findings — a scenario with four members would deduct
    four times, and even once would charge the customer twice for one problem.
    A scenario re-ranks and explains; it does not add a fault to the tally.

    On the risks page both kinds share one list, because a route outranking the
    findings inside it is only visible where they are ranked together — on a
    page of its own it would be a second opinion nobody compares. A scenario
    renders as its own shape rather than as a finding risk with extra fields:
    it shows the route and the arithmetic that lifted it above its worst
    member, and deliberately omits exploitability and asset criticality, which
    are inputs to the *finding* formula and were never used here. Showing them
    would be showing working that was never done.

    **Risk history is now built.** Migration 0015 adds `risk_history`: one
    denormalized row per observing scan, holding the score, the open counts and
    the number of open routes as they stood. Denormalized because it is a time
    series — recomputing last month's posture from today's findings answers a
    different question every time somebody reclassifies one.

    It replaced an estimate rather than filling a gap. `_score_delta`
    reconstructed a prior score by adding back the deduction for every finding
    ever verified fixed, which answers "how much better than when we started"
    while being labelled "movement since the last scan" — and it double-counted
    from the moment a finding could belong to two risks, since it counted
    through the junction and a scenario member is joined twice.

    The frontend consequence was a live bug: the estimate could only ever be
    positive, so the dashboard hard-coded a green up-arrow. A measured delta can
    fall, and a green ↑ over a worsening posture is a plain untruth. `ScoreDelta`
    now has four states, keeping "no previous scan" separate from "no change" —
    a comparison that could not be made is not a comparison that came out
    level.

### Phase 4 — operations and proof

17. **Started** — observability. Per-stage durations are the half the steps
    made free: every stage records when it was claimed and when it settled, so
    `GET /scans/{id}/detail` now returns what each stage did, which scope it
    read, how long it took and which attempt it was on, and each step logs the
    same on completion. "Why was this scan slow" was previously unanswerable —
    a scan was one task with one start and one end, so a slow subscription and
    a slow evaluation looked identical.

    **Now done, in the form this stack can honour.** A scan runs as several
    Celery tasks across several workers, so its lines arrive interleaved with
    every other tenant's and were joined only by whichever ids each call site
    remembered to pass. `log_context` binds `scan_id`, `step_id`, `step_kind`,
    `cloud_account_id` and the task name for the length of a block, and
    `merge_contextvars` was already the first processor — so every line inside,
    including ones nobody thought to annotate, carries them.

    Deliberately **not** OpenTelemetry. Spans need a collector to send them to
    and this deployment has none; an exporter writing into a socket nobody reads
    is the appearance of observability rather than the thing. The ids are the
    part that makes the lines joinable, and they cost nothing. The trigger for
    real tracing is a collector existing, not the code being ready for one.

    The coverage gauge already existed on the dashboard — conclusive over
    conclusive-plus-unknown, from the last scan's rule results. What was missing
    beside it is **evidence freshness**, and the two answer different questions:
    coverage is what fraction of the checks reached a verdict, freshness is how
    recently the provider was asked, and a posture can be fully covered and
    three weeks out of date.

    Measured over the newest reading of each (scope, evidence key) rather than
    from `scans.completed_at`, because those differ now that a scan may carry a
    reading forward instead of re-taking it — and a carried reading keeps the
    time it was *collected* (`DECISIONS.md` §16). The headline is the **oldest**
    of them: an average would let a hundred fresh listings hide the one
    subscription nobody has managed to read since Tuesday. `unusable` counts
    readings that came back failed, truncated or skipped, because "recent" and
    "usable" are two halves of whether to trust the picture.
18. **Done.** All three tables exist. `risk_history` came first with item 16;
    migration 0018 adds the other two, plus `cloud_resources.absent_since`.

    `asset_change_events` records five things: an asset appearing or
    disappearing, and a change in any of the three attributes the risk engine
    multiplies a finding by. Configuration drift is deliberately excluded --
    diffing whole payloads would produce a feed nobody reads, and the drift that
    matters already arrives as a finding. One row per change rather than one per
    scan, so a quiet week reads as a quiet week instead of a wall of rows saying
    everything is still where it was.

    Disappearance needed the new column to be a *transition* rather than a
    standing condition. Derived from `last_seen_at`, an absence would need a
    scan cadence nobody records and would re-report itself on every scan
    afterwards; `absent_since` is set when a covering scan misses an asset and
    cleared when it returns, so an asset that vanishes for a week and comes back
    is one asset with two events rather than two assets.

    `finding_events` records DETECTED, REOPENED, RESOLVED, RISK_ACCEPTED and
    STATUS_CHANGED, each carrying the scan or the person that caused it -- and
    the distinction matters, because a scan observing a check pass is
    verification while a person moving a status is a decision. It sits beside
    the audit log rather than replacing it: that answers "what has anybody in
    this organization done", and this answers "what happened to this finding",
    which is the only one of the two that includes what a scan did.

    `GET /changes` is the feed; `GET /findings/{id}` now carries `timeline`. A
    superseded replay writes neither, for the same reason it writes no risk
    history: it made no observation.
19. **Done for the interval half** — §2.12. Migration 0013 adds
    `cloud_connections.scan_interval_hours` and `scans.trigger`; a beat task
    starts scans for connections whose environment is overdue a reading, using
    the same advisory lock and in-flight check the API uses. Off by default:
    turning a customer's cloud into a recurring API cost without being asked
    would be a surprise on their bill.

    An interval rather than a cron expression, deliberately. "Every night at
    03:00" needs a timezone, a window and an answer for what happens when a
    scan overruns its slot; an interval says the only thing a scanner can
    promise, which is that the environment is read at least this often. Due-ness
    is measured from when the last scan *started*, so a slow scan does not drift
    the schedule later every time.

    The control to set it lives on the connection card, after the "run a scan"
    button rather than beside it: the first scan is the thing to do now, and
    the schedule is what stops there being a next time somebody forgets.

    Still to do: change-triggered scans via Azure Event Grid.
20. **Done for the pattern; declared on three rules so far.**
    `app/remediation/` holds `ExpectedState` and `RemediationSpec`: what has to
    be true for a finding to close, carrying three names for one setting --
    the normalized field the rule reads, the ARM alias a policy matches on, and
    the Terraform argument that sets it -- because the setting genuinely has
    three. The Azure Policy definition and the Terraform hints are *generated*
    from that, which is the `rbac.py` pattern: one declaration, several
    artifacts, tests holding them to each other.

    The test that earns it runs in both directions, as the RBAC ones do. An
    asset built from a rule's own declaration must make that rule PASS, and one
    violating it must make the rule FAIL. Without the second half a declaration
    is documentation, and documentation drifts: a rule whose check moved on
    while its remediation stayed put tells a customer to change something that
    no longer closes the finding, and they do the work and are told it did not
    count.

    Two decisions worth keeping. A policy is generated **only where every**
    expected state carries an alias -- one covering half a rule would pass an
    asset that still fails it, and a customer who deployed it would believe the
    class was closed. And `also_accepts` exists because a rule that accepts TLS
    1.2 *or higher* would otherwise generate a policy pinned to equality, which
    refuses an account configured better than asked; that is a change-control
    incident rather than a bug report.

    Aliases carry `rbac.py`'s own rule about unverified strings: declared where
    verified, omitted where not. `AZ-DB-001` therefore generates a policy for
    SQL and says plainly that the PostgreSQL half and the firewall half are not
    covered, rather than generating something that silently applies to neither.
    Migration 0019 copies the declared expectation onto a verification when the
    claim is made, so `remediation_verifications` is now literally the
    expected-state record this item asked for.

    **All ten rules now carry a declaration**, which needed the vocabulary to
    grow by exactly two comparisons. Most of what a rule expects is not "this
    setting equals that value" but a statement about a collection --
    `NONE_MATCHING` (no inbound rule admits 3389 from anywhere) and `NOT_EMPTY`
    (this resource sends its logs somewhere; this administrator has a second
    factor). Three comparisons and no more: anything they cannot express stays
    undeclared rather than half-declared, because a remediation describing most
    of a check is worse than one describing none — a customer satisfies what
    they were shown and the finding stays open.

    A collection expectation carries a **witness**: the concrete element that
    must not be there, or one that satisfies. It earns its place twice, being
    both the clearest statement of what is looked for and the thing a test needs
    to build an asset the rule must fail. Eight rules are therefore checked in
    both directions against their own declaration.

    Two rules have no per-asset expectation and say why. AZ-ID-002 judges a
    *ratio across the directory*, and AZ-CMP-001 is about a *relationship*
    between a machine and the security groups that govern it — neither is a
    setting on an asset, and the fix for the second lands on the NSG where
    AZ-NET-001 already declares it. An empty declaration is also what a rule
    looks like when nobody could be bothered, so a test requires an empty one to
    carry a reason and something a customer can still run.

    Policy generation stayed narrow on purpose: three rules produce one. The
    network and logging expectations *could* be expressed as Azure Policy
    `count` expressions and DeployIfNotExists definitions respectively, and
    neither the aliases nor the expressions have been verified against a real
    deployment from here — which `rbac.py` records the cost of. The generator
    declines rather than guesses.
21. A second provider, behind the existing `CloudConnector` seam. Only then
    generalize the permission-manifest pattern and migrate the scope
    vocabulary, in the order `MULTI_CLOUD.md` §8 already argues for.

Deliberately postponed, with reasons: automated remediation *apply* (it needs
write permissions, which would destroy the read-only, holds-no-customer-secret
property that is currently the strongest security claim — generated pull
requests against the customer's IaC repository instead); MSP and advisor modes;
the AI copilot; a graph database; event streaming; microservices.

---

## 13. The short version

**Keep, and treat as non-negotiable.** The four-state rule algebra with UNKNOWN
as a first-class value, and the coverage ledger that makes it auditable. The
verbatim snapshot with a replay path that shares `_evaluate` with a live scan
and refuses to resolve findings from a superseded capture. The collection DAG
with per-task outcomes, where PARTIAL degrades a rule exactly as FAILED does.
Auto-resolve on an explicit PASS only. Dual-enforced tenancy against a
non-owner database role. An Azure integration that stores no customer secret at
all. The pattern in `rbac.py` where a declared permission set generates the
deployment artifact, with tests enforcing agreement in both directions.

Those are not implementation details. They are why this system can say
"verified fixed" and mean it, and each is nearly impossible to retrofit into a
codebase that shipped without it.

**Redesign, in order.** Orchestration first: the scan must become a durable,
leased, resumable state machine, because a worker restart currently bricks a
connection and no amount of analysis sophistication survives that. Evidence
second: from an opaque per-scan blob to addressable, provenanced, expiring,
reusable units — the single change that unlocks incremental scans, targeted
verification, cost reduction and real traceability, and the one that gets
dramatically more expensive to defer. The graph third: typed capability edges
over assets and identities, the only foundation on which attack paths and
correlation are buildable at all. And the identity scoping bug immediately,
because it is producing wrong findings today.

**Postpone without apology.** Temporal, a graph database, Kafka, microservices,
automated remediation apply, MSP mode, and AI anywhere near a verdict.

The principle behind all of it — that the system should understand the
environment before deciding what to collect — is right, and the pleasant
surprise of this review is that the hard half is already built.
`collection.py` is a genuine evidence-planning substrate that does not know
about rules yet. Wire the rules into it, give evidence an identity, give the
graph real edges, and make the orchestrator durable enough to survive a deploy.
That is years of work with no rewrite in it.
