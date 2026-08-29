# CloudGuard — Designing for AWS and GCP

Design only. Nothing here is implemented, and deliberately so: most of it should
not be built until a second provider actually exists, because an abstraction
guessed at from one example is usually wrong in the places that matter.

What this document is for is the opposite — deciding which of today's shapes are
load-bearing and must not drift while Azure is the only provider, and naming the
one defect worth fixing before any of it starts.

---

## 1. What already generalizes

These carry no provider knowledge and need no change:

* **`connectors/collection.py`** — the plan, the executor, waves, outcomes,
  the coverage report. Written provider-neutral and it held.
* **`CloudConnector`** — `validate_connection` / `collect` / `normalize` is the
  right three-verb contract for all three clouds.
* **The rule engine, risk scorer, findings lifecycle, compliance machinery.**
  All speak `CloudResource` and `RuleContext`.
* **`ScanPipeline`** below the snapshot. Everything after collection is a pure
  function of stored JSON, and stays so.

The single most valuable thing already built is the pattern in `rbac.py`, not
its contents: a declared permission set, frozen per version, mapped to the
collection tasks that need it, generating the customer's deployment artefact,
with a test enforcing agreement in both directions. AWS and GCP each want
exactly that, in their own vocabulary.

---

## 2. What does not generalize

**Azure vocabulary sits in shared tables.** `cloud_accounts` has `tenant_id` and
`subscription_id`; `cloud_connections` adds `scope_type`, `scope_id`,
`service_principal_object_id`, `consent_status`. These are not neutral columns
with Azure values — they are Azure concepts.

**Eleven import sites reach into `connectors/azure` from outside it** —
`services/cloud_connections.py`, `services/cloud_accounts.py`,
`api/routes/cloud_connections.py`, `connectors/registry.py`. Onboarding is the
Azure-coupled half of the application; scanning is not.

**There is no region dimension.** See §4 — it is the largest structural
difference, and it is not a naming problem.

**`SecurityRule.matches()` ignores `self.provider`.** See §6.

---

## 3. Scope vocabulary

Three hierarchies, one shape:

| | trust boundary | scanned unit | grouping |
|---|---|---|---|
| Azure | tenant | subscription | management group |
| AWS | organization | account | organizational unit |
| GCP | organization | project | folder |

**Decision: two neutral columns plus a provider blob.** `provider_directory_id`
(the trust boundary CloudGuard is trusted *by*) and `provider_account_id` (the
unit a scan reads), with `provider_ref JSONB` for everything that is genuinely
provider-shaped — the Entra service principal object id, the AWS role ARN and
external id, the GCP workload identity pool.

Rejected: renaming to fully abstract terms. "Scope" and "principal" read as
nothing to the customer support engineer trying to match a row against what they
see in a portal. The neutral column names above stay close to what each provider
calls the thing.

Region is deliberately **not** part of identity. An AWS account is the scanned
unit; its regions are a collection concern.

---

## 4. The region dimension

Azure ARM lists a subscription's resources globally. AWS does not: almost every
`Describe*` is per-region, and a customer with 17 enabled regions turns a
12-task plan into ~200 tasks per account. Multiply by accounts in an
organization and the plan is thousands of calls.

Two ways to absorb it.

**(a) Fan out the plan.** `CollectionTask` gains an optional `region`, and the
builder emits one task per (listing × region). The executor already handles
waves, concurrency and per-task outcomes, so it absorbs this without change —
which is a good sign about the executor. The costs are real though: progress
totals grow by an order of magnitude, the coverage report gains a region axis,
`_scoped_key` becomes account+region, and rate budgeting has to become
per-region-per-service because that is how AWS actually throttles.

**(b) Ask the provider's own inventory first.** AWS Resource Explorer, a Config
aggregator, or Cloud Control API can answer "what exists, where" in one call;
GCP's Cloud Asset Inventory does the same per organization. Then fan out detail
calls only to regions that hold something.

**Decision: (b) primary, (a) fallback.** Same reasoning as preferring Defender
for Cloud over a second scanner: let the provider do the fan-out it is built for,
and keep our own enumeration for what the aggregator cannot answer or the
customer has not enabled. Fallback matters — Resource Explorer is opt-in, and a
customer without it must still be scannable rather than reported as empty.

The honest cost of (b): the aggregator is a second thing that can be stale or
disabled, and a stale index reads as a complete one. It gets a `PARTIAL`, for
exactly the reason a truncated listing does.

---

## 5. Establishing trust

The model already holds **two independent grants, each verified by calling**
(`consent_status` and `rbac_verified_at`, proven by `validate_connection`). That
generalizes; what differs is how many grants there are and what deploys them.

**Azure** — Entra admin consent for Graph, plus the ARM role. Two grants, two
failure modes, and they fail independently. Already built.

**AWS** — one cross-account IAM role, assumed via `sts:AssumeRole`. The
**ExternalId is mandatory and must be per-customer and unguessable**. Without it,
anyone who learns CloudGuard's account id can create a role trusting us and have
us scan an environment on their behalf — the confused deputy, and the standard
way third-party CSPM integrations get this wrong. It belongs in `provider_ref`,
generated server-side, never customer-supplied.

The deployment artefact is a **CloudFormation "Launch Stack" URL** — the direct
analogue of Deploy to Azure, and it should be generated from the declared
permission set the same way, not hand-maintained. StackSets cover the
organization-wide case that management-group scope covers on Azure.

**GCP** — a service account with a custom role, reached by **Workload Identity
Federation** rather than an exported key. A downloaded service account key is a
long-lived credential in our database, which is precisely what the Azure design
avoided ("holds NO customer secret" — `cloud_account.py`); adopting one for GCP
would give that property up for the whole product. Deployment via Terraform or
`gcloud`, generated from the same declaration.

---

## 6. Rules: per-provider, over neutral types

**Decision: rules stay provider-specific. Resource types stay neutral.**

The temptation is one `PublicObjectStorageRule` covering Azure Storage
Accounts, S3 buckets and GCS buckets. Resist it, for a reason that is not
aesthetic: **`remediation` is snapshot-copied onto every finding** and is
provider-specific by nature — `az storage account update` and
`aws s3api put-public-access-block` are not variants of one sentence. A shared
rule would have to branch on provider to produce it, and branching on provider
inside a rule is the same mistake as branching on framework name, which
requirement 15 already forbids.

Share helpers, not rules. Where two providers really do express one concept, the
normalizers converge on one `ResourceType` and the two rules each stay a dozen
lines.

`ResourceType` names are Azure-flavoured (`STORAGE_ACCOUNT`, `SQL_SERVER`) but
the concepts are neutral. Rename at the point a second provider maps onto them,
not before — a rename with one caller is bookkeeping, a rename with two is a
decision.

### The one defect to fix now — done

`SecurityRule.provider` was declared and never read, so `matches()` compared
only the resource type. Types are cloud-neutral, so on the first day an AWS
bucket normalized to `STORAGE_ACCOUNT` every Azure storage rule would have
evaluated it and produced findings carrying `az storage account update` as the
fix for something in AWS.

Fixed in two places, because it was two holes. `matches()` now compares the
provider, which covers per-resource rules. AGGREGATE rules never call `matches`
— they read `context.resources` and `get_resources_by_type` directly — so
`RuleContext.for_provider()` narrows the context and `RuleEngine` scopes each
rule to its own cloud, memoized per provider rather than per rule. A
single-provider context returns itself unchanged, so today's scans pay nothing.

`tests/unit/test_rule_provider_scope.py` pins both paths.

---

## 7. Compliance

`FRAMEWORKS` is a tuple and `catalog.py` is data, so CIS AWS and CIS GCP are
additive. One thing does need changing: **coverage must be scoped by provider.**
An AWS-only tenant measured against CIS Azure would report near-zero coverage
for reasons that have nothing to do with its security posture, which is the same
class of misleading number the coverage ledger exists to prevent.

---

## 8. Order, when the time comes

1. ~~Fix `matches()`.~~ Done, along with the aggregate-path hole beside it.
2. Second provider's connector, plan and normalizer — behind the existing
   `CloudConnector` seam, changing nothing above it.
3. The permission-manifest pattern generalized out of `rbac.py`, once there are
   two instances to generalize from.
4. Scope vocabulary migration, driven by what the second connector actually
   needed rather than by this document's guess.
5. Onboarding services split by provider — the eleven import sites, which are
   worth untangling only when there is a second thing to untangle them for.

Steps 3 through 5 are deliberately after step 2. Every one of them is a
refactor whose right shape is knowable from two examples and guessable from one.
