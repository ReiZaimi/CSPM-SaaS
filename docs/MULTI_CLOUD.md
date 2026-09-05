# CloudGuard — Designing for AWS and GCP

Written as design only, while Azure was the only provider: most of it should not
be built until a second one exists, because an abstraction guessed at from one
example is usually wrong in the places that matter.

That is no longer entirely true of the document. AWS is now being built, and the
sections it has reached say so — with what the work actually needed replacing
what this file guessed, since the guesses are only worth keeping where they held.
Everything still marked as design is still design.

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

~~**Eleven import sites reach into `connectors/azure` from outside it.**~~
Down to the registry, which is where mapping a provider to its implementation
belongs. Onboarding sits behind `ProviderOnboarding` (`DECISIONS.md` §71) and
`test_provider_seam.py` has no scheduled exceptions left.

~~**There is no region dimension.**~~ Built. See §4 — it was the largest
structural difference, and it was not a naming problem: readings are now scoped
by region while verdicts stay per evidence key (`DECISIONS.md` §69).

**Rules could judge another cloud's resources.** Fixed ahead of the rest, since it was cheap while still theoretical. See §6.

---

## 3. Scope vocabulary

Three hierarchies, one shape:

| | trust boundary | scanned unit | grouping |
|---|---|---|---|
| Azure | tenant | subscription | management group |
| AWS | organization | account | organizational unit |
| GCP | organization | project | folder |

**Decided as two neutral columns plus a provider blob. Half built** — see
`DECISIONS.md` §70. `provider_ref JSONB` exists on both tables and carries what
is genuinely provider-shaped: the AWS role ARN and external id, later the GCP
workload identity pool.

The rename of `tenant_id` / `subscription_id` to `provider_directory_id` /
`provider_account_id` is **not** done, for a reason this section did not have.
`RawSnapshot.to_json` writes those two names into every stored capture, so
renaming the columns alone leaves two vocabularies and renaming both makes every
capture already taken unreplayable. It is worth doing against a migration of the
stored snapshots, which is its own piece of work. The columns are neutral enough
to carry AWS meanwhile — an organization id and an account id, under names that
happen to be Azure's.

`ConnectionScope` did gain AWS's three levels, in one enum rather than two.

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

**Decided here as (b) primary, (a) fallback. Built as (a).** The reasoning for
(b) still holds — let the provider do the fan-out it is built for — but the
fallback is the part every customer needs, because Resource Explorer is opt-in
and a customer without it must be scannable rather than reported as empty. So
(a) is what exists, and (b) is an optimization to add on top of a working
enumeration rather than the thing the first connector rests on.

The honest cost of (b), when it comes: the aggregator is a second thing that can
be stale or disabled, and a stale index reads as a complete one. It gets a
`PARTIAL`, for exactly the reason a truncated listing does.

**What (a) actually cost, now that it is built** (`DECISIONS.md` §69). Rather
less than this section feared, and in a different place. `CollectionTask` gained
a `region` and the executor absorbed the fan-out without changing shape, as
predicted. What it did not predict: the region could not go into the
`EvidenceKey`, because that is what a rule declares and a rule has no business
knowing which regions a customer enabled — so readings are scoped by key *and*
region while verdicts stay per key, and a key is trustworthy only if every
region's reading of it was. The `evidence` unique constraint had to grow the
column too. And a wave needed a concurrency cap for the first time, since
seventeen regions × nine listings in one wave is a shape designed to be
throttled.

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

**Built, and no rename yet** (`DECISIONS.md` §74). An S3 bucket normalizes to
`STORAGE_ACCOUNT`, an RDS instance to `SQL_SERVER` or `POSTGRESQL_SERVER` by
engine, an IAM role to `SERVICE_PRINCIPAL`. Reading those in AWS code is mildly
odd and nothing more; renaming them now, inside the change that adds the second
provider, would put a migration of stored resource rows in the way of shipping
it. It is a decision with two callers now, which is when this section said to
make it — worth doing, and worth doing on its own.

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

## 7. Compliance — built

`FRAMEWORKS` is a tuple and `catalog.py` is data, so CIS AWS 3.0 was additive
exactly as predicted. The one thing that needed changing did: **coverage is
scoped by provider.** `Framework` carries one, and a cloud benchmark is shown
only to organizations that connect that cloud — an AWS-only tenant measured
against CIS Azure would report near-zero coverage for reasons that have nothing
to do with its security posture.

Two details the section did not anticipate. Frameworks written about
*organizations* — ISO, GDPR, NIST, SOC 2, PCI — carry no provider and are always
shown, because scoping them by cloud would hide the ones that always apply. And
the scoping keys off *any* connection rather than a verified one, so the AWS
benchmark appears while a customer is still setting AWS up.

---

## 8. Order, when the time comes

0. ~~Prove the seam.~~ Done. "Everything above `CloudConnector` is
   provider-neutral" was an intention, not a fact: three neutral modules
   imported `connectors/azure` directly, and each gave the right answer only
   because Azure is the only provider. The pipeline asked Azure's evidence enum
   which keys a category holds; the permissions endpoint returned Azure's grants
   whatever the provider; the change-event service spelled ARM operation names.
   All three now go through the connector or the registry, the signed-state
   helper moved to `app/core/signing.py` (nothing in it was ever Azure), and
   `tests/unit/test_provider_seam.py` fails the build on the next one. This step
   was not in the original list because nobody had checked.
1. ~~Fix `matches()`.~~ Done, along with the aggregate-path hole beside it.
2. ~~Second provider's connector, plan and normalizer.~~ Built —
   `app/connectors/aws/`, behind the existing `CloudConnector` seam
   (`DECISIONS.md` §72). It changed nothing above the seam except the region
   dimension, which landed in the collection executor rather than in the
   connector.

   **This section said it was not startable from a desk, and it was started
   from one.** The warning stands and is now a live liability rather than a
   prediction. Every IAM action name, response key, pagination shape and the
   CloudFormation template is written from the published reference and has been
   called by nothing. IAM makes this worse than the Azure case it was arguing
   from: ARM refuses a role definition atomically, so a wrong action fails the
   deployment visibly, while IAM accepts a policy naming an action that does not
   exist and simply grants nothing — the customer sees a successful deployment
   and a scan that fails later.

   So the risk was taken deliberately and is bounded by two things rather than
   by optimism. Every unverified string is marked in the code, and AWS is
   reachable through the API but **not offered in the UI** until
   `AWS_INTEGRATION.md` §1's checklist has been run against a real account.
   Without that gate this would be exactly what the paragraph warned about: a
   large body of code claiming to scan a cloud nobody had scanned, with the seam
   *looking* finished.
3. The permission-manifest pattern generalized out of `rbac.py`, once there are
   two instances to generalize from.
4. Scope vocabulary migration, driven by what the second connector actually
   needed rather than by this document's guess.
5. ~~Onboarding services split by provider.~~ Done, and step 2 forced it
   rather than the other way round: the AWS connector could not be reached
   without a connection, and a connection could not be made without a flow that
   was not Azure's. `ProviderOnboarding` is what the two clouds turned out to
   have in common — deploy something generated from the declared permission
   set, prove the grant by using it, discover what is beneath the scope — with
   the steps a provider lacks answering "nothing to do" rather than being
   special-cased by the caller (`DECISIONS.md` §71).

Steps 3 through 5 are deliberately after step 2. Every one of them is a
refactor whose right shape is knowable from two examples and guessable from one.
