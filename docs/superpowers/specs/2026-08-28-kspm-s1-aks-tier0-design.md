# KSPM S1 — AKS Tier 0 Posture

**Status:** design approved, not implemented
**Date:** 2026-08-28
**Scope:** first sub-project of the Kubernetes Security Posture Management programme

---

## 1. Why this exists

CloudGuard assesses Azure subscriptions. It does not look at Kubernetes. This
document specifies the first step toward doing so: AKS clusters become
first-class assets inside the Azure scans that already run, evaluated by
Kubernetes rules, mapped to a Kubernetes compliance framework.

The step is deliberately small. It ships value without asking a customer to
install anything, grant new consent, or create a new connection — they redeploy
one ARM template and their next scan returns cluster findings.

## 2. Programme context

KSPM is six subsystems, not one. They are listed here so this document's
boundaries make sense; only S1 is specified.

| | Sub-project | Depends on |
|---|---|---|
| **S1** | **AKS Tier 0 posture from the Azure control plane** | — |
| S2 | Tier 1 agentless read of the Kubernetes API server | S1 |
| S3 | Image inventory and vulnerabilities | S2 |
| S4 | Attack paths across Azure and Kubernetes | S2, better with S3 |
| S5 | IaC scanning (repository-triggered, a separate product surface) | — |
| S6 | Tier 2 in-cluster agent | S2 |

Order: S1 → S2 → S3 → S4. S5 and S6 are demand-driven.

"Continuous monitoring" is not a sub-project. It is scan cadence plus drift
detection over machinery that already exists.

## 3. Decisions this design rests on

Four choices were settled before the design, each recorded with its reasoning
because reversing any of them invalidates most of what follows.

**Kubernetes is a provider inside CloudGuard, not a separate product.** It
reuses the connector contract, rule engine, risk scorer, findings lifecycle,
compliance catalogue, tenancy and UI shell. Azure-first positioning is the
differentiator: cluster identity, node networking and Azure RBAC in one graph is
something a standalone KSPM tool cannot assemble.

**Collection is tiered, agentless-first.** Tier 0 reads the Azure control plane
(this document). Tier 1 reads the Kubernetes API server with a kubeconfig
obtained from Azure. Tier 2 is an in-cluster agent for what neither can reach:
node-level checks, private clusters, private registries, runtime. Rules degrade
to UNKNOWN when their tier is absent — never to PASS.

**Open-source tools split into facts and verdicts.** Tools that produce
observations CloudGuard cannot otherwise obtain are run as subprocesses and
their output is stored verbatim as snapshot data: syft for SBOMs, trivy or grype
for package-to-CVE matching (the value there is a continuously maintained feed,
not the logic), kube-bench for node configuration readings. Tools that produce
configuration verdicts — kubescape, checkov, KICS, kubesec — are not run; their
control catalogues and rule content are ported into CloudGuard rules and the
compliance catalogue. KubeHound contributes its attack-edge taxonomy and none of
its infrastructure. None of this is exercised in S1, which introduces no
external tool at all, but S3 and S4 depend on it.

Consequence for licensing: porting rule *content* from Apache-2.0 projects
requires a deliberate attribution decision, made once, before S3. KubiScan is
believed to be GPL-3.0 — verify before it influences any code.

**Tier 0 collects through Azure but models as Kubernetes.** One Azure scan
produces one snapshot and one graph. The normalizer emits cluster resources
tagged `provider=KUBERNETES`, and rules live in their permanent home from day
one. Two existing properties make this work without engine changes:
`ResourceRecord.provider` is written from the resource, not the account
(`app/services/scanner.py`), and the rule engine filters on `applies_to`
resource type only, never on provider (`app/rules/engine.py`).

The alternative of creating Kubernetes cloud accounts per cluster was rejected:
the credentials would still be the Azure connection's, and the cluster would
land in a different snapshot from its own subnet and NSG — splitting the graph
and destroying the cross-domain attack paths that motivate the whole approach.

Accepted cost: `CloudAccount.provider` stays AZURE while owning KUBERNETES
assets. Legal in the schema, but currently never occurs, so any place that
infers asset provider from account provider must be found and corrected.

## 4. Scope

### In scope

- A `kubernetes` collection category reading `managedClusters` from ARM.
- Node pools, read from the inline `agentPoolProfiles` of the same payload.
- Normalization to `provider=KUBERNETES` resources: cluster and node pool.
- Relationship edges: cluster contains node pool; NSG protects node pool.
- Thirteen `K8S-*` rules answerable from ARM data alone.
- A `CIS_AKS` framework in the compliance catalogue.
- UI: Kubernetes provider filter, cluster detail panel, stale-role prompt.

### Out of scope

Each is a later sub-project, not an oversight: API-server access or kubeconfig;
any in-cluster object (pods, workloads, in-cluster RBAC, secrets, network
policies, admission configuration); images and CVEs; IaC scanning; the agent;
attack paths; runtime detection; and every non-AKS cluster — EKS, GKE,
self-managed, and Azure Arc `connectedClusters`. Arc is the cheapest of those to
add later and is deferred deliberately.

### Done means

An existing customer redeploys their scanner role, the next scan lists their AKS
clusters as assets, findings carry `K8S-*` identifiers, and the compliance page
shows CIS AKS coverage against a stated denominator.

## 5. The role change, and why it shapes everything

The scanner role is a custom role with an explicit action list, not Reader
(`app/connectors/azure/rbac.py`). Every action must be exercised by a real
collector call; tests enforce that in both directions.

S1 adds one action, `Microsoft.ContainerService/managedClusters/read`, and bumps
`ROLE_VERSION` to `v2`. This is the first real use of the version-drift
machinery already built: `role_version` is stored per connection and already
surfaced in scan context (`app/services/scans.py`).

Every existing connection sits at `v1` and cannot read clusters until the
customer redeploys. Three requirements follow:

1. **Cluster rules on a stale role return UNKNOWN, never PASS.** A customer
   whose role predates cluster scanning must not be told their clusters are
   clean.
2. **The gap is visible and actionable in the UI** — not silently missing data.
3. **The action string is verified against `az provider operation show` before
   it ships.** ARM validates role definitions atomically: one plausible but
   non-existent operation fails the entire deployment with
   `InvalidActionOrNotAction`, and the customer sees only "Deployment Failed".
   This has happened before in this codebase and is recorded in `rbac.py`.

## 6. Collection

A new `ArmClient.list_managed_clusters(subscription_id)` calls
`/subscriptions/{id}/providers/Microsoft.ContainerService/managedClusters`,
pinned to a GA api-version in the style of every other call in that file.

Node pools return inline as `properties.agentPoolProfiles`, so collection costs
one request per subscription regardless of cluster count. No per-resource
fan-out, no change to `DETAIL_CONCURRENCY`.

**The api-version is load-bearing.** `securityProfile`, `oidcIssuerProfile` and
`networkProfile.networkDataplane` appear only on recent versions. Pinning too
old makes those fields absent on every cluster, which reads as UNKNOWN forever —
safe, but useless. The chosen version must be confirmed to expose every field
the rule set reads.

**Snapshot shape** follows existing convention: `data["kubernetes_clusters"]`
holds ARM payloads verbatim; failures record under category `"kubernetes"`.

**No credentials are collected.** `servicePrincipalProfile.clientId` is an
identifier, `aadProfile` holds group object ids, and the response contains no
keys, secrets or kubeconfigs. This matters because snapshots persist verbatim.

**Ordering.** The `kubernetes` category must be collected before `logging`,
because `_collect_logging` reads target ids out of `snapshot.data`. Cluster ids
join that target list, which yields cluster diagnostic settings under the
existing `Microsoft.Insights/diagnosticSettings/read` action — no new
permission.

**Stale roles need no special code.** A 403 is caught by `_collect_category`,
recorded as a category error, and the rule engine degrades every rule declaring
`requires_collection = ["kubernetes"]` to UNKNOWN. The safety property in §5
falls out of machinery that already exists.

**Validation probes rather than asks.** `validate_connection` gains a cluster
read alongside its Graph and ARM probes, consistent with that method's stated
philosophy. Success adds to `permissions_verified`; a 403 adds a problem naming
the redeploy, which drives the UI prompt without separate drift-detection logic.

**Empty is not denied.** A subscription with no clusters returns an empty list
and records no error, so cluster rules resolve NOT_APPLICABLE. A refused read
records an error, so they resolve UNKNOWN. Keeping those apart is the difference
between "you have no clusters" and "we could not look".

## 7. Domain model

### Vocabulary

- `Provider.KUBERNETES = "kubernetes"` — a real value, not an extension-point
  comment.
- `ResourceType.KUBERNETES_CLUSTER`, `ResourceType.KUBERNETES_NODE_POOL`.

Names are cloud-neutral so EKS and GKE map onto them later without renaming.

### Identity

Cluster `provider_resource_id` is its ARM id. Node pools have no id in the
inline profile, so it is synthesized as `{cluster_id}/agentPools/{name}` — the
real ARM id format for that sub-resource, so it remains correct if S2 reads that
API directly. Findings are keyed on these ids; an id whose shape changes later
orphans every finding attached to it.

### Relationships

Cluster `CONTAINS` node pool.

`NSG PROTECTS node_pool` is derived by matching a node pool's `vnetSubnetID`
against the `properties.subnets[]` already present on collected NSG payloads.
This needs no subnet resource type and no additional collection. It is the same
edge shape `AZ-CMP-001` uses to ask a VM which NSGs guard it, so a node pool can
query it through `get_related_inverse` with no engine change.

The edge is legitimately absent for AKS-managed vnets (no `vnetSubnetID`) and
for kubenet clusters whose NSG sits elsewhere. Both mean the network position is
unknown, not that it is safe, so dependent rules return UNKNOWN.

### Risk inputs

`public_exposure` derives from `apiServerAccessProfile`: private cluster → LOW;
public with authorized IP ranges → MEDIUM; public without → CRITICAL. The risk
scorer already multiplies severity by exposure, so Kubernetes findings receive
meaningful risk scores with no change to `app/risk/`.

Node pools inherit the cluster's environment and criticality, since tags live on
the cluster rather than the profile. `data_sensitivity` stays UNKNOWN unless
tagged — there is no honest inference from "it is a cluster".

### Normalizer restructuring

`normalizer.py` is 550 lines holding six category methods; S1 adds a seventh and
S2 would add roughly ten more object kinds. It becomes a package,
`connectors/azure/normalize/`, with one module per category (`nsgs`, `storage`,
`databases`, `vms`, `users`, `kubernetes`) and `AzureNormalizer` reduced to the
assembler that calls them and merges results.

The refactor must be behaviour-preserving: existing normalizer tests pass
untouched. If they require editing, the split changed something it should not
have.

## 8. Rules

Thirteen rules, identified as `K8S-<AREA>-<n>`, with `provider =
Provider.KUBERNETES`, under `app/rules/k8s/{api,identity,network,node,logging,security}/`.

| Id | Check | Severity |
|---|---|---|
| K8S-API-001 | Public API server with no authorized IP ranges | CRITICAL |
| K8S-API-002 | Private cluster with `runCommand` enabled | MEDIUM |
| K8S-ID-001 | Local accounts enabled | HIGH |
| K8S-ID-002 | Entra integration or Azure RBAC not enabled | HIGH |
| K8S-ID-003 | Kubernetes RBAC disabled | CRITICAL |
| K8S-ID-004 | Cluster Admin role granted at subscription scope or broadly | HIGH |
| K8S-ID-005 | Service principal with a long-lived secret instead of managed identity | MEDIUM |
| K8S-NET-001 | No network policy | HIGH |
| K8S-NET-002 | Node pool with public IPs on nodes | HIGH |
| K8S-NET-003 | Node subnet's NSG accepts inbound from the internet | HIGH |
| K8S-LOG-001 | No diagnostic settings — control-plane audit logs not exported | HIGH |
| K8S-SEC-001 | Azure Policy add-on disabled | MEDIUM |
| K8S-UPG-001 | Cluster runs an unsupported Kubernetes version | HIGH |


Notes on individual rules:

**K8S-ID-001** matters more than its name suggests. A cluster-admin client
certificate bypasses Entra entirely, cannot be revoked per user, and leaves no
directory audit trail.

**K8S-ID-004** is cross-domain and costs no new collection: role assignments and
definitions are already gathered, and listing at subscription scope returns
assignments at and below it. The "Azure Kubernetes Service Cluster Admin Role"
grants `listClusterAdminCredential`, which returns a certificate that bypasses
Entra and Azure RBAC — so a broad assignment silently undoes K8S-ID-001 and
K8S-ID-002 even when both pass. A KSPM tool without Azure context cannot produce
this finding.

**K8S-LOG-001** stays separate from `AZ-LOG-001`. Collection is shared, but
cluster audit logging concerns specific control-plane categories (`kube-audit`,
`kube-audit-admin`, `guard`) whose remediation shares nothing with storage
diagnostics, and an `AZ-` rule emitting findings against Kubernetes-provider
resources would blur the ownership line drawn in §3.

**K8S-UPG-001** needs data that ages. Rules are pure and cannot call the
network, so the supported-version floor lives as a single constant with a review
date, accompanied by a test that fails the build once that date passes. This
converts a rule that would quietly go wrong into a build failure someone must
look at.

### Deliberately excluded

Defender for Containers, workload identity and OIDC issuer, host encryption, KMS
etcd encryption, and auto-upgrade channels. Each is defensible; none is a
finding a customer would act on this quarter. Two would generate noise: AKS
already encrypts etcd with a platform key, and workload identity being disabled
only matters for clusters that use pod-assigned identity at all. Each is one
file to add later.

### Not registered as phantom rules

Privileged containers, hostPath and hostNetwork, root containers, default
service-account token mounting, secrets in environment variables, and pod
security standards are all invisible at Tier 0. None is registered as a rule
that always returns UNKNOWN. The compliance catalogue is the designed home for
"we do not check this": uncovered controls resolve to NOT_COVERED there, while a
registry full of never-passing rules would pollute coverage tables to say the
same thing worse.

## 9. Compliance

A `CIS_AKS` framework joins `catalog.py`, following the three rules that file
already establishes: control titles written in CloudGuard's own words (CIS text
is copyrighted), uncovered controls listed on purpose, and gaps stated at
whatever resolution is honest.

The scope note states the Tier 0 limitation explicitly — assessed from the Azure
control plane only, in-cluster configuration not read — so workload and
in-cluster RBAC sections appear as NOT_COVERED rather than disappearing and
inflating the percentage.

Rules also map into the existing ISO 27001, NIST CSF and GDPR catalogues where
the mapping is honest, and nowhere else.

Because per-organization framework selection does not exist yet, the compliance
page shows CIS AKS only when the organization has at least one
`KUBERNETES_CLUSTER` asset. Otherwise a cluster-less customer sees a framework
at 0%, which reads as failure when it means absence.

The benchmark version to pin must be confirmed against CIS's current publication
before the catalogue entry is written.

## 10. UI

- Provider filter gains Kubernetes on the assets and findings screens.
- Cluster detail gains a summary panel — API access mode, Entra and RBAC mode,
  network policy, version, node pools — because a generic key-value rendering of
  `resource_metadata` is unreadable for an object of this shape.
- Connection status gains the redeploy prompt, driven by the
  `validate_connection` probe result joined against the stored `role_version`.

## 11. Database

No migration. Enum columns are VARCHAR-backed through `StrEnumType` rather than
native PostgreSQL enums (`app/models/resource.py`), so new `Provider` and
`ResourceType` values need no `ALTER TYPE`. The new values fit the declared
column lengths.

## 12. Testing

In priority order:

1. **A denied cluster read produces UNKNOWN, never PASS.** The safety property
   the entire stale-role story rests on.
2. **Absent is not false.** An api-version that omits `disableLocalAccounts`
   must read UNKNOWN, not "local accounts are disabled". Every rule tests the
   missing-field case separately from the false case. This is the most likely
   way the rule pack goes quietly wrong.
3. **The normalizer split is behaviour-preserving** — existing tests pass
   untouched.
4. Fixture-based rule tests over sanitized real `ManagedCluster` payloads, with
   no network and no database, per the existing strategy.
5. The NSG-to-node-pool edge, including both absent-edge cases resolving to
   UNKNOWN.
6. The expiring version-currency test.
7. The existing bidirectional RBAC test — every action has a call, every call
   has an action — stays green with the new action and client method.

## 13. Rollout

Sequenced so no intermediate state misleads a customer:

1. Verify the ARM action string with `az provider operation show`.
2. Ship collection, normalization and rules.
3. Bump `ROLE_VERSION` to `v2` and update the ARM template.
4. Surface the redeploy prompt.

Rules landing before the role bump is correct: they return UNKNOWN until the
customer redeploys. The reverse order would show empty cluster sections with no
explanation.

## 14. Verify before implementing

Four factual claims in this document were made from memory and must be confirmed
first. Each would change the design if wrong.

- The exact ARM action string `Microsoft.ContainerService/managedClusters/read`.
- Which GA api-version exposes every field the rule set reads, and that the list
  call returns full `properties` rather than a summary projection.
- That listing role assignments at subscription scope returns assignments at
  cluster scope beneath it, as K8S-ID-004 assumes.
- The current CIS AKS Benchmark version number.

## 15. Open questions for later sub-projects

Recorded so they are not rediscovered: attribution policy for ported rule
content (before S3), KubiScan's licence (before any use), graph representation
for attack paths — recursive CTE versus Apache AGE (S4), and whether Arc
`connectedClusters` joins Tier 0 or waits for its own sub-project.
