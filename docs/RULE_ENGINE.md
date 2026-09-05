# CloudGuard — Rule Engine

Rules are deterministic. Every evaluation returns one of four states, and **UNKNOWN must never be treated as PASS.**

```
PASS   FAIL   UNKNOWN   NOT_APPLICABLE
```

---

## 1. Interface

Most rules are per-resource (RDP exposure → one NSG at a time); some are genuinely aggregate ("excessive privileged users" is a statement about the whole tenant). One interface covers both:

```python
class RuleScope(str, Enum):
    PER_RESOURCE = "per_resource"   # engine calls evaluate() once per matching resource
    AGGREGATE = "aggregate"         # engine calls evaluate() once per scan, resource=None

class RuleResult:
    state: Literal["PASS", "FAIL", "UNKNOWN", "NOT_APPLICABLE"]
    evidence: dict | None = None
    message: str | None = None
    resource_id: str | None = None   # required when an AGGREGATE rule emits multiple results

class RuleContext:
    def get_resource(self, resource_id: str) -> CloudResource: ...
    def get_resources_by_type(self, resource_type: str) -> list[CloudResource]: ...
    def get_related(self, resource: CloudResource, relationship_type: str) -> list[CloudResource]: ...

class SecurityRule(ABC):
    rule_id: str
    version: str
    severity: Severity
    category: str
    exploitability: int              # 0-5, REQUIRED -- the worst instance (section 5)
    scope: RuleScope = RuleScope.PER_RESOURCE
    applies_to: list[str] = []       # resource types this rule targets (PER_RESOURCE only)
    risk_grouping: RiskGrouping | None = None   # several findings, one risk (RISK_ENGINE.md section 2)

    def evaluate(
        self, resource: CloudResource | None, context: RuleContext
    ) -> RuleResult | list[RuleResult]:
        ...

# Example
class AzureRdpExposureRule(SecurityRule):
    rule_id = "AZ-NET-001"
    version = "1.0"
    applies_to = ["network_security_group"]

    def evaluate(self, resource, context):
        if allows_public_rdp(resource):
            return RuleResult(state="FAIL", evidence={
                "source": "0.0.0.0/0", "protocol": "TCP", "port": 3389
            })
        return RuleResult(state="PASS")
```

`AZ-NET-001` (RDP exposure) is `PER_RESOURCE`, `applies_to = ["network_security_group"]`. `AZ-ID-001` (MFA missing) is also `PER_RESOURCE`, targeting `applies_to = ["user"]` — one finding per user. `AZ-ID-002` (excessive privileged users) is the one genuinely `AGGREGATE` rule in the initial 10: `evaluate(None, context)` returns a single result (or an empty list if under threshold).

`RuleContext.get_related()` walks the `resource_relationships` table (see `DATABASE.md`) so a rule can confirm an NSG is actually attached to something live before flagging it — an unused, unattached NSG allowing RDP is noise, not a Critical finding.

---

## 2. Evaluation → Findings and Coverage

- **FAIL** → creates or updates a Finding (matched by `rule_id` + `resource_id`).
- **UNKNOWN** → does **not** become a Finding — a Finding means "we observed something wrong", UNKNOWN means we couldn't observe anything. Logged to `scan_evaluation_gaps` for the coverage indicator.
- **PASS / NOT_APPLICABLE** → not persisted per-row (resources × rules per scan is real row bloat for no benefit); rolled into `scan_rule_results` aggregate counts.

Coverage = `(passed + failed) / (passed + failed + unknown)` among applicable evaluations.

---

## 3. Rescan Verification Is Automatic

When a later scan runs the same rule against the same resource and returns PASS where a prior scan had FAIL, the engine auto-transitions that open Finding to `RESOLVED`, stamped with the verifying scan (`resolved_at`). **No human marks anything "verified"** — the scan result *is* the verification. This is the concrete mechanism behind "CloudGuard verified the fix."

---

## 4. Remediation Text & Versioning

- `rules.remediation` is a static template; snapshot-copied into `findings.remediation` at creation so later edits to a rule's guidance don't rewrite history on old findings.
- `findings.rule_version` records which rule version raised it. No automatic migration when a rule changes — the next scan simply re-evaluates under the new version.
- The DB `rules` table is a **read-mirror synced from the Python registry** at startup/deploy, not independently editable — changing a rule means changing code, not a DB row.

---

## 5. The Rule Set

| Rule | Category | Severity | Exploitability |
|---|---|---|---|
| AZ-ID-001 — MFA missing for privileged user | Identity | CRITICAL | 4 |
| AZ-ID-002 — Excessive privileged users (AGGREGATE) | Identity | HIGH | 3 |
| AZ-ID-003 — Privileged account is dormant | Identity | HIGH | 3 |
| AZ-APP-001 — Application credential valid for years | Identity | MEDIUM | 3 |
| AZ-IAM-001 — Person holds full control of a subscription | Identity | HIGH | 3 |
| AZ-IAM-002 — Workload identity holds full control of a subscription | Identity | HIGH | 3 |
| AZ-IAM-003 — Identity can grant itself any role | Identity | CRITICAL | 3 |
| AZ-NET-001 — RDP exposed to Internet (0.0.0.0/0 → TCP/3389) | Network | CRITICAL | 5 |
| AZ-NET-002 — SSH exposed to Internet (0.0.0.0/0 → TCP/22) | Network | HIGH | 4 |
| AZ-NET-003 — Unrestricted inbound NSG rule | Network | HIGH | 4 |
| AZ-NET-004 — WinRM exposed to Internet (TCP/5985, TCP/5986) | Network | CRITICAL | 5 |
| AZ-STO-001 — Storage account allows public access | Storage | HIGH | 5 |
| AZ-STO-002 — Storage encryption/security config insufficient | Storage | HIGH | 2 |
| AZ-STO-003 — Storage account accepts insecure connections | Storage | MEDIUM | 2 |
| AZ-VULN-001 — Internet-facing machine has unpatched vulnerabilities | Posture | CRITICAL | 5 |
| AZ-MAL-001 — Machine has no working endpoint protection | Posture | MEDIUM | 2 |
| AZ-DB-001 — Database publicly accessible | Database | CRITICAL | 5 |
| AZ-DB-002 — Sensitive database has no private connectivity | Database | MEDIUM | 2 |
| AZ-DB-003 — Database server keeps no audit trail | Database | MEDIUM | 1 |
| AZ-KV-001 — Key vault can be permanently destroyed | Secrets | HIGH | 2 |
| AZ-KV-002 — Key vault answers the whole internet | Secrets | HIGH | 4 |
| AZ-LOG-001 — Required activity/diagnostic logging not configured | Logging | MEDIUM | 1 |
| AZ-LOG-002 — Subscription activity log is not exported | Logging | MEDIUM | 1 |
| AZ-CMP-001 — Internet-exposed compute with admin service exposed | Compute | HIGH | 4 |
| AZ-CMP-002 — Virtual machine governed by no security group | Compute | MEDIUM | 2 |

### What bounds this list

Not ambition. Every rule here reads evidence a collector actually produces, and
the constraint is the collectors rather than the writing: there are 21 evidence
keys, and a rule outside them could only ever return UNKNOWN.

So the categories a CSPM is expected to cover and this list does not — backup
configuration among them — are absent because the evidence is, and they arrive
when a collector for them does. Two left that list together: application
credentials and dormant privileged accounts, each with the collector its rule
reads. Vulnerabilities and endpoint protection left that list
the way the others will: by reading Microsoft Defender for Cloud's assessments,
which are facts only the machine knows and only Defender is positioned to
report. Key vault was the first to arrive that way: a v3 scanner role, one ARM
listing, and the two rules it exists to serve.

Not every gap costs a permission, and it is worth checking before assuming one
does. The subscription activity log — the record of *who* changed what, as
against what changed — needed no new action at all: a subscription is a scope
diagnostic settings apply to like any other, so the collector asks about one
more id under the permission every customer already granted in v1. The two
identity gaps that closed last were the same story on the Graph side: admin
consent has requested `Application.Read.All` and `AuditLog.Read.All` since
onboarding existed, no collector had ever called anything needing them, and
between them they reach application credentials and `signInActivity`. Neither
was a re-consent; both were a collector (`DECISIONS.md` §63), and both now
ship.

Dormancy carries the one caveat that is not about permissions at all.
`signInActivity` needs an Entra ID P1 or P2 licence, so a fully consented
tenant on the free tier is refused exactly that reading and AZ-ID-003 reports
UNKNOWN naming the licence. A licence is not something a Global Administrator
can consent their way to, and saying "consent is missing" to a tenant whose
consent is complete would send somebody to fix a directory that is already
correct.

And not every gap is worth closing. Managed disk encryption was scoped and
dropped: managed disks are always encrypted at rest and cannot be turned off, so
a check for it reports PASS for everyone, which is how a catalogue grows in size
and shrinks in signal.

Transparent data encryption was dropped on the same reasoning and has since been
built anyway (AZ-DB-006, role `v6`), which is worth recording as a reversal
rather than quietly overwriting. The original argument still holds on its own
terms -- TDE has been on by default for Azure SQL since 2017, so the check costs
a permission and a per-database fan-out to report PASS for very nearly everyone.
What changed is what a pass is for. Encryption at rest is a control an auditor
asks about by name, and since the compliance view began citing the readings
behind each control, a pass carrying its provenance is the evidence somebody
needs rather than a row nobody reads (`DECISIONS.md` §67). The two answers that
are not a pass are also worth having: a database somebody turned it off on, and
one whose state could not be read. SQL auditing is the opposite —
off by default, one call per server — so v4 carries that action and only that
one. Adding the rule first would produce a
catalogue that looks complete and answers UNKNOWN, which is worse than a shorter
one that answers.

The RBAC rules are the exception that proves it. They needed no new collection —
role assignments were already read for the graph. What they needed was for the
normalizer to record *which role* a directory user holds, rather than only that
they reach a scope: an edge cannot say "Owner", so "this named person holds Owner
over your subscription" was a fact CloudGuard collected, drew a line for, and
could not state.

Exploitability (0–5) is a proposed starting value for each rule — tune after testing against real environments, same as the risk-formula weights in `RISK_ENGINE.md`.

### The scale

What the attacker must **already have**:

| | Needs |
|---|---|
| 5 | nothing — anonymous, from the internet, today |
| 4 | a credential of the kind routinely phished or sprayed, or a guessable identifier |
| 3 | a valid credential, or an existing foothold in the environment |
| 2 | a foothold plus a particular position: a role, a host, a network |
| 1 | no exploitation on its own — it weakens detection or defence in depth |
| 0 | not exploitable |

**Required, with no default.** A default of 0 meant a rule whose author never considered this silently asserted "not exploitable" — the same overclaim as a PASS nobody earned. `severity` is declared the same way for the same reason: leaving it out is an `AttributeError`, not a quiet answer.

**A ceiling, not a constant.** The class value describes the *worst* instance of the misconfiguration. Where the evidence shows one instance is less exploitable, `evaluate` returns a lower value on that `RuleResult` and the risk formula uses it:

| Rule | Steps down when | To |
|---|---|---|
| AZ-NET-001/002/003 | the NSG protects nothing — nobody can reach a machine it does not guard | 1 |
| AZ-STO-001 | the account is open to every network but anonymous blob access is off, so a key or SAS is still needed | 3 |
| AZ-DB-001 | the only over-broad firewall rule is Azure's `0.0.0.0-0.0.0.0` shortcut: every Azure tenant, not the open internet | 3 |

Never up. The class value is the tuned number, and a rule able to raise it per finding would be retuning itself one finding at a time. The clamp enforces `0 ≤ value ≤ tag`, so a mistaken override can only understate.

### Compensating controls

A rule may also return `controls` on a `RuleResult` — defences observed in the *same capture* that make the finding harder to exploit. Each is a ceiling on the same scale, so `effective_exploitability` is the minimum of the tag, the instance step-down, and every control. Several controls therefore compose to the strongest of them without any of them knowing the others exist.

Three rules, in `app/rules/controls.py`:

- **A control never turns FAIL into PASS.** The misconfiguration is still there, and the control can be disabled, rescoped, or have the affected principal excluded in a change nobody reviews.
- **Only prevention counts.** Detection is not compensation — Defender watching a storage account changes who finds out, not what an attacker must have, and this scale is written in terms of the second.
- **The control must be observed.** One CloudGuard could not fully read is absent, and the finding keeps its full score.

Implemented for AZ-ID-001, from evidence read under `Policy.Read.All` and `Group.Read.All` — both already consented, so no customer grants anything new:

| Control | Applies when | Leaves |
|---|---|---|
| Entra security defaults | `isEnabled` is true — every account is challenged | 3 |
| A Conditional Access policy | enabled (not report-only), grants MFA unambiguously, covers **all** applications, covers this account by `All`, by user id or by a directory role, and does not exclude it | 3 |

A policy is discarded rather than weakened whenever any part of it is unresolved: `MFA or compliantDevice` under `OR` is not multi-factor; a policy scoped to particular applications makes no claim, since CloudGuard cannot know which one an attacker would use; and a policy excluding a group whose membership never arrived is dropped outright, because that group could be the one holding the account being judged. Directory role template ids are resolved from the tenant's own `directoryRoles` rather than from a table of GUIDs — the discipline `rbac.py` applies to ARM action strings.

**Not yet modelled, and why.** Just-in-time VM access would be the obvious control for AZ-NET-001/002, and adding it needs `Microsoft.Security/locations/jitNetworkAccessPolicies/read` in the scanner role. `rbac.py` requires every action string to be verified against `az provider operation show` first — an unverified one fails the customer's whole role deployment atomically, as `autoProvisioningSettings/read` did — and it would cost every existing customer a role redeploy. It goes in when the string has been checked against a real tenant, not before.

Registry:

```python
RULE_REGISTRY = [
    AzureMfaRule(),
    AzurePrivilegedUserRule(),
    AzurePublicRdpRule(),
    AzurePublicSshRule(),
    AzureOpenNsgRule(),
    AzurePublicStorageRule(),
    AzureStorageEncryptionRule(),
    AzurePublicDatabaseRule(),
    AzureLoggingRule(),
    AzureExposedComputeRule(),
    # ... and thirteen AWS rules, which are separate classes rather than the
    # same ones taught a second cloud.
    AwsPublicBucketRule(),
    AwsPublicSshRule(),
    AwsUserWithoutMfaRule(),
]
```

**Rules are per provider; resource types are not.** An S3 bucket and an Azure
storage account both normalize to `STORAGE_ACCOUNT`, so `matches()` compares the
provider as well as the type, and the engine narrows the context per provider for
the aggregate rules that never call `matches()` at all. Without both, an Azure
rule would judge a bucket and the finding would carry `az storage account update`
as the fix for something in AWS.

The reason rules are not shared is `remediation`. It is snapshot-copied onto
every finding, so a shared rule would have to branch on provider to produce the
fix — the same mistake as branching on framework name, which requirement 15
already forbids (`MULTI_CLOUD.md` §6, `DECISIONS.md` §74).
