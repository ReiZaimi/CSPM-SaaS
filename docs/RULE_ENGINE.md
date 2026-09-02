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
    exploitability: int              # 0-5, static -- feeds the risk formula
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

## 5. Initial Rule Set (10 rules, expand to 30–50 post-MVP)

| Rule | Category | Severity | Exploitability |
|---|---|---|---|
| AZ-ID-001 — MFA missing for privileged user | Identity | CRITICAL | 4 |
| AZ-ID-002 — Excessive privileged users (AGGREGATE) | Identity | HIGH | 3 |
| AZ-NET-001 — RDP exposed to Internet (0.0.0.0/0 → TCP/3389) | Network | CRITICAL | 5 |
| AZ-NET-002 — SSH exposed to Internet (0.0.0.0/0 → TCP/22) | Network | HIGH | 4 |
| AZ-NET-003 — Unrestricted inbound NSG rule | Network | HIGH | 4 |
| AZ-STO-001 — Storage account allows public access | Storage | HIGH | 5 |
| AZ-STO-002 — Storage encryption/security config insufficient | Storage | HIGH | 2 |
| AZ-DB-001 — Database publicly accessible | Database | CRITICAL | 5 |
| AZ-LOG-001 — Required activity/diagnostic logging not configured | Logging | MEDIUM | 1 |
| AZ-CMP-001 — Internet-exposed compute with admin service exposed | Compute | HIGH | 4 |

Exploitability (0–5) is a proposed starting value for each rule — tune after testing against real environments, same as the risk-formula weights in `RISK_ENGINE.md`.

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
]
```
