# CloudGuard — Roadmap (Post-MVP)

Architecturally anticipated, **not implemented in the MVP** — extension points only. Nothing in this file should influence what gets built now; see `PRODUCT_SPEC.md` §5 for explicit non-goals.

---

## Compliance — **partly built**

The chain below is implemented for CIS Azure 2.0, CIS AWS 3.0 (31 of the 56
controls catalogued; thirteen of the gaps are section-4 metric filters, all the
same shape as the two that are covered), ISO 27001,
GDPR, NIST CSF, NIST SP 800-53 Rev. 5, the SOC 2 Trust Services Criteria and PCI
DSS v4.0.1. A cloud benchmark is shown only to organizations that connect that cloud
(`DECISIONS.md` §74); the rest are about organizations rather than providers and
always apply:
`app/compliance/catalog.py` (frameworks and controls, as data),
`app/services/compliance.py` (coverage against the latest scan), and the
`/compliance` screens. See `DECISIONS.md` §"Compliance mappings drive a coverage
view".

```
Technical Control → Evidence → Requirement → Framework
```

Still roadmap: NIS2 and Albanian requirements; per-control evidence export for
auditors; and framework selection per organization, so a customer reporting only
against ISO does not have to read past three others.

---

## AI — CloudGuard Copilot

Explains findings, generates summaries, answers questions from CloudGuard's own structured data. Never becomes the security authority:

```
Azure → Rules → Findings → Risk → Evidence → AI       (correct)
Azure → AI → security decision                         (never)
```

AI is not required for the product to function. No hallucinated findings, ever — Copilot only narrates what the deterministic engine already produced.

Interface shape for later:

```python
class AIProvider:
    async def explain_finding(...): ...
    async def generate_summary(...): ...
    async def generate_report(...): ...
    async def translate(...): ...
```

---

## Advisor Mode

Lets a cybersecurity consultant create clients, connect their Azure, run assessments, generate reports, help remediate, and move into continuous monitoring. A plausible Albania go-to-market channel. `ADVISOR` role already exists in the schema (`ARCHITECTURE.md` §5) so this is cheap to build later.

```
Advisor → Create Client → Connect Azure → Assessment → Report
        → Help Client Remediate → Continuous Monitoring
```

---

## MSP Mode

Not started. Eventually: multi-client dashboard, delegated administration, white-label reports, billing, alerts.

```
MSP
├── Client A
├── Client B
├── Client C
├── Client D
└── Client E
```

---

## Multi-Cloud

`CloudResource` / `RawSnapshot` / `NormalizedState` / `SecurityRule` / `Finding` / `Risk` stay cloud-neutral so AWS and GCP connectors can be added under `connectors/` without reshaping the core (`ARCHITECTURE.md` §6).

Designed in `MULTI_CLOUD.md`: which seams already hold, the region dimension AWS
introduces and Azure does not, how trust is established per provider, and why
rules stay provider-specific over neutral resource types. The one item there
worth doing before any second provider exists — `SecurityRule.matches()`
ignoring the provider it declares — is **done**, along with the aggregate-path
hole beside it (`MULTI_CLOUD.md` §8).

Two more seams have since been built provider-neutral for the same reason, and
each was cheaper to do now than to retrofit: `CloudConnector.baseline_evidence`,
so a rule-derived collection plan does not silently stop gathering what a second
provider's product surface needs (`DECISIONS.md` §16), and `app/context/`, so a
second connector does not write its own slightly different copy of the tag
vocabulary (§17).

---

## Business Model

```
FREE SECURITY SNAPSHOT → PAID ASSESSMENT → MONTHLY CSPM → ADVISOR → MSP
```

`subscriptions` / `plans` / `usage` kept as a separate schema concern; no pricing hardcoded, no billing built now.

---

## North Star Metric

**Verified Risk Reduction** — open risk score before remediation minus open risk score after verified remediation (`RISK_ENGINE.md`). Supporting metrics: risks discovered, risks fixed, critical risks eliminated, time-to-remediation, coverage.

---

## Long-Term Direction

```
Azure CSPM → Continuous Monitoring → Compliance → Multi-cloud (AWS, GCP)
           → AI Copilot → Advisor Platform → MSP Portal → CNAPP
```

The MVP proves the Layer 1 (security engine) + core Layer 2 (remediation loop) only — see `PRODUCT_SPEC.md`. Everything in this file is Layer 3 and beyond.
