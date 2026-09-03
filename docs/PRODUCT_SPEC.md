# CloudGuard — Product Specification

**Status:** MVP Prototype v0.1 — single source of truth
**Companion docs:** `ARCHITECTURE.md`, `AZURE_INTEGRATION.md`, `DATABASE.md`, `RULE_ENGINE.md`, `RISK_ENGINE.md`, `API.md`, `SECURITY.md`, `TESTING.md`, `UI.md`, `DEPLOYMENT.md`, `MULTI_CLOUD.md`, `ROADMAP.md`
**Decision log:** `DECISIONS.md` — every choice that departed from this spec, and why. Where the two disagree, that file is the later word.

Read this file first. It sets the vision and scope; the companion docs hold the implementation detail for their area.

---

## 1. Product Identity

| Field | Value |
|---|---|
| Product | CloudGuard — Cloud Security Posture Management (CSPM) |
| Positioning | Continuously discovers cloud security risks, explains what matters, prioritizes remediation, verifies fixes, and provides security/compliance evidence. |
| Initial market | Albania — a customer/positioning focus, not a language requirement |
| Initial cloud | Microsoft Azure + Microsoft Entra ID |
| MVP language | English only (UI strings wrapped in i18n now so Albanian can be added later at near-zero cost — no translation work happens in the MVP) |
| Project type | Startup project, solo developer, no fixed deadline |

### Core product loop

Every feature exists to support this loop:

```
CONNECT → DISCOVER → SNAPSHOT → ASSESS → PRIORITIZE → REMEDIATE → VERIFY → MONITOR
```

### MVP success condition

A user connects a real Azure environment, CloudGuard finds a real security problem, explains why it matters, tells them how to fix it, the user fixes it, CloudGuard rescans, and the finding is verified resolved and the score moves. That loop is the entire proof the prototype needs to deliver — nothing else is required to call the MVP a success.

---

## 2. The Problem & Product Philosophy

Organizations running cloud infrastructure without a dedicated security team usually can't answer: what do we have, what's insecure, what actually matters, what should be fixed first, and whether they're getting more or less secure over time. Traditional CSPM tooling tends to be expensive, enterprise-oriented, and overwhelming — it dumps hundreds of findings without prioritization.

**CloudGuard is not primarily a configuration scanner.** The scanner is the engine underneath the product; the actual experience takes a user from *"Something is wrong"* to *"This is why it matters"* to *"This is what I should do"* to *"CloudGuard verified it's fixed."*

**Finding ≠ Risk.** A finding is a technical observation ("RDP is open to 0.0.0.0/0"). A risk is what that finding means in business context (asset criticality, data sensitivity, exposure). This separation is preserved end-to-end — see `RISK_ENGINE.md` and `DATABASE.md`.

---

## 3. Users

The MVP targets two personas directly; the rest are future audiences the architecture should not block, but the MVP does not build dedicated experiences for them.

| Persona | MVP status |
|---|---|
| **IT Administrator** | Primary MVP persona. Needs asset visibility, clear problems in plain language (not "NSG rule ID 94 permits 0.0.0.0/0:3389" but "Internet-exposed RDP on production-vm-01"), remediation instructions, prioritization. |
| **Security Analyst** | Secondary MVP persona — drill-down capability (Risk → Finding → Asset → Evidence → Rule) via the technical dashboard, no dedicated workflows beyond that. |
| **Executive / Business Owner** | Not a dedicated MVP experience. The executive dashboard summary (score, critical/high counts, top risk) is part of the main dashboard, but no separate exec-only view. |
| **Advisor** (cybersecurity consultant) | Future. Role exists in the schema so it's cheap to add later; no Advisor workflows built now. |
| **MSP** | Future. Not built. See `ROADMAP.md`. |

---

## 4. Product Differentiation & UX Principle

CloudGuard does not compete on having the largest rule library. It competes on being simple, actionable, risk-focused, and verifiable.

| Instead of | CloudGuard says |
|---|---|
| 147 vulnerabilities | 8 security risks — here are the 3 that matter most, and what to do about them |
| NSG rule ID 94 permits unrestricted inbound TCP/3389 | Internet-exposed RDP detected on production-vm-01. Restrict TCP/3389 to your VPN or approved networks. |

If a page doesn't help answer **WHAT / WHY / HOW BAD / HOW DO I FIX IT / DID THE FIX WORK**, question whether it belongs in the MVP.

---

## 5. MVP Non-Goals

Explicitly not built now:

```
AWS, GCP, Kubernetes, CNAPP, DSPM, KSPM, CIEM, autonomous remediation,
AI agent, MSP portal, white-labeling, complex billing, enterprise SSO,
microservices
```

**Two items have left this list since it was written, and both were deliberate
scope increases rather than drift.**

*Attack paths* were a non-goal here and are now core. The reason for the change
is the one in §2: a finding is a technical observation, and this product's claim
is that it says what that observation *means*. Five findings across a jump box,
an identity and a storage account rank by severity and get worked top-down,
which is the right order for "what is wrong" and the wrong one for "what is
wrong together". The graph answers the second question from the same normalized
state the rules already read, so it cost a traversal rather than a second
collection path (`app/graph/`, `DECISIONS.md` §44, §49).

*Compliance* is partly built rather than absent — CIS Azure 2.0, ISO 27001, GDPR,
NIST CSF, NIST SP 800-53, SOC 2 and PCI DSS map to a coverage view, driven
entirely by
`rules.compliance_mappings`
data with no rule branching on a framework name. Still a non-goal is the rest of
a compliance *engine*: per-control evidence export for auditors, per-organization
framework selection, NIS2. See `ROADMAP.md`.

---

## 6. MVP Success Criteria

**Technical** — React app runs; FastAPI runs; Supabase + RLS work; Celery/Redis work; the real Azure connector works; a scan completes; findings and risk scores are generated; reports can be generated.

**Product** — a user completes signup → organization → Azure connection → scan → findings → risk → remediation → rescan → resolution, end to end.

**Security** — no cross-tenant data access; no secrets exposed to the frontend; no write access to customer Azure.

---

## 7. Phase Plan

Revised from the original build spec: MockAzureConnector dropped, real Azure integration moved from Phase 9 up to Phase 2.

| Phase | Scope |
|---|---|
| 0 | Foundation — repo, Docker, Supabase, environment variables, CI |
| 1 | Auth — Supabase Auth, organizations, membership, roles, RLS |
| 2 | Azure connector — Entra app registration, admin-consent flow, RBAC verification, collection architecture |
| 3 | Scanner — Celery/Redis, real collection → normalization → snapshot storage |
| 4 | Rule engine — first 10 rules, tested via fixtures |
| 5 | Findings — creation, evidence, severity, status |
| 6 | Risk engine — scoring, grouping, priority |
| 7 | React UI — dashboard, assets, findings, finding detail, scans |
| 8 | Remediation — assignment, status, due date, rescan, verification |
| 9 | Reports — executive + technical PDFs *(Jinja2 + WeasyPrint, generated on request, not stored — see `DECISIONS.md`)* |

**All ten phases are built.** The loop in §1 runs end to end. Work since has been
depth rather than new phases, and it is worth naming because none of it appears
above: the asset graph and attack-path correlation; compensating controls and
per-instance exploitability; the two-number risk score that separates what
CloudGuard ranks by from what it can demonstrate; asset context declarations;
scan replay against a stored snapshot; change tracking between readings; and
remediation verification as its own settled/unsettled state.

---

## 8. Open Items

- ~~Coverage/completeness indicator: visible badge, or internal only?~~
  **Resolved — visible.** It sits third on the dashboard, above the risks, because
  a score computed over half an environment is a different claim from the same
  number over all of it, and a reader who has already acted on the risks below has
  been told too late (`UI.md` §1).
- ~~Cautious-Unknown extended from criticality/data-sensitivity to
  internet_exposure~~ **Resolved — confirmed and shipped.** UNKNOWN scores just
  under HIGH on all three (`app/risk/config.py`). It has since been split in two:
  that cautious reading is what *ranks* a finding, while a second pass takes every
  UNKNOWN at the bottom of the scale and is what the org security score charges
  for (`RISK_ENGINE.md` §3).
- Azure dev tenant/subscription: still the one open item from Phase 2 — whether a
  dedicated tenant with intentionally-misconfigured resources exists, or whether
  fixtures remain the only end-to-end evidence.

---

## 9. Claude Code Initial Instruction

Give Claude Code this instruction before asking it to write any application code:

```
You are the lead engineer for CloudGuard, an Azure-first Cloud Security Posture
Management (CSPM) SaaS.

Build according to the docs/ folder in this repository, starting with
PRODUCT_SPEC.md (this file) and its companion docs. Do not attempt to build
the entire commercial product.

Immediate goal -- Prototype v0.1:
  signup -> organization -> real Azure connection (Entra admin consent + RBAC
  Reader role) -> scan -> resource discovery -> security rules -> findings ->
  risk scoring -> dashboard -> remediation -> rescan -> verified resolution.

Non-negotiable architecture requirements:
 1. Modular monolith, not microservices.
 2. Keep code modular so AWS/GCP connectors can be added later.
 3. Every tenant-owned record requires organization_id, never trusted from
    the frontend -- derived server-side from authenticated membership.
 4. Tenant isolation enforced by PostgreSQL RLS, independent of app logic.
 5. Never expose Supabase service-role/secret keys or Azure credentials to
    the frontend.
 6. Azure access is read-only. Auth is multi-tenant app + admin consent +
    RBAC Reader role -- NOT a manual service-principal credential paste.
 7. There is no MockAzureConnector. Rule unit tests use fixture data only.
    Real Azure integration is built in Phase 2, not deferred.
 8. Cloud collection is separated from rule evaluation (snapshot ->
    normalize -> evaluate).
 9. Every scan creates a snapshot.
10. Rule results are PASS / FAIL / UNKNOWN / NOT_APPLICABLE. UNKNOWN is
    never treated as PASS, and never becomes a Finding -- it's tracked for
    coverage only (scan_rule_results / scan_evaluation_gaps).
11. Findings and risks are separate entities, joined through risk_findings.
    Started 1:1; a rule may now declare that its findings are one problem, so
    forty accounts missing MFA are forty findings and one risk.
12. Risk scoring is the weighted-sum formula in RISK_ENGINE.md, deterministic
    and configuration-driven (not hardcoded). A scenario -- a route through the
    graph -- is scored separately: worst member on the path, plus a bounded
    amplifier. Never the six weights, which describe one asset's context.
13. Remediation is verified automatically: a rescan returning PASS where a
    prior scan had FAIL auto-resolves the Finding. No manual "verified" step.
14. AI is not required for the MVP to function.
15. Compliance mappings are data-driven (rules.compliance_mappings JSONB),
    never hardcoded into business logic.
16. Write tests alongside every security rule.

Development approach: build vertically, following the Phase 0-9 plan in
Section 7 above. At every phase: run tests, run lint/type checks, verify the
app starts, document decisions, and do not silently change architecture.
Before implementing anything, check whether it's actually required by
Prototype v0.1 -- if not, create the extension point but do not build it.

Start by inspecting the repository, identifying what already exists, and
producing a concise implementation plan. Then implement Phase 0.
```
