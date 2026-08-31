# CloudGuard — Product Specification

**Status:** MVP Prototype v0.1 — single source of truth
**Companion docs:** `ARCHITECTURE.md`, `AZURE_INTEGRATION.md`, `DATABASE.md`, `RULE_ENGINE.md`, `RISK_ENGINE.md`, `API.md`, `SECURITY.md`, `TESTING.md`, `UI.md`, `ROADMAP.md`

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
AWS, GCP, Kubernetes, CNAPP, DSPM, KSPM, CIEM, attack paths, autonomous remediation,
full compliance engine, AI agent, MSP portal, white-labeling, complex billing,
enterprise SSO, microservices
```

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
| 9 | Reports — executive + technical PDFs *(built: Jinja2 + WeasyPrint, generated on request, not stored — see `DECISIONS.md`)* |

> **Open item:** whether a dev Azure subscription/tenant is already available for Phase 2 (to register CloudGuard's app and create intentionally-misconfigured test resources) — not yet confirmed.

---

## 8. Open Items

- Coverage/completeness indicator: build a visible badge in the MVP dashboard, or track internally (`scan_rule_results` / `scan_evaluation_gaps`) and surface the UI later?
- Azure dev tenant/subscription: available already, or needs setting up before Phase 2?
- Cautious-Unknown treatment was extended from criticality/data-sensitivity to internet_exposure for consistency — proposed, not explicitly confirmed.

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
11. Findings and risks are separate entities; 1:1 for MVP via risk_findings.
12. Risk scoring is the weighted-sum formula in RISK_ENGINE.md, deterministic
    and configuration-driven (not hardcoded).
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
