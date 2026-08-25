# CloudGuard — Product UI

See `PRODUCT_SPEC.md` §4 for the underlying UX principle: don't overwhelm, prioritize, always answer WHAT/WHY/HOW BAD/HOW DO I FIX IT/DID THE FIX WORK.

---

## 1. Executive Dashboard

```
+------------------------------------------------+
|  Security Posture                               |
|        84 / 100     (+7 since last scan)       |
+------------------------------------------------+
 Critical  1     High  4     Medium  13
 Top Risk: Production database publicly accessible
 Remediation: 78% of high-risk items resolved
```

---

## 2. Technical Dashboard — Navigation

```
Dashboard  Assets  Findings  Risks  Remediation  Compliance  Reports  Scans  Settings
```

---

## 3. Key Pages

**Assets** — resource, type, environment, region, criticality, exposure, findings count, last seen; filterable by type/environment/criticality/exposure/risk.

**Findings** — finding, severity, asset, risk, status, first/last seen; filterable by severity/category/status/asset/environment.

**Finding detail** — title, severity, asset, why it matters, evidence, risk score, recommended fix, estimated effort, owner, and actions: **Assign / Mark In Progress / Accept Risk / Rescan**.

**Scan** — live progress (discovery → rules → risk analysis) then a summary: resources, rules run, findings by severity.

---

## 4. Onboarding

See `AZURE_INTEGRATION.md` §3 for the full onboarding flow and the connection-screen copy.
