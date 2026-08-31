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

**Changes** — what moved in the environment, newest first, grouped by the day it was observed; filterable by window (24 hours / 7 / 30 / 90 days) and by kind. Rows say whether an attribute change went up or down; a move into UNKNOWN is neither. A `DISAPPEARED` row says whether the asset is missing *now*, which is what makes it a job rather than history.

**Scan** — live progress (discovery → rules → risk analysis) then a summary: resources, rules run, findings by severity. A finished run also offers **Re-evaluate**, which runs today's rules against the capture it already stored — no Azure call. A replay labels itself as one, and says which of the two things its counts mean: applied to the current picture (findings moved), or advisory (the capture has been superseded, so nothing was created, resolved or reopened).

**Connection card** — per connection: the two grants, discovered subscriptions and their scope, **Automatic scanning** (an interval, off by default), and **React to changes** (opens CloudGuard's webhook and hands over the `az eventgrid` command per subscription). The change control has to say that turning it on wires nothing up: creating that subscription is a write in the customer's tenant, and CloudGuard holds no write permission anywhere.

---

## 4. Onboarding

See `AZURE_INTEGRATION.md` §3 for the full onboarding flow and the connection-screen copy.
