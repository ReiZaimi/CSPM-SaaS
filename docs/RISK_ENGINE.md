# CloudGuard — Risk Engine

Finding ≠ Risk (see `PRODUCT_SPEC.md` §2). This doc covers how a finding becomes a scored, prioritized risk, and how the org-level Security Score is derived.

---

## 1. Risk Score (per finding)

Weighted sum — chosen over an earlier multiplicative draft because it matches the schema in `DATABASE.md` and reads as a clear breakdown in the UI:

```
risk_score = severity × 0.25
           + asset_criticality × 0.20
           + data_sensitivity  × 0.15
           + internet_exposure × 0.20
           + exploitability    × 0.10
           + business_impact   × 0.10

(each component normalized 0-5, weighted sum × 20 → final 0-100 score)
```

### Component scale

Applies to `severity`, `asset_criticality`, `data_sensitivity`, and `internet_exposure`:

| Level | Score |
|---|---|
| LOW | 1 |
| MEDIUM | 2.5 |
| HIGH | 4 |
| CRITICAL | 5 |
| **UNKNOWN** | **3.5** — cautious: just under High, so missing context never reads as low risk. Applied consistently across all four components (extended from criticality/sensitivity to exposure for consistency — see open item in `PRODUCT_SPEC.md` §8). |

- **`exploitability`** — static per-rule tag, 0–5 (see the rule table in `RULE_ENGINE.md` §5).
- **`business_impact`** — not manually set; **computed** as the average of `asset_criticality` and `data_sensitivity` scores.

All weights and the level-to-score mapping live in a configurable risk-engine config object, not hardcoded into rule logic — tune after testing against real environments.

### Risk level bands (0–100 risk_score)

| Level | Range |
|---|---|
| LOW | 0–24 |
| MEDIUM | 25–49 |
| HIGH | 50–74 |
| CRITICAL | 75–100 |

---

## 2. Findings → Risks

**1:1 by default.** Each finding generates its own risk, joined through the `risk_findings` junction table (see `DATABASE.md`).

**Unless the rule groups them.** A rule that fails once per member of a set may declare a `RiskGrouping` (`app/risk/grouping.py`), and its findings become one risk with many members. The findings stay per resource — each is separately fixed and separately verified — while the risk layer stops repeating one sentence and stops deducting once per repetition. `AZ-ID-001` is the first: forty privileged accounts without MFA is one unwritten Conditional Access policy, and as forty Critical risks it takes the Security Score in §3 to zero on the strength of it.

Grouping is declared, not inferred from the count. Two storage accounts left public are two mistakes; two administrators without MFA are one policy nobody wrote.

A group is scored as its **worst member**, never their sum, and closes only when nothing in it is still open. The band queries in §3 count distinct risks accordingly. Identity across scans is `scenario_key = group:<rule_id>` — the same column scenario risks use, so grouping was a service-layer change and not a migration, exactly as designed.

---

## 3. Security Score (org level)

Strict by design — a few Critical findings should visibly tank the score:

```
security_score = max(0, 100 - Σ deductions)

  Critical open finding:  -20
  High open finding:      - 8
  Medium open finding:    - 3
  Low open finding:       - 1
```

Deductions key off each **risk's** band (asset-context-aware, §1 above), not the rule's raw severity: the same misconfiguration scores differently on a dev VM vs. a production database. One deduction per risk, so a grouped risk (§2) is charged once however many findings it holds. Two open Criticals alone drop the score from 100 to 60.

**Coverage/completeness** (how many rules/assets were actually evaluated vs. `UNKNOWN`, see `RULE_ENGINE.md` §2) is a **separate indicator**, not folded into the score — keeps "why is my score X?" answerable without also explaining coverage math. Whether this indicator gets a visible badge in the MVP dashboard is still open — see `PRODUCT_SPEC.md` §8.

---

## 4. Priority

Beyond raw risk score, prioritization should weigh remediation effort — high impact + high exposure + low effort surfaces first:

| Risk | Impact | Effort | Priority |
|---|---|---|---|
| Public RDP | High | 15 min | Critical |
| MFA gap | Critical | 30 min | Critical |
| Logging | Medium | 120 min | Medium |
| Architecture redesign | High | 2 days | Medium |
