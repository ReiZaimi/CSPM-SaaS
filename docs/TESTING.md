# CloudGuard — Testing Strategy

---

## 1. Rule Unit Tests

Every rule, tested against **fixture data**, not a live or mock connector:

```
fixtures/
├── secure/
├── vulnerable/
└── unknown/
```

```
test_public_rdp_detected()       # RDP open      -> FAIL
test_public_rdp_not_detected()   # RDP restricted -> PASS
test_public_rdp_unknown()        # not an NSG     -> NOT_APPLICABLE
```

Expected rule results must be fully deterministic given fixture input.

---

## 2. Risk Tests

Test the risk formula (`RISK_ENGINE.md`) across the range, e.g.:

- low asset criticality + low severity → low risk_score
- critical asset + Internet exposure + critical finding severity → risk_score in the CRITICAL band

---

## 3. RLS Tests

```
User A → Organization A
```

must never be able to access:

```
Organization B
```

This is a required, automated test category — not manual QA. See `SECURITY.md` §2.

---

## 4. API Tests

Cover: authentication, authorization, tenant isolation, scan creation, finding retrieval, remediation actions.

---

## 5. End-to-End (Playwright)

```
Signup → Login → Organization → Connect Azure → Scan
  → Dashboard → Finding → Remediation → Rescan → Resolved
```

Runs against a **real (test) Azure tenant**, consistent with dropping MockAzureConnector (`AZURE_INTEGRATION.md` §1). CI should use recorded/fixture Azure API responses rather than live calls on every commit, to keep the suite fast and non-flaky — this is internal test plumbing, distinct from the product-facing mock connector that was ruled out.

---

## 6. General

- `pytest` (backend), `vitest` (frontend unit), `playwright` (E2E)
- `ruff` + `mypy` run alongside tests, not as a separate optional step
- At every development phase (`PRODUCT_SPEC.md` §7): run tests, run lint/type checks, verify the app starts
