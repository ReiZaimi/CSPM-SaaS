# CloudGuard — Testing Strategy

---

## 1. Rule Unit Tests

Every rule, tested against **fixture data**, not a live or mock connector:

```
tests/fixtures/
├── secure/            # the check passes
├── vulnerable/        # the check fails
├── unknown/           # the evidence did not arrive
└── azure_raw/         # verbatim Azure JSON, for the normalizer and the
                       # end-to-end pipeline test
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

## 5. End-to-End — not built, and the gap is deliberate

There is **no Playwright suite and no E2E runner in the repository.** An earlier
draft of this file specified one, running the signup → connect → scan → remediate
→ rescan journey against a real test Azure tenant. It was never written, and
saying so is worth more than leaving the plan standing as though it described
something.

What covers that ground today, and where it stops:

- `tests/integration/test_scan_pipeline.py` runs the whole backend journey —
  snapshot → normalize → evaluate → score → persist → resolve — against real
  PostgreSQL, from fixture Azure JSON. Everything except the browser and Azure
  itself.
- `apps/web` has 37 vitest files covering pages and components against a mocked
  API, including the theme toggle and every severity rendering path.
- Nothing exercises the two together, so a contract drift between the API
  envelope and the client's types is caught by TypeScript and by `docs/API.md`
  being right, not by a test.

If E2E is picked up later, the fixture decision above still holds: record Azure
responses rather than calling a live tenant on every commit.

---

## 6. What actually runs

```
apps/api    pytest -q                  # unit; no database needed
            pytest -q -m integration   # needs live PostgreSQL (CI provisions it)
            ruff check . && mypy app
apps/web    npm test                   # vitest, 37 files
            npm run typecheck && npm run lint && npm run build
```

- `@pytest.mark.integration` is the only marker; `asyncio_mode = "auto"`.
- `ruff` + `mypy` run alongside tests, not as a separate optional step.
- Locally, `pytest --collect-only tests/integration` still catches import and
  syntax errors in the tests that cannot be run without PostgreSQL.
- At every development phase (`PRODUCT_SPEC.md` §7): run tests, run lint/type
  checks, verify the app starts.
