# CloudGuard — Azure Integration

Covers how CloudGuard connects to a customer's Azure environment: auth model, consent flow, onboarding, and the collection pipeline. Schema detail: `DATABASE.md` §2 (`cloud_accounts`). Generic connector interface: `ARCHITECTURE.md` §6.

---

## 1. Decision: Real Azure Only

There is **no product-facing MockAzureConnector** in the MVP. Rule unit tests use fixture data (`fixtures/secure/`, `fixtures/vulnerable/`, `fixtures/unknown/` — see `TESTING.md`), not a mock connector component. Real Azure integration is built in **Phase 2** (see `PRODUCT_SPEC.md` §7), not deferred to the end.

---

## 2. Auth Model: Multi-Tenant Entra ID App + Admin Consent

**Not** a manual service-principal credential paste. CloudGuard authenticates as **itself**, using its own app credential, scoped to the customer's `tenant_id`. There is no long-lived per-customer secret to store.

This is **two separate consent steps**, not one:

1. **Entra admin consent** — CloudGuard's multi-tenant app requests Microsoft Graph application permissions (e.g. `Directory.Read.All`, `UserAuthenticationMethod.Read.All` for MFA checks). The customer's Entra admin clicks one consent link and grants tenant-wide.
2. **Azure RBAC Reader role** — a separate grant not covered by Graph consent. The customer assigns CloudGuard's app the **Reader** role on the subscription(s)/resource group(s) to scan, via Portal, Azure CLI, or an ARM/Bicep template CloudGuard provides.

Access is **read-only** for the MVP. No write permissions are ever requested. Credentials/secrets never reach the frontend.

### Why this replaces the earlier "Tenant ID / Client ID / Credential" flow

An earlier draft of the build spec described the connection screen asking for Tenant ID, Client ID, and a Credential — that's the manual service-principal flow, and it's superseded by the model above. The `cloud_accounts` table reflects this: no `client_id`/`credential_reference` columns, just `tenant_id`, `subscription_id`, and consent-tracking fields. See `DATABASE.md` §2.

---

## 3. Onboarding Flow

```
Landing → Create account → Create organization → Choose cloud
  → Connect Azure (Entra admin consent) → Assign RBAC Reader role
  → Verify connection → Run first scan → Dashboard
```

The connection screen explains plainly: *"CloudGuard requires read-only access to assess your Azure environment,"* then walks through the two-step consent above.

---

## 4. Collection Architecture

Rules never execute directly against live Azure APIs. Every scan goes through a fixed pipeline so scans are reproducible and drift-detectable:

```
Azure APIs → Collection → Raw snapshot → Normalization → Internal cloud state → Rule engine
```

Every scan produces a `cloud_snapshots` row (see `DATABASE.md`), enabling historical comparison and future drift detection.

---

## 5. Error Handling

Cloud scanning must tolerate individual API failures. A single Azure API failure (e.g. Storage API timeout) should not fail the entire scan — it should degrade that category's rules to `UNKNOWN` (tracked via `scan_evaluation_gaps`, see `RULE_ENGINE.md` §3) while other categories continue evaluating normally. Scan status supports `PARTIAL` for exactly this case.
