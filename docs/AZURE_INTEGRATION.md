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

### 2.1 Registering CloudGuard's own Entra app

This is CloudGuard's identity, registered **once by whoever operates
CloudGuard** — not per customer. Until it exists, the connection wizard reports
that this deployment cannot start a consent flow.

Do not reuse the app registration that backs *Sign in with Microsoft*
(`DEPLOYMENT.md` step 7). That one authenticates CloudGuard's own users; this
one reads customers' environments. Separate trust boundaries, separate apps.

1. **Azure Portal → Microsoft Entra ID → App registrations → New registration.**
   * Name: `CloudGuard`
   * Supported account types: **Accounts in any organizational directory
     (multitenant)**. This is the setting that makes one app registration
     serve every customer without a per-customer secret.
   * Redirect URI: type **Web**, value
     `https://<your-railway-api-domain>/api/v1/cloud-connections/azure/consent/callback`

2. **API permissions → Add a permission → Microsoft Graph → Application
   permissions.** Add the set in `app/connectors/azure/auth.py`
   (`REQUIRED_GRAPH_PERMISSIONS`). Do **not** grant admin consent in your own
   tenant — each customer's administrator grants it in theirs.

   The consent request asks for `https://graph.microsoft.com/.default`, which
   means *whatever application permissions this registration holds*. So this
   step is not merely documentation: a permission missing here is a permission
   no customer will ever be asked to grant, and the rules that need it degrade
   to UNKNOWN with nothing on the consent screen to explain why.

3. **Certificates & secrets → New client secret.** Copy the *value*
   immediately; the portal will not show it again.

4. **Overview** gives the Application (client) ID and Directory (tenant) ID.

5. Set these on the Railway **API and worker** services, then redeploy:

   ```
   AZURE_CLIENT_ID=<application (client) id>
   AZURE_CLIENT_SECRET=<the secret value, not its id>
   AZURE_TENANT_ID=<your own directory id>
   AZURE_REDIRECT_URI=https://<your-railway-api-domain>/api/v1/cloud-connections/azure/consent/callback
   ```

`AZURE_REDIRECT_URI` must match the registered value exactly — Entra compares
it character for character and refuses the round-trip otherwise. The path
changed when connections replaced per-subscription accounts, so a value ending
`/cloud-accounts/azure/consent/callback` is out of date and will fail.

Confirm with `GET /api/v1/cloud-connections/options`: `azure_configured` turns
`true`, and the wizard's notice disappears.

### Why this replaces the earlier "Tenant ID / Client ID / Credential" flow

An earlier draft of the build spec described the connection screen asking for Tenant ID, Client ID, and a Credential — that's the manual service-principal flow, and it's superseded by the model above. The `cloud_accounts` table reflects this: no `client_id`/`credential_reference` columns, just `tenant_id`, `subscription_id`, and consent-tracking fields. See `DATABASE.md` §2.

---

## 3. Onboarding Flow

A customer connects a **tenant or management group**, not a subscription.
Subscriptions beneath it are discovered. The five steps each derive their
completion from server state, because consent happens in another browser tab and
the access grant frequently happens on another person's machine.

```
Create organization
  → 1. Choose scope + permission mode        (no GUIDs are typed)
  → 2. Entra admin consent                   (Entra reports the tenant id)
  → 3. Run the generated access artifact     (CLI / Bicep / Terraform)
  → 4. Verify — both grants proven by use
  → 5. Confirm discovered subscriptions      → first scan → Dashboard
```

**Nothing is asked for that can be derived.** The consent link targets
`organizations` rather than a named tenant, so the administrator simply signs in
and Entra's callback reports which directory consented. That is the only place
`cloud_connections.tenant_id` is ever written, and it is what binds a connection
to a directory — see `DECISIONS.md`.

**Steps 2 and 3 poll.** Both open something in another tab, so the wizard
advances by itself instead of asking anyone to come back and press a button.
Polling continues while the tab is backgrounded, which is precisely when it
matters.

### The artifact

After consent, CloudGuard reads its own service principal's object id back from
Graph, which is what a role assignment must point at. The artifact is then
generated per connection with nothing left to fill in, in three formats:
Cloud Shell script, Bicep, and Terraform.

A **shell script, not just a template**, because ARM cannot reach Entra — it
deploys resources, and a service principal is not one. The template covers the
RBAC half for customers whose change process requires one.

Note the two grants need *different* permissions from different people: admin
consent needs a **Global Administrator**, and the role assignment needs **Owner
or User Access Administrator** on the chosen scope. The wizard says so before it
sends anyone anywhere.

### Permission modes

`Reader` (`*/read`) is the default: one line, never needs revisiting. The
**CloudGuard custom role** is the alternative — exactly the read operations the
collector performs and no `*/action` entries at all, enumerated in
`app/connectors/azure/rbac.py`. A test asserts every `ArmClient` method has a
matching action and vice versa, so the role cannot silently drift from the code.
The trade is maintenance: a rule reading a new resource type needs a new action
and a customer redeploy, which is what `role_version` tracks.

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
