# CloudGuard — Azure Connector Redesign

Design document for the simplified Azure onboarding flow. Replaces the
five-step wizard with a two-phase flow that matches the two customer actions
Microsoft's model requires. Produced during a brainstorming session before
MVP launch.

Companion to `AZURE_INTEGRATION.md` (auth model, collection pipeline) and
`DECISIONS.md` (implementation choices).

---

## 1. Problem Statement

The current onboarding flow has five steps: scope selection, admin consent,
artifact download (CLI/Bicep/Terraform), manual validation, and manual
subscription discovery. Three issues block MVP launch:

1. **Step 3 is broken.** The artifact delivery endpoints and signed-URL
   mechanism are non-functional.
2. **The Entra app registration is missing its API permission declarations.**
   Admin consent creates the enterprise app in the customer's Entra ID but
   grants no Graph permissions, causing `find_service_principal()` to fail
   persistently.
3. **Too many manual steps.** Downloading a script, running it in Cloud Shell,
   clicking validate, and clicking discover are friction the customer should
   not bear.

---

## 2. Redesigned Customer Flow

Two customer actions, everything else automatic.

### Phase 1 — Connect

The customer clicks "Add Environment" on the Connect page. A form appears:

1. **Name** — free text ("Production", "Staging", etc.)
2. **Scope** — three radio options:
   - **Entire tenant** — "Scan all subscriptions in your Azure AD tenant"
   - **Management group** — shows an ID input when selected
   - **Single subscription** — shows an ID input when selected
3. **"Connect with Microsoft"** button

On submit, the frontend calls `POST /cloud-connections`, which creates the
connection and returns the consent redirect URL. The browser redirects to
Microsoft's admin consent screen. The customer's Global Administrator signs
in and approves the Graph permissions.

Microsoft redirects to CloudGuard's consent callback. The callback:
- Verifies the HMAC-signed state token
- Writes `tenant_id` from Entra (sole authority for tenant binding)
- Acquires a Graph token and reads back CloudGuard's service principal
  object ID via `find_service_principal()`
- Sets `consent_status = GRANTED`
- Redirects the customer to the Connect page

### Phase 2 — Deploy Scanner Role

The customer's connection card now shows:
1. A success banner: "Consent granted for tenant {name}"
2. An explanation: "CloudGuard needs read-only access to your Azure
   resources. This deploys a custom role with 30 specific read
   permissions — no writes, no secrets, no data plane."
3. A **"Deploy to Azure"** button
4. A collapsible "What does this deploy?" section listing the exact
   permissions

The button links to Azure Portal's ARM template deployment page:

```
https://portal.azure.com/#create/Microsoft.Template/uri/{encoded-template-url}
```

The template URL points to CloudGuard's `/template` endpoint (signed token,
7-day TTL). Azure Portal fetches the pre-filled ARM template, the customer
reviews it, and clicks "Create."

The ARM template creates two resources in one deployment:
- **Custom role definition** — "CloudGuard Security Scanner" with the 30
  read actions
- **Role assignment** — assigns that role to CloudGuard's service principal
  at the chosen scope

After the customer returns from Azure Portal, CloudGuard auto-validates:
- Polls every 10 seconds via `GET /cloud-connections/{id}`
- Backend probes ARM access (`list_subscriptions`, `list_resources`)
- On success: sets `rbac_verified_at`, status = ACTIVE
- Then auto-discovers subscriptions, creates `CloudAccount` rows
- Polling stops when `last_discovery_at` is set

The customer returns to a ready state with subscriptions listed and
include/exclude toggles.

---

## 3. Permission Sets

### ARM — Custom Role (30 actions, v1)

> **Superseded 2026-08-28.** The role is now only the actions the collector
> actually calls -- 13 then, 14 since inventory moved to Resource Graph. One of the 17 declared ahead of use
> (`Microsoft.Security/autoProvisioningSettings/read`) is not a real provider
> operation, and ARM validates role definitions atomically, so it failed every
> deployment. See `AZURE_INTEGRATION.md` §"The role is exactly what the scanner
> reads". The list below is kept as the original design record.

Always a custom role named "CloudGuard Security Scanner." No permission
mode choice exposed to the customer.

```
# Existing (13)
Microsoft.Resources/subscriptions/read
Microsoft.Resources/subscriptions/resources/read
Microsoft.Network/networkSecurityGroups/read
Microsoft.Network/networkInterfaces/read
Microsoft.Network/publicIPAddresses/read
Microsoft.Compute/virtualMachines/read
Microsoft.Storage/storageAccounts/read
Microsoft.Sql/servers/read
Microsoft.Sql/servers/firewallRules/read
Microsoft.DBforPostgreSQL/flexibleServers/read
Microsoft.Insights/diagnosticSettings/read
Microsoft.Authorization/roleAssignments/read
Microsoft.Authorization/roleDefinitions/read

# New for MVP (17)
Microsoft.KeyVault/vaults/read
Microsoft.Web/sites/read
Microsoft.Web/sites/config/read
Microsoft.Network/virtualNetworks/read
Microsoft.Network/virtualNetworks/subnets/read
Microsoft.Compute/disks/read
Microsoft.ContainerService/managedClusters/read
Microsoft.Sql/servers/auditingSettings/read
Microsoft.Sql/servers/databases/transparentDataEncryption/read
Microsoft.Sql/servers/advancedThreatProtectionSettings/read
Microsoft.Storage/storageAccounts/blobServices/containers/read
Microsoft.Security/pricings/read
Microsoft.Security/securityContacts/read
Microsoft.Security/autoProvisioningSettings/read
Microsoft.Authorization/policyAssignments/read
Microsoft.Authorization/locks/read
Microsoft.OperationalInsights/workspaces/read
```

This covers CIS Azure Foundations Benchmark sections 1–9 core checks.
Phase 2 will add ~25 more read actions for full CIS coverage.

### Graph API — Application Permissions (10 scopes)

Declared on the CloudGuard app registration. Customers see these on the
consent screen.

```
# Existing (5)
Directory.Read.All
User.Read.All
RoleManagement.Read.Directory
UserAuthenticationMethod.Read.All
Policy.Read.All

# New for MVP (5)
Application.Read.All
Group.Read.All
IdentityRiskyUser.Read.All
AuditLog.Read.All
```

Note: `Policy.Read.All` was already in the codebase's
`REQUIRED_GRAPH_PERMISSIONS` but was never declared on the app registration.
After this redesign, the app registration must list all 10 scopes.

---

## 4. Endpoint Simplification

12 endpoints → 7 endpoints.

### Keep unchanged (3)

| Endpoint | Purpose |
|---|---|
| `GET /cloud-connections` | List connections for org |
| `DELETE /cloud-connections/{id}` | Remove connection |
| `PATCH /cloud-connections/{id}/subscriptions` | Include/exclude subscriptions |

### Keep with changes (2)

| Endpoint | Changes |
|---|---|
| `POST /cloud-connections` | Now also generates and returns the consent redirect URL. One call creates the connection and starts consent. |
| `GET /cloud-connections/{id}` | Response now includes discovered subscriptions. Backend auto-triggers validation and discovery when polled if the connection is in the right state. |

### Add (1)

| Endpoint | Purpose |
|---|---|
| `GET /cloud-connections/{id}/template?token={signed}` | Serves the ARM template JSON. Unauthenticated, signed token (7-day TTL). Azure Portal fetches this. |

### Keep with changes (1)

| Endpoint | Changes |
|---|---|
| `GET /cloud-connections/azure/consent/callback` | After recording consent, triggers auto-validation in the background. Redirects to Connect page with connection ID as query param (no separate `ConnectResult` page). |

### Remove (5)

| Endpoint | Reason |
|---|---|
| `POST /{id}/consent-url` | Merged into `POST /cloud-connections` |
| `GET /cloud-connections/options` | Scope options hardcoded in frontend for MVP |
| `GET /{id}/artifacts` | Replaced by single `/template` endpoint |
| `GET /cloud-connections/artifact` | Replaced by `/template` endpoint |
| `POST /{id}/validate` | Auto-triggered, no manual endpoint |
| `POST /{id}/discover` | Auto-triggered after validation |
| `GET /{id}/subscriptions` | Merged into `GET /cloud-connections/{id}` |

---

## 5. Data Model Changes

Pre-launch MVP — no production data exists. Single Alembic migration.

### Fields removed from `cloud_connections`

| Field | Reason |
|---|---|
| `permission_mode` | Always custom role |
| `external_id` | Deferred to simplify |
| `external_id_verified` | Deferred |
| `consented_by_user_id` | Not populated, adds complexity |
| `consented_scopes` | Only one consent shape |

### Fields kept

```
id                          UUID PK
organization_id             UUID (RLS)
provider                    VARCHAR(16)
name                        VARCHAR(200)

scope_type                  VARCHAR(24) — TENANT_ROOT / MANAGEMENT_GROUP / SUBSCRIPTION
scope_id                    VARCHAR(200)

tenant_id                   VARCHAR(64) — NULL until consent callback
service_principal_object_id VARCHAR(64) — NULL until Graph lookup
role_version                VARCHAR(16) — "v1"

consent_status              VARCHAR(16) — PENDING / GRANTED / REVOKED
consented_at                TIMESTAMP

rbac_verified_at            TIMESTAMP — NULL until ARM probe passes

status                      VARCHAR(16) — PENDING / ACTIVE / ERROR / DISABLED
status_detail               TEXT
last_discovery_at           TIMESTAMP

created_at                  TIMESTAMP
updated_at                  TIMESTAMP

UNIQUE(organization_id, provider, tenant_id, scope_id)
```

### CloudAccount model

Unchanged.

---

## 6. Auto-Validation Flow

After consent callback records tenant binding, the backend attempts
validation whenever `GET /cloud-connections/{id}` is polled:

```
if consent_status != GRANTED:
    skip

if service_principal_object_id is null:
    retry find_service_principal()
    if still null: return (keep polling)

if rbac_verified_at is null:
    probe ARM:
        list_subscriptions()
        list_resources(first_subscription)
    if probe fails:
        keep status PENDING (customer hasn't deployed yet)
        do not surface as error
    if probe passes:
        set rbac_verified_at = now()
        set status = ACTIVE

if rbac_verified_at is set and last_discovery_at is null:
    discover subscriptions
    create CloudAccount rows (in_scope = true)
    set last_discovery_at = now()

return connection with subscriptions
```

Validation failures during polling are **silent** — they mean "the customer
hasn't deployed the role yet." The UI shows "Waiting for deployment..." with
a spinner, not an error.

Polling stops when `status = ACTIVE` or `status = ERROR`.

---

## 7. ARM Template

Served by `GET /cloud-connections/{id}/template?token={signed}`.

The template creates a custom role definition and role assignment in one
deployment. Pre-filled with `principalId` and scope — the customer types
nothing.

### Scope handling

| Scope type | `targetScope` | Notes |
|---|---|---|
| Subscription | `subscription` | Standard subscription deployment |
| Management group | `managementGroup` | Management group deployment |
| Tenant root | `managementGroup` | Root management group ID = tenant ID (known from consent) |

### Template security

- Unauthenticated (Azure Portal fetches it server-side)
- Signed token with connection_id, 7-day TTL
- No customer secrets in the template — only principal object ID and scope
- Role assignment name uses `guid()` for idempotency (redeployment is a
  no-op, not an error)

---

## 8. Frontend Structure

### Removed

- `ConnectWizard.tsx` — replaced by two simpler components
- `ConnectResult.tsx` — consent callback redirects to Connect page directly

### New components

**`ConnectionForm`** — creation + consent redirect:
- Name input + scope radio group (conditional ID field for MG/subscription)
- "Connect with Microsoft" button
- On submit: `POST /cloud-connections` → redirect to consent URL

**`ConnectionCard`** — displays connection state and next action:

| Connection state | Card shows |
|---|---|
| `consent_status = PENDING` | "Consent pending" + "Resume" button |
| `consent_status = GRANTED`, `rbac_verified_at = null` | "Deploy Scanner Role" + Deploy to Azure button + "Waiting for deployment..." spinner |
| `rbac_verified_at` set, `last_discovery_at = null` | "Discovering subscriptions..." spinner |
| `status = ACTIVE` | Subscription list with include/exclude toggles |
| `status = ERROR` | Error detail + "Retry" |

### Polling logic (TanStack Query)

```typescript
refetchInterval: (q) => {
  const conn = q.state.data
  if (!conn) return false
  if (conn.status === 'ACTIVE') return false
  if (conn.status === 'ERROR') return false
  return 10_000
}
```

### Connect page layout

- Top: "Add Environment" button → opens `ConnectionForm`
- Below: list of `ConnectionCard` components
- No separate wizard page

---

## 9. One-Time Platform Setup

Before any customer can connect, the CloudGuard operator must configure the
Entra app registration. This is done once, not per customer.

### API permissions (Azure Portal → App registrations → CloudGuard → API permissions)

Add all 10 scopes listed in §3 as **Application permissions** under
Microsoft Graph. Then click "Grant admin consent for {your tenant}."

This declares the permission list that every customer's admin will see on
their consent screen. A permission not declared here is a permission no
customer will ever be asked to grant.

### Verification

After configuring, the consent flow should:
1. Show the customer all 10 permissions on Microsoft's consent screen
2. Create the enterprise app with those permissions granted
3. Allow `find_service_principal()` to succeed immediately (it queries
   by `appId`, which exists the instant consent creates the principal)

---

## 10. Testing Strategy

### Backend unit tests

| Test | Verifies |
|---|---|
| ARM template renders valid JSON for each scope type | Subscription, management group, tenant root all parse |
| Template contains exactly 30 MVP actions | No drift between `rbac.py` and template |
| Template principal_id and scope are pre-filled | No placeholder parameters |
| Role assignment name is deterministic | Idempotent redeployment |
| Consent URL includes required parameters | `scope`, `client_id`, `redirect_uri`, `state` |
| State token round-trips through URL encoding | Sign → encode → decode → verify |
| State token rejects tampering | Modified payload fails HMAC |
| State token rejects expiry | 30min TTL enforced |
| Connection state machine transitions | PENDING → GRANTED only via consent, ACTIVE only when both verified |
| `is_verified` requires both grants | Consent alone = false, RBAC alone = false |

### Backend integration tests

| Test | Verifies |
|---|---|
| `POST /cloud-connections` creates connection and returns consent URL | Full creation flow |
| Consent callback writes tenant_id, transitions to GRANTED | State verified, tenant written |
| `GET /cloud-connections/{id}` includes subscriptions | Merged response |
| RLS isolation | Org A cannot see Org B's connections |
| Duplicate connection rejected | UNIQUE constraint |

### Frontend tests

| Test | Verifies |
|---|---|
| `ConnectionForm` submits and redirects | Form validation, API call, redirect |
| `ConnectionCard` renders correct state for each status | Deploy button, spinner, subscriptions |
| Polling starts when PENDING, stops when ACTIVE | `refetchInterval` logic |

---

## 11. Decision Log

| # | Decision | Alternatives | Rationale |
|---|---|---|---|
| 1 | Two-phase flow (consent + Deploy to Azure) | Patch 5-step wizard; single-page inline | Maps to the 2 customer actions Microsoft requires. Fewer screens, clearer mental model |
| 2 | "Deploy to Azure" button only — no CLI, no Terraform | Keep all 3 artifact formats | MVP simplicity. One path to test, document, support. Others can return later |
| 3 | Custom role always — no permission mode choice | Customer chooses Reader vs custom; default to Reader | True PoLP with 30 actions. Customer shouldn't decide this. Upgradeable via `role_version` |
| 4 | Defer external_id | Keep as defense-in-depth | Adds complexity for a secondary control. Tenant binding via consent is the primary gate |
| 5 | Auto-validate + auto-discover via polling | Manual validate button; webhook from Azure | Simple and reliable. Customer returns to a done state. No webhook infra for MVP |
| 6 | Merge consent URL into POST /cloud-connections | Keep as separate endpoint | One call instead of two. One button click, connection created and redirect happens |
| 7 | Merge subscriptions into GET /cloud-connections/{id} | Separate endpoint | Frontend needs them together. Eliminates one API call per render |
| 8 | 12 → 7 endpoints | Keep all | Fewer endpoints = less surface to test, document, secure |
| 9 | 30 ARM + 10 Graph for MVP | Current 13+5; full CIS set | 13+5 too thin for credible CSPM. Full CIS too much for MVP. 30+10 covers CIS §1–9 |
| 10 | Silent validation failures during polling | Show errors on every probe | Failed probe = "customer hasn't deployed yet." Errors confuse while they're in Portal |

---

## 12. Future Expansion

These are explicitly out of scope for this redesign and documented for
later phases:

- **CLI and Terraform artifacts** — can be re-added when customers request
  them. The ARM template endpoint pattern supports multiple formats.
- **External ID defense-in-depth** — re-add to template and validation
  once the core flow is proven.
- **Phase 2 permissions** (~25 more ARM actions, ~8 Graph scopes) — add
  via `role_version` bump. Existing customers offered a redeploy.
- **Per-subscription validation** — verify readability of each discovered
  subscription, not just the first.
- **Consent revocation alerts** — detect and notify when a customer
  revokes admin consent.
- **Audit logging** — log consent events, artifact downloads, validation
  results.
- **AWS and GCP connectors** — `CloudConnector` ABC already supports this.
