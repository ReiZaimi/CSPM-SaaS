# CloudGuard — Azure Integration

Covers how CloudGuard connects to a customer's Azure environment: auth model, consent flow, onboarding, and the collection pipeline. Schema detail: `DATABASE.md` §6 (`cloud_connections`, which superseded `cloud_accounts` as the unit a scan runs against). Generic connector interface: `ARCHITECTURE.md` §6.

---

## 1. Decision: Real Azure Only

There is **no product-facing MockAzureConnector** in the MVP. Rule unit tests use fixture data (`tests/fixtures/secure/`, `vulnerable/`, `unknown/` — see `TESTING.md` §1), not a mock connector component. Real Azure integration is built in **Phase 2** (see `PRODUCT_SPEC.md` §7), not deferred to the end.

---

## 2. Auth Model: Multi-Tenant Entra ID App + Admin Consent

**Not** a manual service-principal credential paste. CloudGuard authenticates as **itself**, using its own app credential, scoped to the customer's `tenant_id`. There is no long-lived per-customer secret to store.

This is **two separate consent steps**, not one:

1. **Entra admin consent** — CloudGuard's multi-tenant app requests nine Microsoft Graph *application* permissions, listed in `REQUIRED_GRAPH_PERMISSIONS` (`app/connectors/azure/auth.py`): `Directory.Read.All`, `User.Read.All`, `RoleManagement.Read.Directory`, `UserAuthenticationMethod.Read.All`, `Policy.Read.All`, `Application.Read.All`, `Group.Read.All`, `IdentityRiskyUser.Read.All`, `AuditLog.Read.All`. Every one is a read scope. The customer's Entra admin clicks one consent link and grants tenant-wide.
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
   AZURE_CLIENT_SECRET=<the secret VALUE, not the Secret ID>
   AZURE_TENANT_ID=<your own directory id>
   AZURE_REDIRECT_URI=https://<your-railway-api-domain>/api/v1/cloud-connections/azure/consent/callback
   ```

The portal lists a secret's **Value** and its **Secret ID** side by side, and
only the Secret ID survives past the moment of creation — so the ID is what is
still on screen when people come back to copy it. Pasting it yields
`AADSTS7000215: Invalid client secret provided` from inside a token request,
*after* consent has already succeeded. CloudGuard now refuses to start a consent
flow when `AZURE_CLIENT_SECRET` is GUID-shaped, since a secret value never is.
If the Value has been lost it cannot be recovered: add a new client secret and
copy its Value.

`AZURE_REDIRECT_URI` must match the registered value exactly — Entra compares
it character for character and refuses the round-trip otherwise. The path
changed when connections replaced per-subscription accounts, so a value ending
`/cloud-accounts/azure/consent/callback` is out of date and will fail.

Confirm with `GET /api/v1/cloud-connections/azure/app-registration`. It returns
the manifest fragment this registration must declare plus the `az` command that
applies it, so the deployed registration can be **diffed** against what the code
requires rather than inspected by eye in a portal — which is how a registration
missing seven of its nine permissions still produced a consent screen that
looked entirely normal. The wizard's "cannot start a consent flow" notice
disappears once `AZURE_CLIENT_ID` and `AZURE_CLIENT_SECRET` are both set.

### Why this replaces the earlier "Tenant ID / Client ID / Credential" flow

An earlier draft of the build spec described the connection screen asking for Tenant ID, Client ID, and a Credential — that's the manual service-principal flow, and it's superseded by the model above. The schema reflects it: no `client_id`/`credential_reference` column anywhere. `cloud_connections` carries `tenant_id`, the service principal's object id, and consent-tracking fields, and nothing that is a secret. See `DATABASE.md` §6.

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

It also needs a *work or school* account, which is a separate requirement from
the role and the one people hit first. The consent link targets the
`organizations` endpoint, so Entra refuses a personal Microsoft account
(outlook.com, hotmail.com, live.com) with:

> You can't sign in here with a personal account. Use your work or school
> account instead.

That refusal is correct rather than a misconfiguration. Tenant-wide admin
consent is a directory operation, and a personal account is not a member of the
directory even when it is the account that pays for the subscription beneath it
— a subscription created with a personal account still gets its own Entra
tenant, and the personal account sits outside it.

The way through is a member account in that tenant, usually
`admin@<tenant>.onmicrosoft.com`, granted Global Administrator. Create it under
Entra ID → Users → New user, assign the role, sign in as that account, and
consent again.

### Deploying the role needs rights at the scope, not below it

The scanner role is deployed by the customer, and the commonest failure is
choosing a scope they cannot deploy at:

> You don't have authorization to perform action
> `Microsoft.Resources/deployments/validate/action`.

Azure RBAC inherits **downward only**. Owner on a subscription grants nothing at
the management group above it, and by default *nobody* — including a Global
Administrator — holds Azure RBAC at the tenant root management group. Entra
directory roles and Azure resource roles are separate systems.

Two ways through, and the second is usually right:

1. **Elevate access.** Entra ID → Properties → *Access management for Azure
   resources* → Yes. That grants User Access Administrator at root scope, from
   which the deployer can assign themselves Owner on the tenant root management
   group. Turn it back off afterwards.
2. **Pick a narrower scope.** A single subscription the customer already owns
   needs no elevation at all. Coverage is narrower — new subscriptions are not
   discovered — but it completes in one step.

The scope chooser states the requirement against each option, so the choice is
made on what the customer can finish rather than on coverage alone.

### The template endpoint is deliberately public and CORS-open

Azure Portal fetches the ARM template **from the customer's browser**, not
server-side, so `/cloud-connections/{id}/template` returns
`Access-Control-Allow-Origin: *`. The portal's origins are not enumerable
(regional and sovereign variants exist), and without the header it reports only
that the template could not be downloaded — while the endpoint answers 200 to
`curl`, so it looks healthy from every angle except the one that matters.

The wildcard gives nothing away. Access is gated by the HMAC-signed,
time-limited token in the query string rather than by origin, and the document
names a service principal object id the customer's own directory already lists
plus the read permissions they are about to review. The header is set on this
endpoint alone; the API's global CORS policy still names only this product's
frontend.

### Revocation is the customer's action, and CloudGuard verifies it

Removing a connection deletes CloudGuard's copy of the data. It cannot take
away the access that was granted, and deliberately never will be able to.

Deleting its own role assignment would need
`Microsoft.Authorization/roleAssignments/delete`; removing its service principal
would need Graph `Application.ReadWrite.All`. A CloudGuard holding the first
could strip access from the customer's own administrators. Holding the second it
could rewrite any application in the directory. Both are far more dangerous than
the read access they would revoke, and asking every customer to grant them
permanently to support a rare teardown is the wrong trade — it would also end
the claim that the product holds no write permission of any kind.

So the removal confirmation generates the `az` commands, filled in with this
connection's principal id, scope and role name, and `POST
/cloud-connections/{id}/check-revoked` confirms afterwards by trying to read.
Revocation is verified by the access failing, using the same read-only probe
that verified it working — the product does not assert an outcome it has not
checked.

### The role is exactly what the scanner reads

The custom role declares 14 read actions, and every one is exercised by a real
call in `app/connectors/azure/client.py`. Nothing is granted speculatively.

It was briefly wider — 30 actions, with 17 declared ahead of the rules that
would use them, on the reasoning that a customer should deploy the role once
rather than twice. That reasoning was sound and the outcome was not:
`Microsoft.Security/autoProvisioningSettings/read` is not a real provider
operation, and because ARM validates a role definition **atomically**, one bad
string failed the entire deployment with `InvalidActionOrNotAction`. The
customer saw "Deployment Failed", not a note about one permission.

The asymmetry that decided it: an action a collector call exercises is proven
correct the first time that call succeeds. An action nothing calls has never
been checked against Azure by anything — it is only a plausible-looking string.

Both directions are enforced by tests. Every call must have an action (a missing
one is a 403 inside one collection category, which the engine records as UNKNOWN
rather than as an error anyone reads). And every action must have a call, so
nothing appears on a customer's consent screen that cannot be justified when
they ask what it is for.

Adding a permission ahead of its rule is still legitimate — but verify the
string first:

```bash
az provider operation show --namespace Microsoft.KeyVault \
  --query "resourceTypes[].operations[].name"
```

`ROLE_VERSION` is `v2`. It exists to flag a deployed role that is
*insufficient* for a newer rule; narrowing is backward compatible and does not
warrant a bump. `v2` adds `Microsoft.ResourceGraph/resources/read`, which
inventory needs since it moved off the ARM resource listing (`DECISIONS.md`
§14). A connection still on `v1` keeps every other category and loses
inventory until the customer redeploys, which `degraded_categories` tells them
in those terms rather than as a 403.

### Permission modes

`Reader` (`*/read`) is the default: one line, never needs revisiting. The
**CloudGuard custom role** is the alternative — exactly the read operations the
collector performs and no `*/action` entries at all, enumerated in
`app/connectors/azure/rbac.py`. A test asserts every method on the
ARM-permissioned clients — `ArmClient` and `ResourceGraphClient` — has a
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

**Consent is verified, not assumed.** Admin consent resolves `/.default` to
whatever CloudGuard's app registration declares at the moment it is clicked, so
a registration missing its permissions -- or declaring them as *delegated*
rather than *application* -- produces a consent screen that succeeds and a
service token carrying nothing. The callback therefore reads the token's
`roles` claim (`graph_grant_problem`) and, when the grant is short, names the
missing permissions on the connection instead of "Admin consent granted".
Collection names them too: a Graph 403 during a scan carries the list rather
than only Microsoft's "Insufficient privileges to complete the operation",
which names neither the permission nor who can grant it. `consent_status` stays
GRANTED either way -- the subscription half of the connection is separate and
unaffected.

One Graph 403 is not about consent at all. `signInActivity` -- the reading
behind AZ-ID-003 -- additionally requires an Entra ID P1 or P2 licence, and a
fully consented tenant on the free tier is refused it with the same status code
a missing permission produces. That refusal is recognised from Microsoft's own
wording and reported as a licence, because sending a Global Administrator to a
consent screen that cannot grant it wastes the one action they were asked for.
Which permissions each collector call actually exercises is declared in
`GRAPH_PERMISSION_USE`, and a test refuses any requested permission that is
neither used nor deliberately reserved -- the Graph counterpart of the ARM
role's `ROLE_ONLY_ACTIONS`.

**Validation probes both.** `validate_connection` proves ARM access by
listing, and Resource Graph access by querying a single row. A Resource Graph
failure is recorded as a *note* rather than a problem: it costs inventory and
nothing else, so the connection is still usable and saying otherwise would send
a customer to fix an outage they do not have. It is probed all the same, because
the cause is specific -- a role deployed before §14 -- and the alternative is
meeting it as a degraded category minutes into the first scan.

**Two read surfaces, one snapshot.** Everything a rule judges is read from ARM,
whose JSON is stored verbatim. Inventory alone is read from Azure Resource
Graph through `ResourceGraphClient`, because it asks for every provider's
resources at once and because Resource Graph states `totalRecords` for the
query — so an incomplete inventory is detected by comparison rather than
inferred from a page cap (`DECISIONS.md` §14).

**One request ceiling per scan.** Task fan-out and wave concurrency multiply,
so `RequestLimiter` caps concurrent requests across every client a scan builds
— the unit Azure meters. A permit covers one HTTP attempt and is released
before any `Retry-After` sleep (`DECISIONS.md` §15).

---

## 5. Error Handling

Cloud scanning must tolerate individual API failures. A single Azure API failure (e.g. Storage API timeout) should not fail the entire scan — it should degrade that category's rules to `UNKNOWN` (tracked via `scan_evaluation_gaps`, see `RULE_ENGINE.md` §3) while other categories continue evaluating normally. Scan status supports `PARTIAL` for exactly this case.
