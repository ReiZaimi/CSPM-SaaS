# CloudGuard — API Design

## 1. Endpoints

```
POST   /api/v1/organizations              GET  /api/v1/organizations
GET    /api/v1/organizations/{id}

POST   /api/v1/cloud-connections           GET  /api/v1/cloud-connections
GET    /api/v1/cloud-connections/options   GET  /api/v1/cloud-connections/{id}
POST   /api/v1/cloud-connections/{id}/consent-url
GET    /api/v1/cloud-connections/{id}/artifacts
POST   /api/v1/cloud-connections/{id}/validate
POST   /api/v1/cloud-connections/{id}/discover
GET    /api/v1/cloud-connections/{id}/subscriptions
PATCH  /api/v1/cloud-connections/{id}/subscriptions
DELETE /api/v1/cloud-connections/{id}

GET    /api/v1/cloud-accounts              GET  /api/v1/cloud-accounts/{id}
GET    /api/v1/cloud-accounts/{id}/context
PUT    /api/v1/cloud-accounts/{id}/context
DELETE /api/v1/cloud-accounts/{id}/context

POST   /api/v1/scans                       GET  /api/v1/scans
GET    /api/v1/scans/{id}

GET    /api/v1/assets                      GET  /api/v1/assets/{id}
GET    /api/v1/changes
GET    /api/v1/findings                    GET  /api/v1/findings/{id}
GET    /api/v1/risks                       GET  /api/v1/risks/{id}

POST   /api/v1/remediation                 PATCH /api/v1/remediation/{id}
POST   /api/v1/findings/{id}/accept-risk
POST   /api/v1/findings/{id}/rescan

GET    /api/v1/rules                       GET  /api/v1/rules/{rule_id}
GET    /api/v1/compliance                  GET  /api/v1/compliance/{framework_id}

GET    /api/v1/dashboard
GET    /api/v1/reports                     POST /api/v1/reports
```

`/cloud-accounts` is **read-only** except for `/context`: an account is a
subscription discovered beneath a connection, so there is nothing to create,
consent to, or validate there. Scoping one in or out is a PATCH on its
connection, not a delete — a deleted row would return on the next discovery run.

`/context` is the exception, and a principled one: everything else about a cloud
account records what Azure said, while a declaration records what a *person*
said. A customer marking a subscription production beats any amount of tag
inference, and there was previously nowhere to put the answer. The PUT replaces
the whole declaration rather than patching it — a field left out is one the
customer is no longer claiming, and a body claiming nothing withdraws the
declaration entirely, exactly as DELETE does. `UNKNOWN` is rejected for either
level: it is CloudGuard's own answer for "nothing said anything", so declaring
it would be asserting an absence that leaving the field out already asserts.

A declaration is applied by the next evaluation of the subscription — the next
scan, or a replay of its latest capture — and never rescores stored findings on
the spot. A risk score is what a scan concluded, and rewriting one from an API
call would leave findings carrying numbers no observation ever produced. It is
also applied as a *floor*: it can raise an asset's criticality above what the
capture supported but never lower it, so the worst a mistaken declaration can
do is over-rank something. `GET /assets/{id}` returns a `context` block giving
each value's source and confidence alongside it.

Two endpoints are unauthenticated by necessity, both protected by an HMAC-signed
token rather than a session: `/cloud-connections/azure/consent/callback`, which
Entra's redirect reaches from the customer's browser, and
`/cloud-connections/artifact`, which their Cloud Shell or Terraform run fetches.

`/changes` answers "what moved while I was away": asset appearances,
disappearances, and changes to the three attributes the risk engine multiplies a
finding by. A feed of transitions rather than a diff of two scans, so a week in
which nothing changed returns nothing rather than restating the inventory. The
window defaults to seven days and is bounded at ninety. `GET /findings/{id}`
carries the matching per-finding view as `timeline`, which is where a
regression becomes visible: a finding raised, fixed and raised again is
indistinguishable from one raised and fixed once if all you have is
`first_detected_at` and `resolved_at`.

Marking a remediation task `DONE` opens a **verification**: CloudGuard records
what it now expects to see and checks the environment on a backoff (5m, 15m, 1h,
4h) until it can answer. `GET /findings/{id}` returns that answer under
`verification`, and its `detail` is written for a person, because "still
failing", "CloudGuard could not read enough to tell" and "too soon, checking
again" are the same open finding and three different pieces of news. Cancelling
the task, or accepting the risk, withdraws the question rather than leaving it
pending.

`/compliance` reads the rule catalogue's `compliance_mappings` against the
framework catalogue in `app/compliance/catalog.py` and this organization's
latest scan. Each control resolves to FAILING, INCONCLUSIVE, PASSING,
NOT_ASSESSED or NOT_COVERED — and `coverage_ratio` counts conclusions
(pass **or** fail), never passes, because a share-of-passing figure would be a
compliance score and this API does not issue those.

---

## 2. Response Envelope

Consistent shape for every response:

```json
{ "data": {}, "error": null, "meta": {} }
```

Errors:

```json
{
  "data": null,
  "error": { "code": "CLOUD_ACCOUNT_NOT_FOUND", "message": "Cloud account not found" },
  "meta": {}
}
```

---

## 3. Authentication

```
React → Supabase Auth → JWT → FastAPI → Validate JWT → Get user ID
      → Get organization membership → Check role → Perform operation
```

The frontend may use the Supabase publishable key. **Never** expose the Supabase service-role/secret key in the browser. See `SECURITY.md`.
