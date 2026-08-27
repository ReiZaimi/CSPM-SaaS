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

POST   /api/v1/scans                       GET  /api/v1/scans
GET    /api/v1/scans/{id}

GET    /api/v1/assets                      GET  /api/v1/assets/{id}
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

`/cloud-accounts` is **read-only**: an account is a subscription discovered
beneath a connection, so there is nothing to create, consent to, or validate
there. Scoping one in or out is a PATCH on its connection, not a delete — a
deleted row would return on the next discovery run.

Two endpoints are unauthenticated by necessity, both protected by an HMAC-signed
token rather than a session: `/cloud-connections/azure/consent/callback`, which
Entra's redirect reaches from the customer's browser, and
`/cloud-connections/artifact`, which their Cloud Shell or Terraform run fetches.

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
