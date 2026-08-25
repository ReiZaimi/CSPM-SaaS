# CloudGuard — API Design

## 1. Endpoints

```
POST   /api/v1/organizations              GET  /api/v1/organizations
GET    /api/v1/organizations/{id}

POST   /api/v1/cloud-accounts              GET  /api/v1/cloud-accounts
POST   /api/v1/cloud-accounts/{id}/validate
DELETE /api/v1/cloud-accounts/{id}

POST   /api/v1/scans                       GET  /api/v1/scans
GET    /api/v1/scans/{id}

GET    /api/v1/assets                      GET  /api/v1/assets/{id}
GET    /api/v1/findings                    GET  /api/v1/findings/{id}
GET    /api/v1/risks                       GET  /api/v1/risks/{id}

POST   /api/v1/remediation                 PATCH /api/v1/remediation/{id}
POST   /api/v1/findings/{id}/accept-risk
POST   /api/v1/findings/{id}/rescan

GET    /api/v1/dashboard
GET    /api/v1/reports                     POST /api/v1/reports
```

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
