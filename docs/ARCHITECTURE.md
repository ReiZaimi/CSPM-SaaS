# CloudGuard — Architecture

See `PRODUCT_SPEC.md` for vision/scope. This doc covers the technical shape: stack, repo layout, request flow, multi-tenancy, and roles.

---

## 1. Tech Stack

| Layer | Choice |
|---|---|
| Frontend | React, TypeScript, Vite, Tailwind CSS, shadcn/ui, React Router, TanStack Query, Recharts |
| Backend | Python, FastAPI, Pydantic, SQLAlchemy 2, Alembic, Pytest, Ruff, MyPy |
| Database / Auth | Supabase PostgreSQL + Supabase Auth + PostgreSQL Row-Level Security (a real security boundary, not a frontend convenience) |
| Background jobs | Celery + Redis |
| Cloud | Azure Resource Manager APIs, Azure SDK for Python, Microsoft Graph API, Microsoft Entra ID |
| Infra | Docker, Docker Compose (local dev), GitHub Actions (CI) |
| Testing | Pytest, Vitest, Playwright |
| Monitoring | Sentry now; OpenTelemetry later |
| Reports | Jinja2 + WeasyPrint |
| Architecture style | **Modular monolith + worker.** Explicitly NOT microservices. |

Do not change this stack unless development proves it necessary.

---

## 2. Request / Data Flow

```
React (TS/Vite) → FastAPI (REST) → Supabase PostgreSQL (+RLS)
                              → Redis queue → Celery worker
                                              → Azure/Entra Connector → Azure Cloud
                                              → Cloud Snapshot → Normalization
                                              → Rule Engine → Risk Engine → Findings → PostgreSQL
```

Full detail on the Azure-specific parts of this pipeline (collection architecture, auth model) is in `AZURE_INTEGRATION.md`. Rule/risk engine detail is in `RULE_ENGINE.md` and `RISK_ENGINE.md`.

---

## 3. Repository Structure

Monorepo.

```
cloudguard/
|-- apps/
|   |-- web/                      # React + Vite
|   |   `-- src/, package.json, vite.config.ts
|   `-- api/
|       `-- app/
|           |-- main.py
|           |-- core/            # config, security, logging, dependencies
|           |-- api/routes/      # organizations, cloud_accounts, scans, assets,
|           |                     # findings, risks, remediation, compliance, reports
|           |-- models/, schemas/, repositories/, services/
|           |-- connectors/azure/
|           |-- rules/azure/{identity,network,storage,compute,database,logging}/
|           |-- rules/registry.py
|           |-- risk/{scorer.py, models.py}
|           `-- workers/{celery_app.py, scan_tasks.py}
|-- packages/shared/
|-- database/{migrations/, seed/}
|-- infrastructure/docker/
|-- docs/
|-- docker-compose.yml, .env.example, README.md
`-- .github/workflows/
```

---

## 4. Multi-Tenancy

Every customer is an Organization. Every tenant-owned record carries `organization_id`. The backend derives organization from the authenticated user's membership — **a client-supplied `organization_id` is never trusted.** PostgreSQL RLS independently enforces isolation as a second, database-level boundary, not just an application-layer check. Full schema and RLS policy pattern: `DATABASE.md`.

---

## 5. Roles

MVP permissions kept simple:

| Role | MVP permissions |
|---|---|
| OWNER | Everything |
| ADMIN | Everything except deleting the organization |
| SECURITY_ANALYST | Security data: read/write remediation |
| IT_ADMIN | Assets, findings, remediation |
| VIEWER | Read-only |
| ADVISOR | Read + assessment/report capabilities (schema-ready, no dedicated UI in MVP) |

MSP-specific roles are future functionality, not added now.

---

## 6. Cloud Connector Abstraction

Generic interface so AWS/GCP can be added later without reshaping the core. Azure-specific implementation detail (auth, collection pipeline) lives in `AZURE_INTEGRATION.md`.

```python
class CloudConnector(ABC):
    async def validate_connection(self): ...
    async def discover_resources(self): ...
    async def discover_identity(self): ...
    async def discover_network(self): ...
    async def discover_storage(self): ...
    async def discover_compute(self): ...
    async def discover_databases(self): ...
    async def discover_logging(self): ...

CloudConnector
  `-- AzureConnector          # MVP
      (future: AWSConnector, GCPConnector)
```

The core data model (`CloudResource`, `CloudSnapshot`, `SecurityRule`, `Finding`, `Risk`) stays cloud-neutral; cloud-specific logic lives under `connectors/`.
