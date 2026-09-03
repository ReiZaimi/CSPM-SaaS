# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

CloudGuard — an Azure-first CSPM (Cloud Security Posture Management) SaaS. Modular monolith API + Celery worker backend, React SPA frontend.

## Commands

### Backend (apps/api)

```bash
pip install -e ".[dev]"          # install with dev deps
uvicorn app.main:app --reload    # dev server
ruff check .                     # lint
mypy app                         # type check
pytest -q                        # all tests
pytest -q -k "test_name"         # single test
alembic upgrade head             # run migrations
```

Requires PostgreSQL 16, Redis 7, and env vars: `DATABASE_URL`, `DATABASE_OWNER_URL`, `REDIS_URL`, `SUPABASE_JWT_SECRET`, `APP_ENV=test`.

`DATABASE_URL` must use the RLS-constrained `cloudguard_app` role, not the owner. `DATABASE_OWNER_URL` is the owner connection for migrations only.

### Frontend (apps/web)

```bash
npm ci                           # install (strict lockfile)
npm run dev                      # vite dev server (port 5173)
npm run build                    # tsc -b && vite build
npm run typecheck                # tsc --noEmit
npm run lint                     # eslint
npm test                         # vitest run
```

## Architecture

**Monorepo**: `apps/api` (Python/FastAPI), `apps/web` (React/Vite/TypeScript), `database/` (Alembic migrations + RLS policies), `infrastructure/` (Docker, Railway, Supabase, CI), `docs/` (specs).

**Request flow**: React → FastAPI (Supabase JWT auth) → Supabase PostgreSQL (with RLS) → Celery worker (Redis) → Azure APIs (MSAL).

**Scanner pipeline** (`app/services/scanner.py`): Collect raw Azure JSON → store snapshot → normalize to `CloudResource` → evaluate rules → score risk → persist findings. Raw JSON is stored verbatim for later re-evaluation against new rules.

**Scan execution** (`app/services/orchestrator.py`): a scan is durable `scan_steps` — PLAN, one COLLECT per subscription plus one for the tenant directory, then ANALYZE — claimed under a lease and routed to the `collect`/`analyze` queues. Every write a running step makes is fenced on the attempt it was claimed under.

**Multi-tenancy**: Dual-enforced. App layer derives `organization_id` from JWT. PostgreSQL RLS policies enforce row-level isolation via the `cloudguard_app` role.

**Rule engine** (`app/rules/`): `SecurityRule` ABC. Rules are deterministic — no network, no database, no LLM calls inside evaluation. Results: PASS, FAIL, UNKNOWN, NOT_APPLICABLE. UNKNOWN is never treated as PASS.

**Risk engine** (`app/risk/`): Scores findings by rule severity × asset criticality × data sensitivity × public exposure.

**Cloud connectors** (`app/connectors/`): `CloudConnector` ABC with Azure implementation. Uses REST + MSAL directly (not azure-mgmt-* SDKs) to store verbatim JSON.

**Auth**: Supabase Auth on frontend, JWT verification on backend (ES256/RS256/HS256). Azure integration uses a separate multi-tenant Entra app with admin consent.

**Findings lifecycle**: Auto-resolve when a later scan shows PASS on a prior FAIL.

## Code Style

- **Python**: Ruff (line-length 100, py312, rules E/F/W/I/N/UP/B/C4/SIM/RUF). MyPy strict with `disallow_untyped_defs`. B008 ignored (FastAPI `Depends()`). N818 ignored (domain errors named `NotFound`/`PermissionDenied`).
- **TypeScript**: Strict mode, path alias `@/` → `./src/`. React 18 SPA on Vite — not Next.js, no SSR, no server components; the build is static and Vercel serves it. React Router for routing, TanStack Query for server state.
- **UI**: Tailwind 4 is the styling layer (CSS-first: the theme is `@theme inline` in `apps/web/src/index.css`, there is no `tailwind.config.js`), with severity/status color tokens defined there — use the tokens, not raw hex. The primitives are written in v4 syntax and v3 silently dropped it (DECISIONS.md §35), so do not downgrade. Primitives are shadcn/ui components vendored as source under `src/components/ui/`, built on `@base-ui/react` and installed through the shadcn CLI (`components.json` is checked in, style `base-nova`); `src/components/ui.tsx` is gone (DECISIONS.md §24 supersedes §12). Add new primitives with the CLI, or hand-write one in the same style — they are source, not a runtime black box, and are edited and reviewed like any other file. The severity scale stays deliberately separate from shadcn's chrome tokens: `destructive` means "this button deletes something", `critical` means "an attacker can reach your data", so `SeverityBadge` and `StatusPill` (in `src/components/security/`) are not shadcn's `Badge`. A navigation styled as a button is a `Link` carrying `buttonVariants({ variant, size })`, never `Button render={<Link/>}` (DECISIONS.md §31). Charts: Recharts for anything with axes, series, or tooltips; hand-written SVG for one-off visuals like `ScoreRing`. Do not introduce a second UI or chart kit (Tremor, MUI, Chakra) — Tremor in particular ships its own Tailwind token layer that would collide with the severity tokens; a swap needs an entry in `docs/DECISIONS.md` first.
- **Tests**: pytest with `asyncio_mode = "auto"`. `@pytest.mark.integration` for tests requiring live PostgreSQL. Frontend uses vitest + testing-library.

## Deployment

- **API**: Railway (Docker, `infrastructure/docker/api.Dockerfile`). Start: `alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}`.
- **Frontend**: Vercel (auto-deploy from `apps/web`).
- **Database**: Supabase PostgreSQL. RLS role setup in `infrastructure/supabase/roles.sql`.
- CI checks that `infrastructure/supabase/roles.sql` retains the placeholder password — never commit a real credential there.

## Key Design Decisions (docs/DECISIONS.md)

- REST over Azure SDKs: raw JSON stored for re-evaluation
- Relationship edges indexed both ways at RuleContext construction
- No mock connector in production code; fixture-based unit tests instead
- API response envelope: `{ "data": ..., "error": null, "meta": {} }`
- A step is fenced to the worker that claimed it; one advisory lock per scan target (§65)
- The frontend catches its own failures: error boundaries, request timeouts, 401 signs out (§66)
