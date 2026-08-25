# CloudGuard — Deploying to the Web

Companion to [`DECISIONS.md`](DECISIONS.md). Covers taking the app from
`docker compose up` on your laptop to a real URL, using:

| Layer | Platform | Why |
|---|---|---|
| Postgres + Auth | **Supabase** | The RLS design (`app/core/db.py::rls_session`) sets `request.jwt.claims` and switches role exactly the way Supabase's own PostgREST does — this app was built to run on Supabase, not adapted to it afterward. |
| API + worker + Redis | **Railway** | Runs the existing Dockerfile as-is, GitHub-connected auto-deploy, one-click Redis. |
| Frontend | **Vercel** | Auto-detects the Vite build in `apps/web`, GitHub-connected auto-deploy. |

Your repo is already at `github.com/ReiZaimi/CSPM-SaaS` — Railway and Vercel
both connect to it directly, no separate upload step.

Total setup time: roughly 30–45 minutes, most of it waiting for dashboards to
provision. **I can't create these accounts or click through their dashboards
for you** — account creation and OAuth authorization are things only you can
do. What follows is the exact sequence; the commands you can hand me are
called out separately.

---

## 1. Supabase — database and auth

1. **Create a project** at [supabase.com](https://supabase.com) → New Project.
   Pick a strong database password and save it — you'll need it below.

2. **Create the app's database role.** Supabase already provides
   `authenticated`, `anon`, and `service_role`; this project only needs its own
   login role on top of those (`app/models/base.py`'s whole RLS strategy
   depends on the API connecting as a non-owner). Open **SQL Editor** in the
   Supabase dashboard, paste the contents of
   [`infrastructure/supabase/roles.sql`](../infrastructure/supabase/roles.sql),
   **change the password on the `CREATE ROLE` line first**, and run it.

3. **Get your connection strings.** Project Settings → Database → Connection
   string. You want the **direct** connection (port `5432`, not the `6543`
   pooler) — the pooler's transaction mode doesn't reliably support asyncpg's
   prepared-statement caching, and at this scale there's no reason to take on
   that complexity. You'll build two URLs from it:

   ```
   # Owner connection — runs migrations. Uses the postgres user Supabase gave you.
   DATABASE_OWNER_URL=postgresql+asyncpg://postgres:<db-password>@db.<project-ref>.supabase.co:5432/postgres

   # App connection — what the API uses for every request. RLS-constrained.
   DATABASE_URL=postgresql+asyncpg://cloudguard_app:<the-password-you-set-in-step-2>@db.<project-ref>.supabase.co:5432/postgres
   ```

4. **Run the schema migration against Supabase**, from your machine (this repo
   already has everything installed in the API container):

   ```bash
   docker compose run --rm -e DATABASE_OWNER_URL="postgresql+asyncpg://postgres:<db-password>@db.<project-ref>.supabase.co:5432/postgres" --no-deps api alembic upgrade head
   ```

   Tell me your project ref and I'll run this for you rather than you copying
   commands — just don't paste the actual database password into chat; I'll
   ask you to export it as an environment variable I reference instead.

5. **Get the Auth values.** Project Settings → API:
   - **Project URL** → `SUPABASE_URL` (backend) and `VITE_SUPABASE_URL` (frontend)
   - **anon / publishable key** → `SUPABASE_PUBLISHABLE_KEY` and `VITE_SUPABASE_PUBLISHABLE_KEY`
   - **service_role / secret key** → `SUPABASE_SECRET_KEY` (backend only — **never** put this in Vercel or any frontend env var; see `SECURITY.md` §3)

   Then Project Settings → API → **JWT Settings** → copy the **JWT Secret** →
   `SUPABASE_JWT_SECRET`. This is what `app/core/security.py::decode_token`
   verifies every request against.

   > **If that screen shows only JWKS / asymmetric signing keys and no plain
   > secret string** — some newer Supabase projects default to this — the
   > backend's HS256 verification won't work as-is. Tell me and I'll switch
   > `decode_token` to verify against Supabase's JWKS endpoint instead; it's a
   > contained change (`PyJWKClient` from the `pyjwt` library already installed).

6. **Enable email sign-in.** Authentication → Providers → **Email** should
   already be on by default with "Confirm email" and magic links enabled — the
   frontend uses `signInWithOtp` (`apps/web/src/lib/supabase.ts`), a
   passwordless magic-link flow, so no password provider setup is needed.

   Authentication → URL Configuration → set **Site URL** to your eventual
   Vercel URL (you can update this after step 3 once you know it) and add it
   under **Redirect URLs** too — Supabase refuses to redirect a magic-link
   click anywhere not on that list.

---

## 2. Railway — API, worker, Redis

1. **New Project** at [railway.app](https://railway.app) → **Deploy from GitHub
   repo** → select `ReiZaimi/CSPM-SaaS`. Railway will try to auto-detect a
   service; delete whatever it creates automatically — you're adding three
   services by hand so each gets the right start command.

2. **Add Redis**: in the project, **+ New** → **Database** → **Redis**.
   Railway provisions it and exposes `REDIS_URL` as a variable on that service.

3. **Add the API service**: **+ New** → **GitHub Repo** → same repo again.
   In its Settings:
   - **Root Directory**: `.` (repo root — the Dockerfile's build context needs
     to see both `apps/api` and `database`)
   - **Dockerfile Path**: `infrastructure/docker/api.Dockerfile`
   - **Start Command**:
     ```
     sh -c "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"
     ```
   - **Networking** → generate a public domain. That's your `API_URL`.

4. **Add the worker service**: **+ New** → **GitHub Repo** → same repo a third
   time. Same Root Directory and Dockerfile Path as the API. **Start Command**:
     ```
     celery -A app.workers.celery_app.celery_app worker --loglevel=INFO --concurrency=2
     ```
   No public domain needed — nothing calls the worker over HTTP.

5. **Environment variables**, set on **both** the API and worker services
   (Railway lets you reference another service's variable with
   `${{Redis.REDIS_URL}}` instead of copying the value):

   ```
   APP_ENV=production
   APP_URL=https://<your-vercel-domain>              # step 3, frontend
   API_URL=https://<your-railway-api-domain>
   LOG_LEVEL=INFO

   SUPABASE_URL=https://<project-ref>.supabase.co
   SUPABASE_PUBLISHABLE_KEY=<anon key>
   SUPABASE_SECRET_KEY=<service_role key>
   SUPABASE_JWT_SECRET=<jwt secret>
   JWT_AUDIENCE=authenticated

   DATABASE_URL=postgresql+asyncpg://cloudguard_app:<password>@db.<ref>.supabase.co:5432/postgres
   DATABASE_OWNER_URL=postgresql+asyncpg://postgres:<db-password>@db.<ref>.supabase.co:5432/postgres

   REDIS_URL=${{Redis.REDIS_URL}}

   CORS_ORIGINS=https://<your-vercel-domain>

   # Only needed once you register CloudGuard's own multi-tenant Entra app —
   # see AZURE_INTEGRATION.md §2. Leave blank until then; the app runs fine
   # without a connected Azure tenant, it just can't run a real scan.
   AZURE_CLIENT_ID=
   AZURE_CLIENT_SECRET=
   AZURE_TENANT_ID=
   AZURE_REDIRECT_URI=https://<your-railway-api-domain>/api/v1/cloud-accounts/azure/consent/callback
   AZURE_CONSENT_STATE_SECRET=<generate a random 32+ char string>

   SENTRY_DSN=
   ```

   Note what's **not** here: `SUPABASE_URL` being set is exactly what turns off
   the local dev-token sign-in route (`app/api/routes/auth.py`, gated in
   `app/api/router.py`). Once it's set, the deployed API only accepts real
   Supabase-issued tokens.

6. Push to `main` (or click **Deploy**) — Railway builds both services from the
   same Dockerfile and redeploys automatically on every push from here on.

---

## 3. Vercel — frontend

1. **Add New Project** at [vercel.com](https://vercel.com) → import
   `ReiZaimi/CSPM-SaaS`.
2. **Root Directory**: `apps/web`. Vercel auto-detects the Vite framework
   preset, build command (`npm run build`), and output directory (`dist`) —
   no `vercel.json` needed.
3. **Environment variables**:
   ```
   VITE_API_URL=https://<your-railway-api-domain>
   VITE_SUPABASE_URL=https://<project-ref>.supabase.co
   VITE_SUPABASE_PUBLISHABLE_KEY=<anon key>
   ```
   Only the anon/publishable key goes here — never the service_role key
   (`SECURITY.md` §3: only the publishable key is safe client-side).
4. Deploy. Vercel gives you a `*.vercel.app` domain — that's your `APP_URL`
   and `CORS_ORIGINS` value from step 2. Go back and set those on Railway if
   you didn't know the domain yet, and add the same domain to Supabase's
   **Redirect URLs** (step 1.6).

---

## 4. Verify the loop

```bash
curl https://<your-railway-api-domain>/health/ready
# {"data":{"status":"ready","database":"ok"},"error":null,"meta":{}}
```

Then open the Vercel URL, sign in with your real email (check your inbox for
the magic link — Supabase's default email provider is rate-limited and fine
for testing, not for real traffic), create an organization, and go to
**Connections**. Scanning a real Azure environment additionally needs the
Entra app registration from `AZURE_INTEGRATION.md` §2 — that's a separate
setup, not a hosting one, and the app works fully up through the Connections
screen without it.

---

## Redeploying after code changes

Both Railway and Vercel auto-deploy on push to `main`. Nothing else to do —
this is the entire point of connecting them to GitHub rather than uploading
builds by hand.

## Rolling back

Both platforms keep prior deploys and let you roll back from their dashboard
with one click if a push breaks something. Prefer that over reverting the
commit under pressure — revert the commit afterward, once things are stable
again, following the repo's normal git workflow.
