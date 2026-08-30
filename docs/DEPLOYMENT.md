# CloudGuard — Deploying to the Web

Companion to [`DECISIONS.md`](DECISIONS.md). CloudGuard is cloud-only — there
is no local development mode and no localhost defaults, and the API refuses to
start without a complete deployment environment. Everything runs on:

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
do. Everything below happens in a browser — nothing needs Docker, Python or
Node installed on your machine.

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
   string, and choose **Session pooler**.

   Not the direct connection: on current Supabase projects `db.<ref>.supabase.co`
   resolves to an **IPv6-only** address, and Railway cannot route IPv6. It fails
   with `Network is unreachable` against an address like `2a05:d014:...`. The
   Session pooler is IPv4 and behaves like a normal PostgreSQL connection.

   Not the **Transaction** pooler on port `6543` either — that one does not
   support prepared statements, which asyncpg relies on. You want **port 5432**.

   The pooler puts the project ref in the username, as `<user>.<project-ref>`:

   ```
   # Owner connection — runs migrations, as the table owner.
   DATABASE_OWNER_URL=postgresql+asyncpg://postgres.<project-ref>:<db-password>@aws-0-<region>.pooler.supabase.com:5432/postgres

   # App connection — every request. RLS-constrained, owns nothing.
   DATABASE_URL=postgresql+asyncpg://cloudguard_app.<project-ref>:<the-password-you-set-in-step-2>@aws-0-<region>.pooler.supabase.com:5432/postgres
   ```

   Copy the host and region from the Session pooler string Supabase shows you,
   and remember to change `postgresql://` to `postgresql+asyncpg://`.

4. **The schema migration needs no action here.** The Railway API service's
   start command (step 2.3) runs `alembic upgrade head` on every deploy, so
   the tables and RLS policies are created the first time that service boots.
   Nothing to run from your machine.

   > At one API instance this is the simplest correct option. If you ever scale
   > the API past one replica, move the migration to a Railway *release*
   > command instead, so two booting instances can't race each other on DDL.

5. **Get the Auth values.** Project Settings → API:
   - **Project URL** → `SUPABASE_URL` (backend) and `VITE_SUPABASE_URL` (frontend)
   - **anon / publishable key** → `SUPABASE_PUBLISHABLE_KEY` and `VITE_SUPABASE_PUBLISHABLE_KEY`
   - **service_role / secret key** → `SUPABASE_SECRET_KEY` (backend only — **never** put this in Vercel or any frontend env var; see `SECURITY.md` §3)

   Then Project Settings → API → **JWT Settings** → copy the **JWT Secret** →
   `SUPABASE_JWT_SECRET`. This is what `app/core/security.py::decode_token`
   verifies every request against.

   > **`SUPABASE_JWT_SECRET` is optional.** Current Supabase projects sign
   > tokens with asymmetric keys (ES256) and have no shared secret at all —
   > the backend fetches the public keys from the project's JWKS endpoint,
   > derived from `SUPABASE_URL`. Set this variable only if your project shows
   > a legacy JWT secret; both signing schemes are supported.

6. **Enable email sign-in.** Authentication → Providers → **Email** is on by
   default. Leave both **Confirm email** and the email provider's password
   support enabled: the sign-in screen offers magic links *and* email +
   password, and sign-up shows a "check your email" screen when confirmation
   is on (`apps/web/src/lib/supabase.ts`).

   Authentication → URL Configuration → set **Site URL** to your eventual
   Vercel URL (you can update this after step 3 once you know it). Under
   **Redirect URLs** add both that URL and `<your-vercel-url>/reset-password` —
   Supabase refuses to redirect a link click anywhere not on that list, and the
   password-reset email lands on that second path.

7. **Enable Microsoft (Entra ID) sign-in.** Authentication → Providers →
   **Azure**. This is a *second, separate* Entra app registration from the one
   that scans subscriptions — do not reuse the scanning app's credentials here.

   In the Azure portal, register an app with the redirect URI Supabase shows on
   that provider page (`https://<project-ref>.supabase.co/auth/v1/callback`,
   type *Web*), add a client secret, and grant the delegated Microsoft Graph
   permissions `openid`, `profile`, `email`, `User.Read`. Paste the
   Application (client) ID and secret into Supabase.

   Leave **Azure Tenant URL** blank to accept any Microsoft account, or set it
   to `https://login.microsoftonline.com/<tenant-id>` to restrict sign-in to a
   single directory.

---

## 2. Railway — API, worker, Redis

1. **New Project** at [railway.app](https://railway.app) → **Deploy from GitHub
   repo** → select `ReiZaimi/CSPM-SaaS`. Railway will try to auto-detect a
   service; delete whatever it creates automatically — you're adding three
   services by hand so each gets the right start command.

2. **Add Redis**: in the project, **+ New** → **Database** → **Redis**.
   Railway provisions it and exposes `REDIS_URL` as a variable on that service.

3. **Add the API service**: **+ New** → **GitHub Repo** → same repo again.

   **Leave Root Directory empty (the repo root).** This is the setting that
   most often breaks the build: the Dockerfile copies `apps/api` *and*
   `database`, so both must be inside the build context. Setting Root Directory
   to `apps/api` makes `COPY apps/api/...` fail, because relative to that
   context there is no `apps/api` folder.

   Nothing else needs configuring. `railway.json` at the repo root is read
   automatically and declares the Dockerfile path, the start command (including
   the migration) and the health check. Then **Networking** → generate a public
   domain; that's your `API_URL`.

   <details><summary>Setting it by hand instead</summary>

   - **Dockerfile Path**: `infrastructure/docker/api.Dockerfile`
   - **Start Command**:
     ```
     sh -c "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"
     ```
   - **Health Check Path**: `/health`
   </details>

4. **Add the worker service**: **+ New** → **GitHub Repo** → same repo a third
   time, Root Directory again empty.

   The worker runs Celery rather than the web server, so it needs a different
   start command than the root `railway.json` provides.

   **Preferred:** set its **Config-as-code** field to
   `infrastructure/railway/worker.json`. That file already carries the right
   start command, and nothing has to be retyped.

   Otherwise set **Custom Start Command** — the *Start* one, in the Deploy
   section:

   ```
   celery -A app.workers.celery_app.celery_app worker --beat --schedule=/tmp/celerybeat-schedule --loglevel=INFO --concurrency=2
   ```

   > **Keep `--beat`.** It runs Celery's scheduler inside the worker, and one
   > scheduled task depends on it: the reaper that closes scans whose worker
   > died mid-run. Without it those scans stay non-terminal for ever, and a
   > connection with one of them answers "a scan is already running" to every
   > future scan — the exact symptom that looks like a broken product and is
   > actually a missing flag. `--schedule` points its state file at a path that
   > is writable in the container.
   >
   > Safe with more than one worker replica: the reaper is idempotent, so two
   > schedulers firing it merely means one of them finds nothing left to close.

   > **Not Custom Build Command.** They sit near each other in Railway's
   > settings and the mistake is silent: a build command runs at build time,
   > the container then starts with the Dockerfile's own `CMD` — uvicorn — and
   > the service reports **Online** while running a second copy of the API.
   > Scans queue and nothing ever collects them. See the troubleshooting entry
   > below.

   No public domain and no health check — nothing calls the worker over HTTP.

5. **Environment variables**, set on **both** the API and worker services
   (Railway lets you reference another service's variable with
   `${{Redis.REDIS_URL}}` instead of copying the value):

   ```
   APP_ENV=staging
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

   # Required. Signs the Entra consent round-trip, so it must be secret even
   # before any Azure tenant is connected — the API refuses to start in
   # production without it. Generate with: openssl rand -hex 32
   AZURE_CONSENT_STATE_SECRET=<random 32+ char string>

   # Optional until you register CloudGuard's own multi-tenant Entra app —
   # see AZURE_INTEGRATION.md §2.1 for the registration steps. Leave blank
   # until then; the app runs fine without a connected Azure tenant, it just
   # cannot start a consent flow, and the connection wizard says so.
   #
   # AZURE_REDIRECT_URI must match the value registered on the Entra app
   # character for character, including the path below.
   AZURE_CLIENT_ID=
   AZURE_CLIENT_SECRET=
   AZURE_TENANT_ID=
   AZURE_REDIRECT_URI=https://<your-railway-api-domain>/api/v1/cloud-connections/azure/consent/callback

   SENTRY_DSN=
   ```

   Start on `APP_ENV=staging` while you are still filling in URLs: every value
   above is required, and on `staging` or `production` the API refuses to boot
   until they are all present and none of them points at localhost. Switch to
   `production` in step 4, once the Vercel domain is filled in.

   There is no sign-in path other than Supabase — the API has no token-minting
   code of its own, only verification.

6. Push to `main` (or click **Deploy**) — Railway builds both services from the
   same Dockerfile and redeploys automatically on every push from here on.

---

## 3. Vercel — frontend

1. **Add New Project** at [vercel.com](https://vercel.com) → import
   `ReiZaimi/CSPM-SaaS`.
2. **Root Directory**: `apps/web` is the cleanest choice, but the repo now
   carries a `vercel.json` at both the root and in `apps/web`, so the build
   works either way — Vercel reads whichever matches the Root Directory you
   set. Leave the build/output fields blank; the config file supplies them.

   Both configs include the SPA rewrite that sends unmatched paths to
   `index.html`. Without it the app loads at `/` but any deep link —
   `/findings/<id>`, or just refreshing the page — returns a 404, because
   those routes only exist client-side in React Router.

3. **Environment variables**:
   ```
   VITE_API_URL=https://<your-railway-api-domain>
   VITE_SUPABASE_URL=https://<project-ref>.supabase.co
   VITE_SUPABASE_PUBLISHABLE_KEY=<anon key>
   ```
   Only the anon/publishable key goes here — never the service_role key
   (`SECURITY.md` §3: only the publishable key is safe client-side).
   These are read at **build time**, not run time. Adding or changing one has
   no effect until you redeploy — Vite inlines them into the bundle. If any are
   missing, the deployed app renders a page naming the missing variable rather
   than failing silently — there is no localhost fallback to mask it.

4. Deploy. Vercel gives you a `*.vercel.app` domain — that's your `APP_URL`
   and `CORS_ORIGINS` value from step 2. Go back and set those on Railway if
   you didn't know the domain yet, and add the same domain to Supabase's
   **Redirect URLs** (step 1.6).

---

## 4. Troubleshooting

### "1/1 replicas never became healthy" — healthcheck failed

The build succeeded and the container started, but nothing answered on
`/health`. Two different causes, and the **Deploy Logs** tab tells you which
(the Build Logs tab only covers the image build):

* **The app never started.** The start command runs `alembic upgrade head`
  before uvicorn, so a migration failure means the web server is never reached.
  Look for an Alembic traceback — usually a database URL that is wrong or
  unreachable. A configuration problem shows up the same way; see below.
* **It was still starting.** A first deploy creates every table, RLS policy,
  function and grant before serving anything. `railway.json` allows 300s for
  this; if you overrode the healthcheck timeout in the dashboard to something
  short, raise it.

Migrations run in the start command, which means a failed migration crash-loops
the service. If you would rather they run once per deploy instead, move
`alembic upgrade head` to Railway's **Pre-Deploy Command** and reduce the start
command to just the uvicorn line.

### The API starts, then immediately crashes

The API validates its whole environment before it will serve anything
(`app/core/config.py::config_problems`) and **crashes with an explicit list** of
what is missing. Every check covers something that would otherwise boot cleanly
and look healthy while being broken or exploitable — a missing JWT secret means
no request can be authenticated at all, and a localhost URL means a real
customer gets pointed at their own machine.

Open the Railway deploy logs: every problem is listed at once, in plain
language, with where to get the correct value. `APP_ENV=test` is the only value
that skips these checks, and it exists for CI.

### `ModuleNotFoundError: No module named 'app'`

The image sets `PYTHONPATH=/srv/apps/api`, so this should not happen. If it
does, the service is running a start command from the wrong working directory —
check that **Root Directory** is `.` and not `apps/api`.

### "Failed to build an image" within a few seconds

A build that dies in under ~10 seconds never got as far as installing anything,
so the cause is almost always the build context rather than the code. In order
of likelihood:

1. **Root Directory is not the repo root.** Clear the field. The Dockerfile
   does `COPY apps/api ...` and `COPY database ...`, both relative to the repo
   root; any other root directory makes those paths nonexistent and COPY fails
   immediately.
2. **Railway fell back to Nixpacks.** If it cannot find a Dockerfile it tries
   to auto-detect the project, and the repo root has no `package.json` or
   `requirements.txt` for it to recognise, so it gives up fast. The root
   `railway.json` prevents this — confirm the build logs say it is using the
   Dockerfile builder.
3. **A stale service config** from an earlier attempt overriding the file. A
   value typed into the dashboard wins over `railway.json`; clear the Dockerfile
   Path and Build Command fields so the file applies.

The **Build Logs** tab shows which of these it was — the Details tab only says
that the step failed.

### `Network is unreachable`, with an address like `2a05:d014:...`

That is an IPv6 address. Supabase's **direct** connection hostname
(`db.<ref>.supabase.co`) is IPv6-only on current projects, and Railway cannot
route IPv6, so the connection never leaves the container.

Switch both `DATABASE_URL` and `DATABASE_OWNER_URL` to the **Session pooler**
(step 1.3): host `aws-0-<region>.pooler.supabase.com`, port **5432**, username
`<user>.<project-ref>`. Port 6543 is the Transaction pooler and will break
asyncpg's prepared statements — do not use it.

### The migration fails on deploy

`alembic upgrade head` runs as part of the API start command using
`DATABASE_OWNER_URL`. If it fails, that variable is wrong or the role lacks
permission. It must be the **postgres** user (the table owner), not
`cloudguard_app` — the app role deliberately owns nothing and cannot create
tables.

### The worker service is Online but scans stay Queued

`Online` means the container is running, not that it is running *Celery*. The
usual cause is the Celery command typed into **Custom Build Command** instead
of **Custom Start Command**: the build command runs during the build, the
container then starts with the Dockerfile's `CMD`, and the service quietly
becomes a second copy of the API. It passes every health check because it *is*
a healthy API.

Check, in order:

1. The worker's **Deploy → Custom Start Command** contains `celery`, or its
   **Config-as-code** field points at `infrastructure/railway/worker.json`.
   Clear the build command if the celery line ended up there.
2. Its logs show Celery's startup banner and then `scan.task_received` when a
   scan is queued. An API access log instead means it is running uvicorn.
3. It has the same `REDIS_URL` as the API — they must share one broker.

`GET /api/v1/scans/worker-status` answers this directly: it pings the broker
and reports how many workers respond.

### Vercel: "No Output Directory named 'dist' found"

Vercel built from the wrong directory. Either set Root Directory to `apps/web`,
or leave it at the repo root — both are covered by a `vercel.json` now, but
only if the build/output fields in the dashboard are left **blank** so the
config file is what applies. A value typed into the dashboard overrides the
file.

### The frontend loads but every request fails

Two likely causes, and the app tells you which:

- If it renders a **"deployed but not configured"** page, a `VITE_*` variable
  is missing. Set it and redeploy — Vite inlines these at build time, so a
  variable added without a rebuild changes nothing.
- If it renders normally but requests fail with a CORS error, `CORS_ORIGINS`
  on Railway does not match the Vercel domain exactly. It needs the scheme and
  no trailing slash: `https://your-app.vercel.app`.

### The magic link lands on Supabase's own domain, or a dead page

If the URL after clicking looks like
`https://<ref>.supabase.co/yourapp.vercel.app#access_token=...`, then **Site URL
is missing its `https://` scheme**. Supabase treats a scheme-less value as a
relative path and appends it to its own origin.

Note the `#access_token=` in that URL: authentication *succeeded*: the token was
issued and only the destination was wrong. Fix Site URL to the full
`https://your-domain` and request a fresh link.

If the destination loads but 404s, Site URL points at a domain with no live
deployment. Both fields must be the real production domain — see step 3 of the
Vercel section.

### Deep links 404 but the home page works

The SPA rewrite is not being applied — see the Vercel step above. `/` is a real
file (`index.html`); `/findings/<id>` only exists inside React Router.

---

## 5. Verify the loop

```bash
curl https://<your-railway-api-domain>/health/ready
# {"data":{"status":"ready","database":"ok"},"error":null,"meta":{}}
```

Then open the Vercel URL, sign in with your real email (check your inbox for
the magic link — Supabase's default email provider is rate-limited and fine
for testing, not for real traffic), create an organization, and go to
**Connections**. Scanning a real Azure environment additionally needs the
Entra app registration in `AZURE_INTEGRATION.md` §2.1 — that's a separate
setup, not a hosting one. Without it the app works fully up to the point of
starting a consent flow, and the connection wizard tells you so rather than
failing at the button.

### Scans stay Queued forever

`QUEUED` means the scan row was written and the task handed to Redis. Nothing
else has happened. A worker collects it within seconds when one is running, so
minutes in that state means nothing is listening — and the scans page now says
so rather than showing a progress bar indefinitely.

Almost always: **the Celery worker is not deployed.** It is a *second* Railway
service, built from the same image but started with
`infrastructure/railway/worker.json`:

```
celery -A app.workers.celery_app.celery_app worker --beat --schedule=/tmp/celerybeat-schedule --loglevel=INFO --concurrency=2
```

Check, in order:

1. A worker service exists in the Railway project and is running.
2. It has the same `DATABASE_URL`, `REDIS_URL` and `APP_ENV` as the API — it
   shares the whole codebase and reads the scan row itself.
3. Its logs show `scan.task_received`. If they do not, it is not reaching Redis.

Cancelling a stuck scan is safe: the pipeline re-reads the status before it
starts, so a task collected later stops instead of writing findings.

### Seeing the product loop before Azure is registered

The demo seed runs the real pipeline against a recorded snapshot. On Railway,
open the API service → the **shell** in its dashboard (or `railway run` with
their CLI) and run:

```bash
python /srv/database/seed/demo_environment.py --email you@example.com
```

Sign in through the app **first** — Supabase creates your account when you use
the magic link, and the demo organization attaches to that real account. Then
run it again with `--fix` to watch three findings auto-resolve and the score
move.

The seed refuses to run when `APP_ENV=production`; set that service to
`staging` while demoing, or skip the seed and connect a real tenant instead.

---

## 6. Redeploying after code changes

Both Railway and Vercel auto-deploy on push to `main`. Nothing else to do —
this is the entire point of connecting them to GitHub rather than uploading
builds by hand.

## 7. Rolling back

Both platforms keep prior deploys and let you roll back from their dashboard
with one click if a push breaks something. Prefer that over reverting the
commit under pressure — revert the commit afterward, once things are stable
again, following the repo's normal git workflow.
