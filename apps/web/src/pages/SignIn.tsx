import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, auth, devSignIn, ApiError } from "@/lib/api";
import type { Organization } from "@/lib/types";
import { useT } from "@/i18n";
import { Button, Field, Input } from "@/components/ui";

export function SignInPage() {
  const t = useT();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      // In production this is a Supabase Auth session; CloudGuard's own API
      // only ever verifies the resulting token.
      const { data } = await devSignIn(email);
      auth.token = data.access_token;

      const orgs = await api.get<Organization[]>("/api/v1/organizations");
      if (orgs.data.length === 0) {
        navigate("/onboarding", { replace: true });
      } else {
        auth.organizationId = orgs.data[0].id;
        navigate("/", { replace: true });
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not sign in");
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-stone-50 px-6">
      <div className="w-full max-w-sm">
        <div className="mb-8 text-center">
          <h1 className="text-2xl font-semibold tracking-tight">{t.app.name}</h1>
          <p className="mt-1 text-sm text-stone-500">{t.app.tagline}</p>
        </div>

        <form
          onSubmit={submit}
          className="rounded-xl border border-stone-200 bg-white p-6 shadow-sm"
        >
          <Field label={t.auth.email}>
            <Input
              type="email"
              required
              autoFocus
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="you@company.com"
            />
          </Field>

          {error && <p className="mt-3 text-sm text-critical">{error}</p>}

          <Button type="submit" disabled={busy} className="mt-5 w-full">
            {busy ? t.common.loading : t.auth.continue}
          </Button>
        </form>

        <p className="mt-4 px-2 text-xs leading-relaxed text-stone-500">
          {t.auth.devNotice}
        </p>
      </div>
    </div>
  );
}
