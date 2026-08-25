import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, auth, devSignIn, ApiError } from "@/lib/api";
import { signInWithMagicLink, supabaseConfigured } from "@/lib/supabase";
import type { Organization } from "@/lib/types";
import { useT } from "@/i18n";
import { Button, Field, Input } from "@/components/ui";

export function SignInPage() {
  const t = useT();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [linkSent, setLinkSent] = useState(false);

  async function continueSession() {
    const orgs = await api.get<Organization[]>("/api/v1/organizations");
    if (orgs.data.length === 0) {
      navigate("/onboarding", { replace: true });
    } else {
      auth.organizationId = orgs.data[0].id;
      navigate("/", { replace: true });
    }
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      if (supabaseConfigured) {
        // Passwordless: Supabase emails a link, the click completes the
        // session, and lib/supabase.ts's auth-state listener picks it up —
        // CloudGuard's own backend never sees a password.
        await signInWithMagicLink(email);
        setLinkSent(true);
        setBusy(false);
        return;
      }

      const { data } = await devSignIn(email);
      auth.token = data.access_token;
      await continueSession();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not sign in");
      setBusy(false);
    }
  }

  if (linkSent) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-stone-50 px-6">
        <div className="w-full max-w-sm text-center">
          <h1 className="text-xl font-semibold tracking-tight">Check your email</h1>
          <p className="mt-2 text-sm text-stone-600">
            We sent a sign-in link to <strong>{email}</strong>. Open it on this device to
            continue.
          </p>
        </div>
      </div>
    );
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
            {busy ? t.common.loading : supabaseConfigured ? "Send sign-in link" : t.auth.continue}
          </Button>
        </form>

        {!supabaseConfigured && (
          <p className="mt-4 px-2 text-xs leading-relaxed text-stone-500">
            {t.auth.devNotice}
          </p>
        )}
      </div>
    </div>
  );
}
