import { useState } from "react";
import { signInWithMagicLink } from "@/lib/supabase";
import { useT } from "@/i18n";
import { Button, Field, Input } from "@/components/ui";

/**
 * Passwordless sign-in via Supabase.
 *
 * CloudGuard's own backend never authenticates anyone — Supabase emails a
 * one-time link, and the API only ever *verifies* the token that produces
 * (app/core/security.py::decode_token). There is no password for this
 * application to mishandle, and no local sign-in path.
 */
export function SignInPage() {
  const t = useT();
  const [email, setEmail] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [linkSent, setLinkSent] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await signInWithMagicLink(email);
      setLinkSent(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not send the sign-in link");
    } finally {
      setBusy(false);
    }
  }

  if (linkSent) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-stone-50 px-6">
        <div className="w-full max-w-sm text-center">
          <h1 className="text-xl font-semibold tracking-tight">{t.auth.checkEmail}</h1>
          <p className="mt-2 text-sm text-stone-600">
            {t.auth.linkSentTo} <strong>{email}</strong>. {t.auth.openOnThisDevice}
          </p>
          <button
            onClick={() => setLinkSent(false)}
            className="mt-6 text-sm text-stone-500 underline underline-offset-2 hover:text-stone-900"
          >
            Use a different address
          </button>
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
            {busy ? t.common.loading : t.auth.sendLink}
          </Button>
        </form>

        <p className="mt-4 px-2 text-xs leading-relaxed text-stone-500">
          {t.auth.passwordNotice}
        </p>
      </div>
    </div>
  );
}
