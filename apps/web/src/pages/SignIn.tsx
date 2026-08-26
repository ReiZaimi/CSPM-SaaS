import { useState } from "react";
import { Navigate } from "react-router-dom";
import { signInWithMagicLink } from "@/lib/supabase";
import { useAuthToken } from "@/lib/useAuth";
import { useT } from "@/i18n";
import { ShieldMark } from "@/components/Brand";

/**
 * Passwordless sign-in via Supabase.
 *
 * CloudGuard's own backend never authenticates anyone — Supabase emails a
 * one-time link, and the API only ever *verifies* the token that produces
 * (app/core/security.py::decode_token). There is no password for this
 * application to mishandle, and no local sign-in path.
 *
 * The left panel is not decoration. This is the screen where someone decides
 * whether to hand a product read access to their whole cloud estate, so it
 * states plainly what the access is and what it is not.
 */
export function SignInPage() {
  const t = useT();
  const token = useAuthToken();
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

  // Returning from a magic link lands here first. Once the session is parsed,
  // move on rather than showing a sign-in form to someone already signed in.
  if (token) return <Navigate to="/" replace />;

  return (
    <div className="flex min-h-screen bg-white">
      <BrandPanel />

      <main className="flex flex-1 items-center justify-center px-6 py-12">
        <div className="w-full max-w-sm">
          {/* The mark repeats on mobile, where the left panel is hidden. */}
          <div className="mb-10 flex items-center gap-2.5 lg:hidden">
            <ShieldMark className="h-7 w-7 text-stone-900" />
            <span className="text-base font-semibold tracking-tight">{t.app.name}</span>
          </div>

          {linkSent ? (
            <LinkSent email={email} onUseAnother={() => setLinkSent(false)} />
          ) : (
            <>
              <h1 className="text-2xl font-semibold tracking-tight text-stone-900">
                Sign in
              </h1>
              <p className="mt-2 text-sm leading-relaxed text-stone-500">
                We'll email you a one-time link. No password to choose, forget, or
                have stolen.
              </p>

              <form onSubmit={submit} className="mt-8">
                <label htmlFor="email" className="block text-sm font-medium text-stone-700">
                  {t.auth.email}
                </label>
                <input
                  id="email"
                  type="email"
                  required
                  autoFocus
                  autoComplete="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@company.com"
                  className="mt-2 w-full rounded-lg border border-stone-300 bg-white px-3.5 py-2.5 text-sm text-stone-900 shadow-sm transition placeholder:text-stone-400 hover:border-stone-400 focus:border-stone-900 focus:outline-none focus:ring-2 focus:ring-stone-900/10"
                />

                {error && (
                  <p className="mt-3 rounded-lg border border-critical-border bg-critical-bg px-3 py-2 text-sm text-critical">
                    {error}
                  </p>
                )}

                <button
                  type="submit"
                  disabled={busy}
                  className="mt-5 flex w-full items-center justify-center gap-2 rounded-lg bg-stone-900 px-4 py-2.5 text-sm font-medium text-white shadow-sm transition hover:bg-stone-800 focus:outline-none focus:ring-2 focus:ring-stone-900/20 focus:ring-offset-2 disabled:cursor-not-allowed disabled:bg-stone-300"
                >
                  {busy && (
                    <span className="h-3.5 w-3.5 animate-spin rounded-full border-2 border-white/40 border-t-white" />
                  )}
                  {busy ? "Sending…" : t.auth.sendLink}
                </button>
              </form>

              <p className="mt-8 border-t border-stone-100 pt-6 text-xs leading-relaxed text-stone-500">
                {t.auth.passwordNotice}
              </p>
            </>
          )}
        </div>
      </main>
    </div>
  );
}

function BrandPanel() {
  const t = useT();
  return (
    <aside className="relative hidden w-[46%] max-w-xl flex-col justify-between overflow-hidden bg-stone-900 p-12 text-white lg:flex">
      {/* Two soft radial washes give the flat panel some depth without
          resorting to imagery that would date quickly. */}
      <div
        aria-hidden="true"
        className="pointer-events-none absolute inset-0 opacity-[0.18]"
        style={{
          background:
            "radial-gradient(60rem 40rem at 15% 0%, #fff 0%, transparent 55%), radial-gradient(40rem 30rem at 90% 100%, #fff 0%, transparent 50%)",
        }}
      />

      <div className="relative flex items-center gap-2.5">
        <ShieldMark className="h-8 w-8 text-white" />
        <span className="text-base font-semibold tracking-tight">{t.app.name}</span>
      </div>

      <div className="relative">
        <h2 className="max-w-md text-3xl font-semibold leading-tight tracking-tight">
          Know what's exposed. Fix what matters.
        </h2>
        <p className="mt-4 max-w-md text-sm leading-relaxed text-stone-300">
          CloudGuard reads your Azure environment, ranks what it finds by real
          business risk, and confirms your fixes actually worked.
        </p>

        <ul className="mt-10 space-y-4">
          <Assurance>Read-only access. CloudGuard never changes your resources.</Assurance>
          <Assurance>No credential to hand over — consent, not secrets.</Assurance>
          <Assurance>Your data is isolated at the database level, not just in code.</Assurance>
        </ul>
      </div>

      <p className="relative text-xs text-stone-500">
        Azure-first Cloud Security Posture Management
      </p>
    </aside>
  );
}

function Assurance({ children }: { children: React.ReactNode }) {
  return (
    <li className="flex items-start gap-3 text-sm text-stone-200">
      <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-white/10">
        <svg viewBox="0 0 16 16" className="h-3 w-3" aria-hidden="true">
          <path
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            d="m4 8.5 2.5 2.5L12 5.5"
          />
        </svg>
      </span>
      {children}
    </li>
  );
}

function LinkSent({ email, onUseAnother }: { email: string; onUseAnother: () => void }) {
  const t = useT();
  return (
    <div>
      <div className="flex h-11 w-11 items-center justify-center rounded-full bg-ok-bg text-ok">
        <svg viewBox="0 0 24 24" className="h-5 w-5" aria-hidden="true">
          <path
            fill="none"
            stroke="currentColor"
            strokeWidth="1.8"
            strokeLinecap="round"
            strokeLinejoin="round"
            d="M3 7.5 12 13l9-5.5M4.5 5.5h15a1.5 1.5 0 0 1 1.5 1.5v10a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 17V7a1.5 1.5 0 0 1 1.5-1.5Z"
          />
        </svg>
      </div>

      <h1 className="mt-5 text-2xl font-semibold tracking-tight text-stone-900">
        {t.auth.checkEmail}
      </h1>
      <p className="mt-2 text-sm leading-relaxed text-stone-600">
        {t.auth.linkSentTo} <strong className="text-stone-900">{email}</strong>.{" "}
        {t.auth.openOnThisDevice}
      </p>

      <p className="mt-6 rounded-lg bg-stone-50 px-4 py-3 text-xs leading-relaxed text-stone-500">
        The link works once and expires after an hour. If nothing arrives, check
        spam — and note that some disposable inboxes open links automatically,
        which uses the link up before you get to it.
      </p>

      <button
        onClick={onUseAnother}
        className="mt-6 text-sm font-medium text-stone-600 underline underline-offset-4 transition hover:text-stone-900"
      >
        Use a different address
      </button>
    </div>
  );
}
