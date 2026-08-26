import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { updatePassword } from "@/lib/supabase";
import { useAuthToken } from "@/lib/useAuth";
import { useT } from "@/i18n";
import { ShieldMark } from "@/components/Brand";

/**
 * Where a password-reset email lands.
 *
 * The recovery link carries a real (short-lived) session, which Supabase has
 * already parsed out of the URL by the time this renders — App.tsx waits on
 * `authReady` before routing anything. So the check below is not an auth gate;
 * it is how an expired or already-used link is recognised, and it says so
 * rather than bouncing the user to a sign-in form that will not help them.
 */
const MIN_PASSWORD_LENGTH = 8;

export function ResetPasswordPage() {
  const t = useT();
  const navigate = useNavigate();
  const token = useAuthToken();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent) {
    event.preventDefault();

    if (password.length < MIN_PASSWORD_LENGTH) {
      setError(t.auth.passwordTooShort);
      return;
    }
    if (password !== confirm) {
      setError("The two passwords don't match.");
      return;
    }

    setBusy(true);
    setError(null);
    try {
      await updatePassword(password);
      // The recovery session is a normal session, so there is nowhere to send
      // them but in — signing them out to re-enter the password they just set
      // would be theatre.
      navigate("/", { replace: true });
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not update your password");
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-stone-50 px-6">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex items-center gap-2.5">
          <ShieldMark className="h-7 w-7 text-stone-900" />
          <span className="text-base font-semibold tracking-tight">{t.app.name}</span>
        </div>

        {token ? (
          <>
            <h1 className="text-2xl font-semibold tracking-tight text-stone-900">
              {t.auth.setPassword}
            </h1>
            <p className="mt-2 text-sm leading-relaxed text-stone-500">
              Choose something long. {t.auth.passwordTooShort}
            </p>

            <form
              onSubmit={submit}
              className="mt-6 space-y-4 rounded-xl border border-stone-200 bg-white p-6 shadow-sm"
            >
              <label className="block">
                <span className="mb-1.5 block text-sm font-medium text-stone-700">
                  {t.auth.newPassword}
                </span>
                <input
                  type="password"
                  required
                  autoFocus
                  autoComplete="new-password"
                  minLength={MIN_PASSWORD_LENGTH}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className={FIELD_CLASS}
                />
              </label>

              <label className="block">
                <span className="mb-1.5 block text-sm font-medium text-stone-700">
                  Confirm password
                </span>
                <input
                  type="password"
                  required
                  autoComplete="new-password"
                  minLength={MIN_PASSWORD_LENGTH}
                  value={confirm}
                  onChange={(e) => setConfirm(e.target.value)}
                  className={FIELD_CLASS}
                />
              </label>

              {error && (
                <p role="alert" className="text-sm text-critical">
                  {error}
                </p>
              )}

              <button
                type="submit"
                disabled={busy}
                className="flex w-full items-center justify-center gap-2 rounded-lg bg-stone-900 px-4 py-2.5 text-sm font-medium text-white shadow-sm transition hover:bg-stone-800 disabled:cursor-not-allowed disabled:bg-stone-300"
              >
                {busy ? t.common.loading : t.auth.setPassword}
              </button>
            </form>
          </>
        ) : (
          <>
            <h1 className="text-2xl font-semibold tracking-tight text-stone-900">
              This link has expired
            </h1>
            <p className="mt-2 text-sm leading-relaxed text-stone-500">
              Reset links work once and expire after an hour. Ask for a fresh one
              and open it on this device.
            </p>
            <Link
              to="/sign-in"
              className="mt-6 inline-block text-sm font-medium text-stone-600 underline underline-offset-4 transition hover:text-stone-900"
            >
              {t.auth.backToSignIn}
            </Link>
          </>
        )}
      </div>
    </div>
  );
}

const FIELD_CLASS =
  "w-full rounded-lg border border-stone-300 bg-white px-3.5 py-2.5 text-sm text-stone-900 shadow-sm transition placeholder:text-stone-400 hover:border-stone-400 focus:border-stone-900 focus:outline-none focus:ring-2 focus:ring-stone-900/10";
