import { useState } from "react";
import { Navigate } from "react-router-dom";
import {
  sendPasswordReset,
  signInWithMagicLink,
  signInWithMicrosoft,
  signInWithPassword,
  signUpWithPassword,
} from "@/lib/supabase";
import { useAuthToken } from "@/lib/useAuth";
import { useT } from "@/i18n";
import { ShieldMark } from "@/components/Brand";

/**
 * Sign-in and sign-up, via Supabase.
 *
 * CloudGuard's own backend never authenticates anyone — Supabase does, and the
 * API only ever *verifies* the JWT that comes back
 * (app/core/security.py::decode_token). Four routes in, one token out:
 *
 *   Microsoft (Entra ID)  the front door for an Azure-first product — the same
 *                         directory account that will later grant consent
 *   Email + password      familiar, and works where corporate mail scanners
 *                         eat one-time links before the user sees them
 *   Magic link            no password to choose, forget, or have stolen
 *   Password reset        because a password flow without recovery is a trap
 *
 * A password typed here goes from the browser straight to Supabase over TLS.
 * It is never sent to, logged by, or stored by CloudGuard's API.
 *
 * The left panel is not decoration. This is the screen where someone decides
 * whether to hand a product read access to their whole cloud estate, so it
 * states plainly what the access is and what it is not.
 */

/** Which form is showing. `sent` states are tracked separately, below. */
type Mode = "signin" | "signup" | "magic" | "reset";

/** A "we emailed you something" confirmation, and which something it was. */
type Sent = { kind: "magic" | "confirm" | "reset"; email: string };

const MIN_PASSWORD_LENGTH = 8;

export function SignInPage() {
  const t = useT();
  const token = useAuthToken();
  const [mode, setMode] = useState<Mode>("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState<Sent | null>(null);

  const needsPassword = mode === "signin" || mode === "signup";

  function switchTo(next: Mode) {
    setMode(next);
    setError(null);
    // The password does not carry across a mode change: a value typed for
    // sign-in should not silently become the password of a new account.
    setPassword("");
  }

  async function submit(event: React.FormEvent) {
    event.preventDefault();

    if (needsPassword && password.length < MIN_PASSWORD_LENGTH) {
      setError(t.auth.passwordTooShort);
      return;
    }

    setBusy(true);
    setError(null);
    try {
      if (mode === "signin") {
        await signInWithPassword(email, password);
        // No navigation here. Supabase's onAuthStateChange writes the token,
        // useAuthToken re-renders this component, and the redirect below fires.
      } else if (mode === "signup") {
        const { needsEmailConfirmation } = await signUpWithPassword(email, password);
        if (needsEmailConfirmation) setSent({ kind: "confirm", email });
      } else if (mode === "magic") {
        await signInWithMagicLink(email);
        setSent({ kind: "magic", email });
      } else {
        await sendPasswordReset(email);
        setSent({ kind: "reset", email });
      }
    } catch (err) {
      setError(authErrorMessage(err));
    } finally {
      setBusy(false);
    }
  }

  async function microsoft() {
    setBusy(true);
    setError(null);
    try {
      // Navigates away to Microsoft and does not come back here, so `busy`
      // is deliberately left set — the button should stay disabled for the
      // moment the browser spends unloading the page.
      await signInWithMicrosoft();
    } catch (err) {
      setError(authErrorMessage(err));
      setBusy(false);
    }
  }

  // Returning from a magic link, a confirmation, or Microsoft lands here first.
  // Once the session is parsed, move on rather than showing a sign-in form to
  // someone who is already signed in.
  if (token) return <Navigate to="/" replace />;

  return (
    <div className="flex min-h-screen bg-background">
      <BrandPanel />

      <main className="flex flex-1 items-center justify-center px-6 py-12">
        <div className="w-full max-w-sm">
          {/* The mark repeats on mobile, where the left panel is hidden. */}
          <div className="mb-10 flex items-center gap-2.5 lg:hidden">
            <ShieldMark className="h-7 w-7 text-foreground" />
            <span className="text-base font-semibold tracking-tight">{t.app.name}</span>
          </div>

          {sent ? (
            <SentNotice
              sent={sent}
              onUseAnother={() => {
                setSent(null);
                setPassword("");
              }}
            />
          ) : (
            <>
              <h1 className="text-2xl font-semibold tracking-tight text-foreground">
                {mode === "signup"
                  ? t.auth.signUp
                  : mode === "reset"
                    ? t.auth.resetTitle
                    : t.auth.signIn}
              </h1>
              <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
                {mode === "signup"
                  ? "Start with your work email. You can connect Azure once you're in."
                  : mode === "reset"
                    ? t.auth.resetIntro
                    : mode === "magic"
                      ? "We'll email you a one-time link. No password to choose, forget, or have stolen."
                      : "Use your Microsoft account, or the email and password you signed up with."}
              </p>

              {/* Microsoft first: for an Azure-first product it is the account
                  most users already have, and the one they will consent with. */}
              {mode !== "reset" && (
                <>
                  <MicrosoftButton onClick={microsoft} disabled={busy} label={t.auth.continueWithMicrosoft} />
                  <Divider label={t.auth.orDivider} />
                </>
              )}

              <form onSubmit={submit} className={mode === "reset" ? "mt-8" : "mt-6"}>
                <label htmlFor="email" className="block text-sm font-medium text-foreground">
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
                  className={FIELD_CLASS}
                />

                {needsPassword && (
                  <PasswordField
                    id="password"
                    label={t.auth.password}
                    value={password}
                    onChange={setPassword}
                    // Telling the browser's password manager which of the two
                    // this is, so it offers to fill rather than to save on
                    // sign-in and the reverse on sign-up.
                    autoComplete={mode === "signup" ? "new-password" : "current-password"}
                    hint={mode === "signup" ? t.auth.passwordTooShort : undefined}
                    trailing={
                      mode === "signin" ? (
                        <button
                          type="button"
                          onClick={() => switchTo("reset")}
                          className="text-xs font-medium text-muted-foreground underline underline-offset-2 transition hover:text-foreground"
                        >
                          {t.auth.forgotPassword}
                        </button>
                      ) : undefined
                    }
                  />
                )}

                {error && (
                  <p
                    role="alert"
                    className="mt-3 rounded-lg border border-critical-border bg-critical-bg px-3 py-2 text-sm text-critical"
                  >
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
                  {submitLabel(mode, busy, t)}
                </button>
              </form>

              <AlternateRoutes mode={mode} onSwitch={switchTo} />

              {/* Whichever assurance the mode has actually earned. Reset gets
                  none: there is no password typed here yet and no Microsoft
                  button on screen to qualify. */}
              {mode !== "reset" && (
                <p className="mt-8 border-t border-border pt-6 text-xs leading-relaxed text-muted-foreground">
                  {needsPassword ? t.auth.passwordNotice : t.auth.microsoftHint}
                </p>
              )}
            </>
          )}
        </div>
      </main>
    </div>
  );
}

const FIELD_CLASS =
  "mt-2 w-full rounded-lg border border-input bg-background px-3.5 py-2.5 text-sm text-foreground shadow-sm transition placeholder:text-muted-foreground hover:border-stone-400 focus:border-stone-900 focus:outline-none focus:ring-2 focus:ring-stone-900/10";

function submitLabel(mode: Mode, busy: boolean, t: ReturnType<typeof useT>): string {
  if (busy) {
    if (mode === "signup") return t.auth.creatingAccount;
    if (mode === "signin") return t.auth.signingIn;
    return t.auth.sending;
  }
  if (mode === "signup") return t.auth.signUp;
  if (mode === "signin") return t.auth.signIn;
  if (mode === "magic") return t.auth.sendLink;
  return t.auth.sendReset;
}

/**
 * Turns Supabase's auth errors into something a person can act on.
 *
 * Deliberately does not distinguish "no such user" from "wrong password":
 * that difference is an account-enumeration oracle, and Supabase does not
 * offer it either.
 */
function authErrorMessage(err: unknown): string {
  const raw = err instanceof Error ? err.message : "";
  const text = raw.toLowerCase();

  if (text.includes("invalid login credentials")) {
    return "That email and password don't match an account.";
  }
  if (text.includes("already registered") || text.includes("already exists")) {
    return "An account with that email already exists — sign in instead.";
  }
  if (text.includes("email not confirmed")) {
    return "Confirm your email first. Check for the link we sent when you signed up.";
  }
  if (text.includes("password should be") || text.includes("password is too")) {
    return "That password is too short or too easily guessed. Try a longer one.";
  }
  if (text.includes("rate limit") || text.includes("too many")) {
    return "Too many attempts. Wait a minute and try again.";
  }
  if (text.includes("not configured")) {
    return "This deployment has no Supabase project configured, so sign-in is unavailable.";
  }
  return raw || "Something went wrong. Try again.";
}

function Divider({ label }: { label: string }) {
  return (
    <div className="mt-6 flex items-center gap-3" aria-hidden="true">
      <span className="h-px flex-1 bg-stone-200" />
      <span className="text-xs uppercase tracking-wide text-muted-foreground">{label}</span>
      <span className="h-px flex-1 bg-stone-200" />
    </div>
  );
}

function MicrosoftButton({
  onClick,
  disabled,
  label,
}: {
  onClick: () => void;
  disabled: boolean;
  label: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="mt-8 flex w-full items-center justify-center gap-2.5 rounded-lg border border-input bg-background px-4 py-2.5 text-sm font-medium text-foreground shadow-sm transition hover:border-stone-400 hover:bg-muted/40 focus:outline-none focus:ring-2 focus:ring-stone-900/10 disabled:cursor-not-allowed disabled:text-muted-foreground"
    >
      <MicrosoftMark />
      {label}
    </button>
  );
}

/** Microsoft's four-square mark, at its published brand colors. */
function MicrosoftMark() {
  return (
    <svg viewBox="0 0 16 16" className="h-4 w-4 shrink-0" aria-hidden="true">
      <path fill="#f25022" d="M0 0h7.6v7.6H0z" />
      <path fill="#7fba00" d="M8.4 0H16v7.6H8.4z" />
      <path fill="#00a4ef" d="M0 8.4h7.6V16H0z" />
      <path fill="#ffb900" d="M8.4 8.4H16V16H8.4z" />
    </svg>
  );
}

function PasswordField({
  id,
  label,
  value,
  onChange,
  autoComplete,
  hint,
  trailing,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  autoComplete: string;
  hint?: string;
  trailing?: React.ReactNode;
}) {
  const t = useT();
  const [visible, setVisible] = useState(false);

  return (
    <div className="mt-4">
      <div className="flex items-baseline justify-between gap-3">
        <label htmlFor={id} className="block text-sm font-medium text-foreground">
          {label}
        </label>
        {trailing}
      </div>
      <div className="relative">
        <input
          id={id}
          type={visible ? "text" : "password"}
          required
          autoComplete={autoComplete}
          minLength={MIN_PASSWORD_LENGTH}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className={`${FIELD_CLASS} pr-11`}
        />
        <button
          type="button"
          onClick={() => setVisible((v) => !v)}
          aria-label={visible ? t.auth.hidePassword : t.auth.showPassword}
          className="absolute inset-y-0 right-0 mt-2 flex items-center px-3 text-muted-foreground transition hover:text-foreground"
        >
          <EyeIcon crossed={visible} />
        </button>
      </div>
      {hint && <p className="mt-1.5 text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

function EyeIcon({ crossed }: { crossed: boolean }) {
  return (
    <svg viewBox="0 0 24 24" className="h-4 w-4" aria-hidden="true">
      <g fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round">
        <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" />
        <circle cx="12" cy="12" r="2.8" />
        {crossed && <path d="m4 20 16-16" />}
      </g>
    </svg>
  );
}

/** Links to the sign-in routes that are not the one currently showing. */
function AlternateRoutes({ mode, onSwitch }: { mode: Mode; onSwitch: (mode: Mode) => void }) {
  const t = useT();

  if (mode === "reset") {
    return (
      <div className="mt-6 text-center">
        <TextLink onClick={() => onSwitch("signin")}>{t.auth.backToSignIn}</TextLink>
      </div>
    );
  }

  return (
    <div className="mt-6 space-y-3 text-center text-sm">
      <p>
        <TextLink onClick={() => onSwitch(mode === "magic" ? "signin" : "magic")}>
          {mode === "magic" ? t.auth.passwordInstead : t.auth.magicLinkInstead}
        </TextLink>
      </p>
      <p className="text-muted-foreground">
        {mode === "signup" ? t.auth.haveAccount : t.auth.noAccount}{" "}
        <TextLink onClick={() => onSwitch(mode === "signup" ? "signin" : "signup")}>
          {mode === "signup" ? t.auth.signIn : t.auth.createOne}
        </TextLink>
      </p>
    </div>
  );
}

function TextLink({ onClick, children }: { onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="font-medium text-muted-foreground underline underline-offset-4 transition hover:text-foreground"
    >
      {children}
    </button>
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
          <Assurance>No Azure credential to hand over — consent, not secrets.</Assurance>
          <Assurance>Your data is isolated at the database level, not just in code.</Assurance>
        </ul>
      </div>

      <p className="relative text-xs text-muted-foreground">
        Azure-first Cloud Security Posture Management
      </p>
    </aside>
  );
}

function Assurance({ children }: { children: React.ReactNode }) {
  return (
    <li className="flex items-start gap-3 text-sm text-stone-200">
      <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-background/10">
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

/**
 * "We emailed you something." One screen for all three, because from the
 * user's side the next action is identical: go to your inbox, click the link.
 */
function SentNotice({ sent, onUseAnother }: { sent: Sent; onUseAnother: () => void }) {
  const t = useT();
  const lead =
    sent.kind === "confirm"
      ? t.auth.confirmSentTo
      : sent.kind === "reset"
        ? t.auth.resetSentTo
        : t.auth.linkSentTo;

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

      <h1 className="mt-5 text-2xl font-semibold tracking-tight text-foreground">
        {t.auth.checkEmail}
      </h1>
      <p className="mt-2 text-sm leading-relaxed text-muted-foreground">
        {lead} <strong className="text-foreground">{sent.email}</strong>.{" "}
        {t.auth.openOnThisDevice}
      </p>

      <p className="mt-6 rounded-lg bg-muted/40 px-4 py-3 text-xs leading-relaxed text-muted-foreground">
        The link works once and expires after an hour. If nothing arrives, check
        spam — and note that some disposable inboxes open links automatically,
        which uses the link up before you get to it.
      </p>

      <button
        onClick={onUseAnother}
        className="mt-6 text-sm font-medium text-muted-foreground underline underline-offset-4 transition hover:text-foreground"
      >
        {t.auth.useAnotherAddress}
      </button>
    </div>
  );
}
