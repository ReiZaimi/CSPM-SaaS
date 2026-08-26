/**
 * Supabase Auth bridge.
 *
 * CloudGuard's backend never authenticates anyone itself — it only verifies the
 * JWT Supabase issues (app/core/security.py::decode_token). This file is the
 * other half: it drives Supabase's hosted sign-in and mirrors the resulting
 * session into the same `auth` token store api.ts already uses, so the rest of
 * the app never has to know whether a session came from Supabase or from the
 * local dev-token route.
 *
 * Four ways in, all of them ending in the same Supabase-issued JWT: a magic
 * link, an email + password pair, a password reset, and Microsoft (Entra ID).
 * The backend cannot tell them apart and does not need to — it verifies the
 * token's signature and reads the user id, nothing more.
 *
 * Only active when VITE_SUPABASE_URL / VITE_SUPABASE_PUBLISHABLE_KEY are set;
 * with neither, every function here throws rather than silently doing nothing.
 */
import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { auth } from "./api";

const url = import.meta.env.VITE_SUPABASE_URL;
const key = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY;

export const supabaseConfigured = Boolean(url && key);

// A plain top-level `if` (not an assignment inside a closure) so TypeScript's
// control-flow narrowing correctly widens this to `SupabaseClient | null`
// afterward, instead of anchoring on the `null` initializer.
let clientOrNull: SupabaseClient | null = null;
if (url && key) {
  clientOrNull = createClient(url, key);
}

/** `const` so its narrowing survives being captured by the closures below —
 * TypeScript does not trust a mutable `let` across a closure boundary. */
export const supabase = clientOrNull;

/**
 * Resolves once the initial session check (including parsing a magic-link
 * redirect's URL fragment) has completed. The router waits on this before
 * deciding whether to redirect to /sign-in — without it, a page load that
 * lands mid-redirect would see `auth.token` still null and bounce the user
 * back to sign-in before the session finished parsing.
 */
export const authReady: Promise<void> = supabase
  ? new Promise((resolve) => {
      supabase.auth.onAuthStateChange((_event, session) => {
        auth.token = session?.access_token ?? null;
      });

      supabase.auth.getSession().then(({ data }) => {
        auth.token = data.session?.access_token ?? null;
        resolve();
      });
    })
  : Promise.resolve();

export async function signInWithMagicLink(email: string): Promise<void> {
  if (!supabase) throw new Error("Supabase is not configured");
  const { error } = await supabase.auth.signInWithOtp({
    email,
    options: { emailRedirectTo: window.location.origin },
  });
  if (error) throw error;
}

/**
 * Password sign-in.
 *
 * The password goes from the browser straight to Supabase's auth API over
 * TLS. It never reaches CloudGuard's own API, which still only ever verifies
 * the JWT that comes back (app/core/security.py::decode_token) — so the
 * backend's threat model is unchanged by this file, whatever provider the
 * session came from.
 */
export async function signInWithPassword(email: string, password: string): Promise<void> {
  if (!supabase) throw new Error("Supabase is not configured");
  const { error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) throw error;
}

/**
 * Password sign-up.
 *
 * Returns whether a session was established immediately. With Supabase's
 * "Confirm email" setting on — the default, and what DEPLOYMENT.md tells you
 * to leave on — sign-up creates the user but no session, and the caller must
 * tell the user to go and click the confirmation email. With it off, the user
 * is signed in on the spot. The caller cannot guess which, so it is reported.
 */
export async function signUpWithPassword(
  email: string,
  password: string,
): Promise<{ needsEmailConfirmation: boolean }> {
  if (!supabase) throw new Error("Supabase is not configured");
  const { data, error } = await supabase.auth.signUp({
    email,
    password,
    options: { emailRedirectTo: window.location.origin },
  });
  if (error) throw error;
  return { needsEmailConfirmation: data.session === null };
}

/** Emails a recovery link that lands on /reset-password with a live session. */
export async function sendPasswordReset(email: string): Promise<void> {
  if (!supabase) throw new Error("Supabase is not configured");
  const { error } = await supabase.auth.resetPasswordForEmail(email, {
    redirectTo: `${window.location.origin}/reset-password`,
  });
  if (error) throw error;
}

/** Sets a new password for the session the recovery link just established. */
export async function updatePassword(password: string): Promise<void> {
  if (!supabase) throw new Error("Supabase is not configured");
  const { error } = await supabase.auth.updateUser({ password });
  if (error) throw error;
}

/**
 * Sign in with Microsoft (Entra ID).
 *
 * The natural front door for an Azure-first product: the account someone uses
 * here is the same directory account that will later grant CloudGuard admin
 * consent. Supabase calls this provider `azure`.
 *
 * This never returns normally — it navigates away to Microsoft. The session
 * comes back on the redirect and is picked up by `onAuthStateChange` above,
 * so there is nothing to await and no token handling here.
 */
export async function signInWithMicrosoft(): Promise<void> {
  if (!supabase) throw new Error("Supabase is not configured");
  const { error } = await supabase.auth.signInWithOAuth({
    provider: "azure",
    options: {
      // openid/profile/email is the minimum that yields a usable identity.
      // Nothing here grants access to Azure *resources* — scanning access is a
      // separate admin consent against CloudGuard's own Entra application
      // (docs/AZURE_INTEGRATION.md), not this sign-in.
      scopes: "openid profile email",
      redirectTo: window.location.origin,
    },
  });
  if (error) throw error;
}

export async function supabaseSignOut(): Promise<void> {
  if (!supabase) return;
  await supabase.auth.signOut();
}
