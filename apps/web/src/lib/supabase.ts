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
 * Only active when VITE_SUPABASE_URL / VITE_SUPABASE_PUBLISHABLE_KEY are set.
 * Locally, with neither set, SignIn.tsx falls back to the dev-token flow
 * instead — see AZURE_INTEGRATION and SECURITY docs for why that flow refuses
 * to run once a real Supabase project is configured.
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

export async function supabaseSignOut(): Promise<void> {
  if (!supabase) return;
  await supabase.auth.signOut();
}
