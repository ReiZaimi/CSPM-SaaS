import { useMemo, useSyncExternalStore } from "react";
import { auth, subscribeToAuth } from "./api";

/**
 * The current access token, as React state.
 *
 * useSyncExternalStore rather than a context provider: the token's real home is
 * localStorage (so it survives reloads) and Supabase mutates it from outside
 * the React tree entirely — on sign-in, on the hourly token refresh, and on
 * sign-out. This subscribes to that store directly instead of mirroring it into
 * state that can drift.
 */
export function useAuthToken(): string | null {
  return useSyncExternalStore(
    subscribeToAuth,
    () => auth.token,
    () => null, // server snapshot; there is no SSR here, but the API requires it
  );
}

/**
 * The signed-in user's email, read out of the token rather than stored.
 *
 * Supabase puts it in the JWT's `email` claim, so deriving it here keeps one
 * source of truth: it cannot drift from the session, survives a reload for the
 * same reason the token does, and disappears on sign-out without anything
 * having to remember to clear it.
 *
 * No signature check, deliberately. This value only ever labels the account
 * menu — nothing is authorized by it. The API verifies the same token properly
 * (app/core/security.py) and would reject a forged one, and a user editing
 * their own localStorage to show themselves a different label has achieved
 * nothing.
 */
export function useAuthEmail(): string | null {
  const token = useAuthToken();
  return useMemo(() => emailFromToken(token), [token]);
}

function emailFromToken(token: string | null): string | null {
  if (!token) return null;
  const payload = token.split(".")[1];
  if (!payload) return null;
  try {
    const json = atob(payload.replace(/-/g, "+").replace(/_/g, "/"));
    const claims = JSON.parse(json) as { email?: unknown };
    return typeof claims.email === "string" ? claims.email : null;
  } catch {
    // A malformed token is the API's problem to reject, not this label's.
    return null;
  }
}
