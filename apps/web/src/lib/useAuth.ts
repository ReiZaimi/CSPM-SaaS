import { useSyncExternalStore } from "react";
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
