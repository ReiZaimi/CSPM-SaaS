/**
 * API client.
 *
 * Every response arrives in the { data, error, meta } envelope, so unwrapping
 * and error translation happen once, here, rather than in every component.
 *
 * Note what this file does NOT contain: any Azure credential, any Supabase
 * service key, any organization id chosen by the browser. The token identifies
 * the user; the server decides which tenant that means.
 */

// No fallback on purpose. There is no local API to fall back to, and a
// silent localhost default would make every request fail from a visitor's
// browser with no indication why. main.tsx refuses to render without it.
export const API_URL = import.meta.env.VITE_API_URL ?? "";
const TOKEN_KEY = "cloudguard.token";
const ORG_KEY = "cloudguard.org";

export type Envelope<T> = {
  data: T | null;
  error: { code: string; message: string } | null;
  meta: Record<string, unknown>;
};

export class ApiError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

/**
 * Subscribers for `useAuthToken`.
 *
 * The token lives in localStorage so it survives a reload, but a plain getter
 * is invisible to React: nothing re-renders when it changes. That mattered more
 * than it sounds. Supabase can deliver a session through `onAuthStateChange`
 * *after* the initial `getSession()` has already resolved empty — so the router
 * had already rendered a redirect to /sign-in, and the user sat looking at the
 * sign-in form while actually being signed in. Reloading "fixed" it, which is
 * exactly what "it doesn't keep me logged in" looks like from outside.
 */
const listeners = new Set<() => void>();

function notify(): void {
  for (const listener of listeners) listener();
}

export function subscribeToAuth(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export const auth = {
  get token(): string | null {
    return localStorage.getItem(TOKEN_KEY);
  },
  set token(value: string | null) {
    if (value === this.token) return; // no-op writes must not wake React
    if (value) localStorage.setItem(TOKEN_KEY, value);
    else localStorage.removeItem(TOKEN_KEY);
    notify();
  },
  get organizationId(): string | null {
    return localStorage.getItem(ORG_KEY);
  },
  set organizationId(value: string | null) {
    if (value === this.organizationId) return;
    if (value) localStorage.setItem(ORG_KEY, value);
    else localStorage.removeItem(ORG_KEY);
    notify();
  },
  signOut() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(ORG_KEY);
    notify();
  },
};

// Another tab signing in or out writes to the same localStorage keys. Without
// this, one tab can sit on a stale session indefinitely.
if (typeof window !== "undefined") {
  window.addEventListener("storage", (event) => {
    if (event.key === TOKEN_KEY || event.key === ORG_KEY) notify();
  });
}

/**
 * How long a request may hang before it is given up on.
 *
 * `fetch` has no timeout of its own, and neither does TanStack Query: a request
 * to a host that accepts the connection and then says nothing -- a container
 * mid-redeploy, a captive portal, a dropped mobile connection -- never settles,
 * so the query never leaves `isLoading` and the page spins for as long as the
 * tab is open. A bounded failure is something a reader can act on; an unbounded
 * spinner is not.
 *
 * Generous, because the API is a scanner's API: a dashboard aggregates a
 * tenant's whole posture, and a slow answer is still an answer.
 */
const REQUEST_TIMEOUT_MS = 30_000;
/** A report is rendered on demand, printed to PDF, and legitimately slow. */
const DOCUMENT_TIMEOUT_MS = 120_000;

/**
 * What happens when the server says the caller is not signed in.
 *
 * Only the dashboard used to notice, and it noticed by rendering an error where
 * its charts go. Everywhere else an expired session read as a broken product:
 * every panel on the page failed with its own message, none of them said
 * "signed out", and nothing offered the one action that fixes it. Clearing the
 * token puts the router back in charge -- ``RequireAuth`` sends the reader to
 * sign in, which is what actually happened.
 *
 * 403 is deliberately not this. A viewer refused a write is signed in and
 * should stay signed in; signing them out would answer "you may not do that"
 * with "prove who you are", and they would arrive back at the same refusal.
 */
function handleUnauthorized(): void {
  if (auth.token) auth.signOut();
}

async function send(
  url: string,
  init: RequestInit,
  timeoutMs: number,
): Promise<Response> {
  // A caller's own signal is honoured alongside the timeout -- TanStack passes
  // one when a query is cancelled, and dropping it would leave abandoned
  // requests running.
  const timeout = new AbortController();
  const timer = window.setTimeout(() => timeout.abort(), timeoutMs);
  const external = init.signal;
  const onExternalAbort = () => timeout.abort();
  external?.addEventListener("abort", onExternalAbort);

  try {
    return await fetch(url, { ...init, signal: timeout.signal });
  } catch (err) {
    if (external?.aborted) throw err;
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new ApiError(
        "TIMEOUT",
        `CloudGuard's API did not answer within ${Math.round(timeoutMs / 1000)} seconds.`,
        0,
      );
    }
    // A rejected fetch is the network, not the API: offline, DNS, a refused
    // connection, a CORS policy. Reported as such rather than as the browser's
    // own "Failed to fetch", which reads to a customer as a bug in CloudGuard.
    throw new ApiError(
      "NETWORK_ERROR",
      "CloudGuard could not reach its API. Check your connection and try again.",
      0,
    );
  } finally {
    window.clearTimeout(timer);
    external?.removeEventListener("abort", onExternalAbort);
  }
}

async function request<T>(
  path: string,
  options: RequestInit & { skipAuth?: boolean } = {},
): Promise<{ data: T; meta: Record<string, unknown> }> {
  const { skipAuth, ...init } = options;
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");

  if (!skipAuth && auth.token) {
    headers.set("Authorization", `Bearer ${auth.token}`);
  }
  // A preference the server validates against real membership, not a claim it
  // trusts. Sending it for the wrong org yields 404, not another org's data.
  if (auth.organizationId) {
    headers.set("X-Organization-Id", auth.organizationId);
  }

  const response = await send(`${API_URL}${path}`, { ...init, headers }, REQUEST_TIMEOUT_MS);

  if (response.status === 401 && !skipAuth) handleUnauthorized();

  let body: Envelope<T>;
  try {
    body = await response.json();
  } catch {
    throw new ApiError("NETWORK_ERROR", `Server returned ${response.status}`, response.status);
  }

  if (!response.ok || body.error) {
    const error = body.error ?? { code: "UNKNOWN", message: "Request failed" };
    throw new ApiError(error.code, error.message, response.status);
  }

  return { data: body.data as T, meta: body.meta };
}

/**
 * A response that is a document rather than an envelope.
 *
 * The report endpoints return a PDF or an HTML page, which is why they cannot
 * go through `request`: that parses JSON and would fail on the first byte. And
 * a plain `<a href>` cannot be used either — the bearer token lives in memory,
 * not in a cookie, so a browser-initiated navigation would arrive
 * unauthenticated and the user would be handed a 401 page instead of a file.
 *
 * Errors still arrive as the standard envelope, so a failure says what went
 * wrong rather than saving a file full of JSON.
 */
async function fetchDocument(path: string): Promise<Blob> {
  const headers = new Headers();
  if (auth.token) headers.set("Authorization", `Bearer ${auth.token}`);
  if (auth.organizationId) headers.set("X-Organization-Id", auth.organizationId);

  const response = await send(`${API_URL}${path}`, { headers }, DOCUMENT_TIMEOUT_MS);

  if (response.status === 401) handleUnauthorized();

  if (!response.ok) {
    try {
      const body = (await response.json()) as Envelope<unknown>;
      const error = body.error ?? { code: "UNKNOWN", message: "Request failed" };
      throw new ApiError(error.code, error.message, response.status);
    } catch (err) {
      if (err instanceof ApiError) throw err;
      throw new ApiError("NETWORK_ERROR", `Server returned ${response.status}`, response.status);
    }
  }

  return response.blob();
}

export const api = {
  get: <T,>(path: string) => request<T>(path).then((r) => r),
  /** A PDF or HTML report, fetched with the caller's token. */
  document: (path: string) => fetchDocument(path),
  post: <T,>(path: string, body?: unknown, opts: { skipAuth?: boolean } = {}) =>
    request<T>(path, { method: "POST", body: JSON.stringify(body ?? {}), ...opts }),
  patch: <T,>(path: string, body: unknown) =>
    request<T>(path, { method: "PATCH", body: JSON.stringify(body) }),
  /** A full replacement. Used where the API stores a statement, not a profile. */
  put: <T,>(path: string, body: unknown) =>
    request<T>(path, { method: "PUT", body: JSON.stringify(body) }),
  del: <T,>(path: string) => request<T>(path, { method: "DELETE" }),
};
