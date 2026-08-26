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
const API_URL = import.meta.env.VITE_API_URL ?? "";
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

export const auth = {
  get token(): string | null {
    return localStorage.getItem(TOKEN_KEY);
  },
  set token(value: string | null) {
    if (value) localStorage.setItem(TOKEN_KEY, value);
    else localStorage.removeItem(TOKEN_KEY);
  },
  get organizationId(): string | null {
    return localStorage.getItem(ORG_KEY);
  },
  set organizationId(value: string | null) {
    if (value) localStorage.setItem(ORG_KEY, value);
    else localStorage.removeItem(ORG_KEY);
  },
  signOut() {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(ORG_KEY);
  },
};

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

  const response = await fetch(`${API_URL}${path}`, { ...init, headers });

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

export const api = {
  get: <T,>(path: string) => request<T>(path).then((r) => r),
  post: <T,>(path: string, body?: unknown, opts: { skipAuth?: boolean } = {}) =>
    request<T>(path, { method: "POST", body: JSON.stringify(body ?? {}), ...opts }),
  patch: <T,>(path: string, body: unknown) =>
    request<T>(path, { method: "PATCH", body: JSON.stringify(body) }),
  del: <T,>(path: string) => request<T>(path, { method: "DELETE" }),
};
