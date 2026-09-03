import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, api, auth } from "../api";

const okResponse = (data: unknown) =>
  new Response(JSON.stringify({ data, error: null, meta: {} }), { status: 200 });

describe("api client", () => {
  beforeEach(() => {
    localStorage.clear();
    vi.restoreAllMocks();
  });
  afterEach(() => localStorage.clear());

  it("unwraps the response envelope", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(okResponse({ id: "1" })));
    const result = await api.get<{ id: string }>("/api/v1/things");
    expect(result.data).toEqual({ id: "1" });
  });

  it("throws a typed error carrying the server's error code", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            data: null,
            error: { code: "CLOUD_ACCOUNT_NOT_FOUND", message: "Cloud account not found" },
            meta: {},
          }),
          { status: 404 },
        ),
      ),
    );

    await expect(api.get("/api/v1/cloud-accounts/x")).rejects.toMatchObject({
      code: "CLOUD_ACCOUNT_NOT_FOUND",
      status: 404,
    });
  });

  it("sends the bearer token when one is stored", async () => {
    auth.token = "test-token";
    const fetchMock = vi.fn().mockResolvedValue(okResponse([]));
    vi.stubGlobal("fetch", fetchMock);

    await api.get("/api/v1/findings");

    const headers = fetchMock.mock.calls[0][1].headers as Headers;
    expect(headers.get("Authorization")).toBe("Bearer test-token");
  });

  it("omits the token on requests that opt out", async () => {
    auth.token = "test-token";
    const fetchMock = vi.fn().mockResolvedValue(okResponse({}));
    vi.stubGlobal("fetch", fetchMock);

    await api.post("/api/v1/auth/dev-token", { email: "a@b.c" }, { skipAuth: true });

    const headers = fetchMock.mock.calls[0][1].headers as Headers;
    expect(headers.get("Authorization")).toBeNull();
  });

  it("sends the organization header as a preference, not an authorization", async () => {
    // The server validates this against real membership; the browser choosing
    // an id it does not belong to gets a 404, not another tenant's data.
    auth.token = "t";
    auth.organizationId = "org-123";
    const fetchMock = vi.fn().mockResolvedValue(okResponse([]));
    vi.stubGlobal("fetch", fetchMock);

    await api.get("/api/v1/assets");

    const headers = fetchMock.mock.calls[0][1].headers as Headers;
    expect(headers.get("X-Organization-Id")).toBe("org-123");
  });

  it("clears both token and organization on sign out", () => {
    auth.token = "t";
    auth.organizationId = "o";
    auth.signOut();
    expect(auth.token).toBeNull();
    expect(auth.organizationId).toBeNull();
  });

  // ------------------------------------------------- an expired session
  it("signs the reader out when the server says they are not signed in", async () => {
    // An expired token used to read as a broken product: every panel on the
    // page failed with its own message, none of them said "signed out", and
    // nothing offered the one action that fixes it. Clearing the token puts the
    // router back in charge, which sends the reader to sign in.
    auth.token = "expired";
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            data: null,
            error: { code: "NOT_AUTHENTICATED", message: "Not authenticated" },
            meta: {},
          }),
          { status: 401 },
        ),
      ),
    );

    await expect(api.get("/api/v1/dashboard")).rejects.toBeInstanceOf(ApiError);
    expect(auth.token).toBeNull();
  });

  it("keeps a viewer signed in when they are merely not allowed", async () => {
    // 403 is a different sentence. Signing a viewer out for being refused a
    // write would answer "you may not do that" with "prove who you are", and
    // they would arrive back at the same refusal.
    auth.token = "valid";
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            data: null,
            error: { code: "PERMISSION_DENIED", message: "Read-only" },
            meta: {},
          }),
          { status: 403 },
        ),
      ),
    );

    await expect(api.get("/api/v1/scans")).rejects.toBeInstanceOf(ApiError);
    expect(auth.token).toBe("valid");
  });

  // ------------------------------------------------ when nothing answers
  it("gives up on a request that hangs, rather than spinning for ever", async () => {
    // `fetch` has no timeout and neither does TanStack Query, so a host that
    // accepts the connection and then says nothing left the query in
    // `isLoading` for as long as the tab was open.
    vi.useFakeTimers();
    try {
      vi.stubGlobal(
        "fetch",
        vi.fn().mockImplementation(
          (_url: string, init: RequestInit) =>
            new Promise((_resolve, reject) => {
              init.signal?.addEventListener("abort", () =>
                reject(new DOMException("aborted", "AbortError")),
              );
            }),
        ),
      );

      const pending = api.get("/api/v1/dashboard");
      const assertion = expect(pending).rejects.toMatchObject({ code: "TIMEOUT" });
      await vi.advanceTimersByTimeAsync(31_000);
      await assertion;
    } finally {
      vi.useRealTimers();
    }
  });

  it("reports an unreachable API in its own words", async () => {
    // The browser's "Failed to fetch" reads to a customer as a bug in
    // CloudGuard rather than as a connection that is not there.
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));

    await expect(api.get("/api/v1/dashboard")).rejects.toMatchObject({
      code: "NETWORK_ERROR",
      status: 0,
    });
  });

  it("surfaces a non-JSON server failure as an ApiError", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("<html>502</html>", { status: 502 })),
    );
    await expect(api.get("/api/v1/dashboard")).rejects.toBeInstanceOf(ApiError);
  });
});
