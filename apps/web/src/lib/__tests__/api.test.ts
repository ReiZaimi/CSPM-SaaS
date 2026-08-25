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

  it("surfaces a non-JSON server failure as an ApiError", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("<html>502</html>", { status: 502 })),
    );
    await expect(api.get("/api/v1/dashboard")).rejects.toBeInstanceOf(ApiError);
  });
});
