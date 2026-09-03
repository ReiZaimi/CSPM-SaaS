import { describe, expect, it } from "vitest";

import { ApiError } from "@/lib/api";
import { shouldRetry } from "@/lib/queryClient";

describe("which failures are worth asking again", () => {
  it("does not repeat an answer the server has already given", () => {
    // A 4xx says the same thing twice, and the reader waits twice as long for
    // it: not signed in, not allowed, not found, bad request.
    for (const status of [400, 401, 403, 404, 409, 422]) {
      expect(shouldRetry(0, new ApiError("X", "no", status))).toBe(false);
    }
  });

  it("tries once more when nobody actually answered", () => {
    // A container mid-restart, a request that timed out, a dropped connection.
    // `status === 0` is what the client stamps on the last two.
    expect(shouldRetry(0, new ApiError("TIMEOUT", "no answer", 0))).toBe(true);
    expect(shouldRetry(0, new ApiError("NETWORK_ERROR", "offline", 0))).toBe(true);
    expect(shouldRetry(0, new ApiError("X", "boom", 503))).toBe(true);
  });

  it("stops after one retry", () => {
    expect(shouldRetry(1, new ApiError("X", "boom", 500))).toBe(false);
  });

  it("treats an error it does not recognise as worth one more go", () => {
    // Anything that is not an ApiError never reached the server, so it is the
    // same class of failure as a dropped connection.
    expect(shouldRetry(0, new Error("something threw"))).toBe(true);
  });
});
