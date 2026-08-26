import { afterEach, describe, expect, it, vi } from "vitest";
import { configProblems } from "../config";

/**
 * There is no development exemption to test around: CloudGuard has one
 * deployment target, so these checks apply to every build.
 */
afterEach(() => vi.unstubAllEnvs());

describe("frontend config checks", () => {
  it("flags a build with no API URL", () => {
    const problems = configProblems();
    expect(problems.some((p) => p.variable === "VITE_API_URL")).toBe(true);
  });

  it("flags a build with no Supabase credentials", () => {
    vi.stubEnv("VITE_API_URL", "https://api.example.com");
    const problems = configProblems();
    expect(problems).toHaveLength(1);
    expect(problems[0].variable).toContain("VITE_SUPABASE_URL");
  });

  it("flags a half-configured Supabase setup", () => {
    // The nastiest case: sign-in appears to work and silently does nothing.
    vi.stubEnv("VITE_API_URL", "https://api.example.com");
    vi.stubEnv("VITE_SUPABASE_URL", "https://abc.supabase.co");
    const problems = configProblems();
    expect(problems).toHaveLength(1);
    expect(problems[0].variable).toBe("VITE_SUPABASE_PUBLISHABLE_KEY");
  });

  it("passes a fully configured build", () => {
    vi.stubEnv("VITE_API_URL", "https://api.example.com");
    vi.stubEnv("VITE_SUPABASE_URL", "https://abc.supabase.co");
    vi.stubEnv("VITE_SUPABASE_PUBLISHABLE_KEY", "anon-key");
    expect(configProblems()).toEqual([]);
  });

  it("explains the consequence, not just the variable name", () => {
    for (const problem of configProblems()) {
      expect(problem.detail.length).toBeGreaterThan(60);
    }
  });
});
