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

  it("flags an API URL with no https:// prefix", () => {
    // The real failure this caught: fetch() treats a scheme-less value as a
    // relative path, so every call returns index.html and JSON parsing fails
    // somewhere unrelated. Nothing in the network tab looks obviously wrong.
    vi.stubEnv("VITE_API_URL", "humorous-passion-production-8f76.up.railway.app");
    vi.stubEnv("VITE_SUPABASE_URL", "https://abc.supabase.co");
    vi.stubEnv("VITE_SUPABASE_PUBLISHABLE_KEY", "anon-key");
    const problems = configProblems();
    expect(problems).toHaveLength(1);
    expect(problems[0].variable).toBe("VITE_API_URL");
    expect(problems[0].detail).toContain("https://");
  });

  it("flags a Supabase URL with no https:// prefix", () => {
    vi.stubEnv("VITE_API_URL", "https://api.example.com");
    vi.stubEnv("VITE_SUPABASE_URL", "abc.supabase.co");
    vi.stubEnv("VITE_SUPABASE_PUBLISHABLE_KEY", "anon-key");
    const problems = configProblems();
    expect(problems).toHaveLength(1);
    expect(problems[0].variable).toBe("VITE_SUPABASE_URL");
  });

  it("accepts http:// for a non-TLS deployment", () => {
    vi.stubEnv("VITE_API_URL", "http://api.internal.example.com");
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
