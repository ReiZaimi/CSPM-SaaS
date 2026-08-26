import { describe, expect, it } from "vitest";
import {
  authReady,
  sendPasswordReset,
  signInWithMagicLink,
  signInWithMicrosoft,
  signInWithPassword,
  signUpWithPassword,
  supabase,
  supabaseConfigured,
  supabaseSignOut,
  updatePassword,
} from "../supabase";

/**
 * The test environment sets no Supabase variables, so this covers the
 * unconfigured path — which in a cloud-only app is a misconfigured deployment
 * rather than a normal development state. The configured path is exercised
 * against a live Supabase project as part of the deploy checklist.
 */
describe("supabase auth bridge, unconfigured", () => {
  it("reports itself as not configured", () => {
    expect(supabaseConfigured).toBe(false);
    expect(supabase).toBeNull();
  });

  it("resolves authReady immediately rather than hanging forever", async () => {
    await expect(authReady).resolves.toBeUndefined();
  });

  it("refuses to send a magic link instead of silently no-op'ing", async () => {
    await expect(signInWithMagicLink("a@b.com")).rejects.toThrow("not configured");
  });

  it("treats sign-out as a no-op rather than throwing", async () => {
    await expect(supabaseSignOut()).resolves.toBeUndefined();
  });

  // Every entry point fails loudly for the same reason: a sign-in button that
  // silently does nothing is the single hardest misconfiguration to diagnose
  // from a bug report, which is what config.ts exists to prevent.
  it.each([
    ["password sign-in", () => signInWithPassword("a@b.com", "correct horse battery")],
    ["password sign-up", () => signUpWithPassword("a@b.com", "correct horse battery")],
    ["password reset", () => sendPasswordReset("a@b.com")],
    ["password update", () => updatePassword("correct horse battery")],
    ["Microsoft sign-in", () => signInWithMicrosoft()],
  ])("refuses %s instead of silently no-op'ing", async (_name, call) => {
    await expect(call()).rejects.toThrow("not configured");
  });
});
