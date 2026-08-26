import { describe, expect, it } from "vitest";
import {
  authReady,
  signInWithMagicLink,
  supabase,
  supabaseConfigured,
  supabaseSignOut,
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
});
