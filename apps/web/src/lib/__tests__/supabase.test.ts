import { describe, expect, it } from "vitest";
import { authReady, signInWithMagicLink, supabase, supabaseConfigured, supabaseSignOut } from "../supabase";

/**
 * The test environment sets neither VITE_SUPABASE_URL nor
 * VITE_SUPABASE_PUBLISHABLE_KEY, so this exercises the "not configured" path
 * — the same path local development takes before a Supabase project exists.
 * The configured path (real magic-link calls) is exercised manually against
 * a live Supabase project as part of the deploy checklist, not here.
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
