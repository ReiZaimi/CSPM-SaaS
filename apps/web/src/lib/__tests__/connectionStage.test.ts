import { describe, expect, it } from "vitest";

import { connectionStage, stepIndex } from "@/lib/connectionStage";
import type { CloudConnection } from "@/lib/types";

function connection(overrides: Partial<CloudConnection> = {}): CloudConnection {
  return {
    id: "c1",
    provider: "azure",
    name: "production",
    scope_type: "TENANT_ROOT",
    scope_id: null,
    scope_path: null,
    role_version: "v2",
    tenant_id: null,
    service_principal_object_id: null,
    consent_status: "PENDING",
    consented_at: null,
    rbac_verified_at: null,
    status: "PENDING",
    status_detail: null,
    last_discovery_at: null,
    scan_interval_hours: null,
    created_at: "2026-01-01T00:00:00Z",
    is_verified: false,
    is_ready_to_scan: false,
    subscription_count: 0,
    subscriptions: [],
    consent_url: null,
    template_url: null,
    deploy_stalled: false,
    ...overrides,
  } as CloudConnection;
}

const consented = {
  consent_status: "GRANTED",
  status: "PENDING",
} as Partial<CloudConnection>;

const verified = {
  ...consented,
  rbac_verified_at: "2026-01-01T00:00:00Z",
  is_verified: true,
  status: "ACTIVE",
} as Partial<CloudConnection>;

const subscription = {
  id: "s1",
  subscription_id: "00000000-0000-0000-0000-000000000001",
  display_name: "Production",
  in_scope: true,
};

describe("which step a connection is on", () => {
  it("starts at the scope form when nothing exists yet", () => {
    expect(connectionStage(null)).toBe("scope");
  });

  it("waits on consent before anything else", () => {
    expect(connectionStage(connection())).toBe("consent");
  });

  it("moves to the role deployment once consent lands", () => {
    expect(connectionStage(connection(consented))).toBe("deploy");
  });

  it("distinguishes verified-and-empty from verified-with-subscriptions", () => {
    // Both grants prove CloudGuard may look. Neither says it found anything,
    // and the two states need different words on the screen.
    expect(connectionStage(connection(verified))).toBe("discover");
    expect(
      connectionStage(
        connection({ ...verified, subscriptions: [subscription] } as Partial<CloudConnection>),
      ),
    ).toBe("review");
  });

  it("is done only when something is actually scannable", () => {
    // `is_verified` said yes over an empty connection once. Readiness is the
    // field that knows about scope, so it is the one the last step reads.
    expect(
      connectionStage(
        connection({
          ...verified,
          is_ready_to_scan: true,
          subscriptions: [subscription],
        } as Partial<CloudConnection>),
      ),
    ).toBe("done");
  });

  it("reads a cancelled setup as paused rather than as waiting for consent", () => {
    // A cancelled connection is also un-consented. Checking consent first would
    // have it report itself as waiting for an administrator nobody is asking.
    expect(
      connectionStage(connection({ status: "DISABLED" } as Partial<CloudConnection>)),
    ).toBe("paused");
  });

  it("keeps a disabled but verified connection out of the setup flow", () => {
    expect(
      connectionStage(
        connection({
          ...verified,
          status: "DISABLED",
          is_ready_to_scan: true,
          subscriptions: [subscription],
        } as Partial<CloudConnection>),
      ),
    ).toBe("done");
  });

  it("collapses the three subscription states onto one rail row", () => {
    // Otherwise the finish line moves when a subscription appears.
    expect(stepIndex("discover")).toBe(stepIndex("review"));
    expect(stepIndex("review")).toBe(stepIndex("done"));
  });
});
