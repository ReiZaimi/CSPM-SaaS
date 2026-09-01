import { describe, expect, it } from "vitest";

import {
  cadenceLabel,
  cadenceSummary,
  isNewSinceLastRead,
  lastReadAt,
  statusSummary,
} from "@/lib/connectionSummary";
import type { CloudConnection, DiscoveredSubscription } from "@/lib/types";

function subscription(
  overrides: Partial<DiscoveredSubscription> = {},
): DiscoveredSubscription {
  return {
    id: "s1",
    subscription_id: "00000000-0000-0000-0000-000000000001",
    display_name: "prod",
    in_scope: true,
    status: "ACTIVE",
    discovered_at: "2026-08-01T00:00:00Z",
    last_scan_at: "2026-08-30T00:00:00Z",
    is_scannable: true,
    ...overrides,
  } as DiscoveredSubscription;
}

function connection(overrides: Partial<CloudConnection> = {}): CloudConnection {
  return {
    id: "c1",
    provider: "azure",
    name: "prod",
    scope_type: "TENANT_ROOT",
    scope_id: null,
    scope_path: null,
    role_version: "v2",
    tenant_id: "t1",
    service_principal_object_id: null,
    consent_status: "GRANTED",
    consented_at: "2026-08-01T00:00:00Z",
    rbac_verified_at: "2026-08-01T00:00:00Z",
    status: "ACTIVE",
    status_detail: null,
    last_discovery_at: null,
    scan_interval_hours: 24,
    created_at: "2026-08-01T00:00:00Z",
    is_verified: true,
    is_ready_to_scan: true,
    subscription_count: 1,
    subscriptions: [subscription()],
    consent_url: null,
    template_url: null,
    deploy_stalled: false,
    ...overrides,
  } as CloudConnection;
}

describe("when an environment was last read", () => {
  it("is the latest read of anything beneath it", () => {
    const value = lastReadAt(
      connection({
        subscriptions: [
          subscription({ last_scan_at: "2026-08-10T00:00:00Z" }),
          subscription({ id: "s2", last_scan_at: "2026-08-31T09:00:00Z" }),
        ],
      } as Partial<CloudConnection>),
    );

    expect(value).toBe("2026-08-31T09:00:00Z");
  });

  it("counts a subscription that is now out of scope", () => {
    // The question is when this environment was last looked at, and one
    // excluded yesterday was still looked at last week.
    const value = lastReadAt(
      connection({
        subscriptions: [
          subscription({ in_scope: false, last_scan_at: "2026-08-31T09:00:00Z" }),
        ],
      } as Partial<CloudConnection>),
    );

    expect(value).toBe("2026-08-31T09:00:00Z");
  });

  it("is null when nothing has ever been read", () => {
    expect(
      lastReadAt(
        connection({
          subscriptions: [subscription({ last_scan_at: null })],
        } as Partial<CloudConnection>),
      ),
    ).toBeNull();
  });
});

describe("how often it is read", () => {
  it("words the known intervals and falls back to hours", () => {
    expect(cadenceLabel(null)).toBe("Only when asked");
    expect(cadenceLabel(24)).toBe("Every day");
    expect(cadenceLabel(168)).toBe("Every week");
    // An interval set through the API that the dropdown does not offer.
    expect(cadenceLabel(2)).toBe("Every 2 hours");
  });

  it("names change detection beside the clock, not instead of it", () => {
    // Two mechanisms; a reader shown only one draws the wrong conclusion about
    // the other.
    expect(
      cadenceSummary(
        connection({ change_events_enabled: true } as Partial<CloudConnection>),
      ),
    ).toBe("on change · every day");
    expect(cadenceSummary(connection())).toBe("every day");
  });
});

describe("a subscription discovered since the last read", () => {
  const lastRead = "2026-08-30T00:00:00Z";

  it("is marked when it appeared after that read and has never been scanned", () => {
    expect(
      isNewSinceLastRead(
        subscription({ discovered_at: "2026-08-31T00:00:00Z", last_scan_at: null }),
        lastRead,
      ),
    ).toBe(true);
  });

  it("is not marked once something has read it", () => {
    expect(
      isNewSinceLastRead(
        subscription({
          discovered_at: "2026-08-31T00:00:00Z",
          last_scan_at: "2026-08-31T01:00:00Z",
        }),
        lastRead,
      ),
    ).toBe(false);
  });

  it("says nothing on a connection that has never been read at all", () => {
    // Everything would be "new", which is noise: the whole connection is new.
    expect(
      isNewSinceLastRead(
        subscription({ discovered_at: "2026-08-31T00:00:00Z", last_scan_at: null }),
        null,
      ),
    ).toBe(false);
  });
});

describe("what the status column says", () => {
  it("does not call a connection live when nothing is in scope", () => {
    expect(
      statusSummary(
        connection({
          is_ready_to_scan: false,
          subscriptions: [subscription({ in_scope: false, is_scannable: false })],
        } as Partial<CloudConnection>),
      ).label,
    ).toBe("Nothing in scope");
  });

  it("separates a connection still being set up from one that failed", () => {
    expect(
      statusSummary(
        connection({
          consent_status: "PENDING",
          rbac_verified_at: null,
          is_verified: false,
          is_ready_to_scan: false,
          status: "PENDING",
        } as Partial<CloudConnection>),
      ).label,
    ).toBe("Setting up");

    expect(
      statusSummary(
        connection({
          status: "ERROR",
          status_detail: "The reader role was removed.",
        } as Partial<CloudConnection>),
      ),
    ).toMatchObject({ label: "Needs attention", detail: "The reader role was removed." });
  });

  it("says what is doing the reading when it is live", () => {
    expect(
      statusSummary(
        connection({ change_events_enabled: true } as Partial<CloudConnection>),
      ),
    ).toMatchObject({ label: "Live", detail: "Listening for changes" });
  });
});
