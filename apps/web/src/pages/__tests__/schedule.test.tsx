/**
 * The automatic-scanning control.
 *
 * A security report ages the moment it is written, and until scheduling
 * existed every scan was a button press — a customer who connected Azure,
 * scanned once and got on with their week had a report describing an
 * environment that had moved on.
 *
 * What is worth testing here is not that a dropdown renders. It is that the
 * control cannot silently turn scheduling *off*, and that it says which state
 * it is in without the customer having to open the dropdown to find out.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ScheduleControl } from "../Connect";
import type { CloudConnection } from "@/lib/types";
import { api } from "@/lib/api";

function connection(overrides: Partial<CloudConnection> = {}): CloudConnection {
  return {
    id: "c1",
    provider: "azure",
    name: "production",
    scope_type: "TENANT_ROOT",
    scope_id: null,
    scope_path: null,
    role_version: "v1",
    tenant_id: "t1",
    service_principal_object_id: null,
    consent_status: "GRANTED",
    consented_at: null,
    rbac_verified_at: "2026-01-01T00:00:00Z",
    status: "ACTIVE",
    status_detail: null,
    last_discovery_at: null,
    scan_interval_hours: null,
    created_at: "2026-01-01T00:00:00Z",
    is_verified: true,
    is_ready_to_scan: true,
    subscription_count: 1,
    subscriptions: [],
    consent_url: null,
    template_url: null,
    deploy_stalled: false,
    ...overrides,
  } as CloudConnection;
}

function mount(value: CloudConnection) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <ScheduleControl connection={value} onError={() => {}} />
    </QueryClientProvider>,
  );
}

describe("ScheduleControl", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("says scanning is manual when no interval is set", () => {
    mount(connection());
    expect(screen.getByText("Manual scanning only")).toBeInTheDocument();
  });

  it("says scanning is automatic once an interval is set", () => {
    mount(connection({ scan_interval_hours: 24 }));
    expect(screen.getByText("Scanning automatically")).toBeInTheDocument();
  });

  it("sends the chosen interval in hours", async () => {
    const patch = vi
      .spyOn(api, "patch")
      .mockResolvedValue({ data: connection(), meta: {} });

    mount(connection());
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "24" } });

    await waitFor(() =>
      expect(patch).toHaveBeenCalledWith(
        "/api/v1/cloud-connections/c1/schedule",
        { scan_interval_hours: 24 },
      ),
    );
  });

  it("sends null rather than zero when scheduling is turned off", async () => {
    // Zero would be rejected by the API's lower bound, and the customer would
    // be told their choice was invalid for choosing the one option that always
    // is.
    const patch = vi
      .spyOn(api, "patch")
      .mockResolvedValue({ data: connection(), meta: {} });

    mount(connection({ scan_interval_hours: 24 }));
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "" } });

    await waitFor(() =>
      expect(patch).toHaveBeenCalledWith(
        "/api/v1/cloud-connections/c1/schedule",
        { scan_interval_hours: null },
      ),
    );
  });

  it("keeps an interval the dropdown does not offer", () => {
    // Set through the API, or offered by an older build. Dropping it back to
    // "manual" would turn scheduled scanning off for somebody who never asked
    // — a silent downgrade of the thing they switched on.
    mount(connection({ scan_interval_hours: 12 }));

    const select = screen.getByRole("combobox") as HTMLSelectElement;
    expect(select.value).toBe("12");
    expect(screen.getByText("Scanning automatically")).toBeInTheDocument();
  });

  it("confirms that a change was saved", async () => {
    vi.spyOn(api, "patch").mockResolvedValue({ data: connection(), meta: {} });

    mount(connection());
    fireEvent.change(screen.getByRole("combobox"), { target: { value: "168" } });

    // There is no Save button, so without this the control writes with no
    // evidence it wrote at all.
    await waitFor(() => expect(screen.getByText("Saved")).toBeInTheDocument());
  });
});
