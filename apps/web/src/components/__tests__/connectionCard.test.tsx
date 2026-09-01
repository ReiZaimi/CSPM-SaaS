import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ConnectionCard } from "@/components/connections/ConnectionCard";
import { api } from "@/lib/api";
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
    tenant_id: "t1",
    service_principal_object_id: null,
    consent_status: "PENDING",
    consented_at: null,
    rbac_verified_at: null,
    status: "PENDING",
    status_detail: "Waiting for an administrator to consent.",
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

function mount(value: CloudConnection) {
  vi.spyOn(api, "get").mockResolvedValue({ data: value, meta: {} });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <ConnectionCard connection={value} defaultExpanded={false} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("a connection card", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("explains a dead end rather than showing three grey ticks", () => {
    // Not consented and no link to offer: the deployment cannot start a
    // consent flow, and this used to render nothing at all.
    mount(connection({ consent_url: null }));

    expect(screen.getByText(/Waiting for an administrator/)).toBeInTheDocument();
  });

  it("says a verified connection with nothing under it found no subscriptions", () => {
    // Three green ticks and an empty card was the previous answer.
    mount(
      connection({
        consent_status: "GRANTED",
        rbac_verified_at: "2026-01-01T00:00:00Z",
        is_verified: true,
        status: "ACTIVE",
      }),
    );

    expect(screen.getByRole("button", { name: /look/i })).toBeInTheDocument();
  });

  it("points at the next step once there is something in scope", () => {
    // The flow used to end on a green tick and leave the customer to guess
    // that scanning lives on another page.
    mount(
      connection({
        consent_status: "GRANTED",
        rbac_verified_at: "2026-01-01T00:00:00Z",
        is_verified: true,
        is_ready_to_scan: true,
        status: "ACTIVE",
        subscription_count: 1,
        subscriptions: [
          {
            id: "sub-row-1",
            subscription_id: "00000000-0000-0000-0000-000000000001",
            display_name: "Production",
            in_scope: true,
          },
        ],
      } as Partial<CloudConnection>),
    );

    expect(screen.getByRole("link", { name: /run a scan/i })).toHaveAttribute(
      "href",
      "/scans",
    );
  });

  it("says where automatic scanning went rather than dropping it silently", () => {
    // The schedule used to live on this card. Somebody who set it here once
    // should be told it moved, not left to conclude the feature was removed.
    mount(
      connection({
        consent_status: "GRANTED",
        rbac_verified_at: "2026-01-01T00:00:00Z",
        is_verified: true,
        is_ready_to_scan: true,
        status: "ACTIVE",
        subscription_count: 1,
        scan_interval_hours: null,
        subscriptions: [
          {
            id: "sub-row-1",
            subscription_id: "00000000-0000-0000-0000-000000000001",
            display_name: "Production",
            in_scope: true,
          },
        ],
      } as Partial<CloudConnection>),
    );

    expect(screen.getByText(/Automatic scanning is set on the/)).toBeInTheDocument();
    // And it states the current cadence, so the pointer is also an answer.
    expect(
      screen.getByText(/read only when somebody asks for it/),
    ).toBeInTheDocument();
  });

  it("lets a subscription be taken out of scope", () => {
    mount(
      connection({
        consent_status: "GRANTED",
        rbac_verified_at: "2026-01-01T00:00:00Z",
        is_verified: true,
        status: "ACTIVE",
        subscription_count: 1,
        subscriptions: [
          {
            id: "sub-row-1",
            subscription_id: "00000000-0000-0000-0000-000000000001",
            display_name: "Production",
            in_scope: true,
          },
        ],
      } as Partial<CloudConnection>),
    );

    // Named, not just a checkbox: an unlabelled box in a list of subscriptions
    // is unreadable to a screen reader.
    expect(screen.getByLabelText(/Production/)).toBeInTheDocument();
  });
});
