import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ConnectPage } from "@/pages/Connect";
import { api } from "@/lib/api";
import type { CloudConnection } from "@/lib/types";

function mount(rows: CloudConnection[]) {
  vi.spyOn(api, "get").mockImplementation((path: string) => {
    if (path.startsWith("/api/v1/cloud-accounts/azure/permissions")) {
      return Promise.resolve({
        data: {
          graph_application_permissions: ["Directory.Read.All", "Policy.Read.All"],
          azure_rbac_role: "Reader",
          access_type: "read-only",
          writes_performed: "none",
        },
        meta: {},
      }) as never;
    }
    return Promise.resolve({ data: rows, meta: {} }) as never;
  });

  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <ConnectPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

function connection(overrides: Partial<CloudConnection> = {}): CloudConnection {
  return {
    id: "c1",
    provider: "azure",
    name: "new_architecture",
    scope_type: "TENANT_ROOT",
    scope_id: null,
    scope_path: null,
    role_version: "v2",
    tenant_id: "t1",
    service_principal_object_id: null,
    consent_status: "GRANTED",
    consented_at: "2026-08-14T00:00:00Z",
    rbac_verified_at: "2026-08-31T00:00:00Z",
    status: "ACTIVE",
    status_detail: null,
    last_discovery_at: null,
    scan_interval_hours: 24,
    created_at: "2026-08-01T00:00:00Z",
    is_verified: true,
    is_ready_to_scan: true,
    subscription_count: 1,
    subscriptions: [
      {
        id: "s1",
        subscription_id: "00000000-0000-0000-0000-000000000001",
        display_name: "prod-payments-weu",
        in_scope: true,
        status: "ACTIVE",
        discovered_at: "2026-08-14T00:00:00Z",
        last_scan_at: "2026-08-31T00:00:00Z",
        is_scannable: true,
      },
    ],
    consent_url: null,
    template_url: null,
    deploy_stalled: false,
    ...overrides,
  } as CloudConnection;
}

describe("the connections page", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("says what the next three minutes contain before asking for them", async () => {
    // Setup needs two grants and often two people. A lone button hides the one
    // fact that decides whether now is a good moment to start.
    mount([]);

    expect(await screen.findByText(/what the three minutes look like/i)).toBeInTheDocument();
    expect(
      screen.getByText(/a global administrator grants admin consent/i),
    ).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: /connect a cloud/i })[0]).toHaveAttribute(
      "href",
      "/connections/new",
    );
  });

  it("proves the read-only claim from the API rather than restating it", async () => {
    // A hardcoded list would be a second copy of the claim, free to drift from
    // the one the consent screen actually shows.
    mount([]);

    await userEvent.click(
      await screen.findByRole("button", { name: /read what cloudguard will do/i }),
    );

    expect(await screen.findByText("Directory.Read.All")).toBeInTheDocument();
    expect(screen.getByText(/Reader \(read-only\)/)).toBeInTheDocument();
  });

  it("puts every connection on one comparable line", async () => {
    mount([connection(), connection({ id: "c2", name: "sandbox" })]);

    // Column labels, so the numbers in each row are read as answers to the
    // same questions rather than as unlabelled figures.
    expect(await screen.findByText("Last read")).toBeInTheDocument();
    expect(screen.getByText("new_architecture")).toBeInTheDocument();
    expect(screen.getByText("sandbox")).toBeInTheDocument();
  });
});
