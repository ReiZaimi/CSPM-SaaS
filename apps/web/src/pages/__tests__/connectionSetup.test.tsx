import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ConnectionSetupPage } from "@/pages/ConnectionSetup";
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
    tenant_id: null,
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
    consent_url: "https://login.microsoftonline.com/consent",
    template_url: null,
    deploy_stalled: false,
    ...overrides,
  } as CloudConnection;
}

function mount(value: CloudConnection | null, path = "/connections/c1/setup") {
  if (value) vi.spyOn(api, "get").mockResolvedValue({ data: value, meta: {} });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/connections/new" element={<ConnectionSetupPage />} />
          <Route
            path="/connections/:connectionId/setup"
            element={<ConnectionSetupPage />}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("the connection wizard", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("asks for a name and a scope before anything is created", async () => {
    mount(null, "/connections/new");

    expect(await screen.findByLabelText(/connection name/i)).toBeInTheDocument();
  });

  it("gives the consent link to somebody who cannot grant it themselves", async () => {
    // The step most often looked at by a person who is not a Global
    // Administrator. Handing the link on is a way of finishing it, not of
    // giving up on it.
    mount(connection());

    await userEvent.click(
      await screen.findByRole("button", { name: /not a global administrator/i }),
    );

    // The link, and the sentence that explains what is being approved: a bare
    // URL in a chat window is the request an administrator should refuse.
    expect(
      screen.getByText(/approve read-only access for CloudGuard/i),
    ).toHaveTextContent("https://login.microsoftonline.com/consent");
    expect(screen.getByRole("button", { name: /copy the message/i })).toBeInTheDocument();
  });

  it("shows a failed consent against the step it failed on", async () => {
    mount(
      connection(),
      "/connections/c1/setup?consent_error=AADSTS650056%3A+Misconfigured+application",
    );

    expect(await screen.findByText(/AADSTS650056/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /start consent again/i })).toBeInTheDocument();
  });

  it("names the three causes when a deployment stops arriving", async () => {
    // Past the point where waiting explains it. A spinner here would keep
    // implying progress and give nobody anything to check.
    mount(
      connection({
        consent_status: "GRANTED",
        template_url: "https://portal.azure.com/#create/template",
        deploy_stalled: true,
        status_detail: "No read access has appeared since the consent was granted.",
      } as Partial<CloudConnection>),
    );

    expect(await screen.findByText(/has not propagated yet/i)).toBeInTheDocument();
    // Worded for the scope this connection actually covers, not generically.
    expect(screen.getByText(/root management group/i)).toBeInTheDocument();
    expect(screen.getByText(/Contributor can deploy a template/i)).toBeInTheDocument();
  });

  it("ends on a scan rather than on a green tick", async () => {
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
            id: "s1",
            subscription_id: "00000000-0000-0000-0000-000000000001",
            display_name: "Production",
            in_scope: true,
          },
        ],
      } as Partial<CloudConnection>),
    );

    await waitFor(() =>
      expect(screen.getByRole("link", { name: /run a scan/i })).toHaveAttribute(
        "href",
        "/scans",
      ),
    );
  });

  it("lets a waiting step be left without abandoning it", async () => {
    // Both grants are somebody else's to give. A wizard that can only be
    // finished or cancelled makes the customer sit on a spinner for a
    // colleague who is in a meeting.
    mount(connection());

    expect(await screen.findByRole("button", { name: /finish later/i })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /cancel setup/i })).toBeInTheDocument();
  });
});
