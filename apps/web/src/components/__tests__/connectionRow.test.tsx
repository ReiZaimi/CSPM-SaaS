import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ConnectionRow } from "@/components/connections/ConnectionRow";
import { api } from "@/lib/api";
import type { CloudConnection, DiscoveredSubscription } from "@/lib/types";

const minutesAgo = (minutes: number) =>
  new Date(Date.now() - minutes * 60_000).toISOString();

function subscription(
  overrides: Partial<DiscoveredSubscription> = {},
): DiscoveredSubscription {
  return {
    id: "s1",
    subscription_id: "00000000-0000-0000-0000-000000000001",
    display_name: "prod-payments-weu",
    in_scope: true,
    status: "ACTIVE",
    discovered_at: minutesAgo(60 * 24 * 20),
    last_scan_at: minutesAgo(12),
    is_scannable: true,
    ...overrides,
  } as DiscoveredSubscription;
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
    tenant_id: "8e482025-7ac9-4323-81e5-bc9fa528afd7",
    service_principal_object_id: null,
    consent_status: "GRANTED",
    consented_at: minutesAgo(60 * 24 * 18),
    rbac_verified_at: minutesAgo(60 * 24),
    status: "ACTIVE",
    status_detail: null,
    last_discovery_at: minutesAgo(30),
    scan_interval_hours: 24,
    created_at: "2026-01-01T00:00:00Z",
    is_verified: true,
    is_ready_to_scan: true,
    subscription_count: 1,
    subscriptions: [subscription()],
    consent_url: null,
    template_url: null,
    deploy_stalled: false,
    change_events_enabled: true,
    last_change_event_at: minutesAgo(240),
    ...overrides,
  } as CloudConnection;
}

function mount(value: CloudConnection) {
  vi.spyOn(api, "get").mockResolvedValue({ data: value, meta: {} });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <ConnectionRow connection={value} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("a connection row", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("answers when and how often without being opened", () => {
    // The question this page is skimmed for. An absolute timestamp would make
    // the reader do the subtraction against a clock they cannot see.
    mount(connection());

    expect(screen.getByText("12 minutes ago")).toBeInTheDocument();
    expect(screen.getByText(/on change · every day/i)).toBeInTheDocument();
    expect(screen.getByText("Live")).toBeInTheDocument();
  });

  it("does not call a connection live when nothing beneath it is ticked", () => {
    // `status` is ACTIVE either way; the reader is being told whether anything
    // is actually read.
    mount(
      connection({
        is_ready_to_scan: false,
        subscriptions: [subscription({ in_scope: false, is_scannable: false })],
      } as Partial<CloudConnection>),
    );

    expect(screen.getByText(/nothing in scope/i)).toBeInTheDocument();
  });

  it("offers the step a half-finished connection stopped on, not a scan", () => {
    mount(
      connection({
        consent_status: "PENDING",
        rbac_verified_at: null,
        is_verified: false,
        is_ready_to_scan: false,
        status: "PENDING",
        status_detail: "Waiting for an administrator to consent.",
        subscriptions: [],
      } as Partial<CloudConnection>),
    );

    expect(screen.getByRole("link", { name: /continue setup/i })).toHaveAttribute(
      "href",
      "/connections/c1/setup",
    );
    expect(screen.queryByRole("button", { name: /scan now/i })).not.toBeInTheDocument();
  });

  it("states the access it holds, and the access it does not", async () => {
    mount(connection());

    await userEvent.click(screen.getByRole("button", { name: /show this connection/i }));

    // The product's central claim about itself, beside the grants it did get.
    expect(await screen.findByText("None, by design")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /re-check access/i })).toBeInTheDocument();
  });

  it("says when a subscription was taken out of scope, not just that it was", async () => {
    // A boolean cannot distinguish a decision made last week from one nobody
    // remembers making.
    mount(
      connection({
        subscriptions: [
          subscription(),
          subscription({
            id: "s2",
            subscription_id: "00000000-0000-0000-0000-000000000002",
            display_name: "sandbox-scratch",
            in_scope: false,
            is_scannable: false,
            scope_changed_at: "2026-08-20T09:00:00Z",
          }),
        ],
      } as Partial<CloudConnection>),
    );

    await userEvent.click(screen.getByRole("button", { name: /show this connection/i }));

    expect(await screen.findByText(/excluded by you/)).toHaveTextContent("Aug 20, 2026");
  });

  it("marks a subscription discovered since the last read", async () => {
    // The case the product exists to prevent: an environment created last
    // Tuesday that nothing has ever scanned, sitting beside twelve that are
    // green.
    mount(
      connection({
        subscriptions: [
          subscription(),
          subscription({
            id: "s3",
            subscription_id: "00000000-0000-0000-0000-000000000003",
            display_name: "prod-data-neu",
            discovered_at: minutesAgo(5),
            last_scan_at: null,
          }),
        ],
      } as Partial<CloudConnection>),
    );

    await userEvent.click(screen.getByRole("button", { name: /show this connection/i }));

    expect(await screen.findByText("new since last read")).toBeInTheDocument();
  });

  it("re-checks access by asking Azure, not by re-reading the same row", async () => {
    // Reported from a live tenant: the customer redeployed the role and the
    // panel went on saying "behind". `refetch()` was the whole of the button,
    // and the GET only probes a connection that is not verified yet -- so on a
    // working connection it repainted the answer it already had.
    const behind = connection({
      role_version: "v2",
      role_required_version: "v5",
      role_upgrade_available: true,
      degraded_categories: ["database", "secrets"],
      template_url: "https://portal.azure.com/#create/Microsoft.Template/uri/x",
    } as Partial<CloudConnection>);
    const post = vi.spyOn(api, "post").mockResolvedValue({
      data: {
        ...behind,
        role_version: "v5",
        role_upgrade_available: false,
        degraded_categories: [],
      },
      meta: {},
    } as never);
    mount(behind);

    await userEvent.click(screen.getByRole("button", { name: /show this connection/i }));
    expect(
      await screen.findByText(/some checks cannot run until the role is redeployed/i),
    ).toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: /re-check access/i }));

    expect(post).toHaveBeenCalledWith("/api/v1/cloud-connections/c1/recheck");
    // And the panel is repainted from what Azure said, which is the half the
    // customer could not get to at all.
    await waitFor(() =>
      expect(
        screen.queryByText(/some checks cannot run until the role is redeployed/i),
      ).not.toBeInTheDocument(),
    );
    expect(screen.getByText(/v5, verified/i)).toBeInTheDocument();
  });

  it("asks about removal in a dialog, without moving the rest of the row", async () => {
    // The confirmation is long -- three revocation commands, why CloudGuard
    // cannot run them, and a probe -- and expanded in place it pushed the rest
    // of the connection off screen while somebody decided whether to delete an
    // environment.
    vi.spyOn(api, "get").mockImplementation((path: string) =>
      Promise.resolve(
        path.endsWith("/revocation")
          ? {
              data: {
                principal_id: "sp-1",
                scope_path: "/subscriptions/x",
                why_manual: "CloudGuard holds read-only access.",
                steps: [
                  {
                    title: "Remove the scanner role assignment",
                    detail: "Ends CloudGuard's ability to read Azure resources.",
                    command: "az role assignment delete --assignee sp-1",
                  },
                ],
              },
              meta: {},
            }
          : { data: connection(), meta: {} },
      ) as never,
    );
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <ConnectionRow connection={connection()} />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    await userEvent.click(screen.getByRole("button", { name: /show this connection/i }));
    // Nothing is asked for until the reader asks: a page of six connections
    // must not fetch six sets of revocation commands nobody wanted to see.
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();

    await userEvent.click(
      screen.getByRole("button", { name: /remove connection/i }),
    );

    const dialog = await screen.findByRole("dialog");
    expect(dialog).toHaveTextContent(/remove this connection/i);
    expect(await screen.findByText(/az role assignment delete/)).toBeInTheDocument();
    // The row is still there behind it rather than replaced -- and inert, which
    // is what a modal is for: the access panel's text is in the document, and
    // its controls are out of the accessibility tree while the dialog is open.
    expect(screen.getByText("None, by design")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /re-check access/i })).toBeNull();
  });

  it("closes on the safe answer, and never on a stray keypress", async () => {
    // Escape and "Keep it" are the same action, and the destructive button is
    // not the one either of them reaches.
    vi.spyOn(api, "get").mockResolvedValue({ data: connection(), meta: {} } as never);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <ConnectionRow connection={connection()} />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    await userEvent.click(screen.getByRole("button", { name: /show this connection/i }));
    await userEvent.click(
      screen.getByRole("button", { name: /remove connection/i }),
    );
    await screen.findByRole("dialog");

    await userEvent.keyboard("{Escape}");

    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
  });

  it("scans the connection through one of its scannable subscriptions", async () => {
    // A scan is connection-scoped server-side: the worker resolves what sits
    // beneath, so one scannable subscription names the target for all of them.
    const post = vi
      .spyOn(api, "post")
      .mockResolvedValue({ data: { id: "scan-1" }, meta: {} } as never);
    mount(connection());

    await userEvent.click(screen.getByRole("button", { name: /scan now/i }));

    expect(post).toHaveBeenCalledWith("/api/v1/scans", { cloud_account_id: "s1" });
  });
});
