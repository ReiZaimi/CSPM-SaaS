/**
 * Change-triggered scanning, and the one claim the toggle must not make.
 *
 * Turning it on opens CloudGuard's webhook and nothing else: creating the Event
 * Grid subscription is a write in the customer's tenant, and CloudGuard holds
 * no write permission anywhere. A control that read as "done" would leave a
 * customer believing they were monitored when nothing was ever going to arrive.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ChangeEventsControl } from "@/components/connections/ChangeEventsControl";
import { api } from "@/lib/api";
import type { ChangeEventSetup, CloudConnection } from "@/lib/types";

const connection = { id: "c1" } as CloudConnection;

function setup(overrides: Partial<ChangeEventSetup> = {}): ChangeEventSetup {
  return {
    enabled: false,
    webhook_url: "https://api.example.test/api/v1/events/azure/c1?token=t",
    pending_since: null,
    last_event_at: null,
    quiet_period_minutes: 3,
    minimum_interval_minutes: 30,
    commands: [],
    ...overrides,
  };
}

function mount(value: ChangeEventSetup) {
  vi.spyOn(api, "get").mockResolvedValue({ data: value, meta: {} });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const rendered = render(
    <QueryClientProvider client={client}>
      <ChangeEventsControl connection={connection} onError={() => {}} />
    </QueryClientProvider>,
  );
  return { ...rendered, client };
}

describe("the change-events control", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("says listening is off before it is turned on", async () => {
    mount(setup());

    await waitFor(() => expect(screen.getByText("Not listening")).toBeInTheDocument());
    expect(screen.getByRole("button", { name: "Turn on change detection" })).toBeInTheDocument();
  });

  it("says that turning it on wires nothing up on its own", async () => {
    // The whole point. Without this line the toggle claims work it did not do.
    mount(
      setup({
        enabled: true,
        commands: [{ subscription_id: "sub-1", command: "az eventgrid ..." }],
      }),
    );

    await waitFor(() => expect(screen.getByText("Listening for changes")).toBeInTheDocument());
    expect(screen.getByText(/cannot create that subscription for you/)).toBeInTheDocument();
  });

  it("shows the command in full, one per subscription", async () => {
    mount(
      setup({
        enabled: true,
        commands: [
          { subscription_id: "sub-1", command: "az eventgrid one" },
          { subscription_id: "sub-2", command: "az eventgrid two" },
        ],
      }),
    );

    await waitFor(() => expect(screen.getByText("az eventgrid one")).toBeInTheDocument());
    expect(screen.getByText("az eventgrid two")).toBeInTheDocument();
    expect(screen.getByText("sub-1")).toBeInTheDocument();
  });

  it("does not offer a toggle when there is nowhere to deliver", async () => {
    // Opening a webhook at an address that does not exist would hand over a
    // command whose endpoint answers nothing.
    mount(setup({ webhook_url: null }));

    await waitFor(() =>
      expect(
        screen.getByText("CloudGuard has no public address to receive deliveries"),
      ).toBeInTheDocument(),
    );
    expect(
      screen.queryByRole("button", { name: "Turn on change detection" }),
    ).not.toBeInTheDocument();
  });

  it("states the quiet period and the floor between change scans", async () => {
    mount(setup());

    await waitFor(() => expect(screen.getByText(/3 minutes of quiet/)).toBeInTheDocument());
    expect(screen.getByText(/at most once every 30 minutes/)).toBeInTheDocument();
  });

  it("says when a change is settling rather than looking idle", async () => {
    mount(setup({ enabled: true, pending_since: "2026-08-31T10:00:00Z" }));

    await waitFor(() =>
      expect(
        screen.getByText(/a scan starts once the environment is quiet/),
      ).toBeInTheDocument(),
    );
  });

  it("shows the commands as soon as the toggle is saved", async () => {
    // Written from the PATCH response rather than refetched: commands arriving
    // a request later read as the toggle not having taken.
    mount(setup());
    const patch = vi.spyOn(api, "patch").mockResolvedValue({
      data: setup({
        enabled: true,
        commands: [{ subscription_id: "sub-1", command: "az eventgrid one" }],
      }),
      meta: {},
    });

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Turn on change detection" })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Turn on change detection" }));

    await waitFor(() => expect(screen.getByText("az eventgrid one")).toBeInTheDocument());
    expect(patch).toHaveBeenCalledWith(
      "/api/v1/cloud-connections/c1/change-events",
      { enabled: true },
    );
  });

  it("refreshes the connection the panel beside it reads", async () => {
    // ``ReadCadencePanel`` renders "On change" from the connection, not from
    // this endpoint. Writing only this component's own cache left that panel
    // saying "Not listening" after a toggle that had worked, which is
    // indistinguishable from the button doing nothing.
    const { client } = mount(setup());
    const invalidate = vi.spyOn(client, "invalidateQueries");
    vi.spyOn(api, "patch").mockResolvedValue({
      data: setup({ enabled: true }),
      meta: {},
    });

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Turn on change detection" })).toBeInTheDocument(),
    );
    fireEvent.click(screen.getByRole("button", { name: "Turn on change detection" }));

    await waitFor(() =>
      expect(invalidate).toHaveBeenCalledWith({ queryKey: ["cloud-connections"] }),
    );
    expect(invalidate).toHaveBeenCalledWith({
      queryKey: ["cloud-connection", "c1"],
    });
  });
});
