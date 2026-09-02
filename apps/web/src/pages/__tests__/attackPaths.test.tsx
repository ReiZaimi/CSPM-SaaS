/**
 * The attack paths page.
 *
 * Two things are worth testing here and neither is that a list renders.
 *
 * The first is that an empty answer says *which* nothing it found. "No attack
 * paths" reads as reassurance, and in two of the three cases it is the
 * opposite: nothing classified as sensitive means CloudGuard does not know what
 * would cost the customer anything, which is a gap in what it was told rather
 * than a clean environment.
 *
 * The second is that the route is shown rather than just its endpoints. Naming
 * the links is the whole difference between an alarm and something somebody can
 * go and cut.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AttackPathsPage } from "../AttackPaths";
import { api } from "@/lib/api";
import type { AttackPath, ChokePoint } from "@/lib/types";

const PATH: AttackPath = {
  entry: {
    id: "/subscriptions/s/resourceGroups/prod/providers/vm/jump-01",
    name: "jump-01",
    resource_type: "virtual_machine",
    public_exposure: "CRITICAL",
  },
  target: {
    id: "/subscriptions/s/resourceGroups/prod/providers/storage/customerdata",
    name: "customerdata",
    resource_type: "storage_account",
    data_sensitivity: "HIGH",
  },
  hops: 4,
  steps: [
    {
      source: "jump-01",
      source_id: "vm",
      relationship: "has_identity",
      target: "mi-jump-01",
      target_id: "mi",
      description: "jump-01 runs as mi-jump-01",
    },
    {
      source: "mi-jump-01",
      source_id: "mi",
      relationship: "grants_role",
      target: "sub-1",
      target_id: "sub",
      description: "mi-jump-01 can act over sub-1",
    },
    {
      source: "sub-1",
      source_id: "sub",
      relationship: "contains",
      target: "prod",
      target_id: "rg",
      description: "sub-1 contains prod",
    },
    {
      source: "prod",
      source_id: "rg",
      relationship: "contains",
      target: "customerdata",
      target_id: "storage",
      description: "prod contains customerdata",
    },
  ],
  cheapest_break: {
    description: "jump-01 runs as mi-jump-01",
    relationship: "has_identity",
    source_id: "vm",
    target_id: "mi",
  },
};

function mount(
  paths: AttackPath[],
  meta: Record<string, number>,
  chokes: ChokePoint[] = [],
) {
  vi.spyOn(api, "get").mockImplementation((url: string) =>
    Promise.resolve(
      url.includes("/choke-points")
        ? { data: chokes, meta: { total_routes: meta.total } }
        : { data: paths, meta },
    ) as never,
  );
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <AttackPathsPage />
    </QueryClientProvider>,
  );
}

describe("AttackPathsPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("shows the route, not just where it starts and ends", async () => {
    mount([PATH], { total: 1, entry_points: 1, sensitive_targets: 1 });

    // Every hop, in order. A card naming only the endpoints would be an alarm.
    //
    // The first hop is asserted with getAllByText because it is also the
    // severable one, so it deliberately appears twice — once in the route and
    // once as the recommended fix. The next test is about that; here it would
    // just make getByText throw.
    await waitFor(() =>
      expect(screen.getAllByText("jump-01 runs as mi-jump-01").length).toBeGreaterThan(0),
    );
    expect(screen.getByText("mi-jump-01 can act over sub-1")).toBeInTheDocument();
    expect(screen.getByText("sub-1 contains prod")).toBeInTheDocument();
    expect(screen.getByText("prod contains customerdata")).toBeInTheDocument();
  });

  it("names the one link that severs the route", async () => {
    mount([PATH], { total: 1, entry_points: 1, sensitive_targets: 1 });

    await waitFor(() => expect(screen.getByText("Cut it here")).toBeInTheDocument());
    // Appears twice on purpose: once in the route so the customer can see which
    // hop it is, once as the recommended action.
    expect(screen.getAllByText("jump-01 runs as mi-jump-01")).toHaveLength(2);
  });

  it("distinguishes a clean environment from an unscanned one", async () => {
    mount([], { total: 0, entry_points: 0, sensitive_targets: 0 });

    await waitFor(() =>
      expect(screen.getByText("No scan has run yet")).toBeInTheDocument(),
    );
  });

  it("does not call an unclassified environment safe", async () => {
    // The case that matters most. CloudGuard found exposed assets and nothing
    // it could call sensitive, so it does not know what would cost the customer
    // anything — and saying "no attack paths" here would be reassurance it has
    // not earned.
    mount([], { total: 0, entry_points: 3, sensitive_targets: 0 });

    await waitFor(() =>
      expect(
        screen.getByText("Nothing has been classified as sensitive"),
      ).toBeInTheDocument(),
    );
  });

  it("says plainly when nothing is exposed", async () => {
    mount([], { total: 0, entry_points: 0, sensitive_targets: 4 });

    await waitFor(() =>
      expect(screen.getByText("Nothing is reachable from the internet")).toBeInTheDocument(),
    );
  });

  it("reports a genuinely clean result as clean", async () => {
    // Exposed assets exist, sensitive assets exist, and no route joins them.
    // This is the one case where an empty answer is good news.
    mount([], { total: 0, entry_points: 2, sensitive_targets: 3 });

    await waitFor(() =>
      expect(
        screen.getByText("Nothing exposed can reach anything sensitive"),
      ).toBeInTheDocument(),
    );
  });

  it("leads with the one change that closes the most routes", async () => {
    // The list ranks routes, which is the right order for reading them and the
    // wrong one for acting: fifty routes are fifty things to read, and one role
    // assignment holding them up is one thing to do.
    mount([PATH], { total: 4, entry_points: 2, sensitive_targets: 2 }, [
      {
        description: "mi-jump-01 can act over sub-1",
        relationship: "grants_role",
        source: { id: "mi", name: "mi-jump-01", resource_type: "service_principal" },
        target: { id: "sub", name: "sub-1", resource_type: "subscription" },
        severs: 4,
        on_routes: 4,
        total_routes: 4,
        closes: [
          { entry: "jump-01", target: "customerdata", hops: 4, data_sensitivity: "HIGH" },
        ],
      },
    ]);

    const panel = (
      await screen.findByText("The changes that close the most")
    ).closest("[data-slot='card']") as HTMLElement;

    // Scoped: the route list below repeats the same link, deliberately, so the
    // reader can see which hop it is.
    expect(within(panel).getByText("mi-jump-01 can act over sub-1")).toBeInTheDocument();
    expect(within(panel).getByText("4")).toBeInTheDocument();
    expect(within(panel).getByText(/of 4 routes close/)).toBeInTheDocument();
    // Named, not just counted: the count is a claim and these are its working.
    expect(within(panel).getByText("jump-01 → customerdata")).toBeInTheDocument();
  });

  it("says when a link sits on more routes than it closes", async () => {
    // A customer told four routes close who then sees two remain stops
    // believing the next number too.
    mount([PATH], { total: 4, entry_points: 2, sensitive_targets: 2 }, [
      {
        description: "mi-jump-01 can act over sub-1",
        relationship: "grants_role",
        source: { id: "mi", name: "mi-jump-01", resource_type: "service_principal" },
        target: { id: "sub", name: "sub-1", resource_type: "subscription" },
        severs: 2,
        on_routes: 4,
        total_routes: 4,
        closes: [
          { entry: "web-02", target: "customerdata", hops: 3, data_sensitivity: "HIGH" },
        ],
      },
    ]);

    await waitFor(() =>
      expect(screen.getByText(/another way round/)).toBeInTheDocument(),
    );
  });

  it("says nothing about cutting when there is nothing to cut", async () => {
    mount([], { total: 0, entry_points: 3, sensitive_targets: 0 });

    await waitFor(() =>
      expect(
        screen.getByText("Nothing has been classified as sensitive"),
      ).toBeInTheDocument(),
    );
    expect(
      screen.queryByText("The changes that close the most"),
    ).not.toBeInTheDocument();
  });
});
