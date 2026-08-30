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
import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AttackPathsPage } from "../AttackPaths";
import { api } from "@/lib/api";
import type { AttackPath } from "@/lib/types";

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

function mount(paths: AttackPath[], meta: Record<string, number>) {
  vi.spyOn(api, "get").mockResolvedValue({ data: paths, meta });
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
});
