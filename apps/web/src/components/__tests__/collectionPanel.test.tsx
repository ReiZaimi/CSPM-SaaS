/**
 * What rested on a reading — the citation chain walked from the evidence end.
 *
 * The finding page asks where its evidence came from. Somebody looking at a
 * listing on a scan has the mirror question, and the number answering it has to
 * survive being clicked: it links to the reading, not to its key, because a key
 * spans every subscription and every scan that ever read it.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { CollectionPanel } from "@/components/scans/CollectionPanel";

const READING = {
  subscription: "Subscription 1",
  cloud_account_id: "sub-1",
  task: "storage_accounts",
  category: "storage",
  outcome: "COMPLETE",
  detail: null,
  item_count: 41,
  evidence_id: "ev-1",
  finding_count: 3,
  collected_at: new Date(Date.now() - 2 * 3600 * 1000).toISOString(),
  endpoints: [
    {
      path: "https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Storage/storageAccounts",
      api_version: "2023-01-01",
    },
  ],
};

function mount(tasks: object[], counts: Record<string, number> = {}) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        data: {
          tasks,
          total: tasks.length,
          complete: tasks.length,
          partial: 0,
          failed: 0,
          skipped: 0,
          degraded_categories: [],
          ...counts,
        },
        error: null,
        meta: {},
      }),
    })) as unknown as typeof fetch,
  );

  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <CollectionPanel scanId="scan-1" />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("the collection panel", () => {
  beforeEach(() => vi.restoreAllMocks());
  afterEach(() => vi.unstubAllGlobals());

  it("links a reading to exactly the findings that rest on it", async () => {
    mount([READING]);

    const link = await screen.findByRole("link", {
      name: "3 findings rest on this",
    });
    // The reading, not its key. A key would gather every subscription's copy
    // and the count would stop matching what the click returns.
    expect(link).toHaveAttribute(
      "href",
      "/findings?evidence_id=ev-1&status=all",
    );
  });

  it("carries status=all, so a reading behind a resolved finding still leads somewhere", async () => {
    // The findings list defaults to OPEN. A reading whose findings have since
    // been fixed would otherwise offer a count that lands on an empty table.
    mount([READING]);

    const link = await screen.findByRole("link", { name: /rest on this/ });
    expect(link.getAttribute("href")).toContain("status=all");
  });

  it("says a failed reading supported nothing, and does not link it", async () => {
    mount([
      {
        ...READING,
        outcome: "FAILED",
        item_count: 0,
        finding_count: 0,
        detail: "Denied. Grant Reader.",
      },
    ]);

    expect(
      await screen.findByText(/no findings rest on this/),
    ).toBeInTheDocument();
    // Nothing to go to. A failed reading's rules degraded to UNKNOWN and never
    // became findings, which is the engine working rather than a gap.
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });

  it("names the call and the contract it was made under", async () => {
    mount([READING]);

    expect(await screen.findByText(/2023-01-01/)).toBeInTheDocument();
    expect(screen.getByText(/Microsoft.Storage\/storageAccounts/)).toBeInTheDocument();
  });

  it("says nothing about a contract for a reading taken before it was recorded", async () => {
    // `[]` is CloudGuard's history, not a claim the task called nothing. The
    // line is omitted rather than rendered empty.
    mount([{ ...READING, endpoints: [] }]);

    expect(await screen.findByText(/rest on this/)).toBeInTheDocument();
    expect(screen.queryByText(/api-version/)).not.toBeInTheDocument();
  });

  it("says how long ago the provider was read", async () => {
    mount([READING]);

    expect(await screen.findByText("2 hours ago")).toBeInTheDocument();
  });

  it("uses the singular for one finding", async () => {
    mount([{ ...READING, finding_count: 1 }]);

    expect(
      await screen.findByRole("link", { name: "1 finding rests on this" }),
    ).toBeInTheDocument();
  });

  it("says what an unread reading cost, not only that it happened", async () => {
    /** The invariant was stated for PARTIAL and nowhere else, so a scan where
     * storage failed outright showed a badge, a count, and no word about the
     * consequence -- leaving "could not read" free to be read as "nothing to
     * report", which is the one inference this product exists to prevent. */
    mount([{ ...READING, outcome: "FAILED", finding_count: 0 }], {
      complete: 0,
      failed: 1,
    });

    await waitFor(() =>
      expect(
        screen.getByText(/report unknown, never passed/i),
      ).toBeInTheDocument(),
    );
  });

  it("says it for a skipped reading too", async () => {
    /** Never attempted and attempted-and-failed are different causes with the
     * same consequence, and the consequence is what this line is about. */
    mount([{ ...READING, outcome: "SKIPPED", finding_count: 0 }], {
      complete: 0,
      skipped: 1,
    });

    await waitFor(() =>
      expect(
        screen.getByText(/report unknown, never passed/i),
      ).toBeInTheDocument(),
    );
  });

  it("keeps the two sentences apart", async () => {
    /** An incomplete listing cannot support a pass; an absent one supports
     * nothing at all. One vaguer line covering both would say less about
     * each. */
    mount([{ ...READING, outcome: "PARTIAL" }], { complete: 0, partial: 1 });

    await waitFor(() =>
      expect(screen.getByText(/cannot support a pass/i)).toBeInTheDocument(),
    );
    expect(
      screen.queryByText(/report unknown, never passed/i),
    ).not.toBeInTheDocument();
  });

  it("says neither when everything was read", async () => {
    /** A panel that warns on a clean scan is one nobody reads on a dirty
     * one. */
    mount([READING]);

    await waitFor(() => expect(screen.getByText("Read in full")).toBeInTheDocument());
    expect(screen.queryByText(/cannot support a pass/i)).not.toBeInTheDocument();
    expect(
      screen.queryByText(/report unknown, never passed/i),
    ).not.toBeInTheDocument();
  });

});
