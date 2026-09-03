/**
 * The inventory's two readings.
 *
 * The list is a queue: what is wrong, worst first. The tree is the estate's
 * shape — subscription, then resource group — which is the reading that leads
 * to an owner, because a resource group usually has one.
 *
 * The counts on the tree come from the server over the whole estate rather
 * than from a page of the list. A tree assembled in the browser from fifty
 * rows would show a resource group twice, once on each page its assets
 * straddled, with a fraction of its findings each time.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { AssetsPage } from "@/pages/Assets";

const HIERARCHY = [
  {
    id: "sub-1",
    name: "Production",
    kind: "SUBSCRIPTION",
    asset_count: 60,
    open_findings: 9,
    groups: [
      { name: "prod-rg", asset_count: 40, open_findings: 9 },
      { name: null, asset_count: 20, open_findings: 0 },
    ],
  },
  {
    id: "directory",
    name: "Directory",
    kind: "DIRECTORY",
    asset_count: 12,
    open_findings: 0,
    groups: [{ name: null, asset_count: 12, open_findings: 0 }],
  },
];

const ASSET: Record<string, unknown> = {
  id: "asset-1",
  name: "payroll",
  provider_resource_id:
    "/subscriptions/sub-1/resourceGroups/prod-rg/providers/Microsoft.Storage/storageAccounts/payroll",
  resource_type: "STORAGE_ACCOUNT",
  region: "westeurope",
  environment: "PRODUCTION",
  criticality: "HIGH",
  data_sensitivity: "HIGH",
  public_exposure: "LOW",
  open_findings: 3,
  first_seen_at: "2026-08-01T00:00:00Z",
  last_seen_at: "2026-08-30T00:00:00Z",
};

const UNCHECKED = {
  ...ASSET,
  id: "asset-2",
  name: "checkout-api",
  provider_resource_id:
    "/subscriptions/sub-1/resourceGroups/prod-rg/providers/Microsoft.Web/sites/checkout-api",
  resource_type: "unknown",
  azure_type: "Microsoft.Web/sites",
  public_exposure: "UNKNOWN",
  open_findings: 0,
};

let requested: string[] = [];

function mount(
  assets: object[] = [ASSET],
  meta: Record<string, number> = { total: 40 },
) {
  requested = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      requested.push(url);
      const data = url.includes("/assets/hierarchy") ? HIERARCHY : assets;
      return {
        ok: true,
        status: 200,
        json: async () => ({ data, error: null, meta }),
      } as Response;
    }),
  );

  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/assets"]}>
        <AssetsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("the assets page", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("lays the estate out as subscriptions and their groups", async () => {
    mount();

    fireEvent.click(screen.getByRole("button", { name: /Hierarchy/ }));

    expect(await screen.findByText("Production")).toBeInTheDocument();
    // Counted over the estate, not over a page of it.
    expect(screen.getByText("60 assets")).toBeInTheDocument();
    // Twice: the subscription's nine, and the group inside it they all come
    // from — which is the point of the level.
    expect(screen.getAllByText("9 open findings")).toHaveLength(2);
    // A subscription with something wrong opens itself, so the reader does not
    // click to discover what the page already knew.
    expect(await screen.findByText("prod-rg")).toBeInTheDocument();
  });

  it("asks for a group's assets only when the group is opened", async () => {
    mount();

    fireEvent.click(screen.getByRole("button", { name: /Hierarchy/ }));
    await screen.findByText("prod-rg");

    expect(requested.some((url) => url.includes("resource_group="))).toBe(false);

    fireEvent.click(screen.getByRole("button", { name: /prod-rg/ }));

    expect(await screen.findByText("payroll")).toBeInTheDocument();
    expect(
      requested.some(
        (url) =>
          url.includes("subscription_id=sub-1") &&
          url.includes("resource_group=prod-rg"),
      ),
    ).toBe(true);
  });

  it("names assets that sit in no group as what they are", async () => {
    // Not "Ungrouped", which reads as somebody's tagging oversight rather than
    // as where the asset actually is.
    mount();

    fireEvent.click(screen.getByRole("button", { name: /Hierarchy/ }));

    expect(
      await screen.findByText("Directly in the subscription"),
    ).toBeInTheDocument();
  });

  it("narrows the list to the group a link arrived with", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        requested.push(String(input));
        return {
          ok: true,
          status: 200,
          json: async () => ({ data: [ASSET], error: null, meta: { total: 1 } }),
        } as Response;
      }),
    );
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false } },
    });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter
          initialEntries={["/assets?subscription_id=sub-1&resource_group=prod-rg"]}
        >
          <AssetsPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    // The scope is shown as a filter that can be taken off, rather than as an
    // unexplained short list.
    expect(await screen.findByText("prod-rg")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Clear scope filter" }),
    ).toBeInTheDocument();
    expect(
      requested.some((url) => url.includes("resource_group=prod-rg")),
    ).toBe(true);
  });

  it("names what an unchecked resource actually is", async () => {
    /** A row reading "Unknown" would be a worse answer than the omission it
     * replaced. The point of listing these is that the customer can see what
     * is unchecked, not merely how many. */
    mount([UNCHECKED], { total: 1, unchecked: 1 });

    expect(await screen.findByText("Microsoft.Web/sites")).toBeInTheDocument();
  });

  it("still labels a modelled asset by its neutral type", async () => {
    /** The other branch. `azure_type` is null for anything the connector
     * models, whose cloud-neutral label is the better one -- an Azure storage
     * account and an S3 bucket are one kind of thing to a reader. */
    mount([ASSET], { total: 1, unchecked: 0 });

    expect(await screen.findByText("STORAGE ACCOUNT")).toBeInTheDocument();
  });

  it("says how many resources have no checks", async () => {
    /** CloudGuard reporting its own limits, which is the one thing a customer
     * cannot work out for themselves. Before the inventory was read, a
     * subscription full of App Services looked like a tidy inventory of
     * storage and virtual machines -- an absence that read as coverage. */
    mount([UNCHECKED], { total: 47, unchecked: 35 });

    expect(await screen.findByText(/35 with no checks yet/)).toBeInTheDocument();
  });

  it("says nothing when every resource is covered", async () => {
    /** A line that always appears is a line nobody reads. */
    mount([ASSET], { total: 12, unchecked: 0 });

    expect(await screen.findByText("payroll")).toBeInTheDocument();
    expect(screen.queryByText(/no checks yet/)).not.toBeInTheDocument();
  });


});
