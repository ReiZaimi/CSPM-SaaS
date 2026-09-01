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

const ASSET = {
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

let requested: string[] = [];

function mount() {
  requested = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      requested.push(url);
      const data = url.includes("/assets/hierarchy") ? HIERARCHY : [ASSET];
      return {
        ok: true,
        status: 200,
        json: async () => ({ data, error: null, meta: { total: 40 } }),
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
});
