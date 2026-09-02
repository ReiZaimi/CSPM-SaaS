/**
 * What a finding is part of.
 *
 * The findings list ranks problems one at a time, which is right for triage
 * and wrong as a story: a medium misconfiguration on a host standing between
 * the internet and customer data is not a medium problem. The detail page is
 * the only place that can say so, and an empty answer must not read as an
 * all-clear — what counts as sensitive is something the customer declares.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { FindingDetailPage } from "@/pages/FindingDetail";

const FINDING = {
  id: "finding-1",
  rule_id: "AZ-STORAGE-001",
  severity: "HIGH",
  status: "OPEN",
  title: "Storage account allows public blob access",
  description: "The account permits anonymous reads.",
  evidence: { allowBlobPublicAccess: true },
  remediation: "Disable public access.",
  rule_version: "1.0",
  risk_score: 71,
  first_detected_at: "2026-08-01T00:00:00Z",
  last_detected_at: "2026-08-30T00:00:00Z",
  resolved_at: null,
  resolved_by_scan_id: null,
  resource: {
    id: "asset-1",
    name: "prodstorage",
    resource_type: "STORAGE_ACCOUNT",
    environment: "PRODUCTION",
    region: "westeurope",
    criticality: "HIGH",
    data_sensitivity: "HIGH",
    public_exposure: "HIGH",
  },
};

const PATH = {
  entry: {
    id: "/vm/jump-01",
    name: "jump-01",
    resource_type: "VIRTUAL_MACHINE",
    public_exposure: "CRITICAL",
  },
  target: {
    id: "/storage/prodstorage",
    name: "prodstorage",
    resource_type: "STORAGE_ACCOUNT",
    data_sensitivity: "HIGH",
  },
  hops: 2,
  steps: [
    {
      source: "jump-01",
      source_id: "/vm/jump-01",
      relationship: "HAS_IDENTITY",
      target: "mi-jump",
      target_id: "/principals/mi-jump",
      description: "jump-01 runs as mi-jump",
    },
    {
      source: "mi-jump",
      source_id: "/principals/mi-jump",
      relationship: "GRANTS_ROLE",
      target: "prodstorage",
      target_id: "/storage/prodstorage",
      description: "mi-jump can act over prodstorage",
    },
  ],
  cheapest_break: {
    description: "mi-jump can act over prodstorage",
    relationship: "GRANTS_ROLE",
    source_id: "/principals/mi-jump",
    target_id: "/storage/prodstorage",
  },
  asset_role: "TARGET",
};

function mount(paths: unknown[], finding: object = FINDING) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      const data = url.includes("/attack-paths") ? paths : finding;
      return {
        ok: true,
        status: 200,
        json: async () => ({ data, error: null, meta: {} }),
      } as Response;
    }),
  );

  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/findings/finding-1"]}>
        <Routes>
          <Route path="/findings/:findingId" element={<FindingDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("the finding detail page", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("says when the asset is on a route, and where on it", async () => {
    mount([PATH]);

    expect(
      await screen.findByText(/This asset is the target/),
    ).toBeInTheDocument();
    // The route itself, not just the fact of one: naming the links is what
    // makes it something somebody can go and cut.
    expect(screen.getByText("jump-01 runs as mi-jump")).toBeInTheDocument();
    expect(screen.getByText(/Cutting this link severs the route/)).toBeInTheDocument();
  });

  it("does not report an empty result as an all-clear", async () => {
    mount([]);

    expect(
      await screen.findByText(/declared per subscription in Settings/),
    ).toBeInTheDocument();
  });

  it("says what is already standing in the way, without calling it fixed", async () => {
    // A score arrived at through a rule nobody can see is the kind a customer
    // stops trusting: an administrator with no second factor ranked below a
    // logging gap needs to say why on the page, not in a formula.
    mount([], {
      ...FINDING,
      evidence: {
        ...FINDING.evidence,
        compensating_controls: [
          {
            id: "entra.security_defaults",
            name: "Security defaults",
            detail: "Every account is challenged for a second factor.",
            exploitability: 3,
          },
        ],
      },
    });

    const panel = (
      await screen.findByText("What is standing in the way")
    ).closest("[data-slot='card']")!;

    // Scoped to the panel: the raw evidence block below it carries the same
    // words, because a control is part of what the pipeline recorded.
    expect(within(panel as HTMLElement).getByText("Security defaults")).toBeInTheDocument();
    expect(
      within(panel as HTMLElement).getByText(
        /Every account is challenged for a second factor/,
      ),
    ).toBeInTheDocument();
    // Not reassuring. The misconfiguration underneath is untouched.
    expect(
      within(panel as HTMLElement).getByText(/without making it right/),
    ).toBeInTheDocument();
  });

  it("says nothing when nothing stands in the way", async () => {
    mount([]);

    expect(
      screen.queryByText("What is standing in the way"),
    ).not.toBeInTheDocument();
  });
});
