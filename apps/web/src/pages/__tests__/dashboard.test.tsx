/**
 * The dashboard's two exits.
 *
 * The page is one argument read top to bottom, and it ends with the reader
 * deciding what to do about what they just read. There are two answers — read
 * the environment again, or write this down — and the header has to offer both.
 * Reports existed for a while with nothing anywhere pointing at them.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { DashboardPage } from "../Dashboard";
import { api } from "@/lib/api";
import type { CloudAccount, Dashboard } from "@/lib/types";

function dashboard(overrides: Partial<Dashboard> = {}): Dashboard {
  return {
    security_score: 84,
    score_delta: 7,
    history: [],
    findings_by_severity: { CRITICAL: 1, HIGH: 2, MEDIUM: 3, LOW: 4 },
    findings_by_status: { OPEN: 10 },
    risk_bands: {},
    open_finding_count: 10,
    asset_count: 42,
    verified_resolved_last_30_days: 3,
    remediation_rate: 0.3,
    top_risks: [],
    coverage: { ratio: 0.9, unknown: 1, conclusive: 19 },
    evidence_freshness: null,
    last_scan: {
      id: "s-1",
      status: "COMPLETED",
      completed_at: "2026-08-31T09:00:00Z",
      resource_count: 42,
      rule_count: 30,
      finding_count: 10,
      collection_errors: {},
    },
    ...overrides,
  } as Dashboard;
}

function mount(data: Dashboard, accounts: CloudAccount[] = []) {
  vi.spyOn(api, "get").mockImplementation((path: string) => {
    if (path.includes("cloud-accounts")) {
      return Promise.resolve({ data: accounts, meta: {} }) as never;
    }
    // The panels the page asks for after its own payload. Answered as the
    // lists they really are, so a test about the dashboard is not quietly
    // testing what happens when an endpoint returns the wrong shape.
    if (
      path.includes("attack-paths") ||
      path.includes("changes") ||
      path.includes("scans")
    ) {
      return Promise.resolve({ data: [], meta: {} }) as never;
    }
    return Promise.resolve({ data, meta: {} }) as never;
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("DashboardPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("points at the reports, which is the other thing to do with a posture", async () => {
    mount(dashboard());

    await waitFor(() =>
      expect(screen.getByRole("link", { name: /Reports/ })).toHaveAttribute(
        "href",
        "/reports",
      ),
    );
  });

  it("still offers a rescan, which is the primary action", async () => {
    mount(dashboard());

    await waitFor(() =>
      expect(screen.getByRole("link", { name: /Scan now/ })).toHaveAttribute(
        "href",
        "/scans",
      ),
    );
  });

  it("offers neither before there is a posture to read or report on", async () => {
    // Nothing has been scanned: the only sensible action is the first scan,
    // and a report over no evidence would be a document about nothing.
    mount(dashboard({ last_scan: null }));

    await waitFor(() =>
      expect(screen.getByText("Connect your cloud environment")).toBeInTheDocument(),
    );
    expect(screen.queryByRole("link", { name: /Reports/ })).not.toBeInTheDocument();
  });

  it("sends a ranked risk to that risk, not back to the unfiltered list", async () => {
    // Every top risk used to link to /risks, so clicking the thing the page had
    // just ranked first made the reader find it again in a table.
    mount(
      dashboard({
        top_risks: [
          {
            id: "risk-1",
            title: "Production database reachable from the internet",
            risk_score: 94,
            risk_level: "CRITICAL",
          },
        ],
      }),
    );

    await waitFor(() =>
      expect(
        screen.getByRole("link", { name: /Production database reachable/ }),
      ).toHaveAttribute("href", "/risks/risk-1"),
    );
  });

  it("reads the estate's coverage per category, not just as one number", async () => {
    // A ratio says how much of the picture is missing and never which part, and
    // those call for different actions: an unreadable directory is a consent
    // problem, an unreadable storage listing is usually a role assignment.
    mount(
      dashboard({
        coverage: {
          ratio: 0.75,
          unknown: 1,
          conclusive: 3,
          categories: [
            { name: "identity", readings: 4, incomplete: 3 },
            { name: "network", readings: 6, incomplete: 0 },
          ],
        },
      }),
    );

    expect(await screen.findByText("Identity")).toBeInTheDocument();
    expect(screen.getByText("Network")).toBeInTheDocument();
    // Never phrased as a security percentage: 75% coverage is not 75% secure.
    expect(screen.getByText(/not a security percentage/)).toBeInTheDocument();
  });

  it("counts checks that reached no verdict beside the severities", async () => {
    // UNKNOWN is not a fifth severity and is not a pass. It belongs in the same
    // glance as the problem counts, because a reader tallying what is wrong has
    // to see what could not be answered.
    mount(dashboard({ coverage: { ratio: 0.5, unknown: 7, conclusive: 7 } }));

    const unknown = await screen.findByRole("link", { name: /No verdict/ });
    expect(unknown).toHaveAttribute("href", "/scans");
    expect(unknown).toHaveTextContent("7");
  });

  it("says why a risk outranks the one beneath it", async () => {
    mount(
      dashboard({
        top_risks: [
          {
            id: "risk-1",
            title: "Production database reachable from the internet",
            risk_score: 94,
            risk_level: "CRITICAL",
            kind: "FINDING",
            internet_exposure: "CRITICAL",
            data_sensitivity: "HIGH",
            asset_criticality: "LOW",
          },
        ],
      }),
    );

    expect(await screen.findByText("Internet-facing")).toBeInTheDocument();
    expect(screen.getByText("Sensitive data")).toBeInTheDocument();
    // LOW criticality is not a reason this ranked where it did, so it is not
    // given a line saying nothing.
    expect(screen.queryByText("Business-critical")).not.toBeInTheDocument();
  });

  it("never scores an environment it has not read", async () => {
    mount(dashboard({ last_scan: null }));

    expect(
      await screen.findByText("Connect your cloud environment"),
    ).toBeInTheDocument();
    expect(screen.queryByRole("meter", { name: "Security score" })).not.toBeInTheDocument();
    expect(screen.queryByText("84")).not.toBeInTheDocument();
  });
});
