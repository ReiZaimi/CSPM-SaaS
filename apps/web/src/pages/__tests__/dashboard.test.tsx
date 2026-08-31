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
      expect(screen.getByRole("link", { name: /Run scan/ })).toHaveAttribute(
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
});
