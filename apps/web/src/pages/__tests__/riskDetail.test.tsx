/**
 * One risk, and the findings it was built from.
 *
 * The list can rank a route above the findings inside it; only this page can
 * say which findings those are. It also has to keep the two scoring formulas
 * apart — a scenario is floored at its worst member and amplified for being
 * short, so showing it the six weighted components would be working nobody did.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { RiskDetailPage } from "../RiskDetail";
import { api, ApiError } from "@/lib/api";
import type { RiskDetail } from "@/lib/types";

function findingRisk(overrides: Partial<RiskDetail> = {}): RiskDetail {
  return {
    id: "r-1",
    kind: "FINDING",
    path: [],
    title: "Public blob access on customerdata",
    description: "The storage account allows anonymous blob reads.",
    risk_score: 84,
    risk_level: "CRITICAL",
    status: "OPEN",
    asset_criticality: "HIGH",
    data_sensitivity: "HIGH",
    internet_exposure: "HIGH",
    exploitability: 4,
    business_impact: 4.5,
    score_breakdown: {
      components: {
        data_sensitivity: { value: 4, weight: 0.3, contribution: 25.2 },
      },
      total: 84,
    },
    findings: [
      {
        id: "f-1",
        rule_id: "AZ-STO-001",
        title: "Storage account allows public blob access",
        severity: "CRITICAL",
        status: "OPEN",
      },
    ],
    ...overrides,
  } as RiskDetail;
}

function scenarioRisk(overrides: Partial<RiskDetail> = {}): RiskDetail {
  return findingRisk({
    id: "r-2",
    kind: "ATTACK_PATH",
    title: "jump-01 can reach customerdata",
    path: [
      {
        source: "jump-01",
        source_id: "vm",
        relationship: "has_identity",
        target: "mi-jump-01",
        target_id: "mi",
        description: "jump-01 runs as mi-jump-01",
      },
    ],
    score_breakdown: { worst_member: 84, amplifier: 12, hops: 1, uncapped: 96, total: 96 },
    risk_score: 96,
    ...overrides,
  } as Partial<RiskDetail>);
}

function mount(risk: RiskDetail) {
  vi.spyOn(api, "get").mockResolvedValue({ data: risk, meta: {} });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[`/risks/${risk.id}`]}>
        <Routes>
          <Route path="/risks/:riskId" element={<RiskDetailPage />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("RiskDetailPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("names the findings a risk was built from, each one openable", async () => {
    // The claim the list makes and cannot show.
    mount(scenarioRisk());

    await waitFor(() =>
      expect(
        screen.getByRole("link", { name: "Storage account allows public blob access" }),
      ).toHaveAttribute("href", "/findings/f-1"),
    );
    expect(screen.getByText("AZ-STO-001")).toBeInTheDocument();
  });

  it("shows a scenario its own arithmetic, not the finding formula", async () => {
    mount(scenarioRisk());

    await waitFor(() =>
      expect(screen.getByText("Worst finding on the route")).toBeInTheDocument(),
    );
    expect(screen.getByText("+12")).toBeInTheDocument();
    expect(screen.queryByText("Exploitability")).not.toBeInTheDocument();
    expect(screen.queryByText("Asset criticality")).not.toBeInTheDocument();
  });

  it("shows a finding risk its weighted components and its factors", async () => {
    mount(findingRisk());

    await waitFor(() => expect(screen.getByText("Asset criticality")).toBeInTheDocument());
    expect(screen.getByText(/data sensitivity/)).toBeInTheDocument();
    expect(screen.getByText("25.2")).toBeInTheDocument();
    expect(screen.queryByText("Worst finding on the route")).not.toBeInTheDocument();
  });

  it("draws a scenario's route", async () => {
    mount(scenarioRisk());

    await waitFor(() =>
      expect(screen.getByText("jump-01 runs as mi-jump-01")).toBeInTheDocument(),
    );
  });

  it("explains a score that hit the ceiling", async () => {
    // A card showing 100 whose terms sum to 106 reads as broken arithmetic
    // rather than as a deliberate cap.
    mount(
      scenarioRisk({
        risk_score: 100,
        score_breakdown: { worst_member: 94, amplifier: 12, hops: 1, uncapped: 106, total: 100 },
      }),
    );

    await waitFor(() => expect(screen.getByText(/106 before the ceiling/)).toBeInTheDocument());
  });

  it("says a risk with no linked findings lost them, rather than showing an empty box", async () => {
    mount(findingRisk({ findings: [] }));

    await waitFor(() =>
      expect(screen.getByText("No findings are linked to this risk.")).toBeInTheDocument(),
    );
    expect(screen.getByText(/most likely with the scan that raised them/)).toBeInTheDocument();
  });

  it("names a deleted risk as deleted rather than as a broken product", async () => {
    vi.spyOn(api, "get").mockRejectedValue(
      new ApiError("NOT_FOUND", "Risk not found", 404),
    );
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={["/risks/gone"]}>
          <Routes>
            <Route path="/risks/:riskId" element={<RiskDetailPage />} />
          </Routes>
        </MemoryRouter>
      </QueryClientProvider>,
    );

    await waitFor(() =>
      expect(screen.getByText("That risk no longer exists")).toBeInTheDocument(),
    );
    // Not a retry: retrying a 404 just fails again.
    expect(screen.queryByRole("button", { name: "Try again" })).not.toBeInTheDocument();
  });

  /**
   * When anything last looked.
   *
   * A route is a claim about how an environment is wired *as of a reading*.
   * Without a date, one that survived the latest scan and one nothing has
   * re-checked since Tuesday render identically -- and the second reads as
   * current, which is the direction that gets somebody hurt.
   */
  it("says when a route was last confirmed", async () => {
    mount(
      scenarioRisk({
        observed_at: new Date(Date.now() - 2 * 3600 * 1000).toISOString(),
      }),
    );

    expect(
      await screen.findByText(/still there 2 hours ago/),
    ).toBeInTheDocument();
  });

  it("says it cannot tell rather than implying the route is current", async () => {
    // The scan that found it has been pruned. "Never seen" would be wrong --
    // the route exists because a scan found it -- and a bare date would be a
    // claim CloudGuard cannot support.
    mount(scenarioRisk({ observed_at: null }));

    expect(
      await screen.findByText(/no longer stored/),
    ).toBeInTheDocument();
    expect(screen.queryByText(/still there/)).not.toBeInTheDocument();
  });
});
