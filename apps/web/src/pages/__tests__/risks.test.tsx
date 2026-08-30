/**
 * The risks list, holding two kinds of thing.
 *
 * A scenario is not a louder finding. It is several of them seen as one route,
 * scored from a different formula — floored at its worst member and amplified
 * for being short — so rendering it with the six weighted components of a
 * finding risk would invite the reader to check numbers that were never used.
 *
 * Both kinds share one list on purpose: a route outranking the findings inside
 * it is only visible where they are ranked together.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { RisksPage } from "../Risks";
import { api } from "@/lib/api";
import type { Risk } from "@/lib/types";

function findingRisk(overrides: Partial<Risk> = {}): Risk {
  return {
    id: "r-finding",
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
    score_breakdown: { components: {}, total: 84 },
    ...overrides,
  } as Risk;
}

function scenarioRisk(overrides: Partial<Risk> = {}): Risk {
  return {
    id: "r-scenario",
    kind: "ATTACK_PATH",
    path: [
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
    ],
    title: "jump-01 can reach customerdata",
    description: "Reachable from the internet in 2 steps.",
    risk_score: 96,
    risk_level: "CRITICAL",
    status: "OPEN",
    asset_criticality: "UNKNOWN",
    data_sensitivity: "HIGH",
    internet_exposure: "CRITICAL",
    exploitability: 0,
    business_impact: 4,
    score_breakdown: {
      worst_member: 84,
      amplifier: 12,
      hops: 2,
      uncapped: 96,
      total: 96,
    },
    ...overrides,
  } as Risk;
}

function mount(risks: Risk[]) {
  vi.spyOn(api, "get").mockResolvedValue({ data: risks, meta: {} });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <RisksPage />
    </QueryClientProvider>,
  );
}

describe("RisksPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("shows a scenario's route, hop by hop", async () => {
    mount([scenarioRisk()]);

    await waitFor(() =>
      expect(screen.getByText("jump-01 runs as mi-jump-01")).toBeInTheDocument(),
    );
    expect(screen.getByText("mi-jump-01 can act over sub-1")).toBeInTheDocument();
  });

  it("says a scenario is several findings rather than one", async () => {
    // Without this it reads as a duplicate row with a higher number, which is
    // exactly how a customer learns to distrust the ranking.
    mount([scenarioRisk()]);

    await waitFor(() => expect(screen.getByText("Attack path")).toBeInTheDocument());
    expect(screen.getByText("Several findings, seen as one route")).toBeInTheDocument();
  });

  it("shows the arithmetic that put it above its worst finding", async () => {
    mount([scenarioRisk()]);

    await waitFor(() =>
      expect(screen.getByText("Worst finding on the route")).toBeInTheDocument(),
    );
    expect(screen.getByText("84")).toBeInTheDocument();
    expect(screen.getByText("+12")).toBeInTheDocument();
  });

  it("does not show a scenario the factors it was not scored from", async () => {
    // Exploitability and asset criticality are inputs to the finding formula.
    // A scenario is floored at its worst member and amplified for shortness,
    // so displaying them would be showing working that was never done.
    mount([scenarioRisk()]);

    await waitFor(() => expect(screen.getByText("Attack path")).toBeInTheDocument());
    expect(screen.queryByText("Exploitability")).not.toBeInTheDocument();
    expect(screen.queryByText("Asset criticality")).not.toBeInTheDocument();
  });

  it("still shows a finding risk its own factors", async () => {
    mount([findingRisk()]);

    await waitFor(() => expect(screen.getByText("Asset criticality")).toBeInTheDocument());
    expect(screen.getByText("Data sensitivity")).toBeInTheDocument();
    expect(screen.queryByText("Attack path")).not.toBeInTheDocument();
  });

  it("ranks both kinds in one list", async () => {
    mount([scenarioRisk(), findingRisk()]);

    await waitFor(() =>
      expect(screen.getByText("jump-01 can reach customerdata")).toBeInTheDocument(),
    );
    expect(screen.getByText("Public blob access on customerdata")).toBeInTheDocument();
  });

  it("explains a score that hit the ceiling", async () => {
    // A card showing 100 whose terms sum to 106 would look like a bug in the
    // arithmetic rather than a deliberate cap.
    mount([
      scenarioRisk({
        risk_score: 100,
        score_breakdown: {
          worst_member: 94,
          amplifier: 12,
          hops: 1,
          uncapped: 106,
          total: 100,
        },
      }),
    ]);

    await waitFor(() => expect(screen.getByText("Capped at 100.")).toBeInTheDocument());
  });

  it("does not claim a cap that did not happen", async () => {
    mount([scenarioRisk()]);

    await waitFor(() => expect(screen.getByText("Attack path")).toBeInTheDocument());
    expect(screen.queryByText("Capped at 100.")).not.toBeInTheDocument();
  });

  it("renders a privilege escalation as a route, with its own name", async () => {
    // Scored by the scenario formula, so it must not fall through to the
    // finding card — that would show asset criticality and exploitability,
    // which this score was never built from. And it is not an attack path: one
    // says what can be reached, the other what could be granted.
    mount([
      scenarioRisk({
        id: "r-escalation",
        kind: "ESCALATION",
        title: "jump-01 leads to control of sub-1",
      }),
    ]);

    await waitFor(() =>
      expect(screen.getByText("Privilege escalation")).toBeInTheDocument(),
    );
    expect(screen.getByText("jump-01 leads to control of sub-1")).toBeInTheDocument();
    expect(screen.getByText("The route")).toBeInTheDocument();
    expect(screen.queryByText("Attack path")).not.toBeInTheDocument();
  });
});
