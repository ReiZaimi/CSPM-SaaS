/**
 * One framework, control by control — and the honesty the page turns on.
 *
 * Five verdicts, and the two that look alike are the ones that matter.
 * NOT_COVERED is CloudGuard having no rule for a control: a fact about this
 * product. INCONCLUSIVE is CloudGuard having a rule, running it, and failing to
 * reach an answer: a fact about a scan. Collapsing them would let "we have
 * nothing to check this with" and "we checked and could not tell" read as the
 * same shrug, on the one screen somebody might print for an auditor.
 *
 * INCONCLUSIVE is also the only verdict here a reader cannot act on from the
 * verdict alone. Failing points at findings, passing needs nothing, not-covered
 * has no action. So the reason travels with it.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ComplianceFrameworkPage } from "@/pages/ComplianceFramework";

const ROLE_REASON =
  "The server's auditing settings could not be read. If this persists, the " +
  "deployed scanner role may predate the permission that reads them.";

function rule(overrides: Record<string, unknown> = {}) {
  return {
    rule_id: "AZ-DB-003",
    name: "Database server keeps no audit trail",
    severity: "MEDIUM",
    open_finding_count: 0,
    unknown_count: 0,
    evaluated: true,
    unknown_reasons: [],
    ...overrides,
  };
}

function control(overrides: Record<string, unknown> = {}) {
  return {
    id: "4.1.1",
    title: "Databases keep an audit trail",
    group: "Database",
    technically_assessable: true,
    status: "PASSING",
    open_finding_count: 0,
    rules: [rule()],
    ...overrides,
  };
}

function mount(controls: object[]) {
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => ({
      ok: true,
      status: 200,
      json: async () => ({
        data: {
          id: "CIS_AZURE_2.0",
          name: "CIS Microsoft Azure Foundations Benchmark",
          short_name: "CIS Azure",
          version: "2.0",
          authority: "Center for Internet Security",
          url: "https://www.cisecurity.org/",
          summary: "A benchmark.",
          scope_note: "A subset.",
          control_count: controls.length,
          coverage_ratio: 0.5,
          status_counts: {
            FAILING: 0,
            INCONCLUSIVE: 0,
            PASSING: 0,
            NOT_ASSESSED: 0,
            NOT_COVERED: 0,
          },
          controls,
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
      <MemoryRouter initialEntries={["/compliance/CIS_AZURE_2.0"]}>
        <Routes>
          <Route
            path="/compliance/:frameworkId"
            element={<ComplianceFrameworkPage />}
          />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("one compliance framework", () => {
  beforeEach(() => vi.restoreAllMocks());
  afterEach(() => vi.unstubAllGlobals());

  it("says why a control could not be assessed, not only that it could not", async () => {
    mount([
      control({
        status: "INCONCLUSIVE",
        rules: [rule({ unknown_count: 4, unknown_reasons: [ROLE_REASON] })],
      }),
    ]);

    expect(await screen.findByText(/4 could not be evaluated/)).toBeInTheDocument();
    expect(screen.getByText(/deployed scanner role may predate/)).toBeInTheDocument();
  });

  it("keeps several reasons apart", async () => {
    /** One rule can fail differently on different resources. Collapsing them
     * would name the wrong cause for half the assets. */
    mount([
      control({
        status: "INCONCLUSIVE",
        rules: [
          rule({
            unknown_count: 2,
            unknown_reasons: ["Azure timed out", "Configuration missing"],
          }),
        ],
      }),
    ]);

    expect(await screen.findByText("Azure timed out")).toBeInTheDocument();
    expect(screen.getByText("Configuration missing")).toBeInTheDocument();
  });

  it("adds no explanation where nothing went wrong", async () => {
    /** A line that always appears is a line nobody reads, and an empty one
     * under a passing control would imply something to look into. */
    mount([control({ status: "PASSING" })]);

    expect(await screen.findByText("Passing")).toBeInTheDocument();
    expect(screen.queryByText(/could not be evaluated/)).not.toBeInTheDocument();
  });

  it("distinguishes a control nothing checks from one that could not tell", async () => {
    /** The distinction the whole page turns on. One is a fact about
     * CloudGuard, the other about a scan, and only the second has an action
     * behind it. */
    mount([
      control({ id: "9", title: "Something unchecked", status: "NOT_COVERED", rules: [] }),
      control({
        id: "4.1.1",
        status: "INCONCLUSIVE",
        rules: [rule({ unknown_count: 1, unknown_reasons: [ROLE_REASON] })],
      }),
    ]);

    expect(await screen.findByText("Not covered")).toBeInTheDocument();
    expect(screen.getByText("Inconclusive")).toBeInTheDocument();
  });

  it("never shows an inconclusive control as passing", async () => {
    /** The invariant, on the one screen where somebody might put it in front
     * of an auditor. */
    mount([
      control({
        status: "INCONCLUSIVE",
        rules: [rule({ unknown_count: 9, unknown_reasons: [ROLE_REASON] })],
      }),
    ]);

    expect(await screen.findByText("Inconclusive")).toBeInTheDocument();
    expect(screen.queryByText("Passing")).not.toBeInTheDocument();
  });
});
