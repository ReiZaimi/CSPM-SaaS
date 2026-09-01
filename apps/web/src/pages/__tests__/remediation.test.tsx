/**
 * The queue has to say what the work is.
 *
 * `GET /remediation` returns a task and nothing of the finding behind it, so
 * the page used to offer a severity badge, a status and a link reading "View
 * finding" — everything about the record and nothing about the problem. A
 * person deciding what to do next had to open every card to find out.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { RemediationPage } from "@/pages/Remediation";

const TASK = {
  id: "task-1",
  finding_id: "finding-1",
  risk_id: null,
  status: "TODO",
  priority: "CRITICAL",
  due_date: null,
  estimated_effort_minutes: 15,
  notes: null,
  completed_at: null,
  created_at: "2026-08-01T00:00:00Z",
};

const FINDING = {
  id: "finding-1",
  rule_id: "AZ-STORAGE-001",
  severity: "CRITICAL",
  status: "IN_PROGRESS",
  title: "Storage account allows public blob access",
  description: "",
  evidence: {},
  remediation: "",
  rule_version: "1.0",
  risk_score: 91,
  first_detected_at: "2026-08-01T00:00:00Z",
  last_detected_at: "2026-08-01T00:00:00Z",
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

function renderPage() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/remediation"]}>
        <RemediationPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("the remediation queue", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        const body = url.includes("/findings/") ? FINDING : [TASK];
        return {
          ok: true,
          status: 200,
          json: async () => ({ data: body, error: null, meta: {} }),
        } as Response;
      }),
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("names the finding and the asset the work is on", async () => {
    renderPage();

    const title = await screen.findByRole("link", {
      name: "Storage account allows public blob access",
    });
    expect(title).toHaveAttribute("href", "/findings/finding-1");
    expect(await screen.findByText(/prodstorage/)).toBeInTheDocument();
  });
});
