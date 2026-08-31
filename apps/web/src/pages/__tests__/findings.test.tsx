import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { FindingsPage } from "@/pages/Findings";

/** 120 findings, so a single default page cannot be the whole set. */
const TOTAL = 120;

function finding(index: number) {
  return {
    id: `00000000-0000-0000-0000-${String(index).padStart(12, "0")}`,
    rule_id: `AZ-RULE-${index}`,
    severity: index === 0 ? "CRITICAL" : "LOW",
    status: "OPEN",
    title: `Finding number ${index}`,
    description: "",
    evidence: {},
    remediation: "",
    rule_version: "1.0",
    risk_score: 50,
    first_detected_at: "2026-01-01T00:00:00Z",
    last_detected_at: "2026-01-01T00:00:00Z",
    resolved_at: null,
    resolved_by_scan_id: null,
    resource: null,
  };
}

let requested: string[] = [];

function renderPage() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={["/findings"]}>
        <FindingsPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("the findings list", () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    requested = [];
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        requested.push(url);
        const params = new URL(url, "https://example.test").searchParams;
        const limit = Number(params.get("limit") ?? 100);
        const offset = Number(params.get("offset") ?? 0);
        const page = Array.from({ length: Math.min(limit, TOTAL - offset) }, (_, i) =>
          finding(offset + i),
        );
        return {
          ok: true,
          status: 200,
          json: async () => ({ data: page, error: null, meta: { total: TOTAL } }),
        } as Response;
      }),
    );
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("reports the true total, not the size of the page it was given", async () => {
    renderPage();

    // The bug this replaces: a hundred rows rendered as though they were all
    // of them, with nothing on screen saying otherwise.
    expect(await screen.findByText(/of 120 findings/)).toBeInTheDocument();
  });

  it("asks the database for the ordering rather than sorting a page", async () => {
    renderPage();
    await screen.findByText(/of 120 findings/);

    expect(requested[0]).toContain("sort=risk");
    expect(requested[0]).toContain(`limit=50`);
  });

  it("sends a search to the API instead of filtering what it holds", async () => {
    renderPage();
    await screen.findByText(/of 120 findings/);

    fireEvent.change(screen.getByLabelText("Search findings"), {
      target: { value: "payroll" },
    });
    await vi.advanceTimersByTimeAsync(300);

    // Filtering in the browser would search 50 of 120 findings and report
    // "no findings match" for the other 70.
    await waitFor(() =>
      expect(requested.some((url) => url.includes("search=payroll"))).toBe(true),
    );
  });

  it("debounces, so typing a word is one request and not six", async () => {
    renderPage();
    await screen.findByText(/of 120 findings/);
    const before = requested.length;

    for (const value of ["p", "pa", "pay", "payr", "payro", "payroll"]) {
      fireEvent.change(screen.getByLabelText("Search findings"), { target: { value } });
    }
    await vi.advanceTimersByTimeAsync(300);
    await waitFor(() =>
      expect(requested.some((url) => url.includes("search=payroll"))).toBe(true),
    );

    expect(requested.length - before).toBe(1);
  });

  it("turns the page by offset, not by slicing in the browser", async () => {
    renderPage();
    await screen.findByText(/of 120 findings/);

    fireEvent.click(screen.getByRole("button", { name: "Next" }));

    await waitFor(() => expect(requested.some((url) => url.includes("offset=50"))).toBe(true));
    expect(await screen.findByText(/51–100 of 120 findings/)).toBeInTheDocument();
  });

  it("returns to the first page when a filter changes the set", async () => {
    renderPage();
    await screen.findByText(/of 120 findings/);
    fireEvent.click(screen.getByRole("button", { name: "Next" }));
    await screen.findByText(/51–100 of 120 findings/);

    fireEvent.change(screen.getByLabelText("Search findings"), {
      target: { value: "storage" },
    });
    await vi.advanceTimersByTimeAsync(300);

    // Page two of the old result describes nothing in the new one.
    await waitFor(() =>
      expect(
        requested.some((url) => url.includes("search=storage") && url.includes("offset=0")),
      ).toBe(true),
    );
  });
});
