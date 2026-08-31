import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ScanCard } from "@/components/scans/ScanCard";
import { api } from "@/lib/api";
import type { Scan } from "@/lib/types";

function scan(overrides: Partial<Scan> = {}): Scan {
  return {
    id: "s1",
    cloud_account_id: "a1",
    status: "COMPLETED",
    started_at: "2026-01-01T00:00:00Z",
    completed_at: "2026-01-01T00:05:00Z",
    resource_count: 12,
    rule_count: 30,
    finding_count: 3,
    error_message: null,
    collection_errors: {},
    created_at: "2026-01-01T00:00:00Z",
    ...overrides,
  } as Scan;
}

function mount(value: Scan) {
  vi.spyOn(api, "get").mockResolvedValue({ data: null, meta: {} });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <ScanCard scan={value} />
    </QueryClientProvider>,
  );
}

describe("a scan card", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("separates finding nothing from failing to look", () => {
    // Zero resources reads as a failure and usually is not one. A scan with no
    // collection errors looked successfully and the environment was empty.
    mount(scan({ resource_count: 0 }));

    expect(screen.getByText(/nothing/i)).toBeInTheDocument();
  });

  it("says a zero-resource scan with collection errors could not look", () => {
    const { container } = mount(
      scan({ resource_count: 0, collection_errors: { "sub-1": "Denied. Grant Reader." } }),
    );

    expect(container.textContent).toContain("sub-1");
  });

  it("summarises collection errors rather than printing all of them", () => {
    // One reason per subscription per category turns a tenant-wide scan into a
    // wall nobody reads; the structured breakdown is behind Details.
    mount(
      scan({
        collection_errors: {
          "sub-1": "First failed.",
          "sub-2": "Second failed.",
          "sub-3": "Third failed.",
          "sub-4": "Fourth failed.",
          "sub-5": "Fifth failed.",
        },
      }),
    );

    expect(screen.getByText("and 2 more")).toBeInTheDocument();
  });

  it("offers Cancel only while something is still running", () => {
    mount(scan({ status: "EVALUATING" }));
    expect(screen.getByRole("button", { name: /cancel/i })).toBeInTheDocument();
  });

  it("does not offer to delete a scan that is still running", () => {
    // Deleting mid-flight would race the worker writing its results.
    mount(scan({ status: "EVALUATING" }));
    expect(screen.queryByRole("button", { name: /delete/i })).not.toBeInTheDocument();
  });

  it("keeps details closed until asked, because opening costs two requests", () => {
    mount(scan());
    expect(screen.getByRole("button", { name: /details/i })).toHaveAttribute(
      "aria-expanded",
      "false",
    );
  });
});
