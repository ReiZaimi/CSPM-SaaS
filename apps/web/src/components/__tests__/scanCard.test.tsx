import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
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

  it("offers to re-evaluate a run that stored a capture", async () => {
    // The verbatim JSON is kept precisely so a rule written since can be
    // applied to it, and until now there was no way to ask for that.
    mount(scan());

    expect(screen.getByRole("button", { name: "Re-evaluate" })).toBeInTheDocument();
    expect(screen.getByText(/No Azure call, no consent/)).toBeInTheDocument();
  });

  it("does not offer to re-evaluate a run that may have collected nothing", async () => {
    // A FAILED scan may have fallen over before the snapshot was written, and
    // a button that usually answers "no stored snapshot" reads as data loss.
    mount(scan({ status: "FAILED", error_message: "Collection failed" }));

    expect(screen.queryByRole("button", { name: "Re-evaluate" })).not.toBeInTheDocument();
  });

  it("queues the re-evaluation against the scan it was asked for", async () => {
    const post = vi.spyOn(api, "post").mockResolvedValue({ data: scan(), meta: {} });
    mount(scan());

    fireEvent.click(screen.getByRole("button", { name: "Re-evaluate" }));

    await waitFor(() => expect(post).toHaveBeenCalledWith("/api/v1/scans/s1/replay"));
  });

  it("says why a re-evaluation was refused rather than doing nothing", async () => {
    vi.spyOn(api, "post").mockRejectedValue(
      new Error("A scan is already running for this connection"),
    );
    mount(scan());

    fireEvent.click(screen.getByRole("button", { name: "Re-evaluate" }));

    await waitFor(() =>
      expect(
        screen.getByText("A scan is already running for this connection"),
      ).toBeInTheDocument(),
    );
  });

  it("marks a replay as a replay rather than letting it pass for a scan", async () => {
    mount(scan({ id: "s2", replay_of_scan_id: "s1" }));

    expect(screen.getByText("Re-evaluation of an earlier scan")).toBeInTheDocument();
  });

  it("says an advisory replay changed no finding", async () => {
    // The dangerous case. A month-old capture producing PASS where a finding
    // was FAIL must never stamp that finding "verified fixed".
    mount(scan({ id: "s2", replay_of_scan_id: "s1", evaluation_only: true }));

    expect(screen.getByText("What the rules would have found")).toBeInTheDocument();
    expect(
      screen.getByText(/No finding was created, resolved or reopened/),
    ).toBeInTheDocument();
    // And the counter must not read as findings that exist.
    expect(screen.getByText("Findings (would have)")).toBeInTheDocument();
  });

  it("says a replay of the current capture did count", async () => {
    mount(scan({ id: "s2", replay_of_scan_id: "s1", evaluation_only: false }));

    expect(screen.getByText("Applied to your current picture")).toBeInTheDocument();
    expect(screen.getByText("Findings")).toBeInTheDocument();
  });
});
