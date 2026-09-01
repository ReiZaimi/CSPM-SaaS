/**
 * The change feed, which is the only screen about movement rather than state.
 *
 * Two readings have to survive: a level that got *worse* must not look like one
 * that got better, and a DISAPPEARED event must say whether the asset is
 * missing now — the row is history either way, and only one of them is a job.
 */
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ChangesPage } from "../Changes";
import { api } from "@/lib/api";
import type { ChangeEvent } from "@/lib/types";

function event(overrides: Partial<ChangeEvent> = {}): ChangeEvent {
  return {
    id: "c-1",
    change: "EXPOSURE_CHANGED",
    previous_value: "LOW",
    current_value: "CRITICAL",
    observed_at: "2026-08-30T09:15:00+00:00",
    scan_id: "s-1",
    asset: {
      id: "a-1",
      name: "customerdata",
      resource_type: "storage_account",
      environment: "production",
      absent_since: null,
    },
    ...overrides,
  };
}

function mount(events: ChangeEvent[]) {
  vi.spyOn(api, "get").mockResolvedValue({ data: events, meta: {} });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <ChangesPage />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("ChangesPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("shows an attribute change as the move it was, not just its new value", async () => {
    mount([event()]);

    await waitFor(() => expect(screen.getByText("customerdata")).toBeInTheDocument());
    expect(screen.getByText("Exposure changed")).toBeInTheDocument();
    expect(screen.getByText("Low")).toBeInTheDocument();
    expect(screen.getByText("Critical")).toBeInTheDocument();
    expect(screen.getByText("Got worse")).toBeInTheDocument();
  });

  it("does not call a de-escalation a deterioration", async () => {
    mount([event({ previous_value: "CRITICAL", current_value: "LOW" })]);

    await waitFor(() => expect(screen.getByText("Got better")).toBeInTheDocument());
    expect(screen.queryByText("Got worse")).not.toBeInTheDocument();
  });

  it("treats a move into UNKNOWN as neither better nor worse", async () => {
    // Ranking UNKNOWN below LOW would render a loss of knowledge as a green
    // improvement, which is the one thing this product must never do.
    mount([event({ previous_value: "HIGH", current_value: "UNKNOWN" })]);

    await waitFor(() => expect(screen.getByText("Exposure changed")).toBeInTheDocument());
    expect(screen.queryByText("Got better")).not.toBeInTheDocument();
    expect(screen.queryByText("Got worse")).not.toBeInTheDocument();
  });

  it("says a disappeared asset is still missing", async () => {
    mount([
      event({
        change: "DISAPPEARED",
        previous_value: null,
        current_value: null,
        asset: {
          id: "a-2",
          name: "jump-01",
          resource_type: "virtual_machine",
          environment: "production",
          absent_since: "2026-08-29T09:15:00+00:00",
        },
      }),
    ]);

    await waitFor(() => expect(screen.getByText("Still missing")).toBeInTheDocument());
    expect(screen.queryByText("Seen again since")).not.toBeInTheDocument();
  });

  it("says a disappeared asset that came back came back", async () => {
    mount([
      event({
        change: "DISAPPEARED",
        previous_value: null,
        current_value: null,
        asset: {
          id: "a-2",
          name: "jump-01",
          resource_type: "virtual_machine",
          environment: null,
          absent_since: null,
        },
      }),
    ]);

    await waitFor(() => expect(screen.getByText("Seen again since")).toBeInTheDocument());
    expect(screen.queryByText("Still missing")).not.toBeInTheDocument();
  });

  it("groups the feed by the day each change was observed", async () => {
    mount([
      event({ id: "c-1", observed_at: "2026-08-30T09:15:00+00:00" }),
      event({ id: "c-2", observed_at: "2026-08-30T18:40:00+00:00" }),
      event({ id: "c-3", observed_at: "2026-08-28T11:00:00+00:00" }),
    ]);

    await waitFor(() => expect(screen.getAllByText("customerdata")).toHaveLength(3));
    // Two days, not three rows of the same heading.
    expect(screen.getAllByRole("heading", { level: 2 })).toHaveLength(2);
  });

  it("reads a quiet window as a quiet window", async () => {
    mount([]);

    await waitFor(() =>
      expect(screen.getByText("Nothing moved in this window")).toBeInTheDocument(),
    );
  });

  it("asks the API for the window and kind being looked at", async () => {
    const get = vi
      .spyOn(api, "get")
      .mockResolvedValue({ data: [], meta: {} });
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <ChangesPage />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    await waitFor(() => expect(get).toHaveBeenCalled());
    expect(get.mock.calls[0][0]).toContain("days=7");
    expect(get.mock.calls[0][0]).toContain("limit=50");
  });

  it("links each row to the asset it is about", async () => {
    mount([event()]);

    await waitFor(() =>
      expect(screen.getByRole("link", { name: "customerdata" })).toHaveAttribute(
        "href",
        "/assets/a-1",
      ),
    );
  });
});
